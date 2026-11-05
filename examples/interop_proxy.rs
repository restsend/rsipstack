//! A single-next-hop, loopback SIP proxy used by the three-process interop tests.
//! This example is intentionally not a registrar, forking proxy or production SBC.
mod interop_support;
use interop_support::{App, AppResult, Calls, Tasks};
use rsipstack::{
    sip::{
        prelude::{HeadersExt, ToTypedHeader},
        Header, Method, Request, SipMessage, StatusCode, Uri,
    },
    transaction::{
        endpoint::EndpointInnerRef,
        key::{TransactionKey, TransactionRole},
        transaction::TransactionEvent,
        Transaction,
    },
    transport::SipAddr,
};
use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc,
};

#[tokio::main]
async fn main() -> AppResult {
    let app = App::start(true).await?;
    let mut incoming = app.endpoint.incoming_transactions()?;
    let endpoint = app.endpoint.inner.clone();
    let target = app.config.target.clone();
    let local = app.uri.clone();
    let calls = app.calls.clone();
    let tasks = app.tasks.clone();
    app.tasks.spawn("proxy router", async move {
        while let Some(tx) = incoming.recv().await {
            let endpoint = endpoint.clone();
            let target = target.clone();
            let local = local.clone();
            let calls = calls.clone();
            let handlers = tasks.clone();
            tasks.spawn("proxy request", async move {
                relay(tx, endpoint, target, local, calls, handlers).await
            });
        }
        Ok(())
    });
    app.run(|| 0).await
}

fn routed(mut request: Request, local: &Uri, target: Option<&Uri>) -> AppResult<Request> {
    if let Some(target) = target {
        request.uri = target.clone();
    }
    // The example advertises a single loose route and consumes only its own hop.
    request.headers.retain(|h| {
        !matches!(h, Header::Route(route)
        if route.typed().is_ok_and(|r| r.uri.host_with_port == local.host_with_port))
    });
    let hops: u32 = request.max_forwards_header()?.value().parse()?;
    let hops = hops.checked_sub(1).ok_or("Max-Forwards exhausted")?;
    request
        .headers
        .unique_push(Header::MaxForwards(hops.to_string().into()));
    Ok(request)
}

async fn send_request(endpoint: &EndpointInnerRef, mut request: Request) -> AppResult {
    let destination = SipAddr::try_from(&request.uri)?;
    request
        .headers
        .push_front(endpoint.get_via(None, None)?.into());
    let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
    let mut tx = Transaction::new_client(key, request, endpoint.clone(), None);
    tx.destination = Some(destination);
    tx.send().await?;
    if tx.original.method != Method::Ack {
        while tx.receive().await.is_some() {}
    }
    Ok(())
}

async fn relay(
    mut incoming: Transaction,
    endpoint: EndpointInnerRef,
    target: Uri,
    local: Uri,
    calls: Calls,
    tasks: Tasks,
) -> AppResult {
    let method = incoming.original.method.clone();
    let initial = method == Method::Invite && incoming.original.to_header()?.tag()?.is_none();
    if !matches!(
        method,
        Method::Invite | Method::Ack | Method::Bye | Method::Options
    ) {
        incoming.reply(StatusCode::NotImplemented).await?;
        return Ok(());
    }
    if incoming
        .original
        .max_forwards_header()?
        .value()
        .parse::<u32>()?
        == 0
    {
        if method != Method::Ack {
            incoming.reply(StatusCode::TooManyHops).await?;
        }
        return Ok(());
    }
    let mut request = routed(
        incoming.original.clone(),
        &local,
        initial.then_some(&target),
    )?;
    if method == Method::Ack {
        return send_request(&endpoint, request).await;
    }
    let id = request.call_id_header()?.value().to_owned();
    if initial {
        calls.add(id.clone());
        tasks.event(format!("CALL {id}"));
    }
    let destination = SipAddr::try_from(&request.uri)?;
    let via = endpoint.get_via(None, None)?;
    request.headers.push_front(via.clone().into());
    if initial {
        request
            .headers
            .push_front(endpoint.get_record_route()?.into());
    }
    let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
    let mut outgoing = Transaction::new_client(key, request.clone(), endpoint.clone(), None);
    outgoing.destination = Some(destination.clone());
    outgoing.send().await?;

    let status = Arc::new(AtomicU16::new(0));
    let saved_status = status.clone();
    let response_sender = incoming.tu_sender.clone();
    let upstream_connection = incoming
        .connection
        .clone()
        .ok_or("Missing upstream connection")?;
    let upstream_destination = incoming.destination.clone();
    let outgoing_tasks = tasks.clone();
    tasks.spawn("proxy responses", async move {
        while let Some(message) = outgoing.receive().await {
            if let SipMessage::Response(mut response) = message {
                let code = response.status_code.code();
                saved_status.store(code, Ordering::SeqCst);
                if code == 100 {
                    continue;
                }
                // SIPp coalesces Via hops onto one line; remove one value,
                // not the entire header (PJSUA normally sends separate lines).
                let mut first_via = true;
                let mut headers = Vec::new();
                for header in response.headers.iter() {
                    if let Header::Via(via) = header {
                        if first_via {
                            first_via = false;
                            let first = via.first_value()?;
                            let rest = via.value().trim()[first.value().len()..].trim_start();
                            if let Some(rest) = rest.strip_prefix(',') {
                                headers.push(Header::Via(rest.trim_start().into()));
                            }
                            continue;
                        }
                    }
                    headers.push(header.clone());
                }
                response.headers = headers.into();
                if (initial && code >= 300) || (method == Method::Bye && code >= 200) {
                    calls.remove(&id);
                    outgoing_tasks.event(format!("ENDED {id}"));
                }
                // If upstream transaction retention has already ended, a
                // repeated downstream 2xx still has to reach the original UA.
                if response_sender
                    .send(TransactionEvent::Respond(response.clone()))
                    .is_err()
                {
                    if method == Method::Invite && (200..300).contains(&code) {
                        upstream_connection
                            .send(response.into(), upstream_destination.as_ref())
                            .await?;
                    } else {
                        return Err("Upstream transaction ended before its response".into());
                    }
                }
            }
        }
        Ok(())
    });

    // Each transaction has one owning receive loop. Never select between two
    // receive() futures: receive() is explicitly not cancellation-safe.
    while let Some(message) = incoming.receive().await {
        if let SipMessage::Request(request_in) = message {
            match request_in.method {
                Method::Cancel if status.load(Ordering::SeqCst) < 200 => {
                    let mut cancel = request.clone();
                    cancel.method = Method::Cancel;
                    cancel.cseq_header_mut()?.mut_method(Method::Cancel)?;
                    cancel.headers.retain(|h| {
                        !matches!(h, Header::ContentType(_) | Header::ContentLength(_))
                    });
                    cancel.headers.unique_push(Header::ContentLength(0.into()));
                    cancel.body.clear();
                    let cancel_key =
                        TransactionKey::from_request(&cancel, TransactionRole::Client)?;
                    let mut cancel_tx =
                        Transaction::new_client(cancel_key, cancel, endpoint.clone(), None);
                    cancel_tx.destination = Some(destination.clone());
                    tasks.spawn("proxy CANCEL", async move {
                        cancel_tx.send().await?;
                        while cancel_tx.receive().await.is_some() {}
                        Ok(())
                    });
                }
                Method::Ack if (200..300).contains(&status.load(Ordering::SeqCst)) => {
                    send_request(&endpoint, routed(request_in, &local, None)?).await?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}
