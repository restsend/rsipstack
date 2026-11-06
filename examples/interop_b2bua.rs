//! A small offer-in-INVITE B2BUA: two real dialogs joined by an application actor.
//! No media relay, authentication, transfer, PRACK or session-modification policy.
mod interop_support;
use interop_support::{App, AppResult, Calls, Tasks};
use rsipstack::{
    dialog::{
        dialog::{Dialog, DialogState},
        dialog_layer::DialogLayer,
        invitation::{InviteAsyncResult, InviteOption},
        invite_dialog::InviteDialog,
    },
    sip::{prelude::HeadersExt, Header, Method, Response, StatusCode, Uri},
    transaction::{Transaction, TransactionState, TransactionType},
};
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> AppResult {
    let app = App::start(false).await?;
    let layer = Arc::new(DialogLayer::new(app.endpoint.inner.clone()));
    let mut incoming = app.endpoint.incoming_transactions()?;
    let router_layer = layer.clone();
    let tasks = app.tasks.clone();
    let calls = app.calls.clone();
    let contact = app.uri.clone();
    let target = app.config.target.clone();
    app.tasks.spawn("B2BUA router", async move {
        while let Some(mut tx) = incoming.recv().await {
            if let Some(dialog) = router_layer.match_dialog(&tx) {
                tasks.spawn("dialog request", drive(dialog, tx));
            } else if tx.original.method == Method::Invite
                && tx.original.to_header()?.tag()?.is_none()
            {
                if !tx.original.body.is_empty() {
                    start_call(
                        tx,
                        router_layer.clone(),
                        contact.clone(),
                        target.clone(),
                        calls.clone(),
                        tasks.clone(),
                    )?;
                } else {
                    tx.reply(StatusCode::NotAcceptableHere).await?;
                }
            } else if tx.original.method != Method::Ack {
                tx.reply(StatusCode::CallTransactionDoesNotExist).await?;
            }
        }
        Ok(())
    });
    app.run(move || layer.len()).await
}

async fn drive(mut dialog: Dialog, mut tx: Transaction) -> AppResult {
    dialog.handle(&mut tx).await?;
    if tx.transaction_type == TransactionType::ServerInvite
        && matches!(
            tx.state,
            TransactionState::Completed | TransactionState::Confirmed
        )
    {
        while tx.receive().await.is_some() {}
    }
    Ok(())
}

enum Event {
    State(DialogState),
    Final(InviteAsyncResult),
}

fn start_call(
    tx: Transaction,
    layer: Arc<DialogLayer>,
    contact: Uri,
    target: Uri,
    calls: Calls,
    tasks: Tasks,
) -> AppResult {
    let (states, mut receiver) = layer.new_dialog_state_channel();
    let a = layer.get_or_create_server_invite(&tx, states.clone(), None, Some(contact.clone()))?;
    let a_id = a.id().call_id.to_string();
    let (b, invite_task) = layer.do_invite_async(
        InviteOption {
            caller: tx.original.from_header()?.uri()?,
            callee: target,
            contact,
            offer: Some(tx.original.body.clone()),
            content_type: tx.original.headers.iter().find_map(|h| match h {
                Header::ContentType(value) => Some(value.value().to_owned()),
                _ => None,
            }),
            ..Default::default()
        },
        states,
    )?;
    calls.add(a_id.clone());
    tasks.event(format!("BRIDGE {} {}", a_id, b.id().call_id));
    let (events, event_rx) = mpsc::unbounded_channel();
    let state_events = events.clone();
    let state_tasks = tasks.clone();
    tasks.spawn("dialog events", async move {
        while let Some(state) = receiver.recv().await {
            state_tasks.event(format!("STATE {state:?}"));
            if state_events.send(Event::State(state)).is_err() {
                break;
            }
        }
        Ok(())
    });
    tasks.spawn("outgoing INVITE", async move {
        let result = invite_task.await?;
        events
            .send(Event::Final(result))
            .map_err(|_| "Bridge stopped before the INVITE completed")?;
        Ok(())
    });
    tasks.spawn("initial dialog", drive(Dialog::Invite(a.clone()), tx));
    let actor_tasks = tasks.clone();
    tasks.spawn("bridge", async move {
        bridge(a, b, event_rx, layer, calls, actor_tasks).await
    });
    Ok(())
}

fn body_headers(response: &Response) -> Option<Vec<Header>> {
    response.headers.iter().find_map(|h| match h {
        Header::ContentType(_) => Some(vec![h.clone()]),
        _ => None,
    })
}

async fn bridge(
    a: InviteDialog,
    b: InviteDialog,
    mut events: mpsc::UnboundedReceiver<Event>,
    layer: Arc<DialogLayer>,
    calls: Calls,
    tasks: Tasks,
) -> AppResult {
    let a_call_id = a.id().call_id.to_string();
    let mut a_ended = false;
    let mut b_ended = false;
    let mut invite_done = false;
    let mut end_a_after_ack = false;
    while let Some(event) = events.recv().await {
        match event {
            Event::State(DialogState::Early(id, response))
                if id.call_id != a_call_id && !a_ended =>
            {
                a.ringing(
                    body_headers(&response),
                    (!response.body.is_empty()).then_some(response.body),
                )?;
            }
            Event::Final(result) => {
                invite_done = true;
                let (_, response) = result?;
                let response = response.ok_or("Outgoing INVITE ended without a final response")?;
                if !a_ended {
                    if response.status_code.code() < 300 {
                        a.accept(body_headers(&response), Some(response.body))?;
                        if b_ended {
                            end_a_after_ack = true;
                        }
                    } else {
                        a.reject(Some(response.status_code), None)?;
                    }
                } else if matches!(b.state(), DialogState::Confirmed(..)) {
                    b.bye().await?;
                }
            }
            Event::State(DialogState::Confirmed(id, _))
                if id.call_id == a_call_id && end_a_after_ack =>
            {
                end_a_after_ack = false;
                a.bye().await?;
            }
            Event::State(DialogState::Terminated(id, _)) => {
                layer.remove_dialog(&id);
                if id.call_id == a_call_id {
                    a_ended = true;
                    if !b_ended {
                        b.hangup().await?;
                    }
                } else {
                    b_ended = true;
                    if !a_ended {
                        match a.state() {
                            DialogState::Confirmed(..) => a.bye().await?,
                            DialogState::WaitAck(..) => end_a_after_ack = true,
                            _ => {} // The final response decides how to end the early A leg.
                        }
                    }
                }
            }
            _ => {}
        }
        if a_ended && b_ended && invite_done {
            calls.remove(&a_call_id);
            tasks.event(format!("ENDED {a_call_id}"));
            return Ok(());
        }
    }
    Err("Bridge event channel closed with live legs".into())
}
