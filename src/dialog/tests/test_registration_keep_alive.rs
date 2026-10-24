//! `Registration::keep_alive` refreshes on the expiry the registrar granted,
//! not the one it requested (issue 210). Registrars often grant less than
//! requested, and say so only in the Contact `expires` of the 200 OK.
use crate::dialog::registration::{RefreshOutcome, Registration};
use crate::sip::message::HeadersExt;
use crate::sip::{headers::*, Method, StatusCode, Uri};
use crate::transaction::TransactionReceiver;
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

async fn udp_endpoint(
    token: &CancellationToken,
    ua: &str,
) -> crate::Result<(crate::transaction::endpoint::Endpoint, u16)> {
    let tl = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let port = udp.get_addr().addr.port.map(u16::from).unwrap_or(0);
    tl.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent(ua)
        .with_transport_layer(tl)
        .with_cancel_token(token.child_token())
        .build();
    let inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = inner.serve().await;
    });
    Ok((endpoint, port))
}

/// Registrar: answers every REGISTER with 200 OK, granting `granted` seconds
/// on the echoed Contact. Reports each REGISTER as it arrives.
fn spawn_registrar(mut incoming: TransactionReceiver, granted: u32) -> UnboundedReceiver<()> {
    let (seen_tx, seen_rx) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            if tx.original.method != Method::Register {
                continue;
            }
            let _ = seen_tx.send(());
            let contact = tx
                .original
                .contact_header()
                .expect("REGISTER carries a Contact")
                .typed()
                .expect("parsable Contact");
            let granted = Contact::new(format!("<{}>;expires={granted}", contact.uri));
            tokio::spawn(async move {
                tx.reply_with(StatusCode::OK, vec![granted.into()], None)
                    .await
                    .expect("reply 200");
            });
        }
    });
    seen_rx
}

#[tokio::test]
async fn test_keep_alive_refreshes_on_granted_expiry() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (registrar, registrar_port) = udp_endpoint(&token, "rsipstack-registrar").await?;
    let (ua, _) = udp_endpoint(&token, "rsipstack-ua").await?;
    let mut seen = spawn_registrar(registrar.incoming_transactions()?, 2);

    // Ask for 240 s; the registrar grants 2 s, so the next REGISTER is due
    // after 1 s (75%, floored), not after 180 s.
    let server = Uri::try_from(format!("sip:127.0.0.1:{registrar_port}").as_str())?;
    let mut registration = Registration::new(ua.inner.clone(), None);
    let keep_alive_token = token.child_token();
    let (outcome_tx, mut outcome_rx) = unbounded_channel();
    tokio::spawn(async move {
        registration
            .keep_alive(server, 240, keep_alive_token, |outcome| {
                let _ = outcome_tx.send(matches!(outcome, RefreshOutcome::Registered(_)));
            })
            .await;
    });

    for n in 1..=2 {
        tokio::time::timeout(Duration::from_secs(3), seen.recv())
            .await
            .unwrap_or_else(|_| panic!("REGISTER #{n} not sent on the granted expiry"));
        let registered = tokio::time::timeout(Duration::from_secs(3), outcome_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("no outcome for REGISTER #{n}"));
        assert_eq!(registered, Some(true), "REGISTER #{n} should succeed");
    }

    token.cancel();
    Ok(())
}
