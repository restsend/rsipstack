//! UDP SIP signaling probe; it does not run an RTP/media engine.
//! Usage: prack_probe LISTEN FROM CALLEE CONTACT SDP_FILE [--require]
//! Supply an SDP offer prepared for the peer's media capabilities.
use async_trait::async_trait;
use rsipstack::dialog::{
    authenticate::Credential,
    dialog_layer::DialogLayer,
    invitation::InviteOption,
    reliable::{
        IncomingPrack, PrackBody, PrackHandler, ReliableProvisionalConfig, ReliableResponse,
        SdpKind,
    },
    DialogId,
};
use rsipstack::sip::{Request, Response, StatusCodeKind};
use rsipstack::transport::{udp::UdpConnection, TransportLayer};
use rsipstack::{EndpointBuilder, Result};
use std::{env, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

struct Media {
    sdp: Vec<u8>,
}
#[async_trait]
impl PrackHandler for Media {
    async fn on_reliable_response(&self, event: ReliableResponse) -> Result<Option<PrackBody>> {
        eprintln!(
            "reliable {}: {:?}, dialog {}",
            event.response.status_code, event.sdp_kind, event.dialog_id
        );
        Ok((event.sdp_kind == SdpKind::Offer).then(|| PrackBody::sdp(self.sdp.clone())))
    }
    async fn on_prack(&self, event: IncomingPrack) -> Result<Option<PrackBody>> {
        eprintln!("incoming PRACK: {:?}", event.sdp_kind);
        Ok((event.sdp_kind == SdpKind::Offer).then(|| PrackBody::sdp(self.sdp.clone())))
    }
    async fn on_prack_result(&self, _: Request, response: Option<Response>) {
        eprintln!(
            "PRACK result: {}",
            response
                .map(|r| r.status_code.to_string())
                .unwrap_or_else(|| "timeout".into())
        );
    }
    async fn on_error(&self, id: DialogId, message: String) {
        eprintln!("100rel error ({id}): {message}");
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() < 5 || args.iter().any(|a| a == "--help") {
        eprintln!("Usage: prack_probe LISTEN FROM CALLEE CONTACT SDP_FILE [--require]\nSends one real SIP call and BYE after answer. SDP must be prepared for the peer; no RTP is sent.");
        return Ok(());
    }
    for flag in &args[5..] {
        if flag != "--require" {
            return Err(format!("Unknown option: {flag}").into());
        }
    }
    let media = Arc::new(Media {
        sdp: std::fs::read(&args[4])?,
    });
    if media.sdp.is_empty() {
        return Err("SDP file is empty".into());
    }
    let token = CancellationToken::new();
    let transport = TransportLayer::new(token.child_token());
    let udp =
        UdpConnection::create_connection(args[0].parse()?, None, Some(token.child_token())).await?;
    transport.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_transport_layer(transport)
        .with_cancel_token(token.child_token())
        .build();
    let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    layer.set_reliable_provisional(Some(ReliableProvisionalConfig {
        handler: media.clone(),
        require: args.iter().any(|a| a == "--require"),
    }));
    let mut incoming = endpoint.incoming_transactions()?;
    let router = layer.clone();
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            if let Some(mut dialog) = router.match_dialog(&tx) {
                tokio::spawn(async move { dialog.handle(&mut tx).await });
            } else {
                tx.reply(rsipstack::sip::StatusCode::CallTransactionDoesNotExist)
                    .await
                    .ok();
            }
        }
    });
    let server = endpoint.inner.clone();
    tokio::spawn(async move { server.serve().await });
    let credential = match (env::var("SIP_USERNAME"), env::var("SIP_PASSWORD")) {
        (Ok(username), Ok(password)) => Some(Credential {
            username,
            password,
            realm: env::var("SIP_REALM").ok(),
            auth_username: None,
        }),
        (Err(_), Err(_)) => None,
        _ => return Err("Set both SIP_USERNAME and SIP_PASSWORD".into()),
    };
    let option = InviteOption {
        caller: args[1].as_str().try_into()?,
        callee: args[2].as_str().try_into()?,
        contact: args[3].as_str().try_into()?,
        offer: Some(media.sdp.clone()),
        credential,
        ..Default::default()
    };
    let (states, mut events) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            eprintln!("{event}");
        }
    });
    let (dialog, mut join) = layer.do_invite_async(option, states)?;
    let (_, result) = match tokio::time::timeout(Duration::from_secs(60), &mut join).await {
        Ok(result) => result??,
        Err(_) => {
            dialog.cancel().await?;
            let _ = tokio::time::timeout(Duration::from_secs(35), &mut join).await;
            token.cancel();
            return Err("Call setup timed out; CANCEL requested".into());
        }
    };
    if let Some(response) = result {
        eprintln!("INVITE result: {}", response.status_code);
        if response.status_code.kind() == StatusCodeKind::Successful {
            tokio::time::sleep(Duration::from_secs(2)).await;
            dialog.bye().await?;
        }
    }
    layer.remove_dialog(&dialog.id());
    token.cancel();
    Ok(())
}
