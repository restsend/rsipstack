//! Public storage hooks must observe final responses and refreshed targets before ACK.
use rsipstack::{
    dialog::{
        dialog::{Dialog, DialogSnapshot, DialogSnapshotState},
        dialog_layer::DialogLayer,
        invitation::InviteOption,
        invite_dialog::InviteDialog,
        persistence::{
            DialogCheckpoint, DialogCheckpointReason, DialogPersistence, DialogPersistenceConfig,
        },
        reinvite::ReinviteOptions,
        DialogId,
    },
    sip::{Header, HeadersExt, Method, Request, SipMessage, StatusCode, ToTypedHeader},
    transaction::key::TransactionRole,
    transaction::EndpointBuilder,
    transport::{udp::UdpConnection, TransportLayer},
};
use std::{sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(2);

struct Storage {
    checkpoints: mpsc::UnboundedSender<DialogCheckpoint>,
    release: CancellationToken,
    fail: bool,
}
#[async_trait::async_trait]
impl DialogPersistence for Storage {
    async fn save(&self, checkpoint: DialogCheckpoint) -> rsipstack::Result<()> {
        let wait = checkpoint.reason == DialogCheckpointReason::BeforeAck;
        self.checkpoints.send(checkpoint).ok();
        if wait {
            self.release.cancelled().await;
            if self.fail {
                return Err(rsipstack::Error::Error("injected write failure".into()));
            }
        }
        Ok(())
    }
}
struct Stop(CancellationToken);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn boundary(role: Option<TransactionRole>, status: StatusCode, fail: bool) -> Result<()> {
    let stop = Stop(CancellationToken::new());
    let transport = TransportLayer::new(stop.0.clone());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, Some(stop.0.clone()))
        .await?;
    let local = udp.get_addr().get_socketaddr()?;
    transport.add_transport(udp.into());
    let endpoint = Arc::new(
        EndpointBuilder::new()
            .with_transport_layer(transport)
            .with_cancel_token(stop.0.clone())
            .build(),
    );
    let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let (sender, mut checkpoints) = mpsc::unbounded_channel();
    let storage = Arc::new(Storage {
        checkpoints: sender,
        release: CancellationToken::new(),
        fail,
    });
    layer.set_persistence(Some(DialogPersistenceConfig::new(storage.clone())))?;
    let serving = endpoint.clone();
    tokio::spawn(async move { serving.serve().await });
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let refreshed = UdpSocket::bind("127.0.0.1:0").await?;
    let target = format!("sip:peer@{}", peer.local_addr()?);
    let new_target = format!("sip:refreshed@{}", refreshed.local_addr()?);
    let (states, _events) = mpsc::unbounded_channel();
    let dialog: InviteDialog;
    if let Some(role) = role {
        let local_uri = format!("<sip:local@{local}>;tag=local");
        let remote_uri = format!("<{target}>;tag=remote");
        let (from, to) = if role == TransactionRole::Client {
            (local_uri, remote_uri)
        } else {
            (remote_uri, local_uri)
        };
        let snapshot = DialogSnapshot::builder(
            DialogId {
                call_id: "checkpoints".into(),
                local_tag: "local".into(),
                remote_tag: "remote".into(),
            },
            role,
            rsipstack::sip::From::from(from).typed()?,
            rsipstack::sip::To::from(to).typed()?,
            target.as_str().try_into()?,
        )
        .state(DialogSnapshotState::Confirmed)
        .local_cseq(1)
        .remote_cseq(1)
        .runtime(Default::default())
        .local_contact(Some(format!("sip:local@{local}").as_str().try_into()?))
        .remote_contact(Some(format!("<{target}>").into()))
        .build()?;
        let id = snapshot.id.clone();
        assert!(layer.restore_from_snapshot(snapshot, states)?);
        let Some(Dialog::Invite(d)) = layer.get_dialog(&id) else {
            panic!("missing restored dialog")
        };
        dialog = d;
        let request = dialog.prepare_reinvite(None, Some(b"v=0\r\n".to_vec()))?;
        let operation = dialog.clone();
        tokio::spawn(async move {
            operation
                .send_reinvite(request, ReinviteOptions::default())
                .await
        });
    } else {
        let (d, _task) = layer.do_invite_async(
            InviteOption {
                caller: "sip:local@example.com".try_into()?,
                callee: target.as_str().try_into()?,
                contact: format!("sip:local@{local}").as_str().try_into()?,
                ..Default::default()
            },
            states,
        )?;
        dialog = d;
    }
    let mut bytes = [0; 8192];
    let (n, source) = tokio::time::timeout(WAIT, peer.recv_from(&mut bytes)).await??;
    let invite: Request = SipMessage::try_from(&bytes[..n])?.try_into()?;
    assert_eq!(invite.method, Method::Invite);
    let mut response = endpoint.inner.make_response(&invite, status.clone(), None);
    if role.is_none() {
        response
            .headers
            .unique_push(Header::To(format!("<{target}>;tag=remote").into()));
    }
    response
        .headers
        .push(Header::Contact(format!("<{new_target}>").into()));
    response.headers.push(Header::Reason(
        "SIP;cause=488;text=\"response must be durable\"".into(),
    ));
    peer.send_to(response.to_string().as_bytes(), source)
        .await?;
    let checkpoint = tokio::time::timeout(WAIT, async {
        loop {
            let c = checkpoints.recv().await.expect("storage channel closed");
            if c.reason == DialogCheckpointReason::BeforeAck {
                break c;
            }
        }
    })
    .await?;
    assert_eq!(
        checkpoint.message,
        Some(SipMessage::Response(response.clone()))
    );
    if role.is_some() {
        assert_eq!(
            checkpoint.snapshot.remote_uri.to_string(),
            if status == StatusCode::OK {
                new_target.clone()
            } else {
                target.clone()
            }
        );
        assert!(checkpoint.snapshot.runtime.pending.negotiations > 0);
    }
    let ack_peer = if status == StatusCode::OK {
        &refreshed
    } else {
        &peer
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(40), ack_peer.recv_from(&mut bytes))
            .await
            .is_err(),
        "ACK escaped before commit"
    );
    storage.release.cancel();
    if fail {
        tokio::time::timeout(WAIT, async {
            while dialog.persistence_status().unwrap().failure.is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(80), ack_peer.recv_from(&mut bytes))
                .await
                .is_err(),
            "failed checkpoint still sent ACK"
        );
    } else {
        let (n, _) = tokio::time::timeout(WAIT, ack_peer.recv_from(&mut bytes)).await??;
        let ack: Request = SipMessage::try_from(&bytes[..n])?.try_into()?;
        assert_eq!(ack.method, Method::Ack);
        assert_eq!(ack.cseq_header()?.seq()?, invite.cseq_header()?.seq()?);
    }
    Ok(())
}
#[tokio::test]
async fn initial_rejection_is_committed_before_ack() -> Result<()> {
    boundary(None, StatusCode::NotAcceptableHere, false).await
}
#[tokio::test]
async fn rejected_reinvite_keeps_previous_target_before_ack() -> Result<()> {
    boundary(
        Some(TransactionRole::Client),
        StatusCode::NotAcceptableHere,
        false,
    )
    .await
}
#[tokio::test]
async fn uac_refresh_target_is_committed_before_ack() -> Result<()> {
    boundary(Some(TransactionRole::Client), StatusCode::OK, false).await
}
#[tokio::test]
async fn uas_refresh_target_is_committed_before_ack() -> Result<()> {
    boundary(Some(TransactionRole::Server), StatusCode::OK, false).await
}
#[tokio::test]
async fn failed_rejection_checkpoint_prevents_ack() -> Result<()> {
    boundary(None, StatusCode::NotAcceptableHere, true).await
}
