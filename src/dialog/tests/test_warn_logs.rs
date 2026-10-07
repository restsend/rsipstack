//! WARN records carry metadata only; the whole SIP message is logged below WARN.
use crate::dialog::dialog::{DialogInner, DialogState};
use crate::dialog::{client_dialog::ClientInviteDialog, invite_dialog::InviteDialog};
use crate::dialog::{server_dialog::ServerInviteDialog, DialogId};
use crate::sip::{Request, SipMessage, Uri};
use crate::transaction::{endpoint::TargetLocator, key::TransactionRole};
use crate::transport::{SipAddr, TransportLayer};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::unbounded_channel;
use tracing::{field::Field, span, Event, Level, Metadata, Subscriber};

const MARKER: &str = "private-marker";

/// Records every event as (level, " field=value ...").
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<(Level, String)>>>);

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut line = String::new();
        event.record(&mut |f: &Field, v: &dyn std::fmt::Debug| {
            line.push_str(&format!(" {}={:?}", f.name(), v))
        });
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), line));
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

impl Capture {
    fn lines(&self, level: Level, needle: &str) -> Vec<String> {
        let records = self.0.lock().unwrap();
        let hits = records
            .iter()
            .filter(|(l, s)| *l == level && s.contains(needle));
        hits.map(|(_, s)| s.clone()).collect()
    }
}

/// Fails every lookup, so `Transaction::send` returns an error.
struct NoRoute;

#[async_trait::async_trait]
impl TargetLocator for NoRoute {
    async fn locate(&self, _: &Uri) -> crate::Result<SipAddr> {
        Err(crate::Error::Error("no route".to_string()))
    }
}

/// A request or response whose From carries `MARKER`.
fn message(start_line: &str, cseq: &str) -> SipMessage {
    let text = format!(
        "{start_line}\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKwarn\r\nCSeq: {cseq}\r\n\
         From: \"{MARKER}\" <sip:{MARKER}@example.com>;tag=a\r\n\
         To: <sip:bob@example.com>;tag=b\r\nCall-ID: warn-call\r\n\r\n"
    );
    SipMessage::try_from(text.as_str()).unwrap()
}

fn request(method: &str, cseq: u32) -> Request {
    let start_line = format!("{method} sip:bob@127.0.0.1:5999 SIP/2.0");
    match message(&start_line, &format!("{cseq} {method}")) {
        SipMessage::Request(req) => req,
        other => panic!("{other:?}"),
    }
}

/// A UAC dialog on an endpoint whose every request send fails.
fn dialog() -> crate::Result<Arc<DialogInner>> {
    let endpoint = crate::EndpointBuilder::new()
        .with_transport_layer(TransportLayer::new(Default::default()))
        .with_target_locator(Box::new(NoRoute))
        .build();
    let id = DialogId {
        call_id: "warn-call".to_string(),
        local_tag: "a".to_string(),
        remote_tag: "b".to_string(),
    };
    let (state_tx, _) = unbounded_channel();
    let (tu_tx, _) = unbounded_channel();
    let invite = request("INVITE", 1);
    let inner = DialogInner::new(
        TransactionRole::Client,
        id,
        invite,
        endpoint.inner.clone(),
        state_tx,
        None,
        None,
        tu_tx,
    )?;
    Ok(Arc::new(inner))
}

#[tokio::test]
async fn test_failed_request_send_warns_without_the_request() -> crate::Result<()> {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let inner = dialog()?;

    // send_dialog_request, then send_prack_request.
    assert!(inner.do_request(request("INFO", 2)).await.is_err());
    assert!(inner.send_prack_request(request("PRACK", 3)).await.is_err());

    let warns = capture.lines(Level::WARN, "failed to send request");
    assert_eq!(warns.len(), 2, "{warns:?}");
    assert!(warns.iter().all(|w| !w.contains(MARKER)), "{warns:?}");
    assert!(warns[0].contains("method=INFO") && warns[1].contains("method=PRACK"));
    let debugs = capture.lines(Level::DEBUG, "request that failed to send");
    assert_eq!(debugs.len(), 2, "{debugs:?}");
    assert!(debugs.iter().all(|d| d.contains(MARKER)), "{debugs:?}");
    Ok(())
}

#[tokio::test]
async fn test_bye_in_early_state_warns_without_the_response() -> crate::Result<()> {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let inner = dialog()?;
    let SipMessage::Response(ringing) = message("SIP/2.0 180 Ringing", "1 INVITE") else {
        unreachable!()
    };
    inner.transition(DialogState::Early(inner.id.lock().clone(), ringing))?;

    let errors = [
        ClientInviteDialog {
            inner: inner.clone(),
        }
        .bye()
        .await,
        InviteDialog {
            inner: inner.clone(),
        }
        .bye()
        .await,
        ServerInviteDialog { inner }.bye().await,
    ];
    for e in errors {
        let e = e.expect_err("BYE in Early must fail").to_string();
        assert!(e.contains("(Early)") && !e.contains(MARKER), "{e}");
    }
    let warns = capture.lines(Level::WARN, "bye skipped");
    assert_eq!(warns.len(), 3, "{warns:?}");
    assert!(warns.iter().all(|w| !w.contains(MARKER)), "{warns:?}");
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn test_websocket_parse_failure_warns_without_the_message() -> crate::Result<()> {
    use crate::transport::{stream::StreamConnection, websocket::WebSocketConnection};
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::{handshake::server::Response, Message};

    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let sip = |_: &_, mut resp: Response| {
            let headers = resp.headers_mut();
            headers.insert("sec-websocket-protocol", "sip".parse().unwrap());
            Ok(resp)
        };
        let mut ws = tokio_tungstenite::accept_hdr_async(stream, sip)
            .await
            .unwrap();
        let text = format!("NOT SIP <sip:{MARKER}@example.com>\r\n\r\n");
        ws.send(Message::Text(text.into())).await.unwrap();
        ws.close(None).await.ok();
    });
    let remote = SipAddr::new(crate::sip::transport::Transport::Ws, addr.into());
    let conn = WebSocketConnection::connect(&remote, None).await?;
    conn.serve_loop(unbounded_channel().0).await?;

    let warns = capture.lines(Level::WARN, "Error parsing SIP message");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(!warns[0].contains(MARKER), "{warns:?}");
    assert!(warns[0].contains("len="));
    // Still logged, below WARN, when it is received.
    assert!(!capture.lines(Level::INFO, MARKER).is_empty());
    Ok(())
}
