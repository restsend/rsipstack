//! Stream connection idle-timeout behavior: half-open peers (vanished without
//! FIN) must be reaped after the configured idle timeout, while live peers
//! exchanging keepalives must survive. `Duration::ZERO` keeps the legacy
//! blocking-read behavior.

use std::time::Duration;

use tokio::{net::TcpListener, sync::mpsc::unbounded_channel, time::timeout};

use crate::{
    platform::CancellationToken,
    sip::transport::Transport,
    transport::{
        stream::StreamConnection, tcp::TcpConnection, SipAddr, SipConnection, TransportEvent,
        TransportLayer,
    },
};

const IDLE: Duration = Duration::from_millis(300);

/// Spawn a peer that accepts one connection and then holds the socket
/// silently (never reads, writes, or closes) — simulating a half-open peer.
/// Returns the listener address to connect to.
async fn silent_peer_listener() -> SipAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_sock, _) = listener.accept().await.unwrap();
        // Hold the socket open without any traffic for the duration of the test.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    SipAddr::new(Transport::Tcp, addr.into())
}

/// Spawn a peer that accepts one connection on `listener` and keeps it alive
/// by sending a keepalive every 100 ms.
async fn keepalive_peer(listener: TcpListener) {
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        loop {
            use tokio::io::AsyncWriteExt;
            if sock.write_all(b"\r\n\r\n").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

#[tokio::test]
async fn idle_timeout_closes_silent_connection() {
    let remote = silent_peer_listener().await;

    let conn = TcpConnection::connect(&remote, None).await.unwrap();
    let started = std::time::Instant::now();
    let result = conn.serve_loop(unbounded_channel().0, IDLE).await.unwrap();
    let _ = result;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "idle timeout did not fire promptly, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn traffic_keeps_connection_alive() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    keepalive_peer(listener).await;
    let remote = SipAddr::new(Transport::Tcp, addr.into());

    let conn = TcpConnection::connect(&remote, None).await.unwrap();
    let mut serve = std::pin::pin!(conn.serve_loop(unbounded_channel().0, IDLE));
    // 1s of steady keepalive traffic with a 300ms idle timeout: the loop
    // must still be running.
    let res = timeout(Duration::from_secs(1), serve.as_mut()).await;
    assert!(
        res.is_err(),
        "serve_loop exited despite keepalive traffic: {:?}",
        res
    );
}

#[tokio::test]
async fn zero_timeout_disables_idle_reaping() {
    let remote = silent_peer_listener().await;
    let conn = TcpConnection::connect(&remote, None).await.unwrap();

    let mut serve = std::pin::pin!(conn.serve_loop(unbounded_channel().0, Duration::ZERO));
    let res = timeout(Duration::from_millis(700), serve.as_mut()).await;
    assert!(
        res.is_err(),
        "idle reaping fired despite Duration::ZERO (disabled)"
    );
}

#[tokio::test]
async fn transport_layer_retires_idle_connection() {
    let remote = silent_peer_listener().await;

    let tl = TransportLayer::new(CancellationToken::new());
    tl.set_stream_idle_timeout(IDLE);
    assert_eq!(tl.stream_idle_timeout(), IDLE);

    let conn = TcpConnection::connect(&remote, None).await.unwrap();
    let sip_conn = SipConnection::Tcp(conn.clone());
    tl.add_connection(sip_conn.clone());
    assert_eq!(tl.connections_count(), 1, "connection not tracked");

    tl.inner.serve_connection(sip_conn);

    // Idle timeout (300ms) fires → serve_loop exits → retire_connection
    // removes the entry from the table.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        tl.connections_count(),
        0,
        "idle connection was not retired from the connection table"
    );
}

/// The serve_loop must surface incoming SIP messages while alive (sanity that
/// the timeout wrapping did not break the data path).
#[tokio::test]
async fn serve_loop_still_delivers_messages_under_idle_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let payload = "OPTIONS sip:service@sip.example.com SIP/2.0\r\n\
                   Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKtest\r\n\r\n";
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        use tokio::io::AsyncWriteExt;
        let _ = sock.write_all(payload.as_bytes()).await;
        // Hold briefly so the write lands before teardown.
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    let remote = SipAddr::new(Transport::Tcp, addr.into());

    let conn = TcpConnection::connect(&remote, None).await.unwrap();
    let (tx, mut rx) = unbounded_channel();
    conn.serve_loop(tx, IDLE).await.unwrap();

    match rx.recv().await.unwrap() {
        TransportEvent::Incoming(msg, _, _) => match msg {
            crate::sip::SipMessage::Request(req) => {
                assert_eq!(*req.method(), crate::sip::Method::Options);
            }
            other => panic!("expected a SIP request, got {other:?}"),
        },
        other => panic!("expected Incoming event, got {other:?}"),
    }
}
