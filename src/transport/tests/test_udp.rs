use crate::{
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        udp::{UdpConnection, UdpInner},
        SipAddr, TransportEvent,
    },
    Result,
};
use std::time::Duration;
use tokio::{select, sync::mpsc::unbounded_channel, time::sleep};

#[tokio::test]
async fn test_udp_keepalive() -> Result<()> {
    let peer_bob = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let peer_alice = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (alice_tx, _) = unbounded_channel::<TransportEvent>();

    let bob_loop = async {
        sleep(Duration::from_millis(20)).await; // wait for serve_loop to start
                                                // send keep alive
        peer_bob
            .send_raw(KEEPALIVE_REQUEST, peer_alice.get_addr())
            .await
            .expect("send_raw");
        // wait for keep alive response
        let buf = &mut [0u8; 2048];
        let (n, _) = peer_bob.recv_raw(buf).await.expect("recv_raw");
        assert_eq!(&buf[..n], KEEPALIVE_RESPONSE);
    };

    select! {
        _ = peer_alice.serve_loop(alice_tx) => {
            assert!(false, "serve_loop exited");
        }
        _ = bob_loop => {}
        _= sleep(Duration::from_millis(200)) => {
            assert!(false, "timeout waiting for keep alive response");
        }
    };
    Ok(())
}

#[tokio::test]
async fn test_udp_recv_sip_message() -> Result<()> {
    let peer_bob = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let peer_alice = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (alice_tx, _) = unbounded_channel();
    let (bob_tx, mut bob_rx) = unbounded_channel();

    let send_loop = async {
        sleep(Duration::from_millis(20)).await; // wait for serve_loop to start
        let msg_1 = "REGISTER sip:bob@restsend.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bKnashd92\r\nCSeq: 1 REGISTER\r\n\r\n";
        peer_alice
            .send_raw(msg_1.as_bytes(), peer_bob.get_addr())
            .await
            .expect("send_raw");
        sleep(Duration::from_secs(3)).await;
    };

    select! {
        _ = peer_alice.serve_loop(alice_tx) => {
            assert!(false, "alice serve_loop exited");
        }
        _ = peer_bob.serve_loop(bob_tx) => {
            assert!(false, "bob serve_loop exited");
        }
        _ = send_loop => {
            assert!(false, "send_loop exited");
        }
        event = bob_rx.recv() => {
            match event {
                Some(TransportEvent::Incoming(msg, connection, from)) => {
                    assert!(msg.is_request());
                    assert_eq!(from, peer_alice.get_addr().to_owned());
                    assert_eq!(connection.get_addr(), peer_bob.get_addr());
                }
                _ => {
                    assert!(false, "unexpected event");
                }
            }
        }
        _= sleep(Duration::from_millis(500)) => {
            assert!(false, "timeout waiting");
        }
    };
    Ok(())
}

#[tokio::test]
async fn test_udp_learns_public_addr_from_response_when_external_not_configured() -> Result<()> {
    let peer = UdpConnection::create_connection_with_auto_learn_public_addr(
        "127.0.0.1:0".parse()?,
        None,
        None,
        true,
    )
    .await?;
    let remote = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (tx, mut rx) = unbounded_channel();

    let remote_public_port = 62000u16;
    let response = format!(
        "SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1;rport={};received=198.51.100.10\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: abc\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
        remote_public_port
    );

    let peer_addr = peer.get_addr().to_owned();
    tokio::spawn(async move {
        sleep(Duration::from_millis(20)).await;
        remote
            .send_raw(response.as_bytes(), &peer_addr)
            .await
            .expect("send_raw");
    });

    select! {
        _ = peer.serve_loop(tx) => {
            assert!(false, "peer serve_loop exited");
        }
        event = rx.recv() => {
            match event {
                Some(TransportEvent::Incoming(msg, _, _)) => {
                    assert!(msg.is_response());
                    assert_eq!(
                        peer.get_contact_addr().to_string(),
                        format!("UDP 198.51.100.10:{}", remote_public_port)
                    );
                }
                _ => assert!(false, "unexpected event"),
            }
        }
        _ = sleep(Duration::from_millis(500)) => {
            assert!(false, "timeout waiting");
        }
    };

    Ok(())
}

#[tokio::test]
async fn test_udp_contact_prefers_configured_external_addr() -> Result<()> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    let peer = UdpConnection::attach_with_auto_learn_public_addr(
        UdpInner {
            conn: socket,
            addr: SipAddr::from(local_addr),
            learned_public_addr: arc_swap::ArcSwapOption::empty(),
            auto_learn_public_addr: false,
        },
        Some("203.0.113.10:5060".parse()?),
        None,
        true,
    )
    .await;
    let remote = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (tx, mut rx) = unbounded_channel();

    let response = "SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1;rport=62000;received=198.51.100.10\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: abc\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";

    let peer_local_addr = SipAddr::from(local_addr);
    tokio::spawn(async move {
        sleep(Duration::from_millis(20)).await;
        remote
            .send_raw(response.as_bytes(), &peer_local_addr)
            .await
            .expect("send_raw");
    });

    select! {
        _ = peer.serve_loop(tx) => {
            assert!(false, "peer serve_loop exited");
        }
        event = rx.recv() => {
            match event {
                Some(TransportEvent::Incoming(msg, _, _)) => {
                    assert!(msg.is_response());
                    assert_eq!(peer.get_contact_addr().to_string(), "UDP 203.0.113.10:5060");
                }
                _ => assert!(false, "unexpected event"),
            }
        }
        _ = sleep(Duration::from_millis(500)) => {
            assert!(false, "timeout waiting");
        }
    };

    Ok(())
}

#[tokio::test]
async fn test_udp_does_not_learn_public_addr_by_default() -> Result<()> {
    let peer = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let remote = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (tx, mut rx) = unbounded_channel();

    let local_contact_before = peer.get_contact_addr();
    let response = "SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1;rport=62000;received=198.51.100.10\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: abc\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";

    let peer_addr = peer.get_addr().to_owned();
    tokio::spawn(async move {
        sleep(Duration::from_millis(20)).await;
        remote
            .send_raw(response.as_bytes(), &peer_addr)
            .await
            .expect("send_raw");
    });

    select! {
        _ = peer.serve_loop(tx) => {
            assert!(false, "peer serve_loop exited");
        }
        event = rx.recv() => {
            match event {
                Some(TransportEvent::Incoming(msg, _, _)) => {
                    assert!(msg.is_response());
                    assert_eq!(peer.get_contact_addr(), local_contact_before);
                }
                _ => assert!(false, "unexpected event"),
            }
        }
        _ = sleep(Duration::from_millis(500)) => {
            assert!(false, "timeout waiting");
        }
    };

    Ok(())
}
