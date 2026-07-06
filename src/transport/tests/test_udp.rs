use crate::{
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        udp::UdpConnection,
        TransportEvent,
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
                    assert_eq!(connection.get_remote_addr(), Some(peer_alice.get_addr()));
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
async fn test_udp_recv_binary_body_sip_message() -> Result<()> {
    let peer_bob = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let peer_alice = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (bob_tx, mut bob_rx) = unbounded_channel();

    let send_loop = async {
        sleep(Duration::from_millis(20)).await;
        let mut datagram = b"MESSAGE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Type: application/isup\r\n\
Content-Length: 3\r\n\r\n"
            .to_vec();
        datagram.extend_from_slice(&[0x00, 0x91, 0x01]);
        assert!(std::str::from_utf8(&datagram).is_err());

        peer_alice
            .send_raw(&datagram, peer_bob.get_addr())
            .await
            .expect("send_raw");
        sleep(Duration::from_secs(3)).await;
    };

    select! {
        _ = peer_bob.serve_loop(bob_tx) => {
            assert!(false, "bob serve_loop exited");
        }
        _ = send_loop => {}
        event = bob_rx.recv() => {
            match event {
                Some(TransportEvent::Incoming(msg, _, from)) => {
                    assert!(msg.is_request());
                    assert_eq!(from, peer_alice.get_addr().to_owned());
                    match msg {
                        crate::sip::SipMessage::Request(req) => {
                            assert_eq!(req.body, vec![0x00, 0x91, 0x01]);
                        }
                        crate::sip::SipMessage::Response(_) => {
                            assert!(false, "expected request");
                        }
                    }
                }
                _ => {
                    assert!(false, "unexpected event");
                }
            }
        }
        _= sleep(Duration::from_millis(500)) => {
            assert!(false, "timeout waiting for binary body message");
        }
    };
    Ok(())
}
