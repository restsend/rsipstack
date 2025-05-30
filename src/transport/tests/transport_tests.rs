use crate::{
    transport::{
        connection::TransportEvent, stream::StreamConnection, tcp::TcpConnection,
        transport_layer::TransportConfig, TransportLayer,
    },
    Result,
};
use rsip::{SipMessage, Transport};
use std::time::Duration;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Test TCP client and server
#[tokio::test]
async fn test_tcp_client_server() -> Result<()> {
    // Create transport layer
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());

    // Create event channel
    let (sender, mut receiver) = mpsc::unbounded_channel();

    // Create TCP listener
    let server_addr = transport_layer
        .add_tcp_listener("127.0.0.1:0".parse()?, sender.clone())
        .await?;
    info!("Created TCP server on {}", server_addr);

    // Start transport layer
    transport_layer.serve_listens(sender.clone()).await?;

    // Create TCP client connection
    let client_connection = TcpConnection::connect(&server_addr).await?;
    info!("Created TCP client connection: {}", client_connection);

    // Send test message
    let test_message = "REGISTER sip:example.com SIP/2.0\r\n\
                        Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
                        From: <sip:alice@example.com>;tag=test\r\n\
                        To: <sip:alice@example.com>\r\n\
                        Call-ID: test-call-id\r\n\
                        CSeq: 1 REGISTER\r\n\
                        Contact: <sip:alice@127.0.0.1:5060>\r\n\
                        Max-Forwards: 70\r\n\
                        Content-Length: 0\r\n\r\n";

    let sip_message = SipMessage::try_from(test_message)?;
    client_connection.send_message(sip_message.clone()).await?;

    // Wait for message
    let event = wait_for_event(&mut receiver).await?;
    info!("Received event: {:?}", event);
    match event {
        TransportEvent::Incoming(msg, _conn, addr) => {
            assert_eq!(msg.to_string(), sip_message.to_string());
            assert_eq!(addr.r#type, Some(Transport::Tcp));
        }
        TransportEvent::Closed(_conn) => {
            info!("Connection closed by the server");
        }
        TransportEvent::New(_conn) => {
            info!("Connection created");
        }
    }

    // Close connection
    client_connection.close().await?;
    cancel_token.cancel();

    Ok(())
}

/// Wait for event with timeout
async fn wait_for_event(
    receiver: &mut UnboundedReceiver<TransportEvent>,
) -> Result<TransportEvent> {
    match timeout(Duration::from_secs(5), receiver.recv()).await {
        Ok(Some(event)) => Ok(event),
        Ok(None) => Err(crate::Error::Error("Channel closed".to_string())),
        Err(_) => Err(crate::Error::Error("Timeout waiting for event".to_string())),
    }
}

/// Test interoperability between TCP and UDP
#[tokio::test]
#[ignore]
async fn test_tcp_udp_interop() -> Result<()> {
    // Create transport layer
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());

    // Create event channel
    let (sender, mut receiver) = mpsc::unbounded_channel();

    // Create UDP listener
    let udp_addr = transport_layer
        .add_udp_listener("127.0.0.1:0".parse()?)
        .await?;
    info!("Created UDP server on {}", udp_addr);

    // Create TCP listener
    let tcp_addr = transport_layer
        .add_tcp_listener("127.0.0.1:0".parse()?, sender.clone())
        .await?;
    info!("Created TCP server on {}", tcp_addr);

    // Start transport layer
    transport_layer.serve_listens(sender.clone()).await?;

    // Create test message
    let test_message = "REGISTER sip:example.com SIP/2.0\r\n\
                        Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
                        From: <sip:alice@example.com>;tag=test\r\n\
                        To: <sip:alice@example.com>\r\n\
                        Call-ID: test-call-id\r\n\
                        CSeq: 1 REGISTER\r\n\
                        Contact: <sip:alice@127.0.0.1:5060>\r\n\
                        Max-Forwards: 70\r\n\
                        Content-Length: 0\r\n\r\n";

    let sip_message = SipMessage::try_from(test_message)?;

    // Use lookup to find connection
    let uri: rsip::Uri = "sip:example.com;transport=tcp".try_into()?;
    let (connection, _) = transport_layer.lookup(&uri, sender.clone()).await?;

    // Send message
    connection
        .send(sip_message.clone(), Some(&tcp_addr))
        .await?;

    // Wait for message
    let event = wait_for_event(&mut receiver).await?;
    match event {
        TransportEvent::Incoming(msg, _, _) => {
            assert_eq!(msg.to_string(), sip_message.to_string());
        }
        _ => panic!("Expected Incoming event"),
    }

    cancel_token.cancel();

    Ok(())
}

/// Test WebSocket functionality
#[cfg(feature = "websocket")]
#[tokio::test]
//#[ignore] // Requires external WebSocket server to run
async fn test_websocket() -> Result<()> {
    // Create transport layer
    let cancel_token = CancellationToken::new();
    let mut config = TransportConfig::default();
    config.enable_ws = true;

    let transport_layer = TransportLayer::with_config(cancel_token.clone(), config);

    // Create event channel
    let (sender, mut receiver) = mpsc::unbounded_channel();

    // Create WebSocket listener
    let ws_addr = transport_layer
        .add_ws_listener("127.0.0.1:0".parse()?, sender.clone(), false)
        .await?;
    info!("Created WebSocket server on {}", ws_addr);

    // Start transport layer
    //transport_layer.serve_listens(sender.clone()).await?;

    // Create WebSocket client connection
    let uri: rsip::Uri = format!(
        "sip:127.0.0.1:{};transport=ws",
        ws_addr.addr.port.unwrap().value()
    )
    .try_into()?;
    let (connection, _) = transport_layer.lookup(&uri, sender.clone()).await?;

    // Send test message
    let test_message = "REGISTER sip:example.com SIP/2.0\r\n\
                        Via: SIP/2.0/WS 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
                        From: <sip:alice@example.com>;tag=test\r\n\
                        To: <sip:alice@example.com>\r\n\
                        Call-ID: test-call-id\r\n\
                        CSeq: 1 REGISTER\r\n\
                        Contact: <sip:alice@127.0.0.1:5060;transport=ws>\r\n\
                        Max-Forwards: 70\r\n\
                        Content-Length: 0\r\n\r\n";

    let sip_message = SipMessage::try_from(test_message)?;
    connection.send(sip_message.clone(), None).await?;

    // Wait for create
    {
        let event = wait_for_event(&mut receiver).await?;
        match event {
            TransportEvent::New(_sg) => {}
            _ => panic!("Expected New event"),
        }
    }

    // Wait for message
    {
        let event = wait_for_event(&mut receiver).await?;
        match event {
            TransportEvent::Incoming(msg, _, _) => {
                assert_eq!(msg.to_string(), sip_message.to_string());
            }
            _ => panic!("Expected Incoming event"),
        }
    }

    cancel_token.cancel();

    Ok(())
}
