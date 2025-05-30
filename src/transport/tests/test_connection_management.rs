use crate::{
    transport::{
        connection::TransportEvent, stream::StreamConnection, tcp::TcpConnection, TransportLayer,
    },
    Result,
};
use rsip::{
    prelude::{HeadersExt, UntypedHeader},
    SipMessage, Transport,
};
use std::time::Duration;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Test TCP server accept flow
#[tokio::test]
async fn test_tcp_server_accept_flow() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());
    let (sender, mut receiver) = mpsc::unbounded_channel();

    // Create TCP listener
    let server_addr = transport_layer
        .add_tcp_listener("127.0.0.1:0".parse()?, sender.clone())
        .await?;
    info!("Created TCP server on {}", server_addr);

    // Start transport layer
    transport_layer.serve_listens(sender.clone()).await?;

    // Create multiple client connections
    let client1 = TcpConnection::connect(&server_addr).await?;
    let client2 = TcpConnection::connect(&server_addr).await?;
    let client3 = TcpConnection::connect(&server_addr).await?;

    info!("Created 3 client connections");

    // Wait for new connection events
    let mut new_connections = 0;
    for _ in 0..3 {
        match wait_for_event(&mut receiver).await? {
            TransportEvent::New(_conn) => {
                new_connections += 1;
                info!("New connection received: {}", new_connections);
            }
            event => info!("Other event: {:?}", event),
        }
    }

    assert_eq!(new_connections, 3, "Should receive 3 new connection events");

    // Close connections
    client1.close().await?;
    client2.close().await?;
    client3.close().await?;

    cancel_token.cancel();
    Ok(())
}

/// Test multiple clients sending messages simultaneously
#[tokio::test]
async fn test_multiple_client_messages() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());
    let (sender, mut receiver) = mpsc::unbounded_channel();

    // Create TCP listener
    let server_addr = transport_layer
        .add_tcp_listener("127.0.0.1:0".parse()?, sender.clone())
        .await?;

    // Start transport layer
    transport_layer.serve_listens(sender.clone()).await?;

    // Create multiple client connections
    let client1 = TcpConnection::connect(&server_addr).await?;
    let client2 = TcpConnection::connect(&server_addr).await?;

    // Wait for new connection events
    wait_for_event(&mut receiver).await?; // client1 new
    wait_for_event(&mut receiver).await?; // client2 new

    // Send messages from both clients
    let message1 = create_test_message("client1");
    let message2 = create_test_message("client2");

    client1.send_message(message1.clone()).await?;
    client2.send_message(message2.clone()).await?;

    // Wait for incoming messages
    let mut received_messages = Vec::new();
    for _ in 0..2 {
        match wait_for_event(&mut receiver).await? {
            TransportEvent::Incoming(msg, _conn, _addr) => {
                received_messages.push(msg);
            }
            event => info!("Other event: {:?}", event),
        }
    }

    assert_eq!(received_messages.len(), 2, "Should receive 2 messages");

    // Verify messages (order might be different)
    let call_ids: Vec<String> = received_messages
        .iter()
        .map(|msg| match msg {
            SipMessage::Request(req) => req.call_id_header().unwrap().value().to_string(),
            _ => panic!("Expected request"),
        })
        .collect();

    assert!(call_ids.contains(&"client1".to_string()));
    assert!(call_ids.contains(&"client2".to_string()));

    client1.close().await?;
    client2.close().await?;
    cancel_token.cancel();
    Ok(())
}

/// Test lookup mechanism with different protocols
#[tokio::test]
async fn test_transport_lookup() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());
    let (sender, _receiver) = mpsc::unbounded_channel();

    // Test UDP lookup
    let udp_addr = transport_layer
        .add_udp_listener("127.0.0.1:0".parse()?)
        .await?;

    let udp_uri: rsip::Uri = format!(
        "sip:test@{}:{};transport=udp",
        "127.0.0.1",
        udp_addr.addr.port.unwrap().value()
    )
    .try_into()?;

    let (udp_connection, _) = transport_layer.lookup(&udp_uri, sender.clone()).await?;
    assert!(matches!(
        udp_connection.get_addr().r#type,
        Some(Transport::Udp)
    ));

    // Test TCP lookup (should create new connection)
    let tcp_uri: rsip::Uri = "sip:test@127.0.0.1:12345;transport=tcp".try_into()?;

    // This should fail because there's no TCP server on 12345
    let tcp_result = transport_layer.lookup(&tcp_uri, sender.clone()).await;
    assert!(
        tcp_result.is_err(),
        "Should fail to connect to non-existent TCP server"
    );

    cancel_token.cancel();
    Ok(())
}

/// Test connection reuse for UDP
#[tokio::test]
async fn test_udp_connection_reuse() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());
    let (sender, _receiver) = mpsc::unbounded_channel();

    // Create UDP listener
    let udp_addr = transport_layer
        .add_udp_listener("127.0.0.1:0".parse()?)
        .await?;

    // Multiple lookups should return the same connection
    let uri: rsip::Uri = format!(
        "sip:test@{}:{};transport=udp",
        "127.0.0.1",
        udp_addr.addr.port.unwrap().value()
    )
    .try_into()?;

    let (conn1, _) = transport_layer.lookup(&uri, sender.clone()).await?;
    let (conn2, _) = transport_layer.lookup(&uri, sender.clone()).await?;

    // For UDP, should reuse the same connection
    assert_eq!(conn1.get_addr(), conn2.get_addr());

    cancel_token.cancel();
    Ok(())
}

/// Test connection error handling
#[tokio::test]
async fn test_connection_error_handling() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());
    let (sender, mut receiver) = mpsc::unbounded_channel();

    // Create TCP listener
    let server_addr = transport_layer
        .add_tcp_listener("127.0.0.1:0".parse()?, sender.clone())
        .await?;

    transport_layer.serve_listens(sender.clone()).await?;

    // Create client connection
    let client = TcpConnection::connect(&server_addr).await?;

    // Wait for new connection event
    wait_for_event(&mut receiver).await?;

    // Send a message
    let message = create_test_message("test");
    client.send_message(message).await?;

    // Wait for incoming message
    let _incoming = wait_for_event(&mut receiver).await?;

    // Force close the client connection
    client.close().await?;

    // The server should eventually detect the closed connection
    // This might generate a Closed event or cause the serve_loop to exit

    cancel_token.cancel();
    Ok(())
}

/// Test outbound connection configuration
#[tokio::test]
async fn test_outbound_connection() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let mut transport_layer = TransportLayer::new(cancel_token.clone());
    let (sender, _receiver) = mpsc::unbounded_channel();

    // Create UDP listener to use as outbound
    let udp_addr = transport_layer
        .add_udp_listener("127.0.0.1:0".parse()?)
        .await?;

    // Set outbound connection
    transport_layer.outbound = Some(udp_addr.clone());

    // Any lookup should use the outbound connection
    let uri: rsip::Uri = "sip:test@example.com:5060".try_into()?;
    let (connection, _) = transport_layer.lookup(&uri, sender.clone()).await?;

    assert_eq!(connection.get_addr(), &udp_addr);

    cancel_token.cancel();
    Ok(())
}

async fn wait_for_event(
    receiver: &mut UnboundedReceiver<TransportEvent>,
) -> Result<TransportEvent> {
    match timeout(Duration::from_secs(5), receiver.recv()).await {
        Ok(Some(event)) => Ok(event),
        Ok(None) => Err(crate::Error::Error("Channel closed".to_string())),
        Err(_) => Err(crate::Error::Error("Timeout waiting for event".to_string())),
    }
}

fn create_test_message(call_id: &str) -> SipMessage {
    let test_message = format!(
        "REGISTER sip:example.com SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
         From: <sip:alice@example.com>;tag=test\r\n\
         To: <sip:alice@example.com>\r\n\
         Call-ID: {}\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <sip:alice@127.0.0.1:5060>\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n",
        call_id
    );

    SipMessage::try_from(test_message.as_str()).expect("parse SIP message")
}
