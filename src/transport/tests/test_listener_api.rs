use crate::{
    transport::{SipAddr, TcpListenerConnection, WebSocketListenerConnection},
    Result,
};

/// Test new TcpListenerConnection API
#[tokio::test]
async fn test_tcp_listener_connection_api() -> Result<()> {
    // Create TCP listener connection with a specific port to avoid conflicts
    let socket_addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let local_addr = SipAddr::new(crate::sip::transport::Transport::Tcp, socket_addr.into());
    let tcp_listener = TcpListenerConnection::new(local_addr, None).await?;

    // Get the address (should be the same as input since we don't bind in new())
    let bound_addr = tcp_listener.get_addr().clone();

    println!(
        "Successfully created TCP listener using new API: {:?}",
        bound_addr
    );

    // Test that we can get the address
    assert_eq!(bound_addr.r#type, Some(crate::sip::transport::Transport::Tcp));
    assert_eq!(bound_addr.addr.host.to_string(), "127.0.0.1");

    Ok(())
}

/// Test new WebSocketListenerConnection API
#[cfg(feature = "websocket")]
#[tokio::test]
async fn test_websocket_listener_connection_api() -> Result<()> {
    // Create WebSocket listener connection
    let socket_addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let local_addr = SipAddr::new(crate::sip::transport::Transport::Ws, socket_addr.into());
    let ws_listener = WebSocketListenerConnection::new(local_addr, None, false).await?;

    // Get the address (should be the same as input since we don't bind in new())
    let bound_addr = ws_listener.get_addr().clone();

    println!(
        "Successfully created WebSocket listener using new API: {:?}",
        bound_addr
    );

    // Test that we can get the address
    assert_eq!(bound_addr.r#type, Some(crate::sip::transport::Transport::Ws));
    assert_eq!(bound_addr.addr.host.to_string(), "127.0.0.1");

    Ok(())
}
