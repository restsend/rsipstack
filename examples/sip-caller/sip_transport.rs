/// 传输层辅助函数模块
///
/// 包含创建各种传输连接和 SDP 解析的辅助函数
use crate::config::Protocol;
use rsipstack::transport::{
    tcp::TcpConnection, udp::UdpConnection, websocket::WebSocketConnection, SipAddr,
};
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// 根据协议类型创建传输连接
///
/// # 参数
/// - `protocol`: 传输协议类型（UDP/TCP/WS/WSS）
/// - `local_addr`: 本地绑定地址
/// - `server_addr`: 服务器地址
/// - `cancel_token`: 取消令牌用于优雅关闭
///
/// # 返回
/// 返回对应协议的 SIP 连接
pub async fn create_transport_connection(
    protocol: Protocol,
    local_addr: SocketAddr,
    server_addr: &str,
    cancel_token: CancellationToken,
) -> Result<rsipstack::transport::SipConnection, Box<dyn std::error::Error>> {
    match protocol {
        Protocol::Udp => {
            info!("创建 UDP 连接: {}", local_addr);
            let connection = UdpConnection::create_connection(
                local_addr,
                None, // external address
                Some(cancel_token.child_token()),
            )
            .await?;
            Ok(connection.into())
        }
        Protocol::Tcp => {
            info!("创建 TCP 连接到服务器: {}", server_addr);
            // 将服务器地址转换为 SipAddr
            let server_sip_addr =
                SipAddr::new(rsip::transport::Transport::Tcp, server_addr.try_into()?);
            let connection =
                TcpConnection::connect(&server_sip_addr, Some(cancel_token.child_token())).await?;
            Ok(connection.into())
        }
        Protocol::Ws => {
            info!("创建 WebSocket 连接到服务器: ws://{}", server_addr);
            // 将服务器地址转换为 SipAddr
            let server_sip_addr =
                SipAddr::new(rsip::transport::Transport::Ws, server_addr.try_into()?);
            let connection =
                WebSocketConnection::connect(&server_sip_addr, Some(cancel_token.child_token()))
                    .await?;
            Ok(connection.into())
        }
        Protocol::Wss => {
            info!("创建 WebSocket Secure 连接到服务器: wss://{}", server_addr);
            // 将服务器地址转换为 SipAddr
            let server_sip_addr =
                SipAddr::new(rsip::transport::Transport::Wss, server_addr.try_into()?);
            let connection =
                WebSocketConnection::connect(&server_sip_addr, Some(cancel_token.child_token()))
                    .await?;
            Ok(connection.into())
        }
    }
}

/// 从 SDP 中提取对端 RTP 地址
///
/// # 参数
/// - `sdp`: SDP 消息内容
///
/// # 返回
/// 返回 IP:Port 格式的 RTP 地址，如果解析失败则返回 None
///
/// # 示例
/// ```
/// let sdp = r#"
/// v=0
/// o=- 123 456 IN IP4 192.168.1.100
/// s=Session
/// c=IN IP4 192.168.1.100
/// t=0 0
/// m=audio 20000 RTP/AVP 0
/// "#;
///
/// let addr = extract_peer_rtp_addr(sdp);
/// assert_eq!(addr, Some("192.168.1.100:20000".to_string()));
/// ```
pub fn extract_peer_rtp_addr(sdp: &str) -> Option<String> {
    let mut ip = None;
    let mut port = None;

    for line in sdp.lines() {
        let line = line.trim();
        // 解析 c= 行获取 IP
        if line.starts_with("c=") {
            // c=IN IP4 192.168.1.100
            if let Some(addr) = line.split_whitespace().last() {
                ip = Some(addr.to_string());
            }
        }
        // 解析 m= 行获取端口
        else if line.starts_with("m=audio") {
            // m=audio 20000 RTP/AVP 0
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                port = parts[1].parse::<u16>().ok();
            }
        }
    }

    if let (Some(ip), Some(port)) = (ip, port) {
        Some(format!("{}:{}", ip, port))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_peer_rtp_addr() {
        let sdp = r#"v=0
o=- 123 456 IN IP4 192.168.1.100
s=Session
c=IN IP4 192.168.1.100
t=0 0
m=audio 20000 RTP/AVP 0"#;

        let addr = extract_peer_rtp_addr(sdp);
        assert_eq!(addr, Some("192.168.1.100:20000".to_string()));
    }

    #[test]
    fn test_extract_peer_rtp_addr_missing_ip() {
        let sdp = r#"v=0
o=- 123 456 IN IP4 192.168.1.100
s=Session
t=0 0
m=audio 20000 RTP/AVP 0"#;

        let addr = extract_peer_rtp_addr(sdp);
        assert_eq!(addr, None);
    }

    #[test]
    fn test_extract_peer_rtp_addr_missing_port() {
        let sdp = r#"v=0
o=- 123 456 IN IP4 192.168.1.100
s=Session
c=IN IP4 192.168.1.100
t=0 0"#;

        let addr = extract_peer_rtp_addr(sdp);
        assert_eq!(addr, None);
    }
}
