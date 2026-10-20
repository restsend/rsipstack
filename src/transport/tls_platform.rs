//! no_std TLS client connection carried by the [`crate::platform::tls`] seam.
//!
//! The tokio build dials TLS inside [`crate::transport::tls`] (rustls, with the
//! platform connector taking precedence). Embedded builds (embassy) have no
//! tokio and usually no rustls: there the transport layer dials through the
//! registered [`crate::platform::tls::TlsConnector`] directly — the connector
//! owns the TCP dial and the handshake — and the resulting
//! [`crate::platform::tls::TlsStream`] is wrapped in this connection, which
//! speaks stream-framed SIP (Content-Length, RFC 3261 §7.5) over it.
//!
//! Wire format mirrors the tokio `SipCodec`: CRLF keepalives, header block
//! terminated by CRLFCRLF, body length from `Content-Length` (compact form
//! `l:` honoured), messages coalesced or split across reads.

use crate::platform::CancellationToken;
use crate::sip::{SipMessage, Transport};
use crate::transport::connection::{TransportEvent, TransportSender};
use crate::transport::connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE};
use crate::transport::{SipAddr, SipConnection};
use crate::{Error, Result};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::SocketAddr;

const MAX_SIP_MESSAGE_SIZE: usize = 65535;

/// SIP-over-TLS client connection for embedded backends (platform connector
/// seam). Reliable, stream-framed, carries `Transport::Tls`.
#[derive(Clone)]
pub struct PlatformTlsConnection {
    stream: Arc<dyn crate::platform::tls::TlsStream>,
    local_addr: SipAddr,
    remote_addr: SipAddr,
    cancel_token: Option<CancellationToken>,
}

impl PlatformTlsConnection {
    /// Dial `target` through the registered platform connector. `target` must
    /// already be resolved to an IP address (the transport layer's domain
    /// resolver runs first); `server_name` is the pre-resolution host, used
    /// for SNI / certificate identity.
    pub async fn connect(
        target: &SipAddr,
        server_name: Option<&str>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let connector = crate::platform::tls::client_connector().ok_or_else(|| {
            Error::Error(
                "TLS: no platform connector registered (platform::tls::set_client_connector)"
                    .to_string(),
            )
        })?;
        let addr: SocketAddr = target.get_socketaddr()?;
        let server_name = server_name
            .map(String::from)
            .unwrap_or_else(|| target.addr.host.to_string());
        let config = crate::platform::tls::TlsClientConfig {
            server_name,
            ..Default::default()
        };
        let stream = connector.connect(&config, addr).await?;
        let local = SipAddr {
            r#type: Some(Transport::Tls),
            addr: stream.local_addr()?.into(),
        };
        Ok(Self {
            stream: Arc::from(stream),
            local_addr: local,
            remote_addr: target.clone(),
            cancel_token,
        })
    }

    pub fn get_addr(&self) -> &SipAddr {
        &self.local_addr
    }

    pub fn get_remote_addr(&self) -> &SipAddr {
        &self.remote_addr
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }

    /// Whether `self` and `other` wrap the same underlying TLS stream.
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.stream, &other.stream)
    }

    pub async fn send_message(&self, msg: SipMessage) -> Result<()> {
        self.stream.send_all(msg.to_bytes()).await
    }

    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        self.stream.send_all(data.to_vec()).await
    }

    /// Receives chunks from the TLS stream, frames them into SIP messages and
    /// forwards them on `sender`. Exits when the stream errors or closes (an
    /// empty chunk signals backend EOF).
    pub async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        let connection = SipConnection::TlsPlatform(self.clone());
        let remote_addr = self.remote_addr.clone();
        let remote_socket_addr = remote_addr.get_socketaddr()?;
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            let chunk = match self.stream.recv().await {
                Ok(chunk) => chunk,
                Err(e) => {
                    tracing::warn!(error = %e, "tlsplatform: recv error, closing connection");
                    return Err(Error::Error(alloc::format!(
                        "tls platform recv from {remote_addr}: {e}"
                    )));
                }
            };
            if chunk.is_empty() {
                // Backend EOF signal: the connection is gone.
                tracing::warn!("tlsplatform: backend EOF, serve_loop exits");
                return Ok(());
            }
            if buffer.len() + chunk.len() > MAX_SIP_MESSAGE_SIZE {
                return Err(Error::Error("SIP message too large".to_string()));
            }
            buffer.extend_from_slice(&chunk);
            loop {
                match frame(&buffer)? {
                    Some(Frame::KeepaliveRequest) => {
                        buffer.drain(..KEEPALIVE_REQUEST.len());
                        self.send_raw(KEEPALIVE_RESPONSE).await?;
                    }
                    Some(Frame::KeepaliveResponse) => {
                        buffer.drain(..KEEPALIVE_RESPONSE.len());
                    }
                    Some(Frame::Message(len)) => {
                        let msg = SipMessage::try_from(&buffer[..len])?;
                        buffer.drain(..len);
                        let msg = SipConnection::update_msg_received(
                            msg,
                            remote_socket_addr,
                            Transport::Tls,
                        )?;
                        if let Err(e) = sender.send(TransportEvent::Incoming(
                            msg,
                            connection.clone(),
                            remote_addr.clone(),
                        )) {
                            return Err(e.into());
                        }
                    }
                    None => break, // need more bytes
                }
            }
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.stream.shutdown().await
    }
}

impl core::fmt::Display for PlatformTlsConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TLS {} -> {}", self.local_addr, self.remote_addr)
    }
}

impl core::fmt::Debug for PlatformTlsConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TLS {} -> {}", self.local_addr, self.remote_addr)
    }
}

/// One complete frame at the front of `buf`.
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    /// `\r\n\r\n` (RFC 5626 §4.4.1 keepalive ping).
    KeepaliveRequest,
    /// `\r\n` keepalive pong.
    KeepaliveResponse,
    /// A full SIP message of `len` bytes (headers + body).
    Message(usize),
}

/// Stream framing: finds the first complete frame in `buf` without consuming
/// it. Returns `None` when more bytes are needed.
fn frame(buf: &[u8]) -> Result<Option<Frame>> {
    // Keepalive pings/pongs start the buffer (RFC 5626 double-CRLF / CRLF).
    if buf.starts_with(KEEPALIVE_REQUEST) {
        return Ok(Some(Frame::KeepaliveRequest));
    }
    if buf.starts_with(KEEPALIVE_RESPONSE) {
        return Ok(Some(Frame::KeepaliveResponse));
    }
    let Some(headers_end) = find(buf, b"\r\n\r\n") else {
        if buf.len() > MAX_SIP_MESSAGE_SIZE {
            return Err(Error::Error("SIP message too large".to_string()));
        }
        return Ok(None);
    };
    let content_length = content_length(&buf[..headers_end]).unwrap_or(0);
    let total = headers_end + 4 + content_length;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(Frame::Message(total)))
}

/// Parses `Content-Length` (compact form `l:` honoured) from the raw header
/// block (without the terminating CRLFCRLF).
fn content_length(headers: &[u8]) -> Option<usize> {
    let mut start = 0usize;
    while start < headers.len() {
        let end = find(&headers[start..], b"\n")
            .map(|p| start + p)
            .unwrap_or(headers.len());
        let mut line = &headers[start..end];
        if let Some(&b'\r') = line.last() {
            line = &line[..line.len() - 1];
        }
        if let Some(colon) = find(line, b":") {
            let name = &line[..colon];
            let is_cl = (name.len() == 14 && name.eq_ignore_ascii_case(b"content-length"))
                || (name.len() == 1 && (name == b"l" || name == b"L"));
            if is_cl {
                let value = core::str::from_utf8(&line[colon + 1..]).ok()?;
                return value.trim().parse().ok();
            }
        }
        start = if end < headers.len() { end + 1 } else { end };
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite(body: &str) -> Vec<u8> {
        alloc::format!(
            concat!(
                "INVITE sip:bob@example.com SIP/2.0\r\n",
                "Via: SIP/2.0/TLS pc.example.com;branch=z9hG4bK1\r\n",
                "From: <sip:alice@example.com>;tag=1\r\n",
                "To: <sip:bob@example.com>\r\n",
                "Call-ID: 1@example\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: {}\r\n",
                "\r\n",
                "{}"
            ),
            body.len(),
            body
        )
        .into_bytes()
    }

    #[test]
    fn frames_a_complete_message() {
        let raw = invite("v=0\r\n");
        assert_eq!(frame(&raw).unwrap(), Some(Frame::Message(raw.len())));
    }

    #[test]
    fn waits_for_a_partial_body() {
        let raw = invite("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n");
        let partial = &raw[..raw.len() - 5];
        assert_eq!(frame(partial).unwrap(), None);
    }

    #[test]
    fn waits_for_partial_headers() {
        let raw = invite("");
        assert_eq!(frame(&raw[..raw.len() / 2]).unwrap(), None);
    }

    #[test]
    fn compact_content_length_is_honoured() {
        let raw = alloc::format!("BYE sip:b@example.com SIP/2.0\r\nl: 3\r\n\r\nabc").into_bytes();
        assert_eq!(frame(&raw).unwrap(), Some(Frame::Message(raw.len())));
    }

    #[test]
    fn coalesced_messages_frame_one_at_a_time() {
        let raw = invite("");
        let mut two = raw.clone();
        two.extend_from_slice(&raw);
        assert_eq!(frame(&two).unwrap(), Some(Frame::Message(raw.len())));
    }

    #[test]
    fn keepalive_frames() {
        assert_eq!(
            frame(KEEPALIVE_REQUEST).unwrap(),
            Some(Frame::KeepaliveRequest)
        );
        assert_eq!(
            frame(KEEPALIVE_RESPONSE).unwrap(),
            Some(Frame::KeepaliveResponse)
        );
        // a message may follow a keepalive pong in the same chunk
        let mut buf = KEEPALIVE_RESPONSE.to_vec();
        let raw = invite("");
        buf.extend_from_slice(&raw);
        assert_eq!(frame(&buf).unwrap(), Some(Frame::KeepaliveResponse));
    }

    #[test]
    fn message_body_is_included_in_frame_length() {
        let body = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n";
        let raw = invite(body);
        match frame(&raw).unwrap() {
            Some(Frame::Message(len)) => {
                let msg = SipMessage::try_from(&raw[..len]).unwrap();
                match msg {
                    SipMessage::Request(req) => {
                        assert_eq!(req.body.len(), body.len());
                    }
                    _ => panic!("expected request"),
                }
            }
            _ => panic!("expected message frame"),
        }
    }
}
