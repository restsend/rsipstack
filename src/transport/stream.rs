use crate::sip::SipMessage;
use crate::{
    transport::{
        connection::{TransportSender, KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        SipAddr, SipConnection, TransportEvent,
    },
    Result,
};
use bytes::{Buf, BytesMut};
use memchr::{memchr, memmem};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

pub(super) const MAX_SIP_MESSAGE_SIZE: usize = 65535;
const CL_FULL_NAME: &[u8] = b"content-length";
const CL_SHORT_NAME: &[u8] = b"l";

pub struct SipCodec {}

impl SipCodec {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SipCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum SipCodecType {
    Message(SipMessage),
    KeepaliveRequest,
    KeepaliveResponse,
}

impl std::fmt::Display for SipCodecType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SipCodecType::Message(msg) => write!(f, "{}", msg),
            SipCodecType::KeepaliveRequest => write!(f, "Keepalive Request"),
            SipCodecType::KeepaliveResponse => write!(f, "Keepalive Response"),
        }
    }
}

impl Decoder for SipCodec {
    type Item = SipCodecType;
    type Error = crate::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() >= 4 && &src[0..4] == KEEPALIVE_REQUEST {
            src.advance(4);
            return Ok(Some(SipCodecType::KeepaliveRequest));
        }

        if src.len() >= 2 && &src[0..2] == KEEPALIVE_RESPONSE {
            src.advance(2);
            return Ok(Some(SipCodecType::KeepaliveResponse));
        }

        if let Some(headers_end) = memmem::find(src, b"\r\n\r\n") {
            let headers = &src[..headers_end + 4]; // include CRLFCRLF

            // Parse Content-Length as u32 without UTF-8 conversion
            let mut content_length: usize = 0;
            let mut start = 0;
            while start < headers.len() {
                // find end of line with memchr
                let end = memchr(b'\n', &headers[start..])
                    .map(|p| start + p)
                    .unwrap_or(headers.len());

                let mut line = &headers[start..end];
                if let Some(&b'\r') = line.last() {
                    line = &line[..line.len().saturating_sub(1)];
                }

                if let Some(colon) = memchr(b':', line) {
                    let header = &line[..colon];
                    let is_cl = if header.len() == CL_FULL_NAME.len()
                        && header
                            .iter()
                            .zip(CL_FULL_NAME.iter())
                            .all(|(&a, &b)| a.to_ascii_lowercase() == b)
                    {
                        true
                    } else {
                        header.len() == CL_SHORT_NAME.len()
                            && header
                                .iter()
                                .zip(CL_SHORT_NAME.iter())
                                .all(|(&a, &b)| a.to_ascii_lowercase() == b)
                    };

                    if is_cl {
                        // parse value
                        let value_buf = &line[colon + 1..];
                        content_length = std::str::from_utf8(value_buf)
                            .map_err(|_| crate::Error::Error("Invalid Content-Length".to_string()))?
                            .trim()
                            .parse()
                            .map_err(|_| {
                                crate::Error::Error("Invalid Content-Length value".to_string())
                            })?;
                        break;
                    }
                }

                start = if end < headers.len() { end + 1 } else { end };
            }

            let total_len = headers_end + 4 + content_length;

            if src.len() >= total_len {
                let msg_data = src.split_to(total_len); // consume full message
                let msg = SipMessage::try_from(&msg_data[..])?;
                return Ok(Some(SipCodecType::Message(msg)));
            }
        }

        if src.len() > MAX_SIP_MESSAGE_SIZE {
            return Err(crate::Error::Error("SIP message too large".to_string()));
        }
        Ok(None)
    }
}

impl Encoder<SipMessage> for SipCodec {
    type Error = crate::Error;

    fn encode(&mut self, item: SipMessage, dst: &mut BytesMut) -> Result<()> {
        let data = item.to_string();
        dst.extend_from_slice(data.as_bytes());
        Ok(())
    }
}

pub struct StreamConnectionInner<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub local_addr: SipAddr,
    pub remote_addr: SipAddr,
    pub read_half: Mutex<Option<R>>,
    pub write_half: Mutex<W>,
}

impl<R, W> StreamConnectionInner<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(local_addr: SipAddr, remote_addr: SipAddr, read_half: R, write_half: W) -> Self {
        Self {
            local_addr,
            remote_addr,
            read_half: Mutex::new(Some(read_half)),
            write_half: Mutex::new(write_half),
        }
    }

    pub async fn send_message(&self, msg: SipMessage) -> Result<()> {
        send_to_stream(&self.write_half, msg).await
    }

    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        send_raw_to_stream(&self.write_half, data).await
    }

    pub async fn serve_loop(
        &self,
        sender: TransportSender,
        connection: SipConnection,
    ) -> Result<()> {
        let mut read_half = match self.read_half.lock().await.take() {
            Some(read_half) => read_half,
            None => {
                warn!(local = %self.local_addr, "Connection already closed");
                return Ok(());
            }
        };

        let remote_addr = self.remote_addr.clone();

        let mut codec = SipCodec::new();
        let mut buffer = BytesMut::with_capacity(MAX_SIP_MESSAGE_SIZE);
        let mut read_buf = BytesMut::with_capacity(MAX_SIP_MESSAGE_SIZE);
        read_buf.resize(MAX_SIP_MESSAGE_SIZE, 0);
        loop {
            use tokio::io::AsyncReadExt;
            match read_half.read(&mut read_buf).await {
                Ok(0) => {
                    debug!(local = %self.local_addr, remote = %remote_addr, "Connection closed");
                    break;
                }
                Ok(n) => {
                    buffer.extend_from_slice(&read_buf[0..n]);

                    while let Some(msg) = codec.decode(&mut buffer)? {
                        match msg {
                            SipCodecType::Message(sip_msg) => {
                                debug!(src = %remote_addr, raw_message = %sip_msg, "received message");
                                let remote_socket_addr = remote_addr.get_socketaddr()?;
                                let sip_msg = SipConnection::update_msg_received(
                                    sip_msg,
                                    remote_socket_addr,
                                    remote_addr.r#type.unwrap_or_default(),
                                )?;

                                if let Err(e) = sender.send(TransportEvent::Incoming(
                                    sip_msg,
                                    connection.clone(),
                                    remote_addr.clone(),
                                )) {
                                    warn!(error = ?e, "Error sending incoming message");
                                    return Err(e.into());
                                }
                            }
                            SipCodecType::KeepaliveRequest => {
                                self.send_raw(KEEPALIVE_RESPONSE).await?;
                            }
                            SipCodecType::KeepaliveResponse => {}
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, src = %remote_addr, "Error reading from stream");
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let mut write_half = self.write_half.lock().await;
        write_half
            .shutdown()
            .await
            .map_err(|e| crate::Error::Error(format!("Failed to shutdown write half: {}", e)))?;
        Ok(())
    }
}

#[async_trait::async_trait]
pub trait StreamConnection: Send + Sync + 'static {
    fn get_addr(&self) -> &SipAddr;
    async fn send_message(&self, msg: SipMessage) -> Result<()>;
    async fn send_raw(&self, data: &[u8]) -> Result<()>;
    async fn serve_loop(&self, sender: TransportSender) -> Result<()>;
    async fn close(&self) -> Result<()>;
}

pub async fn send_to_stream<W>(write_half: &Mutex<W>, msg: SipMessage) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    send_raw_to_stream(write_half, msg.to_string().as_bytes()).await
}

pub async fn send_raw_to_stream<W>(write_half: &Mutex<W>, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let mut lock = write_half.lock().await;
    lock.write_all(data).await?;
    lock.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    fn make_codec() -> SipCodec {
        SipCodec::new()
    }

    // Minimal valid INVITE with the given body.
    fn invite_bytes(body: &str) -> Vec<u8> {
        let msg = format!(
            concat!(
                "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776\r\n",
                "To: Bob <sip:bob@biloxi.com>\r\n",
                "From: Alice <sip:alice@atlanta.com>;tag=123\r\n",
                "Call-ID: abc@test\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Type: application/sdp\r\n",
                "Content-Length: {}\r\n",
                "\r\n",
                "{}"
            ),
            body.len(),
            body
        );
        msg.into_bytes()
    }

    fn register_bytes() -> Vec<u8> {
        concat!(
            "REGISTER sip:registrar.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP bob:5060;branch=z9hG4bKnashds8\r\n",
            "To: Bob <sip:bob@example.com>\r\n",
            "From: Bob <sip:bob@example.com>;tag=456\r\n",
            "Call-ID: 843817637@998sdasdh09\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes()
        .to_vec()
    }

    // ── 基本解码 ──────────────────────────────────────────────────────────────

    #[test]
    fn decode_complete_message_no_body() {
        let mut codec = make_codec();
        let mut buf = BytesMut::from(register_bytes().as_slice());
        let result = codec.decode(&mut buf).unwrap();
        assert!(matches!(result, Some(SipCodecType::Message(_))));
        assert_eq!(buf.len(), 0, "buffer should be fully consumed");
    }

    #[test]
    fn decode_complete_message_with_body() {
        let body = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n";
        let mut codec = make_codec();
        let mut buf = BytesMut::from(invite_bytes(body).as_slice());
        let result = codec.decode(&mut buf).unwrap();
        assert!(matches!(result, Some(SipCodecType::Message(_))));
        assert_eq!(buf.len(), 0);
    }

    // ── 分包：header 尚未完整 ─────────────────────────────────────────────────

    #[test]
    fn decode_returns_none_when_headers_incomplete() {
        let mut codec = make_codec();
        let full = register_bytes();
        // Feed only the first half of the message.
        let half = &full[..full.len() / 2];
        let mut buf = BytesMut::from(half);
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none(), "should wait for more data");
        // Buffer must be untouched.
        assert_eq!(buf.as_ref(), half);
    }

    // ── 分包：body 尚未完整 ───────────────────────────────────────────────────

    #[test]
    fn decode_returns_none_when_body_incomplete() {
        let body = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n";
        let mut codec = make_codec();
        let full = invite_bytes(body);
        // Feed headers + CRLFCRLF but only half the body.
        let headers_end = memmem::find(&full, b"\r\n\r\n").unwrap() + 4;
        let partial_body = body.len() / 2;
        let partial = &full[..headers_end + partial_body];
        let mut buf = BytesMut::from(partial);
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
        assert_eq!(buf.len(), partial.len());
    }

    // ── 粘包：两条消息连在一起 ────────────────────────────────────────────────

    #[test]
    fn decode_two_back_to_back_messages() {
        let mut codec = make_codec();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&register_bytes());
        buf.extend_from_slice(&register_bytes());

        let first = codec.decode(&mut buf).unwrap();
        assert!(matches!(first, Some(SipCodecType::Message(_))));

        let second = codec.decode(&mut buf).unwrap();
        assert!(matches!(second, Some(SipCodecType::Message(_))));

        assert_eq!(buf.len(), 0);
    }

    // ── Content-Length 短格式 'l' ─────────────────────────────────────────────

    #[test]
    fn decode_short_content_length_header() {
        let body = "hello";
        let raw = format!(
            concat!(
                "INVITE sip:bob@example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP pc;branch=z9hG4bK1\r\n",
                "To: <sip:bob@example.com>\r\n",
                "From: <sip:alice@example.com>;tag=1\r\n",
                "Call-ID: x@y\r\n",
                "CSeq: 1 INVITE\r\n",
                "l: {}\r\n",
                "\r\n",
                "{}"
            ),
            body.len(),
            body
        );
        let mut codec = make_codec();
        let mut buf = BytesMut::from(raw.as_bytes());
        let result = codec.decode(&mut buf).unwrap();
        assert!(matches!(result, Some(SipCodecType::Message(_))));
    }

    // ── Keepalive 帧 ──────────────────────────────────────────────────────────

    #[test]
    fn decode_keepalive_request() {
        let mut codec = make_codec();
        let mut buf = BytesMut::from(KEEPALIVE_REQUEST.as_ref());
        let result = codec.decode(&mut buf).unwrap();
        assert!(matches!(result, Some(SipCodecType::KeepaliveRequest)));
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn decode_keepalive_response() {
        let mut codec = make_codec();
        let mut buf = BytesMut::from(KEEPALIVE_RESPONSE.as_ref());
        let result = codec.decode(&mut buf).unwrap();
        assert!(matches!(result, Some(SipCodecType::KeepaliveResponse)));
        assert_eq!(buf.len(), 0);
    }

    // ── 消息过大 ─────────────────────────────────────────────────────────────

    #[test]
    fn decode_rejects_oversized_buffer() {
        let mut codec = make_codec();
        let mut buf = BytesMut::from(vec![b'X'; MAX_SIP_MESSAGE_SIZE + 1].as_slice());
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }
}
