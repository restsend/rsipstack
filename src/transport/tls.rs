use super::{
    connection::TransportSender,
    sip_addr::SipAddr,
    stream::{StreamConnection, StreamConnectionInner},
    SipConnection,
};
use crate::platform::CancellationToken;
use crate::sip::SipMessage;
use crate::{error::Error, transport::transport_layer::TransportLayerInnerRef, Result};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use socket2::{Domain, Protocol, Socket, Type};
use std::{fmt, fmt::Debug, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{pki_types, pki_types::pem::PemObject, ClientConfig, RootCertStore, ServerConfig},
    TlsAcceptor, TlsConnector,
};
use tracing::{debug, warn};

/// Certificate info extracted from PEM for logging purposes
#[derive(Debug)]
struct CertInfo {
    /// Common Name (CN) from subject
    cn: Option<String>,
    /// Certificate expiration timestamp (not_after)
    expires: Option<String>,
}

impl CertInfo {
    /// Parse certificate info from PEM data
    fn from_pem(pem_data: &[u8]) -> Option<Self> {
        // Find the certificate from PEM data
        let pem_str = String::from_utf8_lossy(pem_data);
        let start_idx = pem_str.find("-----BEGIN CERTIFICATE-----")?;
        let end_idx = pem_str.find("-----END CERTIFICATE-----")?;

        // Extract base64 content between markers
        let cert_b64 = &pem_str[start_idx + 27..end_idx];
        let cert_der = base64_decode(cert_b64).ok()?;

        // Parse ASN.1 to extract basic info
        // This is a simplified parser - just extracts CN and validity dates
        parse_cert_info(&cert_der).ok()
    }
}

/// Simple base64 decoder
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, std::io::Error> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Parse DER-encoded certificate to extract CN and validity dates
fn parse_cert_info(der: &[u8]) -> std::result::Result<CertInfo, std::io::Error> {
    // Simplified ASN.1 parsing - look for common patterns
    // X.509 certificate structure:
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    // TBSCertificate ::= SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... }

    let mut cn = None;
    let mut expires = None;

    // Find "CN=" pattern in the DER (works for simple cases)
    let der_str = String::from_utf8_lossy(der);
    if let Some(cn_start) = der_str.find("CN=") {
        let cn_rest = &der_str[cn_start + 3..];
        let cn_end = cn_rest.find(&[',', '/', '\n'][..]).unwrap_or(cn_rest.len());
        let cn_val = &cn_rest[..cn_end];
        if !cn_val.is_empty() && cn_val.len() <= 64 {
            cn = Some(cn_val.to_string());
        }
    }

    // Look for validity dates (notAfter in UTCTime or GeneralizedTime format)
    // UTCTime format: YYMMDDHHMMSSZ or YYMMDDHHMMSS+HHMM
    // GeneralizedTime format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS+HHMM
    if let Some(not_after_pos) = der_str.find("notAfter") {
        let after_not_after = &der_str[not_after_pos + 9..];
        // Skip the ASN.1 type byte and length, then parse the time
        let time_start = after_not_after
            .find(&[' ', '\n', 'Z'][..])
            .map(|_p| {
                let mut pos = 0;
                for (i, c) in after_not_after.chars().enumerate() {
                    if c == ' ' || c == '\n' {
                        pos = i + 1;
                        break;
                    }
                }
                pos
            })
            .unwrap_or(0);

        let time_str = &after_not_after[time_start..];
        let time_end = time_str
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-' && c != 'Z')
            .unwrap_or(14.min(time_str.len()));
        if time_end > 0 {
            expires = Some(time_str[..time_end].trim().to_string());
        }
    }

    Ok(CertInfo { cn, expires })
}

struct TlsKeyAndCert {
    certified_key: Arc<CertifiedKey>,
}

pub struct ReloadableCertResolver {
    key_and_cert: crate::platform::sync::RwLock<TlsKeyAndCert>,
    provider: Arc<CryptoProvider>,
}

impl ReloadableCertResolver {
    pub fn new(
        cert_data: &[u8],
        key_data: &[u8],
        provider: Arc<CryptoProvider>,
    ) -> std::result::Result<Self, Error> {
        let certified_key = Self::create_certified_key(cert_data, key_data, &provider)?;

        Ok(Self {
            key_and_cert: crate::platform::sync::RwLock::new(TlsKeyAndCert { certified_key }),
            provider,
        })
    }

    fn create_certified_key(
        cert_data: &[u8],
        key_data: &[u8],
        provider: &CryptoProvider,
    ) -> std::result::Result<Arc<CertifiedKey>, Error> {
        let certs = {
            pki_types::CertificateDer::pem_slice_iter(cert_data)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::Error(format!("Failed to parse certificate: {}", e)))?
        };

        let key = {
            let keys: Vec<_> = pki_types::PrivatePkcs8KeyDer::pem_slice_iter(key_data)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::Error(format!("Failed to parse PKCS8 key: {}", e)))?;

            if !keys.is_empty() {
                pki_types::PrivateKeyDer::Pkcs8(keys[0].clone_key())
            } else {
                let keys: Vec<_> = pki_types::PrivatePkcs1KeyDer::pem_slice_iter(key_data)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| Error::Error(format!("Failed to parse RSA key: {}", e)))?;

                if !keys.is_empty() {
                    pki_types::PrivateKeyDer::Pkcs1(keys[0].clone_key())
                } else {
                    return Err(Error::Error("No valid private key found".to_string()));
                }
            }
        };

        CertifiedKey::from_der(certs, key, provider)
            .map(Arc::new)
            .map_err(|e| Error::Error(format!("Failed to create certified key: {}", e)))
    }

    pub fn reload(&self, cert_data: &[u8], key_data: &[u8]) -> std::result::Result<(), Error> {
        let certified_key = Self::create_certified_key(cert_data, key_data, &self.provider)?;

        // Extract certificate info for logging
        let cert_info = CertInfo::from_pem(cert_data);
        let sni_info = cert_info
            .as_ref()
            .and_then(|c| c.cn.as_ref())
            .map(|cn| format!("SNI/CN={}", cn))
            .unwrap_or_else(|| "SNI/CN=unknown".to_string());
        let expires_info = cert_info
            .as_ref()
            .and_then(|c| c.expires.as_ref())
            .map(|e| format!("expires={}", e))
            .unwrap_or_else(|| "expires=unknown".to_string());

        let mut guard = self.key_and_cert.write();
        guard.certified_key = certified_key;
        warn!(
            "TLS certificate reloaded successfully [{}, {}]",
            sni_info, expires_info
        );
        Ok(())
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let guard = self.key_and_cert.read();
        Some(guard.certified_key.clone())
    }
}

impl Debug for ReloadableCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableCertResolver").finish()
    }
}

impl Clone for ReloadableCertResolver {
    fn clone(&self) -> Self {
        Self {
            key_and_cert: crate::platform::sync::RwLock::new(TlsKeyAndCert {
                certified_key: self.key_and_cert.read().certified_key.clone(),
            }),
            provider: self.provider.clone(),
        }
    }
}

// TLS configuration
#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    // Server certificate in PEM format
    pub cert: Option<Vec<u8>>,
    // Server private key in PEM format
    pub key: Option<Vec<u8>>,
    // Client certificate in PEM format
    pub client_cert: Option<Vec<u8>>,
    // Client private key in PEM format
    pub client_key: Option<Vec<u8>>,
    // Root CA certificates in PEM format
    pub ca_certs: Option<Vec<u8>>,
    // SNI hostname for TLS client connections (overrides the hostname derived from the remote address)
    pub sni_hostname: Option<String>,
}

fn parse_private_key(key_data: &[u8]) -> Result<pki_types::PrivateKeyDer<'static>> {
    // Try PKCS8 format first
    let keys: Vec<_> = pki_types::PrivatePkcs8KeyDer::pem_slice_iter(key_data)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Error(format!("Failed to parse PKCS8 key: {}", e)))?;

    if !keys.is_empty() {
        let key_der = keys[0].clone_key();
        return Ok(pki_types::PrivateKeyDer::Pkcs8(key_der));
    }

    // Try PKCS1 format
    let keys: Vec<_> = pki_types::PrivatePkcs1KeyDer::pem_slice_iter(key_data)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Error(format!("Failed to parse RSA key: {}", e)))?;

    if !keys.is_empty() {
        let key_der = keys[0].clone_key();
        return Ok(pki_types::PrivateKeyDer::Pkcs1(key_der));
    }

    Err(Error::Error("No valid private key found".to_string()))
}

// TLS Listener Connection Structure
pub struct TlsListenerConnectionInner {
    pub local_addr: SipAddr,
    pub external: Option<SipAddr>,
    pub config: TlsConfig,
    pub cert_resolver: crate::platform::sync::Mutex<Option<Arc<ReloadableCertResolver>>>,
}

#[derive(Clone)]
pub struct TlsListenerConnection {
    pub inner: Arc<TlsListenerConnectionInner>,
}

impl TlsListenerConnection {
    pub async fn new(
        local_addr: SocketAddr,
        external: Option<SocketAddr>,
        config: TlsConfig,
    ) -> Result<Self> {
        let inner = TlsListenerConnectionInner {
            local_addr: SipAddr {
                r#type: Some(crate::sip::transport::Transport::Tls),
                addr: local_addr.into(),
            },
            external: external.map(|addr| SipAddr {
                r#type: Some(crate::sip::transport::Transport::Tls),
                addr: addr.into(),
            }),
            config,
            cert_resolver: crate::platform::sync::Mutex::new(None),
        };
        Ok(TlsListenerConnection {
            inner: Arc::new(inner),
        })
    }

    pub async fn serve_listener(
        &self,
        transport_layer_inner: TransportLayerInnerRef,
    ) -> Result<()> {
        let local = self.inner.local_addr.get_socketaddr()?;
        let domain = if local.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if let Err(e) = socket.set_reuse_address(true) {
            warn!(error = %e, "failed to set SO_REUSEADDR on TLS listener");
        }
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;
        socket.listen(128)?;
        let listener = TcpListener::from_std(socket.into())?;
        let (acceptor, resolver) = Self::create_acceptor(&self.inner.config).await?;
        *self.inner.cert_resolver.lock() = Some(resolver);
        let listener_local_addr = self.get_addr().clone();

        crate::platform::spawn(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok((stream, remote_addr)) => (stream, remote_addr),
                    Err(e) => {
                        warn!(error = ?e, "Failed to accept TLS connection");
                        continue;
                    }
                };
                if !transport_layer_inner.is_whitelisted(remote_addr.ip()).await {
                    debug!(remote = %remote_addr, "tls connection rejected by whitelist");
                    continue;
                }

                let acceptor_clone = acceptor.clone();
                let transport_layer_inner_ref = transport_layer_inner.clone();
                let local_addr = listener_local_addr.clone();

                crate::platform::spawn(async move {
                    // Perform TLS handshake
                    let tls_stream = match acceptor_clone.accept(stream).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            warn!(error = %e, "TLS handshake failed");
                            return;
                        }
                    };

                    // Create remote SIP address
                    let remote_sip_addr = SipAddr {
                        r#type: Some(crate::sip::transport::Transport::Tls),
                        addr: remote_addr.into(),
                    };
                    // Create TLS connection
                    let tls_connection = match TlsConnection::from_server_stream(
                        tls_stream,
                        local_addr,
                        remote_sip_addr.clone(),
                        Some(transport_layer_inner_ref.cancel_token.child_token()),
                    )
                    .await
                    {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!(error = ?e, %remote_sip_addr, "Failed to create TLS connection");
                            return;
                        }
                    };

                    let sip_connection = SipConnection::Tls(tls_connection.clone());
                    transport_layer_inner_ref.add_connection(sip_connection.clone());
                    debug!(?remote_sip_addr, "new tls connection");
                });
            }
        });
        Ok(())
    }

    pub fn get_addr(&self) -> &SipAddr {
        if let Some(external) = &self.inner.external {
            external
        } else {
            &self.inner.local_addr
        }
    }

    pub async fn close(&self) -> Result<()> {
        Ok(())
    }

    async fn create_acceptor(
        config: &TlsConfig,
    ) -> Result<(TlsAcceptor, Arc<ReloadableCertResolver>)> {
        let resolver = ReloadableCertResolver::new(
            config
                .cert
                .as_ref()
                .ok_or_else(|| Error::Error("No certificate provided".to_string()))?,
            config
                .key
                .as_ref()
                .ok_or_else(|| Error::Error("No private key provided".to_string()))?,
            ServerConfig::builder().crypto_provider().clone(),
        )?;
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver.clone()));

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        Ok((acceptor, Arc::new(resolver)))
    }

    pub async fn reload_tls_config(&self, cert: Vec<u8>, key: Vec<u8>) -> Result<()> {
        let resolver = {
            let guard = self.inner.cert_resolver.lock();
            guard
                .as_ref()
                .ok_or_else(|| Error::Error("No cert resolver available".to_string()))?
                .clone()
        };
        resolver.reload(&cert, &key)
    }
}

impl fmt::Display for TlsListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS Listener {}", self.get_addr())
    }
}

impl fmt::Debug for TlsListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// Define a type alias for the TLS stream to make the code more readable
type TlsClientStream = tokio_rustls::client::TlsStream<TcpStream>;
type TlsServerStream = tokio_rustls::server::TlsStream<TcpStream>;

/// Client halves are boxed so rustls and platform-seam streams share one
/// `TlsConnectionInner::Client` representation.
type ClientReadHalf = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type ClientWriteHalf = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Bridges a seam TLS stream (async-fn, owned-data) back into the tokio
/// world. Chunks from `recv()` are buffered; `send_all`/`shutdown` futures
/// hold an owned `Arc` + `Vec`, so nothing borrows across polls.
struct TokioSeamStream {
    inner: Arc<dyn crate::platform::tls::TlsStream>,
    recv_fut: Option<BoxFuture<Result<Vec<u8>>>>,
    send_fut: Option<BoxFuture<Result<()>>>,
    shutdown_fut: Option<BoxFuture<Result<()>>>,
    chunk: alloc::collections::VecDeque<u8>,
}

impl TokioSeamStream {
    fn new(inner: Arc<dyn crate::platform::tls::TlsStream>) -> Self {
        Self {
            inner,
            recv_fut: None,
            send_fut: None,
            shutdown_fut: None,
            chunk: alloc::collections::VecDeque::new(),
        }
    }
}

impl tokio::io::AsyncRead for TokioSeamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rbuf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.chunk.is_empty() {
                let n = this.chunk.len().min(rbuf.remaining());
                let data: Vec<u8> = this.chunk.drain(..n).collect();
                rbuf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            if this.recv_fut.is_none() {
                let inner = this.inner.clone();
                this.recv_fut = Some(Box::pin(async move { inner.recv().await }));
            }
            match this.recv_fut.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Ready(Ok(data)) => {
                    this.recv_fut = None;
                    if data.is_empty() {
                        // Peer closed the stream.
                        return Poll::Ready(Ok(()));
                    }
                    this.chunk.extend(data);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(seam_io_err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn seam_io_err(e: crate::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

impl tokio::io::AsyncWrite for TokioSeamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.send_fut.is_none() {
            let inner = this.inner.clone();
            let data = buf.to_vec();
            this.send_fut = Some(Box::pin(async move { inner.send_all(data).await }));
        }
        match this.send_fut.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                this.send_fut = None;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(seam_io_err(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(())) // send_all is already awaited to completion
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown_fut.is_none() {
            let inner = this.inner.clone();
            this.shutdown_fut = Some(Box::pin(async move { inner.shutdown().await }));
        }
        match this.shutdown_fut.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown_fut = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(seam_io_err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// TLS connection - uses enum to handle both client and server streams
#[derive(Clone)]
pub struct TlsConnection {
    inner: TlsConnectionInner,
    pub cancel_token: Option<CancellationToken>,
}

#[derive(Clone)]
enum TlsConnectionInner {
    Client(Arc<StreamConnectionInner<ClientReadHalf, ClientWriteHalf>>),
    Server(
        Arc<
            StreamConnectionInner<
                tokio::io::ReadHalf<TlsServerStream>,
                tokio::io::WriteHalf<TlsServerStream>,
            >,
        >,
    ),
}

impl TlsConnection {
    pub(crate) fn ptr_eq(&self, other: &TlsConnection) -> bool {
        match (&self.inner, &other.inner) {
            (TlsConnectionInner::Client(a), TlsConnectionInner::Client(b)) => Arc::ptr_eq(a, b),
            (TlsConnectionInner::Server(a), TlsConnectionInner::Server(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    // Connect to a remote TLS server
    pub async fn connect(
        remote_addr: &SipAddr,
        tls_config: Option<&TlsConfig>,
        custom_verifier: Option<Arc<dyn ServerCertVerifier>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        // A registered platform connector (embedded backends) takes
        // precedence over the built-in rustls path.
        if let Some(connector) = crate::platform::tls::client_connector() {
            return Self::connect_via_platform(remote_addr, tls_config, cancel_token, connector)
                .await;
        }

        let mut root_store = RootCertStore::empty();

        // Load CA certificates if provided
        if let Some(ca_data) = tls_config.and_then(|c| c.ca_certs.as_ref()) {
            let certs = pki_types::CertificateDer::pem_slice_iter(ca_data.as_slice())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::Error(format!("Failed to parse CA certificates: {}", e)))?;
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| Error::Error(format!("Failed to add CA certificate: {}", e)))?;
            }
        }

        // Build client config with optional mutual TLS
        let mut client_config = match (
            tls_config.and_then(|c| c.client_cert.as_ref()),
            tls_config.and_then(|c| c.client_key.as_ref()),
        ) {
            (Some(cert_data), Some(key_data)) => {
                let certs = pki_types::CertificateDer::pem_slice_iter(cert_data.as_slice())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| {
                        Error::Error(format!("Failed to parse client certificate: {}", e))
                    })?;
                let key = parse_private_key(key_data)?;
                ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| Error::Error(format!("Client auth configuration error: {}", e)))?
            }
            _ => ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        };

        if let Some(verifier) = custom_verifier {
            client_config.dangerous().set_certificate_verifier(verifier);
        }

        // Prefer explicit SNI, otherwise use the remote host.
        let domain_string = tls_config
            .and_then(|c| c.sni_hostname.clone())
            .unwrap_or_else(|| match &remote_addr.addr.host {
                crate::sip::Host::Domain(domain) => domain.to_string(),
                crate::sip::Host::IpAddr(ip) => ip.to_string(),
            });

        let connector = TlsConnector::from(Arc::new(client_config));

        let socket_addr = match &remote_addr.addr.host {
            crate::sip::Host::Domain(domain) => {
                let port = remote_addr.addr.port.as_ref().map_or(5061, |p| p.value());
                format!("{}:{}", domain, port).parse()?
            }
            crate::sip::Host::IpAddr(ip) => {
                let port = remote_addr.addr.port.as_ref().map_or(5061, |p| p.value());
                SocketAddr::new(*ip, port)
            }
        };

        let server_name = pki_types::ServerName::try_from(domain_string.as_str())
            .map_err(|_| Error::Error(format!("Invalid DNS name: {}", domain_string)))?
            .to_owned();

        let stream = TcpStream::connect(socket_addr).await?;
        let local_addr = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Tls),
            addr: stream.local_addr()?.into(),
        };

        let tls_stream = connector.connect(server_name, stream).await?;
        let (read_half, write_half) = tokio::io::split(tls_stream);
        let (read_half, write_half) = (
            Box::new(read_half) as ClientReadHalf,
            Box::new(write_half) as ClientWriteHalf,
        );

        let connection = Self {
            inner: TlsConnectionInner::Client(Arc::new(StreamConnectionInner::new(
                local_addr.clone(),
                remote_addr.clone(),
                read_half,
                write_half,
            ))),
            cancel_token,
        };
        debug!(
            "Created TLS client connection: {} -> {}",
            local_addr, remote_addr
        );

        Ok(connection)
    }

    // Client connect through the platform TLS seam (embedded backends).
    async fn connect_via_platform(
        remote_addr: &SipAddr,
        tls_config: Option<&TlsConfig>,
        cancel_token: Option<CancellationToken>,
        connector: Arc<dyn crate::platform::tls::TlsConnector>,
    ) -> Result<Self> {
        let config = crate::platform::tls::TlsClientConfig {
            server_name: tls_config
                .and_then(|c| c.sni_hostname.clone())
                .unwrap_or_else(|| match &remote_addr.addr.host {
                    crate::sip::Host::Domain(domain) => domain.to_string(),
                    crate::sip::Host::IpAddr(ip) => ip.to_string(),
                }),
            root_certs: tls_config.and_then(|c| c.ca_certs.clone()),
            client_cert: tls_config.and_then(|c| c.client_cert.clone()),
            client_key: tls_config.and_then(|c| c.client_key.clone()),
        };

        let socket_addr = match &remote_addr.addr.host {
            crate::sip::Host::Domain(domain) => {
                let port = remote_addr.addr.port.as_ref().map_or(5061, |p| p.value());
                format!("{}:{}", domain, port).parse()?
            }
            crate::sip::Host::IpAddr(ip) => {
                let port = remote_addr.addr.port.as_ref().map_or(5061, |p| p.value());
                SocketAddr::new(*ip, port)
            }
        };

        // The connector owns the TCP dial (backend-specific TCP stack).
        let tls_stream = connector.connect(&config, socket_addr).await?;
        let local = tls_stream.local_addr()?;

        let local_addr = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Tls),
            addr: local.into(),
        };
        let (read_half, write_half) = tokio::io::split(TokioSeamStream::new(Arc::from(tls_stream)));
        let (read_half, write_half) = (
            Box::new(read_half) as ClientReadHalf,
            Box::new(write_half) as ClientWriteHalf,
        );

        let connection = Self {
            inner: TlsConnectionInner::Client(Arc::new(StreamConnectionInner::new(
                local_addr.clone(),
                remote_addr.clone(),
                read_half,
                write_half,
            ))),
            cancel_token,
        };
        debug!(
            "Created TLS client connection (platform seam): {} -> {}",
            local_addr, remote_addr
        );

        Ok(connection)
    }

    // Create TLS connection from existing client TLS stream
    pub async fn from_client_stream(
        stream: TlsClientStream,
        remote_addr: SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let local_addr = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Tls),
            addr: stream.get_ref().0.local_addr()?.into(),
        };

        // Split stream into read and write halves
        let (read_half, write_half) = tokio::io::split(stream);
        let (read_half, write_half) = (
            Box::new(read_half) as ClientReadHalf,
            Box::new(write_half) as ClientWriteHalf,
        );

        // Create TLS connection
        let connection = Self {
            inner: TlsConnectionInner::Client(Arc::new(StreamConnectionInner::new(
                local_addr,
                remote_addr.clone(),
                read_half,
                write_half,
            ))),
            cancel_token,
        };

        debug!(
            "Created TLS client connection: {} <- {}",
            connection.get_addr(),
            remote_addr
        );

        Ok(connection)
    }

    // Create TLS connection from existing server TLS stream
    pub async fn from_server_stream(
        stream: TlsServerStream,
        local_addr: SipAddr,
        remote_addr: SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        // Split stream into read and write halves
        let (read_half, write_half) = tokio::io::split(stream);

        // Create TLS connection
        let connection = Self {
            inner: TlsConnectionInner::Server(Arc::new(StreamConnectionInner::new(
                local_addr,
                remote_addr.clone(),
                read_half,
                write_half,
            ))),
            cancel_token,
        };

        debug!(
            "Created TLS server connection: {} <- {}",
            connection.get_addr(),
            remote_addr
        );

        Ok(connection)
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

// Implement StreamConnection trait for TlsConnection
#[async_trait::async_trait]
impl StreamConnection for TlsConnection {
    fn get_addr(&self) -> &SipAddr {
        match &self.inner {
            TlsConnectionInner::Client(inner) => &inner.local_addr,
            TlsConnectionInner::Server(inner) => &inner.local_addr,
        }
    }

    fn get_remote_addr(&self) -> &SipAddr {
        match &self.inner {
            TlsConnectionInner::Client(inner) => &inner.remote_addr,
            TlsConnectionInner::Server(inner) => &inner.remote_addr,
        }
    }

    async fn send_message(&self, msg: SipMessage) -> Result<()> {
        match &self.inner {
            TlsConnectionInner::Client(inner) => inner.send_message(msg).await,
            TlsConnectionInner::Server(inner) => inner.send_message(msg).await,
        }
    }

    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        match &self.inner {
            TlsConnectionInner::Client(inner) => inner.send_raw(data).await,
            TlsConnectionInner::Server(inner) => inner.send_raw(data).await,
        }
    }

    async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        let sip_connection = SipConnection::Tls(self.clone());
        match &self.inner {
            TlsConnectionInner::Client(inner) => inner.serve_loop(sender, sip_connection).await,
            TlsConnectionInner::Server(inner) => inner.serve_loop(sender, sip_connection).await,
        }
    }

    async fn close(&self) -> Result<()> {
        match &self.inner {
            TlsConnectionInner::Client(inner) => inner.close().await,
            TlsConnectionInner::Server(inner) => inner.close().await,
        }
    }
}

impl fmt::Display for TlsConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            TlsConnectionInner::Client(inner) => {
                write!(f, "TLS {} -> {}", inner.local_addr, inner.remote_addr)
            }
            TlsConnectionInner::Server(inner) => {
                write!(f, "TLS {} -> {}", inner.local_addr, inner.remote_addr)
            }
        }
    }
}

impl fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod platform_seam_tests {
    use super::*;
    use crate::platform::tls as seam;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Plaintext pass-through "TLS": proves the registered connector was used
    /// instead of rustls (which would fail to handshake with a plain echoer).
    /// The connector dials `addr` itself, exactly like an embedded backend
    /// (embassy-net + embedded-tls) would.
    struct MockConnector;

    #[async_trait::async_trait]
    impl seam::TlsConnector for MockConnector {
        async fn connect(
            &self,
            _config: &seam::TlsClientConfig,
            addr: SocketAddr,
        ) -> Result<Box<dyn seam::TlsStream>> {
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            let local = tcp.local_addr()?;
            Ok(Box::new(MockStream {
                inner: tcp.into(),
                local,
            }))
        }
    }

    struct MockStream {
        inner: tokio::sync::Mutex<tokio::net::TcpStream>,
        local: SocketAddr,
    }

    #[async_trait::async_trait]
    impl seam::TlsStream for MockStream {
        async fn recv(&self) -> Result<Vec<u8>> {
            let mut buf = vec![0u8; 512];
            let mut tcp = self.inner.lock().await;
            let n = tcp.read(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
        }

        async fn send_all(&self, data: Vec<u8>) -> Result<()> {
            let mut tcp = self.inner.lock().await;
            tcp.write_all(&data).await?;
            Ok(())
        }

        async fn shutdown(&self) -> Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(self.local)
        }
    }

    #[tokio::test]
    async fn platform_connector_takes_precedence_over_rustls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut sock, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf, b"ping");
            tokio::io::AsyncWriteExt::write_all(&mut sock, b"pong")
                .await
                .unwrap();
        });

        seam::set_client_connector(std::sync::Arc::new(MockConnector));

        let remote = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Tls),
            addr: addr.into(),
        };
        let conn = TlsConnection::connect(&remote, None, None, None)
            .await
            .expect("seam connector should bypass rustls entirely");

        conn.send_raw(b"ping").await.unwrap();
        echo.await.unwrap();

        seam::clear_client_connector();
    }
}
