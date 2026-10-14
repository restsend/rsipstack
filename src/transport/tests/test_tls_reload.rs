use crate::Result;
use std::sync::Arc;

/// Generate a self-signed certificate and key for testing
#[cfg(feature = "rustls")]
pub(super) fn generate_test_cert(
    subject_cn: &str,
) -> std::result::Result<(String, String), std::io::Error> {
    use std::process::Command;
    use tempfile::TempDir;

    let temp_dir = TempDir::new()?;
    let key_path = temp_dir.path().join("key.pem");
    let cert_path = temp_dir.path().join("cert.pem");

    // Generate private key
    let key_gen = Command::new("openssl")
        .args(["genrsa", "-out", key_path.to_str().unwrap(), "2048"])
        .output()?;

    if !key_gen.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to generate private key",
        ));
    }

    // Generate self-signed certificate
    let cert_gen = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            key_path.to_str().unwrap(),
            "-sha256",
            "-days",
            "1",
            "-out",
            cert_path.to_str().unwrap(),
            "-outform",
            "PEM",
            "-subj",
            &format!("/CN={}", subject_cn),
            "-addext",
            "subjectAltName=DNS:localhost",
        ])
        .output()?;

    if !cert_gen.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to generate certificate",
        ));
    }

    // Read the generated files
    let key_pem = std::fs::read_to_string(&key_path)?;
    let cert_pem = std::fs::read_to_string(&cert_path)?;

    // temp_dir will be cleaned up when dropped
    Ok((cert_pem, key_pem))
}

/// Get the default crypto provider for testing
#[cfg(feature = "rustls")]
fn get_test_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let temp_builder = rustls::ServerConfig::builder();
    let provider = temp_builder.crypto_provider().clone();
    provider
}

/// Test ReloadableCertResolver creation with valid certificate
#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_reloadable_cert_resolver_new() -> Result<()> {
    use crate::transport::tls::ReloadableCertResolver;

    let (cert, key) = generate_test_cert("test1.example.com")?;
    let provider = get_test_provider();

    let resolver = ReloadableCertResolver::new(cert.as_bytes(), key.as_bytes(), provider)?;

    // Verify resolver was created successfully
    assert!(!format!("{:?}", resolver).is_empty());

    Ok(())
}

/// Test ReloadableCertResolver reload with new certificate
#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_reloadable_cert_resolver_reload() -> Result<()> {
    use crate::transport::tls::ReloadableCertResolver;

    let (cert1, key1) = generate_test_cert("test1.example.com")?;
    let (cert2, key2) = generate_test_cert("test2.example.com")?;
    let provider = get_test_provider();

    let resolver =
        ReloadableCertResolver::new(cert1.as_bytes(), key1.as_bytes(), provider.clone())?;

    // Reload with new certificate
    resolver.reload(cert2.as_bytes(), key2.as_bytes())?;

    // Verify reload succeeded (no error)
    Ok(())
}

/// Test ReloadableCertResolver error handling with invalid PEM
#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_reload_error_handling() -> Result<()> {
    use crate::transport::tls::ReloadableCertResolver;

    let (cert, key) = generate_test_cert("test.example.com")?;
    let provider = get_test_provider();

    let resolver = ReloadableCertResolver::new(cert.as_bytes(), key.as_bytes(), provider)?;

    // Try to reload with invalid certificate - should return error
    let invalid_cert = b"not a valid certificate";
    let result = resolver.reload(invalid_cert, key.as_bytes());

    // Should return an error (old cert should be preserved)
    assert!(result.is_err());

    Ok(())
}

/// Test ReloadableCertResolver error handling with invalid key
#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_reload_error_handling_invalid_key() -> Result<()> {
    use crate::transport::tls::ReloadableCertResolver;

    let (cert, key) = generate_test_cert("test.example.com")?;
    let provider = get_test_provider();

    let resolver = ReloadableCertResolver::new(cert.as_bytes(), key.as_bytes(), provider)?;

    // Try to reload with invalid key - should return error
    let invalid_key = b"not a valid key";
    let result = resolver.reload(cert.as_bytes(), invalid_key);

    // Should return an error (old cert should be preserved)
    assert!(result.is_err());

    Ok(())
}

/// Test that TlsListenerConnection can be created with TlsConfig
#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_tls_listener_connection_with_config() -> Result<()> {
    use crate::transport::{TlsConfig, TlsListenerConnection};
    use std::net::SocketAddr;

    let (cert, key) = generate_test_cert("test.example.com")?;
    let socket_addr: SocketAddr = "127.0.0.1:0".parse()?;

    let config = TlsConfig {
        cert: Some(cert.into_bytes()),
        key: Some(key.into_bytes()),
        ..Default::default()
    };

    let tls_listener = TlsListenerConnection::new(socket_addr, None, config).await?;
    assert_eq!(
        tls_listener.get_addr().r#type,
        Some(crate::sip::transport::Transport::Tls)
    );

    Ok(())
}

/// A handshake after `reload_tls_config` must present the new certificate.
///
/// The acceptor used to hold a clone of the resolver, so a reload changed
/// the stored resolver but never the one that answers handshakes.
#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_reload_tls_config_reaches_handshake() -> Result<()> {
    use crate::transport::{TlsConfig, TlsListenerConnection, TransportLayer};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;

    /// Accepts any certificate and records the one the server presented.
    #[derive(Debug)]
    struct Recorder {
        seen: Mutex<Option<CertificateDer<'static>>>,
        schemes: Vec<SignatureScheme>,
    }

    impl ServerCertVerifier for Recorder {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            *self.seen.lock().unwrap() = Some(end_entity.clone().into_owned());
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.schemes.clone()
        }
    }

    /// Connects once and returns the certificate the server presented.
    async fn presented_cert(addr: SocketAddr) -> Result<CertificateDer<'static>> {
        let provider = get_test_provider();
        let recorder = Arc::new(Recorder {
            seen: Mutex::new(None),
            schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        });
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| crate::Error::Error(e.to_string()))?
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(recorder.clone());
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        tls.shutdown().await.ok();
        let seen = recorder.seen.lock().unwrap().clone();
        seen.ok_or_else(|| crate::Error::Error("no certificate seen".to_string()))
    }

    let (cert1, key1) = generate_test_cert("before.example.com")?;
    let (cert2, key2) = generate_test_cert("after.example.com")?;
    let der1 = CertificateDer::from_pem_slice(cert1.as_bytes()).unwrap();
    let der2 = CertificateDer::from_pem_slice(cert2.as_bytes()).unwrap();
    assert_ne!(der1, der2);

    // A free port; the listener binds with SO_REUSEADDR.
    let addr = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        probe.local_addr()?
    };
    let cancel = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel.clone());
    let listener = TlsListenerConnection::new(
        addr,
        None,
        TlsConfig {
            cert: Some(cert1.into_bytes()),
            key: Some(key1.into_bytes()),
            ..Default::default()
        },
    )
    .await?;
    listener
        .serve_listener(transport_layer.inner.clone())
        .await?;

    let first = tokio::time::timeout(Duration::from_secs(5), presented_cert(addr))
        .await
        .expect("first handshake timed out")?;
    assert_eq!(
        first, der1,
        "the listener starts with the first certificate"
    );

    listener
        .reload_tls_config(cert2.into_bytes(), key2.into_bytes())
        .await?;

    let second = tokio::time::timeout(Duration::from_secs(5), presented_cert(addr))
        .await
        .expect("second handshake timed out")?;
    assert_eq!(
        second, der2,
        "a handshake after the reload gets the new certificate"
    );

    cancel.cancel();
    Ok(())
}
