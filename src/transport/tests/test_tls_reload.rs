use crate::Result;
use std::sync::Arc;

/// Generate a self-signed certificate and key for testing
#[cfg(feature = "rustls")]
fn generate_test_cert(subject_cn: &str) -> std::result::Result<(String, String), std::io::Error> {
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
    use crate::transport::{SipAddr, TlsConfig, TlsListenerConnection};
    use std::net::SocketAddr;

    let (cert, key) = generate_test_cert("test.example.com")?;
    let socket_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let local_addr = SipAddr::new(rsip::transport::Transport::Tls, socket_addr.into());

    let config = TlsConfig {
        cert: Some(cert.into_bytes()),
        key: Some(key.into_bytes()),
        ..Default::default()
    };

    let _tls_listener = TlsListenerConnection::new(local_addr, None, config).await?;

    Ok(())
}
