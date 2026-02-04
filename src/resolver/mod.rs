use rsip::{Domain, Port, Transport};
use std::net::SocketAddr;
#[cfg(feature = "srv_lookup")]
pub mod sip_resolver;

#[cfg(feature = "srv_lookup")]
pub use sip_resolver::SipResolver;

#[cfg(not(feature = "srv_lookup"))]
pub type SipResolver = DummyResolver;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub addr: SocketAddr,
    pub transport: Transport,
}

#[derive(Debug, Clone)]
pub struct DummyResolver {}

impl Default for DummyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DummyResolver {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn lookup(
        &self,
        domain: &Domain,
        port: Option<Port>,
        transport: Option<Transport>,
        secure: bool,
    ) -> Result<Vec<Target>, String> {
        // Dummy implementation: A/AAAA only using system resolver (tokio::net::lookup_host)
        let domain_str = domain.to_string();

        let actual_port: u16 = if let Some(p) = port {
            p.into()
        } else {
            let t = transport.unwrap_or(if secure {
                Transport::Tls
            } else {
                Transport::Udp
            });
            t.default_port().into()
        };

        let addr_str = format!("{}:{}", domain_str, actual_port);
        let lookup_result = tokio::net::lookup_host(&addr_str).await;

        match lookup_result {
            Ok(addrs) => {
                let t = transport.unwrap_or(if secure {
                    Transport::Tls
                } else {
                    Transport::Udp
                });
                let targets: Vec<Target> =
                    addrs.map(|addr| Target { addr, transport: t }).collect();

                if targets.is_empty() {
                    Err(format!("No addresses found for {}", domain_str))
                } else {
                    Ok(targets)
                }
            }
            Err(e) => Err(format!("DNS resolution failed for {}: {}", domain_str, e)),
        }
    }
}
