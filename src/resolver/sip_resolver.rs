use rsip::{Domain, Port, Transport};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use hickory_resolver::TokioResolver;
use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub addr: SocketAddr,
    pub transport: Transport,
}

#[derive(Debug, Clone)]
pub struct SipResolver {
    resolver: Arc<TokioResolver>,
}

impl Default for SipResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SipResolver {
    pub fn new() -> Self {
        let resolver = TokioResolver::builder_tokio()
            .expect("Unexpected error creating DNS resolver")
            .build();
        Self {
            resolver: Arc::new(resolver),
        }
    }

    /// Main lookup function implementing core of RFC 3263 (SRV + Fallback)
    pub async fn lookup(
        &self,
        domain: &Domain,
        port: Option<Port>,
        transport: Option<Transport>,
        secure: bool,
    ) -> Result<Vec<Target>, String> {
        let source = HickorySource(self.resolver.clone());
        resolve_logic(&source, domain, port, transport, secure).await
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrvRecord {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

#[async_trait::async_trait]
pub trait LookupSource: Send + Sync {
    async fn lookup_srv(&self, name: &str) -> Result<Vec<SrvRecord>, String>;
    async fn lookup_a_aaaa(&self, name: &str) -> Result<Vec<IpAddr>, String>;
}

struct HickorySource(Arc<TokioResolver>);

#[async_trait::async_trait]
impl LookupSource for HickorySource {
    async fn lookup_srv(&self, name: &str) -> Result<Vec<SrvRecord>, String> {
        match self.0.srv_lookup(name).await {
            Ok(records) => {
                let mut res = Vec::new();
                for r in records {
                    let target = r.target().to_string();
                    // Remove trailing dot
                    let target = target.trim_end_matches('.').to_string();
                    res.push(SrvRecord {
                        target,
                        port: r.port(),
                        priority: r.priority(),
                        weight: r.weight(),
                    });
                }
                Ok(res)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    async fn lookup_a_aaaa(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        match self.0.lookup_ip(name).await {
            Ok(records) => Ok(records.iter().collect()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub async fn resolve_logic<S: LookupSource + ?Sized>(
    source: &S,
    domain: &Domain,
    port: Option<Port>,
    transport: Option<Transport>,
    secure: bool,
) -> Result<Vec<Target>, String> {
    let domain_str = domain.to_string();

    if let Ok(ip) = IpAddr::from_str(&domain_str) {
        let t = transport.unwrap_or(if secure {
            Transport::Tls
        } else {
            Transport::Udp
        });
        let p: u16 = port
            .map(|p| p.into())
            .unwrap_or_else(|| t.default_port().into());
        return Ok(vec![Target {
            addr: SocketAddr::new(ip, p),
            transport: t,
        }]);
    }

    if let Some(p) = port {
        let t = transport.unwrap_or(if secure {
            Transport::Tls
        } else {
            Transport::Udp
        });
        let ips = source.lookup_a_aaaa(&domain_str).await.unwrap_or_default();

        if ips.is_empty() {
            return Err(format!("Could not resolve IP for {}", domain_str));
        }

        let p_u16: u16 = p.into();
        let targets = ips
            .into_iter()
            .map(|ip| Target {
                addr: SocketAddr::new(ip, p_u16),
                transport: t,
            })
            .collect();
        return Ok(targets);
    }

    let mut targets = Vec::new();
    let mut candidates = Vec::new();

    if let Some(t) = transport {
        candidates.push(t);
    } else {
        if secure {
            candidates.push(Transport::Tls);
        } else {
            candidates.push(Transport::Udp);
            candidates.push(Transport::Tcp);
        }
    }

    let mut _srv_found = false;

    for t in candidates.iter() {
        let prefix = srv_prefix(*t, secure);
        if prefix.is_empty() {
            continue;
        } // Unsupported transport for SRV

        let srv_name = format!("{}.{}", prefix, domain_str);

        if let Ok(records) = source.lookup_srv(&srv_name).await {
            if !records.is_empty() {
                _srv_found = true;
                let ordered = order_srv_records(records);

                for rec in ordered {
                    // Start sub-query for A/AAAA
                    if let Ok(ips) = source.lookup_a_aaaa(&rec.target).await {
                        for ip in ips {
                            targets.push(Target {
                                addr: SocketAddr::new(ip, rec.port),
                                transport: *t,
                            });
                        }
                    }
                }
            }
        }
    }

    if targets.is_empty() {
        let def_transport = transport.unwrap_or(if secure {
            Transport::Tls
        } else {
            Transport::Udp
        });
        let def_port = def_transport.default_port();

        match source.lookup_a_aaaa(&domain_str).await {
            Ok(ips) if !ips.is_empty() => {
                for ip in ips {
                    targets.push(Target {
                        addr: SocketAddr::new(ip, def_port.into()),
                        transport: def_transport,
                    });
                }
                Ok(targets)
            }
            _ => Err(format!("Resolution failed for {}", domain_str)),
        }
    } else {
        Ok(targets)
    }
}

fn srv_prefix(transport: Transport, secure: bool) -> &'static str {
    match (transport, secure) {
        (Transport::Udp, false) => "_sip._udp",
        (Transport::Tcp, false) => "_sip._tcp",
        (Transport::Tls, _) => "_sips._tcp",
        (Transport::Tcp, true) => "_sips._tcp",
        (Transport::Wss, true) => "_sips._tcp", // Common practice fallback
        _ => "",
    }
}

fn order_srv_records(mut records: Vec<SrvRecord>) -> Vec<SrvRecord> {
    records.sort_by_key(|k| k.priority);

    let mut ordered = Vec::new();
    let mut start_idx = 0;

    while start_idx < records.len() {
        let current_priority = records[start_idx].priority;
        let mut end_idx = start_idx;

        // Find range with same priority
        while end_idx < records.len() && records[end_idx].priority == current_priority {
            end_idx += 1;
        }

        // Group of records with same priority
        let mut group = records[start_idx..end_idx].to_vec();

        // Selection sort based on weights
        while !group.is_empty() {
            let total_weight: u32 = group.iter().map(|r| r.weight as u32).sum();
            let mut rng = rand::rng();

            if total_weight == 0 {
                // All zero, just pick one (shuffle or first)
                let idx = rng.random_range(0..group.len()); // 0..len (exclusive) => OK
                ordered.push(group.remove(idx));
            } else {
                let mut r = rng.random_range(0..=total_weight); // 0..=total
                let mut selected_idx = 0;
                for (i, rec) in group.iter().enumerate() {
                    let w = rec.weight as u32;
                    if r <= w {
                        selected_idx = i;
                        break;
                    }
                    r -= w;
                }
                if selected_idx >= group.len() {
                    selected_idx = group.len() - 1;
                }

                ordered.push(group.remove(selected_idx));
            }
        }

        start_idx = end_idx;
    }

    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockDns {
        srv: Mutex<HashMap<String, Vec<SrvRecord>>>,
        a: Mutex<HashMap<String, Vec<IpAddr>>>,
    }

    impl MockDns {
        fn new() -> Self {
            Self {
                srv: Mutex::new(HashMap::new()),
                a: Mutex::new(HashMap::new()),
            }
        }

        fn add_srv(&self, name: &str, target: &str, port: u16, priority: u16, weight: u16) {
            let mut map = self.srv.lock().unwrap();
            map.entry(name.to_string()).or_default().push(SrvRecord {
                target: target.to_string(),
                port,
                priority,
                weight,
            });
        }

        fn add_a(&self, name: &str, ip: IpAddr) {
            let mut map = self.a.lock().unwrap();
            map.entry(name.to_string()).or_default().push(ip);
        }
    }

    #[async_trait::async_trait]
    impl LookupSource for MockDns {
        async fn lookup_srv(&self, name: &str) -> Result<Vec<SrvRecord>, String> {
            let map = self.srv.lock().unwrap();
            if let Some(recs) = map.get(name) {
                Ok(recs.clone())
            } else {
                Err("Not found".to_string())
            }
        }

        async fn lookup_a_aaaa(&self, name: &str) -> Result<Vec<IpAddr>, String> {
            let map = self.a.lock().unwrap();
            if let Some(ips) = map.get(name) {
                Ok(ips.clone())
            } else {
                Err("Not found".to_string())
            }
        }
    }

    #[tokio::test]
    async fn test_ip_direct() {
        let mock = MockDns::new();
        let domain = Domain::from("127.0.0.1".to_string());

        let res = resolve_logic(&mock, &domain, None, None, false)
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].addr.ip().to_string(), "127.0.0.1");
        assert_eq!(res[0].transport, Transport::Udp); // Default insecure
    }

    #[tokio::test]
    async fn test_domain_with_port() {
        let mock = MockDns::new();
        mock.add_a("example.com", "1.2.3.4".parse().unwrap());

        let domain = Domain::from("example.com".to_string());
        let res = resolve_logic(
            &mock,
            &domain,
            Some(5090.into()),
            Some(Transport::Tcp),
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].addr, "1.2.3.4:5090".parse().unwrap());
        assert_eq!(res[0].transport, Transport::Tcp);
    }

    #[tokio::test]
    async fn test_srv_lookup_basic() {
        let mock = MockDns::new();
        // Setup SRV
        mock.add_srv("_sip._udp.example.com", "sip1.example.com", 5060, 10, 100);

        // Setup A
        mock.add_a("sip1.example.com", "10.0.0.1".parse().unwrap());

        let domain = Domain::from("example.com".to_string());
        let res = resolve_logic(&mock, &domain, None, Some(Transport::Udp), false)
            .await
            .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].addr, "10.0.0.1:5060".parse().unwrap());
        assert_eq!(res[0].transport, Transport::Udp);
    }

    #[tokio::test]
    async fn test_srv_priority() {
        let mock = MockDns::new();
        // Priority 10 vs 20
        mock.add_srv("_sip._udp.example.com", "high.example.com", 5060, 10, 100);
        mock.add_srv("_sip._udp.example.com", "low.example.com", 5060, 20, 100);

        mock.add_a("high.example.com", "1.1.1.1".parse().unwrap());
        mock.add_a("low.example.com", "2.2.2.2".parse().unwrap());

        let domain = Domain::from("example.com".to_string());
        let res = resolve_logic(&mock, &domain, None, Some(Transport::Udp), false)
            .await
            .unwrap();

        assert_eq!(res.len(), 2);
        assert_eq!(res[0].addr.ip().to_string(), "1.1.1.1");
        assert_eq!(res[1].addr.ip().to_string(), "2.2.2.2");

        // Check order
        let ips: Vec<String> = res.iter().map(|t| t.addr.ip().to_string()).collect();
        assert_eq!(ips, vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[tokio::test]
    async fn test_fallback_to_a() {
        let mock = MockDns::new();
        // No SRV records added
        mock.add_a("example.com", "9.9.9.9".parse().unwrap());

        let domain = Domain::from("example.com".to_string());
        let res = resolve_logic(&mock, &domain, None, Some(Transport::Udp), false)
            .await
            .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].addr, "9.9.9.9:5060".parse().unwrap());
    }

    #[test]
    fn test_srv_ordering_weight() {
        let records = vec![
            SrvRecord {
                target: "a".into(),
                port: 1,
                priority: 1,
                weight: 10,
            },
            SrvRecord {
                target: "b".into(),
                port: 1,
                priority: 1,
                weight: 90,
            },
        ];

        // This is randomized, but checking it runs without panic
        let ordered = order_srv_records(records);
        assert_eq!(ordered.len(), 2);
    }
}
