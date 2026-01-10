/// SIP 工具函数模块
///
/// 提供自定义的 SIP 相关辅助函数，用于覆盖 rsipstack 的默认行为
use crate::config::Protocol;
use std::net::IpAddr;

/// 从 SIP URI 中提取 transport 协议
///
/// 按照以下优先级提取:
/// 1. 显式的 transport 参数 (如 ;transport=tcp)
/// 2. 根据 URI scheme 推断 (sips -> TCP, sip -> UDP)
///
/// # 参数
/// - `uri`: SIP URI 对象引用
///
/// # 返回
/// 提取到的 Protocol 类型
///
/// # 示例
/// ```rust,no_run
/// use rsip::Uri;
/// use sip_caller::utils::extract_protocol_from_uri;
///
/// let uri: Uri = "sip:example.com:5060;transport=tcp".try_into().unwrap();
/// let protocol = extract_protocol_from_uri(&uri);
/// assert_eq!(protocol, Protocol::Tcp);
///
/// let uri2: Uri = "sips:example.com:5061".try_into().unwrap();
/// let protocol2 = extract_protocol_from_uri(&uri2);
/// assert_eq!(protocol2, Protocol::Tcp); // sips 默认 TLS over TCP
/// ```
pub fn extract_protocol_from_uri(uri: &rsip::Uri) -> Protocol {
    // 1. 优先从 transport 参数提取
    uri.params
        .iter()
        .find_map(|p| match p {
            rsip::Param::Transport(t) => Some((*t).into()),
            _ => None,
        })
        .unwrap_or_else(|| {
            // 2. 根据 scheme 返回默认值
            match uri.scheme.as_ref() {
                Some(rsip::Scheme::Sips) => Protocol::Tcp, // sips默认TLS over TCP
                Some(rsip::Scheme::Sip) | Some(rsip::Scheme::Other(_)) | None => Protocol::Udp,
            }
        })
}

/// 初始化日志系统
///
/// # 参数
/// - `log_level`: 日志级别字符串 (trace, debug, info, warn, error)
///
/// # 示例
/// ```rust,no_run
/// initialize_logging("debug");
/// ```
pub fn initialize_logging(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => {
            eprintln!("无效的日志级别 '{}', 使用默认值 'info'", log_level);
            tracing::Level::INFO
        }
    };

    tracing_subscriber::fmt().with_max_level(level).init();
}

/// 获取第一个非回环的网络接口 IP 地址
///
/// 遍历系统所有网络接口，优先返回指定版本的 IP 地址，
/// 如果找不到则自动回退到另一个版本
///
/// # 参数
/// - `prefer_ipv6`: 是否优先使用 IPv6 地址
///
/// # 返回
/// - `Ok(IpAddr)` - 成功找到的 IP 地址（IPv4 或 IPv6）
/// - `Err` - 未找到可用的网络接口
///
/// # 行为
/// - 当 `prefer_ipv6 = true` 时：优先返回 IPv6，找不到则回退到 IPv4
/// - 当 `prefer_ipv6 = false` 时：优先返回 IPv4，找不到则回退到 IPv6
///
/// # 示例
/// ```rust,no_run
/// use sip_caller::utils::get_first_non_loopback_interface;
///
/// // 优先使用 IPv6，找不到则回退到 IPv4
/// let local_ip = get_first_non_loopback_interface(true).unwrap();
/// println!("本地IP: {}", local_ip);
///
/// // 只使用 IPv4
/// let local_ip_v4 = get_first_non_loopback_interface(false).unwrap();
/// println!("本地IPv4: {}", local_ip_v4);
/// ```
pub fn get_first_non_loopback_interface(
    prefer_ipv6: bool,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let interfaces = get_if_addrs::get_if_addrs()?;

    let mut ipv4_addr = None;
    let mut ipv6_addr = None;

    // 遍历所有接口，收集可用的 IPv4 和 IPv6 地址
    for interface in interfaces {
        if !interface.is_loopback() {
            match interface.addr {
                get_if_addrs::IfAddr::V4(ref addr) => {
                    if ipv4_addr.is_none() {
                        ipv4_addr = Some(IpAddr::V4(addr.ip));
                    }
                }
                get_if_addrs::IfAddr::V6(ref addr) => {
                    if ipv6_addr.is_none() {
                        ipv6_addr = Some(IpAddr::V6(addr.ip));
                    }
                }
            }
        }
    }

    // 根据优先级返回
    if prefer_ipv6 {
        // 优先 IPv6，回退到 IPv4
        if let Some(addr) = ipv6_addr {
            return Ok(addr);
        }
        if let Some(addr) = ipv4_addr {
            tracing::info!("未找到 IPv6 接口，回退使用 IPv4: {}", addr);
            return Ok(addr);
        }
    } else {
        // 优先 IPv4，回退到 IPv6
        if let Some(addr) = ipv4_addr {
            return Ok(addr);
        }
        if let Some(addr) = ipv6_addr {
            tracing::info!("未找到 IPv4 接口，回退使用 IPv6: {}", addr);
            return Ok(addr);
        }
    }

    Err("未找到可用的网络接口".into())
}

#[test]
fn test_get_first_non_loopback_interface_ipv4() {
    // 测试优先 IPv4
    let result = get_first_non_loopback_interface(false);

    // 至少应该能找到一个接口（无论是 IPv4 还是 IPv6）
    assert!(
        result.is_ok(),
        "应该能找到至少一个网络接口（可能回退到 IPv6）"
    );
}

#[test]
fn test_get_first_non_loopback_interface_ipv6() {
    // 测试优先 IPv6
    let result = get_first_non_loopback_interface(true);

    // 至少应该能找到一个接口（可能回退到 IPv4）
    assert!(
        result.is_ok(),
        "应该能找到至少一个网络接口（可能回退到 IPv4）"
    );
}

#[test]
fn test_get_first_non_loopback_interface_return_type() {
    // 测试返回的地址不是回环地址
    if let Ok(addr) = get_first_non_loopback_interface(false) {
        assert!(!addr.is_loopback(), "返回的地址不应该是回环地址");
    }
}
