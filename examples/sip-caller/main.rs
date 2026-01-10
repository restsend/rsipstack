use clap::Parser;
mod config;
mod rtp;
/// SIP Caller 主程序（使用 rsipstack）
///
/// 演示如何使用 rsipstack 进行注册和呼叫
mod sip_client;
mod sip_dialog;
mod sip_transport;
mod utils;

use sip_client::{SipClient, SipClientConfig};
use tracing::info;

/// 解析 SIP URI，支持简单格式和完整 URI 格式
///
/// 简单格式如 "example.com:5060" 会自动添加 "sip:" scheme
/// 完整格式如 "sip:example.com:5060;transport=tcp" 直接解析
fn parse_sip_uri(s: &str) -> Result<rsip::Uri, String> {
    // 如果不包含 scheme，添加默认的 sip:
    let uri_with_scheme = if !s.contains(':') || s.chars().filter(|&c| c == ':').count() == 1 {
        format!("sip:{}", s)
    } else {
        s.to_string()
    };

    uri_with_scheme
        .as_str()
        .try_into()
        .map_err(|e: rsip::Error| format!("无效的 SIP URI '{}': {}", s, e))
}

/// SIP Caller - 基于 Rust 的 SIP 客户端
#[derive(Parser, Debug)]
#[command(name = "sip-caller")]
#[command(author = "SIP Caller Team")]
#[command(version = "0.2.0")]
#[command(about = "SIP 客户端，支持注册和呼叫功能", long_about = None)]
struct Args {
    /// SIP 服务器地址
    /// 支持多种格式：
    ///   - 简单格式: "example.com:5060" (默认UDP)
    ///   - 完整URI: "sip:example.com:5060;transport=tcp"
    ///   - SIPS URI: "sips:example.com:5061" (自动使用TLS over TCP)
    #[arg(short, long, value_parser = parse_sip_uri, default_value = "xfc:5060")]
    server: rsip::Uri,

    /// Outbound 代理服务器地址（可选）
    /// 支持完整URI格式，例如: "sip:proxy.example.com:5060;transport=udp;lr"
    /// Transport参数将自动从URI中提取
    #[arg(long, value_parser = parse_sip_uri)]
    outbound_proxy: Option<rsip::Uri>,

    /// SIP 用户 ID（例如：alice@example.com）
    #[arg(short, long, default_value = "1001")]
    user: String,

    /// SIP 密码
    #[arg(short, long, default_value = "admin")]
    password: String,

    /// 呼叫目标（例如：bob@example.com）
    #[arg(short, long, default_value = "1000")]
    target: String,

    /// 本地 SIP 端口
    #[arg(long, default_value = "0")]
    local_port: u16,

    /// 优先使用 IPv6（找不到时自动回退到 IPv4）
    #[arg(long, default_value = "false")]
    ipv6: bool,

    /// RTP 起始端口
    #[arg(long, default_value = "20000")]
    rtp_start_port: u16,

    /// User-Agent 标识
    #[arg(long, default_value = "RSipCaller/0.2.0")]
    user_agent: String,

    /// 日志级别 (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 解析命令行参数
    let args = Args::parse();

    // 初始化日志系统
    utils::initialize_logging(&args.log_level);

    info!(
        "SIP Caller 启动 - 服务器: {}, 代理: {}, 用户: {}, 目标: {}, IPv6: {}, RTP端口: {}, User-Agent: {}",
        args.server,
        args.outbound_proxy.as_ref().map(|u| u.to_string()).unwrap_or_else(|| "无".to_string()),
        args.user,
        args.target,
        args.ipv6,
        args.rtp_start_port,
        args.user_agent
    );

    // 创建客户端配置
    let config = SipClientConfig {
        server: args.server,
        outbound_proxy: args.outbound_proxy,
        username: args.user,
        password: args.password,
        local_port: args.local_port,
        prefer_ipv6: args.ipv6,
        rtp_start_port: args.rtp_start_port,
        user_agent: args.user_agent,
    };

    // 创建 SIP 客户端
    let client = SipClient::new(config).await?;

    // 执行注册
    let response = client.register().await?;
    if response.status_code != rsip::StatusCode::OK {
        return Err(format!("注册失败: {}", response.status_code).into());
    }

    // 发起呼叫
    client.make_call(&args.target).await?;

    // 关闭客户端
    client.shutdown().await;

    Ok(())
}
