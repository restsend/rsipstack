use clap::Parser;
/// SIP Caller 主程序（使用 rsipstack）
///
/// 演示如何使用 rsipstack 进行注册和呼叫
mod sip_client;
mod config;
mod sip_dialog;
mod rtp;
mod sip_transport;
mod utils;

use sip_client::{SipClient, SipClientConfig};
use config::Protocol;
use tracing::info;

/// SIP Caller - 基于 Rust 的 SIP 客户端
#[derive(Parser, Debug)]
#[command(name = "sip-caller")]
#[command(author = "SIP Caller Team")]
#[command(version = "0.2.0")]
#[command(about = "SIP 客户端，支持注册和呼叫功能", long_about = None)]
struct Args {
    /// SIP 服务器地址（例如：127.0.0.1:5060）
    #[arg(short, long, default_value = "xfc:5060")]
    server: String,

    /// 传输协议类型 (udp, tcp, ws, wss)
    #[arg(long, default_value = "udp")]
    protocol: Protocol,

    /// Outbound 代理服务器地址（可选，例如：proxy.example.com:5060）
    #[arg(long)]
    outbound_proxy: Option<String>,

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
        "SIP Caller 启动 - 服务器: {}, 协议: {}, 代理: {}, 用户: {}, 目标: {}, IPv6: {}, RTP端口: {}, User-Agent: {}",
        args.server,
        args.protocol,
        args.outbound_proxy.as_deref().unwrap_or("无"),
        args.user,
        args.target,
        args.ipv6,
        args.rtp_start_port,
        args.user_agent
    );

    // 创建客户端配置
    let config = SipClientConfig {
        server: args.server,
        protocol: args.protocol,
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
