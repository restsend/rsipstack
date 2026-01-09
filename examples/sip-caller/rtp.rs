/// RTP 媒体流处理模块
///
/// 提供 RTP 连接建立、音频播放等功能
use rsipstack::transport::udp::UdpConnection;
use rsipstack::transport::SipAddr;
use rsipstack::{Error, Result};
use rtp_rs::RtpPacketBuilder;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// 媒体会话配置选项
#[derive(Debug, Clone)]
pub struct MediaSessionOption {
    /// RTP 起始端口
    pub rtp_start_port: u16,
    /// 外部 IP 地址（用于 NAT 穿透）
    pub external_ip: Option<String>,
    /// 取消令牌
    pub cancel_token: CancellationToken,
}

impl Default for MediaSessionOption {
    fn default() -> Self {
        Self {
            rtp_start_port: 20000,
            external_ip: None,
            cancel_token: CancellationToken::new(),
        }
    }
}

/// 构建 RTP 连接并生成 SDP
///
/// # 参数
/// * `local_ip` - 本地 IP 地址
/// * `opt` - 媒体会话配置选项
/// * `ssrc` - RTP 同步源标识符
/// * `payload_type` - 有效载荷类型 (0=PCMU, 8=PCMA)
///
/// # 返回
/// 返回 UDP 连接和 SDP 字符串
pub async fn build_rtp_conn(
    local_ip: IpAddr,
    opt: &MediaSessionOption,
    ssrc: u32,
    payload_type: u8,
) -> Result<(UdpConnection, String)> {
    let mut conn = None;

    // 尝试绑定 100 个端口
    for p in 0..100 {
        let port = opt.rtp_start_port + p * 2;
        let addr = format!("{}:{}", local_ip, port).parse()?;

        if let Ok(c) = UdpConnection::create_connection(
            addr,
            opt.external_ip
                .as_ref()
                .map(|ip| ip.parse::<SocketAddr>().expect("Invalid external IP")),
            Some(opt.cancel_token.clone()),
        )
        .await
        {
            conn = Some(c);
            break;
        }
    }

    if conn.is_none() {
        return Err(Error::Error("无法绑定 RTP 端口".to_string()));
    }

    let conn = conn.unwrap();
    let codec = payload_type;
    let codec_name = match codec {
        0 => "PCMU",
        8 => "PCMA",
        _ => "Unknown",
    };

    let socketaddr: SocketAddr = conn.get_addr().addr.to_owned().try_into()?;

    // 生成 SDP 描述
    let sdp = format!(
        "v=0\r\n\
        o=- 0 0 IN IP4 {}\r\n\
        s=rsipstack\r\n\
        c=IN IP4 {}\r\n\
        t=0 0\r\n\
        m=audio {} RTP/AVP {codec}\r\n\
        a=rtpmap:{codec} {codec_name}/8000\r\n\
        a=ssrc:{ssrc}\r\n\
        a=sendrecv\r\n",
        socketaddr.ip(),
        socketaddr.ip(),
        socketaddr.port(),
    );

    info!("✓ RTP 连接已建立: {}", conn.get_addr().addr);
    tracing::debug!("SDP 内容:\n{}", sdp);
    Ok((conn, sdp))
}

/// 播放回声（将接收到的数据原样发送回去）
///
/// # 参数
/// * `conn` - UDP 连接
/// * `token` - 取消令牌
/// * `peer_addr` - 对端 RTP 地址
/// * `ssrc` - RTP 同步源标识符
pub async fn play_echo(
    conn: UdpConnection,
    token: CancellationToken,
    peer_addr: String,
    ssrc: u32,
) -> Result<()> {
    use rsipstack::transport::SipAddr;
    use rtp_rs::RtpReader;

    info!("✓ RTP 回声模式已启动");
    let mut packet_count = 0u64;
    let mut seq = 0u16;
    let mut ts = 0u32;

    // 将对端地址解析为 SipAddr
    let peer_sip_addr = SipAddr {
        addr: peer_addr
            .try_into()
            .map_err(|e| Error::Error(format!("解析对端地址失败: {:?}", e)))?,
        r#type: Some(rsip::transport::Transport::Udp),
    };

    // 先发送几个静音包来"打开"NAT和激活对端
    info!("发送初始静音包以激活 RTP 流...");
    let silence_packet = vec![0u8; 160]; // G.711 静音包
    for i in 0..5 {
        let rtp_packet = match rtp_rs::RtpPacketBuilder::new()
            .payload_type(0) // PCMU
            .ssrc(ssrc)
            .sequence((i as u16).into())
            .timestamp(i * 160)
            .payload(&silence_packet)
            .build()
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("构建初始 RTP 包失败: {:?}", e);
                break;
            }
        };

        if let Err(e) = conn.send_raw(&rtp_packet, &peer_sip_addr).await {
            tracing::warn!("发送初始 RTP 包失败: {:?}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    info!("初始静音包已发送，等待接收对端 RTP 数据...");

    select! {
        _ = token.cancelled() => {
            tracing::debug!("RTP 回声会话已取消，共处理 {} 个数据包", packet_count);
        }
        _ = async {
            loop {
                let mut mbuf = vec![0; 1500];
                let (len, _addr) = match conn.recv_raw(&mut mbuf).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("接收 RTP 数据失败: {:?}", e);
                        break;
                    }
                };

                packet_count += 1;
                if packet_count == 1 {
                    info!("✓ 开始接收 RTP 数据包");
                } else if packet_count.is_multiple_of(50) {
                    tracing::debug!("已处理 {} 个 RTP 数据包", packet_count);
                }

                // 解析接收到的 RTP 包
                let rtp_reader = match RtpReader::new(&mbuf[..len]) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("解析 RTP 包失败: {:?}", e);
                        continue;
                    }
                };

                // 提取有效载荷
                let payload = rtp_reader.payload();
                let payload_type = rtp_reader.payload_type();

                // 用我们自己的 SSRC 重新打包
                let echo_packet = match RtpPacketBuilder::new()
                    .payload_type(payload_type)
                    .ssrc(ssrc)
                    .sequence(seq.into())
                    .timestamp(ts)
                    .payload(payload)
                    .build()
                {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!("构建回声 RTP 包失败: {:?}", e);
                        continue;
                    }
                };

                // 更新序列号和时间戳
                seq = seq.wrapping_add(1);
                ts = ts.wrapping_add(payload.len() as u32);

                // 发送回声包
                if let Err(e) = conn.send_raw(&echo_packet, &peer_sip_addr).await {
                    tracing::error!("发送回声 RTP 包失败: {:?}", e);
                    break;
                }
            }
        } => {}
    };

    info!("RTP 回声会话结束，共处理 {} 个数据包", packet_count);
    Ok(())
}

/// 播放音频文件
///
/// # 参数
/// * `conn` - UDP 连接
/// * `token` - 取消令牌
/// * `ssrc` - RTP 同步源标识符
/// * `filename` - 音频文件名（不带扩展名）
/// * `ts` - 初始时间戳
/// * `seq` - 初始序列号
/// * `peer_addr` - 对端地址
/// * `payload_type` - 有效载荷类型 (0=PCMU, 8=PCMA)
///
/// # 返回
/// 返回最终的时间戳和序列号
#[allow(dead_code)]
pub async fn play_audio_file(
    conn: UdpConnection,
    token: CancellationToken,
    ssrc: u32,
    filename: &str,
    mut ts: u32,
    mut seq: u16,
    peer_addr: String,
    payload_type: u8,
) -> Result<(u32, u16)> {
    select! {
        _ = token.cancelled() => {
            tracing::debug!("音频播放会话已取消");
        }
        _ = async {
            let peer_addr = SipAddr{
                addr: peer_addr.try_into().expect("peer_addr"),
                r#type: Some(rsip::transport::Transport::Udp),
            };
            let sample_size = 160;
            let mut ticker = tokio::time::interval(Duration::from_millis(20));

            let ext = match payload_type {
                8 => "pcma",
                0 => "pcmu",
                _ => {
                    tracing::error!("不支持的编解码器类型: {}", payload_type);
                    return;
                }
            };

            let file_name = format!("./assets/{filename}.{ext}");
            tracing::info!("播放音频: {} (编解码器: {}, 采样: {}字节)",
                  file_name, ext.to_uppercase(), sample_size);

            let example_data = match tokio::fs::read(&file_name).await {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!("读取音频文件失败 {}: {:?}", file_name, e);
                    return;
                }
            };

            for chunk in example_data.chunks(sample_size) {
                let result = match RtpPacketBuilder::new()
                    .payload_type(payload_type)
                    .ssrc(ssrc)
                    .sequence(seq.into())
                    .timestamp(ts)
                    .payload(chunk)
                    .build() {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("构建 RTP 数据包失败: {:?}", e);
                        break;
                    }
                };
                ts += chunk.len() as u32;
                seq += 1;
                match conn.send_raw(&result, &peer_addr).await {
                    Ok(_) => {},
                    Err(e) => {
                        tracing::error!("发送 RTP 数据失败: {:?}", e);
                        break;
                    }
                }
                ticker.tick().await;
            }
        } => {}
    };
    Ok((ts, seq))
}
