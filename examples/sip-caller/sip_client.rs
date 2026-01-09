/// SIP 客户端核心模块
///
/// 提供高层次的SIP客户端功能封装
use crate::{
    config::Protocol,
    rtp::{self, MediaSessionOption},
    sip_dialog::process_dialog,
    sip_transport::{create_transport_connection, extract_peer_rtp_addr},
};
use rand::Rng;
use rsipstack::{
    dialog::{
        authenticate::Credential, dialog_layer::DialogLayer, invitation::InviteOption,
        registration::Registration,
    },
    transaction::Endpoint,
    transport::TransportLayer,
    EndpointBuilder,
};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;


/// SIP 客户端配置
pub struct SipClientConfig {
    /// 服务器地址 (如 "xfc:5060" 或 "sip.example.com:5060")
    pub server: String,

    /// 传输协议
    pub protocol: Protocol,

    /// Outbound 代理地址（可选）
    pub outbound_proxy: Option<String>,

    /// SIP 用户名
    pub username: String,

    /// SIP 密码
    pub password: String,

    /// 本地绑定端口
    pub local_port: u16,

    /// 优先使用IPv6
    pub prefer_ipv6: bool,

    /// RTP起始端口
    pub rtp_start_port: u16,

    /// User-Agent字符串
    pub user_agent: String,
}

/// SIP 客户端
pub struct SipClient {
    config: SipClientConfig,
    endpoint: Endpoint,
    dialog_layer: Arc<DialogLayer>,
    cancel_token: CancellationToken,
    local_ip: std::net::IpAddr,
}

impl SipClient {
    /// 创建新的SIP客户端
    pub async fn new(config: SipClientConfig) -> Result<Self, Box<dyn std::error::Error>> {
        rsipstack::transaction::set_make_call_id_generator(|_domain| {
            Uuid::new_v4().to_string().into()
        });

        let cancel_token = CancellationToken::new();

        // 获取本地IP
        let local_ip = crate::utils::get_first_non_loopback_interface(config.prefer_ipv6)?;
        info!(
            "检测到本地出口IP: {} ({})",
            local_ip,
            if local_ip.is_ipv6() { "IPv6" } else { "IPv4" }
        );

        // 创建传输层
        let transport_layer = TransportLayer::new(cancel_token.clone());

        // 物理连接目标：如果配置了代理则使用代理，否则使用服务器地址
        let connection_target = config.outbound_proxy.as_ref().unwrap_or(&config.server);

        // 创建传输连接
        let local_addr = format!("{}:{}", local_ip, config.local_port).parse()?;
        let connection = create_transport_connection(
            config.protocol,
            local_addr,
            connection_target,
            cancel_token.clone(),
        )
        .await?;

        transport_layer.add_transport(connection);

        // 创建端点，配置全局 route_set (Outbound Proxy)
        let mut endpoint_builder = EndpointBuilder::new();
        endpoint_builder
            .with_cancel_token(cancel_token.clone())
            .with_transport_layer(transport_layer)
            .with_user_agent(&config.user_agent);

        // 如果配置了 Outbound 代理，设置全局 route_set
        if let Some(ref outbound_proxy) = config.outbound_proxy {
            // 构造代理 URI，并添加 ;lr 参数以启用 Loose Routing
            let proxy_uri_str = if outbound_proxy.contains(";lr") {
                format!("sip:{}", outbound_proxy)
            } else {
                format!("sip:{};lr", outbound_proxy)
            };
            let proxy_uri: rsip::Uri = proxy_uri_str.as_str().try_into()?;
            endpoint_builder.with_route_set(vec![proxy_uri]);
            info!("配置全局 Outbound 代理（Loose Routing）: {}", proxy_uri_str);
        }

        let endpoint = endpoint_builder.build();

        // 启动端点服务
        let endpoint_for_serve = endpoint.inner.clone();
        tokio::spawn(async move {
            endpoint_for_serve.serve().await.ok();
        });

        // 创建对话层
        let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));

        // 启动传入请求处理
        Self::start_incoming_handler(
            endpoint.incoming_transactions()?,
            dialog_layer.clone(),
            cancel_token.clone(),
        );

        Ok(Self {
            config,
            endpoint,
            dialog_layer,
            cancel_token,
            local_ip,
        })
    }

    /// 启动传入请求处理器
    fn start_incoming_handler(
        mut incoming: rsipstack::transaction::TransactionReceiver,
        dialog_layer: Arc<DialogLayer>,
        cancel_token: CancellationToken,
    ) {
        tokio::spawn(async move {
            while let Some(mut transaction) = tokio::select! {
                tx = incoming.recv() => tx,
                _ = cancel_token.cancelled() => None,
            } {
                let method = transaction.original.method;
                debug!("收到传入请求: {}", method);

                if let Some(mut dialog) = dialog_layer.match_dialog(&transaction.original) {
                    tokio::spawn(async move {
                        if let Err(e) = dialog.handle(&mut transaction).await {
                            error!("处理 {} 请求失败: {}", method, e);
                        }
                    });
                } else {
                    warn!("未找到匹配的对话: {}", method);
                }
            }
        });
    }

    /// 执行注册
    pub async fn register(&self) -> Result<rsip::Response, Box<dyn std::error::Error>> {
        info!("正在注册到 SIP 服务器...");

        let actual_local_addr = self
            .endpoint
            .get_addrs()
            .first()
            .ok_or("未找到地址")?
            .addr
            .clone();

        info!("本地绑定的实际地址: {}", actual_local_addr);

        // 构造注册URI（直接使用 config.server）
        let register_uri_str = format!("sip:{}", self.config.server);
        let server_uri_parsed: rsip::Uri = register_uri_str.as_str().try_into()?;

        info!("Register URI: {}", register_uri_str);

        // 创建认证凭证
        let credential = Credential {
            username: self.config.username.clone(),
            password: self.config.password.clone(),
            realm: None, // 将从 401 响应自动提取
        };

        // 创建 Registration 实例（全局 route_set 已在 Endpoint 层面配置）
        let mut registration = Registration::new(
            self.endpoint.inner.clone(),
            Some(credential),
        );

        // 执行注册
        let response = registration.register(server_uri_parsed, Some(3600)).await?;

        if response.status_code == rsip::StatusCode::OK {
            info!("✔ 注册成功,响应状态: {}", response.status_code);
        } else {
            warn!("注册响应: {}", response.status_code);
        }

        Ok(response)
    }

    /// 发起呼叫
    pub async fn make_call(&self, target: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!("📞发起呼叫到: {}", target);

        let actual_local_addr = self
            .endpoint
            .get_addrs()
            .first()
            .ok_or("未找到地址")?
            .addr
            .clone();

        let contact_uri_str = format!("sip:{}@{}", self.config.username, actual_local_addr);

        // 构造 From/To URI（使用相同的域名部分）
        let from_uri = format!("sip:{}@{}", self.config.username, self.config.server);
        let to_uri = if target.contains('@') {
            format!("sip:{}", target)
        } else {
            format!("sip:{}@{}", target, self.config.server)
        };

        info!("Call信息 源：{} -> 目标：{}", from_uri, to_uri);

        // 创建 RTP 会话
        let rtp_cancel = self.cancel_token.child_token();
        let media_opt = MediaSessionOption {
            rtp_start_port: self.config.rtp_start_port,
            external_ip: None,
            cancel_token: rtp_cancel.clone(),
        };

        let ssrc = rand::rng().random::<u32>();
        let payload_type = 0u8; // PCMU

        let (rtp_conn, sdp_offer) =
            rtp::build_rtp_conn(self.local_ip, &media_opt, ssrc, payload_type).await?;

        debug!("SDP Offer:{}", sdp_offer);

        // 生成呼叫 Call-ID（直接使用 UUID 字符串）
        let call_id_string = uuid::Uuid::new_v4().to_string();
        info!("生成呼叫 Call-ID: {}", call_id_string);

        // 创建认证凭证
        let credential = Credential {
            username: self.config.username.clone(),
            password: self.config.password.clone(),
            realm: None, // 将从 401/407 响应自动提取
        };

        // 全局 route_set 已在 Endpoint 层面配置，INVITE 会自动使用
        let invite_opt = InviteOption {
            caller: from_uri.as_str().try_into()?,
            callee: to_uri.as_str().try_into()?,
            contact: contact_uri_str.as_str().try_into()?,
            credential: Some(credential),
            caller_display_name: None,
            caller_params: vec![],
            destination: None, // 让 rsipstack 自动从 Route header 解析
            content_type: Some("application/sdp".to_string()),
            offer: Some(sdp_offer.as_bytes().to_vec()),
            headers: None, // 不需要手动添加，rsipstack 自动处理
            support_prack: false,
            call_id: Some(call_id_string),
        };

        // 创建状态通道
        let (state_sender, state_receiver) = self.dialog_layer.new_dialog_state_channel();

        // 发送 INVITE
        let (dialog, response) = self
            .dialog_layer
            .do_invite(invite_opt, state_sender)
            .await?;

        let dialog_id = dialog.id();
        info!(
            "✅ INVITE 请求已发送，Dialog -> Call-ID: {} From-Tag: {} To-Tag: {}",
            dialog_id.call_id, dialog_id.from_tag, dialog_id.to_tag
        );

        if let Some(resp) = response {
            info!("响应状态: {}", resp.status_code());

            // 处理 SDP Answer
            let body = resp.body();
            if !body.is_empty() {
                let sdp_answer = String::from_utf8_lossy(body);
                debug!("SDP Answer: {}", sdp_answer);

                if let Some(peer_addr) = extract_peer_rtp_addr(&sdp_answer) {
                    info!("✓ 对端 RTP 地址: {}", peer_addr);

                    // 启动对话状态监控
                    let dialog_clone = Arc::new(dialog.clone());
                    let rtp_cancel_clone = rtp_cancel.clone();
                    tokio::spawn(async move {
                        process_dialog(dialog_clone, state_receiver, rtp_cancel_clone).await;
                    });

                    // 启动 RTP 回声
                    info!("🔊 启动回声模式");
                    let rtp_cancel_clone = rtp_cancel.clone();
                    let peer_addr_clone = peer_addr.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            rtp::play_echo(rtp_conn, rtp_cancel_clone, peer_addr_clone, ssrc).await
                        {
                            error!("RTP 回声播放失败: {}", e);
                        }
                    });

                    // 等待用户挂断
                    info!("📞 通话中，按 Ctrl+C 手动挂断");
                    tokio::signal::ctrl_c().await?;

                    // 挂断呼叫
                    match dialog.bye().await {
                        Ok(_) => {
                            info!("✅ 通话结束");
                        }
                        Err(e) => {
                            warn!("发送 BYE 失败: {}", e);
                        }
                    }

                    rtp_cancel.cancel();
                } else {
                    error!("无法从 SDP Answer 中提取对端 RTP 地址");
                }
            }
        }

        Ok(())
    }

    /// 关闭客户端
    pub async fn shutdown(&self) {
        self.cancel_token.cancel();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
