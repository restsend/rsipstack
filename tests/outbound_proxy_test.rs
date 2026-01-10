/// RFC 3261 Outbound Proxy 实现测试
///
/// 验证 Loose Routing 和 Strict Routing 的正确实现
use rsipstack::{dialog::registration::Registration, transport::TransportLayer, EndpointBuilder};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_loose_routing_register_request() {
    // 配置全局 Outbound Proxy（Loose Routing）
    let proxy_uri: rsip::Uri = "sip:proxy.example.com:5060;lr".try_into().unwrap();

    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(cancel_token.clone())
        .with_transport_layer(transport_layer)
        .with_route_set(vec![proxy_uri.clone()])
        .build();

    // 创建 Registration
    let registration = Registration::new(endpoint.inner.clone(), None);

    // 验证通过检查 Registration 使用的 route_set
    assert_eq!(
        registration.endpoint.route_set.len(),
        1,
        "应该有 1 个 route"
    );
    assert_eq!(
        registration.endpoint.route_set[0].to_string(),
        "sip:proxy.example.com:5060;lr",
        "Route URI 应该匹配"
    );

    // 验证 lr 参数存在
    let first_route = &registration.endpoint.route_set[0];
    let has_lr = first_route
        .params
        .iter()
        .any(|p| matches!(p, rsip::Param::Lr));
    assert!(has_lr, "Route URI 应该包含 lr 参数（Loose Routing）");

    cancel_token.cancel();
    println!("✅ Loose Routing 配置测试通过");
}

#[tokio::test]
async fn test_strict_routing_register_request() {
    // 配置全局 Outbound Proxy（Strict Routing - 无 lr 参数）
    let proxy_uri: rsip::Uri = "sip:proxy.example.com:5060".try_into().unwrap();

    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(cancel_token.clone())
        .with_transport_layer(transport_layer)
        .with_route_set(vec![proxy_uri.clone()])
        .build();

    // 创建 Registration
    let registration = Registration::new(endpoint.inner.clone(), None);

    // 验证 route_set
    assert_eq!(
        registration.endpoint.route_set.len(),
        1,
        "应该有 1 个 route"
    );

    // 验证 lr 参数不存在
    let first_route = &registration.endpoint.route_set[0];
    let has_lr = first_route
        .params
        .iter()
        .any(|p| matches!(p, rsip::Param::Lr));
    assert!(!has_lr, "Route URI 不应该包含 lr 参数（Strict Routing）");

    cancel_token.cancel();
    println!("✅ Strict Routing 配置测试通过");
}

#[tokio::test]
async fn test_multiple_proxies_loose_routing() {
    // 配置多个代理（Loose Routing）
    let proxy1: rsip::Uri = "sip:proxy1.example.com:5060;lr".try_into().unwrap();
    let proxy2: rsip::Uri = "sip:proxy2.example.com:5060;lr".try_into().unwrap();

    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(cancel_token.clone())
        .with_transport_layer(transport_layer)
        .with_route_set(vec![proxy1.clone(), proxy2.clone()])
        .build();

    let registration = Registration::new(endpoint.inner.clone(), None);

    // 验证多个 routes
    assert_eq!(
        registration.endpoint.route_set.len(),
        2,
        "应该有 2 个 routes"
    );
    assert_eq!(
        registration.endpoint.route_set[0].to_string(),
        "sip:proxy1.example.com:5060;lr"
    );
    assert_eq!(
        registration.endpoint.route_set[1].to_string(),
        "sip:proxy2.example.com:5060;lr"
    );

    cancel_token.cancel();
    println!("✅ 多代理 Loose Routing 配置测试通过");
}

#[tokio::test]
async fn test_no_outbound_proxy() {
    // 不配置 Outbound Proxy（直接路由）
    let cancel_token = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel_token.clone());

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(cancel_token.clone())
        .with_transport_layer(transport_layer)
        .build();

    let registration = Registration::new(endpoint.inner.clone(), None);

    // 验证没有 route_set
    assert_eq!(registration.endpoint.route_set.len(), 0, "不应该有 routes");

    cancel_token.cancel();
    println!("✅ 无 Outbound Proxy 配置测试通过");
}

#[test]
fn test_call_id_generator_go_style() {
    use rsipstack::transaction::{make_call_id, set_make_call_id_generator};

    // 设置自定义 Call-ID 生成器（Go 风格）
    set_make_call_id_generator(|domain| format!("test-{}", domain.unwrap_or("default")).into());

    // 测试生成
    let call_id = make_call_id(Some("example.com"));
    // Call-ID header 格式是 "Call-ID: value"，我们需要提取 value
    let call_id_str = call_id.to_string();
    assert!(
        call_id_str.contains("test-example.com"),
        "Call-ID should contain 'test-example.com', got: {}",
        call_id_str
    );

    let call_id2 = make_call_id(None);
    let call_id2_str = call_id2.to_string();
    assert!(
        call_id2_str.contains("test-default"),
        "Call-ID should contain 'test-default', got: {}",
        call_id2_str
    );

    println!("✅ Go 风格 Call-ID 生成器测试通过");
}

/// 测试用户提供的具体URI格式: sip:sip.tst.novo-one.com:5060;transport=udp;lr
#[tokio::test]
async fn test_user_specific_uri_format() {
    let uri_string = "sip:sip.tst.novo-one.com:5060;transport=udp;lr";

    println!("\n测试URI格式: {}", uri_string);

    // 1. 解析URI
    let proxy_uri: rsip::Uri = uri_string.try_into().unwrap();

    println!("✅ URI解析成功");
    println!("  Scheme: {:?}", proxy_uri.scheme);
    println!("  Host: {}", proxy_uri.host_with_port);
    println!("  Params: {:?}", proxy_uri.params);

    // 2. 检查transport参数
    let has_transport = proxy_uri
        .params
        .iter()
        .any(|p| matches!(p, rsip::Param::Transport(rsip::Transport::Udp)));
    assert!(has_transport, "应该有transport=udp参数");

    // 3. 检查lr参数
    let has_lr = proxy_uri
        .params
        .iter()
        .any(|p| matches!(p, rsip::Param::Lr));
    assert!(has_lr, "应该有lr参数");

    // 4. 测试在EndpointBuilder中使用
    let cancel_token = CancellationToken::new();

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(cancel_token.clone())
        .with_route_set(vec![proxy_uri.clone()])
        .build();

    // 5. 验证outbound配置
    assert!(
        endpoint.inner.transport_layer.outbound.is_some(),
        "outbound应该被配置"
    );
    let outbound = endpoint.inner.transport_layer.outbound.as_ref().unwrap();

    assert_eq!(
        outbound.r#type,
        Some(rsip::Transport::Udp),
        "Transport应该是UDP"
    );
    assert_eq!(
        outbound.addr.to_string(),
        "sip.tst.novo-one.com:5060",
        "地址应该正确解析"
    );

    // 6. 验证route_set
    assert_eq!(endpoint.inner.route_set.len(), 1, "应该有1个route");
    let first_route = &endpoint.inner.route_set[0];
    println!("✅ route_set配置正确: {}", first_route);

    cancel_token.cancel();
    println!("\n✅ 格式 '{}' 完全支持！", uri_string);
}

/// 测试完整的SIPS URI with WSS transport
#[tokio::test]
async fn test_sips_wss_full_uri() {
    let uri_string = "sips:proxy.example.com:8443;transport=wss;lr";

    println!("\n测试完整SIPS+WSS URI: {}", uri_string);

    let proxy_uri: rsip::Uri = uri_string.try_into().unwrap();

    // 检查scheme
    assert_eq!(
        proxy_uri.scheme,
        Some(rsip::Scheme::Sips),
        "应该是sips scheme"
    );

    // 检查transport参数
    let has_wss = proxy_uri
        .params
        .iter()
        .any(|p| matches!(p, rsip::Param::Transport(rsip::Transport::Wss)));
    assert!(has_wss, "应该有transport=wss参数");

    // 使用EndpointBuilder
    let cancel_token = CancellationToken::new();

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(cancel_token.clone())
        .with_route_set(vec![proxy_uri])
        .build();

    // 验证outbound
    let outbound = endpoint.inner.transport_layer.outbound.as_ref().unwrap();
    assert_eq!(
        outbound.r#type,
        Some(rsip::Transport::Wss),
        "Transport应该是WSS"
    );

    cancel_token.cancel();
    println!("✅ SIPS+WSS完整URI支持正常！");
}

/// 测试错误的URI格式（在已有scheme前再加sip:）
#[tokio::test]
#[should_panic(expected = "ParseError")]
async fn test_double_scheme_uri_should_fail() {
    // 这种格式应该解析失败
    let bad_uri = "sip:sips:proxy.example.com:8443;transport=wss;lr";
    let _: rsip::Uri = bad_uri.try_into().unwrap(); // 应该panic
}
