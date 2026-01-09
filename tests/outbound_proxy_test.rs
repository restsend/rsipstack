/// RFC 3261 Outbound Proxy 实现测试
///
/// 验证 Loose Routing 和 Strict Routing 的正确实现

use rsipstack::{
    dialog::registration::Registration,
    transport::TransportLayer,
    EndpointBuilder,
};
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
    assert_eq!(
        registration.endpoint.route_set.len(),
        0,
        "不应该有 routes"
    );

    cancel_token.cancel();
    println!("✅ 无 Outbound Proxy 配置测试通过");
}

#[test]
fn test_call_id_generator_go_style() {
    use rsipstack::transaction::{make_call_id, set_make_call_id_generator};

    // 设置自定义 Call-ID 生成器（Go 风格）
    set_make_call_id_generator(|domain| {
        format!("test-{}", domain.unwrap_or("default")).into()
    });

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
