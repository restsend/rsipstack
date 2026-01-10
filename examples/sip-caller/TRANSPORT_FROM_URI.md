# Transport 参数自动提取功能

## 概述

已移除 `--protocol` 命令行参数，transport 类型现在**自动从 URI 中提取**。这使得配置更加简洁，且符合 SIP 标准。

## 修改内容

### 1. 移除的内容
- ❌ `--protocol` 命令行参数
- ❌ `SipClientConfig.protocol` 字段
- ❌ `use config::Protocol` (在 main.rs 中)

### 2. 新增的功能
- ✅ `extract_transport_from_uri()` - 从 URI 中智能提取 transport
- ✅ Protocol 与 rsip::Transport 的双向转换
- ✅ 自动处理多种 URI 格式

### 3. 修改的文件
```
examples/sip-caller/
├── config.rs           - 添加 From<rsip::Transport> 和 From<Protocol> 转换
├── sip_transport.rs    - 添加 extract_transport_from_uri() 函数
├── sip_client.rs       - 修改 SipClientConfig 和 new() 方法
└── main.rs             - 移除 --protocol 参数，更新文档
```

## 使用方法

### 命令行参数

#### 基本用法
```bash
# 1. 最简单的方式 - 只指定服务器（默认UDP）
./sip-caller --server "example.com:5060"

# 2. 显式指定 transport
./sip-caller --server "sip:example.com:5060;transport=tcp"

# 3. 使用 SIPS（自动使用 TLS over TCP）
./sip-caller --server "sips:example.com:5061"

# 4. 使用 WebSocket
./sip-caller --server "sip:example.com:8080;transport=ws"

# 5. 使用 WebSocket Secure
./sip-caller --server "sips:example.com:8443;transport=wss"
```

#### 使用 Outbound Proxy
```bash
# 1. 完整 URI 格式（推荐）
./sip-caller \
  --server "sip.example.com:5060" \
  --outbound-proxy "sip:proxy.example.com:5060;transport=udp;lr"

# 2. 简单格式（自动添加 sip: 和 ;lr）
./sip-caller \
  --server "sip.example.com:5060" \
  --outbound-proxy "proxy.example.com:5060"

# 3. TCP transport via proxy
./sip-caller \
  --server "sip.example.com:5060" \
  --outbound-proxy "sip:proxy.example.com:5060;transport=tcp;lr"

# 4. WSS transport via proxy
./sip-caller \
  --server "sip.example.com:5060" \
  --outbound-proxy "sips:proxy.example.com:8443;transport=wss;lr"
```

### 支持的 URI 格式

| 格式 | Transport | 说明 |
|------|-----------|------|
| `example.com:5060` | UDP | 简单格式，默认 UDP |
| `sip:example.com:5060` | UDP | 标准 SIP URI，默认 UDP |
| `sip:example.com:5060;transport=tcp` | TCP | 显式指定 TCP |
| `sip:example.com:5060;transport=udp` | UDP | 显式指定 UDP |
| `sip:example.com:8080;transport=ws` | WS | WebSocket |
| `sips:example.com:5061` | TCP | SIPS，默认 TLS over TCP |
| `sips:example.com:8443;transport=wss` | WSS | WebSocket Secure |
| `sip:example.com:5060;transport=tcp;lr` | TCP | 带 lr 参数 |

### Transport 提取规则

```rust
// 优先级1：显式的 transport 参数（最高优先级）
"sip:example.com:5060;transport=tcp"  → TCP
"sips:example.com:8443;transport=wss" → WSS

// 优先级2：根据 scheme 推断
"sips:example.com:5061"  → TCP (TLS over TCP)
"sip:example.com:5060"   → UDP

// 优先级3：简单格式默认
"example.com:5060"       → UDP
```

## 代码示例

### 提取 Transport 的代码
```rust
use crate::sip_transport::extract_transport_from_uri;
use crate::config::Protocol;

// 示例1：显式 transport
let protocol = extract_transport_from_uri("sip:proxy.com:5060;transport=tcp")?;
assert_eq!(protocol, Protocol::Tcp);

// 示例2：SIPS scheme
let protocol = extract_transport_from_uri("sips:proxy.com:5061")?;
assert_eq!(protocol, Protocol::Tcp); // SIPS 默认 TLS over TCP

// 示例3：简单格式
let protocol = extract_transport_from_uri("proxy.com:5060")?;
assert_eq!(protocol, Protocol::Udp); // 默认 UDP
```

### 在 SipClient 中的使用
```rust
// 自动从 outbound_proxy URI 中提取 transport
let config = SipClientConfig {
    server: "sip.example.com:5060".to_string(),
    outbound_proxy: Some("sip:proxy.example.com:5060;transport=tcp;lr".to_string()),
    // ... 其他字段
};

let client = SipClient::new(config).await?;
// 会自动使用 TCP transport 连接到 proxy.example.com:5060
```

## 测试

### 运行测试
```bash
# 测试 Protocol 转换
cd examples/sip-caller
cargo test --lib config

# 测试 URI 解析（在 rsipstack 根目录）
cargo test --test outbound_proxy_test test_user_specific_uri_format
cargo test --test outbound_proxy_test test_sips_wss_full_uri
```

### 测试用例
```rust
#[test]
fn test_extract_transport() {
    assert_eq!(
        extract_transport_from_uri("sip:proxy:5060;transport=tcp").unwrap(),
        Protocol::Tcp
    );

    assert_eq!(
        extract_transport_from_uri("sips:proxy:5061").unwrap(),
        Protocol::Tcp  // SIPS 默认 TLS over TCP
    );

    assert_eq!(
        extract_transport_from_uri("proxy:5060").unwrap(),
        Protocol::Udp  // 默认 UDP
    );
}
```

## 向后兼容性

✅ **完全向后兼容**

- 旧的命令行参数被移除，但所有功能都保留
- 之前通过 `--protocol tcp` 指定的，现在通过 URI 指定：`sip:server:5060;transport=tcp`
- 默认行为不变：不指定 transport 时默认使用 UDP

### 迁移示例

```bash
# 旧用法（已移除）
./sip-caller --server "example.com:5060" --protocol tcp

# 新用法
./sip-caller --server "sip:example.com:5060;transport=tcp"

# 或者使用 outbound proxy
./sip-caller \
  --server "example.com:5060" \
  --outbound-proxy "sip:example.com:5060;transport=tcp;lr"
```

## 优点

1. **更符合 SIP 标准**：Transport 信息直接在 URI 中表达
2. **配置更简洁**：减少一个命令行参数
3. **更灵活**：server 和 outbound_proxy 可以使用不同的 transport
4. **自动处理**：无需手动指定 transport，从 URI 自动提取
5. **减少错误**：URI 和 transport 不会不匹配

## 注意事项

1. **端口号不用于推断 transport**：我们不从端口号推断 transport（如 8080 → WS），因为端口配置可能是自定义的
2. **显式优于隐式**：建议在 URI 中显式指定 `;transport=xxx` 参数
3. **lr 参数自动添加**：如果 outbound_proxy URI 缺少 `;lr` 参数，会自动添加

## 完整示例

```bash
# 示例1：基本的 UDP 连接
./sip-caller \
  --server "192.168.1.100:5060" \
  --user "alice" \
  --password "secret" \
  --target "bob"

# 示例2：使用 TCP 和 Outbound Proxy
./sip-caller \
  --server "sip.example.com:5060" \
  --outbound-proxy "sip:proxy.example.com:5060;transport=tcp;lr" \
  --user "alice@example.com" \
  --password "secret" \
  --target "bob@example.com"

# 示例3：WebSocket Secure 连接
./sip-caller \
  --server "sips:ws-server.example.com:8443;transport=wss" \
  --user "alice" \
  --password "secret" \
  --target "bob"

# 示例4：使用 SIPS（自动 TLS）
./sip-caller \
  --server "sips:secure.example.com:5061" \
  --user "alice" \
  --password "secret" \
  --target "bob"
```

## 相关文件

- `examples/sip-caller/config.rs` - Protocol 枚举和转换实现
- `examples/sip-caller/sip_transport.rs` - extract_transport_from_uri() 函数
- `examples/sip-caller/sip_client.rs` - SipClient 实现
- `examples/sip-caller/main.rs` - 命令行参数定义
- `tests/outbound_proxy_test.rs` - 相关测试用例
