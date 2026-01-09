# RFC 3261 Outbound Proxy 完整实现方案

## 目录

1. [RFC 3261 核心概念](#rfc-3261-核心概念)
2. [Outbound Proxy 原理](#outbound-proxy-原理)
3. [路由模式详解](#路由模式详解)
4. [实现架构](#实现架构)
5. [详细实现步骤](#详细实现步骤)
6. [测试验证](#测试验证)
7. [常见问题](#常见问题)

---

## RFC 3261 核心概念

### 1. Request-URI

**RFC 3261 Section 8.1.1.1 - Request-URI**

> The initial Request-URI of the message SHOULD be set to the value of the URI in the To field.

**作用**：
- 标识请求的**最终目标资源**
- 对于 REGISTER：目标是 Registrar 服务器
- 对于 INVITE：目标是被叫方的 SIP URI
- 对于 in-dialog 请求：目标是对方的 Contact URI

**关键原则**：
- Request-URI 应该始终指向最终目标，而不是中间代理
- 只有在使用 Strict Routing 时，才会将 Request-URI 替换为代理地址

### 2. Route Header

**RFC 3261 Section 20.34 - Route**

> The Route header field is used to force routing for a request through the listed set of proxies.

**作用**：
- 指定请求必须经过的**中间代理列表**
- 定义请求的传输路径
- 按顺序列出所有需要经过的代理

**格式**：
```
Route: <sip:proxy1.example.com;lr>
Route: <sip:proxy2.example.com;lr>, <sip:proxy3.example.com;lr>
```

### 3. Record-Route Header

**RFC 3261 Section 20.30 - Record-Route**

> The Record-Route header field is inserted by proxies in a request to force future requests in the dialog to be routed through the proxy.

**作用**：
- 代理插入自己的地址到响应中
- 确保后续的 in-dialog 请求经过同一条路径
- 用于构建 Dialog 的 route set

**Dialog Route Set 构建规则**（RFC 3261 Section 12.1.2）：
- **UAC**：从 2xx 响应的 Record-Route headers 构建，**反转顺序**
- **UAS**：从 INVITE 请求的 Record-Route headers 构建，**保持顺序**

### 4. lr 参数（Loose Routing）

**RFC 3261 Section 19.1.1 - SIP and SIPS URI Components**

> The lr parameter, when present, indicates that the element responsible for this resource implements the routing mechanisms specified in this document.

**作用**：
- `lr` = loose routing（宽松路由）
- 指示代理支持 RFC 3261 的路由规则
- **推荐在所有现代 SIP 实现中使用**

---

## Outbound Proxy 原理

### 什么是 Outbound Proxy

**RFC 3261 Section 8.1.2 - Sending the Request**

> A client that is configured to use an outbound proxy MUST populate the Route header field with the outbound proxy URI.

**定义**：
- Outbound Proxy 是 UA 配置的**固定代理服务器**
- 所有 out-of-dialog 请求都通过该代理发送
- 实现方式：在 UA 中预配置一个包含单个 URI 的 route set

### 为什么需要 Outbound Proxy

1. **NAT 穿透**：通过边缘代理建立可靠的连接
2. **安全策略**：强制所有流量通过受信任的代理
3. **企业网络**：满足公司防火墙和访问控制要求
4. **负载均衡**：将请求分发到多个服务器
5. **协议转换**：在不同传输协议间转换（UDP ↔ TCP ↔ TLS）

### Outbound Proxy 的作用范围

| 请求类型 | 使用的 Route Set | 说明 |
|---------|-----------------|------|
| REGISTER | 全局 route set | Outbound Proxy |
| Initial INVITE | 全局 route set | Outbound Proxy |
| Initial MESSAGE | 全局 route set | Outbound Proxy |
| Initial OPTIONS | 全局 route set | Outbound Proxy |
| In-dialog BYE | Dialog route set | 从 Record-Route 构建 |
| In-dialog ACK | Dialog route set | 从 Record-Route 构建 |
| In-dialog re-INVITE | Dialog route set | 从 Record-Route 构建 |

**关键区别**：
- **Out-of-dialog 请求**：使用全局配置的 Outbound Proxy
- **In-dialog 请求**：使用从 Record-Route 构建的 Dialog route set

---

## 路由模式详解

### Loose Routing（RFC 3261 推荐）

**RFC 3261 Section 16.12 - Processing of Route Information**

#### 原理

当第一个 Route URI 包含 `lr` 参数时：
1. **Request-URI** 保持为最终目标
2. **Route headers** 包含所有中间代理
3. 每个代理移除自己的 Route，转发到下一个

#### REGISTER 示例（Loose Routing）

```
REGISTER sip:registrar.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKnashds7
Route: <sip:proxy.example.com:5060;lr>
Max-Forwards: 70
To: <sip:alice@example.com>
From: <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710@192.168.1.100
CSeq: 1 REGISTER
Contact: <sip:alice@192.168.1.100:5060>
Expires: 3600
Content-Length: 0
```

**关键点**：
- ✅ Request-URI = `sip:registrar.example.com`（目标服务器）
- ✅ Route = `<sip:proxy.example.com:5060;lr>`（中间代理）
- ✅ 物理发送到 `proxy.example.com:5060`
- ✅ 代理转发到 `registrar.example.com`

#### INVITE 示例（Loose Routing）

```
INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKnashds8
Route: <sip:proxy.example.com:5060;lr>
Max-Forwards: 70
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=1928301775
Call-ID: b94f5a8e@192.168.1.100
CSeq: 1 INVITE
Contact: <sip:alice@192.168.1.100:5060>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 2890844526 2890844526 IN IP4 192.168.1.100
s=-
c=IN IP4 192.168.1.100
t=0 0
m=audio 49172 RTP/AVP 0
a=rtpmap:0 PCMU/8000
```

**路由流程**：
1. Alice 的 UA 发送 INVITE 到 `proxy.example.com:5060`
2. Proxy 看到 Request-URI = `sip:bob@example.com`，移除自己的 Route
3. Proxy 查询 Bob 的位置，转发到 Bob 的 UA
4. Bob 响应 200 OK，包含 Record-Route（如果 Proxy 添加了）

#### 多代理链示例（Loose Routing）

```
INVITE sip:bob@example.com SIP/2.0
Route: <sip:proxy1.example.com:5060;lr>
Route: <sip:proxy2.example.com:5060;lr>
Route: <sip:proxy3.example.com:5060;lr>
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=123
...
```

**处理流程**：
1. UA → Proxy1：移除第一个 Route
2. Proxy1 → Proxy2：移除第一个 Route
3. Proxy2 → Proxy3：移除第一个 Route
4. Proxy3 → Bob：根据 Request-URI 转发

### Strict Routing（遗留模式）

**RFC 3261 Section 16.12 - Processing of Route Information**

> If the first URI of the route set does not contain the lr parameter, the UAC MUST place the first URI of the route set into the Request-URI, place the remainder of the route set into the Route header field values, and place the original Request-URI into the route set as the last entry.

#### 原理

当第一个 Route URI **不包含** `lr` 参数时：
1. **Request-URI** 替换为第一个 Route
2. **Route headers** 包含剩余代理 + 原始 Request-URI（作为最后一项）

#### REGISTER 示例（Strict Routing）

```
REGISTER sip:proxy.example.com:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKnashds7
Route: <sip:registrar.example.com>
Max-Forwards: 70
To: <sip:alice@example.com>
From: <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710@192.168.1.100
CSeq: 1 REGISTER
Contact: <sip:alice@192.168.1.100:5060>
Expires: 3600
Content-Length: 0
```

**关键点**：
- ❌ Request-URI = `sip:proxy.example.com:5060`（代理地址）
- ✅ Route = `<sip:registrar.example.com>`（最终目标）
- ✅ 物理发送到 `proxy.example.com:5060`
- ⚠️ 代理需要特殊处理逻辑

#### 为什么不推荐 Strict Routing

1. **违反直觉**：Request-URI 不是最终目标
2. **复杂性高**：代理需要特殊的路由重写逻辑
3. **兼容性差**：现代 SIP 栈可能不支持
4. **已废弃**：RFC 3261 推荐使用 Loose Routing

---

## 实现架构

### 系统架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        SIP Application                          │
│  (使用 DialogLayer 和 Registration API)                        │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Dialog Layer                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Registration (Out-of-dialog)                            │  │
│  │  - global route_set: Vec<Uri>                            │  │
│  │  - with_route_set() builder method                       │  │
│  │  - Route header injection in register()                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Invitation (Out-of-dialog)                              │  │
│  │  - InviteOption.headers: Option<Vec<Header>>             │  │
│  │  - Route headers added via custom headers                │  │
│  │  - make_invite_request() processes headers               │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Dialog (In-dialog)                                      │  │
│  │  - route_set: Vec<Uri> (from Record-Route)               │  │
│  │  - update_route_set_from_response()                      │  │
│  │  - Route headers in in-dialog requests                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Transaction Layer                             │
│  - Transaction.destination: Option<SipAddr>                     │
│  - Auto-resolve from Route header (first URI)                   │
│  - Fallback to Request-URI if no Route                          │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Transport Layer                               │
│  - Physical network connection                                  │
│  - TCP/UDP/WS/WSS protocols                                     │
└─────────────────────────────────────────────────────────────────┘
```

### 数据流图

#### Out-of-Dialog Request (REGISTER/INVITE)

```
Application
    │
    │ 配置 route_set = [sip:proxy.example.com;lr]
    ▼
Registration/Invitation
    │
    │ 1. 检查 route_set 是否为空
    │ 2. 检查第一个 URI 是否有 lr 参数
    │ 3. 决定使用 Loose 或 Strict Routing
    │
    ▼ Loose Routing
    ├─ Request-URI = server (e.g., sip:registrar.example.com)
    └─ Route = route_set (e.g., <sip:proxy.example.com;lr>)
    │
    ▼
Transaction
    │
    │ destination = first Route URI or Request-URI
    ▼
Transport
    │
    │ 物理发送到 destination
    ▼
Network (UDP/TCP)
```

#### In-Dialog Request (BYE/re-INVITE)

```
Application
    │
    │ dialog.bye() / dialog.reinvite()
    ▼
Dialog
    │
    │ 使用 dialog.route_set（从 Record-Route 构建）
    │
    ▼
    ├─ Request-URI = remote_target (对方的 Contact URI)
    └─ Route = dialog.route_set
    │
    ▼
Transaction
    │
    │ destination = first Route URI or Request-URI
    ▼
Transport
```

---

## 详细实现步骤

### Step 1: Registration 实现（Out-of-Dialog）

#### 1.1 数据结构

```rust
pub struct Registration {
    pub last_seq: u32,
    pub endpoint: EndpointInnerRef,
    pub credential: Option<Credential>,
    pub contact: Option<rsip::typed::Contact>,
    pub allow: rsip::headers::Allow,
    pub public_address: Option<rsip::HostWithPort>,
    pub call_id: Option<rsip::headers::CallId>,

    /// 全局路由集（Outbound Proxy）
    /// 用于所有 out-of-dialog REGISTER 请求
    pub route_set: Vec<rsip::Uri>,
}
```

#### 1.2 Builder 方法

```rust
impl Registration {
    pub fn new(endpoint: EndpointInnerRef, credential: Option<Credential>) -> Self {
        Self {
            last_seq: 0,
            endpoint,
            credential,
            contact: None,
            allow: Default::default(),
            public_address: None,
            call_id: None,
            route_set: Vec::new(), // 默认空
        }
    }

    /// 设置全局路由集（Outbound Proxy）
    pub fn with_route_set(mut self, route_set: Vec<rsip::Uri>) -> Self {
        self.route_set = route_set;
        self
    }

    /// 设置 Call-ID（用于注册持久化）
    pub fn with_call_id(mut self, call_id: rsip::headers::CallId) -> Self {
        self.call_id = Some(call_id);
        self
    }
}
```

#### 1.3 路由逻辑实现

```rust
pub async fn register(&mut self, server: rsip::Uri, expires: Option<u32>) -> Result<Response> {
    self.last_seq += 1;

    // ... 构建 To, From, Via, Contact ...

    // RFC 3261 Section 12.2.1.1: Request construction with route set
    let (request_uri, route_headers) = if !self.route_set.is_empty() {
        // 检查第一个 Route URI 是否包含 lr 参数
        let first_route = &self.route_set[0];
        let is_loose_routing = first_route.params.iter()
            .any(|p| matches!(p, rsip::Param::Lr));

        if is_loose_routing {
            // Loose Routing (推荐)
            // Request-URI = 目标服务器
            // Route headers = 完整 route_set
            info!("使用 Loose Routing (lr 参数存在)");
            (server.clone(), self.route_set.clone())
        } else {
            // Strict Routing (遗留)
            // Request-URI = 第一个 route（移除 headers）
            // Route headers = 剩余 routes + server
            info!("使用 Strict Routing (lr 参数缺失)");

            let mut request_uri = first_route.clone();
            request_uri.headers.clear(); // RFC 3261: headers 不允许在 Request-URI

            let mut routes = self.route_set[1..].to_vec();
            routes.push(server.clone());

            (request_uri, routes)
        }
    } else {
        // 无 route set: 标准直接路由
        (server.clone(), vec![])
    };

    // 构建请求
    let mut request = self.endpoint.make_request(
        rsip::Method::Register,
        request_uri,
        via,
        from,
        to,
        self.last_seq,
        None,
    );

    // 添加 Call-ID（持久化）
    let call_id = self.call_id.clone().unwrap_or_else(|| {
        let new_call_id = make_call_id(self.endpoint.option.callid_suffix.as_deref());
        self.call_id = Some(new_call_id.clone());
        new_call_id
    });
    request.headers.unique_push(call_id.into());

    // 添加其他 headers
    request.headers.unique_push(contact.into());
    request.headers.unique_push(self.allow.clone().into());
    if let Some(expires) = expires {
        request.headers.unique_push(rsip::headers::Expires::from(expires).into());
    }

    // 注入 Route headers
    if !route_headers.is_empty() {
        for route_uri in &route_headers {
            let uri_with_params = rsip::UriWithParams {
                uri: route_uri.clone(),
                params: vec![],
            };
            let uri_with_params_list = rsip::UriWithParamsList(vec![uri_with_params]);
            let typed_route = rsip::typed::Route(uri_with_params_list);
            request.headers.push(rsip::headers::Route::from(typed_route).into());
        }
        info!("Route headers 已添加: {} 个路由", route_headers.len());
    }

    // 创建事务并发送
    let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
    let mut tx = Transaction::new_client(key, request, self.endpoint.clone(), None);

    tx.send().await?;

    // 处理响应循环（认证等）
    // ...
}
```

### Step 2: Invitation 实现（Out-of-Dialog）

#### 2.1 数据结构

```rust
pub struct InviteOption {
    pub caller_display_name: Option<String>,
    pub caller_params: Vec<rsip::uri::Param>,
    pub caller: rsip::Uri,
    pub callee: rsip::Uri,
    pub destination: Option<SipAddr>,
    pub content_type: Option<String>,
    pub offer: Option<Vec<u8>>,
    pub contact: rsip::Uri,
    pub credential: Option<Credential>,

    /// 自定义 headers（包括 Route）
    pub headers: Option<Vec<rsip::Header>>,

    pub support_prack: bool,
    pub call_id: Option<String>,
}
```

#### 2.2 使用方法

```rust
// 在应用层构建 Route headers
let mut custom_headers = Vec::new();
if let Some(ref proxy) = config.outbound_proxy {
    let proxy_uri_str = if proxy.contains(";lr") {
        format!("sip:{}", proxy)
    } else {
        format!("sip:{};lr", proxy) // 添加 lr 参数
    };
    let proxy_uri: rsip::Uri = proxy_uri_str.as_str().try_into()?;

    // 创建 Route header
    let uri_with_params = rsip::UriWithParams {
        uri: proxy_uri.clone(),
        params: vec![],
    };
    let uri_with_params_list = rsip::UriWithParamsList(vec![uri_with_params]);
    let typed_route = rsip::typed::Route(uri_with_params_list);
    custom_headers.push(rsip::headers::Route::from(typed_route).into());
}

let invite_opt = InviteOption {
    caller: from_uri.try_into()?,
    callee: to_uri.try_into()?,
    contact: contact_uri.try_into()?,
    credential: Some(credential),
    headers: if custom_headers.is_empty() { None } else { Some(custom_headers) },
    destination: None, // 让 rsipstack 自动从 Route 解析
    // ... 其他字段
};

let (dialog, response) = dialog_layer.do_invite(invite_opt, state_sender).await?;
```

#### 2.3 DialogLayer.make_invite_request()

```rust
pub fn make_invite_request(&self, opt: &InviteOption) -> Result<Request> {
    let last_seq = self.increment_last_seq();

    let to = rsip::typed::To {
        display_name: None,
        uri: opt.callee.clone(), // Request-URI = callee
        params: vec![],
    };
    let recipient = to.uri.clone();

    let from = rsip::typed::From {
        display_name: opt.caller_display_name.clone(),
        uri: opt.caller.clone(),
        params: opt.caller_params.clone(),
    }.with_tag(make_tag());

    let call_id = opt.call_id.as_ref()
        .map(|id| rsip::headers::CallId::from(id.clone()));

    let via = self.endpoint.get_via(None, None)?;

    // 构建请求
    let mut request = self.endpoint.make_request(
        rsip::Method::Invite,
        recipient, // Request-URI = 被叫方
        via,
        from,
        to,
        last_seq,
        call_id,
    );

    // 添加 Contact
    let contact = rsip::typed::Contact {
        display_name: None,
        uri: opt.contact.clone(),
        params: vec![],
    };
    request.headers.unique_push(rsip::Header::Contact(contact.into()));

    // 添加 Content-Type
    request.headers.unique_push(rsip::Header::ContentType(
        opt.content_type.clone()
            .unwrap_or("application/sdp".to_string())
            .into(),
    ));

    // 添加 PRACK 支持
    if opt.support_prack {
        request.headers.unique_push(rsip::Header::Supported("100rel".into()));
    }

    // 添加自定义 headers（包括 Route）
    if let Some(headers) = opt.headers.as_ref() {
        for header in headers {
            match header {
                rsip::Header::MaxForwards(_) => {
                    request.headers.unique_push(header.clone())
                }
                _ => request.headers.push(header.clone()),
            }
        }
    }

    Ok(request)
}
```

#### 2.4 Transaction 自动解析 destination

```rust
pub fn create_client_invite_dialog(
    &self,
    opt: InviteOption,
    state_sender: DialogStateSender,
) -> Result<(ClientInviteDialog, Transaction)> {
    let mut request = self.make_invite_request(&opt)?;
    request.body = opt.offer.unwrap_or_default();
    request.headers.unique_push(rsip::Header::ContentLength(
        (request.body.len() as u32).into(),
    ));

    let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
    let mut tx = Transaction::new_client(key, request.clone(), self.endpoint.clone(), None);

    // 自动解析 destination
    if opt.destination.is_some() {
        // 如果手动指定，使用手动值
        tx.destination = opt.destination;
    } else {
        // 从 Route header 自动解析
        if let Some(route) = tx.original.route_header() {
            if let Some(first_route) = route.typed().ok()
                .and_then(|r| r.uris().first().cloned())
            {
                tx.destination = SipAddr::try_from(&first_route.uri).ok();
            }
        }
    }

    // 创建 dialog
    let id = DialogId::try_from(&request)?;
    let dlg_inner = DialogInner::new(
        TransactionRole::Client,
        id.clone(),
        request.clone(),
        self.endpoint.clone(),
        state_sender.clone(),
    );

    let dialog = ClientInviteDialog::new(dlg_inner, opt.credential);

    Ok((dialog, tx))
}
```

### Step 3: Dialog 实现（In-Dialog）

#### 3.1 数据结构

```rust
pub struct DialogInner {
    pub role: TransactionRole,
    pub id: DialogId,
    pub endpoint: EndpointInnerRef,
    pub last_seq: AtomicU32,
    pub local_uri: rsip::Uri,
    pub remote_uri: rsip::Uri,
    pub remote_target: rsip::Uri, // 对方的 Contact URI

    /// Dialog route set（从 Record-Route 构建）
    pub route_set: Vec<rsip::Uri>,

    pub state_sender: DialogStateSender,
    // ...
}
```

#### 3.2 从响应构建 route_set（UAC）

```rust
impl DialogInner {
    /// 从 2xx 响应构建 route set (UAC 视角)
    /// RFC 3261 Section 12.1.2
    pub fn update_route_set_from_response(&mut self, response: &rsip::Response) {
        // 只处理 2xx 成功响应
        if !response.status_code.is_success() {
            return;
        }

        // 提取所有 Record-Route headers
        let record_routes: Vec<rsip::headers::RecordRoute> = response
            .headers
            .iter()
            .filter_map(|h| {
                if let rsip::Header::RecordRoute(rr) = h {
                    Some(rr.clone())
                } else {
                    None
                }
            })
            .collect();

        if !record_routes.is_empty() {
            // UAC: Record-Route 需要**反转顺序**变成 Route set
            // 原因：代理按顺序添加 Record-Route，UAC 需要反向遍历
            self.route_set = record_routes
                .into_iter()
                .rev() // 反转！
                .flat_map(|rr| {
                    match rr.typed() {
                        Ok(typed) => typed.uris().into_iter()
                            .map(|uri_with_params| uri_with_params.uri)
                            .collect(),
                        Err(_) => vec![],
                    }
                })
                .collect();

            info!("Dialog route set 已更新 (UAC): {} 个路由", self.route_set.len());
        }
    }
}
```

#### 3.3 从请求构建 route_set（UAS）

```rust
impl DialogInner {
    /// 从 INVITE 请求构建 route set (UAS 视角)
    /// RFC 3261 Section 12.1.1
    pub fn update_route_set_from_request(&mut self, request: &rsip::Request) {
        // 提取所有 Record-Route headers
        let record_routes: Vec<rsip::headers::RecordRoute> = request
            .headers
            .iter()
            .filter_map(|h| {
                if let rsip::Header::RecordRoute(rr) = h {
                    Some(rr.clone())
                } else {
                    None
                }
            })
            .collect();

        if !record_routes.is_empty() {
            // UAS: Record-Route **保持顺序**变成 Route set
            self.route_set = record_routes
                .into_iter()
                // 不反转！
                .flat_map(|rr| {
                    match rr.typed() {
                        Ok(typed) => typed.uris().into_iter()
                            .map(|uri_with_params| uri_with_params.uri)
                            .collect(),
                        Err(_) => vec![],
                    }
                })
                .collect();

            info!("Dialog route set 已更新 (UAS): {} 个路由", self.route_set.len());
        }
    }
}
```

#### 3.4 发送 in-dialog 请求

```rust
impl DialogInner {
    /// 准备 in-dialog 请求（注入 Route headers）
    pub fn prepare_in_dialog_request(&self, method: rsip::Method) -> Result<rsip::Request> {
        let seq = self.last_seq.fetch_add(1, Ordering::SeqCst) + 1;

        let to = rsip::typed::To {
            display_name: None,
            uri: self.remote_uri.clone(),
            params: vec![rsip::Param::Tag(self.id.to_tag.clone())],
        };

        let from = rsip::typed::From {
            display_name: None,
            uri: self.local_uri.clone(),
            params: vec![rsip::Param::Tag(self.id.from_tag.clone())],
        };

        let via = self.endpoint.get_via(None, None)?;

        // Request-URI = remote_target (对方的 Contact URI)
        let mut request = self.endpoint.make_request(
            method,
            self.remote_target.clone(), // ← Contact URI
            via,
            from,
            to,
            seq,
            Some(self.id.call_id.clone()),
        );

        // 注入 Route headers（如果 route_set 非空）
        if !self.route_set.is_empty() {
            for route_uri in &self.route_set {
                let uri_with_params = rsip::UriWithParams {
                    uri: route_uri.clone(),
                    params: vec![],
                };
                let uri_with_params_list = rsip::UriWithParamsList(vec![uri_with_params]);
                let typed_route = rsip::typed::Route(uri_with_params_list);
                request.headers.push(rsip::headers::Route::from(typed_route).into());
            }
            info!("In-dialog Route headers 已添加: {} 个路由", self.route_set.len());
        }

        Ok(request)
    }
}
```

---

## 测试验证

### 测试环境搭建

#### 1. 使用 Wireshark 抓包

```bash
# 启动 Wireshark 并监听网络接口
sudo wireshark

# 过滤 SIP 流量
sip
```

#### 2. 搭建测试代理（可选）

使用 Kamailio 或 OpenSIPS 作为测试代理：

```bash
# Kamailio 示例配置
listen=udp:192.168.1.10:5060
record_route=yes  # 启用 Record-Route
```

### 测试用例

#### Test Case 1: REGISTER with Loose Routing

**配置**：
```rust
let proxy_uri: rsip::Uri = "sip:proxy.example.com:5060;lr".try_into()?;
let mut registration = Registration::new(endpoint, Some(credential))
    .with_call_id(call_id)
    .with_route_set(vec![proxy_uri]);

let server = rsip::Uri::try_from("sip:registrar.example.com")?;
let response = registration.register(server, Some(3600)).await?;
```

**期望的 SIP 消息**：
```
REGISTER sip:registrar.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds
Route: <sip:proxy.example.com:5060;lr>
Max-Forwards: 70
To: <sip:user@example.com>
From: <sip:user@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 REGISTER
Contact: <sip:user@192.168.1.100:5060>
Expires: 3600
Content-Length: 0
```

**验证点**：
- ✅ Request-URI = `sip:registrar.example.com`
- ✅ Route header 存在
- ✅ Route URI 包含 `;lr` 参数
- ✅ 物理发送到 `proxy.example.com:5060`

#### Test Case 2: REGISTER with Strict Routing

**配置**：
```rust
let proxy_uri: rsip::Uri = "sip:proxy.example.com:5060".try_into()?; // 无 lr
let mut registration = Registration::new(endpoint, Some(credential))
    .with_route_set(vec![proxy_uri]);
```

**期望的 SIP 消息**：
```
REGISTER sip:proxy.example.com:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds
Route: <sip:registrar.example.com>
Max-Forwards: 70
To: <sip:user@example.com>
From: <sip:user@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 REGISTER
Contact: <sip:user@192.168.1.100:5060>
Expires: 3600
Content-Length: 0
```

**验证点**：
- ✅ Request-URI = `sip:proxy.example.com:5060`
- ✅ Route header 包含最终目标
- ❌ Route URI 不包含 `;lr` 参数

#### Test Case 3: INVITE with Loose Routing

**配置**：
```rust
let proxy_uri: rsip::Uri = "sip:proxy.example.com:5060;lr".try_into()?;

let mut custom_headers = Vec::new();
let uri_with_params = rsip::UriWithParams {
    uri: proxy_uri,
    params: vec![],
};
let typed_route = rsip::typed::Route(rsip::UriWithParamsList(vec![uri_with_params]));
custom_headers.push(rsip::headers::Route::from(typed_route).into());

let invite_opt = InviteOption {
    caller: "sip:alice@example.com".try_into()?,
    callee: "sip:bob@example.com".try_into()?,
    headers: Some(custom_headers),
    destination: None,
    // ...
};
```

**期望的 SIP 消息**：
```
INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKnashds8
Route: <sip:proxy.example.com:5060;lr>
Max-Forwards: 70
To: <sip:bob@example.com>
From: <sip:alice@example.com>;tag=1928301775
Call-ID: b94f5a8e@192.168.1.100
CSeq: 1 INVITE
Contact: <sip:alice@192.168.1.100:5060>
Content-Type: application/sdp
Content-Length: 142

v=0
...
```

**验证点**：
- ✅ Request-URI = `sip:bob@example.com`
- ✅ Route header 存在
- ✅ 物理发送到 `proxy.example.com:5060`

#### Test Case 4: In-Dialog BYE

**前提**：
- INVITE 已建立 dialog
- 响应包含 Record-Route

**期望行为**：
1. Dialog 从 2xx 响应提取 Record-Route
2. 反转顺序构建 route_set
3. BYE 请求包含 Route headers

**期望的 SIP 消息**：
```
BYE sip:bob@192.168.1.200:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKnashds9
Route: <sip:proxy.example.com:5060;lr>
Max-Forwards: 70
To: <sip:bob@example.com>;tag=987654
From: <sip:alice@example.com>;tag=1928301775
Call-ID: b94f5a8e@192.168.1.100
CSeq: 2 BYE
Content-Length: 0
```

**验证点**：
- ✅ Request-URI = `sip:bob@192.168.1.200:5060` (Bob 的 Contact)
- ✅ Route header 来自 Record-Route
- ✅ 使用 dialog route set，不是全局 route set

### 自动化测试脚本

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_loose_routing() {
        let endpoint = create_test_endpoint().await;
        let proxy_uri: rsip::Uri = "sip:127.0.0.1:5060;lr".try_into().unwrap();

        let mut registration = Registration::new(endpoint, None)
            .with_route_set(vec![proxy_uri.clone()]);

        let server: rsip::Uri = "sip:127.0.0.1:5070".try_into().unwrap();

        // 构建请求（不实际发送）
        let (request_uri, route_headers) = registration
            .compute_routing(server.clone());

        // 验证 Loose Routing
        assert_eq!(request_uri, server); // Request-URI = server
        assert_eq!(route_headers.len(), 1);
        assert_eq!(route_headers[0], proxy_uri);
    }

    #[tokio::test]
    async fn test_register_strict_routing() {
        let endpoint = create_test_endpoint().await;
        let proxy_uri: rsip::Uri = "sip:127.0.0.1:5060".try_into().unwrap(); // 无 lr

        let mut registration = Registration::new(endpoint, None)
            .with_route_set(vec![proxy_uri.clone()]);

        let server: rsip::Uri = "sip:127.0.0.1:5070".try_into().unwrap();

        let (request_uri, route_headers) = registration
            .compute_routing(server.clone());

        // 验证 Strict Routing
        assert_eq!(request_uri, proxy_uri); // Request-URI = proxy
        assert_eq!(route_headers.len(), 1);
        assert_eq!(route_headers[0], server); // Route = server
    }

    #[tokio::test]
    async fn test_dialog_route_set_uac() {
        let mut dialog = create_test_dialog();

        // 模拟 2xx 响应包含 Record-Route
        let response = create_response_with_record_route(vec![
            "sip:proxy1.example.com;lr",
            "sip:proxy2.example.com;lr",
        ]);

        dialog.update_route_set_from_response(&response);

        // UAC: 应该反转顺序
        assert_eq!(dialog.route_set.len(), 2);
        assert!(dialog.route_set[0].to_string().contains("proxy2")); // 反转！
        assert!(dialog.route_set[1].to_string().contains("proxy1"));
    }
}
```

---

## 常见问题

### Q1: 什么时候使用全局 route_set，什么时候使用 dialog route_set？

**A**:
- **全局 route_set**（Outbound Proxy）：
  - 用于 **out-of-dialog** 请求：REGISTER, Initial INVITE, OPTIONS, MESSAGE
  - 在应用启动时配置
  - 所有新会话都使用

- **Dialog route_set**：
  - 用于 **in-dialog** 请求：BYE, ACK, re-INVITE, UPDATE, INFO
  - 从响应的 Record-Route 自动构建
  - 每个 dialog 独立维护

### Q2: 如何判断应该使用 Loose 还是 Strict Routing？

**A**: 检查第一个 Route URI 的 `lr` 参数：
```rust
let is_loose_routing = first_route.params.iter()
    .any(|p| matches!(p, rsip::Param::Lr));
```

**推荐**：始终使用 Loose Routing（添加 `;lr` 参数）

### Q3: Record-Route 和 Route 的区别是什么？

**A**:
| Header | 方向 | 作用 | 添加者 |
|--------|------|------|--------|
| Record-Route | 请求 → 响应 | 记录代理路径 | Proxy |
| Route | 请求 | 指定路由路径 | UA |

**关系**：
- Proxy 在转发请求时添加 **Record-Route**
- UA 从响应的 Record-Route 构建 **Route** 用于后续请求

### Q4: 为什么 UAC 要反转 Record-Route 顺序？

**A**:
```
原始路径：UA → Proxy1 → Proxy2 → Server

Record-Route 顺序：
  [Proxy1, Proxy2]  # Proxy1 先添加，Proxy2 后添加

返回路径：UA ← Proxy2 ← Proxy1 ← Server

Route 顺序（反转）：
  [Proxy2, Proxy1]  # 反向遍历
```

**原因**：后续请求需要按照相同的路径发送，所以需要反转。

### Q5: destination 和 Request-URI 的关系？

**A**:
- **Request-URI**：SIP 协议层的目标（逻辑地址）
- **destination**：传输层的物理地址（IP + Port）

**关系**：
```
如果有 Route header:
    destination = 第一个 Route URI 的地址
否则:
    destination = Request-URI 的地址
```

### Q6: 多代理链如何处理？

**A**:
```rust
let route_set = vec![
    "sip:proxy1.example.com:5060;lr".try_into()?,
    "sip:proxy2.example.com:5060;lr".try_into()?,
    "sip:proxy3.example.com:5060;lr".try_into()?,
];

registration.with_route_set(route_set);
```

**SIP 消息**：
```
REGISTER sip:registrar.example.com SIP/2.0
Route: <sip:proxy1.example.com:5060;lr>
Route: <sip:proxy2.example.com:5060;lr>
Route: <sip:proxy3.example.com:5060;lr>
```

**处理流程**：
1. UA → Proxy1：移除第一个 Route
2. Proxy1 → Proxy2：移除第一个 Route
3. Proxy2 → Proxy3：移除第一个 Route
4. Proxy3 → Registrar：根据 Request-URI

### Q7: 如何处理代理返回的 Record-Route 不含 lr 参数的情况？

**A**: 两种方案：

**方案 1（推荐）**：自动添加 lr 参数
```rust
fn normalize_route_set(route_set: Vec<rsip::Uri>) -> Vec<rsip::Uri> {
    route_set.into_iter().map(|mut uri| {
        let has_lr = uri.params.iter().any(|p| matches!(p, rsip::Param::Lr));
        if !has_lr {
            uri.params.push(rsip::Param::Lr);
        }
        uri
    }).collect()
}
```

**方案 2**：保持原样，支持 Strict Routing
```rust
// 让实现自动检测并处理
```

### Q8: REGISTER 是否需要 Record-Route？

**A**: **不需要**
- REGISTER 不建立 dialog
- Record-Route 只用于 dialog-forming 请求（INVITE, SUBSCRIBE）
- REGISTER 的每次请求都独立，使用全局 route_set

### Q9: 如何测试 Outbound Proxy 实现是否正确？

**A**: 使用 Wireshark 验证：

**检查清单**：
1. ✅ Request-URI 是否为最终目标（Loose Routing）
2. ✅ Route header 是否存在
3. ✅ Route URI 是否包含 `;lr` 参数
4. ✅ 物理发送地址是否为代理地址
5. ✅ Via header 是否为本地地址（不受 Route 影响）
6. ✅ In-dialog 请求是否使用 dialog route_set

### Q10: 遇到 "transaction already terminated" 错误怎么办？

**A**: 检查以下几点：
1. Call-ID 是否正确持久化（REGISTER）
2. 是否正确处理认证响应
3. route_set 是否正确设置
4. Transaction timeout 是否过短

---

## 参考资料

### RFC 文档

- **RFC 3261** - SIP: Session Initiation Protocol
  - Section 8.1.2 - Sending the Request
  - Section 12.2.1.1 - Generating the Request (with Route Set)
  - Section 16.12 - Processing of Route Information
  - Section 20.30 - Record-Route
  - Section 20.34 - Route

### 相关标准

- **RFC 3263** - SIP: Locating SIP Servers (DNS)
- **RFC 3581** - SIP: Symmetric Response Routing (rport)
- **RFC 5626** - SIP Outbound (Keep-alive)

### 实现参考

- **rsipstack** - Rust SIP Stack Implementation
- **PJSIP** - Open Source SIP Stack
- **Sofia-SIP** - SIP User Agent Library

---

## 总结

### 核心原则

1. **Request-URI** = 最终目标（Loose Routing）
2. **Route header** = 中间代理路径
3. **全局 route_set** 用于 out-of-dialog 请求
4. **Dialog route_set** 用于 in-dialog 请求，从 Record-Route 构建
5. **始终使用 Loose Routing**（添加 `;lr` 参数）

### 实现检查清单

- [x] Registration 支持 route_set
- [x] with_route_set() builder 方法
- [x] Loose/Strict Routing 自动检测
- [x] Route header 正确注入
- [x] INVITE 支持通过 headers 添加 Route
- [x] Transaction 自动从 Route 解析 destination
- [x] Dialog 从 Record-Route 构建 route_set
- [x] UAC 反转 Record-Route 顺序
- [x] UAS 保持 Record-Route 顺序
- [x] In-dialog 请求使用 dialog route_set

### 最佳实践

1. **优先使用 Loose Routing**
2. **全局配置 Outbound Proxy** 而不是每次手动设置
3. **Call-ID 持久化** 用于 REGISTER
4. **使用 Wireshark 验证** SIP 消息格式
5. **编写单元测试** 覆盖各种路由场景

---

**版本**: 1.0
**日期**: 2026-01-09
**作者**: Claude Code
**基于**: RFC 3261 (2002)
