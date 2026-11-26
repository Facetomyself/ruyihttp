# 03 · MASQUE：两层 HTTP/3，一条显式 UDP 路由

`masque://` 改变的是**如何把源站 QUIC 包送出去**，不是由谁发起 HTTPS 请求。客户端的第一个网络对端是 MASQUE 代理；真正的 HTTPS 对端仍然是目标 URL 的源站。外层 aioquic 只与代理建立 QUIC/TLS 和 `CONNECT-UDP`，内层 Neqo/NSS 仍与源站握手、发送普通 HTTP/3 请求并读取响应。客户端只解析代理地址；它既没有直连源站的 UDP socket，也没有为这条路由建立源站 TCP 连接。

[架构目录](README.md) · [请求路由](01-request-routing.md) · [协议引擎](02-protocol-engines.md) · [信任与配置档位](04-trust-profiles.md) · [配置和复验说明](../masque.md#使用)

源码证据固定在 [`9e88bfe023fd46a96254f8de66e8d72517339911`][pin]；[`v0.9.4` 的标签提交 `74953f7`][tag-commit] 与之只差顶层 README，以下运行时与测试路径一致。

![MASQUE 时序：先认证代理并建隧道，原生回环 A 与外层 worker 回环 B 双向交接内层 QUIC，代理 UDP 出口与独立源站往返](diagrams/masque-tunnel.svg)

[交互时序图（HTML）](diagrams/masque-tunnel.html) · [Archify 源数据（JSON）](diagrams/masque-tunnel.json)。图中 A/B 是同一客户端进程里的回环端点，代理出口是远端 socket；箭头合并了 TLS 的多个消息，两个证书由不同的客户端组件验证。

## 1. 路由选择：显式选择 UDP，普通代理仍走 TCP

| 请求走哪条路 | 决定点 | 第一个网络对端与后续动作 |
| --- | --- | --- |
| 已选代理为 `masque://` | `Session.merge_environment_settings` / `send` → `HTTPAdapter._send_once` | 认证代理的 QUIC/H3 → `CONNECT-UDP` → 原生源站 H3；要求 HTTPS、源站验证开启且无 `cert=`。首次连接也直接尝试 H3，无需 `Alt-Svc`。 |
| `http://` / `https://` 普通代理访问 HTTPS | `HTTPAdapter._connect` | 先 TCP 到代理；`https://` 先加代理 TLS；发传统 `CONNECT host:port`，再在字节流内做源站 TLS，使用 H1/H2。SOCKS 另走自己的握手。 |
| 无代理，普通 HTTPS | `HTTPAdapter._send_once` 直连分支 | TCP 到源站或按有效 `Alt-Svc` 选择/竞争直连 H3，参见[请求路由](01-request-routing.md)。 |

`is_masque_proxy` 只识别 `masque:`；`parse_proxy` 私有入口也能解析 `https:`，这不赋予普通代理 URL 选路能力。`adapters.py` 仅重新导出适配器，实现主体在 `_transport.py`。显式单次配置在合并时提升为目标专用键，已选 MASQUE 时跳过 Requests 的系统代理/PAC 查询，保留其源站 CA 环境处理：`trust_env` 开启且合并后的 `verify is True` 才读取 `REQUESTS_CA_BUNDLE`、再读 `CURL_CA_BUNDLE`。通常的 `verify=True` 配套根集因此以未被环境覆盖为前提。已选 MASQUE 但挂载的是其他 Adapter 时直接报 `ProxyError`。依据：[sessions.py:79–108][environment]、[sessions.py:150–190][session-send]、[adapters.py:5–9][adapter-export]、[_transport.py:94–116][route-id]、[_transport.py:862–944][tcp-proxy]、[_transport.py:1194–1297][transport-select-1194-1297]。

这里的 CONNECT 是内部为一个目标发出的 [RFC 9298 Extended CONNECT][rfc9298-request]，不是向用户开放任意方法/UDP 的通用隧道 API。原生 H3 profile 里可见的 Extended CONNECT SETTINGS 是另一回事：常规原生 `fetch` 拒绝 `CONNECT`，原生 JSON 接口没有通用 `connect` / `connect-udp` 操作，外层 CONNECT 是 Python aioquic 发的。安装额外依赖 `ruyihttp[masque]` 才使用这一路径；当前适配范围为 `aioquic>=1.3.0,<1.4`，线级夹具固定验证 `1.3.0`。依据：[GECKO_H3_POLICY.md:17–27][native-policy]、[pyproject.toml:40–42][extra]、[_masque.py:201–223][lazy-quic]、[smoke_masque.py:1111–1144][wire-cli]。

## 2. 建立时序：网络首跳、回环句柄与两次证书校验

1. **适配器把真实目标与代理分开。** `_send_once` 用 connect timeout 构造 `Attempt`，先在目标和路由分区内找可复用 H3；新建时 `_connect_masque` 从请求 URL 取 `host/port`（默认 443），构造内层 `_ssl_context(verify, None, …)`，再把捕获 `proxy/host/port` 的 `via_proxy(cancel_event, on_error)` 传给 `_http3.Connection`。外层使用 `budget.remaining()`，原生构造器也等待同一预算的剩余时间；只有没有设置 connect deadline 时，外层 `open_tunnel` 才使用自己的 30 秒默认值。[_transport.py:1046–1066][connect-masque]、[_transport.py:1182–1259][transport-select-1182-1259]、[_http3.py:173–206][owner-start]、[_masque.py:787–808][open-tunnel-787-808]。
2. **外层 worker 取得唯一网络首跳。** 原生 owner 通过 `tunnel_factory(self._stopping, self._wake)` 创建隧道。`open_tunnel` 先解析代理与目标路径、验证 CA 参数、加载 aioquic，再 `_resolve(proxy, …)`；代理 IP 字面量绕开 DNS，域名只按代理名调用 `getaddrinfo(SOCK_DGRAM)`。`ruyihttp-masque-outer` 对当前代理地址创建独立的非阻塞 UDP socket 并 `connect(address)`；有限的本地建 socket 或握手前不可达错误可试同一代理的另一地址，证书、协议或 HTTP 失败不会触发改拨源站。目标名称只交给 CONNECT 路径和源站 TLS。[_masque.py:95–135][resolve]、[_masque.py:787–867][open-tunnel]、[_http3.py:518–536][owner-attach-518-536]。
3. **代理 TLS 先于 CONNECT。** `OuterQuic` 使用代理标识、`CERT_REQUIRED`、ALPN `h3`，不提供 session ticket；`HandshakeCompleted` 也拒绝已恢复或接受 early data 的连接，然后以同一信任根对实际证书链执行 OpenSSL `X509_PURPOSE_SSL_SERVER` 验证。`proxy_verify=True` 使用 certifi；显式 CA 文件替换默认根集，而非追加。叶证书存在 KeyUsage/EKU 时分别要求 `digitalSignature` 与 `serverAuth`，链另有 32 张中间证书的上限；用途配置或验证失败即停止。达成 SETTINGS、传输参数和受保护的包长探测要求后才在外层发 CONNECT。[_masque.py:68–83][proxy-ca]、[_masque.py:225–289][outer-tls]、[_masque.py:576–599][maybe-request]、[_masque.py:646–686][relay-events]。
4. **原生 FD 指向回环 A，而非网络 socket。** `Tunnel` 拥有 `_udp_pair()` 返回的两个 `AF_INET/SOCK_DGRAM`：各绑定 `127.0.0.1:0` 的独立临时端口，非阻塞、互相 `connect()`，建好后有界排空预连接窗口可能排队的包。A 是 `Tunnel.socket`，B 是 `Tunnel._relay`。收到有效最终 2xx、事件处理完成并使 `_ready` 置位后，owner 才从工厂取得 A：原生 `new` 的 `local` 是 A 的地址，`remote` 是 B 的地址，`host` 仍是真实源站；`attach(socket=udp.fileno())` 传 A 的 FD（Windows 为 socket handle）。`tunnel` 分支 `peer_address=None`，禁止把 B 或代理地址误当成源站的 DNS 合并证据。外层 selector 看 B 和网络 UDP；原生 selector 看 A 和命令/错误唤醒用的另一对 `socketpair()`，它不是数据中继。[_masque.py:138–164][udp-pair]、[_masque.py:450–503][tunnel]、[_masque.py:729–779][relay-loop]、[_http3.py:173–184][owner-start-173-184]、[_http3.py:513–552][owner-attach]。
5. **内层仍认证源站。** 经过回环/代理送达的第一个内层 QUIC Initial 由 Neqo 发出。NSS 负责内层 TLS 协议与 Firefox 档位；owner 收到原生 `auth` 事件后把 DER 证书串交给 `_nss.Context.verify`，由 Python `cryptography` 的 server verifier 对真实源站 DNS 名或 IP SAN 及证书链校验，再以 `auth(accepted=…)` 回写。`verify=True` 默认用随包 Firefox 根及根失信截止约束；显式 CA 用自己的根。原生 `connected` 事件在必要时还从 `info` 补取证书并复核，才让调用者继续。内层不支持 `cert=`；两层各自必须成功，换一边的 CA 无法替另一边背书。详见 [04 · 信任与配置档位](04-trust-profiles.md)、[_http3.py:265–300][origin-auth]、[_nss.py:185–259][origin-store]。

## 3. CONNECT 协商：开放条件、封装与包长预算

**请求。** `_masque_codec.parse_proxy` 只收 authority（可带可选用户信息及末尾 `/`），默认端口 443；`target_path` 对目标做 IDNA/字面量规范化、变量 URI 编码（如 `::1` → `%3A%3A1`）。缺省 `/.well-known/masque/udp/{target_host}/{target_port}/`；自定义 `masque_path_template` 只支持两种简单变量，且两者都必须出现，可在路径/查询内。`connect_headers` 精确构造 `:method=CONNECT`、`:protocol=connect-udp`、`:scheme=https`、代理 `:authority`、展开后的 `:path`、`capsule-protocol: ?1`，外加可选 URL Basic `proxy-authorization`；`send_headers(..., end_stream=False)` 保持流打开。代理收到的是 CONNECT 路径中的目标主机与端口，不是应用请求的 URL path/query。依据：[_masque_codec.py:15–124][connect-codec]、[_masque.py:576–599][maybe-request]、[RFC 9298 §3.4][rfc9298-request]。

**能力与 MTU。** `_maybe_request` 等待 H3 SETTINGS；对端须通告 `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`（`0x08`）、`SETTINGS_H3_DATAGRAM=1`（`0x33`），且 QUIC `max_datagram_frame_size` 必须可用。`OuterQuic` 另保留对端 `max_udp_payload_size`（省略时 `65527`），因为 aioquic 1.3 校验但不为此路径保留该值。建连时外层常规限 `1200` 字节，探测候选上限 `min(对端 UDP 载荷上限, 1400)`。代码使用保守上界：短头 `41`（标志 1＋最长 DCID 20＋包号 4＋AEAD tag 16），DATAGRAM 附加 `5`（含长度的帧类型 1＋长度 2＋首次请求的 Quarter Stream ID 1＋Context ID 0 的 1）。于是：

```text
内层发送预算 = min(已确认外层 UDP 载荷 − 41 − 5, 对端 DATAGRAM 帧上限 − 5)
保证装下 1252 字节内层 Initial ⇒ 外层 UDP 载荷至少 1298，帧上限至少 1257
```

先用对端上限判定是否有机会承载 Initial，再等握手确认才测**客户端→代理**路径。`_MtuSearch` 从 ceiling 开始，依次尝试比它更小的 `1360/1320/1298`，最后再试 `1298` 一次。`OuterQuic._write_ping_frame` 只在该探针临时放宽包构建上限，把一个受 1-RTT 保护的 `PING` 用 `PADDING` 填到精确 UDP 长度；无 STREAM 数据。只有当前探针 UID 对应的 ACK 生效，丢失的 UID 不准被更短的恢复 PING 重新使用；普通 PTO、迟到 ACK 和本地 `send` 成功都不能替代此证据。探针遇到 `EMSGSIZE` 可提前转下一档；单档等待受 PTO、`75–750 ms` 目标区间及总预算的分摊共同约束，留出后续探针和 CONNECT 响应时间。收到有效 ACK 后以测得值更新常规发送上限和内层预算，再发 CONNECT；探不到下界则 `ConnectTimeout`。探测前外层 UDP socket 按平台开启禁分片选项（其他平台有相应选项才设置），并使用连接固定的 UDP peer。ACK 很小，故该结果既不测反向大包，也不测代理到源站的 UDP 段。依据：[_masque.py:37–61][constants]、[_masque.py:167–188][no-fragment]、[_masque.py:230–248][udp-param]、[_masque.py:291–346][protected-probe]、[_masque.py:505–553][mtu-search]、[_masque.py:576–599][maybe-request]、[_masque.py:654–664][relay-events-654-664]、[RFC 9000 §§14、18.2][rfc9000-mtu]、[RFC 9221 §3][rfc9221-frame]、[RFC 9220 §3][rfc9220]。

**状态与数据报。** `_response_status` 要求唯一三位 `:status`（100–599，101 无效）并限制字段段大小。`OuterHttp` 处理连续 HEADERS 时把合法 1xx 留在等待最终头状态；`_Relay._handle_http` 只允许最多 16 个且不得带 FIN。最终非 2xx 以 `H3_REQUEST_CANCELLED` 重置该请求流并报告 `MasqueError`（`ProxyError` 子类），407/403/502 都是**代理**结果。成功还排除 204/205/206、`Content-Length` / `Content-Type` / `Transfer-Encoding`、立即结束的流和额外 HEADERS；代理没回显 `Capsule-Protocol` 本身不是失败（RFC 9297 的 SHOULD）。只有已接纳的对应请求流能传 UDP。

- **发送：** `h3.send_datagram(stream_id, b"\x00" + udp)`；H3 层加 `stream_id / 4` 的 Quarter Stream ID，Context ID `0` 后才是原 UDP 载荷。两个 ID 分别定位外层请求流与 UDP 上下文；当前单请求连接通常用流 0，解析按实际流 ID，并非把流号和 Context ID 混为一谈。
- **接收：** 已接纳流的 QUIC DATAGRAM 经 `udp_payload` 取 Context 0；未知 Context 或截断的 Context varint 在不可靠报文里丢弃。可靠流的 H3 DATA 用 `CapsuleDecoder` 增量解析 类型/长度/Context 三个 varint，允许跨 DATA 帧或同帧多 capsule；仅取 DATAGRAM capsule（type `0`）的 Context 0，跳过未知类型/上下文且不缓存其声明长度。DATAGRAM capsule 缺完整 Context、超 RFC UDP 上限或 FIN 截断是流错误。两种载体接收均受 `_INNER_MAX=1354` 限制（与本次已测出的**发送**上限分开）；本版只发送 QUIC DATAGRAM，反向可收 capsule 并不意味着支持 capsule-only 代理。

依据：[_masque.py:191–198][response-status]、[_masque.py:354–430][outer-h3-354-430]、[_masque.py:601–686][relay-http]、[_masque.py:716–727][relay-send]、[_masque_codec.py:127–221][datagram-codec]、[RFC 9114 §4.1][rfc9114-response]、[RFC 9297 §§2–3][rfc9297]、[RFC 9298 §§3.5、4–5][rfc9298-response]。

## 4. 往返与故障：从应用调用追到谁读写哪个 socket

**去程。** `HTTPAdapter` 复制请求头并删除 `Proxy-Authorization`，为 H3 创建 `_http3.Exchange`。`Exchange` 从原请求提取 method、authority/path、过滤过的头和优先级，通过 `Connection.submit("fetch", …)` 排队并唤醒 owner；有正文则 `write`，最后 `finish`。只有 owner 调 `necko_quic_call`（及可用时的二进制 body ABI），`pump` 驱动原生 QUIC 在 A 上收发。A 发到 B，外层 `_Relay._drain_local()` 从 B `recv`，把同一个 UDP payload 打成 DATAGRAM，`_flush()` 通过已连接网络 UDP `send` 给代理。代理拆去外层封装，由 UDP 出口把原包发给源站；客户端不会把内层 H3 明文或源站 HTTP 头抄进 CONNECT。依据：[_transport.py:1314–1385][exchange-send]、[_http3.py:208–252][owner-submit]、[_http3.py:347–453][owner-execute]、[_http3.py:625–747][exchange]、[_masque.py:693–768][relay-io-693-768]、[smoke_masque.py:412–433][relay-forward]。

**回程。** 源站把 UDP 响应包发给代理出口；夹具 `Egress.datagram_received` 在活动外层流调用 `return_udp`。外层 worker 按 selector 从网络 socket `recv`，交给 aioquic 的 `receive_datagram`；解析流和上下文后 `_incoming()` 在 B `send`，内层 A 可读使 owner 立即再 `pump`。原生 `headers` / `readable` 事件唤醒 `Exchange.receive` 或满足 `read`，`_Body` 把源站正文交给 urllib3；源站 H3 响应是 `raw.version == 30`。`response.tls` 是源站连接信息，`response.proxy_tls` 是外层认证后的 `alpn/protocol/datagram_mode/verified` 及两个外层发送预算字段的快照；没有把代理证书、CONNECT 状态或 PING ACK 当成源站成功。依据：[smoke_masque.py:291–301][egress]、[smoke_masque.py:435–460][relay-return]、[_masque.py:601–644][relay-http-601-644]、[_masque.py:729–779][relay-loop]、[_http3.py:321–344][origin-events]、[_http3.py:455–511][owner-pump]、[_transport.py:683–745][raw-body]、[_transport.py:1384–1409][response-return]、[_masque.py:473–479][tunnel-473-479]。

| 症状 | 控制与能观察到的结果 | 对应证据 |
| --- | --- | --- |
| QUIC 通了但没有 CONNECT | 缺任一 SETTINGS、DATAGRAM 参数/空间不足，或 GOAWAY 排除首流，代理侧无 CONNECT；路径探不到容纳 1252 的档位为 `ConnectTimeout`，而非源站超时。 | [test_masque_transport.py:136–178][transport-mtu-tests]、[test_masque_transport.py:340–422][transport-wire-tests]、[smoke_masque.py:983–1017][wire-negative] |
| 代理 407、403、502 或畸形响应 | 非 2xx 请求取消；畸形成功头、前置 DATA、非法 FIN/capsule 用 `H3_MESSAGE_ERROR`；控制/QPACK 关键流关闭是连接错误，收到 CONNECT 流 RESET/STOP_SENDING 也使隧道失败。状态不会冒充源站 HTTP 响应。 | [_masque.py:387–430][outer-h3-387-430]、[_masque.py:608–686][relay-http-608-686]、[test_masque_transport.py:340–422][transport-wire-tests]、[smoke_masque.py:983–1004][wire-negative-983-1004] |
| 队列满、个别大包/上下文异常 | 单次读最多 32 包，待发 DATAGRAM 上限 64；超发送预算或队列满直接丢包。阻塞/`ENOBUFS`（含 Windows 对应错误）在回环返回或网络发送时按 UDP 丢包处理，保留包边界；已建连后的网络 `EMSGSIZE` 报路径失败。外层同时设置静态 QPACK、流数/重组及字段大小限额（本地总流数阈值 32，单重组缓冲 32768，字段 16384）。这些限制不同于内层 H3 流控；原生写可挂起，等可写事件、输入或有界复查。 | [_masque.py:37–58][constants-37-58]、[_masque.py:348–370][outer-limits]、[_masque.py:429–434][outer-h3-429-434]、[_masque.py:693–784][relay-io]、[_http3.py:347–395][owner-execute-347-395]、[test_masque_transport.py:53–107][transport-bounds-tests]、[test_masque_codec.py:73–117][codec-tests] |
| 建连取消、隧道断开、读取无响应或提前关闭正文 | `Tunnel._fail` 只锁存首错、置位 `_ready` 并唤醒 owner；内层就绪之前保留该错误，之后转普通 `ProtocolError`（源站可能已收到字节）。`Connection.idle` 立即排除已锁存错误的连接。取消/关闭会唤醒 owner，结束待命命令并关闭原生 handle；`Tunnel.close` 停 worker、关 A，worker 清空队列后尽力发送 reset/connection close、关 B 和网络 socket。仅关闭单个未结束的 H3 正文是取消对应内层 stream，未必销毁共享隧道。DNS 取消只停止等待，libc 查询本身无法中断，由 8 个槽限制遗留解析 worker。 | [_http3.py:223–252][owner-submit-223-252]、[_http3.py:442–449][owner-execute-442-449]、[_http3.py:455–466][owner-pump-455-466]、[_http3.py:553–599][owner-stop]、[_masque.py:482–503][tunnel-482-503]、[_masque.py:769–779][relay-loop-769-779]、[test_masque_transport.py:424–439][transport-cancel-tests]、[test_masque_routing.py:259–297][route-cancel-tests]、[smoke_masque.py:1051–1108][wire-close] |

MASQUE 分支不走 `Alt-Svc`／TCP 探测或降级；协议标记要求 H1 或直连时原样报错。已建立的外层断链也不会被误判为「未发请求」而自动做协议级重放。仍须区分用户配置的 urllib3 `Retry`，以及源站明确拒绝且支持重试的协议事件：适配器保留了这两层机制，若重试也是所选 MASQUE 路由，且流式请求体必须可重绕。一次停滞或未收到响应不能证明源站没处理；夹具验证默认重试设置下的 stall POST 只送一次。依据：[_transport.py:1068–1180][adapter-retry]、[_transport.py:1410–1449][adapter-cleanup]、[_retry.py:38–52][restartable]、[smoke_masque.py:1058–1065][wire-close-1058-1065]。

## 5. 凭据与重定向：分区守恒，跨源仍可开新隧道

- **凭据归属。** 代理 URL userinfo 经严格 percent 解码，转为外层 Basic；`ProxyEndpoint.authorization` 排除于 `repr`。`connect_headers` 从零构造头，不从 `PreparedRequest` 复制 `Authorization` 或 `Cookie`；适配器和重定向重建时都移除发往源站的 `Proxy-Authorization`。外层关闭异常只呈现本地文案、状态或错误码，独立的静默 logger 不收对端可控的 reason phrase。[_masque_codec.py:22–59][connect-codec-22-59]、[_masque_codec.py:113–124][connect-codec-113-124]、[_transport.py:1328–1335][exchange-send-1328-1335]、[sessions.py:118–148][redirect-hooks-118-148]、[_masque.py:58–61][constants-58-61]、[_masque.py:439–447][outer-error]。
- **池与同源复用。** `masque_route_id` 对原始代理 URL（含 userinfo）、代理 CA 标记（默认/文件绝对路径）、模板做带长度前缀的 SHA-256；池键再包含目标的 scheme/hostname/port 表示、源站 CA 标记及协议分区，不放明文代理凭据或模板查询。不把同址不同源站合并；同分区健康连接可承载多个原生 H3 stream，外层仍只有一个 CONNECT 请求。CA 文件分区按路径而不是文件内容；换了同一路径的 CA 文件不等于自动重新验证已经建立的池连接。[_transport.py:94–116][route-id]、[_transport.py:394–460][pool]、[_transport.py:1200–1297][transport-select-1200-1297]、[_masque.py:354–363][outer-h3-354-363]。
- **重定向与再发送。** 响应携带 `_ruyi_masque_route`；`rebuild_method` 在系统 bypass/PAC 前给下一跳打标，`rebuild_proxies` 保持代理映射并去掉已派生的代理头；`rebuild_auth` 仍先走 Requests 的源站 auth 规则再更新 Firefox 头/cookie。即使 `allow_redirects=False`，准备好的 `response.next` 也带锁；真正发送时若降为 HTTP、更换代理/代理 CA/模板或离开该代理，抛 `ProxyError`。这不是同源锁：另一 HTTPS 源站可通过相同代理路由重新 CONNECT，但使用新的目标池分区；测试中的新目标被固定出口夹具以 403 拒绝，未向另一路由发包。依据：[sessions.py:110–179][redirect-hooks]、[_transport.py:1233–1245][transport-select-1233-1245]、[test_masque_routing.py:96–172][route-redirect-tests]、[smoke_masque.py:1039–1050][wire-redirect]。

## 6. 证据边界：代理看见什么，源站看见什么

| 观察者 | 实际收到与可核对的事件 | 证据的范围 |
| --- | --- | --- |
| 代理入口／出口 | 入口收到客户端首跳 UDP、外层 `h3`、SETTINGS、CONNECT authority/目标路径、可选 Basic 与流号；可区分出口 UDP 的包边界、大小、时序和返回方向。 | 能看到目标，而非匿名路由；内层 QUIC Initial 的保护密钥可从公开信息推导，且本路径没有 ECH 配置，不能把内层 ClientHello 元数据视为对代理保密。真正的内层 1-RTT HTTP 内容与应用凭据由源站连接保护，代理不是内层 TLS 端点。[RFC 9001 §5.2][rfc9001-initial] |
| HTTPS 源站 | UDP 网络对端是代理出口；能解自己的 TLS/H3 得到源站 `:authority`、应用路径、正文和应用凭据，与外层 CONNECT/Basic 无关。关闭未完成的内层响应时，源站可收到该 H3 stream 的取消；关闭 Session 时，代理观测的是外层 CONNECT 被回收。 | 源站的 socket 对端并非发起内层 TLS 的客户端地址；该路由没有转交外层的客户端网络身份。[_http3.py:442–449][owner-execute-442-449]、[smoke_masque.py:926–969][wire-proof-926-969] |
| 本地调用者 | 分别看到 `response.tls` / `response.proxy_tls`；代理证书错时连接尚无 CONNECT；源站证书错时代理与源站之间可已有 UDP 往返，但源站无应用请求头。 | 两类 `SSLError` 由到达阶段、观测对端和门禁区分；代理接受 CONNECT、端口可达或有往返都不是源站应用成功的证据。[smoke_masque.py:983–1017][wire-negative] |

**分层验收。** [日常 CI][ci-tests] 跑 codec、外层 loopback 和路由合同。`test_masque_native.py` 的夹具自检先故意送错目标及错误来源，证实原站 UDP 守卫、TCP 陷阱和旁路 UDP/TCP 哨兵会响；这一步使用独立参考端点，不算原生产品验收。安装态 `ci/smoke_masque.py` 才走公开 `Session` API：代理入口/出口与源站入口分别记录完整 UDP 数据报序列的数量、字节数和摘要；顺/逆两向逐段对齐，同时拦截本地源站 DNS、监测旁路、记录两套 TLS 事件与关闭后的存活 worker。源站实测初始 UDP 载荷 **1252**、QUIC v1 Initial、3 字节 SCID；在相应 POSIX 档位另断言协商到 v2 和内层 SETTINGS `0x08=1`。正例覆盖 256 KiB GET 和 POST 回显、应用/代理凭据隔离、两条同连接流真正重叠及取消；负例检查独立坏证书、缺能力、拒绝码、黑洞、错误 Context、接收 capsule、IPv6/路径模板与重定向。依据：[test_masque_native.py:29–60][native-test]、[smoke_masque.py:657–713][fixture-calibration]、[smoke_masque.py:726–772][client-observer]、[smoke_masque.py:917–1108][wire-proof]。

**独立代理实现。** wheel gate 分别跑 Python 线级夹具与 `masque-go v0.6.0` / `quic-go v0.63.0` 对端。后者由 `ci/masque_interop` 构建，`ProxyConnectedSocket` 只接收预连接的单一回环 UDP 出口；收到正确路径和 Basic 才打开一次 CONNECT，并记录接纳和回收。Python 驱动核对实际 Go 模块版本、退出状态、源站请求与数据、peer 地址和取消；这证明另一套 H3/MASQUE 实现互通，不是把 Python 夹具的所有恶劣场景在 Go 上重测。本版的[五平台安装验收][wheel-run]与[发行验收摘要][qualification]记录：五种 wheel 在 CPython 3.10 / 3.14 的十个组合均通过 `masque-controls`、`masque-rfc9298`（各 22 个场景）与 `masque-go-interop`；两个 Linux 架构在 glibc 2.31 下的四个组合另记录 `wire-passed`（见[最低系统验收](../linux-glibc231-qualification.md)）。这是已列矩阵与夹具的证据，不是公网任意代理兼容保证。依据：[wheels.yml:77–109][wheel-ci]、[qualify_wheel.py:83–89][wheel-hooks]、[main.go:49–104][go-peer]、[go.mod:3–9][go-versions]、[smoke_masque_go.py:63–135][go-proof]。

## 7. 维护边界

- **现有行为：** 单个代理、外层 H3／QUIC DATAGRAM 必须可用、回程可收 DATAGRAM capsule；固定外层 UDP peer。既没有 HTTP/2 外层、capsule-only、CONNECT-IP、多跳或迁移，也没有持续 PMTU 重探或双向 MTU 保证。此处的 aioquic 外层也不属于[直连 Firefox 指纹]的验证范围。
- **变更方向，不是当前功能：** 若引入持续/双向路径预算、更多载体或跨目标共用外层连接，应分别重新定义丢包、请求流身份、重认证与分区；现有实测只约束建连一次、单目标、单 CONNECT 的 UDP 路径。评估减线程或采用事件聚合时，须保住 A/B 所有权、双向报文边界、取消路径与无隐式源站 socket 的断言，先用上述双端收据比较，再谈收益。

[pin]: https://github.com/Facetomyself/ruyihttp/tree/9e88bfe023fd46a96254f8de66e8d72517339911
[tag-commit]: https://github.com/Facetomyself/ruyihttp/commit/74953f70e87f5935a9ce4410c639727d26ea323e
[environment]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L79-L108
[session-send]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L150-L190
[adapter-export]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/adapters.py#L5-L9
[route-id]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L94-L116
[tcp-proxy]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L862-L944
[native-policy]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/patches/GECKO_H3_POLICY.md#L17-L27
[extra]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/pyproject.toml#L40-L42
[lazy-quic]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L201-L223
[wire-cli]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L1111-L1144
[connect-masque]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1046-L1066
[owner-start]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L173-L206
[open-tunnel]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L787-L867
[resolve]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L95-L135
[owner-attach]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L513-L552
[proxy-ca]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L68-L83
[outer-tls]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L225-L289
[maybe-request]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L576-L599
[relay-events]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L646-L686
[udp-pair]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L138-L164
[tunnel]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L450-L503
[relay-loop]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L729-L779
[origin-auth]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L265-L300
[origin-store]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L185-L259
[connect-codec]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque_codec.py#L15-L124
[no-fragment]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L167-L188
[udp-param]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L230-L248
[constants]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L37-L61
[protected-probe]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L291-L346
[mtu-search]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L505-L553
[response-status]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L191-L198
[relay-http]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L601-L686
[relay-send]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L716-L727
[datagram-codec]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque_codec.py#L127-L221
[exchange-send]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1314-L1385
[owner-submit]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L208-L252
[owner-execute]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L347-L453
[exchange]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L625-L747
[relay-io]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L693-L784
[relay-forward]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L412-L433
[egress]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L291-L301
[relay-return]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L435-L460
[origin-events]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L321-L344
[owner-pump]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L455-L511
[raw-body]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L683-L745
[response-return]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1384-L1409
[transport-mtu-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_transport.py#L136-L178
[transport-wire-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_transport.py#L340-L422
[wire-negative]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L983-L1017
[outer-limits]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L348-L370
[transport-bounds-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_transport.py#L53-L107
[codec-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_codec.py#L73-L117
[owner-stop]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L553-L599
[transport-cancel-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_transport.py#L424-L439
[route-cancel-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_routing.py#L259-L297
[wire-close]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L1051-L1108
[adapter-retry]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1068-L1180
[adapter-cleanup]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1410-L1449
[restartable]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_retry.py#L38-L52
[redirect-hooks]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L110-L179
[outer-error]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L439-L447
[pool]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L394-L460
[route-redirect-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_routing.py#L96-L172
[wire-redirect]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L1039-L1050
[ci-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/.github/workflows/ci.yml#L28-L48
[native-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_native.py#L29-L60
[fixture-calibration]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L657-L713
[client-observer]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L726-L772
[wire-proof]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L917-L1108
[wheel-run]: https://github.com/Facetomyself/ruyihttp/actions/runs/45810139410
[qualification]: https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/qualification.json
[wheel-ci]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/.github/workflows/wheels.yml#L77-L109
[wheel-hooks]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/qualify_wheel.py#L83-L89
[go-peer]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/masque_interop/main.go#L49-L104
[go-versions]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/masque_interop/go.mod#L3-L9
[go-proof]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque_go.py#L63-L135
[直连 Firefox 指纹]: ../firefox-profile-wire.md
[rfc9298-request]: https://www.rfc-editor.org/rfc/rfc9298#section-3.4
[rfc9298-response]: https://www.rfc-editor.org/rfc/rfc9298#section-3.5
[rfc9114-response]: https://www.rfc-editor.org/rfc/rfc9114#section-4.1
[rfc9297]: https://www.rfc-editor.org/rfc/rfc9297#section-2
[rfc9000-mtu]: https://www.rfc-editor.org/rfc/rfc9000#section-14
[rfc9220]: https://www.rfc-editor.org/rfc/rfc9220#section-3
[rfc9221-frame]: https://www.rfc-editor.org/rfc/rfc9221#section-3
[rfc9001-initial]: https://www.rfc-editor.org/rfc/rfc9001#section-5.2
[transport-select-1194-1297]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1194-L1297
[transport-select-1182-1259]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1182-L1259
[open-tunnel-787-808]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L787-L808
[owner-attach-518-536]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L518-L536
[owner-start-173-184]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L173-L184
[relay-events-654-664]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L654-L664
[outer-h3-354-430]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L354-L430
[relay-io-693-768]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L693-L768
[relay-http-601-644]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L601-L644
[tunnel-473-479]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L473-L479
[outer-h3-387-430]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L387-L430
[relay-http-608-686]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L608-L686
[wire-negative-983-1004]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L983-L1004
[constants-37-58]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L37-L58
[outer-h3-429-434]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L429-L434
[owner-execute-347-395]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L347-L395
[owner-submit-223-252]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L223-L252
[owner-execute-442-449]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L442-L449
[owner-pump-455-466]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L455-L466
[tunnel-482-503]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L482-L503
[relay-loop-769-779]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L769-L779
[wire-close-1058-1065]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L1058-L1065
[connect-codec-22-59]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque_codec.py#L22-L59
[connect-codec-113-124]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque_codec.py#L113-L124
[exchange-send-1328-1335]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1328-L1335
[redirect-hooks-118-148]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L118-L148
[constants-58-61]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L58-L61
[transport-select-1200-1297]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1200-L1297
[outer-h3-354-363]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L354-L363
[transport-select-1233-1245]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1233-L1245
[wire-proof-926-969]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L926-L969
