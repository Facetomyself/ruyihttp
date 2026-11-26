# 01 · 请求路由、连接预算与租约

[架构总览](README.md) · [协议引擎](02-protocol-engines.md) · [MASQUE](03-masque.md) · [信任与 Firefox 配置](04-trust-profiles.md)

本章跟踪 **从 Requests 风格 API 到响应体归还租约** 的控制流。代码依据固定在公开提交 [`9e88bfe023fd46a96254f8de66e8d72517339911`][baseline]；[`v0.9.4` 标签][release]和它在本章范围内的实现、测试一致，两个提交之间只有根目录 `README.md` 变化。阅读时先区分三个单位：**重定向的一跳、适配器的一次尝试、一次尝试内的建连竞争**；后两者不是同一种重试。

## 入口、准备与重定向

- [`ruyihttp.__init__`][exports] 再导出 Requests 的 `Request`、`PreparedRequest`、`Response` 和异常；[`api.request()`][api] 每次进入一个临时 `Session`，`get`、`post` 等都是薄包装；`head` 默认 `allow_redirects=False`。希望复用连接、Cookie 或 Alt-Svc 时，显式使用同一 `Session`，流式读取也在该会话存活期间完成。
- [`Session.__init__` / `prepare_request`][session-prepare] 关闭 Requests 原装的默认适配器，将**同一个** RuyiHttp 适配器挂在 `http://` 与 `https://`。Requests 先合并请求与会话的 headers、cookies、auth 等并准备 `PreparedRequest`，RuyiHttp 再按 Firefox 配置、`context`、`document_url` 和 `user_activation` 处理头与 Cookie；[`Session.send`][session-send] 发送时再应用相同逻辑、注入会话超时及检查代理路线。`context="navigation"`、`document_url=None`、`user_activation=True`、`verify=True`、`timeout=None` 是会话默认；Firefox 选择是显式版本 → `NECKO_FIREFOX` → `159`，见 [版本解析][firefox]。使用 `Session.prepare_request(Request(...))` 才会把会话状态纳入初次准备；`Request.prepare()` 直接构造请求会绕过这一层合并。
- Requests 的 [`Session.request`][requests-request] 调 `merge_environment_settings` 再调 `send`；[`Session.send`][requests-send] 选挂载点、分派响应 hooks、提取 Cookie、处理重定向；`stream=False` 时再读 `r.content`。手动 `send(prepared)` 不会完整走 `request()` 的环境合并；例如要让 `REQUESTS_CA_BUNDLE` 参与 HTTPS 校验，可显式调用 `merge_environment_settings` 后把结果交给 `send`。若 `Session(timeout=...)` 已配置，发送参数缺省或为 `None` 都会继承该会话值。
- [`resolve_redirects`][requests-redirect] 消费、关闭旧响应后再发下一跳；默认上限 **30 次重定向**，来自 Requests 的会话设置。Requests 把非 `HEAD` 的 `302/303`、以及 `301` 的 `POST` 改成 `GET`；`307/308` 保留方法和体，其他已跟随的重定向清掉体及其 framing 头。可回卷的上传在所需时回到原位置。Requests 按规则剥离跨目的地址的 `Authorization`，重建代理和 Cookie；[RuyiHttp 重定向钩子][session-redirect] 再应用 Firefox 上下文，并传播 MASQUE 路由标记。`allow_redirects=False` 仍可构造 `Response.next`，真正发送它时才做 MASQUE 同一路线检查。

```python
import ruyihttp

# 一次性请求；timeout 的数值单位是秒。
print(ruyihttp.get("https://example.com/", timeout=(3, 10)).status_code)

# 保留会话；在关闭会话前消费或关闭响应体。
with ruyihttp.Session(timeout=(3, 10), context="fetch",
                     document_url="https://example.com/") as session:
    prepared = session.prepare_request(ruyihttp.Request("GET", "https://example.com/"))
    settings = session.merge_environment_settings(prepared.url, {}, True, None, None)
    with session.send(prepared, **settings, allow_redirects=False) as response:
        print(response.status_code, response.raw.version, response.tls)
        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                print(len(chunk))
```

## 代理优先级：先合并，再选键

| 调用入口 | 代理配置如何生效 |
| --- | --- |
| `Session.request(..., proxies=...)` / `get(...)` | 一般路线继承 [Requests 的环境合并][requests-merge]：同键上请求声明优先，`trust_env=True` 时环境填请求映射中的空缺，随后请求／环境合并结果覆盖同键的 `Session.proxies`。`NO_PROXY` 影响环境发现，别把它当成删除手写代理映射或承诺强制直连的开关。 |
| `Session.send(prepared, proxies=...)` | 明传映射就用该映射；明传 `{}` 表示本次没有代理映射。未传时从 `Session.proxies` 出发，普通路线调用 `resolve_proxies`，由环境补同 scheme 的空缺；已有 MASQUE 路线则跳过普通环境发现。 |
| 请求或会话所选路线为 `masque://` | [`merge_environment_settings`][session-proxies] 在普通环境发现前判定；手写请求中选出的 MASQUE 会写到当前 scheme/hostname 的精确键。最终选中明确的 MASQUE 时，系统环境里的普通 TCP 代理、平台 bypass/PAC 均不参与替换；对同一键显式选择普通 TCP 代理则仍属普通路线。源站 CA 合并后若 `trust_env=True` 且是字面 `True`，才读取 `REQUESTS_CA_BUNDLE`、`CURL_CA_BUNDLE`。 |

[`select_proxy` / `resolve_proxies`][requests-proxy] 的选键次序是 `<scheme>://<hostname>` → `<scheme>` → `all://<hostname>` → `all`，首个存在的键即结束查找；scheme 是**目标 URL** 的 scheme，host 键不带端口。上述优先级描述同键合并，不能简化成“任意请求键总赢任意会话键”。复现时要排除外部环境可设 `session.trust_env = False`，并显式检查会话和调用点上的映射。

[`HTTPAdapter._connect`][connect] 的 TCP 首跳是代理（有代理时）或源站（直连）；普通代理可用 `http`、`https`、`socks4`、`socks4a`、`socks5`、`socks5h`，省 scheme 补 `http`。默认端口：HTTP **80**、HTTPS **443**、SOCKS **1080**。HTTPS 代理外层 TLS 强制不用 H2；HTTP(S) 代理到 HTTPS 源站时先发 `CONNECT` 并要求 **200**，随后在隧道里按**源站名**建立 TLS；普通 HTTP 正向代理以代理所需的请求目标形式发出，无此 CONNECT 步骤。普通 HTTPS 代理的 TLS 校验沿用 `verify`，`proxy_verify` 是 MASQUE 专用设置。代理 Basic 认证由 CONNECT 或普通 HTTP 代理请求构造；适配器不会把请求头里已有的 `Proxy-Authorization` 当作 HTTPS 源站头透传，见 [头部构造][wire-request]。

## 单次尝试的连接截止时间与 DNS

[`HTTPAdapter._send_once`][budget] 每次规范化超时并创建 `Attempt`：接受秒数、`(connect, read)`、或克隆后的 `urllib3.util.Timeout`。`None` 表示相应阶段无该显式上限；数值要有限且为正，原生转换要求 `seconds * 1000 < 0xFFFFFFFF`，有限值按毫秒向上取整（至少 **1 ms**）。连接使用同一个**单调时钟绝对截止时间**，贯穿等池、候选筛选及所需 DNS、拨号、SOCKS/CONNECT 协商与 TLS 或 QUIC；探测输家的清理不延长等待。连接结束后重新计算读超时（若有 `Timeout(total=...)` 会计入连接耗时）；读超时不是整个上传、下载、重试和重定向合计的墙钟时限。适配器重进 `_send_once` 会建立新的连接预算，每次重定向的发送也独立。

- **解析有界。** [`resolve_addresses`][dns] 对数字 IP 直返；只消费 `AF_INET`/`AF_INET6`，按解析器顺序分族、族内去重，保留所需的 IPv6 scope。全局共享 **16** 个 daemon `getaddrinfo` 名额；等名额和结果最多以 **50 ms** 片段检查剩余预算。调用者能在到期时返回 `ConnectTimeout`，已进 libc 的 DNS 工作者仍占名额直到调用结束。合并需要 DNS 时，合并失败后常规拨号使用同一份解析结果，避免重复查找或重置预算。
- **TCP 两族竞争。** [`connect_tcp` / `race`][tcp-race] 先发起解析结果中的首个地址族；若有另一族，首路失败时可立即放行，否则延迟 **250 ms**，有期限时取该延迟与剩余预算一半之较小者。同族按序拨：还有多个候选时，每个获得剩余时间除以未试候选数；无总期限时，非末个候选限 **1 s**。首个成功者被移交，输家取消或在迟到后自己关闭；这只是 TCP 可用性，随后的代理协商和 TLS 仍走原有预算与逻辑主机名。
- **SOCKS 分开首跳和目标解析。** [`_socks.negotiate`][socks] 依赖 `ruyihttp[socks]`。先拨代理；`socks4a`／`socks5h` 把目标主机名交给代理解析，本地只需处理代理首跳地址。`socks4`／`socks5` 用同一连接 `Attempt` 本地解析目标，再把首个所选数字 IP 交给 PySocks；前者只接 IPv4，后者可用 IPv6 并去掉客户端 scope。这里没有多目标 SOCKS 协商竞速。MASQUE 的代理解析与期限另见[第 03 章](03-masque.md)。

## 图解：直连 HTTPS 如何取得租约

![直连 HTTPS 按池内命中、Alt-Svc 或常规源站分支取得连接，随后将租约交给响应体](diagrams/request-route.svg)

[交互图（HTML）](diagrams/request-route.html) · [可编辑图源（JSON）](diagrams/request-route.json)

以同一会话对某个 HTTPS 源站的连续 GET 为例，且没有代理、客户端证书或强制 H1。第一次没有提示或已有连接：从左侧申请租约，拿到拨号预留后走**下方常规源站**，拨 TCP 并按 ALPN 发请求。若响应公告 `Alt-Svc: h3=":443"; ma=60`，下一次会优先尝试取现成的 H3；若没有并取得预留，走**中间分支**，重新确认提示后决定竞速或直接借温 TCP。例如只剩约 **50 ms** 且已存在可借的 TCP 连接时，若池内检查已经取到该租约，就走**上方已有连接**边，不发 QUIC 探测；若是在取得预留后才走同样的短路，则从中间分支汇入交换。三个分支都指向同一个协议交换：先有租约，后按 ALPN 选择引擎；收到响应头后由响应体接管。图只画这段成功交接；不画代理、错误清理、上传时序、重定向或重试，箭头也不是耗时刻度。

## 池的所有权、跨主机合并与排空

1. **分区。** [`_send_once` 的池键与分支][pool-route] 包含 URL scheme、hostname、显式 `port`（缺省为 `None`）、所选代理/`('masque', route_id)`、源站验证表示、客户端证书表示和 `http1` 标志。普通路线的验证与证书参与键的是字符串表示；MASQUE 区分打包信任和绝对 CA 路径。池按适配器隔离；默认最多 **10 个键**（LRU），各池配置 `pool_maxsize=10`、`pool_block=False`，池大小必须为正。LRU 淘汰会关闭池的空闲连接，仍在用的共享连接在租约归零时处理。见 [适配器默认和 LRU][adapter-pool]。
2. **租约与拨号预留。** [`_Pool.acquire` / `register`][pool-acquire] 优先检查可接单的 `shared` 连接，然后按条件等在建连的请求或 `pool_block` 门槛，再从 `idle` 列表取独占连接；若仍没有，置 `connecting=True`、增加 `leased` 并返回 `None`，表示调用者有**拨号预留**，而非“没借到也没占槽”。H2/H3 放在 `shared`，记录每条连接的 lease 数；H2 在排队提交 HEADERS 前已计入 peer stream capacity，工作线程仍会在开流前复查 SETTINGS。`pool_maxsize` 不是全局 socket 上限：已可用的共享流先检查；非阻塞池可溢出建连；闲置 H1 和闲置 H2 各有保留限制，实现没有把同一个 H2 容量检查或闲置上限套到 H3 上。
3. **借用与清理。** [`_BorrowedConnection.close`][borrow-proxy] 把输了竞速的借用连接退回原池，不把连接本身关闭；取胜后 [`_send_once`][pool-transfer] 用 `release(None)` 归还本池拨号预留，把交换交给借出池。新连接则 `register`。只有归还 `None` 的拨号预留才清 `connecting`；丢弃某个 H1 租约不能擦除别的请求的建连状态。异常和调用中断也释放相应所有权；如果只是建连预算在开始协议交换前耗尽，未用且仍可用的旧租约可退回。见 [`_Pool.release` / `close`][pool-release] 和 [异常出口][transport-errors]。
4. **合并不是看证书通配符就借。** [`_coalesce`][coalesce] 在符合条件的已验证直连 HTTPS 上查同适配器兄弟池，要求其 proxy／验证／cert／H1 等键尾一致；[`_Pool.borrow`][pool-borrow] 还要求共享连接可用、有容量、有效源站端口一致、协议符合本次偏好/开关，且目标未被该连接标记拒绝。H2 须先收到 SETTINGS；若收到 [`ORIGIN` 帧][h2-origin]，目标 `(host, port)` 必须在名单中，命中可不查 DNS；否则用本次源站 DNS 结果匹配连接 peer 地址。最后**始终用该连接的验证上下文对新主机名和握手证书链复验**，不是只比 IP 或复用首站验证结论。池的验证参数键也不是证书文件内容摘要，具体信任加载与刷新边界见[第 04 章](04-trust-profiles.md)。
5. **421 与 GOAWAY 各管一件事。** [适配器的 421 分支][reply-retries] 只识别跨池合并后返回的 `421`：在这条连接的拒绝集合加入该 hostname、关闭响应，再按共享的协议重启计数重试。它排除该连接，并非封掉整个池，也不保证下一次必拨新连接；普通 421 不走此专用分支。GOAWAY 是连接排空信号：H2 不再接新流，对尚未结束且 `stream_id > last_stream_id` 的流报未处理（`HTTP_1_1_REQUIRED` 保留降级语义）；H3 边界是 `stream_id >= last`。已接受的流可继续；池不再给排空连接分配新租约，最后一个用户释放后再清理。见 [H2 GOAWAY／开流门槛][h2-goaway]、[H2 容量][h2-capacity] 和 [H3 GOAWAY／可用性][h3-events]、[`Connection.idle`][h3-idle]。

## Alt-Svc：提示、竞速、冷却与令牌

- **提示是后续选路状态。** 适配器从无代理、无客户端证书的 HTTPS 响应记提示；为未强制 H1 且此次允许 H3 的直连 HTTPS 优先找活跃提示。解析接受 `h3="host:port"` 或 `h3=":port"`，会检查 authority 形状。`ma` 单位为秒，缺省和上限均是 **86,400 s**；`ma=0` 或 `clear` 移除公告。公告 LRU 上限 **256 条**；觉察池等待后提示变化，会在拨号预留内再读。`clear` 不等于关闭池内 H3 连接或抹掉单独缓存的冷却。见 [路由优先判断][pool-route]、[记公告调用点][exchange] 和 [缓存解析][alt-cache]。
- **只竞速可用连接，不双发请求。** [`_connect_alternative`][alt-race] 以 H3 为首路，先考虑可信 H3 合并，否则按候选目的地做 UDP 解析和尝试；备用 TCP 延迟上限 **100 ms**（有期限时取剩余预算一半之较小者；首路先失败可提前放行）。TCP 优先借本池温 H2/H1，再尝试经验证的 H2 合并，再拨源站；启用短预算旁路时（剩余 **≤100 ms** 且温租约可借）可直接取温 TCP。选择 H3 后，TLS/HTTP 权威仍是原始源站；`Alt-Used` 描述另选端点。真正启动的竞争若以 TCP 胜出，对 `(池键, 候选端点)` 冷却 **5 s**；短预算未探测则无冷却。公告刷新不续冷却；冷却另有 **256 条**上限。若一次协议错误将 `http3` 置为 `False`，此次 `send` 的后续尝试既不进入 Alt-Svc 分支，也不借 H3（包括跨池）。这不是全局禁用开关。
- **QUIC 令牌另算。** [令牌缓存][alt-token] 以 `(池键, Alt-Svc 端点)` 区分，记录 native 回调交来的 ASCII 编码串，供同路线后续 H3 握手；不是 Cookie、不是响应缓存。上限 **128 条**、合计 **512 KiB**、单条 **16 KiB**（均按编码串大小），有效期取 native 提供值与 **86,400 s** 之较小者。尝试失败且未被取消时，只删除这次握手读到的旧记录对象，以免抹掉并发刷新；关闭适配器清理其各缓存。

## MASQUE：已选择的路线是强制约束

[`is_masque_proxy` / `masque_route_id`][route-id] 只把 `masque:` 视作适配器的 MASQUE 代理选择；`https://proxy` 仍是普通 TCP 代理。需安装 `ruyihttp[masque]`，请求目标必须 HTTPS 且验证源站证书（`verify=True` 或 CA 路径），此路不接源站客户端证书；`proxy_verify` 单独绑定代理信任，也只接受 `True` 或 CA 文件路径。适配器使用代理 URL、代理信任和路径模板的长度前缀哈希分区，池键不存明文代理凭据或模板 query。示例中的地址是配置占位：

```python
import ruyihttp

with ruyihttp.Session(proxy_verify="/path/to/relay-ca.pem",
                      verify="/path/to/origin-ca.pem") as session:
    session.proxies = {"https": "masque://relay.example.net:443"}
    response = session.get("https://origin.example.net/", timeout=(5, 15))
    print(response.status_code, response.tls, response.proxy_tls)
```

[`_connect_masque`][masque-dial] 交给独立 H3 `Connection`，其 `tunnel_factory` 通过 [open_tunnel][masque-tunnel] 建代理 QUIC 与 CONNECT-UDP 隧道，再承载到源站的 H3；源站与代理的 TLS 证据分别在 `response.tls` 和 `response.proxy_tls`。`open_tunnel` 使用外层连接剩余预算，没有上层期限时该隧道内部默认 **30 s**。路线失败不转 Alt-Svc、常规 TCP、直连源站或跨主机合并；配置错误可在拿池/拨网前失败。重定向（包括显式发送 `Response.next`）必须仍是 HTTPS，适配器支持 MASQUE，且选中的路由指纹完全一致；切到普通代理、直连、HTTP 或更换代理 CA/模板都会失败。对目标选择精确主机键时，要确保重定向目标也能选中同一路线。构造、失败与支持边界详见[第 03 章](03-masque.md)。

## 重试、提前响应与流式释放

| 层次 | 触发与实际作用 |
| --- | --- |
| 建连路径 | TCP 地址族竞争、Alt-Svc 竞争或 MASQUE 对相同代理的受限地址候选发生在创建协议交换前。胜出连接才用于请求，别把这种后备当作业务重放。 |
| 协议重启 | [`restartable`][restart] 先排除已收到响应数据；明确的 `Rejected` 允许重启。普通 `Reset` 要求安全方法（实现列表 `GET, HEAD, OPTIONS, TRACE, PROPFIND, REPORT, SEARCH`）或已知尚未发送；发送状态未知按已发处理，池化 socket、没有响应、无上传体均不是未处理证据。`Http1Required` 可设 H1-only；`DirectRouteReset` 可使后续尝试不使用 H3；`Http3ProtocolError` 走 H3→TCP 重启须对应 Firefox profile 启用（`>=159`，`158` 保留为普通 `ProtocolError`）。MASQUE 遇到要退出其路线的标记直接抛出。见 [协议判定和标记][transport-errors]、[适配器循环][send-retries]、[profile 阈值][firefox-fallback]。 |
| 合并后收到 421 | 上述一般“已收到数据不重启”规则之外的专门分支；它本身没有按方法过滤。与协议重启共用 `MAX_REQUEST_ATTEMPTS = 10`（即至多 **9 次**该计数内的额外尝试，每次 `send` 单独计数）。 |
| 用户配置的 `urllib3.Retry` | 默认 `max_retries=0`。连接、读取、TLS/代理错误等，经适配器翻译后交 `Retry.increment`；状态码重试由 `is_retry` 与策略控制，随后读取/关闭响应，再按策略睡眠，含满足条件的 `Retry-After`。次数和方法由 `Retry` 管；与上面的协议计数分开，**10** 不是整个调用可发请求次数的总上限。显式给 `POST` 配置 read/status 重试时，服务端若已生效可能再次执行；生产端要以可验证的幂等键/去重策略判定是否能重复，不能把连接故障当事务回滚。 |
| Redirect | Requests 发新的 `PreparedRequest`，可能改变方法或丢体；保留体时由 Requests 跟踪重定向回卷。此层还会重新检查代理选键与 MASQUE 的同路约束。 |

在适配器一轮 `send` 内，[`send`][send-retries] 记录初始 `body.tell()`；重发前，非 `str`／`bytes`／`bytearray`／`memoryview` 的体要能 `seek` 回原偏移，典型为可寻址文件或 `io.BytesIO`。单次生成器、不可回卷的流，或失败的 seek 会以 `UnrewindableBodyError` 结束，发生在第二次提交之前。常规 `GET`/`HEAD` 的协议重启与业务层幂等仍应分开看；若需要调整错误重试，设置该会话适配器的 `max_retries` 为明确的 `urllib3.util.Retry`（默认两种 URL scheme 使用同一适配器）。

[`_send_once`][exchange] 选择 H1/H2/H3 后发送请求体；文件按 **65,536 字节**读块，迭代体在取下一片之前检查 `upload_stopped`。H2 在已有完整最终响应时收到 `RST_STREAM(NO_ERROR)` 才将上传正常停下并保留响应；仅收到结束响应还不等于上行停止。H3 的 `STOP_SENDING(0x100)` 停止发送但仍要等最终响应。H2 的 `REFUSED_STREAM`、H3 的 `H3_REQUEST_REJECTED` 属明确拒绝；H2 的 `HTTP_1_1_REQUIRED` 流重置不单独证明未处理。见 [H2 事件处理][h2-goaway]、[H3 事件处理][h3-events] 以及 [H3 Exchange][h3-upload]。停止标记不会中断用户的迭代器已进入的一次阻塞 `next()` 或 `read()`；详见[第 02 章](02-protocol-engines.md)。

收到响应头后，[`_Body`][body] 持有 exchange 和它的所属池。读至结束、显式 `Response.close()` 或读失败关闭时归还租约；`stream=True` 的未读响应仍占一个 lease。H1 只有 framing 完成且连接可复用才回闲置列表；未读完时关闭会牺牲这条连接。H2/H3 通过关闭/取消自己的交换归还流，其他可用流不因这个 `close()` 一起关闭；已失效或排空的共享连接在最后一个用户归还时回收。`iter_content()` 已把部分字节交给调用方后发生错误，不会由适配器回到 `send` 循环自动重放；`stream=False` 的常规内容预读也在 Requests 的适配器调用外（状态重试消费体是单独路径）。

## 故障定位表

| 观测 | 先查什么 | 路线或租约结果 |
| --- | --- | --- |
| 等池、DNS 或拨号到期 | `timeout=(connect, read)`、是否 `pool_block`、未关闭流、DNS 名额；[预算][budget]与 [DNS][dns] 共用截止时间。 | 通常为 `ConnectTimeout`；普通代理建连内部的部分连接错误会包装为 `ProxyError`，MASQUE 连接期限保持 `ConnectTimeout`。检查失败后是否归还预留；别把读超时和连接期限混算。 |
| 已连接但响应头/体停住 | [交换层][exchange] 的 read timeout、[错误翻译][transport-errors] 和调用者是否正在等自己的上传生产器。 | 头部阶段 `TimeoutError` 可映射 `ReadTimeout`；体阶段已在适配器重试范围外，可能由 Requests/urllib3 包装。关闭未完成响应，明确释放租约。 |
| CONNECT 非 200、SOCKS 协商失败或 CA 错 | 分离首跳与源站：看代理 scheme、端口、代理认证、源站 `verify`；MASQUE 另查 `proxy_verify`。 | 普通代理失败查 `ProxyError`，证书失败查 `SSLError`。本地 SOCKS 目标 DNS 的 `socket.gaierror` 可以原样向上传播；不要一律捕获成代理认证失败。 |
| 宣告 H3 却还在 H1/H2 | 检查直连资格、提示是否有效/冷却、剩余预算、是否已有温 TCP、profile 或本次 H3 禁用标记。 | 温 TCP 短路没有 UDP 探测；探测后 TCP 胜出才冷却该端点。不要只凭 `response.raw.version` 判定是哪一个分支。 |
| 421 或 GOAWAY 后仍有其他流完成 | 看该响应是否来自跨池合并；记 HTTP/2 与 HTTP/3 的 stream-id 门槛。 | 421 限制这条连接的目标 host；GOAWAY 停新流并依照各协议的 stream-id 边界判定未处理，让已接受的流继续。 |
| `POST` 返回连接错误，或重试前报 `UnrewindableBodyError` | [重启条件][restart] 是否有未处理证据、用户 Retry 是否允许 POST、体原偏移能否回卷。 | 没收到响应仍可能已执行。先查服务端结果；无法回卷时适配器在第二次发送前结束。 |
| MASQUE 重定向突然失败 | 对比重定向目标的代理选键、scheme、代理 CA 与路径模板；若返回 `Response.next`，确认实际发送点。 | `ProxyError` 在换路前抛出；不应看到普通 TCP fallback、直连或平台 PAC 查询源站。 |

## 修改点与回归入口

以下先列能锁定分支的现有测试，再说明应加的断言；**替身和内存帧的断言不等于已验证网络行为**。

| 要修改的部位 | 现有覆盖与维护动作 |
| --- | --- |
| 代理合并、重定向或 MASQUE 分区 | [`test_masque_routing.py`][test-masque] 用 mock 验证普通拨号/Alt-Svc 不被调用、手动跟随 downgrade 在外拨前失败；同文件的[代理优先级用例][test-proxy-priority] 验证环境不替换显式路由。变更时并测 `get`、`send(prepared)`、`Response.next`，加入不同优先键与 CA 的用例；真实代理互通看[第 03 章](03-masque.md)中的 loopback/互通脚本。 |
| DNS 调度、TCP 竞速及 SOCKS 协商 | [`test_connect_dualstack.py`][test-dns] 注入 resolver 和 socket opener，验证饱和、取消、数字地址、同族去重等；[`test_connection_budget.py`][test-budget] 检查复用 DNS 结果和等池超时；[`test_socks_deadline.py`][test-socks] 验证 `rdns` 与实际传给协商方法的地址。修改时加等待、解析、握手共享同一绝对截止时间以及输家迟到仍关闭的断言；网络行为另用 [`ci/smoke_connect_budget.py`][smoke-connect]。 |
| 池共享容量、合并与租约移交 | [`test_http2_flow.py`][test-flow] 覆盖未创建流时的 lease 预留、H2 闲置裁剪与饱和跳过；[连接预算用例][test-coalesce] 单测 ORIGIN 命中仍验链、错误端口不查 DNS、解析失败释放预留。改 421 分支时应新增明确的 421 回归：只屏蔽原连接对应 host、普通 421 不触发、关闭第一响应不泄漏 lease、重放前回卷体；现有引用的 GOAWAY/合并测试不代替它。 |
| Alt-Svc 缓存、温借用、失败冷却 | [`test_alt_svc.py` 的缓存用例][test-alt-cache] 与[温连接用例][test-alt] 控制时钟与连接替身验证过期/冷却、令牌大小和替换、温 H2 饱和及输家归还。改竞速要加“短预算不发探测也不进入冷却”的断言；[`test_alt_svc_native.py`][test-alt-native] 是带 native H3 开关和兼容运行库的真实本地 TCP/TLS 与 UDP 黑洞/成功升级测试，可观测 TCP 连接 id 和 UDP 包数。 |
| 安全重试、提前返回、读完释放 | [`test_retry_safety.py`][test-retry] 单测已发送/已收到数据分类、拒绝条件与不可回卷体；同文件的 [native 回环测试][test-retry-native] 确认服务端读完 POST 再断连时不会默认重放，并验证显式配置会回卷到原偏移。H2 用 [`test_http2_early_response.py`][test-early] 的内存帧与 [`ci/smoke_h2_early_response.py`][smoke-early] 的回环测试，H3 用 [`test_h3_body_abi.py`][test-early-h3] 的 native 条件用例。更改关闭逻辑时，检查部分读取、显式关闭、失败后再次借用，以及并发流仍然可用；对不同协议分别断言。 |

在已安装项目依赖的 Python 环境，从仓库根目录运行聚焦用例（native 用例按各文件开关和运行库前提单独启用）：

```bash
python -m pytest -q tests/test_connect_dualstack.py tests/test_connection_budget.py \
  tests/test_socks_deadline.py tests/test_alt_svc.py tests/test_retry_safety.py \
  tests/test_http2_flow.py tests/test_http2_early_response.py tests/test_masque_routing.py \
  tests/test_cookie_site.py
```

[baseline]: https://github.com/Facetomyself/ruyihttp/tree/9e88bfe023fd46a96254f8de66e8d72517339911
[release]: https://github.com/Facetomyself/ruyihttp/tree/74953f70e87f5935a9ce4410c639727d26ea323e
[exports]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/__init__.py#L9-L43
[api]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/api.py#L8-L38
[session-prepare]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L27-L77
[session-proxies]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L79-L108
[session-redirect]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L110-L148
[session-send]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L150-L190
[firefox]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L247-L263
[firefox-fallback]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L232-L244
[requests-request]: https://github.com/psf/requests/blob/v2.32.5/src/requests/sessions.py#L566-L591
[requests-send]: https://github.com/psf/requests/blob/v2.32.5/src/requests/sessions.py#L673-L748
[requests-merge]: https://github.com/psf/requests/blob/v2.32.5/src/requests/sessions.py#L750-L784
[requests-proxy]: https://github.com/psf/requests/blob/v2.32.5/src/requests/utils.py#L828-L878
[requests-redirect]: https://github.com/psf/requests/blob/v2.32.5/src/requests/sessions.py#L159-L353
[connect]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L862-L959
[wire-request]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1314-L1366
[budget]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1182-L1201
[dns]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_connect.py#L13-L35
[tcp-race]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_connect.py#L54-L244
[socks]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_socks.py#L14-L82
[adapter-pool]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L772-L827
[pool-route]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1200-L1283
[pool-acquire]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L394-L460
[borrow-proxy]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L382-L391
[pool-transfer]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1284-L1305
[pool-release]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L527-L571
[coalesce]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L829-L860
[pool-borrow]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L484-L525
[h2-origin]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L414-L440
[h2-goaway]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L304-L349
[h2-capacity]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L442-L479
[h3-events]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L301-L344
[h3-idle]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L591-L599
[h3-upload]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L695-L753
[alt-cache]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1503-L1576
[alt-race]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L961-L1044
[alt-token]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1453-L1501
[route-id]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L94-L116
[masque-dial]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1046-L1066
[masque-tunnel]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L787-L847
[restart]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_retry.py#L7-L52
[send-retries]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1068-L1148
[reply-retries]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1149-L1180
[exchange]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1336-L1409
[transport-errors]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1410-L1451
[body]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L683-L745
[test-masque]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_routing.py#L52-L171
[test-proxy-priority]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_masque_routing.py#L204-L257
[test-dns]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_connect_dualstack.py#L28-L186
[test-budget]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_connection_budget.py#L156-L260
[test-socks]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_socks_deadline.py#L49-L160
[test-flow]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_http2_flow.py#L352-L378
[test-coalesce]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_connection_budget.py#L55-L114
[test-alt-cache]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_alt_svc.py#L38-L161
[test-alt]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_alt_svc.py#L271-L503
[test-alt-native]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_alt_svc_native.py#L166-L219
[test-retry]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_retry_safety.py#L46-L168
[test-retry-native]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_retry_safety.py#L199-L274
[test-early]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_http2_early_response.py#L67-L122
[test-early-h3]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_h3_body_abi.py#L394-L467
[smoke-connect]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_connect_budget.py
[smoke-early]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_h2_early_response.py
