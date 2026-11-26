# 02 · 协议引擎：HTTP/1.x、HTTP/2、HTTP/3

`HTTPAdapter._send_once()` 按已选传输的 `alpn` 创建 Exchange：H1 把消息分帧交给 `necko_core`，H2 在 Python 中用 hyper-h2 驱动 NSS TLS，H3 由 Python owner 驱动原生 Neqo。三个实现共用 `_Body`，但**响应读完、请求发送完、连接可再租用是三件事**。修改超时、释放或重试前，先确定这三种状态分别由哪一层更新。

公开发行版：[v0.9.4](https://github.com/Facetomyself/ruyihttp/releases/tag/v0.9.4)，已测试标签提交 [`74953f70`](https://github.com/Facetomyself/ruyihttp/commit/74953f70e87f5935a9ce4410c639727d26ea323e)。本文代码锚点和两图固定到公开 `main` 的 [`9e88bfe0`](https://github.com/Facetomyself/ruyihttp/tree/9e88bfe023fd46a96254f8de66e8d72517339911)；相对该标签，证据提交只改了仓库首页 README。导航：[架构总览](README.md) · [请求路由](01-request-routing.md) · [MASQUE](03-masque.md) · [信任与 Firefox 配置](04-trust-profiles.md) · [原生交付](05-native-delivery.md)。

## 共用入口与责任边界

| 引擎 | 处理 HTTP 的位置 | I/O 与所有权 | `_Body` 何时释放租约 |
| --- | --- | --- | --- |
| H1 | `necko_exchange_*`；Python 组装参数并把响应头映射成 Requests 需要的对象 | 调用线程同步穿过 ctypes。一个 Exchange 持有一个消息句柄；连接租约独占。明文走 `_NativeSocket`，HTTPS 走 `_nss.TLS` | 空读或 native 判定完整时读取结束。先询问 `necko_exchange_reusable`，再销毁消息句柄；池据此保留或关闭连接 |
| H2 | `_http2.Connection` 中的 `_Protocol(H2Connection)`；`Exchange` 表示单流 | 每连接一个 worker，独占 hyper-h2 状态与握手后的 NSS I/O；调用线程通过队列下命令 | `ended && !buffer` 或显式关闭时移除流并归还租约；即使丢弃单流，也按共享连接的健康状态管理池 |
| H3 | `_http3.Connection` 调 `necko_quic_call`；原生 Neqo 驱动内层 H3/QUIC | 每连接一个 owner，同线程执行 JSON 控制和可选二进制 body ABI；调用线程只提交命令 | 读侧 `ended` 或显式关闭后清除流登记并归还租约；单流取消与连接退出是两条路径 |

[_send_once 的分派与上传][dispatch]：先补 Host 等请求头，H1 无 `Content-Length` 的 body 会得到 `Transfer-Encoding: chunked`；H2/H3 在各自 `Exchange` 构造时剔除逐跳头。上传的固定字节串直接传给 `write()`；文件每次取至多 65,536 B；迭代体逐次取元素。文件/迭代体在每次取值前检查 `upload_stopped`，已经开始的一次读取无需倒带。`receive()` 后创建 `urllib3.HTTPResponse(preload_content=False, decode_content=False)`，把 body 所有权交给 [`_Body`][body]；这两个标志描述 adapter 的交接点，并非 Requests 最终永远以原始编码或流式返回。`_Body.read()` 按 ≤64 KiB 反复读取；`read1()` 至多读一次；空读、读完或异常分别触发关闭，异常原样向上抛出。`read(0)` 直接返回空字节，区别于真实 EOF。

## H1：两个 native 句柄，两次独立释放

1. **连接句柄。** [`_connect()`][tcp] 先建立原生 TCP；HTTPS 用 `_nss.TLS` 包装，普通 HTTP 仍是明文。传统 HTTP/HTTPS 代理到 HTTPS 源站时，先用独立 `_Exchange("CONNECT", authority, ...)` 读到 200，关闭的是 CONNECT 消息对象，再在隧道内建立源站 TLS。HTTPS 代理自身也有一层 TLS，设置 `http2=False`。`TLS` 保持读、写、空闲探测、验证和证书解压 callback 的引用，`necko_tls_open_profile` 接收 SNI、配置、分区后的会话键、可选客户端证书和私钥；返回后获取 ALPN、版本、套件与恢复状态。证书验证走 `_nss.Context.verify`；涉及的信任材料与分区见[信任章节](04-trust-profiles.md)。[_nss.TLS 初始化][tls-open] · [TLS 回调与关闭][tls-io]
2. **消息句柄。** `_Exchange.__init__` 把 method、target、`name: value\r\n` 串及读写 callback 交给 `necko_exchange_open`，头值按 Latin-1 表示、method/target 按 ASCII；含 NUL 的参数在进入 ABI 前报 `InvalidHeader`。`_Exchange._read/_write` 是 native HTTP 分帧器与 transport 的双向适配器：接收时 `memmove` 到 native 提供的缓冲，发送时从指针复制字节给 transport；HTTPS 的 transport 为 NSS TLS，下一层 TLS callback 才访问 TCP。`_Exchange.close()` 释放消息句柄并断开 callback 引用；`TLS._close_native()` 关闭 TLS 句柄及其下层，`_NativeSocket` 在 `_handle_lock` 下仲裁中断和关闭，复位自己的指针。[_Exchange ABI 与回调][h1] · [_NativeSocket I/O][socket]
3. **上传、头、下载。** `write()` 按 65,536 B 切块并拷入 `ctypes` 数组；`receive()` 触发 native 接收，再读 Latin-1 状态行与头，构造邮件消息对象和 `HTTPHeaderDict`，版本字段为 `11` 或 `10`。响应 `read(size)` 由 Python 分配输出数组，`necko_exchange_read` 写入长度；TLS 和 socket 的读函数使用同一 [`read_bytes`][native-buffer] 约定：校验 `0 ≤ used ≤ capacity`，`used=0` 返回 `b""`，其余用 `memoryview(...).cast("B")[:used].tobytes()` 复制出自有字节。省去的是中间 int 列表，跨 FFI 的拷贝仍存在。[_Exchange I/O][h1-io]
4. **EOF、错误与复用。** 首个响应字节之前遇到 EOF，`_Exchange._read` 记录 `Reset`。已收到字节后的零长度读回传给 native 消息分帧器，由它按实际响应边界报告完成或错误；不能从 TCP EOF 单独推出响应完整。回调异常暂存于对象并返回数字状态，`check()` 优先恢复原异常，为普通 `OSError` 转 `Reset`（保留 `TimeoutError` 与 `ssl.SSLError`），并带 `_necko_sent/_necko_received` 给重试层；native 返回 `1` 为请求分帧或长度问题（`InvalidHeader`），其他非零为 `ProtocolError`。`_Body.close()` 在关闭 Exchange **之前**查询复用；提前放弃/读错的 H1 连接丢弃，能复用的加入空闲池，有后续请求时先做 `idle()` 探测（NSS `pending == 0`，明文 `necko_socket_idle`）。共享 H2/H3 则按连接状态增减租约，流错误不直接等价为连接错误。[_Exchange 错误][h1] · [池释放][pool-release]

维护者的证据边界是这些 ABI 调用、返回值和测试；仓库随 wheel 带 native 二进制及构建补丁，本文不从导出的函数名反推未跟踪的 Gecko/HTTP 分帧器内部状态。最短回归来自 [`smoke_local.py`][smoke-h1] 的回环 HTTP 200 与精确 body；[`BufferTests`][buffer-test] 检查部分、空、越界读和复制后的独立所有权；[真实 H1 重试用例][retry-test] 将读过的 POST、无 body 的 POST、安全 GET 和显式可回卷重试分开。

## H2：由消费归还接收信用

![H2 时序图：调用线程、连接 worker 与 TLS 对端之间的 DATA、读出和窗口更新方向](diagrams/h2-flow.svg)

**图 1 · H2 接收方向。** 箭头给出局部因果顺序；实际接收、读取和 ACK 可重复交错，图无耗时刻度。 [静态 SVG](diagrams/h2-flow.svg) · [交互 HTML](diagrams/h2-flow.html) · [可编辑 JSON](diagrams/h2-flow.json)

### 初始化、顺序和发送背压

- `TLS` 协商 `h2` 且套件通过允许表后，`_connect()` 创建 H2 worker；`enable_nonblocking()` 将 native 的读/写回调切到非阻塞路径（嵌套 TLS 递归设置）。worker 开始前构造 hyper-h2 状态、替换 encoder，按 Firefox profile 顺序发 preface、SETTINGS、连接 `WINDOW_UPDATE(0, 12517377)`。159–161 的 SETTINGS 顺序是 `[(1,65536),(2,0),(4,131072),(5,16384)]`；这三版官方补充采样的首个无 body 导航 HEADERS 用流 3、依赖流 0、权重 42、非 exclusive。SETTINGS ACK 的位置随对端 SETTINGS 到达而变；补充采样止于首个 HEADERS，覆盖不到随其后的私有流窗口策略。旧 profile 按配置保留有/无优先树、ENABLE_PUSH 缺省及 HPACK 规则；有树时先建 3–13 的空闲优先流，首个请求用 15。`FirefoxEncoder` 用 HPACK/Huffman，`authorization` 与短 `cookie` 使用 never-index；`:path`、大项或小表有 literal 策略。[_Protocol 与初始化][h2-init] · [配置表][h2-settings] · [官方前缀证据](../firefox-h2-preface.md)
- Constructor 依次构造 `:method / :path / :authority / :scheme`，过滤逐跳头及 Connection 指名的字段，并按 `; ` 拆 cookie。`fetch` 发送 HEADERS（无上传即带 END_STREAM）后才为有名额的流加额，再尝试捎带连接信用。上传时 `local_flow_control_window(stream_id)` 以**对端授予**的连接/流两级发送窗口为准，`count = min(剩余字节, 可用窗口, 对端 max_outbound_frame_size, 16000)`；窗口为零或内部输出已达 `_OUTPUT_LIMIT = 64 KiB`，本次 `fetch/write/finish` 留队等待。该阈值是开始下一项工作的门槛，非硬性限制瞬时输出内存。`flush()` 分至多 16,384 B 的块、每轮至多 32 次，保存未写完的后缀，处理 NSS 仍有待刷数据的情况。`finish` 在 `sent_end` 为假时发送 END_STREAM，然后才等最终头。[_execute][h2-commands] · [首部与调用顺序][h2-exchange] · [flush][h2-flush]

### 接收预算与信用账本

| 量 | 固定值及含义 |
| --- | --- |
| 初始连接接收信用 | 由 `65,535` 加 `12,517,377` 到 `12,582,912 B = 12 MiB` |
| 每流基础；加额 | SETTINGS 的 `131,072 B = 128 KiB`；最多 7 份保留各加 `524,288 B = 512 KiB`，加额流共 `640 KiB`；释放后名额可再用 |
| 保留上限 | 64 个已登记流（含结束但尚未释放的响应）；以 `64×128 KiB + 7×512 KiB = 11.5 MiB` 给 worker 逐流 payload 留上限，连接至少剩 `512 KiB` 未分配给这些保留 |
| 连接信用回收 | 低水位 `6 MiB`；处理完的信用累计 `64 KiB` 方可回送，窗口为零可回更小一批；窗口大于低水位时等下一次 HEADERS 或本地发出的 RST_STREAM 捎带，捎带同样受批量条件限制 |

[常量与连接窗口管理器][h2-init]。这个 11.5 MiB 是 **Python worker 保留的响应 payload**，不是连接的总 RSS；临时 TLS/帧对象、分配开销、调用者已取走的 bytes 和 `stream=False` 聚合另计。`receive()` 对每个分派到活动流的 DATA 同时检查 `len(exchange.buffer) + size <= exchange.receive_limit` 及 `_buffered + size <= _BUFFER_LIMIT`，防止解析状态与保留政策脱节。两级账本具体按以下事件推进：

| 事件 | worker 改动 | 何时允许 `WINDOW_UPDATE` |
| --- | --- | --- |
| 入站 DATA | `event.data` 入该流 `bytearray`；`event.flow_controlled_length - len(event.data)` 是另行结算的填充信用 | 仅填充立即交给 hyper-h2 `acknowledge_received_data()`；实际 UPDATE 还要过各自窗口策略。未读 payload 不作 padding 退款 |
| 应用读出 | `_take_body()` 从队首复制并删去取走的字节，扣 `_buffered` | 未结束流调用 `acknowledge_received_data(count, stream_id)`，由 hyper-h2 处理流级信用，并走本项目的 `_ConnectionWindow` 连接策略；已经 `ended` 时只归还连接信用 |
| 丢弃/晚到 DATA | `_fail_exchange()` 清空流的 buffer；取消释放保留，向未完全结束的活动流尝试发 `RST_STREAM(CANCEL)`。已关闭/失败/未知流上的 DATA 事件以 `flow_controlled_length` 结算，hyper-h2 对 reset 流内部消化的迟到 DATA 也受替换后的连接窗口处理器约束 | 只退连接信用，不给已丢弃的流增发窗口；避免重复释放 payload。即使没有应用读取，每个 TLS 批次后也重查低水位 |

[入站事件与记账][h2-data] · [应用消费、取消与回收][h2-commands]。**慢流隔离来自预留上限和 ACK 时机，而非服务器必须轮询所有流。** 例如大响应占满自己的 640 KiB 后停，另一流仍有独立额度；若 7 个加额槽均占用，新流基数只有 128 KiB。按 `窗口 / RTT` 粗估，在 RTT = 100 ms 的假设路径上，128 KiB 和 640 KiB 分别约 10.5 和 52.4 Mbit/s（十进制），只是检查 BDP 是否越过窗口的量级，非实测速率或保证；窗口更新节奏、TCP 拥塞、服务端调度和消费者进度都会改变结果。12 MiB 连接窗口不能推导出每条流也有 12 MiB。

### worker、租约、超时与结束

- **锁和调度。** `_Pool.condition` 管池及租约，从 acquire（甚至 HEADERS 尚未下发）计到 body release，也包括借用/合并；连接端只在 `_command_lock` 下串联入队、取消和终结，hyper-h2 的收发状态由 worker 执行。池端 H2 可用租约 `< min(64, peer MAX_CONCURRENT_STREAMS)`，SETTINGS 到来前先只放一份；worker `fetch` 另外检查 64 个实际登记保留与 `open_outbound_streams`，所以租约取得后对端收紧窗口/并发时仍能等待。非阻塞池可另拨一条，但至多保留 `pool_maxsize` 条空闲 H2；阻塞池达到其拨号门槛时等待释放，受 connect deadline 限制。[_Pool][pool] · [worker 命令和容量][h2-commands]
- **等待非忙转。** `submit()` 用 `_Call` 带单操作 monotonic deadline 及 `done`，唤醒 `threading.Event`；调用线程等待超时会标取消并提交逐流 `cancel`。`_run()` 每轮取命令，对留队项逐个尝试，较早被窗口、响应头或 body 卡住的调用不会冻结同轮其他流；这是避免队首阻塞，并非严格轮转或吞吐公平保证。native 只暴露 `necko_tls_pending` 探针，没有可供此 worker 注册的 fd：活跃等待退避 1–8 ms，空闲 5–40 ms，受最近 deadline 截断；收到帧或新命令可提前推进。即使空闲也继续接收 SETTINGS、PING、ORIGIN 和 GOAWAY。`receive()` 每次读至多 65,536 B，超时与暂时不可读不同。[_Call][call] · [H2 提交与关闭后读取][h2-submit] · [worker 循环][h2-worker]
- **事件与 EOF。** `ResponseReceived` 填最终头，1xx 和 trailers 标记已收到事件但不替代最终头；`StreamEnded` 只标读侧结束。只在「有最终 status 且响应已 END_STREAM」之后的 `RST_STREAM(NO_ERROR)` 才将 `upload_stopped` 置真，保留响应且停止后续上传；单独的提前 END_STREAM 仍不关闭上传。RST code 7 为明确拒绝，13 仅要求 H1（不证明未处理），0/8 在其余分支作普通 `ProtocolError`，其他作 `Reset`，9 同时阻止接新流。未结束且暂无 bytes 的 `read` 继续等，TLS EOF/关闭只给**已完整**的已排队或后续调用交付剩余 body；部分响应失败并丢弃缓冲。旧 profile 即便省略 `ENABLE_PUSH`，无 Requests 消费者的推送流也被取消。[_Protocol 事件][h2-events] · [EOF 结算][h2-worker]
- **GOAWAY 不是 421。** `_Protocol._receive_goaway_frame` 保留 `last_stream_id` 事件而不让 hyper-h2 在此直接拆掉连接，停止新租约/`fetch`，`stream_id > last_stream_id` 且未结束的流才标 `Rejected`（若 code 13，则 `Http1RequiredUnprocessed`）；边界以内的流继续排空。H2 ORIGIN 扩展只接收直连上 stream 0 的合法 HTTPS origin，池借用仍复核目标证书；没有 ORIGIN 授权时才以实际 peer IP 对照 DNS（见[路由章](01-request-routing.md)）。H3 的 GOAWAY 比较符不同，详见下节。[_Protocol GOAWAY][h2-init] · [GOAWAY 和 ORIGIN 分发][h2-events] · [借用条件][coalesce]

## H3：所有连接控制与 body I/O 共享同一个 owner

![H3 生命周期图：native 建连、源站认证、流命令及 STOP、reset、关闭分支](diagrams/h3-owner.svg)

**图 2 · H3 连接 owner 到单流释放。** 主线终于本次流租约，连接仍可服务其他流；另有连接级退出分支。 [静态 SVG](diagrams/h3-owner.svg) · [交互 HTML](diagrams/h3-owner.html) · [可编辑 JSON](diagrams/h3-owner.json)

### 连接建好之前：UDP、JSON 控制与验证门

1. `_transport._connect_alternative.quic()` 把 origin 名称与实际 Alt-Svc endpoint 分开，按 route/endpoint 使用会话 token；MASQUE 则传 `tunnel_factory`。`Connection._run()` 直连创建非阻塞 connected UDP，或从工厂拿已认证外层隧道的本地 datagram endpoint（此分支不解析或直拨 origin，也不给 DNS coalescing 提供 relay IP）。两者将 UDP 与 nonblocking `socketpair` 读端注册进 `DefaultSelector`。设置证书解压 callback，`new` JSON 携带 `host/local/remote/token/profile/firefox`，用 `handle=0` 调用；检查结果为真整数且 `0 < handle < 2^64`，再 `attach(socket=udp.fileno())`。[_run 建连][h3-run] · [替代 endpoint 与 MASQUE 工厂][h3-route]
2. `_run_loop` 调 `pump` 推进 native UDP I/O 与计时，下一次时间按其 `delay` 钳在 0–100 ms；紧接着拉 `events`，`more` 为真则继续取批。`auth` 事件给 Base64 DER 链，Python 组为网络字节序 `u32` 长度前缀的证书序列，对**源站** `Context.verify(host, chain)`；失败回 `auth(accepted=False)` 后抛证书错误，成功回 `true` 并要求立即 repump。`state=connected` 时取 `info.tls`；若尚无链，从 `info.certificates` 构出并验证，之后才置 `ready`。`token` 事件回调缓存，`ech_retry` 报需要更新 DNS；转发 CONNECT-UDP 的外层信任与这里的源站信任各自独立。[_run_loop][h3-loop] · [events/auth/info][h3-events] · [Context.verify][trust]
3. `ready.wait()` 受握手预算限制；超时、竞速取消或调用者中断会置 `_stopping` 并写 wake socket。外层隧道错误发生于 `ready` 前时保留连接错误，已 ready 后转 `ProtocolError`（请求可能已达源站），不会把断隧道当成直连许可。[_http3 建连等待][h3-open] · [泵循环的代理错误][h3-loop]

### 流命令、backpressure 与 body ABI

- **从调用者到 owner。** `submit()` 在 `_command_lock` 内检查连接状态并把 `_Call` 入队；通过 wake 写端唤醒，随后按命令剩余 deadline 等 `done`。owner 每轮 drain 队列并尝试所有 pending，未就绪则保留；成功的命令或 `auth` 反馈促使立即 repump。否则 selector 等到 `pump_at`、等待命令的最早 deadline、写探测时间三者的最早者；UDP 可读令 `_input_epoch` 增加，wake 可读则清空通知字节（数据仍在队列）。超时用 `call.cancelled` 和逐流 `cancel`，不是直接在调用线程摸 native handle。`fetch` 对 stream-limit 错误等待、校验返回的 `0..2^62-1` 流 ID，再登记 `stream → Exchange`；其 JSON 参数包括 method、authority、path、Base64 headers、urgency (≤7) 与 incremental。[_Call 与 submit][h3-submit] · [owner 循环][h3-loop] · [stream 执行][h3-execute] · [Exchange 参数][h3-exchange]
- **读写命令。** 非 interim 最终头入 `HTTPHeaderDict`，置 `headers_ready`；`readable` 允许读，没读到字节且无 FIN 则清 `readable` 并继续等。`write` 在已有阻塞纪元且没到 probe 时间时留队；`writable` 增加流纪元可重新启用，legacy bridge 把 UDP input 纪元也算上。无进展的写（legacy 还包括部分写）记下阻塞纪元并设 20 ms 探测；二进制短写则可及时试未写后缀，直到零写触发等待。20 ms 是探测策略，既不是单次 I/O deadline，也不是 H3 协议重传时间。[_event_batch 与 body 路径][h3-io] · [stream 执行][h3-execute]

| 接口 | 当前行为 | 必须保留的契约 |
| --- | --- | --- |
| 控制面（各平台） | `necko_quic_call(handle, json, len)`：`new/attach/pump/events/auth/info/fetch/finish/cancel/close`；异常 JSON `error` 映射 `ProtocolError` | body 是否为二进制不改变控制协议，也不改变 handle/stream 的 owner |
| 二进制 body ABI v1 | `_BodyABI.negotiate()` 要求 `necko_quic_body_abi_version() == 1` **及** `necko_quic_body_read_v1` / `necko_quic_body_write_v1` 同时存在。读为 `handle, stream, data*, len, count*, fin*`；写无 `fin*` | native 长度 1..65,536，stream ≤ `2^62−1`、指针/输出地址满足契约；`NULL` 返回值为成功，错误字符串为线程局部。读回检查 `count <= capacity` 且 FIN 仅 0/1；写检查 `count <= remaining`。native 不保留缓冲，写只借用 immutable bytes（偏移指针，生命周期覆盖调用），读仍要复制到 Python bytes。ABI 错误上抛而非尝试改用同一流的 JSON 重试 |
| 兼容 body | 协商缺符号或版本不对才选 JSON `read/write`：`data` Base64、`count` 整数、`fin` 布尔。零写重试保持同一 `call.frame`，部分写后新命令只编码原块剩余部分 | 仍限 65,536 B/块；校验 Base64 编码长度、严格解码后 payload 长度和 `fin` 类型；写入只接受 `0..remaining` 的真整数。暂时零字节与读侧 FIN 分开 |

[Python ABI 协商及调用][h3-abi] · [native `body_abi.rs` patch][h3-abi-patch]。POSIX patch 调用 owner 线程局部 `SESSIONS`，同一个 handle 跨线程应报错，即使那条线程也有 session；macOS 补丁把编号改成进程内原子分配，map 仍线程局部，解决跨线程同号误命中。`writable` 事件的两套桥接见 ABI 补丁的 [Linux 段][h3-writable]与 [macOS 段][h3-writable-mac]；[macOS 全局 handle 补丁][h3-handles]单独改编号器。进程内编号唯一不是线程可迁移的承诺。

### FIN、提前 413、reset 与回收

- **分清两个半关闭。** 无请求体的 Exchange 在 `fetch` 后立即 `_finish()`，有请求体的在 `receive()` 先 `_finish()` 再等最终头；本地 `sent_end` 防止重复提交。`finish` 仅在没收到正常停传时发送 native 写侧结束，绝不生成读侧 EOF。读侧 `ended` 由最终头的 `fin` 或 `read` 返回的 FIN 设置；读到最后一块时可以同时带 FIN，`_Body` 仍交付该块并关闭租约。只有 FIN 才让没有后续字节的响应完成；头标明的长度完整性另由上层响应读取检查。[_finish / receive / read][h3-reader] · [读写执行][h3-execute]
- **停传是信号，不是响应。** `STOP_SENDING(0x100/H3_NO_ERROR)` 只设 `send_stopped`；pending write 成功解除等待但返回 `None`，不冒充写入字节或 FIN，也不会吞掉最终 413。adapter 看见标记以后不再拉文件或生成器（允许已有一次在执行），`receive()` 仍等待非 interim 最终头。有 STOP 无最终头则 headers timeout；`RESET_STREAM`（包括其 code 0x100）和其他 STOP 分别进入流错误路径：`0x10B → Rejected`、`0x110 → Http1Required`、`0x10C → ProtocolError`、其他 → `DirectRouteReset`。回环 peer 证明 `413 + 7 B + FIN + STOP` 可读，缺最终头为 `ReadTimeout`，取消为 `ConnectionError`，`Content-Length: 700` 却只送 7 B 则上层 `ChunkedEncodingError`。[_event_batch][h3-io] · [回环 413 用例][h3-413]
- **两种清理作用域。** `Exchange.close()` 或操作超时将逐流 `cancel` 入队；owner 先 `streams.pop`，仅当有 stream ID 且尚无响应 FIN，才尽力调用 native `cancel`；`exchange.fail()` 记录首错、置 `headers_ready` 解除等待。GOAWAY 将连接置为 draining，`stream_id >= last` 失败（与 H2 的 `>` 不同）；新 fetch 拒绝。连接退出时 `_run.finally` 标关闭、释放 `ready`、令现存流和剩余命令失败，然后在原 owner 上调用 native `close`，依次回收 selector、隧道或 UDP、两个 wake socket 与 Windows DLL 目录句柄。`close()` 从外线程唤醒并等待最多 1 s；它不是保证在 1 s 内结束任何系统调用的强制中止。H3 没有 H2 在 TLS EOF 后保留已缓冲完整响应的 `_after_close` 分支。[_http3.cancel 与事件][h3-submit] · [GOAWAY 与 closed][h3-events] · [finally][h3-cleanup]

## 池、重试与平台边界

**流拒绝与 421 处理在不同层。** `_retry.restartable()` 先排除已收到响应数据的场景，再判断明确 `Rejected`，或 `Reset` 且方法在安全列表/已知尚未发送。`_send_once()` 在换成 Requests 异常时保留 `_necko_http1/_necko_direct` 给 `send()`；按 profile，某些 H3 连接级协议错误允许禁用 H3 后尝试 TCP，显式 MASQUE 路由则无此分支。`421` 是普通 HTTP 最终状态，专门分支仅在 `_necko_coalesced`（跨 origin 池借到连接）且 `protocol_retries < MAX_REQUEST_ATTEMPTS - 1` 时运行（`MAX_REQUEST_ATTEMPTS = 10`，与协议错误共用 9 次重启额度）：把本 hostname 记入**该 transport** 的 `coalescing_denied`，关闭响应，再次选路。它不将整个连接标为 GOAWAY，不对普通同池的 421 作该种重试；这个专门分支没有方法白名单，但 body 若需要重传仍必须是字节类或可回卷，否则 `UnrewindableBodyError`。[`restartable`][retry] · [421 与回卷][421] · [异常转换][convert]

**Windows 与 POSIX 的界面按产物而分。** `win_amd64` 是上游 LoseNine 的公开 0.11.0 wheel 中六个原样 DLL，`necko_core.dll` 为 ABI v1；`necko_quic.dll` 的导出中有 JSON call/decoder，无三项 body ABI v1 导出，所以走兼容 body；Windows QUIC profile schema 保持上游形状。四个 POSIX 槽 `darwin_arm64 / darwin_x86_64 / linux_aarch64 / linux_x86_64` 为固定 donor/Firefox 161.0/Neqo 0.34.0/NSS 3.133 的源码构建，均含 body ABI v1。Linux/macOS 末序 QUIC policy patch 将 `max_data=25,165,824`（24 MiB）、`max_stream_data_bidi_local=12,582,912`（12 MiB）和 `h3_connect`（Firefox ≥145）传给 Neqo；客户端 Initial 仍 v1，155+ profile 启用 `Version::all()` 的协商顺序；macOS 补丁还改为 3 B SCID，并在该 QUIC 连接握手前开启 NSS delegated credentials。上述是本仓库配置和 patch 能证明的行为，接收窗口是 QUIC transport 参数而非 Python body buffer 预算；Extended CONNECT SETTINGS 非普通 bridge 提供的隧道 API，MASQUE 外层是独立实现。见 [native 矩阵](../../native/README.md)、[Win 导出清单][win]、[POSIX 配置][quic-profile]、[应用补丁顺序][patch-order]、[Linux QUIC 补丁][quic-policy-linux]、[macOS QUIC 补丁][quic-policy-mac]、[Gecko H3 策略说明](../../native/patches/GECKO_H3_POLICY.md)及[原生交付](05-native-delivery.md)。

## 回归入口与待验证假设

| 修改区域 | 测试与验收 | 守住的观测 |
| --- | --- | --- |
| H1 回调/拷贝/关闭 | [`smoke_local.py`][smoke-h1] · [native buffer 单测][buffer-test] · [请求重试][retry-test] | 回环响应字节一致；越界/EOF 有区分；读到部分字节后输出有独立所有权；已送出的 POST 与可回卷显式重试按边界处理 |
| H2 启动、压力与停传 | [官方首航 fixtures](../firefox-h2-preface.md) · [窗口单测][h2-flow-test] · [`smoke_h2_flow.py`][h2-flow-smoke] · [`smoke_h2_early_response.py`][h2-early] · [`smoke_h2_close.py`][h2-eof] | 64 份保留/7 次加额、padding、晚到 DATA、取消后连接信用、SETTINGS 缩到 0 均有断言。12 MiB 大响应 A 在未读时耗尽自身窗口，B 在同连接另一流照常完成；随后排空与 SHA-256 校验。完整早响应连同 NO_ERROR 保留，提前/不完整 reset 报错；完整 END_STREAM 后立即 TLS EOF 仍可读，截断报错 |
| H3 owner、ABI 与结束 | [真实原生 H3][h3-native-test] · [ABI/跨线程与字节回显][h3-abi-test] · [413 矩阵][h3-413] · [POSIX QUIC policy smoke][h3-policy-test] | UDP-only GET/POST、严格证书失败、逐流 reset/timeout 后连接可用；binary 与强制 JSON 两模式的二进制 payload 同字节，binary 模式仍有 JSON 控制但 JSON body 调用为零；坏参数/跨线程结果明确；验证实际 QUIC 协商与 SETTINGS/接收限制 |

[Wheel 验收入口][wheel-ci] 在已安装发行形态运行上述 smoke/原生检查与 [request-boundaries][request-ci]，后者显式从源码树外导入安装包并运行 H2 flow/early-response 与 trust/buffer suites；[Linux floor 资格流程][floor-ci]另验证基线环境。图示和本文描述的是实现及这些验证入口，不将 fixture 的计划时间或图中顺序读成生产网络延迟。

下列是**优化假设**，未改变当前实现。按 [性能基准说明](../performance.md) 在相同机器、CPU 亲和、Python/依赖、已安装 wheel 上 A/B，验证正确性后再比较吞吐、CPU、峰值常驻内存及分位数：

| 假设 | 落地前闸门 |
| --- | --- |
| H1/TLS 减少 callback 边界的拷贝 | 先定位分配热点；要求明文和 TLS 响应的二进制字节、分段读、EOF、错误传播、排空/复用和 callback/内存生命周期全保持；量 RSS 与分配次数，不将 `memoryview` 本身称为零拷贝 |
| H2 按路径 BDP 重新分配流加额，或降低空闲探针 CPU | 同时量高 RTT 大对象与慢消费者共存，守住连接和流信用不超发、首航 SETTINGS/顺序、A 慢时 B 可进展、空闲 control frame/超时及时、取消后不退款两次，并对窗口预算变化写明新的上限 |
| H3 减少 FFI 调用或调整 write probe | 分别量 POSIX binary 与 Win JSON/Base64；先过 owner 约束、短写偏移/零写帧复用、两个 FIN 方向、STOP 后 413/no-final、reset/timeout 和认证及隧道退出；比较正常与拥塞/丢包后的 CPU 和推进，而非以更紧的循环换取测试分数 |

[dispatch]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1314-L1409
[body]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L683-L745
[tcp]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L862-L959
[tls-open]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L262-L328
[tls-io]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L330-L469
[h1]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L574-L637
[h1-io]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L639-L680
[socket]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L307-L375
[native-buffer]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_native_buffer.py#L6-L12
[pool]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L394-L481
[pool-release]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L527-L559
[coalesce]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L484-L525
[h2-init]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L41-L215
[h2-settings]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L149-L167
[h2-exchange]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L674-L777
[h2-submit]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L217-L275
[h2-flush]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L277-L313
[h2-data]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L381-L413
[h2-events]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L304-L440
[h2-commands]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L442-L549
[h2-worker]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L551-L668
[trust]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L234-L259
[h3-open]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L133-L215
[h3-route]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L961-L1066
[h3-run]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L513-L552
[h3-events]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L257-L320
[call]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L91-L107
[h3-submit]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L217-L252
[h3-io]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L321-L395
[h3-execute]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L397-L453
[h3-loop]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L455-L511
[h3-cleanup]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L553-L599
[h3-exchange]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L602-L683
[h3-reader]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L685-L753
[h3-abi]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L29-L88
[h3-abi-patch]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/patches/h3-body-abi-v1.patch#L26-L141
[h3-writable]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/patches/h3-body-abi-v1.patch#L5-L12
[h3-writable-mac]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/patches/h3-body-abi-v1.patch#L155-L164
[h3-handles]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/patches/macos-h3-global-handles.patch#L13-L41
[retry]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_retry.py#L38-L52
[421]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1068-L1165
[convert]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1410-L1451
[win]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/win_amd64/exports.json#L591-L615
[quic-profile]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L118-L132
[patch-order]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tools/posix_firefox161.py#L10-L53
[quic-policy-linux]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/patches/firefox-posix-quic-policy-linux.patch#L9-L54
[quic-policy-mac]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/native/patches/firefox-posix-quic-policy-macos.patch#L19-L87
[smoke-h1]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_local.py#L14-L41
[buffer-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_trust_and_buffers.py#L217-L227
[retry-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_retry_safety.py#L235-L277
[h2-flow-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_http2_flow.py#L78-L337
[h2-flow-smoke]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_h2_flow.py#L162-L337
[h2-early]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_h2_early_response.py#L38-L167
[h2-eof]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_h2_close.py#L18-L83
[h3-native-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_http3_native.py#L322-L489
[h3-abi-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_h3_body_abi.py#L174-L295
[h3-413]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_h3_body_abi.py#L394-L489
[h3-policy-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_posix_quic_policy.py#L185-L234
[wheel-ci]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/qualify_wheel.py#L61-L103
[request-ci]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/verify_request_boundaries.sh#L1-L18
[floor-ci]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/qualify_glibc231.py#L324-L350
