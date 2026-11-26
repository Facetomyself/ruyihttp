# 06 · 架构诊断与优化路线

[架构导读](README.md) · [运行包分析工作台](analysis/runtime.html) · [全仓分析工作台](analysis/repository.html) · [机器可读测量](analysis/metrics.json) · [如何刷新](07-keeping-current.md)

**建议先给路由和租约的失败边界加测试，再拆 `HTTPAdapter._send_once`。先别改 QUIC 引擎或增大所有流的窗口。** 前者有源码集中度和真实分支作为证据；后两者的收益取决于负载，失误却会影响协议身份、内存上限或副作用请求。以下是维护方案，不是已实现的改动或已证实的性能缺陷。

## 1. 两次静态分析究竟测了什么

对同一个干净检出 [`9e88bfe`](https://github.com/Facetomyself/ruyihttp/commit/9e88bfe023fd46a96254f8de66e8d72517339911) 分别运行 Archify 3.3.2 `code-analysis prepare`，选择 Python / Pyright parser `1.1.414`、3.14 语法。该检出比被发行的 v0.9.4 仅多 README 更新。取样是**干净工作树快照**；静态工作台的「源码」是当时采集的文本，不会随着 `main` 漂移。

| 分析范围 | 已解析 Python 文件 | 按角色排除 | 模块 / 聚合导入边 | 提示：错误 / 警告 / 信息 | 本次生成耗时 |
|---|---:|---:|---:|---:|---:|
| [全仓](analysis/repository.html)，包括工具、CI、基准 | 64 | 30 | 5 / 2 | 0 / 30 / 59 | 16.87 s |
| [仅 `ruyihttp/`](analysis/runtime.html)，按文件看运行包 | 17 | 0 | 17 / 30 | 0 / 13 / 22 | 9.95 s |

分组粒度不同，**不能用 2 与 30 判断跨层调用次数**。两个样本均无 Python 解析错误；分别有 970 / 160 条 `external` 引用，不是 970 / 160 个故障。执行了六条静态规则，包括导入环、模块环、耦合与函数复杂度；未报告导入环，不代表不存在运行时回调环、竞争或死锁。未配置架构分层规则和重复检测；全仓识别出另一种语言 Go 的一个文件，未用 Go 适配器分析。`ctypes` 绑定、预编译库内部、Rust/C++ 补丁意图、协议协商和网络时序不能从 Python import graph 推导。工作台的 Atlas、源码证据和任务复制入口可用来找下一处阅读位置，不能取代线路证明。仓库中只将机器绝对路径的重查命令改成从仓根执行；采集内容和诊断保留。

### 最值得阅读的三处

| 实际位置 | 观察值（包内口径） | 分支出现在什么责任边界 |
|---|---|---|
| [`HTTPAdapter._send_once`][once] | 270 行、圈复杂度 97、最大嵌套 6；所在文件 1,588 行，3 个本包模块导入它，它依赖 9 个本包模块 | 校验 URL/信任、建立单次预算、借/转租约、候选竞争、协议派发、响应包装和异常清理在一个函数中交接。复杂度最大的嵌套在新路由与跨池租约判定附近，不是上传字节数最大的地方 |
| [`_http2.Connection._execute`][h2-exec] / [`_run`][h2-loop] | 分别为 100 行／圈复杂度 42、112 行／40；`receive` 为 110 行／35 | 单一 owner 要同时服从对端并发上限、本地内存预留、发送窗口和取消。将一个方法拆成多个类若破坏相同 owner，反而引入并发问题 |
| [`_http3.Connection._event_batch`][h3-events] 与 [`_masque._Relay.run`][relay] | 前者 81 行／圈复杂度 32；后者 51 行／最大嵌套 7 | 前者处理源站认证、连接状态和逐流事件；后者控制另一个 QUIC 引擎和两只 socket 的外层 I/O。路径相关，但不是重复的同一个事件循环 |

全仓另有一条 `coupling/internal-leak`：`benchmarks` 与 `ci` 合计 10 处导入六个包内私有模块。例如 [MASQUE 见证](https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_masque.py#L725-L772) 要计真正的 ABI 读写并截获本地源站解析，[正文计数器][h3-bench]要区分 native 接受的字节与 JSON 帧。它们是有意的**白盒测量**，不是十处都该对外公开的 API。重命名私有方法时同步核对测量者，并保留独立 UDP 源站／Go 对端的黑盒验证。

## 2. 动态证据：哪些数可以当对照

[同机成对回环运行 45810150980](https://github.com/Facetomyself/ruyihttp/actions/runs/45810150980)在 AArch64、单 CPU 亲和性、glibc 2.39、CPython 3.12.16 上比较 v0.9.4 实现与固定 v0.9.3。两只基准 wheel 从相应源码打包；这是**直连基准**，不是 Release 附件的相同 ZIP 摘要，也不是代理吞吐测量。更换 CPU、RTT、证书集合或 Python 版本后，必须先重建对照。

| 同一轮 0.9.4 观察 | 可用来发现的回退 | 不可由此推出 |
|---|---|---|
| 256 KiB 温连接下载、64 KiB 读块，18 次；H1/H2/H3 p50 各 **1.67 / 3.36 / 14.04 ms** | 同协议、相同代码路径的前后对比，需保留正文摘要与连接 ID | 某协议在公网一定最快，或 H3 花的时间都是 Python 热点 |
| H2 留下大流不读，源站送入 **655,360 B** 后仍有 **32/32** 个小请求完成，p95 **1.6118 ms** | 慢读者是否占住连接信用、调度改动是否拖累旁路小流 | 655,360 B 是整个进程 RSS 限额；所有流都应改成该窗口 |
| 4 条空闲 H2 连接约 **98.7 次 pending 探测/s**；新默认信任材料构造 p50 **0.1777 ms** | 唤醒/探测成本与热材料构造是否变化 | 100 次探测就是 CPU 满载；缓存已经替代了叶证书验证 |
| POSIX 1 MiB H3 上传，binary body ABI 1；单位有效字节对应 JSON 正文帧字节为 **0** | 是否悄悄退回 JSON/Base64 正文路径；结合 accepted bytes 判断短写 | 全程零拷贝，或网络上没有 QUIC、TLS、HTTP 控制开销 |

完整样本还包括一个反例：H2 新会话小请求、fixture CA 的候选 p50 为 55.00 ms，候选/旧版约 **1.14**，而温连接 H2 大响应的同口径比值约 **0.97**。单轮共享 runner 不能解释因果；不要只挑较快的场景。见[基准命令与方法](../performance.md)和[独立回环源站](../../benchmarks/_origin.py)。

## 3. 建议的实施顺序与回退条件

### 第一阶段：先锁定行为，再分离路由与所有权（高价值，成本中）

1. **先补一条有鉴别力的合并连接 421 用例。** 源码只在 `response.status_code == 421`、连接标记为跨池合并、协议重试尚有余额时，才记录该 `transport + hostname` 拒绝表、关闭当前响应并重试。以同一个证书覆盖两个测试 authority，记录连接号和每次的 Host；同一对端再用非合并租约作反例，检查 421 不会被这条专用规则处理。另测不可回卷的请求体：第二次写入前停止。此处是**新增覆盖提案**，不要把既有 GOAWAY、一般 retry 或同主机复用的测试当作 421 证明。[421 分支][retry-421]、[已有重放边界测试][retry-tests]。
2. **先提取纯数据，再提取具有副作用的代码。** 第一笔变更只提取 `PreparedRequest + 目标 + 代理选项 → 路由键与约束`，后者先作为私有值对象；对照代理 CA 与源站 CA、显式模板、非默认端口和 `http1/http3` 条件。第二笔才提取“取得/登记/转交租约”；不要把 `pool.acquire() == None` 当无事发生：它已经拿了拨号预留。`_BorrowedConnection` 换池时要释放原预留。最后才把 Exchange 构造和响应包装分出去。[分区与借用][leases]、[响应接管及异常归还][return-lease]。
3. **验收门槛。** 借用、失败、超时、用户中断、池关闭和重定向每条路径都检查归还次数、源站请求次数、旧/新 route key、是否触发源站 DNS。TLS 验失败、已有响应字节或可能已发送的 POST 不得因为拆方法而多发一次；显式调用者 `Retry` 与内部协议重启保持独立。保留 Alt-Svc 的获胜条件是连接就绪、不是同时发两份业务请求。[现有路由控制](../../tests/test_masque_routing.py)、[预算控制](../../tests/test_connection_budget.py)、[原生 Alt-Svc 控制](../../tests/test_alt_svc_native.py)。只降低复杂度数字却改变这些观察的提交应回退。

### 第二阶段：H2 背压和 CPU 需要两套指标（有真实负载再调参）

- **可先做的低风险拆分：** 把「已读/已丢弃的字节如何归还连接信用」和「一个 stream 是否可增窗」分成可单测的记账操作，所有实际 `hyper-h2` 变更仍由原 owner 执行。将 payload、padding、RST 后迟到的 DATA、已结束未读和读后关闭分别建例，验证连接与流信用守恒。有序首帧、默认 SETTINGS 及其对照不能被“优化”改掉。[流控不变量](../h2-flow-control.md)、[消费与归还][h2-exec]。
- **需先证实价值的实验：** `necko_tls_pending` 是非阻塞探测，不是可直接交给 `select()` 的 fd。保持当前主动 1–8 ms／被动 5–40 ms 的实现作为控制，在空闲连接、活跃上传、未读大流三类负载同时测探测次数、进程 CPU、快流 p95、首个可读数据时延。若要引入可等待的 native 通知，应走**可选新 ABI**，老库继续旧路径，并能被命令/close 唤醒。不要把裸 TCP 可读当成“嵌套 TLS 一定能读出应用数据”。[owner 调度][h2-loop]、[背压与 EOF 线路控制](../../ci/smoke_h2_flow.py)、[完整/截断响应控制](../../ci/smoke_h2_close.py)。
- **回退条件：** 旁路小流不能全部完成、收尾/EOF 语义变化、提高内存预留，或仅用高延迟/高 RSS 换来更低空闲 CPU。若目标是高 RTT 单流，请另做受控 RTT/丢包对照，保持 `64×128 KiB + 7×512 KiB` 组合预算能被解释；不要把本地 32/32 的成绩外推到 WAN。

### 第三阶段：减少有证据的拷贝，并约束外层依赖升级（分别提交）

| 提案 | 从哪里切入 | 如何判定是否值得合并 |
|---|---|---|
| 大响应的 Python 分配／拷贝 | `_Body.readinto` 当前走 `read(len(buffer))` 再复制；H3 v1 的 native read 先写临时缓冲，再返回有独立所有权的 `bytes`。可先测量特定消费方式，再试只在 owner 上复用 scratch buffer；新数据面能力按导出和版本协商，保留 JSON 路径 | 同一响应内容、4 KiB/64 KiB 两种读块，采 CPU ms/MiB、峰值分配、吞吐与 SSL/QUIC 错误；短写、空块、FIN、早停、调用者在下次 read 后仍可读到之前字节。跨线程指针、过长 native count 或数据别名造成结果变动即撤回。[读口与关闭][body]、[v1 边界][abi]、[正文 ABI 双路径试验](../../tests/test_h3_body_abi.py) |
| 将 MASQUE 对 aioquic 1.3 私有接口的依赖集中到窄适配面 | 外层额外保存 peer UDP 上限、为 PMTU 探测关联确认、处理 GOAWAY/1xx，并校验 TLS 链用途。先把依赖的字段/语义列成契约矩阵，再尝试升级版本；不是简单放宽依赖上限 | 在升级前后运行 22 个固定出口场景和独立 Go 对端。保留双层错误证书、拒绝 CONNECT、MTU 边界、取消后停止发送、同一 POST 计数及无源站 DNS/TCP。另看 CPU、丢包和隧道建立耗时；只靠 HTTP 200 或 ALPN `h3` 不算通过。[外层 TLS/传输参数][outer-interop]、[MTU 关联逻辑][mtu]、[互操作](03-masque.md) |
| 降低并发冷启动时根材料的重复解析 | 已有锁外解析、锁内二次确认，竞态会重复解析、不会重复留存。先记录并发首次构造与稳态命中；若解析确实成为瓶颈，可在**相同内容摘要**上合并进行中的解析并妥善传播失败 | 同路径、同长度、同 mtime 换根也要被发现；坏约束、删除 CA、不同主机、不同客户端身份继续正确拒绝/隔离；fork 后没有继承住锁。热态 p50 已很小，测不到实际收益就保留现状。不要改成仅用 stat 或跨主机缓存验证通过。[信任缓存][trust-cache]、[回环换根控制](../../ci/smoke_trust_rotation.py) |

### 不应混进上述 PR 的功能

仅 capsule 的外层、HTTP/2 外层 CONNECT-UDP、多跳 MASQUE、完整浏览器状态机、新平台/更低 glibc 或 macOS 下限都是**能力扩展**，不是这次性能重构的副产品。每项都应有单独接口选择、拒绝行为、资源预算和真实对端/最低系统。特别是强制 `masque://` 从出生起就是独立路由，能力缺失时不可悄悄改为直连。

## 4. 维护者的实验模板

| PR 里记录 | 一个可检查的答案 |
|---|---|
| 版本和输入 | 源码 SHA、wheel SHA、OS/CPU/Python、对应 native provenance、信任材料和对端；与基线保持一致 |
| 要改变的一个机制 | 例如“减少 `_Body.readinto` 的一次中间复制”；写明绝不改变的对端、API 结果、谁拥有缓冲和谁关闭连接 |
| 正例与反例 | 正例返回正确字节与协议；故障时记录 *是否真的向源站写过*。对 H2/H3 同时测 FIN、RST、STOP、消费者放弃和并发。单元断言与独立对端计数分别留证 |
| 取样与停止标准 | 冷/热分开；以同一连接 ID、ALPN 和正文 SHA 过滤错误样本；先看可重复的 CPU/时延/内存变化，再讨论取舍。故障观察改变即停止；大数字只在共享 runner 出现一次不能宣布提速 |
| 发布前 | 运行 [请求边界脚本](../../ci/verify_request_boundaries.sh)、[安装态控制](../../ci/qualify_wheel.py)；涉及原生、信任、线路配置时，按[发布章](05-native-delivery.md)复跑对应平台。更新受影响图源、固定源码引用和证据，而不是手改 SVG |

[once]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1182-L1451
[h2-exec]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L450-L549
[h2-loop]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L551-L662
[h3-events]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L265-L345
[relay]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L729-L779
[h3-bench]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/benchmarks/transport.py#L178-L229
[retry-421]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1149-L1165
[retry-tests]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_retry_safety.py#L38-L85
[leases]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1233-L1297
[return-lease]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1384-L1433
[body]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L683-L745
[abi]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L37-L88
[outer-interop]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L220-L291
[mtu]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L505-L553
[trust-cache]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_trust.py#L63-L134
