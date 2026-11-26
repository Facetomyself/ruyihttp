# RuyiHttp 实现与维护手册

**RuyiHttp 保留 Requests 的会话、请求和响应接口，替换的是实际搬运字节的传输层。** 一个 `HTTPAdapter` 决定可借哪条连接、何时允许另建或重试；具体协议的 `Exchange` 完成一笔事务；响应体 `_Body` 把流或连接的租约交回池。改动时先问「谁拥有这个状态、发生错误后谁负责释放」，再问「应该改哪个文件」。

**适用版本。** 本手册按 [源码 `9e88bfe`](https://github.com/Facetomyself/ruyihttp/tree/9e88bfe023fd46a96254f8de66e8d72517339911) 取证；与 [v0.9.4 发行提交 `74953f7`](https://github.com/Facetomyself/ruyihttp/releases/tag/v0.9.4) 相比仅首页 README 有变化，运行实现相同。下文分别标出源码行为、已有实测和优化提案。手册随后加入 `main`，既不会重写旧标签，也不是对将来版本的无条件承诺。

![RuyiHttp 出站架构：Session、租约和三类物理路径](diagrams/overview.svg)

[打开交互总图](diagrams/overview.html) · [可编辑的总图 JSON](diagrams/overview.json) · [七图核验清单](verification.json)

图上箭头是**出站方向**。左边到的是首个 TCP 对端：普通 HTTPS 代理外层用 H1，源站隧道内才可能协商 H2；右边的 Neqo 要么拨 Alt-Svc 的 UDP 端点，要么只碰本地回环 socket，由独立 aioquic 连接把内层 QUIC 送往代理。代理的 TLS 和源站的 TLS 在不同位置终止。返回路径和异常收尾见下列分图。GitHub 可直接看静态 SVG；交互版请在本地打开 HTML，或下载包含同目录全部 HTML 的项目快照。图中的节点可查看对应实现源码，明细图可以返回总览。

## 从你的问题开始

| 要回答的问题 | 读哪一章 | 可单独打开的交互图 |
|---|---|---|
| 为什么这一次复用了 H2、试了 H3、走了代理，或者没有重试？ | [01 · API、路由、连接池与重试](01-request-routing.md) | [路由与租约](diagrams/request-route.html) |
| 慢读者为什么没有堵死其他流？H3 的 native 句柄在哪个线程关闭？ | [02 · H1、H2、H3 协议引擎](02-protocol-engines.md) | [H2 的消费与信用](diagrams/h2-flow.html) · [H3 owner 的生命周期](diagrams/h3-owner.html) |
| 怎样证明 HTTP/3 确实经过 CONNECT-UDP？代理掉线或拒绝请求时发生什么？ | [03 · MASQUE 原理、双层握手与数据流](03-masque.md) | [隧道建立和双向转发](diagrams/masque-tunnel.html) |
| 为什么 URL 看起来相似而 Cookie 不同？切换 Firefox 配置或 CA 会改变什么？ | [04 · Firefox、Cookie、信任与握手身份](04-trust-profiles.md) | [材料缓存与证书判定](diagrams/trust-path.html) |
| 哪些原生库是重编的？新标签、安装成功、网络行为能否互相证明？ | [05 · 原生 ABI、平台准入与 wheel 发布](05-native-delivery.md) | [从源码到已验收工件](diagrams/native-delivery.html) |
| 先拆哪里、先测什么、什么情况下应该撤回优化？ | [06 · 源码热点与分阶段优化路线](06-maintenance-roadmap.md) | [运行包工作台](analysis/runtime.html) · [全仓工作台](analysis/repository.html) |
| 改实现后怎样更新图、审图、发现旧引用？ | [07 · 图文维护与证据刷新](07-keeping-current.md) | [固定范围与工件摘要](verification.json) |

## 走读：从 `get()` 到关闭流

1. **准备。** `api.get → api.request` 新建一个临时 `Session`；需要跨请求复用或记住 Alt-Svc 时使用显式的长期会话。`Session` 在 HTTP/HTTPS 两个前缀挂同一 `HTTPAdapter`。Requests 继续负责请求/响应的基础模型、重定向骨架和 hooks；本仓在 prepare、send、redirect 上应用 Firefox HTTP 上下文、Cookie 和强制代理规则。[公共函数][api] · [挂载和请求准备][session]
2. **借连接，不是先写业务数据。** `_send_once` 建立本次尝试的 `Attempt`，按路由与信任分区取池。`pool.acquire()` 返回现成连接，或以 `None` 表示**新拨号名额已经预留**。若候选来自另一池，要释放原预留、接手对方租约。直连的 Alt-Svc 竞争选的是先就绪的传输；强制 MASQUE 走独立分区，没有「借普通 TCP 凑一个 200」的路径。[选择分支与登记][choose]
3. **建立传输。** 常规 TCP 只解析首跳；HTTPS 时以目标主机名做 NSS 握手，根据 ALPN 分 H2 与 H1。直连 H3 的拨号地址可以是另一 Alt-Svc 端点，但证书主体仍为原始源站。MASQUE 则先通过另一层 H3 请求取得已认证的隧道，内层 Neqo 的 FD 只连专用回环对；源站名由代理处理。[TCP/SOCKS/CONNECT][tcp] · [H3、备选竞速与隧道工厂][h3]
4. **收发。** Adapter 用实际 `alpn` 创建 H1/H2/H3 `Exchange`，补齐/过滤请求字段，提交 header 和 body，再等最终响应头。H1 的同步 ctypes 回调使用连接；H2/H3 的调用线程将操作交给各自的连接 owner，`stream_id` 标识的是一条流，不是另一个连接。单流 `STOP_SENDING`/RST 和整条连接失败不能合并为一个“重试”。[Exchange 分派与上传][write] · [协议引擎](02-protocol-engines.md)
5. **响应与归还。** `_Body(exchange, pool)` 交给 `urllib3.HTTPResponse`，再包装成 Requests `Response`。源站信息在 `response.tls`；强制隧道另有 `response.proxy_tls`。调用者读完或关闭时，`_Body.close` 先询问可复用状态，再关闭 Exchange、归还租约。`stream=True` 若忘记关闭，外部看似响应已经返回，池/流/内存预留可能还占用。使用 `with session.get(..., stream=True) as r:` 或显式 `close()`。[响应装配][return] · [读取与关闭的真实次序][body]

### 不同协议由谁执行

| 选择条件 | 本机执行栈 | 下一跳／验证对象 |
|---|---|---|
| 普通 HTTP，或源站 TLS 未选 H2 且未使用 H3 | Python `_Exchange` → `necko_exchange_*`；明文用 `_NativeSocket`，HTTPS 套 `_nss.TLS` | 直连 TCP 源站，或所配置的第一跳代理；普通代理是否发 CONNECT 取决于目标是否 HTTPS |
| 已协商源站 H2 | Python `hyper-h2` + 专用 worker，通过 NSS 的非阻塞 I/O 通向 TCP | H2 是源站协议，不是指 HTTPS 代理外层协商了 H2 |
| HTTPS 直连且有可用 H3 租约，或合资格的 Alt-Svc 备选取得连接 | Python owner → `necko_quic_call` / 正文 ABI → 原生 Neqo/NSS | 直连 UDP 备选端点，验证原始源站；TCP 可参与**连接就绪**竞速，不复制当前业务请求 |
| 显式 `masque://`，目标 HTTPS，双方要求验证 | 同一内层 Neqo/NSS；另一个 worker 运行 aioquic 外层 H3 | 外层 UDP 连接代理、内层验证源站；本地回环不是源站地址。仅实现单跳且外层须协商 QUIC DATAGRAM |

## 文件地图：从接口走到所有者

这里按职责覆盖运行包的 **17 个 Python 模块**。默认部署是同一进程内的库；这些文件不是十七个服务，也没有外置连接池或数据库。

| 层 | 入口文件和符号 | 改它会影响什么 |
|---|---|---|
| 公共表面 | [`__init__.py`](../../ruyihttp/__init__.py)、[`api.py`](../../ruyihttp/api.py)、[`adapters.py`](../../ruyihttp/adapters.py)、[`sessions.py`](../../ruyihttp/sessions.py) | Requests 类型/异常重导出、短会话与长会话、代理合并与重定向。`adapters.py` 是公开别名，主要实现不在那里 |
| 策略和所有权 | [`_transport.py`](../../ruyihttp/_transport.py) 的 `HTTPAdapter`、`_Pool`、`_Exchange`、`_Body`、`HeaderMap`；[`_retry.py`](../../ruyihttp/_retry.py) 的 `restartable` | 路由、借还、协议选择、保留重复头、是否可重放。默认 `max_retries=0` 不等于禁掉所有协议层的「明确未处理」路径 |
| 名字与拨号 | [`_connect.py`](../../ruyihttp/_connect.py) 的 `Attempt / resolve_addresses / connect_tcp / race`、[`_socks.py`](../../ruyihttp/_socks.py) 的 `negotiate` | 首跳 DNS、地址族调度、取消和剩余预算；远端解析模式不可悄悄变成本地源站查询 |
| H2 / H3 | [`_http2.py`](../../ruyihttp/_http2.py) 和 [`_http3.py`](../../ruyihttp/_http3.py) 的 `Connection / Exchange` | 前者持有 hyper-h2 协议状态和流控；后者拥有原生 QUIC 句柄、定时器及二进制/JSON 正文协商。`_Call` 同名不代表通用状态机 |
| 强制隧道 | [`_masque.py`](../../ruyihttp/_masque.py) 的 `open_tunnel / Tunnel / _Relay`；[`_masque_codec.py`](../../ruyihttp/_masque_codec.py) | 外层代理发现、TLS、CONNECT/MTU、关闭；authority/URI 模板、上下文与 capsule 解码。`aioquic` 是这个可选外层的依赖，不是直连源站的 H3 栈 |
| 身份与字节 | [`_firefox.py`](../../ruyihttp/_firefox.py)、[`_tls_profiles.py`](../../ruyihttp/_tls_profiles.py)、[`_nss.py`](../../ruyihttp/_nss.py)、[`_trust.py`](../../ruyihttp/_trust.py)、[`_native_buffer.py`](../../ruyihttp/_native_buffer.py) | 请求语义/线序、TLS 输入表、ctypes 结构和回调、根材料 LRU、从原生缓冲复制实际长度。逐对端验证与共享只读根材料分层 |

包外再分三类：`native/<slot>/` 是可装载库和来源凭证，`native/patches/` 是本仓维护的 donor 适配（不是整套原生引擎源码）；`tools/`、`setup.py` 负责编译输入校验、准入、选槽与打包；`ci/`、`tests/`、`benchmarks/` 分别提供安装后的独立协议对端、可重复的契约回归和固定负载测量。见[交付章](05-native-delivery.md)。

## 对象的寿命和锁的作用域

| 对象 / 写者 | 保护的内容 | 结束或回收时刻 |
|---|---|---|
| `HTTPAdapter` 的 `_lock`、`_token_lock` | adapter 级池集合、备选/冷却记录、独立的 QUIC 恢复记录；随机 TLS 分区区分适配器 | 会话关闭清理其池；反序列化重新初始化这些运行态，不序列化活连接。[构造和重建][adapter] |
| 一个 `_Pool` 的 `Condition` | `leased`、新拨号 `connecting`、H1 `idle` 和 H2/H3 `shared` 计数；这是**分区内**的租约管理 | `register` 将预留变为连接；`release` 或失败路径归还。`pool_maxsize` 在默认非阻塞模式不是进程级硬连接上限。[池][pool] |
| H2/H3 每连接 owner | 一个协议状态机/句柄、流表、命令队列及完成信号；调用者可以等待，不在别的线程直接操作原生 H3 句柄 | 连接退出需要使等待者醒来；还要区分完整但未消费的响应和截断。H3 隧道另有外层 worker；它终止不等于源站确认没有收到业务请求。[H2 owner][h2-owner] / [H3 owner][h3-owner] |
| 进程的 `TrustCache` 与每次 `Context` | 共享可只读复用的 Store、约束和内容标识；主机、叶证书决策、客户端身份不在该共享缓存 | 换根的**新**握手重读输入。活连接退役由池/调用者处理，不是修改文件就能中断。[信任图与不变量](04-trust-profiles.md) |

## 修改前如何选证据

- **看代码能证明所有权，不证明网络已走该路线。** 校验 `raw.version==30` 时，同时看外层 CONNECT 与代理出口、源站是否收到同一组 UDP 流量；仅打印 ALPN 或 SETTINGS 不够。
- **看测试结果先问对象是谁。** 源码布局的“默认库应缺失”诊断与安装态的“必须装载包内库”是反方向的检查。打包器的 SHA/导出、最低系统真实安装和协议事务也不能互换。[实际发布资格报告](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/qualification.json)记录五个 wheel × 两个现代 CPython 端点及额外四个 glibc 2.31 端点；本手册没有重新发布这些字节。
- **找重构入口先读有限视图。** [仅运行包分析](analysis/runtime.html)适合看导入关系、函数复杂度和源码位置；[全仓分析](analysis/repository.html)同时包含 CI/基准的白盒观察。两者都不是网络跟踪、漏洞报告或性能剖析。优先项与不做的事分别列在[优化章](06-maintenance-roadmap.md)。
- **图和代码一起审。** 每张图附近都有 SVG、可离线运行的 HTML 和可改的 JSON。按[维护章](07-keeping-current.md)重生并校验；[生成物说明](notices.md)标明阅读器来源。保持分图 HTML 同目录，概览下钻、父图回链才有效。

[api]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/api.py#L8-L20
[session]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L42-L77
[choose]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1233-L1297
[tcp]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L862-L950
[h3]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L989-L1066
[write]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1336-L1386
[return]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1384-L1409
[body]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L683-L745
[adapter]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L772-L827
[pool]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L394-L460
[h2-owner]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http2.py#L195-L230
[h3-owner]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L157-L206
