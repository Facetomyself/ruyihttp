# 04 · 身份分三层：请求上下文、协议配置与证书信任

[返回架构导读](README.md) · [连接池与路由](01-request-routing.md) · [协议引擎](02-protocol-engines.md) · [MASQUE 双层握手](03-masque.md)

排查「像哪个 Firefox」「为什么这个 Cookie 没发」「由谁验证了这个域名」时，先写下三个值：**会话选中的 Firefox 版本、实际加载的原生槽、当前要证明的对端身份**。`firefox="161"` 是配置选择，不会下载 Firefox；`response.tls` 是源站传输信息，不是证书本身；经 MASQUE 再多一个独立的代理 TLS 对端。以下为 [v0.9.4 的实现快照][manifest]，不是完整浏览器的隐私策略说明。

## 1. 版本号如何落到线上

| 输入与门槛 | 消费点 | 维护时容易弄错的区别 |
|---|---|---|
| `Session(firefox=…)` → `NECKO_FIREFOX` → 默认 `159`；归一化后必须在 `100..161` | `firefox_version`、`Session.__init__`，适配器持有归一化结果 | `161.0`、`firefox-161` 都可选中 161；进程实际 NSS/Neqo 版本仍取平台库。[版本选择][choice] / [会话安装适配器][session] |
| OS 类与 CPU 槽 | `client_platform` 选指纹大类；`runtime_platform` 选 `linux_aarch64` 等；`_user_agent` 独立决定 UA 文本 | Apple Silicon 的公开 UA 仍是 Intel Mac；桌面 Linux ARM64 从 **Firefox 123** 起发送约简后的 `Linux x86_64`，但加载 ARM64 ELF。[映射源码][host] / [跨版本回归][ua-test] |
| HTTP 字段、Fetch Metadata、H2 SETTINGS 与优先级、H3 参数 | `_firefox.PROFILES` 按版本生成。H2 顺序是数据的一部分，不是无序字典；H3 在 Windows 保留上游 schema，POSIX 再加连接/双向流额度及版本化开关 | 同一输入不等于同一实现。`h3_connect` 与 WebTransport 分开，发送 SETTINGS 也不等于已建 CONNECT-UDP 隧道。[H2 初帧策略][settings] / [QUIC 的平台分叉][quic] / [MASQUE 路径](03-masque.md) |
| TCP/TLS 的 profile 集群 | `_tls_profiles.PLATFORM_PROFILES` → `_nss.native_profile` → `necko_tls_open_profile` | 159/160/161 在 TCP TLS 表中复用 `_P7`，但 UA、其他版本化行为、实际选库仍各自生效。`_Profile` 里的指针引用 `ctypes` 数组；`native._arrays` 把数组保活，不能在调用前只留下裸指针。[输入表][tls-table] / [结构与生命周期][ffi-profile] |
| 平台文件和四个数据摘要 | `runtime-manifest.json`、wheel 安装校验及 `_nss.configure_library` | `firefox-profile.json` 是历史记录；活动根集、根约束、PSL 是各自的文件。运行时的 NSS 版本守卫、打包时的逐文件 SHA 检查和正式浏览器对照是三项不同验证。[数据/槽清单][manifest] / [安装核验][installed] |

例如 161 的 POSIX `quic_profile` 给出 `max_data=25165824`、`max_stream_data_bidi_local=12582912`，即 24 / 12 MiB。这是 **QUIC 的配置输入**，不要当成 H2 的 12 MiB 连接窗口或 Python 进程 RSS 限额。观察报告还区分 QUIC 首个 Initial 版本与协商结果。直连实际覆盖 H1/H2 导航和 H3 同源 fetch；历史 100–158 配置主要有源码依据，而非完整的逐版本、逐平台浏览器抓包。[官方参考范围与动态字段](../firefox-profile-wire.md)

## 2. 请求头不是一个静态模板

`prepare_request` 先调用 Requests 生成 `PreparedRequest`，再补会话的 Firefox 字段和 Cookie；`send` 以及重定向认证钩子还会重算。`apply_headers` 第一次记录 `_firefox_explicit`，只重写其管理且未被标为显式的标准字段。因此要验证的是**准备后的请求和实际线序**，不是 `session.headers` 的快照。[准备阶段][prepared] / [重定向钩子][redirect] / [上下文算法][headers]

- `context="navigation"` 与 `"fetch"` 有各自的 `Accept`、目的类型、模式和优先级；`user_activation` 只影响相应导航的 `Sec-Fetch-User`。HTTPS、localhost、IP loopback 被视为可信目标；在明文非可信 URL，默认编码集合可缩至 `gzip, deflate`。显式业务头与自动推导的头要分开测。
- 参考 URL 来自 `document_url` 或已有 `Referer`。同源时自动 Referer 保留路径/查询、去掉片段和 URL 身份信息；跨源时只取 origin 加 `/`；HTTPS 降级则省略自动 Referer。`Origin` 的生成另看是否有参考、请求方法和 fetch 场景。**这只是 HTTP 请求元数据，不是实现浏览器 CORS、预检或 DOM。**
- `wire_headers` 将已知头按固定顺序放入映射，剩余字段接在后面；只有 H2 分支在这里加 `TE: trailers`。之后 H2/H3 Exchange 各自生成伪头、过滤逐跳字段并编码；仅看字典内容无法断言线序。[头顺序][wire-headers] / [最终分派][dispatch] / [H2 首帧证据](../firefox-h2-preface.md)

这个最小例子只做准备，**不会发网络请求**，可用于复现同站但跨源：

```python
from ruyihttp import Request, Session

with Session(firefox="161", context="fetch", document_url="https://app.example.co.uk/form?q=1") as s:
    s.trust_env = False
    p = s.prepare_request(Request("GET", "https://api.example.co.uk/items"))
    assert p.headers["Sec-Fetch-Site"] == "same-site"
    assert p.headers["Referer"] == "https://app.example.co.uk/"
    assert p.headers["Origin"] == "https://app.example.co.uk"
```

### Cookie 的两个判定时刻

`origin` 比较 scheme、规范化主机和有效端口；`site` 比较 `(scheme, 可注册 DNS 域或完整 IP)`，**不含端口**。DNS 使用 Public Suffix List（含私有后缀），IPv4/IPv6 不拿尾部标签做域归并。旧式数字 IPv4 能可靠解析则规范化；含歧义的数字串保留整串。`_SUFFIXES` 在模块加载时从随包 PSL 构建，缺文件时才走依赖的默认列表；这不是 TLS 材料缓存的逐次轮换模型。[数据搜索次序][data] / [IP、origin、site][site]

| 时刻 | 核心决定 | 改错时的可见现象 |
|---|---|---|
| 接收 `Set-Cookie` | 先过标准库基础策略，再拒收显式公共后缀 Domain、不合规 Secure、`__Secure-` / `__Host-`、无 Secure 的 `SameSite=None` | 设置动作就没成功；不能据下次请求缺头推断发生了网络丢包 |
| 准备发送 | 基础策略后才看 `document_url` 与目标的 schemeful site；跨站 Strict 拦下，Lax 默认值仅允许顶层安全方法导航，None 要求 Secure | 换端口可以跨 origin 又同 site；不同 IP 或两个 `github.io` 租户则不是同 site |
| 合并请求 Cookie | 对无 domain 的条目复制并绑定主机，然后安装当前策略；由库负责 Cookie 时重算自动头。显式提供的 Cookie 头和 jar 过滤不是同一条管道 | 测试应使用与真实来源一致的 `Set-Cookie`/jar，并区分调用者手写 Header |

[CookiePolicy 与 jar][cookies]；[DNS/IP/上下文矩阵][site-test]同时断言 Fetch Metadata 和实际上准备发送的 Cookie；[PSL 变化控制][root-test]用真实分区示例，而非假设最后两段域名总是同站。此处没有浏览器的 partitioned cookie jar。

## 3. 信任材料与活连接的寿命不同

![被验证源站的根、对端证书和握手决策](diagrams/trust-path.svg)

[交互图：查看每个节点的源码](diagrams/trust-path.html) · [可编辑图源](diagrams/trust-path.json)

从左向右读：一个输入是可信根与约束，另一个输入是本次对端主机与证书链；只有同时拥有二者才能验证。**缓存返回 `TrustMaterial`，绝不返回“这个域名通过”。** 图中不包含普通活连接复用，也不代指 MASQUE 代理的外层 TLS。

1. `Context(verify, cert, data_directory)` 选择来源。默认根是 `firefox-roots.pem` 并带相邻 `firefox-root-constraints.json`；调用者传入文件或目录则使用该信任集合和空约束。显式路径缺失时报错。发行数据为 **118** 个服务器根、一个受测试的截止约束、**10,463** 条 PSL 规则；这些数量必须与具体版本一起看。[Context][ctx] / [数据来源与数量][data-counts]
2. `TrustCache.load` 对解析后的路径、默认/自定义标记、目录排序后实际含 PEM 标记的文件内容，以及约束原始字节加长度前缀计算 SHA-256。即使 mtime 和大小不变，换根也会换 key。文件读、X.509 解析在锁外；命中更新 LRU，未命中生成 `Store`/只读约束后在锁内二次确认，允许并发首次重复解析但只收录一个对象。[读取与指纹][cache-key] / [插入、淘汰与 fork][cache-store]
3. 默认 LRU 上限是 **8 份、4 MiB 源材料**（不是 Store 的 RSS 上限）；单份太大则照常构建、走不入缓存的路径。约束 JSON 会校验指纹、截止日期和重复项；解析失败不会“借上一次好快照”。支持的平台在 fork 后清空此缓存并换锁，这一规则不等价于会话、活动 socket 和 worker 都可跨 fork 复用。
4. 对端链以 `4 字节大端长度 + DER` 拼接。`Context.verify` 区分 IP 与 IDNA DNS subject，调用 `PolicyBuilder().store(...).build_server_verifier(subject)` 验叶子与链，再取验证出的根指纹。命中内置约束时比较**叶证书 `notBefore`** 与截止时间，晚于才拒绝，不是把现时钟同截止时间比较。TLS 回调返回成功/失败并传回异常；H3 的原生 `auth` 命令显式反馈接受与否，`connected` 时尚未保存证书链还有相应检查。[验证分支][verify] / [TLS 回调][callback] / [H3 事件][h3-auth]
5. 客户端身份加载是另一条支路：为该 `Context` 解析证书和私钥、匹配公钥，私钥不进全局缓存。TCP/TLS 会话的恢复分区把 `peer`、信任/客户端证书标识和 Firefox 版本一起散列；成功调用原生 `open_profile` 后清空 `context.key` 引用。这不是对 Python 内存做物理擦除的承诺。已建立的连接仍使用其建立时的身份；紧急退役活连接与轮换根文件是两件事。[客户端身份][ctx] / [握手与恢复分区][resume] / [连接合并的二次证书检查][pool-cert]

### 三种 TLS 对端不要混用

| 对端 | 验证输入和主机 | 可观测结果 |
|---|---|---|
| 直接源站、普通代理隧道内的源站或 MASQUE 内层源站 | 原始目标主机 + 源站 `verify`；直接 Alt-Svc 即便连接另一端口/主机也保留原始身份 | `response.tls` 表示源站。H3 字段按各平台桥能力返回，以 manifest 为准。普通明文 HTTP 没有源站 TLS |
| 普通 HTTPS TCP 代理 | 先以代理主机建立一层 NSS TLS，使用此路径的 `verify`，外层禁用 H2；目标为 HTTPS 才发 CONNECT 并在隧道内再建源站 TLS。HTTP 目标直接在到代理的 TLS 中发送正向 HTTP 请求 | **不是** `proxy_verify` 配置的 MASQUE 外层；`https://` 代理地址不能仅因采用 TLS 就当作 UDP 代理。见[普通代理拨号][proxy-tls] |
| 显式 `masque://` 代理 | aioquic 对代理主机与证书链校验；`proxy_verify=True` 使用 certifi，也可提供独立 CA 文件；另以 OpenSSL 的 TLS server purpose 校验整条链。源站 CA/认证头不替代代理凭据 | `response.proxy_tls` 单独记录已协商的外层。此路径要求验证两层，暂不接源站客户端证书；见[代理 TLS 实现][masque-tls]和[双层原理](03-masque.md) |

## 4. 改动与定位顺序

| 症状或变更 | 第一个可区分原因的检查 | 复验入口 |
|---|---|---|
| 更新根/约束后仍访问旧连接 | 先区分池中旧连接 vs 新握手；核对实际 CA 路径、`REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` 的环境选择以及显式 `verify`。缓存 key 不依赖 mtime | [`test_trust_and_buffers.py`][cache-test]；[真实同路径换根][rotation] 强制前后新握手，旧根拒绝、新根通过 |
| 网站端 UA 看似 x64，目标是 ARM64 | 分别查 `runtime_platform()`、已安装原生库的机器类型、HTTP UA 和选择的 Firefox 主版本 | [`test_runtime.py`][ua-test]、[构建与发布](05-native-delivery.md)及每槽的官方控制 |
| 改 PSL 后 Cookie 或 Referer 异常 | 为一对 URL 同时列出 origin 与 site，检查显式头标记、上下文、方法，以及 cookie 是在存入还是发出阶段被拦 | [`test_cookie_site.py`][site-test]、[`test_upstream_trust_data.py`][root-test]；避免把 cookie domain-match 与同站性合并成一个谓词 |
| 增加一个 Firefox profile | 同时审 HTTP 字段、TLS 集群、H2 初帧/优先级、H3 QUIC 策略、各原生库可接收的 schema；跑相同平台的独立 H1/H2/H3 对端 | [Firefox wire 契约](../firefox-profile-wire.md)、[原生准入与发布](05-native-delivery.md)；TLS 的随机扩展排列不应被「固定排序后全等」掩盖 |

[manifest]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/runtime-manifest.json#L1-L36
[choice]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L228-L265
[session]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L42-L62
[host]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L45-L105
[settings]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L158-L167
[quic]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L118-L132
[tls-table]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_tls_profiles.py#L145-L164
[ffi-profile]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L58-L108
[installed]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/verify_installed.py#L38-L56
[prepared]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L64-L77
[redirect]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/sessions.py#L110-L148
[headers]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L359-L427
[wire-headers]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L430-L460
[dispatch]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L1325-L1366
[data]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L20-L42
[site]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L272-L345
[cookies]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_firefox.py#L463-L541
[site-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_cookie_site.py#L37-L95
[root-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_upstream_trust_data.py#L15-L71
[ctx]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L185-L232
[data-counts]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/docs/upstream-0.11.0-data.json#L15-L34
[cache-key]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_trust.py#L53-L93
[cache-store]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_trust.py#L95-L134
[verify]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L234-L259
[callback]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L381-L388
[h3-auth]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_http3.py#L265-L300
[resume]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_nss.py#L282-L328
[pool-cert]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L484-L525
[proxy-tls]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_transport.py#L893-L943
[masque-tls]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ruyihttp/_masque.py#L225-L289
[ua-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_runtime.py#L228-L337
[cache-test]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/tests/test_trust_and_buffers.py#L82-L214
[rotation]: https://github.com/Facetomyself/ruyihttp/blob/9e88bfe023fd46a96254f8de66e8d72517339911/ci/smoke_trust_rotation.py#L34-L64
