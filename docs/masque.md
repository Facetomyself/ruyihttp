# 通过 MASQUE 代理访问 HTTP/3 源站

从独立维护版 **0.9.4** 起，`masque://` 明确要求使用一个 [RFC 9298 CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298#section-3.4) 代理。它和普通的 `http://` / `https://` TCP CONNECT、SOCKS、或两跳 TCP 代理部署是三种不同的路径。无需源站先发 `Alt-Svc`；该显式路由要求源站在目标端口直接接受 UDP HTTP/3。

```text
RuyiHttp：内层 Neqo + NSS，与源站完成 TLS / H3
  ↕ 内层 QUIC 数据包（原生库只连接私有的、双方已连接的回环 UDP socket 对）
可选 aioquic 外层：验证代理证书、打开 H3 CONNECT-UDP、传输 HTTP Datagrams
  ↕ QUIC / UDP
MASQUE 代理：按 CONNECT 的目标转发 UDP ←→ 源站
```

## 使用

从本仓 checkout 安装 `python -m pip install '.[masque]'`，或从本仓 `0.9.4` 交付目录安装对应平台的 wheel，例如：

```sh
python -m pip install --upgrade './ruyihttp-0.9.4-py3-none-manylinux_2_31_x86_64.whl[masque]'
```

随后使用实际配置的代理和支持 H3 的 HTTPS 源站；下面的主机名用于示例：

```python
import ruyihttp

with ruyihttp.Session(firefox="161", verify=True, proxy_verify=True,
                      timeout=(8, 20)) as session:
    session.trust_env = False
    session.proxies["https"] = "masque://relay.example:443"
    response = session.get("https://origin.example/document")
    response.raise_for_status()
    assert response.raw.version == 30 and response.tls["alpn"] == "h3"
    print(response.proxy_tls["protocol"], response.proxy_tls["datagram_mode"])
    # connect-udp quic
```

也可在单次请求中传入 `proxies={"https": "masque://relay.example:443"}`。`proxy_verify` 指定外层代理 CA：`True` 使用 aioquic 的 certifi 根集，也可传入自己的 PEM CA 文件路径。`verify` 指定内层源站 CA：`True` 使用本仓 Firefox 根集，可指定不同的 CA 路径。两层分别检查证书和主机名，代理证书还校验整条链的 TLS 服务端用途。两层都要求验证；当前内层 H3 路径不接收 `cert=` 客户端证书。`response.tls` 始终描述源站；`response.proxy_tls` 描述已验证的代理协商结果（`alpn`、`protocol`、`datagram_mode` 和路径载荷预算等）。外层 aioquic 并非浏览器 NSS 指纹；不会把它计作直连 Firefox 的对照样本。

代理 URL 只放 authority，默认目标路径为 `/.well-known/masque/udp/{target_host}/{target_port}/`。自定义服务可在 `Session` 构造器设置 `masque_path_template="/relay/udp?host={target_host}&port={target_port}"`。这里只支持两个简单变量和固定的路径/查询；目标域名按 IDNA 规范化，IPv6 字面量按 URI 模板编码，例如 `::1` 变为 `%3A%3A1`。可在代理 URL 里使用 percent-encoded Basic 用户名/口令；该凭据仅进入外层 CONNECT，源站 Authorization/Cookie 不被复制到代理请求。

## 路由与互操作边界

- **只解析代理地址。** CONNECT 请求内传递目的主机/端口，本机不为这条路由解析源站或打开直连源站的 socket。隧道可承载同源的并发内层 H3 请求并复用；不同代理凭据、代理 CA、目标、路径模板分别隔离。一次经 MASQUE 的重定向不能悄悄离开该代理；明文 HTTP、代理鉴权失败、证书错误、UDP 不通均不会改走直连或 TCP 重发。
- 外层需要 `h3`、`SETTINGS_ENABLE_CONNECT_PROTOCOL=1`、`SETTINGS_H3_DATAGRAM=1` 和可用的 QUIC DATAGRAM。CONNECT 使用 `:protocol=connect-udp`、代理 authority、`https` 和展开的目标路径，发送 `Capsule-Protocol: ?1`；只有符合协议的最终 2xx 才开放 UDP。中间 1xx 不是成功，407 也不是源站响应。按 [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) 处理流关联和上下文：本版转发 Context ID 0，跳过未知上下文/胶囊；接收路径也支持相应连接上的 DATAGRAM capsule。**仅支持 capsule 传输的代理、HTTP/2 外层 CONNECT-UDP、CONNECT-IP 和多个 MASQUE 代理串联，不在本版范围内。**
- 建立时在同一个 connect 预算内，用受保护的 PING/ACK 测量**客户端到代理**的 UDP 载荷预算；较大探测未被确认时有界回落（上限 1400 字节，保守下界 1298），须容纳原生 1252 字节 Initial 后才发送 CONNECT。受限接收队列满或数据包超限时保留 UDP 的丢包语义，不把包拆散或无限缓冲。此初始测量不是双向 MTU 保证，也不意味着支持路径迁移或持续重探测。

## 复验

从 checkout 以外用已安装 wheel 的解释器运行：

```sh
python -I /path/to/ruyihttp/ci/smoke_masque.py --json-output masque-wire.json
```

[独立固定出口夹具](../ci/smoke_masque.py)使用两个独立 CA、仅提供 UDP 的测试源站、TCP 陷阱和拒绝其他来源的 UDP 入口。它对比接收数据包来源、数据包序列与摘要、256 KiB GET/POST 回显、请求次数、并发与关闭，并包括两层错误证书、407/403/502、缺能力、MTU/上下文、断链、无响应 POST、IPv6 源站、模板以及禁止走其他路由的重定向。可另用[受限的 Go 互操作夹具](../ci/masque_interop/main.go)与 `ci/smoke_masque_go.py` 对照 `masque-go v0.6.0 / quic-go v0.63.0`。Go 仅为验证对端，用户安装客户端无需 Go。该测试代理只接受测试时预先指定的单个回环 UDP socket，不是可部署的通用代理。
