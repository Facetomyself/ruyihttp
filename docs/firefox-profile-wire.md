# Firefox 160/161 配置与线路证据

`Session(firefox="160")`、`Session(firefox="161")` 和 `NECKO_FIREFOX=160` / `161` 选择对应配置；显式会话参数优先。默认仍为 `159`。PyPI 上游 [0.11.0 Windows wheel](https://pypi.org/project/ruyihttp/0.11.0/#files) 的 Firefox 159/160/161 共用 `_P7`，九个非 UA HTTP/H2/H3 声明字段也与本仓 159 一致。这里的配置选择与 wheel 的原生构建版本是两个值：后者由 `runtime-manifest.json` 和 `native-provenance.json` 记录，读取原生版本并核对文件散列是独立验收。

## Wheel 验收

在对应平台安装本仓 wheel 以及 `aioquic==1.3.0`；从源码检出目录之外使用该解释器执行：

```sh
python -I /absolute/path/to/ruyihttp/ci/smoke_firefox_profiles.py <slot>
```

标准 wheel 资格验收自动运行此用例，记录 `firefox-profile-wire.txt`。每个配置分别建立新连接：

- TCP/TLS：服务器解析 H1 请求行、按顺序读取字段，解析 H2 pseudo-header、实际请求头和首个 SETTINGS。服务器捕获并解析 ClientHello，比较 cipher suites、supported groups、key share groups、签名与证书压缩算法、ALPN 等结构字段。
- UDP/QUIC：H2 响应发布 Alt-Svc，随后关闭 TCP 监听并在已建立的 H2 连接上发送 GOAWAY；下一请求必须来自 UDP。服务器记录 H3 字段、SETTINGS、协商 QUIC 版本和选定的客户端传输参数。响应还检查状态、正文、协议版本以及按 manifest 记录的原生遥测形状。Windows 历史桥的 H3 遥测字段较少，服务器观察独立于客户端标记。
- 160/161 与同一 wheel 的 159 对照比较；去除 UA 版本与回环端口，保留字段的顺序和固定值。ClientHello 比较跳过随机数、临时公钥内容和随机扩展顺序；QUIC 比较跳过连接 ID、GREASE 设置和包序号。TLS、QUIC 指纹全量一致并非验收条件。

## Mozilla 对照

[固定参考记录](../ci/firefox_wire_reference.json)来自 Mozilla 正式 en-US Linux ARM64 Firefox 159.0、160.0、161.0，归档 SHA-256 对照 Mozilla 同版本目录中的 `SHA256SUMS`。在 ARM64 Ubuntu 24.04 隔离环境运行浏览器和回环源站；H1/H2 使用独立的新浏览器配置和同一个测试 CA，两个监听端分别仅协商 `http/1.1` 和 `h2`。三个浏览器版本的 H1/H2 有序导航头（归一化 UA 与 authority）、H2 初始 SETTINGS 和归一化 TCP ClientHello 结构相同。

在该环境另用 Firefox 161.0，通过 HTTPS Alt-Svc 和同源 JavaScript fetch 观察到官方浏览器使用 ALPN `h3`、QUIC v2（`0x6b3343cf`）；浏览器配置允许本地测试 CA 的 H3。它与同机实测 fork wheel 的选定 QUIC 传输参数一致。浏览器发出了 `SETTINGS_ENABLE_CONNECT_PROTOCOL (8)=1`，该 wheel 未发送这一项；其余选定 H3 SETTINGS 相同。fetch 与库的导航上下文有别，H3 请求头分别记录，未作逐项匹配断言。

在 ARM64 上，官方这三个浏览器版本的约简 UA 使用 `X11; Linux x86_64`；本仓保留原有 `X11; Linux aarch64`。wheel 验收要求本仓宿主 UA 正确，同时在报告中明确显露这一差异。Linux ARM64 基线 wheel（NSS 3.132 / Neqo 0.33.0）实测 159/160/161 三套配置，全部通过 H1、H2、H3；这组对照限于已测字段和环境。其他原生 slot 的结论以各自安装后的验收结果为准。
