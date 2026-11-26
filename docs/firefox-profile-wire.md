# Firefox 159/160/161 配置与线路证据

`Session(firefox="160")`、`Session(firefox="161")` 和 `NECKO_FIREFOX=160` / `161` 选择对应配置；显式会话参数优先。默认仍为 `159`。Python 配置选择、原生库构建版本和网络实测是三个不同的验收项；原生版本及文件散列以 `runtime-manifest.json` 和 `native-provenance.json` 为准。

## Wheel 验收

在对应平台的 CPython 环境中安装本仓 wheel 和 `aioquic==1.3.0`，从源码目录之外使用该解释器执行：

```sh
python -I /absolute/path/to/ruyihttp/ci/smoke_firefox_profiles.py <slot> --output wire.jsonl
```

标准 wheel 资格验收会保存 `firefox-profile-wire.txt` 和 `firefox-profile-wire.jsonl`。五个目标各自对照官方 Firefox en-US 159.0、160.0、161.0 的原始线路样本。每个 slot 必须有完整的三个版本，且每个版本至少需要两个同平台、同架构原生浏览器样本；参考缺失或不完整时，验收立即失败。Apple Silicon 与 Intel 虽共享 Mozilla 的通用安装包，仍需要各自的原生进程和样本。

- H1 和 H2 使用顶层导航；逐项核对请求目标、实际协商的 ALPN、完整 UA、请求头名称和值的顺序、TCP ClientHello 选定字段，以及 H2 首个非 ACK SETTINGS 的实际顺序。[独立 H2 首帧门禁](firefox-h2-preface.md)使用同一次 wheel 连接观察首个连接 WINDOW_UPDATE、独立 PRIORITY 序列、首个请求 stream 及内联依赖/权重；服务端 SETTINGS ACK 的相对到达时序另行记录。
- H3 比较从已验证的 `https://localhost:<port>/boot` 发起的默认同源 Fetch。只映射实际回环端口，保留 Fetch Metadata、完整 `Referer` 路径、`Alt-Used`、伪头和普通请求头顺序。H1 引导响应发布 Alt-Svc，随后关闭 TCP 路径；HTTP/3 必须使用 UDP，且服务器独立观测 ClientHello、首次 Initial 版本、协商版本、选定传输参数与有序 SETTINGS。
- 捕获输出保留 TLS 扩展顺序：只有同 slot、版本和请求方式的官方样本实际出现排列变化时，才比较固定扩展及 GREASE 数量，并保持可证实的固定位置。实测确有稳定扩展的排列变化时，wheel 也必须在最多五次独立连接内出现至少两种合规排列，每次均需通过固定字段核对。固定字段的具体范围和加密随机量、协议环境边界见[参考格式](../ci/firefox_wire_references/README.md)。这些测试是结构化字段的线路对照，不是全网络指纹或报文散列。

## 来源规则与修复范围

- **UA 与本机 ABI 分开。** [Firefox 122](https://github.com/mozilla-firefox/firefox/blob/f16f94e4ec9404ae1cec1377a32c4812bbdbf0d3/netwerk/protocol/http/nsHttpHandler.cpp) 的桌面 Linux 分支使用 `uname`。[Firefox 123 稳定版的默认偏好](https://github.com/mozilla-firefox/firefox/blob/83a2fe4a63390103d1ea7cacb15be96451e923f5/modules/libpref/init/StaticPrefList.yaml#L11540-L11555)对 64 位 ARM 开启 `freezeCpu`。因此 100–122 的 Linux ARM64 配置保留 `aarch64`，123–161 发送 `x86_64`；ARM64 原生库选择从未变成 x86。159/160/161 三版另有签名浏览器的实测记录，早期分界依据的是发布源码，不是对每一版重跑浏览器。
- **协议选项不是修改观测值。** [Gecko 源码与 POSIX 补丁](../native/patches/GECKO_H3_POLICY.md)分别处理 Extended CONNECT、QUIC 版本偏好、实体流控窗口及原生 TLS。Firefox 161 冷连接实测 first Initial 为 v1、与支持 v2 的对端完成协商后使用 v2；只有 v1 的对端仍可正常协商。它并非无条件发送 v2。H3 对照保留源/目的 CID 长度和实际包号宽度，不保存 CID、包号和密钥的具体值。
- **H2 首帧也有单独证据。** [5 平台、3 版本、每版 2 个全新导航](firefox-h2-preface.md)捕获 SETTINGS、连接级 WINDOW_UPDATE、独立 PRIORITY 序列以及首次请求的 stream ID 和内联优先级。后续因大文件或慢读者产生的策略仍按[本仓流控说明](h2-flow-control.md)，不把首帧对齐推广到任意负载和时序。

## 对照与诊断

[`v0.9.2` 的历史 Linux ARM64 参考](../ci/firefox_wire_reference.json)曾省略 UA 的具体值，并把官方 H3 Fetch 与库的 H3 导航放在报告中并列；这个文件只能用于理解旧证据，不能用于新验收。新版保留原始捕获证据，也可对旧 wheel 或没有 fork manifest 的 PyPI 包运行独立采集：

```sh
python -I /absolute/path/to/ruyihttp/ci/smoke_firefox_profiles.py <slot> --collect --repeats 2 --output observed.jsonl
python -I /absolute/path/to/ruyihttp/ci/firefox_wire.py <slot> observed.jsonl
```

`--collect` 仅观测实际安装的 wheel；单个版本可用 `--release 161` 做定位，正式验收始终检查三个版本。旧日志可用 `ci/firefox_wire.py <slot> old-profile-wire.txt --legacy` 重放；H3 的导航上下文及未采集字段会明确报错，不能当作同源 Fetch 验收。
