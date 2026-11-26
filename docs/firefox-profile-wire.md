# Firefox 159/160/161 配置与线路证据

`Session(firefox="160")`、`Session(firefox="161")` 和 `NECKO_FIREFOX=160` / `161` 选择对应配置；显式会话参数优先。默认仍为 `159`。Python 配置选择、原生库构建版本和网络实测是三个不同的验收项；原生版本及文件散列以 `runtime-manifest.json` 和 `native-provenance.json` 为准。

## Wheel 验收

在对应平台的 CPython 环境中安装本仓 wheel 和 `aioquic==1.3.0`，从源码目录之外使用该解释器执行：

```sh
python -I /absolute/path/to/ruyihttp/ci/smoke_firefox_profiles.py <slot> --output wire.jsonl
```

标准 wheel 资格验收会保存 `firefox-profile-wire.txt` 和 `firefox-profile-wire.jsonl`。五个目标各自对照官方 Firefox en-US 159.0、160.0、161.0 的原始线路样本。每个 slot 必须有完整的三个版本，且每个版本至少需要两个同平台、同架构原生浏览器样本；参考缺失或不完整时，验收立即失败。Apple Silicon 与 Intel 虽共享 Mozilla 的通用安装包，仍需要各自的原生进程和样本。

- H1 和 H2 使用顶层导航；逐项核对请求目标、实际协商的 ALPN、完整 UA、请求头名称和值的顺序、TCP ClientHello 选定字段，以及 H2 首个非 ACK SETTINGS 的实际顺序。
- H3 比较从已验证的 `https://localhost:<port>/boot` 发起的默认同源 Fetch。只映射实际回环端口，保留 Fetch Metadata、完整 `Referer` 路径、`Alt-Used`、伪头和普通请求头顺序。H2 引导响应发布 Alt-Svc，随后关闭 TCP 路径；HTTP/3 必须使用 UDP，且服务器独立观测 ClientHello、首次 Initial 版本、协商版本、选定传输参数与有序 SETTINGS。
- 捕获输出保留 TLS 扩展顺序：只有同 slot、版本和请求方式的官方样本实际出现排列变化时，才比较固定扩展及 GREASE 数量，并保持可证实的固定位置。固定字段的具体范围和加密随机量、协议环境边界见[参考格式](../ci/firefox_wire_references/README.md)。这些测试是结构化字段的线路对照，不是全网络指纹或报文散列。

## 对照与诊断

[`v0.9.2` 的历史 Linux ARM64 参考](../ci/firefox_wire_reference.json)曾省略 UA 的具体值，并把官方 H3 Fetch 与库的 H3 导航放在报告中并列；这个文件只能用于理解旧证据，不能用于新验收。新版保留原始捕获证据，也可对旧 wheel 或没有 fork manifest 的 PyPI 包运行独立采集：

```sh
python -I /absolute/path/to/ruyihttp/ci/smoke_firefox_profiles.py <slot> --collect --output observed.jsonl
python -I /absolute/path/to/ruyihttp/ci/firefox_wire.py <slot> observed.jsonl
```

`--collect` 仅观测实际安装的 wheel；单个版本可用 `--release 161` 做定位，正式验收始终检查三个版本。旧日志可用 `ci/firefox_wire.py <slot> old-profile-wire.txt --legacy` 重放；H3 的导航上下文及未采集字段会明确报错，不能当作同源 Fetch 验收。
