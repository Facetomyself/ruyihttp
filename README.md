# RuyiHttp

RuyiHttp 是基于 Firefox Necko/NSS 的 Requests 风格 HTTP 客户端。每个会话可以选择 Firefox 100–159 的网络配置，使用真实的 HTTP/1.1、HTTP/2 或 HTTP/3 传输，无需启动浏览器。项目维护 Python API、原生库、构建来源与安装后的协议验收；浏览器 DOM 和页面生命周期属于其他组件。

## 上游与本仓的关系

本仓是 [PyPI `ruyihttp`](https://pypi.org/project/ruyihttp/) 的**独立维护分支**，起点是上游 [0.9.0 发行包](https://pypi.org/project/ruyihttp/0.9.0/)中的 Python 源码和 Windows x64 原生库。上游署名 **LoseNine**，PyPI 列出的项目仓库为 [charlesval/ruyiHttp](https://github.com/charlesval/ruyiHttp)（核对时公开访问返回 404，发行文件以 PyPI 为准）。[ff-ruyijs](https://github.com/cutetailbud/ff-ruyijs) 和 [Mozilla Firefox](https://github.com/mozilla-firefox/firefox) 是本仓 POSIX 原生组件的源码来源，与 Python 项目上游是两层关系。

| | 上游 PyPI 发行 | 本仓 `Facetomyself/ruyihttp` |
| --- | --- | --- |
| 版本（2026-11-26 核对） | [0.11.0](https://pypi.org/project/ruyihttp/0.11.0/)，默认 Firefox 161，范围 100–161 | **0.9.1**，默认 Firefox 159，范围 100–159；独立版本线 |
| 原生运行时（NSS / Neqo） | Windows：3.133 / 0.34.0 | Windows：3.131 / 0.32.0；Linux、macOS：3.132 / 0.33.0 |
| 该版本的 wheel | PyPI 仅列 Windows x64 | Windows x64、Linux x86_64 / ARM64、macOS Intel / Apple Silicon；见[五平台工件与验收](https://github.com/Facetomyself/ruyihttp/actions/runs/45670260976) |

**安装时请区分来源：** 两条线的包名和导入名都是 `ruyihttp`。从公共 PyPI 执行 `pip install -U ruyihttp` 会按平台解析**上游**发行包；要使用本仓，请在独立虚拟环境安装本仓 CI 的对应 wheel，或按下文从本仓源码安装。这里的 `0.9.1` 并非上游 `0.11.0` 的五平台重打包。

[上游 0.11.0 差异与跟进计划](docs/upstream.md)记录了优先更新的信任数据、Firefox 160/161 与原生库的验收条件，以及应保留的分支修复。[传输策略与性能趋势](docs/performance.md)说明本仓的连接复用、H2 背压与 H3 数据接口。

## 平台矩阵

| 平台 | 状态 | Firefox / NSS / Neqo | wheel tag | 原生库 |
| --- | --- | --- | --- | --- |
| `win_amd64` | ready | 159.0 / 3.131 / 0.32.0 | `py3-none-win_amd64` | `native/win_amd64/*.dll` |
| `darwin_arm64` | ready | 159.0 / 3.132 / 0.33.0 | `py3-none-macosx_26_0_arm64` | `native/darwin_arm64/*.dylib` |
| `linux_x86_64` | ready | 159.0 / 3.132 / 0.33.0 | `py3-none-manylinux_2_39_x86_64` | `native/linux_x86_64/*.so` |
| `darwin_x86_64` | ready | 159.0 / 3.132 / 0.33.0 | `py3-none-macosx_15_0_x86_64` | `native/darwin_x86_64/*.dylib` |
| `linux_aarch64` | ready | 159.0 / 3.132 / 0.33.0 | `py3-none-manylinux_2_39_aarch64` | `native/linux_aarch64/*.so` |

Intel Mac 的最低系统版本为 macOS 15.0，Apple Silicon 为 macOS 26.0；两个 Linux wheel 均要求 glibc 2.39 或更高。各平台的编译、安装与实际网络测试分别记录在[平台验收说明](docs/platform-support.md)。

## 目录

```text
ruyihttp/                  Python 包（MPL-2.0）
native/<platform>/         平台原生运行时 + provenance + SHA256SUMS
ruyihttp/runtime-manifest.json
                           平台矩阵、NSS/NSPR/Neqo 版本、文件 hash
tests/                     契约测试和 live transport smoke
tools/                     原生库导入、构建预检及来源校验
ci/                        已安装 wheel 的协议、升级与平台验收
benchmarks/                独立回环源站、性能基准及趋势摘要
docs/                      平台支持、构建、传输策略和许可说明
```

## 安装与构建

运行时用隔离解释器，避免和系统 Python 的 `requests`/`cryptography` 版本互相污染：

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install .
```

macOS/Linux 把 `.venv\Scripts\python.exe` 换成 `.venv/bin/python`。

`pip install -e .` 不会把 `native/<platform>/` 拷进包目录；要可编辑安装，请设置
`NECKO_CORE_LIBRARY` 和 `NECKO_QUIC_LIBRARY` 指向对应平台的库。

构建 wheel：

```powershell
python -m pip wheel --no-build-isolation --no-deps -w dist .
```

在 Windows 上会产出 `py3-none-win_amd64`；macOS arm64 产出
`py3-none-macosx_26_0_arm64`；Ubuntu 24.04 产出
`py3-none-manylinux_2_39_x86_64`。`setup.py` 会按平台把
`native/<platform>/` 的库拷进包内。

在一个主机上交叉构建其他平台时，使用 `RUYIHTTP_PLATFORM` 和
`RUYIHTTP_GLIBC`，例子见 `docs/build-native.md`。

## 测试

```powershell
python -m unittest discover -s tests -v
python tools/build_native.py --check
python tools/verify_runtime.py
```

`tests/test_runtime.py` 覆盖平台文件名、profile 选择、NSS 版本矩阵、manifest、
wheel 装配和 Windows/macOS/Linux 原生布局。真正发请求的 smoke 建议放在目标平台
上跑，不要只依赖契约测试。

## 运行时来源

- Windows：`ruyihttp 0.9.0` 原 wheel 的 `win_amd64` DLL，NSS 3.131 / Neqo 0.32.0。
- Linux x86_64、Linux ARM64、Intel Mac、Apple Silicon：分别在目标 CPU 从固定的 ff-ruyijs / Firefox 源码构建。NSS 3.132 / Neqo 0.33.0，支持 H3 正文二进制 ABI v1；控制操作继续使用 JSON。Windows 保留原生 JSON 正文路径。
- 源码侧以 [runtime-manifest.json](ruyihttp/runtime-manifest.json) 和各平台目录的 `provenance.json` 为准；wheel 内的 `ruyihttp/native-provenance.json` 记录该包携带的库与来源。构建和安装验收逐项核对原生库及四个配置与信任数据文件的哈希。
- 同一平台 wheel 分别在 CPython 3.10、3.14 上安装验收，覆盖真实 H1/H2/H3、停止上传、证书负例、双跳代理及正文读写；升级用例检查新旧包的安装身份。[平台说明](docs/platform-support.md)区别了各桥实际返回的 TLS 字段。

## 边界

- 只覆盖 transport，不是完整浏览器。没有 DOM、页面生命周期、RuyiTrace 探针、
  浏览器 cache/HSTS/CRLite/partitioned cookie jars。
- TLS ClientHello 的 cluster 表来自 Firefox release sources；macOS/Linux 复用
  同一 cluster，并按 NSS 3.132 的计数/布局做对照，不宣称字节级一致。
- HTTP/3 需要 Alt-Svc；DNS HTTPS/ECH 没有集成。已验证 HTTP CONNECT、HTTPS CONNECT、SOCKS5h 三种 TCP 入口的双跳部署；这与 H3 经代理是两个场景。
- `darwin_arm64` 只支持 macOS 26+；要支持更旧版本必须降 deployment target 重编。
- `ruyijs/ff-ruyijs` 是 AGPL-3.0-only 或商业许可，Mozilla 派生部分是 MPL-2.0。
  分发二进制前先读 `docs/licensing.md`。
