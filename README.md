# RuyiHttp

RuyiHttp 是基于 Firefox Necko/NSS 的 Requests 风格 Python HTTP 客户端。它直接使用 HTTP/1.1、HTTP/2 或 HTTP/3，无需启动浏览器。会话可选择 Firefox 100–161 的网络配置，默认是 **159**。

**当前稳定版：[RuyiHttp v0.9.4](https://github.com/Facetomyself/ruyihttp/releases/tag/v0.9.4)** · [五平台合集](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-release-bundle.zip) · [附件 SHA-256](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/SHA256SUMS) · [逐平台验收报告](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/qualification.json)

本仓是 [PyPI `ruyihttp`](https://pypi.org/project/ruyihttp/) 的独立维护分支。要安装**本仓版本**，请使用下方 GitHub Release 的 wheel；`pip install -U ruyihttp` 从公共 PyPI 解析的是上游发行包。

## 平台矩阵

使用 **64 位 Python 3.10+**。以下是正式 Release 中可单独下载的五份 wheel，链接附带 SHA-256，可直接交给 pip。

| 系统 | CPU 架构 | 运行环境 | v0.9.4 wheel |
| --- | --- | --- | --- |
| Windows | x86_64（AMD64） | Windows x64 | [ruyihttp-0.9.4-py3-none-win_amd64.whl](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-py3-none-win_amd64.whl#sha256=e6692f97d83eb8433640ad81a75d7a8aee7498729eae58f1f072591829d0f3c3) |
| Linux | x86_64 | glibc 2.31+ | [ruyihttp-0.9.4-py3-none-manylinux_2_31_x86_64.whl](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-py3-none-manylinux_2_31_x86_64.whl#sha256=8f6e78ba29799625bd46adc2d73928e06fbbe4a06c541e9bb1f9f7f9b15854d3) |
| Linux | ARM64（AArch64） | glibc 2.31+ | [ruyihttp-0.9.4-py3-none-manylinux_2_31_aarch64.whl](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-py3-none-manylinux_2_31_aarch64.whl#sha256=191552eeb0428961e77113f1022c84ac2ec7da7c9be7e1921dca772a6bc469ef) |
| macOS | Intel x86_64 | macOS 15.0+ | [ruyihttp-0.9.4-py3-none-macosx_15_0_x86_64.whl](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-py3-none-macosx_15_0_x86_64.whl#sha256=cf038b0ceed31963c5cd810dbca0e9380802c057f92288c584ec7933b4baf616) |
| macOS | Apple Silicon arm64 | macOS 26.0+ | [ruyihttp-0.9.4-py3-none-macosx_26_0_arm64.whl](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-py3-none-macosx_26_0_arm64.whl#sha256=a04671785eba6c61de45b93dd0d8fcc6bbc9778aa39f02e495aafd38c2100e68) |

历史版本仍可从 [v0.9.3 Release](https://github.com/Facetomyself/ruyihttp/releases/tag/v0.9.3) 获取；该版本的 Linux wheel 为 glibc 2.39+。

### 安装 v0.9.4

在虚拟环境中安装对应系统的链接或已下载的 wheel。以 Windows x64 为例：

```sh
python -m pip install --upgrade "https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-py3-none-win_amd64.whl#sha256=e6692f97d83eb8433640ad81a75d7a8aee7498729eae58f1f072591829d0f3c3"
python -m pip check
python -c "import ruyihttp as r; print(r.__version__, r.DEFAULT_FIREFOX)"
```

预期输出 `0.9.4 159`。需要离线保存这五份项目 wheel 和验收材料时，可下载[合集](https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-release-bundle.zip)；首次安装所需的第三方依赖仍由 pip 单独解析。

## HTTP/3 经 MASQUE 代理

启用 `masque` extra 后，使用 `masque://` 指定支持 CONNECT-UDP 的代理。普通直连和 TCP 代理只需安装基本包。以下为 Linux x86_64 的正式 wheel 安装示例：

```sh
python -m pip install --upgrade "ruyihttp[masque] @ https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.4/ruyihttp-0.9.4-py3-none-manylinux_2_31_x86_64.whl#sha256=8f6e78ba29799625bd46adc2d73928e06fbbe4a06c541e9bb1f9f7f9b15854d3"
```

```python
import ruyihttp

with ruyihttp.Session(firefox="161", verify=True, proxy_verify=True, timeout=(8, 20)) as s:
    s.trust_env = False
    s.proxies["https"] = "masque://relay.example:443"  # 改为实际支持 CONNECT-UDP 的代理
    response = s.get("https://origin.example/document")  # 改为实际提供 H3 的源站
    response.raise_for_status()
    print(response.raw.version, response.tls["alpn"], response.proxy_tls["protocol"])
    # 30 h3 connect-udp
```

内层由 NSS/Neqo 与源站握手；外层由 aioquic 验证代理、协商 H3 并承载 UDP。目标域名交由代理处理。强制 MASQUE 路由不会静默改走直连/TCP；`https://` 代理仍是普通 TCP CONNECT。参见[代理 CA、URI 模板、MTU 和互操作](docs/masque.md)。

## 直连示例

```python
import ruyihttp

with ruyihttp.Session(firefox="161") as session:
    response = session.get("https://example.com/", timeout=10)
    response.raise_for_status()
    print(response.status_code, response.tls["alpn"])
```

## 上游与本仓的关系

本仓从 LoseNine 发布的[上游 0.9.0](https://pypi.org/project/ruyihttp/0.9.0/) 的 Python 源码和 Windows 原生库起步。PyPI 元数据列出的项目仓库是 [charlesval/ruyiHttp](https://github.com/charlesval/ruyiHttp)；发行文件以 PyPI 版本页为准。当前分支选择性跟进[上游 0.11.0](https://pypi.org/project/ruyihttp/0.11.0/#files)，两个项目沿用相同的包名和导入名，但版本线独立。

上游 0.11.0 默认选择 Firefox 161，PyPI 仅提供 Windows x64 wheel。本仓当前默认仍为 Firefox 159，覆盖上表五个目标。五个平台的原生运行时均为 NSS 3.133 / NSPR 4.40 / Neqo 0.34.0：Windows 原样导入上游六个 DLL，Linux 和 macOS 则使用固定的 [ff-ruyijs](https://github.com/cutetailbud/ff-ruyijs) 与 [Mozilla Firefox](https://github.com/mozilla-firefox/firefox) 源码在目标架构上构建。本版沿用 0.9.2 核验的 118 张 Mozilla TLS 服务端受信根和公共后缀列表。参见[上游差异](docs/upstream.md)、[构建来源](docs/build-native.md)和[更新日志](CHANGELOG.md)。

## 网络配置的验收含义

本版对照的是相同系统和 CPU 架构上的 **Mozilla 官方 en-US Firefox 159.0、160.0 和 161.0**。H1/H2 验证顶层导航，H3 验证同源文档发起的普通 `fetch`。完整 UA、有序请求头、TLS ClientHello 的稳定字段、H2 首帧和优先级、H3 SETTINGS、QUIC 初始与协商版本及选定传输参数都进入发布门禁。[0.9.4 五平台安装验收](https://github.com/Facetomyself/ruyihttp/actions/runs/45810139410)覆盖从 0.9.0 基线、本仓 0.9.1、0.9.2 和 0.9.3 的正常升级。两个 Linux 架构的最终 wheel 还分别在 Debian 11 / glibc 2.31 的 CPython 3.10 与 3.14 上原样安装并验证了经代理 H3，见[最低系统验收](docs/linux-glibc231-qualification.md)。

Linux ARM64 始终加载 ARM64 原生库；从 Firefox 123 配置起，对外发送官方约简后的 UA `X11; Linux x86_64`。100–158 的历史配置按版本源码规则维护，五平台实机对照的结论限于前述三个版本和请求场景。见[线路对照与边界](docs/firefox-profile-wire.md)、[签名浏览器采样](docs/firefox-reference-collection.md)和[H2 首帧证据](docs/firefox-h2-preface.md)。

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

正式版直接安装[平台矩阵](#平台矩阵)中对应的 Release wheel。开发者可在本仓源码目录、已激活的虚拟环境中运行：

```sh
python -m pip install .
python -m pip wheel --no-deps -w dist .
```

`pip wheel` 会把目标平台已验收的原生库封装进 wheel。`RUYIHTTP_PLATFORM` 可用于在一台主机上打包另一平台的已有二进制；这与重新编译原生库、在目标机上运行验收是三件事。使用 `pip install -e .` 时需设置 `NECKO_CORE_LIBRARY` 和 `NECKO_QUIC_LIBRARY` 指向该平台的库。详见[构建说明](docs/build-native.md)。

## 测试

```sh
python -m unittest discover -s tests -v
python tools/build_native.py --check
python tools/verify_runtime.py
```

上述命令检查源码契约、清单和原生导出。发行版另在目标机上安装 wheel，并用真实 TLS、H2、UDP/H3 对端验证行为；测试入口和版本记录见[平台说明](docs/platform-support.md)，回环性能的测量方法见[性能基准](docs/performance.md)。

## 运行时来源

- Windows：从 PyPI 上游 0.11.0 精确导入六个 `win_amd64` DLL，NSS 3.133 / Neqo 0.34.0；Windows 采用 JSON 正文 ABI，此处没有宣称从源码重建。
- Linux x86_64、Linux ARM64、Intel Mac、Apple Silicon：分别在目标 CPU 从固定的 ff-ruyijs / Firefox 源码构建。各自的来源、版本与哈希见平台矩阵及 provenance，支持 H3 正文二进制 ABI v1；控制操作继续使用 JSON。Windows 保留原生 JSON 正文路径。
- 源码侧以 [runtime-manifest.json](ruyihttp/runtime-manifest.json) 和各平台目录的 `provenance.json` 为准；wheel 内的 `ruyihttp/native-provenance.json` 记录该包携带的库与来源。构建和安装验收逐项核对原生库及四个配置与信任数据文件的哈希。
- 同一平台 wheel 分别在 CPython 3.10、3.14 上安装验收，覆盖真实 H1/H2/H3、停止上传、证书负例、双跳代理及正文读写；升级用例检查新旧包的安装身份。[平台说明](docs/platform-support.md)区别了各桥实际返回的 TLS 字段。

## 边界

- 只覆盖 transport，不是完整浏览器。没有 DOM、页面生命周期、RuyiTrace 探针、
  浏览器 cache/HSTS/CRLite/partitioned cookie jars。
- TLS ClientHello 的 cluster 表来自 Firefox release sources；macOS/Linux 复用
  同一 cluster，并按实际加载的 NSS 及对应平台的实测字段做对照，不宣称字节级一致。
- 直连 H3 使用 HTTPS Alt-Svc；显式 `masque://` 让内层直接通过一个 CONNECT-UDP 代理建立到目标的 H3。双跳 TCP 代理另行测试。当前无 DNS HTTPS/ECH、CONNECT-IP、多跳 MASQUE 或仅 capsule 外层的支持。
- `darwin_arm64` 只支持 macOS 26+；要支持更旧版本必须降 deployment target 重编。
- `ruyijs/ff-ruyijs` 是 AGPL-3.0-only 或商业许可，Mozilla 派生部分是 MPL-2.0。
  分发二进制前先读 `docs/licensing.md`。
