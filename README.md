# ruyihttp

Firefox Necko/NSS 的 Requests 风格 HTTP 客户端。一个会话可以选择 Firefox
100–159 的网络档，TLS、请求头、HTTP/2 和 HTTP/3 按该正式版发送。不启动浏览器。
Web 逆向里它是 `test.py` 的真实 TLS 引擎，不是 browser fact，也不替代
RuyiTrace、RuyiDOM 或 ruyipage。

这是私有维护树，来源是 PyPI `ruyihttp==0.9.0` 的 Python 源码，加上 ruyijs /
ff-ruyijs 产出的平台原生运行时。目标不是继续做 wheel 抽包，而是把 Python、
原生库、manifest、构建脚本、测试和发布流程放在同一个仓库里维护。

## 平台矩阵

| 平台 | 状态 | Firefox / NSS / Neqo | wheel tag | 原生库 |
| --- | --- | --- | --- | --- |
| `win_amd64` | ready | 159.0 / 3.131 / 0.32.0 | `py3-none-win_amd64` | `native/win_amd64/*.dll` |
| `darwin_arm64` | ready | 159.0 / 3.132 / 0.33.0 | `py3-none-macosx_26_0_arm64` | `native/darwin_arm64/*.dylib` |
| `linux_x86_64` | ready | 159.0 / 3.132 / 0.33.0 | `py3-none-manylinux_2_39_x86_64` | `native/linux_x86_64/*.so` |
| `darwin_x86_64` | build-required | 159.0 / 3.132 / 0.33.0 | `py3-none-macosx_11_0_x86_64` | 空位 |
| `linux_aarch64` | build-required | 159.0 / 3.132 / 0.33.0 | `py3-none-manylinux_2_39_aarch64` | 空位 |

`darwin_arm64` 的 minos 是 26.0；`linux_x86_64` 的 floor 是 glibc 2.39。
两个 `build-required` 平台已有代码路径和 manifest 槽位，但没有二进制。

## 目录

```text
ruyihttp/                  Python 包（MPL-2.0）
native/<platform>/         平台原生运行时 + provenance + SHA256SUMS
ruyihttp/runtime-manifest.json
                           平台矩阵、NSS/NSPR/Neqo 版本、文件 hash
tests/                     契约测试和 live transport smoke
tools/                     native 导入/校验脚本
docs/                      平台支持、构建、许可说明
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
- macOS arm64 / Linux x86_64：来自 `Facetomyself/ff-ruyijs` 0.4.1 的
  `ruyijs` wheel，NSS 3.132 / Neqo 0.33.0。core 和 QUIC 必须整组使用，不要和
  3.131 的 core 混搭。
- 每个目录的 `provenance.json` 记录来源 wheel、wheel SHA-256、文件 hash 和
  许可说明。`ruyihttp/runtime-manifest.json` 是代码实际读取的平台矩阵。

## 边界

- 只覆盖 transport，不是完整浏览器。没有 DOM、页面生命周期、RuyiTrace 探针、
  浏览器 cache/HSTS/CRLite/partitioned cookie jars。
- TLS ClientHello 的 cluster 表来自 Firefox release sources；macOS/Linux 复用
  同一 cluster，并按 NSS 3.132 的计数/布局做对照，不宣称字节级一致。
- HTTP/3 需要 Alt-Svc；DNS HTTPS/ECH 没有集成。代理路径需要单独验收。
- `darwin_arm64` 只支持 macOS 26+；要支持更旧版本必须降 deployment target 重编。
- 这是私有维护树。`ruyijs/ff-ruyijs` 是 AGPL-3.0-only 或商业许可，Mozilla 派生
  部分是 MPL-2.0。公开发布前先读 `docs/licensing.md`。
