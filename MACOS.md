# ruyihttp 0.9.0 Mac 端口分析

arm64 core 已在 Mac mini 上编译并加载。QUIC 库还没有。

## 树里有什么

| 路径 | 内容 |
| --- | --- |
| `ruyihttp/*.py` | PyPI `ruyihttp==0.9.0` wheel 里的 MPL 源码，13 个文件。wheel 没有 `.pyc` |
| `native/win_amd64/*.dll` | 已发布的 Windows x64 运行时，6 个文件。`runtime-manifest.json` 的 `platform` 是 `win_amd64` |
| `native/darwin_arm64/` | `libnecko_core.dylib` 加 NSS donor：`libnss3.dylib`、`libmozglue.dylib`、`libfreebl3.dylib`、`libsoftokn3.dylib`。没有 `libnecko_quic.dylib` |
| `native/darwin_x86_64/` | 空位 |
| `setup.py` 的 `macosx_26_0_arm64` | 来自这份 arm64 dylib 的 `LC_BUILD_VERSION` minos 26.0。`macosx_11_0_x86_64` 仍是没有二进制的占位 |

Windows 上执行 `python -m pip wheel` 仍只打 `py3-none-win_amd64`，并把 `native/win_amd64/*.dll` 拷进包内。官方 wheel 仍是 `tools/ruyihttp/dist/ruyihttp-0.9.0-py3-none-win_amd64.whl`。

## Python 装载合同

核心库由 `_load_library` 决定（`ruyihttp/_transport.py`）：

1. 参数 `path`，否则环境变量 `NECKO_CORE_LIBRARY`。
2. 两者都空时，按平台取与 `_transport.py` 同目录的文件名：Windows `necko_core.dll`，macOS `libnecko_core.dylib`，其他 `libnecko_core.so`。
3. 文件不存在则 `FileNotFoundError`。Windows 用 `os.add_dll_directory` 再 `ctypes.CDLL`；其他平台直接 `ctypes.CDLL`。
4. 随后 `configure_library`。`_nss.py` 把 `necko_tls_nss_version()` 和 `b"3.131"` 比较，不等则 `RuntimeError: firefox-159 requires the packaged NSS 3.131 runtime`。

HTTP/3 库在 `ruyihttp/_http3.py` 的 `Connection`：默认文件名是 `necko_quic.dll` / `libnecko_quic.dylib` / `libnecko_quic.so`，可用 `NECKO_QUIC_LIBRARY` 覆盖。未设置时，路径是 core 库所在目录加上这个文件名。Python 实际调用了 `necko_quic_call` 和 `necko_quic_set_decoder`。导出表里还有 `necko_quic_init`、`necko_quic_version`，这份 Python 源码没有引用它们。

`ruyihttp/_firefox.py` 的 `data_path` 在设置了 `NECKO_CORE_LIBRARY` 时，会到该文件的父目录以及 `ruyihttp/`、`necko/` 子目录找 `firefox-suffixes.dat` 等数据文件。未设置时用 Python 模块同目录。Mac 上若 dylib 不和这些数据文件放在一起，需要同时满足这条查找规则。

`Session(library_path=...)` 可以绕过默认文件名，见 `_transport.py` 里 `FileNotFoundError` 的提示。

## 不把 Windows 指纹套到 Mac

`_tls_profiles.py` 里的 ClientHello 是 Windows x64 正式版抓包。`_firefox.py` 里的 QUIC 档也来自这套 Windows 测量。Darwin 上 `native_profile` 和 `quic_profile` 会直接拒绝，不会把这两张表交给 necko。

User-Agent 按 Firefox 自己的缩减令牌分开。Windows 仍是 `Windows NT 10.0; Win64; x64`。Darwin 用 `Macintosh; Intel Mac OS X 10.15`，Apple Silicon 也是这一条，不是把 Windows 令牌换个文件名。110–119 的 `rv:` 冻结到 109，两边一样。

Accept、HTTP/2 SETTINGS 还在同一张版本表里。它们没有单独的 macOS 抓包，不能写成已经按 Mac 核对过。

## 原生 ABI

`native/win_amd64/exports.json` 来自这 6 份 DLL 的 PE 导出和导入表，机器类型 `0x8664`。

- `necko_core.dll` 导出 50 个 `necko_*`。Python 通过 `necko_` 前缀取符号，包括 socket、exchange、http client 和 `necko_tls_*`。
- `necko_quic.dll` 导出上面 4 个 `necko_quic_*`。
- `necko_core.dll` 的导入包含 `nss3.dll`、`WINHTTP.dll`、`WS2_32.dll`、`MSVCP140.dll`、`VCRUNTIME140.dll`。`necko_quic.dll` 的导入包含 `nss3.dll`、`ws2_32.dll`、`winmm.dll`、`IPHLPAPI.DLL`、`VCRUNTIME140.dll`。
- `freebl3.dll`、`mozglue.dll`、`softokn3.dll` 在同一 Windows 运行时目录里，并由 `runtime-manifest.json` 记录 SHA-256。它们的 Mac 对应安装名要看将来 dylib 自己的链接关系。不能把 `nss3.dll` 改名为某个 `.dylib` 就当作 Mac 依赖。

## 和 ruyiJS 参照仓的对照

参照是 `storage/ruyijs/repo`，记录在 `storage/ruyijs/repo-clone.json`：浅克隆，`main` / `989848cb`，包 `0.1.6`，MPL-2.0。这轮不改那个目录。

两边相同的地方：MPL-2.0，Python 3.10+，wheel 内嵌一份锁定的原生运行时，安装后不再下载浏览器。

ruyiJS 当前是 Windows 门禁：

- `setup.py` 的 `BuildPython.run` 在非 Windows x64 时抛出 `ruyijs requires Windows x64 and a 64-bit Python installation`。
- `python/ruyijs/_runtime_paths.py` 的 `get_runtime_path` 同样拒绝非 Windows x64。
- `runtime.json` 只钉 `ruyijs-runtime-0.1.5-win-amd64.zip` 和它的 SHA-256。

ruyihttp 的 Python 按 Darwin 选择 `libnecko_core.dylib` 和 `libnecko_quic.dylib`。arm64 core 和它链接的 NSS 已经在 `native/darwin_arm64/`。quic 文件仍然没有。这里也没有一份 Mac 版 `runtime.json` 式的 hash 钉，core 的 SHA-256 写在该目录的 README。

`storage/ruyijs/repo/AGENTS.md` 和 `CONTRIBUTING.md` 写到 `tools/build.py`、`ARCHITECTURE.md`、`docs/`。这份浅克隆里没有这些路径，不能从它抄出一套 Mac 构建脚本。`src/transport/necko_*` 是 ruyiJS 自己的 SpiderMonkey 进程传输，不是 ruyihttp 的 `necko_core` dylib 源码。

## Mac mini 上已经做的编译

机器是 arm64，macOS 26.5.2。用来装载的 Python 是 `~/.local/bin/python3.12`（3.12.13）。`/usr/bin/python3` 是 3.9.6，低于包要求的 3.10。

`libnecko_core.dylib` 用与 `ff-ruyijs/tools/build.py` 里 `build_necko_core` 相同的 clang 参数，在独立目录 `~/Workspaces/ruyihttp-0.9.0-darwin/lib` 编译，没有改 `ff-ruyijs/dist`。源文件是 `necko_tls.c` 和 `necko_exchange.c`。donor NSS 来自 `~/Workspaces/firefox-159/obj-necko/dist/bin`。`MACOSX_DEPLOYMENT_TARGET=26.0`。

加载这份新文件后，`necko_tls_nss_version()` 为 `3.131`，`necko_tls_nspr_version()` 为 `4.40`。用 `native/necko_tls/hello_probe.py` 对这份新库做了本地 ClientHello 捕获，探针要求的 100 与 159 形状检查通过。这不是把 Windows 抓包字节写进 Darwin 表。

同一份二进制打进 `ruyihttp-0.9.0-py3-none-macosx_26_0_arm64.whl`。从解开的 wheel 加载 `ruyihttp`，`necko_tls_nss_version()` 仍是 `3.131`，`necko_tls_nspr_version()` 仍是 `4.40`。wheel 里没有 Windows DLL。Python 的 `native_profile` 在 Darwin 上仍不会把 Windows ClientHello 表交给 necko。这次核对的是编译产物和库加载，不是 `Session` 走完一次 Mac HTTPS。

`firefox-159/obj-necko` 是浏览器 donor，里面没有 `libnecko_core.dylib`。`libnecko_quic.dylib` 在这两棵树里都不存在，C 源也不导出 `necko_quic_*`。HTTP/3 这次没有编译。

Intel 目录仍然为空。缺二进制时 `setup.py` 不会把 Windows DLL 打进那个 wheel。
