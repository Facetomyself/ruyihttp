# ruyihttp 0.9.0 源码树

这是从 PyPI wheel `ruyihttp-0.9.0-py3-none-win_amd64.whl` 抽出的维护树。13 个 `.py` 是包里的 MPL 源码，wheel 里没有 `.pyc`，所以这里没有做字节码反编译。

Windows 原生库仍是编译好的 DLL，放在 `native/win_amd64/`。它们是 Firefox Necko/NSS 运行时，不是这份 Python 源码能还原出来的 C 工程。Mac 版本要另备 Darwin 二进制，再接到下面已经写好的装载名。

| 项目 | 值 |
| --- | --- |
| 来源 wheel SHA-256 | `95b67581b2538194b9fc9b41b7f7077f1cb2767dbc5c776d404e78cd11d42f48` |
| 许可证 | MPL-2.0，见 `LICENSE` |
| Python | 3.10–3.14 |
| 当前原生平台 | `runtime-manifest.json` 的 `platform` 是 `win_amd64` |
| NSS 校验 | `_nss.py` 要求 `necko_tls_nss_version()` 为 `3.131` |

`upstream/` 仍是 0.8.1 子模块，不要改它，也不要从它安装。

## 和 0.8.1 源码的差别

0.9.0 新增 `ruyihttp/_tls_profiles.py`。相对 `tools/ruyihttp/upstream`，这些 Python 文件有内容差：`__init__.py`、`_firefox.py`、`_http2.py`、`_http3.py`、`_nss.py`、`_retry.py`、`_transport.py`、`api.py`、`sessions.py`。六份 DLL 的字节也不同。

## Mac 端口

分析写在 [MACOS.md](MACOS.md)。`native/darwin_arm64/` 有在 Mac mini 上编译的 `libnecko_core.dylib`（minos 26.0）和它链接的 NSS donor。`native/darwin_x86_64/` 仍是空位。没有 `libnecko_quic.dylib`。Darwin 不把 Windows 上抓到的 QUIC 档当成 Mac 结果。

## 构建

在本目录：

```powershell
python -m pip wheel --no-build-isolation --no-deps -w dist .
```

在这台 Windows x64 上，产物 tag 是 `py3-none-win_amd64`，并会把 `native/win_amd64/*.dll` 拷进包内。官方 wheel 仍以 `tools/ruyihttp/dist/` 那一份为准。
