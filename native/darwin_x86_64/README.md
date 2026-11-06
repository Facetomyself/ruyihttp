# Intel 原生库空位

这里还没有文件。Mac 端口需要至少：

- `libnecko_core.dylib`
- `libnecko_quic.dylib`

Python 用 `ctypes.CDLL` 按上述文件名加载，并调用 Windows 版已经导出的 `necko_*` 符号。NSS、NSPR、mozglue 的安装名以这份 dylib 的实际链接为准。NSS 版本字符串必须是 `3.131`，否则 `_nss.py` 会拒绝加载。
