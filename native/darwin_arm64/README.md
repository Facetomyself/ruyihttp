# Apple Silicon 原生库

`libnecko_core.dylib` 于 2026-10-31 在 Mac mini（arm64，macOS 26.5.2）上从 `ff-ruyijs/native/necko_tls/necko_tls.c` 与 `necko_exchange.c` 编译。`LC_BUILD_VERSION` 的 minos 是 26.0。SHA-256：`4a92b8e8c655d60f42ba751f9d24f9ab349aff76a46d3c12f8a8e969643740fc`。

同目录的 `libnss3.dylib`、`libmozglue.dylib`、`libfreebl3.dylib`、`libsoftokn3.dylib` 是 Firefox 159 `obj-necko/dist/bin` 的 donor，不是这次 clang 的产物。core 的 install name 是 `@rpath/libnecko_core.dylib`，rpath 是 `@loader_path`，并链接 `@rpath/libnss3.dylib`。

在这台机器上加载后，`necko_tls_nss_version()` 返回 `3.131`，`necko_tls_nspr_version()` 返回 `4.40`。

没有 `libnecko_quic.dylib`。这两份 C 文件不导出 `necko_quic_*`，树里也没有对应的 QUIC 源码。HTTP/3 还不能编。
