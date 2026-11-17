# Apple Silicon native runtime

This directory is a complete macOS arm64 Necko/NSS set imported from
`Facetomyself/ff-ruyijs` 0.4.1
(`ruyijs-0.4.1-py3-none-macosx_26_0_arm64.whl`).

| File | Role |
| --- | --- |
| `libnecko_core.dylib` | `necko_socket_*`, `necko_exchange_*`, `necko_tls_*` |
| `libnecko_quic.dylib` | Neqo 0.33.0 HTTP/3 bridge |
| `libnss3.dylib` | NSS 3.132 |
| `libsoftokn3.dylib` | NSS softoken |
| `libfreebl3.dylib` | NSS freebl |
| `libmozglue.dylib` | Firefox mozglue |

`libnecko_core.dylib` has `@loader_path` rpath and links `@rpath/libnss3.dylib`.
`libnecko_quic.dylib` links `@rpath/libnss3.dylib` and `@rpath/libfreebl3.dylib`.
Keep the whole directory together.

minos is 26.0; this wheel does not run on older macOS. NSS reports `3.132`.
`provenance.json` records the source wheel and per-file SHA-256.

The previous 3.131 `libnecko_core.dylib` was replaced as a set. Do not mix it
with the 3.132 QUIC library.
