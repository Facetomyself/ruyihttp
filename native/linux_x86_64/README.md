# Linux x86_64 native runtime

This directory is a complete Linux x86_64 Necko/NSS set imported from
`Facetomyself/ff-ruyijs` 0.4.1
(`ruyijs-0.4.1-py3-none-manylinux_2_39_x86_64.whl`).

| File | Role |
| --- | --- |
| `libnecko_core.so` | `necko_socket_*`, `necko_exchange_*`, `necko_tls_*` |
| `libnecko_quic.so` | Neqo 0.33.0 HTTP/3 bridge |
| `libnss3.so`, `libnssutil3.so`, `libssl3.so` | NSS 3.132 |
| `libnspr4.so`, `libplc4.so`, `libplds4.so` | NSPR 4.40 |
| `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so` | NSS softoken/freebl |
| `libsqlite3.so` | NSS softoken's SQLite dependency |
| `libnssckbi.so`, `libnsssysinit.so` | NSS built-in roots and system initialization |

Both `libnecko_core.so` and `libnecko_quic.so` carry a `$ORIGIN` runpath, so the
sibling libraries load without setting `LD_LIBRARY_PATH`. Keep the directory
together.

The build floor is glibc 2.39 (Ubuntu 24.04). `provenance.json` records the
source wheel and per-file SHA-256. NSS reports `3.132`.
