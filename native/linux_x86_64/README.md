# Linux x86_64 native runtime

This directory is a complete Linux x86_64 Necko/NSS set built from pinned
Firefox and ff-ruyijs sources on an Ubuntu 24.04 x86_64 runner. The source-built
set replaces the historical ruyijs 0.4.1 wheel binaries with measured optional
H3 body ABI v1 while preserving the installed-wheel H1/H2/H3 and proxy checks.
CPython 3.10 and 3.14 ran the 1,048,579-byte binary and JSON echo controls and
verified native argument bounds with two simultaneous owners.

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

The wheel floor is glibc 2.39 (Ubuntu 24.04). [Provenance](provenance.json)
records source pins, per-file SHA-256, candidate wheel hash and hosted runs.
NSS reports `3.132`; this bridge's version export returns integer ABI `32`.
