# Linux x86_64 native runtime

This directory is a complete Linux x86_64 Necko/NSS set built from pinned
Firefox 161.0 and the pinned ff-ruyijs donor on an Ubuntu 24.04 x86_64 runner.
The [hosted qualification](https://github.com/Facetomyself/ruyihttp/actions/runs/45769276419)
replayed the source libraries by digest. The installed wheel passed H1/H2/H3,
proxy checks, the same-slot comparison against official Firefox 159/160/161 with
fresh TLS permutation witnesses, and the in-place upgrade from the 0.9.0 fork.
On CPython 3.10 and 3.14, the 1,048,579-byte binary and JSON echo controls and
argument bounds with two simultaneous native owners passed.

| File | Role |
| --- | --- |
| `libnecko_core.so` | `necko_socket_*`, `necko_exchange_*`, `necko_tls_*` |
| `libnecko_quic.so` | Neqo 0.34.0 HTTP/3 bridge |
| `libnss3.so`, `libnssutil3.so`, `libssl3.so` | NSS 3.133 |
| `libnspr4.so`, `libplc4.so`, `libplds4.so` | NSPR 4.40 |
| `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so` | NSS softoken/freebl |
| `libsqlite3.so` | NSS softoken's SQLite dependency |
| `libnssckbi.so`, `libnsssysinit.so` | NSS built-in roots and system initialization |

Both `libnecko_core.so` and `libnecko_quic.so` carry a `$ORIGIN` runpath, so the
sibling libraries load without setting `LD_LIBRARY_PATH`. Keep the directory
together.

The tested wheel policy is `manylinux_2_39_x86_64` (Ubuntu 24.04); `auditwheel`
agrees. ELF inspection recorded `GLIBC_2.38` as the highest required versioned
symbol, which does not establish a lower tested host floor. [Provenance](provenance.json)
records source pins, per-file SHA-256, candidate wheel hash and hosted runs.
NSS reports `3.133`; the H3 version export still returns integer ABI `32`.
