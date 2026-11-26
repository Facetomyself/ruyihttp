# Linux x86_64 native runtime

This is the complete Linux x86_64 Necko/NSS set built from pinned Firefox 161.0
and ff-ruyijs in a digest-pinned Debian Bullseye container on a native Ubuntu
24.04 x86_64 runner. The [source build and modern qualification](https://github.com/Facetomyself/ruyihttp/actions/runs/45793633435)
and [independent Bullseye qualification](https://github.com/Facetomyself/ruyihttp/actions/runs/45796429837)
used the same wheel bytes. Installed-wheel HTTP/1.1, HTTP/2, HTTP/3, Firefox
159/160/161 wire parity with fresh TLS permutation witnesses, and native body
ABI v1 with two simultaneous owners passed on CPython 3.10 and 3.14. Clean
Bullseye pip rejected the v0.9.3 wheel; modern glibc upgraded it in place.

| File | Role |
| --- | --- |
| `libnecko_core.so` | `necko_socket_*`, `necko_exchange_*`, `necko_tls_*` |
| `libnecko_quic.so` | Neqo 0.34.0 HTTP/3 bridge |
| `libnss3.so`, `libnssutil3.so`, `libssl3.so` | NSS 3.133 |
| `libnspr4.so`, `libplc4.so`, `libplds4.so` | NSPR 4.40 |
| `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so` | NSS softoken/freebl |
| `libsqlite3.so` | NSS softoken's SQLite dependency |
| `libnssckbi.so`, `libnsssysinit.so` | NSS built-in roots and system initialization |

All 14 libraries carry `DT_RUNPATH=$ORIGIN`; no loader environment changes are
needed. The external requirements are standard system libraries, including
Bullseye's libgcc and libstdc++. `auditwheel show` inferred `manylinux_2_31_x86_64`;
the highest required ELF glibc symbol was `GLIBC_2.30`, while the independent
installed-wheel runtime floor was glibc 2.31. [Provenance](provenance.json)
records compiler and sysroot pins, each dependency and symbol-version family,
per-file SHA-256, and both hosted proofs. NSS reports `3.133`; the H3 version
export returns integer ABI `32`.
