# Apple Silicon native runtime

This directory contains the macOS arm64 Necko/NSS set built from Firefox 161.0
and pinned ff-ruyijs sources on a native Apple Silicon runner. It retains real
NSS H3 TLS telemetry, native owner-thread isolation and binary body ABI v1.

| File | Role |
| --- | --- |
| `libnecko_core.dylib` | `necko_socket_*`, `necko_exchange_*`, `necko_tls_*` |
| `libnecko_quic.dylib` | Neqo 0.34.0 HTTP/3 bridge |
| `libnss3.dylib` | NSS 3.133 and folded NSPR 4.40 |
| `libsoftokn3.dylib` | NSS softoken |
| `libfreebl3.dylib` | NSS freebl |
| `libmozglue.dylib` | Firefox mozglue |

`libnecko_core.dylib` has `@loader_path` rpath and links `@rpath/libnss3.dylib`.
`libnecko_quic.dylib` links `@rpath/libnss3.dylib` and `@rpath/libfreebl3.dylib`.
Keep the whole directory together.

The measured `LC_BUILD_VERSION` minimum is macOS 26.0.0 on each of the six
libraries. The wheel tag remains `macosx_26_0_arm64`. NSS reports `3.133`;
`necko_quic_version()` reports `neqo-0.34.0/nss-3.133`.

[Provenance](provenance.json) records exact source pins, patch hashes, the
per-file deployment targets and SHA-256, and the verified wheel. The
[hosted qualification](https://github.com/Facetomyself/ruyihttp/actions/runs/45771609225)
passed CPython 3.10 and 3.14, H1/H2/H3, native IPv4/IPv6 and certificate negatives,
same-slot official Firefox 159/160/161 comparisons with fresh TLS permutation
witnesses, two-live-owner tests, the 1,048,579-byte binary and JSON controls,
and an in-place upgrade from the 0.9.0 fork.
