# Apple Silicon native runtime

This directory is a complete macOS arm64 Necko/NSS set built from pinned
Firefox and ff-ruyijs sources on a native Apple Silicon runner. It replaces the
historical ruyijs 0.4.1 set, whose H3 bridge emitted `tls: null`. This build adds
native H3 TLS metadata and optional binary body ABI v1.

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

The measured `LC_BUILD_VERSION` minimum is macOS 26.0.0 on each of the six
libraries. The wheel tag remains `macosx_26_0_arm64`. NSS reports `3.132`;
`necko_quic_version()` reports `neqo-0.33.0/nss-3.132`.

[Provenance](provenance.json) records exact source pins, patch hashes, the
per-file deployment targets and SHA-256, and the verified wheel. CPython 3.10
and 3.14 passed H1/H2/H3, native IPv4/IPv6 and certificate negatives, telemetry,
two-live-owner tests and the 1,048,579-byte binary and JSON controls.
