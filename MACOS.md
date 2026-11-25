# macOS arm64 runtime

Status: ready. Version 0.9.1 uses a native Apple Silicon source build, not the historical 0.4.1 donor wheel. The six dylibs are recorded in [platform provenance](native/darwin_arm64/provenance.json), together with source pins and H3 bridge patches.

## Runtime

| Item | Value |
| --- | --- |
| Wheel tag | `py3-none-macosx_26_0_arm64` |
| Native directory | `native/darwin_arm64/` |
| NSS | 3.132 |
| NSPR | 4.40 |
| Neqo | 0.33.0 |
| Deployment target | macOS 26.0 |

The directory contains:

- `libnecko_core.dylib` — socket, exchange and TLS ABI
- `libnecko_quic.dylib` — Neqo HTTP/3 bridge
- `libnss3.dylib`, `libsoftokn3.dylib`, `libfreebl3.dylib` — NSS 3.132
- `libmozglue.dylib` — Firefox mozglue

`libnecko_core.dylib` uses `@loader_path` and links `@rpath/libnss3.dylib`.
`libnecko_quic.dylib` links `@rpath/libnss3.dylib` and
`@rpath/libfreebl3.dylib`. Keep the whole directory together.

## Loading contract

- `ruyihttp/_transport.py` loads `libnecko_core.dylib` next to the package.
- `ruyihttp/_http3.py` loads `libnecko_quic.dylib` from the same directory.
- `ruyihttp/_nss.py` reads `ruyihttp/runtime-manifest.json` and requires the
  NSS version recorded for `darwin_arm64` (currently `3.132`).
- `Session(library_path=...)`, `NECKO_CORE_LIBRARY` and
  `NECKO_QUIC_LIBRARY` remain available as explicit overrides.

## Verification

0.9.1 qualifies HTTP/1.1, H2, real QUIC/H3, positive/negative certificate controls, the optional binary body ABI and JSON compatibility on the native Apple Silicon runner. The H3 response now includes measured NSS/TLS metadata.

Historical 0.9.0 HTTPS control on a Mac mini (arm64, macOS 26.5.2, Python 3.12.13):

```text
local smoke OK 0.9.0 http
live smoke OK 200 {'backend': 'NSS', 'nss': '3.132', 'nspr': '4.40',
                  'profile': 'firefox-159', 'version': 772, 'alpn': 'h2',
                  'cipher_suite': 4865, 'resumed': False}
```

## Boundaries

- macOS 26+ only; the deployment target is 26.0.
- Intel macOS uses a separate source-built x86_64 wheel, minimum macOS 15.0. See [Intel acceptance](docs/platform-support.md#native-intel-macos-wheel).
- The 100–159 TLS cluster table is shared with Windows. macOS validates the
  cluster counts and live ALPN, not byte-identical ClientHello records.
- HTTP/3 still requires Alt-Svc; DNS HTTPS/ECH is not integrated.

## Historical note

The earlier 0.9.0 analysis described an arm64-only `libnecko_core.dylib` built
against NSS 3.131 with no QUIC library. That set was later replaced by a complete imported ff-ruyijs 0.4.1 arm64 set, then by the source-built 0.9.1 runtime. Historical artifacts in `dist-v0.9.0-legacy/` are retained only as provenance.
