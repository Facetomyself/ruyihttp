# Platform support

## Matrix

| Platform | Status | Runtime | Wheel tag | Notes |
| --- | --- | --- | --- | --- |
| Windows x64 | ready | NSS 3.131 / NSPR 4.40 / Neqo 0.32.0 | `py3-none-win_amd64` | Original 0.9.0 DLL set. Live HTTPS checked. |
| macOS arm64 | ready | NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 | `py3-none-macosx_26_0_arm64` | Core and QUIC imported from `ruyijs` 0.4.1. minos 26.0. |
| Linux x86_64 | ready | NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 | `py3-none-manylinux_2_39_x86_64` | Core and QUIC imported from `ruyijs` 0.4.1. glibc 2.39 floor. |
| macOS x86_64 | build-required | expected NSS 3.132 / Neqo 0.33.0 | `py3-none-macosx_11_0_x86_64` | No binary in the tree. Build on Intel macOS. |
| Linux aarch64 | build-required | expected NSS 3.132 / Neqo 0.33.0 | `py3-none-manylinux_2_39_aarch64` | No binary in the tree. Build on aarch64 Linux. |

`build-required` means the Python path, manifest slot and wheel tag exist, but
`setup.py` raises `native runtime missing` rather than packaging another
platform's binary.

## TLS / HTTP profiles

- `ruyihttp/_tls_profiles.py` holds the 100–159 cluster table. The clusters were
  derived from Firefox release sources and checked against Windows x64 captures.
- macOS and Linux select the same clusters. The NSS 3.132 runtimes are validated
  by cipher/group/key-share counts, not by byte-identical ClientHello records.
- `ruyihttp/_firefox.py` supplies the platform User-Agent:
  - Windows: `Windows NT 10.0; Win64; x64`
  - macOS: `Macintosh; Intel Mac OS X 10.15`
  - Linux: `X11; Linux x86_64` (or `aarch64` when the host reports it)
- HTTP/2 SETTINGS and header order are selected by the Firefox profile and are
  platform-independent in this tree.
- HTTP/3 requires `Alt-Svc`. DNS HTTPS/ECH configuration is still not integrated.

## Runtime loading

`ruyihttp/_transport.py` loads:

- Windows: `necko_core.dll`
- macOS: `libnecko_core.dylib`
- Linux: `libnecko_core.so`

`ruyihttp/_http3.py` loads the matching `necko_quic` library. Each platform
directory contains its own NSS/NSPR/Neqo dependencies. Linux libraries carry
`$ORIGIN` runpaths; macOS libraries carry `@loader_path`.

Do not mix a core and QUIC library built against different NSS versions. Use the
whole `native/<platform>/` directory from one provenance record.

## Verification

```sh
python -m unittest discover -s tests -v
python tools/build_native.py --check
python tools/verify_runtime.py
```

On a ready platform, also run a live request:

```python
import ruyihttp

with ruyihttp.Session(firefox="159") as session:
    response = session.get("https://example.com/", timeout=20)
    print(response.status_code, response.tls)
```

Expected: `200`, ALPN `h2`, and the NSS version from the platform manifest.

## Validation record

Checked on 2026-11-17:

| Platform | Host | Result |
| --- | --- | --- |
| Windows x64 | Windows, Python 3.13.12 | local HTTP 200; `https://example.com/` 200, ALPN `h2`, NSS 3.131 |
| macOS arm64 | Mac mini, macOS 26.5.2, Python 3.12.13 | local HTTP 200; `https://example.com/` 200, ALPN `h2`, NSS 3.132 |
| Linux x86_64 | cross-built wheel | manifest/ELF/ABI checks pass; live smoke pending because no x86_64 Linux host is available in this environment |
