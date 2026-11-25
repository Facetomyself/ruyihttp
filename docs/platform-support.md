# Platform support

## Matrix

| Platform | Status | Runtime | Wheel tag | Notes |
| --- | --- | --- | --- | --- |
| Windows x64 | ready | NSS 3.131 / NSPR 4.40 / Neqo 0.32.0 | `py3-none-win_amd64` | Original, hash-verified 0.9.0 DLLs; JSON body ABI, H3 reports the historical NSS/Neqo field set. |
| macOS arm64 | ready | NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 | `py3-none-macosx_26_0_arm64` | Six source-built arm64 dylibs, deployment floor 26.0; measured NSS H3 telemetry and binary body ABI v1. |
| Linux x86_64 | ready | NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 | `py3-none-manylinux_2_39_x86_64` | Fourteen source-built ELF libraries, glibc 2.39 policy, H3 binary body ABI v1. |
| macOS x86_64 | ready | NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 | `py3-none-macosx_15_0_x86_64` | Six source-built thin Intel dylibs; deployment floor 15.0, tested on 15.7.9. |
| Linux aarch64 | ready | NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 | `py3-none-manylinux_2_39_aarch64` | 14 source-built ELF libraries. See native ARM acceptance below. |

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

## 0.9.1 qualification policy

Every [wheel job](../.github/workflows/wheels.yml) builds the platform wheel once, installs that same artifact on CPython 3.10 and 3.14, and records the interpreter, installed paths, native hashes and actual protocol results. Wire-level HTTP/3, strict certificate negatives, early response, IPv4/IPv6 Alt-Svc, blocked UDP/warm TCP, two-hop TCP proxies, H2 EOF/backpressure and source-to-destination upgrade are distinct checks. See [transport performance and limitations](performance.md) for budgets and the weekly comparison.

Windows uses the original x64 DLLs (NSS 3.131). Its H3 TLS result is `NSS/Neqo` and contains the negotiated protocol/version/cipher/resumption flag; it does not invent a Firefox-profile or NSS-version field. The core NSS version is measured separately. The four POSIX sets use source-built versioned body exports and provide the native NSS/Neqo TLS report. Binary ABI tests send and receive real bodies with embedded zeros, test owner isolation, and force the same bridge through JSON as an independent compatibility control. Protocol support here does not mean H3 through an ordinary TCP proxy.

## Validation record

Checked on 2026-11-17:

| Platform | Host | Result |
| --- | --- | --- |
| Windows x64 | Windows, Python 3.13.12 | local HTTP 200; `https://example.com/` 200, ALPN `h2`, NSS 3.131 |
| macOS arm64 | Mac mini, macOS 26.5.2, Python 3.12.13 | local HTTP 200; `https://example.com/` 200, ALPN `h2`, NSS 3.132 |
| Linux x86_64 | cross-built wheel | At this date manifest/ELF/ABI checks passed; runtime validation followed below. |

### Linux x86_64 transport acceptance

- 2026-11-20: on a native x86_64 CPU, the installed Linux wheel in an Ubuntu 24.04 container (glibc 2.39) completed a real request to `https://example.com/`: HTTP 200, TLS 1.3, ALPN `h2`, NSS 3.132.
- 2026-11-24: [ten proxy-chain cases](https://github.com/Facetomyself/ruyihttp/actions/runs/45333462315) passed on Ubuntu 24.04 x86_64. The client selected a single HTTP CONNECT, HTTPS CONNECT or SOCKS5h ingress; that proxy used a second CONNECT hop. Positive cases recorded ingress, exit and TLS origin; the origin returned a fresh nonce and received no `Proxy-Authorization`. Refusing the second hop produced `ProxyError` and zero origin requests. A wrong origin certificate produced `SSLError`; a wrong HTTPS proxy certificate prevented even the first CONNECT. The fixture uses a private test CA and loopback sockets; all certificate checks remain enabled.

- 2026-11-24: a native x86_64 client completed a TLS 1.3/ALPN `h3` handshake with an independent aioquic UDP server, exchanged 256 KiB GET/POST bodies and reused QUIC streams. For both IPv4 and IPv6, `Session` first discovered a port-only `Alt-Svc` over HTTPS; with all TCP listeners closed, the server then observed one H3 connection with streams 0 and 4. Wrong-host, expired and untrusted certificates failed before any origin HTTP request. A port-only alternative on an IPv6 literal used to be lost because URI brackets were stripped; the adapter now restores those brackets. This is a controlled real handshake, not a claim about UDP reachability on arbitrary networks.

To repeat H3, install the wheel and `aioquic==1.3.0`, then from outside the source tree run `RUYIHTTP_TEST_NATIVE_H3=1 python -m unittest discover -s /path/to/checkout/tests -p test_http3_native.py -v`.

To reproduce the proxy cases, install the built wheel, PySocks and the OpenSSL CLI, then run `python ci/smoke_proxy_chain.py`. This measures a chained proxy deployment carrying TCP/TLS, not a list of proxy URLs in the client API, nor UDP/HTTP/3 through CONNECT.

### Native ARM64 Linux wheel

The [source build](https://github.com/Facetomyself/ruyihttp/actions/runs/45335744015) compiled the 14-library set on an ARM runner. A [separate validation](https://github.com/Facetomyself/ruyihttp/actions/runs/45336869695) rebuilt the wheel from the exact committed libraries, verified its manylinux policy and local library mappings, then installed and exercised HTTP/1, HTTP/2 and HTTP/3. On a second native ARM64 machine (Glibc 2.39), the installed wheel also passed the UDP-only IPv4/IPv6 H3 upgrade, three invalid-certificate controls, ten proxy-chain cases and the HTTP/2 peer-close regression. See [native provenance](../native/linux_aarch64/provenance.json).

### Native Intel macOS wheel

On a native Intel runner (x86_64, macOS 15.7.9), the [strict source-built candidate](https://github.com/Facetomyself/ruyihttp/actions/runs/45341302623) loaded all six dylibs from the installed package. Each Mach-O load command reported minimum macOS 15.0. HTTP/1, H2 and H3 worked; H3 returned measured TLS 1.3/ALPN, cipher, resumption flag and the selected Firefox profile. Six native H3 tests (including nondefault Firefox 158), ten two-hop proxy tests and the H2 EOF controls passed. The earlier candidate transported H3 but returned a null TLS report; it was not admitted. The donor patch is recorded in [Intel build provenance](../native/darwin_x86_64/provenance.json).
