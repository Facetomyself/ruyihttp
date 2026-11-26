# Changelog

## 0.9.4 — authenticated CONNECT-UDP and lower Linux runtime floor (2026-11-26)

- Add an explicit HTTP/3 MASQUE client via the optional `masque` extra. The outer layer authenticates the proxy; the inner origin remains native Firefox NSS/Neqo. Proxy and origin credentials and trust are separate. An explicit route does not fall back to origin TCP/direct UDP or perform local origin resolution.
- Qualify ordinary/custom CONNECT-UDP targets, independent relay egress, end-to-end GET/POST bodies and same-tunnel streams, redirects, native certificate failures and authenticated HTTP/3 path budget. Test against a second pinned, loopback-only `masque-go` implementation. See [proxy details and limits](docs/masque.md).
- Build and inspect fresh 14-library Linux x86_64 and AArch64 runtime sets in Bullseye. Independently install the identical release-format artifact in glibc 2.31 userlands at CPython 3.10 and 3.14 and exercise the native protocols plus MASQUE. The old v0.9.3 wheels remain at glibc 2.39; Windows/macOS native sets and deployment floors remain unchanged. See [floor checks](docs/linux-glibc231-qualification.md).

## 0.9.3 — same-platform Firefox network behavior (2026-11-26)

- Correct the desktop Linux ARM64 public UA at the actual Firefox **123** release boundary. Through 122 the Linux token remains host-derived; native file selection continues to use the actual architecture on both sides.
- Align the Linux/macOS Neqo adapters with Gecko's release preferences: negotiate Extended CONNECT separately from WebTransport, use Gecko's version preference and receive windows, and correct the macOS Initial source connection-ID length and NSS delegated-credentials setting. These are real native protocol options, not cosmetic bytes. Keep the Windows ABI and its upstream DLLs unchanged.
- Promote only verified native outputs. Each target compares against signed official en-US builds for 159, 160 and 161 on the same OS/architecture. Check raw UA and ordered headers, TCP/QUIC ClientHello structure, H2 control frames and HEADERS priority, ordered H3 SETTINGS, QUIC Initial vs negotiated versions, selected peer transport parameters and fresh-extension-order behavior. [Scope](docs/firefox-profile-wire.md), [raw references](docs/firefox-reference-collection.md), [H2 supplement](docs/firefox-h2-preface.md).
- Separate the original PyPI 0.11.0 Windows wheel, the previously published fork 0.9.2, and the current Windows wheel; collect actual TLS/H1/H2/H3 observations and compare to a fresh official Firefox 161. Add ordinary upgrade from the exact public 0.9.2 asset alongside the existing baselines. The `v0.9.2` tag/Release is the immutable comparison, not a republished wheel.

## 0.9.2 — selective upstream data, profiles and native runtimes (2026-11-26)

- Update the packaged TLS server roots (121 → 118), one unchanged issuance cutoff, and the public suffix list (+70 / −5 rules) against both the official Mozilla 161 release and upstream PyPI 0.11.0. Test same-/cross-site Strict cookies and compare retired roots against a retained trust control.
- Add explicit Firefox 160/161 selections; keep 159 as the default. Capture H1/H2/H3 with all three selections, and compare bounded fields to official Mozilla browser observations. See [wire reference and differences](docs/firefox-profile-wire.md).
- Import the six verified Windows 0.11.0 DLLs, preserving the existing JSON body ABI. Rebuild POSIX slots on their native runners against pinned Firefox 161 sources when their gates pass. The [platform matrix](docs/platform-support.md) and packaged provenance, not the selected profile name, identify the actual native library revisions.
- Keep the fork's POST replay guard, bounded fallback, TLS trust rotation, H2 flow control and H3 STOP/optional binary body ABI. Requalify ordinary upgrades from both preceding baselines. This version is an independent fork release, not the upstream 0.11.0 package.

## 0.9.1 — transport performance and native qualification (2026-11-26)

- Honor H3 upload stop without losing the final response; share a healthy TCP fallback for an unusable Alt-Svc route and bound retry/caching costs. Preserve TLS verification and all request replay controls.
- Isolate slow H2 readers, enforce peer/local stream capacity, and adapt idle polling. Batch connection credit with ordinary outgoing frames when there is ample room. The exact H2 wire and memory trade-offs are described in `docs/h2-flow-control.md`.
- Avoid temporary integer lists on native reads. Cache read-only trust material by its exact source/contents and constraints, with fresh hostname/chain checks. Ship and check the platform provenance alongside profile/trust data.
- Add optional binary H3 body v1 to source-built POSIX runtimes. Keep JSON fallback for older bridges including the original Windows DLLs. Qualify all five native wheel targets on CPython 3.10 and 3.14, including in-place upgrade and real UDP/HTTP/3. Add manual/weekly installed-wheel performance reporting without a shared-runner speed threshold.

### Included request-boundary fixes (2026-11-25)

- A reset on a pooled connection no longer implicitly repeats a possibly processed POST. Safe methods, requests known not to have been sent, and explicit protocol rejections retain their recovery paths. An ambiguous write raises a connection error; this does not establish that the server did nothing. Applications may explicitly configure a retry policy for operations they can safely repeat.
- IP-literal schemeful sites use the full address. Target-owned `SameSite=Strict` cookies are withheld for cross-IP fetches, even when the addresses share their final octets. DNS names still use their registrable domain.
- Pool acquisition, eligible cross-origin DNS checks and TCP/TLS establishment now share one connect deadline per attempt. If certificate or address checks prevent coalescing, the dial reuses the DNS answer and remaining budget. Local SOCKS resolution is bounded; remote-DNS schemes keep passing the original destination name to the proxy.
- HTTP/2 preserves a complete early response followed by `RST_STREAM(NO_ERROR)` and stops pulling additional upload chunks once that signal is processed. Incomplete responses and other reset codes still fail.

To repeat the regression gates, install the wheel and PySocks in a fresh environment with an OpenSSL CLI. From outside the checkout run `bash /path/to/checkout/ci/verify_request_boundaries.sh`. All network peers in these gates use loopback.

## 0.9.0-private.1

- Added a platform runtime manifest with Windows x64, macOS arm64 and Linux x86_64.
- Added macOS arm64 `libnecko_quic.dylib` and the full NSS 3.132 sibling set.
- Added Linux x86_64 `libnecko_core.so`, `libnecko_quic.so`, NSS/NSPR/SSL libraries
  and `$ORIGIN` runpaths.
- Added Linux user-agent handling and platform profile selection.
- Replaced the hard-coded NSS 3.131 check with a manifest-driven expected version.
- Added `tools/build_native.py`, `tools/verify_runtime.py`, platform docs and
  contract tests for all ready platforms.
- Windows live HTTPS remains 200 / ALPN h2 / NSS 3.131.
- macOS arm64 live HTTPS verified on the Mac mini: 200 / ALPN h2 / NSS 3.132.
- Linux x86_64 wheel cross-built; ELF/ABI/manifest checks pass, live smoke still
  needs an x86_64 Linux host.
