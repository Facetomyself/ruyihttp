# Changelog

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
