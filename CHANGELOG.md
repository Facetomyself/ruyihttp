# Changelog

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
