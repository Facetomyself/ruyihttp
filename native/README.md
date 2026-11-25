# Native runtime matrix

`ruyihttp` has ready native runtimes for five targets. Each ready directory is a complete
set; do not mix core/QUIC/NSS files across directories.

| Directory | Status | Runtime | Source |
| --- | --- | --- | --- |
| `win_amd64/` | ready | NSS 3.131 / Neqo 0.32.0 | original ruyihttp 0.9.0 wheel |
| `darwin_arm64/` | ready | NSS 3.132 / Neqo 0.33.0 | pinned source build on Apple Silicon macOS; minOS 26.0 |
| `linux_x86_64/` | ready | NSS 3.132 / Neqo 0.33.0 | pinned source build on Ubuntu 24.04 x86_64 |
| `darwin_x86_64/` | ready | NSS 3.132 / Neqo 0.33.0 | pinned source build on Intel macOS 15 |
| `linux_aarch64/` | ready | NSS 3.132 / Neqo 0.33.0 | pinned source build on Ubuntu 24.04 ARM64 |

`ruyihttp/runtime-manifest.json` is the authoritative list. Each ready directory
has `provenance.json` and `SHA256SUMS`.

The historical macOS ARM64 bridge reported `tls: null`; the current source
build reports measured H3 NSS/TLS metadata. The H3 wire and certificate checks
apply to both. Windows keeps its original NSS 3.131 / Neqo 0.32.0 set and the
historical `NSS/Neqo` H3 TLS shape. Linux ARM64, Linux x86_64 and Apple Silicon
ship pinned source builds with optional binary H3 body ABI v1. Each platform's
provenance identifies the exact native bytes.

Verify with:

```sh
python tools/build_native.py --check
python tools/verify_runtime.py
```
