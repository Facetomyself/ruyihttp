# Native runtime matrix

`ruyihttp` has ready native runtimes for five targets. Each ready directory is a complete
set; do not mix core/QUIC/NSS files across directories.

| Directory | Status | Runtime | Source |
| --- | --- | --- | --- |
| `win_amd64/` | ready | NSS 3.133 / Neqo 0.34.0 | exact six DLLs from LoseNine's official ruyihttp 0.11.0 PyPI wheel; import only |
| `darwin_arm64/` | ready | NSS 3.133 / Neqo 0.34.0 | pinned source build on Apple Silicon macOS; minOS 26.0 |
| `linux_x86_64/` | ready | NSS 3.133 / Neqo 0.34.0 | pinned source build on Ubuntu 24.04 x86_64 |
| `darwin_x86_64/` | ready | NSS 3.133 / Neqo 0.34.0 | pinned source build on Intel macOS 15 |
| `linux_aarch64/` | ready | NSS 3.133 / Neqo 0.34.0 | pinned source build on Ubuntu 24.04 ARM64 |

`ruyihttp/runtime-manifest.json` is the authoritative list. Each ready directory
has `provenance.json` and `SHA256SUMS`.

The historical macOS ARM64 bridge reported `tls: null`; the current source
build reports measured H3 NSS/TLS metadata. The H3 wire and certificate checks
apply to both. The Windows 0.11.0 donor preserves the `NSS/Neqo` H3 TLS
shape and legacy JSON body interface; its Necko core ABI is v1. The immutable
Windows 0.9.0 pip-upgrade source is separate from the active runtime in
[its baseline record](../ci/baselines/windows-0.9.0.json). Both Linux and both
macOS architectures ship pinned source builds with optional binary H3 body ABI v1.
Each platform's provenance identifies the exact native bytes.

Verify with:

```sh
python tools/build_native.py --check
python tools/verify_runtime.py
```
