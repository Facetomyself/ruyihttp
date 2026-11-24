# Native runtime matrix

`ruyihttp` has ready native runtimes for five targets. Each ready directory is a complete
set; do not mix core/QUIC/NSS files across directories.

| Directory | Status | Runtime | Source |
| --- | --- | --- | --- |
| `win_amd64/` | ready | NSS 3.131 / Neqo 0.32.0 | original ruyihttp 0.9.0 wheel |
| `darwin_arm64/` | ready | NSS 3.132 / Neqo 0.33.0 | ruyijs 0.4.1 macOS wheel |
| `linux_x86_64/` | ready | NSS 3.132 / Neqo 0.33.0 | ruyijs 0.4.1 manylinux wheel |
| `darwin_x86_64/` | ready | NSS 3.132 / Neqo 0.33.0 | pinned source build on Intel macOS 15 |
| `linux_aarch64/` | ready | NSS 3.132 / Neqo 0.33.0 | pinned source build on Ubuntu 24.04 ARM64 |

`ruyihttp/runtime-manifest.json` is the authoritative list. Each ready directory
has `provenance.json` and `SHA256SUMS`.

macOS ARM64 and Linux x86_64 were imported from `Facetomyself/ff-ruyijs` 0.4.1 at
`0b02c04fb8f2b54d5b66ac0dddba1a1711f1a89c`. The wheel SHA-256 values are in the
platform `provenance.json`.

Verify with:

```sh
python tools/build_native.py --check
python tools/verify_runtime.py
```
