# Building and importing native runtimes

RuyiHttp 0.9.1 keeps the original Windows x64 DLLs. Both Linux architectures and both macOS architectures are compiled on their target CPU from pinned upstream sources. The runtime manifest and each slot’s provenance identify its actual patches, hashes and loader policy. Packaging tracked libraries is separate from recompiling them.

## Historical import example (a disposable checkout only)

```sh
python tools/build_native.py \
  --wheel /path/to/ruyijs-0.4.1-py3-none-manylinux_2_39_x86_64.whl \
  --platform linux_x86_64
```

```sh
python tools/build_native.py \
  --wheel /path/to/ruyijs-0.4.1-py3-none-macosx_26_0_arm64.whl \
  --platform darwin_arm64
```

These examples describe the original 0.9.0 donor sets, not a substitute for qualifying 0.9.1: the script copies the platform libraries into `native/<platform>/`, writes
`provenance.json` and `SHA256SUMS`, and updates
`ruyihttp/runtime-manifest.json`.

To cross-build a wheel from another host, set `RUYIHTTP_PLATFORM` to the target
directory name. Linux tags also honor `RUYIHTTP_GLIBC`:

```sh
RUYIHTTP_PLATFORM=darwin_arm64 python -m pip wheel --no-build-isolation --no-deps -w dist .
RUYIHTTP_PLATFORM=linux_x86_64 RUYIHTTP_GLIBC=2.39 python -m pip wheel --no-build-isolation --no-deps -w dist .
```

## Verify what is checked in

```sh
python tools/build_native.py --check
python tools/verify_runtime.py
```

`--check` compares every ready platform file against the manifest hashes.
`verify_runtime.py` checks the required `necko_*` exports and NSS version
markers.

## Source-built targets: Linux and macOS on x86_64 and ARM64

The [native workflow](../.github/workflows/native-arm64-intel.yml) records the host architecture, upstream Git revisions and file inventory. It calls [the native build script](../ci/build_native_target.sh) on `ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15-intel` or `macos-26`. Both the donor commit `f557fcd437aae5f18f313eb330bd3ef50f5fc7df` and its Firefox gitlink `2887d9de1f69c0e9776413da80e7ba0d1225dd9b` are pinned; the runtime source version and the client-selected Firefox profile are distinct. Per-slot provenance is the authority for any additional patches.

1. Compile on the target CPU. For Linux, inspect the entire ELF set, exported ABI, dependencies and `$ORIGIN` search paths. For macOS, check each Mach-O architecture, deployment load command and sibling install names. Derive the wheel minimum from the binaries, rather than the SDK version or the runner label.
2. Build a candidate wheel, check its hashes against its manifest and inspect its members. Check Linux platform policy with `auditwheel show`. Linux packaging never lowers the 2.39 compatibility floor to match an older build machine.
3. Install the wheel in a fresh target venv outside the checkout, clear all native library overrides, and verify that the process loads libraries from the installed package. Exercise real HTTP/1, TLS/HTTP/2, UDP/HTTP/3 and negative controls. A build job or a `dlopen` alone does not qualify the slot.
4. Admit exactly the tested files, recording hashes, source revisions, build and verification receipts. Repack from the committed bytes and repeat the installed-wheel gate. The [Wheels workflow](../.github/workflows/wheels.yml) produces downloadable CI artifacts, not PyPI releases.

## Body ABI and reproducible promotion

The POSIX source targets apply `native/patches/h3-body-abi-v1.patch`; macOS also applies the negotiated TLS reporting and global session handle patches. The versioned data ABI bounds buffers and byte counts; it runs only on the owning connection thread and never keeps a caller’s buffer. Artifacts from a failed source job remain diagnostic until independent target verification ties the exact hashes to a successful install and wire test. A matching build receipt alone is not release qualification.

The per-platform `native-provenance.json` shipped in the installed wheel describes native sources and patches; its file inventory must agree with `runtime-manifest.json`. The four profile/root inputs are checked against their exact byte hashes at build time and after installing, including on Windows. A release upgrade uses ordinary pip version comparison, not `--force-reinstall`: Windows starts from the pinned original PyPI 0.9.0 wheel; other platforms reconstruct the prior five-platform distribution at `ea44f8f`.

## Historical rebuild path for imported libraries

The native C/C++/Rust sources and build scripts live in the ff-ruyijs tree, not
in this package by default. To rebuild from source:

1. Check out `Facetomyself/ff-ruyijs` at
   `0b02c04fb8f2b54d5b66ac0dddba1a1711f1a89c` (0.4.1 line), recorded in
   `native/<platform>/provenance.json`.
2. On macOS arm64, follow `ff-ruyijs/tools/build_necko_darwin.py` and
   `ff-ruyijs/tools/build_necko_quic.py`.
3. On Linux x86_64, follow `ff-ruyijs/tools/build_necko_linux.py --http3`.
4. Copy only the resulting `libnecko_core.*`, `libnecko_quic.*` and the matching
   NSS/NSPR/Neqo libraries into this tree.
5. Run `python tools/build_native.py --check` and `python tools/verify_runtime.py`.

Do not copy the ff-ruyijs Python helper or its whole runtime; ruyihttp only
consumes the native ABI.

Imported wheel pins:

| Platform | Wheel | SHA-256 |
| --- | --- | --- |
| macOS arm64 | `ruyijs-0.4.1-py3-none-macosx_26_0_arm64.whl` | `f85e54dcfed913d482509c2f86f598ad9b23e9dce422dd6706e25f45cd928b77` |
| Linux x86_64 | `ruyijs-0.4.1-py3-none-manylinux_2_39_x86_64.whl` | `f80de6b269e0bcef9fd6dccab6c722e57d6350ce5a5ecce5c68a96270b908d37` |

## Version rules

| Platform | NSS | NSPR | Neqo | Firefox profile |
| --- | --- | --- | --- | --- |
| Windows x64 | 3.131 | 4.40 | 0.32.0 | 159.0 |
| macOS arm64 / x86_64 | 3.132 | 4.40 | 0.33.0 | 159.0 |
| Linux x86_64 / aarch64 | 3.132 | 4.40 | 0.33.0 | 159.0 |

`ruyihttp/_nss.py` reads `ruyihttp/runtime-manifest.json` and rejects a library
whose `necko_tls_nss_version()` does not match the platform entry.

## Adding a build-required platform

1. Build or import the native runtime.
2. Add the platform key to `PLATFORM_FILES` in `tools/build_native.py`.
3. Add the platform to `PLATFORMS` and `host_platform()` in `setup.py`.
4. Add a `ready` entry to `ruyihttp/runtime-manifest.json`.
5. Add a contract test that the wheel copies the expected library names.
6. Run the installed-wheel smoke on that platform.
