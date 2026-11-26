# Building and importing native runtimes

RuyiHttp 0.9.4 retains exactly the six Windows x64 DLLs from upstream PyPI 0.11.0; `python -B tools/sync_windows_native.py --check-slot` verifies the selected bank. This is not a Windows source-build claim. Both Linux architectures and both macOS architectures are compiled on their target CPU from pinned upstream sources. The runtime manifest and each slot’s provenance identify its actual patches, hashes and loader policy. Packaging tracked libraries is separate from recompiling them.

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

These examples describe the original 0.9.0 donor sets, not a substitute for qualifying a current wheel: the script copies the platform libraries into `native/<platform>/`, writes
`provenance.json` and `SHA256SUMS`, and updates
`ruyihttp/runtime-manifest.json`.

To cross-build a wheel from another host, set `RUYIHTTP_PLATFORM` to the target
directory name. Linux tags also honor `RUYIHTTP_GLIBC`:

```sh
RUYIHTTP_PLATFORM=darwin_arm64 python -m pip wheel --no-build-isolation --no-deps -w dist .
RUYIHTTP_PLATFORM=linux_x86_64 RUYIHTTP_GLIBC=2.31 python -m pip wheel --no-build-isolation --no-deps -w dist .
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

The [native workflow](../.github/workflows/native-arm64-intel.yml) records the host architecture, upstream Git revisions and file inventory. It calls [the native build script](../ci/build_native_target.sh) on `ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15-intel` or `macos-26`. The donor commit `f557fcd437aae5f18f313eb330bd3ef50f5fc7df` still has its original Firefox 160 gitlink `2887d9de1f69c0e9776413da80e7ba0d1225dd9b`. The [Firefox 161 recipe](../tools/posix_firefox161.py) verifies that gitlink, then deliberately uses the independent official `FIREFOX_161_0_RELEASE` commit `9c70d5d48c866afc2e581d6b7ff6de98a1371d99`. The embedded Mozilla/Neqo/NSS inputs, dependency lock and ordered adapter patches are verified before promotion. Native source version and per-session Firefox selection are distinct. Per-slot provenance is the authority for any additional patches, including the [Gecko HTTP/3 policy adaptations](../native/patches/GECKO_H3_POLICY.md). Pinning NSS/Neqo versions alone does not configure the browser’s network preferences.

1. Compile on the target CPU. For Linux, inspect the entire ELF set, exported ABI, dependencies and `$ORIGIN` search paths. For macOS, check each Mach-O architecture, deployment load command and sibling install names. Derive the wheel minimum from the binaries, rather than the SDK version or the runner label.
2. Build a candidate wheel, check its hashes against its manifest and inspect its members. Check Linux platform policy with `auditwheel show`. For Linux 0.9.4, use the baseline build in a pinned Bullseye userland, inspect every `GLIBC/GLIBCXX/CXXABI/GCC` requirement and loader path, then [verify the same artifact on actual glibc 2.31](linux-glibc231-qualification.md). The measured tag cannot be lowered by repacking old runtime bytes.
3. Install the wheel in a fresh target venv outside the checkout, clear all native library overrides, and verify that the process loads libraries from the installed package. Exercise real HTTP/1, TLS/HTTP/2, UDP/HTTP/3 and negative controls. A build job or a `dlopen` alone does not qualify the slot.
4. Admit exactly the tested files, recording hashes, source revisions, build and verification receipts. Repack from the committed bytes and repeat the installed-wheel gate. The [Wheels workflow](../.github/workflows/wheels.yml) produces downloadable CI artifacts, not PyPI releases.

## Body ABI and reproducible promotion

The POSIX source targets apply `native/patches/h3-body-abi-v1.patch`; macOS also applies the negotiated TLS reporting and global session handle patches. The versioned data ABI bounds buffers and byte counts; it runs only on the owning connection thread and never keeps a caller’s buffer. Artifacts from a failed source job remain diagnostic until independent target verification ties the exact hashes to a successful install and wire test. A matching build receipt alone is not release qualification.

The per-platform `native-provenance.json` shipped in the installed wheel describes native sources and patches; its file inventory must agree with `runtime-manifest.json`. The four profile/root inputs are checked against their exact byte hashes at build time and after installing, including on Windows. A release upgrade uses ordinary pip version comparison, not `--force-reinstall`: Windows starts from the pinned original PyPI 0.9.0 wheel; other platforms reconstruct the prior five-platform distribution at `ea44f8f`. All five wheel jobs additionally reconstruct this fork at `fae13b0` (0.9.1), then verify ordinary upgrade, wire requests, installed identity, and the three removed roots against a retained positive control. The 0.9.4 release-format wheel jobs also retain the v0.9.2 negative wire control and exercise upgrade from the exact v0.9.3 release. For the new Linux floor, incompatible older wheels are never installed by forcing pip; use the dedicated Bullseye gate and ordinary clean installation instead.

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

See the [current per-platform matrix](platform-support.md) for the shipped NSS / NSPR / Neqo versions. The default synthetic profile remains 159; 160 and 161 are opt-in.

`ruyihttp/_nss.py` reads `ruyihttp/runtime-manifest.json` and rejects a library
whose `necko_tls_nss_version()` does not match the platform entry.

## Adding a build-required platform

1. Build or import the native runtime.
2. Add the platform key to `PLATFORM_FILES` in `tools/build_native.py`.
3. Add the platform to `PLATFORMS` and `host_platform()` in `setup.py`.
4. Add a `ready` entry to `ruyihttp/runtime-manifest.json`.
5. Add a contract test that the wheel copies the expected library names.
6. Run the installed-wheel smoke on that platform.
