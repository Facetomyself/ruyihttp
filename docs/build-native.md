# Building and importing native runtimes

This repository does not rebuild Firefox, NSS or Neqo by itself. The Python
package is maintained here; the native runtimes are imported from a pinned
`ruyijs` / `ff-ruyijs` build and recorded with hashes.

## Fast path: import a pinned wheel

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

The script copies the platform libraries into `native/<platform>/`, writes
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

## Source rebuild path

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
| macOS arm64 | 3.132 | 4.40 | 0.33.0 | 159.0 |
| Linux x86_64 | 3.132 | 4.40 | 0.33.0 | 159.0 |

`ruyihttp/_nss.py` reads `ruyihttp/runtime-manifest.json` and rejects a library
whose `necko_tls_nss_version()` does not match the platform entry.

## Adding a build-required platform

1. Build or import the native runtime.
2. Add the platform key to `PLATFORM_FILES` in `tools/build_native.py`.
3. Add the platform to `PLATFORMS` and `host_platform()` in `setup.py`.
4. Add a `ready` entry to `ruyihttp/runtime-manifest.json`.
5. Add a contract test that the wheel copies the expected library names.
6. Run the installed-wheel smoke on that platform.
