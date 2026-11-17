# Native maintenance tools

These scripts keep the checked-in native runtimes honest. They do not rebuild
Firefox/NSS by themselves.

| Script | Purpose |
| --- | --- |
| `build_native.py --wheel <wheel> --platform <platform>` | Import a pinned ruyijs/ff-ruyijs wheel into `native/<platform>/`, write `provenance.json` and `SHA256SUMS`, update `ruyihttp/runtime-manifest.json`. |
| `build_native.py --check` | Verify every ready platform's files against the manifest hashes. |
| `verify_runtime.py` | Check the required `necko_*` exports and NSS version markers. |

The source-build path is documented in `../docs/build-native.md`. Keep the
imported wheel and its SHA-256 in `provenance.json`; do not silently replace a
runtime with a different build.
