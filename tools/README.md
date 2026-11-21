# Native maintenance tools

These scripts keep the checked-in native runtimes honest. They do not rebuild
Firefox/NSS by themselves.

| Script | Purpose |
| --- | --- |
| `build_native.py --inspect-wheel <wheel> --platform <platform>` | Read only the declared native entries with bounded ZIP inspection, verify their names and the Linux ELF architecture, and report hashes. Use this for reference wheels. |
| `build_native.py --wheel <wheel> --platform <platform>` | Historical import path. Validates the entire selected set before touching native files or the runtime manifest. |
| `build_native.py --check` | Verify every ready platform's files against the manifest hashes. |
| `verify_runtime.py` | Check the required `necko_*` exports and NSS version markers. |
| `check_linux_candidate.py DIR --arch aarch64` | Read-only ELF, ABI, loader-path and glibc dependency preflight for a complete Linux candidate. Use `--reference` for historical artifact analysis; no runtime qualification. |

The source-build path is documented in `../docs/build-native.md`. Keep the
imported wheel and its SHA-256 in `provenance.json`; do not silently replace a
runtime with a different build.
