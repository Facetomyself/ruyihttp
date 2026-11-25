# Native maintenance tools

These scripts keep the checked-in native runtimes honest. They do not rebuild
Firefox/NSS by themselves.

| Script | Purpose |
| --- | --- |
| `build_native.py --inspect-wheel <wheel> --platform <platform>` | Read declared native entries with bounded ZIP inspection, verify their names and ELF/Mach-O/PE architecture, and report hashes. |
| `build_native.py --wheel <wheel> --platform <platform>` | Historical import path. Validates the entire selected set before touching native files or the runtime manifest. |
| `build_native.py --check` | Verify every ready platform's files against the manifest hashes. |
| `verify_runtime.py` | Check the required `necko_*` exports and NSS version markers. |
| `check_linux_candidate.py DIR --arch aarch64` | Read-only ELF, ABI, loader-path and glibc dependency preflight for a complete Linux candidate. Use `--reference` for historical artifact analysis; no runtime qualification. |

Use the [Native runtime qualification and source candidates workflow](../.github/workflows/native-arm64-intel.yml)
for POSIX `rebuild` (pinned builds) or `requalify` (the exact native bytes of a
named diagnostic artifact rebuilt into a fresh candidate wheel). Both run
installed wheels on CPython 3.10 and 3.14. Windows uses the `verify` mode with
its original DLL set.

For promotion, download the successful target job's `verified-native-wheel`
and `native-evidence` artifacts. Save the read-only GitHub Actions API responses
for the run, its jobs and its artifacts, then execute from the project root:

```sh
python3 -B tools/promote_native_candidate.py PLATFORM WHEEL EVIDENCE_DIR RUN_JSON JOBS_JSON ARTIFACTS_JSON
python3 -B tools/build_native.py --check
```

Promotion requires exact digests and a successful native H3 binary/JSON and
owner-thread witness on both interpreter endpoints. The proof pins the wheel,
native hashes, source build run and qualification run in the platform provenance.
