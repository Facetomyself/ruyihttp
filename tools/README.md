# Native maintenance tools

These scripts keep the checked-in native runtimes honest. They do not rebuild
Firefox/NSS by themselves.

| Script | Purpose |
| --- | --- |
| `build_native.py --inspect-wheel <wheel> --platform <platform>` | Read declared native entries with bounded ZIP inspection, verify their names and ELF/Mach-O/PE architecture, and report hashes. |
| `build_native.py --wheel <wheel> --platform <platform>` | Historical POSIX import path. Validates the entire selected set before touching native files or the runtime manifest. |
| `sync_windows_native.py --wheel <wheel> [--apply]` | Read-only by default; verify the pinned PyPI 0.11.0 wheel, RECORD and PE ABI policy, then optionally update only the six Windows DLLs and their slot metadata. |
| `sync_windows_native.py --check-slot [--wheel <wheel>]` | Recompute Windows PE export inventory and check the tracked DLLs and metadata; with `--wheel`, also compare the exact donor bytes. |
| `build_native.py --check` | Verify every ready platform's files against the manifest hashes. |
| `verify_runtime.py` | Check the required `necko_*` exports and NSS version markers. |
| `check_linux_candidate.py DIR --arch aarch64 --baseline` | Read-only ABI preflight for all 14 ELF libraries, including native machine, bridge definitions, `DT_NEEDED`, `$ORIGIN`, and GLIBC/GLIBCXX/CXXABI/GCC version requirements. Use `--reference` without `--baseline` for historical artifact analysis. |

Use the [Native runtime qualification and source candidates workflow](../.github/workflows/native-arm64-intel.yml)
for POSIX `rebuild` (pinned builds) or `requalify` (the exact native bytes of a
named `source-native-wheel` artifact rebuilt into a fresh candidate wheel).
Both run installed wheels on CPython 3.10 and 3.14. Windows uses `platform=win_amd64`
with `mode=verify` to qualify the tracked DLL import on hosted Windows x64.

For promotion, download the successful target job's `verified-native-wheel`
and `native-evidence` artifacts. Save the read-only GitHub Actions API responses
for the run, its jobs and its artifacts, then execute from the project root:

```sh
python3 -B tools/promote_native_candidate.py PLATFORM WHEEL EVIDENCE_DIR RUN_JSON JOBS_JSON ARTIFACTS_JSON
python3 -B tools/build_native.py --check
```

Promotion requires exact digests, the [POSIX protocol policy](../native/patches/GECKO_H3_POLICY.md),
a successful native H3 binary/JSON and owner-thread witness, and three successful
same-slot official Firefox wire receipts on both interpreter endpoints. The
promoter recomputes the comparison against the current official fixture and pins
its digest, wheel and native hashes, and both run identities in the platform provenance.

For a Linux floor build, dispatch `mode=baseline` on a native Linux slot. The
hosted job builds in the pinned Bullseye loader/headers with pinned CPython,
Clang and Rust. `auditwheel show` must pass before the stamped `source-native-wheel`
is uploaded for the separate [Linux floor workflow](../.github/workflows/linux-minimum.yml).
A disposable wheel may carry the proposed tag while its bank manifest still
records the historical policy. A normal release build uses only an admitted tag.

Low-floor promotion also takes the two original `glibc231` ZIP artifacts from
that independent run (3.10 and 3.14), the original modern evidence and wheel ZIPs,
and the independent run/jobs/artifacts API responses. Download originals from
`repos/Facetomyself/ruyihttp/actions/artifacts/ARTIFACT_ID/zip` and leave them
intact; the promoter checks each ZIP against the hosted digest. For example:

```sh
python3 -B tools/promote_native_candidate.py \
  PLATFORM WHEEL EVIDENCE_DIR RUN_JSON JOBS_JSON ARTIFACTS_JSON \
  --native-evidence-zip NATIVE_EVIDENCE_ZIP --native-wheel-zip NATIVE_WHEEL_ZIP \
  --floor-run FLOOR_RUN_JSON --floor-jobs FLOOR_JOBS_JSON --floor-artifacts FLOOR_ARTIFACTS_JSON \
  --floor-cp310-zip FLOOR_CP310_ZIP --floor-cp314-zip FLOOR_CP314_ZIP \
  --check-only
```

After verification, rerun without `--check-only` to write the exact candidate
libraries, manifest, hashes and source/runtime provenance into the slot.
