# Intel macOS native runtime

The checked-in `macosx_15_0_x86_64` runtime was source-built on an Intel macOS 15
runner. Every Mach-O file is thin x86_64 and records macOS 15.0 as its minimum.
See [provenance.json](provenance.json) for the pinned sources, native QUIC TLS
telemetry patch, runner evidence and wheel hash. The complete set is:

- `libnecko_core.dylib`
- `libnecko_quic.dylib`
- `libnss3.dylib`
- `libsoftokn3.dylib`
- `libfreebl3.dylib`
- `libmozglue.dylib`

The runtime is NSS 3.132 / NSPR 4.40 / Neqo 0.33.0. A clean installed-wheel
run validated all [six native hashes](SHA256SUMS), package-local dynamic
loading, HTTP/1.1, HTTP/2 and HTTP/3, six strict native H3 cases (including
Firefox 158 telemetry and certificate negatives), 10 two-hop proxy cases,
and 12 complete/3 truncated H2 EOF cases. The pinned rebuild adds binary H3
body ABI v1 and unique handles across owner threads. Both CPython 3.10 and 3.14
passed native body checks and the 1,048,579-byte binary/JSON controls. The source
job's evidence upload timed out; the independent installed-wheel run confirmed
the exact same six native file hashes and uploaded complete evidence. The
manifest requires those hashes during wheel packaging.
