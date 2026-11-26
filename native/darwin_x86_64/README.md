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

The pinned Firefox 161.0 runtime is NSS 3.133 / NSPR 4.40 / Neqo 0.34.0. The
[hosted qualification](https://github.com/Facetomyself/ruyihttp/actions/runs/45771612177)
verified the [six native hashes](SHA256SUMS), package-local dynamic loading, real
H1/H2/H3, strict IPv4/IPv6 H3 and NSS telemetry, same-slot official Firefox
159/160/161 comparisons with fresh TLS permutation witnesses, proxy and H2 EOF
cases, and in-place upgrades from the 0.9.0 fork on CPython 3.10 and 3.14. The
build retains binary H3 body ABI v1 and unique handles across owner threads;
both interpreters passed the 1,048,579-byte binary body and JSON controls. The
manifest requires the proven hashes during packaging.
