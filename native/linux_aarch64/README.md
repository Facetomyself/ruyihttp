# Linux aarch64 native runtime

The checked-in `manylinux_2_31_aarch64` runtime was built in a digest-pinned
Debian Bullseye container on a native Ubuntu 24.04 ARM64 runner. The [source build
and modern qualification](https://github.com/Facetomyself/ruyihttp/actions/runs/45792538631)
and [independent Bullseye qualification](https://github.com/Facetomyself/ruyihttp/actions/runs/45796424436)
used the same wheel bytes. See [provenance.json](provenance.json) for the pins,
ELF requirements and hosted proofs, and [SHA256SUMS](SHA256SUMS) for the native
inventory. The standalone SpiderMonkey donor is separate from this Necko ABI.
The complete set is:

- `libnecko_core.so`
- `libnecko_quic.so`
- `libnss3.so`, `libnssutil3.so`, `libssl3.so`
- `libnspr4.so`, `libplc4.so`, `libplds4.so`
- `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so`
- `libsqlite3.so`, `libnssckbi.so`, `libnsssysinit.so`

The runtime uses Firefox 161.0 sources with NSS 3.133 / NSPR 4.40 / Neqo 0.34.0.
`auditwheel show` inferred `manylinux_2_31_aarch64`; the highest required ELF
glibc symbol was `GLIBC_2.30`, while the independent installed-wheel runtime
floor was glibc 2.31. CPython 3.10 and 3.14 passed HTTP/1.1, HTTP/2, HTTP/3 body
ABI v1 with two simultaneous owners, and exact-slot Firefox 159/160/161 wire
parity with fresh TLS permutation witnesses. Clean Bullseye pip rejected the
v0.9.3 wheel; modern glibc upgraded it in place.

Run the read-only preflight from the project root:

```sh
python3 -B tools/check_linux_candidate.py /absolute/path/to/runtime --arch aarch64 --baseline
```

The preflight checks all 14 ELF shared objects for defined ABI exports, `DT_NEEDED`,
`DT_RUNPATH=$ORIGIN`, and the `GLIBC`, `GLIBCXX`, `CXXABI` and `GCC` version families.
The read-only helper establishes a static ABI bound. Hosted installed-wheel
qualification establishes the independent runtime floor before admission.
