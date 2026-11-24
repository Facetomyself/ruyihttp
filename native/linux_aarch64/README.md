# Linux aarch64 native runtime

The checked-in `manylinux_2_39_aarch64` runtime was built and tested on GitHub's
Ubuntu 24.04 ARM64 runner, including a clean installed-wheel HTTP/1.1, NSS HTTP/2,
and NSS/Neqo HTTP/3 exchange. See [provenance.json](provenance.json) for the exact
source pins, run and wheel digest, and [SHA256SUMS](SHA256SUMS) for the native bytes.
The standalone SpiderMonkey donor is separate from this Necko ABI. The complete set is:

- `libnecko_core.so`
- `libnecko_quic.so`
- `libnss3.so`, `libnssutil3.so`, `libssl3.so`
- `libnspr4.so`, `libplc4.so`, `libplds4.so`
- `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so`
- `libsqlite3.so`, `libnssckbi.so`, `libnsssysinit.so`

The runtime is NSS 3.132 / NSPR 4.40 / Neqo 0.33.0. The wheel's supported
floor is glibc 2.39; `auditwheel` agrees. The manifest inventory and exact hashes
are required for packaging.

Run the read-only preflight from the project root:

```sh
python3 -B tools/check_linux_candidate.py /absolute/path/to/runtime --arch aarch64
```

This checks 14 ELF shared objects, 31 defined core functions, two QUIC bridge functions, the dynamic dependency names, sibling-only loader paths for the two bridges, and parsed `GLIBC_*` requirements up to 2.39. The tool neither loads libraries nor marks the manifest ready. Next verify runtime versions and real local HTTP/2 and QUIC behavior on the target architecture before promoting the slot.
