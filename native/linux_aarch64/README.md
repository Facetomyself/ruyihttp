# Linux aarch64 native runtime (build-required)

This slot is empty. The Python path, wheel tag and runtime manifest entry exist,
but no `libnecko_core.so` or `libnecko_quic.so` is checked in.

Build the private Necko/NSS candidate for aarch64 from pinned and recorded source inputs. Keep `ff-ruyijs` and the historical x86_64 binary set as comparison references. The standalone SpiderMonkey donor is separate from this Necko ABI. Before placing a new candidate in this slot, validate this complete set:

- `libnecko_core.so`
- `libnecko_quic.so`
- `libnss3.so`, `libnssutil3.so`, `libssl3.so`
- `libnspr4.so`, `libplc4.so`, `libplds4.so`
- `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so`
- `libsqlite3.so`, `libnssckbi.so`, `libnsssysinit.so`

The expected runtime is NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 with a glibc 2.39
floor. `setup.py` raises `native runtime missing` instead of packaging another
platform's binary.

Run the read-only preflight from the project root:

```sh
python3 -B tools/check_linux_candidate.py /absolute/path/to/runtime --arch aarch64
```

This checks 14 ELF shared objects, 31 defined core functions, two QUIC bridge functions, the dynamic dependency names, sibling-only loader paths for the two bridges, and parsed `GLIBC_*` requirements up to 2.39. The tool neither loads libraries nor marks the manifest ready. Next verify runtime versions and real local HTTP/2 and QUIC behavior on the target architecture before promoting the slot.
