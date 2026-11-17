# Linux aarch64 native runtime (build-required)

This slot is empty. The Python path, wheel tag and runtime manifest entry exist,
but no `libnecko_core.so` or `libnecko_quic.so` is checked in.

Build on an aarch64 Linux host with the ff-ruyijs native sources and copy the
whole set here:

- `libnecko_core.so`
- `libnecko_quic.so`
- `libnss3.so`, `libnssutil3.so`, `libssl3.so`
- `libnspr4.so`, `libplc4.so`, `libplds4.so`
- `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so`
- `libsqlite3.so`, `libnssckbi.so`, `libnsssysinit.so`

The expected runtime is NSS 3.132 / NSPR 4.40 / Neqo 0.33.0 with a glibc 2.39
floor. `setup.py` raises `native runtime missing` instead of packaging another
platform's binary.
