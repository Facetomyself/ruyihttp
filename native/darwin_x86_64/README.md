# Intel macOS native runtime (build-required)

This slot is empty. The Python path, wheel tag and runtime manifest entry exist,
but no `libnecko_core.dylib` or `libnecko_quic.dylib` is checked in.

To populate it, build on an Intel macOS host with the ff-ruyijs native sources
and copy the whole set here:

- `libnecko_core.dylib`
- `libnecko_quic.dylib`
- `libnss3.dylib`
- `libsoftokn3.dylib`
- `libfreebl3.dylib`
- `libmozglue.dylib`

The expected runtime is NSS 3.132 / NSPR 4.40 / Neqo 0.33.0. `setup.py` raises
`native runtime missing` instead of packaging another platform's binary.
