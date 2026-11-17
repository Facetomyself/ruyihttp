# Licensing and distribution

This is a private maintenance tree. Private use lowers the practical risk but
does not rewrite the licenses of the native runtimes.

## Python package

`ruyihttp/` retains the Mozilla Public License 2.0 notices. See `LICENSE`.
Mozilla-derived Firefox / Necko / NSS / NSPR code is MPL-2.0. Keep the license
and notice files when redistributing a wheel.

## macOS and Linux native runtimes

The macOS arm64 and Linux x86_64 native runtimes were imported from
`Facetomyself/ff-ruyijs` 0.4.1 (`ruyijs` wheels).

`ff-ruyijs` is dual-licensed:

- AGPL-3.0-only, or
- a commercial license from the author.

Mozilla-derived files remain MPL-2.0 under either choice. The AGPL obligations
apply if you distribute the binary or let users interact with a modified version
over a network. If this tree is only used privately and is not distributed or
offered as a network service, the practical exposure is lower; if you publish
wheels or run it for external users, decide between AGPL compliance and a
commercial license before shipping.

## Windows native runtime

The Windows DLL set comes from the original `ruyihttp 0.9.0` wheel. Keep its
Mozilla notices and the `ruyihttp/licenses/` directory.

## Corresponding source

MPL-2.0 section 3.2 requires making the corresponding source of covered binary
code available to recipients. This tree records the native provenance in
`native/<platform>/provenance.json` and the platform manifest, but it does not
contain the full ff-ruyijs native source. Before distributing binaries, either:

1. publish the corresponding source and build scripts, or
2. obtain terms that cover the distribution, or
3. keep the build strictly private and do not distribute the binaries.

This note is an engineering record, not legal advice.
