# Licensing and distribution

This is a public source-maintenance tree. Publishing it does not rewrite the
licenses of the native runtimes it bundles.

## Python package

`ruyihttp/` retains the Mozilla Public License 2.0 notices. See `LICENSE`.
Mozilla-derived Firefox / Necko / NSS / NSPR code is MPL-2.0. Keep the license
and notice files when redistributing a wheel.

## macOS and Linux native runtimes

Earlier builds imported macOS arm64 and Linux x86_64 donor wheels. The 0.9.1 POSIX sets use pinned ff-ruyijs and Firefox sources; the corresponding revisions and local patch hashes are recorded in each platform’s provenance. See [source rebuild instructions](build-native.md).

`ff-ruyijs` is dual-licensed:

- AGPL-3.0-only, or
- a commercial license from the author.

Mozilla-derived files remain MPL-2.0 under either choice. The AGPL obligations
apply if you distribute the binary or let users interact with a modified version
over a network. This repository is published, so anyone redistributing a wheel
built from it must pick AGPL compliance or a commercial license from the
`ff-ruyijs` author before shipping.

## Windows native runtime

The Windows DLL set is an unchanged import from [LoseNine's `ruyihttp 0.11.0`
PyPI wheel](https://pypi.org/project/ruyihttp/0.11.0/). The published wheel contains
those binaries and attribution notices but no native source, and the source
repository listed in its metadata did not return a public snapshot when checked.
The [Windows provenance](../native/win_amd64/provenance.json) records the exact wheel
and DLL hashes. The supplemental Mozilla and Rust notices are shipped with the
wheel and indexed in [upstream-notices.json](../native/win_amd64/upstream-notices.json).

## Corresponding source

MPL-2.0 section 3.2 requires making the corresponding source of covered binary
code available to recipients. This tree records the native provenance in
`native/<platform>/provenance.json` and the platform manifest. The full
`ff-ruyijs` native source and build scripts live in
`Facetomyself/ff-ruyijs`; a redistributor of these binaries must either:

1. point recipients at that corresponding source and keep the build scripts
   available, or
2. obtain terms that cover the distribution.

This note is an engineering record, not legal advice.
