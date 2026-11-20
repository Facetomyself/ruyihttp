# Third-party notices

The Python sources retain their Mozilla Public License 2.0 notices. See
`LICENSE`. Bundling native libraries does not change the licensing of their
covered source files.

| Component | Version / reference | Upstream |
| --- | --- | --- |
| ruyihttp Python package | 0.9.0, source-maintenance fork | Original PyPI `ruyihttp` wheel |
| Standalone Necko core (Windows) | 0.8.2, locally adapted | Mozilla Necko plus local wrappers |
| Standalone Necko core (macOS/Linux) | ff-ruyijs 0.4.1 native ABI | `Facetomyself/ff-ruyijs` |
| Firefox / Necko / mozglue / roots and suffix data | Windows profile 159; macOS/Linux donor from ff-ruyijs 0.4.1 | https://github.com/mozilla-firefox/firefox |
| NSS | 3.131 on Windows; 3.132 on macOS/Linux | https://firefox-source-docs.mozilla.org/security/nss/ |
| NSPR | 4.40 | https://firefox-source-docs.mozilla.org/nspr/ |
| Neqo | 0.32.0 on Windows; 0.33.0 on macOS/Linux | https://github.com/mozilla/neqo |
| nss-rs | 0.16.1, locally modified in ff-ruyijs | https://github.com/mozilla/nss-rs |
| SQLite | Bundled in the Linux runtime as `libsqlite3.so`; also used by NSS softoken | https://www.sqlite.org/ |

## Native file sets

- Windows: `necko_core.dll`, `necko_quic.dll`, `nss3.dll`, `softokn3.dll`,
  `freebl3.dll`, `mozglue.dll`. NSPR is included in this `nss3.dll` build.
- macOS arm64: `libnecko_core.dylib`, `libnecko_quic.dylib`, `libnss3.dylib`,
  `libsoftokn3.dylib`, `libfreebl3.dylib`, `libmozglue.dylib`.
- Linux x86_64: `libnecko_core.so`, `libnecko_quic.so`, `libnss3.so`,
  `libnssutil3.so`, `libssl3.so`, `libnspr4.so`, `libplc4.so`, `libplds4.so`,
  `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so`, `libsqlite3.so`,
  `libnssckbi.so`, `libnsssysinit.so`.

Mozilla's collected license and copyright notices are retained in
`ruyihttp/licenses/firefox-license.html` and
`ruyihttp/licenses/firefox-notice.txt`. Additional Rust dependency license texts
and an index are included in the same directory.

## ff-ruyijs licensing

The macOS arm64 and Linux x86_64 native runtimes were imported from
`Facetomyself/ff-ruyijs` 0.4.1 (`ruyijs` wheels). `ff-ruyijs` is dual-licensed:

- GNU Affero General Public License v3.0 only (AGPL-3.0-only), or
- a commercial license from the author.

Mozilla-derived files remain MPL-2.0 under either choice. AGPL obligations apply
if the binary is distributed or a modified version is offered to users over a
network. This repository is published; see `docs/licensing.md` before
redistributing wheels or exposing a hosted service.

## Corresponding source status

MPL-2.0 section 3.2 requires making the corresponding Source Code Form of
covered software available to recipients of its executable form, including
covered modifications. This repository contains Python sources, prebuilt native
libraries, per-platform provenance and hashes. The full ff-ruyijs native source
and build scripts live in `Facetomyself/ff-ruyijs`; redistributors of these
binaries either point recipients at that source or obtain terms that cover the
distribution.

Official license and guidance:
https://www.mozilla.org/en-US/MPL/2.0/ and
https://www.mozilla.org/en-US/MPL/2.0/FAQ/.
No rights to Mozilla or Firefox trademarks are granted.
