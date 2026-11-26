# Third-party notices

The Python sources retain their Mozilla Public License 2.0 notices. See
`LICENSE`. Bundling native libraries does not change the licensing of their
covered source files.

| Component | Version / reference | Upstream |
| --- | --- | --- |
| ruyihttp Python package | Fork based on 0.9.0, with local transport and other changes | Original PyPI `ruyihttp` wheel |
| Standalone Necko core (Windows) | Unchanged DLLs imported from the upstream 0.11.0 wheel | [LoseNine's PyPI publication](https://pypi.org/project/ruyihttp/0.11.0/) |
| Standalone Necko core (macOS/Linux) | pinned ff-ruyijs native sources, local ABI patches | [cutetailbud/ff-ruyijs](https://github.com/cutetailbud/ff-ruyijs) |
| Firefox / Necko / mozglue / roots and suffix data | Windows runtime built against Firefox 161 per donor; macOS/Linux from pinned donor and Firefox sources | https://github.com/mozilla-firefox/firefox |
| NSS | 3.133 on all five targets | https://firefox-source-docs.mozilla.org/security/nss/ |
| NSPR | 4.40 | https://firefox-source-docs.mozilla.org/nspr/ |
| Neqo | 0.34.0 on all five targets | https://github.com/mozilla/neqo |
| nss-rs | 0.16.2 (Windows donor inventory; POSIX uses the pinned Firefox vendor overlay) | https://github.com/mozilla/nss-rs |
| SQLite | Bundled in the Linux runtime as `libsqlite3.so`; also used by NSS softoken | https://www.sqlite.org/ |

## Native file sets

- Windows: `necko_core.dll`, `necko_quic.dll`, `nss3.dll`, `softokn3.dll`,
  `freebl3.dll`, `mozglue.dll`. NSPR is included in this `nss3.dll` build.
- macOS arm64 and x86_64: `libnecko_core.dylib`, `libnecko_quic.dylib`, `libnss3.dylib`,
  `libsoftokn3.dylib`, `libfreebl3.dylib`, `libmozglue.dylib`.
- Linux x86_64 and aarch64: `libnecko_core.so`, `libnecko_quic.so`, `libnss3.so`,
  `libnssutil3.so`, `libssl3.so`, `libnspr4.so`, `libplc4.so`, `libplds4.so`,
  `libsoftokn3.so`, `libfreebl3.so`, `libfreeblpriv3.so`, `libsqlite3.so`,
  `libnssckbi.so`, `libnsssysinit.so`.

Mozilla's collected license and copyright notices are retained in
`ruyihttp/licenses/firefox-license.html` and
`ruyihttp/licenses/firefox-notice.txt`. The supplemental attribution files for
Windows are the donor's `firefox-161-license.html`, `rust-dependencies-windows-0.11.0.json`
and mapped Rust license texts in that directory. Their original wheel members
and SHA-256 digests are recorded separately in
[`native/win_amd64/upstream-notices.json`](native/win_amd64/upstream-notices.json).

## ff-ruyijs licensing

Earlier releases imported macOS arm64 and Linux x86_64 donor wheels. The current POSIX native sets are compiled from fixed ff-ruyijs/Firefox revisions with the patches recorded in each platform’s provenance. See `docs/build-native.md`. `ff-ruyijs` is dual-licensed:

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
and build scripts live in [the pinned donor](https://github.com/cutetailbud/ff-ruyijs/tree/f557fcd437aae5f18f313eb330bd3ef50f5fc7df) and [Firefox 161](https://github.com/mozilla-firefox/firefox/tree/9c70d5d48c866afc2e581d6b7ff6de98a1371d99); redistributors of these
binaries either point recipients at that source or obtain terms that cover the
distribution.

Official license and guidance:
https://www.mozilla.org/en-US/MPL/2.0/ and
https://www.mozilla.org/en-US/MPL/2.0/FAQ/.
No rights to Mozilla or Firefox trademarks are granted.
