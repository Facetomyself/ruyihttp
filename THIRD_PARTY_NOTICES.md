# Third-party notices

The Python sources retain their Mozilla Public License 2.0 notices. See LICENSE.
The bundled native libraries and data retain their existing licenses; distributing
them as DLLs or shared objects does not change the licensing of their covered source files.

| Component | Version / reference | Upstream |
| --- | --- | --- |
| Standalone Necko core | 0.8.2, locally adapted | Mozilla Necko plus local wrappers |
| Firefox / Necko / mozglue / root and suffix data | Firefox 159 (tag FIREFOX_159_0_RELEASE, revision 9a2dc53c369c7ae5172018b35988e1d2ffeff402) | https://github.com/mozilla-firefox/firefox |
| NSS | 3.131 | https://firefox-source-docs.mozilla.org/security/nss/ |
| NSPR | 4.40 | https://firefox-source-docs.mozilla.org/nspr/ |
| Neqo | 0.32.0, locally modified to reproduce earlier Firefox releases' QUIC behaviour | https://github.com/mozilla/neqo |
| nss-rs | 0.16.1, locally modified | https://github.com/mozilla/nss-rs |
| SQLite | Bundled in the Linux runtime as libmozsqlite3.so | https://www.sqlite.org/ |

The Windows runtime includes necko_core.dll, necko_quic.dll, nss3.dll,
softokn3.dll, freebl3.dll and mozglue.dll. NSPR is included in this nss3.dll build.
The Linux runtime includes libnecko_core.so, libnecko_quic.so, libnss3.so,
libnssutil3.so, libssl3.so, libsoftokn3.so, libfreebl3.so, libfreeblpriv3.so,
libnspr4.so, libplc4.so, libplds4.so and libmozsqlite3.so.
SQLite's upstream code is dedicated to the public domain; see
https://www.sqlite.org/copyright.html. Mozilla modifications retain their notices.
Mozilla's collected license and copyright notices are retained in
ruyihttp/licenses/firefox-license.html and ruyihttp/licenses/firefox-notice.txt.
Additional Rust dependency license texts and an index are included in the same directory.
The Firefox root certificates and public suffix data are bundled as runtime data.
Python dependencies are installed separately by pip and retain their respective licenses.

## Corresponding source status

MPL 2.0 section 3.2 requires making the corresponding Source Code Form of covered
software available to recipients of its executable form, including covered
modifications. This repository contains Python sources and prebuilt native
libraries. A complete corresponding native source download for these particular
binaries has not been published here. The upstream links above identify origins;
they do not include all local modifications and do not replace that obligation.
This notice does not assert that the binary distribution has fulfilled it.

Official license and guidance:
https://www.mozilla.org/en-US/MPL/2.0/ and https://www.mozilla.org/en-US/MPL/2.0/FAQ/.
No rights to Mozilla or Firefox trademarks are granted.
