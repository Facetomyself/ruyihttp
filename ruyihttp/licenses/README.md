# Bundled component license notices

`firefox-license.html` and `firefox-notice.txt` retain Mozilla's collected notices.
The HTML is the upstream source template, including its preprocessing directives;
it is supplemented here with the individual Rust dependency license documents.
The collection also describes Firefox components beyond this standalone runtime.

`rust-dependencies.json` maps the 106 packages in the native QUIC build dependency
export to their declared license, version, upstream repository, and included
license documents. The export includes build-time and optional dependencies;
this is a notice inventory, not a list of crates proven to be linked into the DLL.

License documents are copied verbatim. Identical documents are stored once and
referenced by every applicable package. Copyright and license headers are
retained in the index where a package has no separate license file. The Neqo
crates and nss-rs declare MIT OR Apache-2.0. A package-specific note identifies
where the included Apache-2.0 text is used for a package whose export omits a
separate license document. Mozilla shim crates carrying MPL notices refer to
the MPL text in `firefox-license.html` and the project LICENSE.

The Python package includes Mozilla certificate-root and public-suffix data.
Their accompanying notices are retained in `mozilla-runtime-data.txt` and the
suffix data file.
Python dependencies are installed separately and carry their own license files.

License and attribution notices do not provide corresponding source code.
See the project's THIRD_PARTY_NOTICES.md for the status of native source
availability. This inventory does not assert that all binary distribution
license obligations have been fulfilled.
