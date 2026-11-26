# Collecting official Firefox loopback references

The reference is **Mozilla's en-US stable binary**, not RuyiHttp, a distribution Firefox package, a moving `latest` download, or a user profile. The capture tooling measures a bounded localhost scenario on the same OS and native architecture as the client being compared. The reference is not a claim about platforms, origins, or contexts outside the collected matrix.

## Releases and provenance

| Firefox | Mozilla release directory | Mozilla Git release ref commit |
| --- | --- | --- |
| 159.0 | [159.0](https://archive.mozilla.org/pub/firefox/releases/159.0/) | [`9a2dc53c369c7ae5172018b35988e1d2ffeff402`](https://github.com/mozilla-firefox/firefox/commit/9a2dc53c369c7ae5172018b35988e1d2ffeff402) |
| 160.0 | [160.0](https://archive.mozilla.org/pub/firefox/releases/160.0/) | [`2887d9de1f69c0e9776413da80e7ba0d1225dd9b`](https://github.com/mozilla-firefox/firefox/commit/2887d9de1f69c0e9776413da80e7ba0d1225dd9b) |
| 161.0 | [161.0](https://archive.mozilla.org/pub/firefox/releases/161.0/) | [`9c70d5d48c866afc2e581d6b7ff6de98a1371d99`](https://github.com/mozilla-firefox/firefox/commit/9c70d5d48c866afc2e581d6b7ff6de98a1371d99) |

The release pins in [the acquisition module](../ci/firefox_reference_releases.py) cover the individual en-US archives, `SHA256SUMS`, source archives, and Mozilla Git tag commits. `prepare` verifies the manifest SHA-256 and its detached signature in a temporary GnuPG home. It pins both the Mozilla release [primary key](https://blog.mozilla.org/security/2025/04/01/updated-gpg-key-for-signing-firefox-releases-2/) `14F26682D0916CDD81E37B6D61B7B526D98F0353` and the signing subkey actually used by these three manifests, `827E658608679618CD349F93678E455D76767AA3`. The source archives are identified by the signed manifests; source trees need not be downloaded. The archive, executable SHA-256, `application.ini` version/BuildID and source stamp have separate fields. Windows extraction uses the installer's `core` payload without executing the installer; Linux uses its native tarball; Apple Silicon and Intel use the **same** signed universal DMG and their native slice.

## Capture

Run on a dedicated native host or the [hosted matrix](../.github/workflows/firefox-reference.yml). Linux uses a loopback-only network namespace, macOS temporarily gates new non-loopback IP egress through a dedicated PF anchor on the ephemeral runner, and Windows uses short-lived per-program outbound firewall rules. The PF path leaves Firefox's own sandbox enabled: running Firefox inside an outer Seatbelt sandbox failed during Firefox child-sandbox initialization. The fixture binds `127.0.0.1` and the browser uses `https://localhost:<port>`. Acquisition and dependency installation take place before browser isolation. Browser startup is headless, with an isolated home, a new profile per protocol and sample, and startup/update/telemetry prefs disabled. A fresh certificate for `localhost` chains to a local CA installed only into the temporary NSS profile database. H3 explicitly allows this fixture trust anchor for protocol eligibility; hostname and chain validation remain on. No profile or certificate key is part of the evidence artifact.

The observer keeps raw ordered request pairs, including pseudo-header order on H2/H3 and field-name casing on H1. It observes the following distinct contexts:

1. **H1 navigation:** A top-level `GET /profile-wire`, with server ALPN restricted to HTTP/1.1.
2. **H2 navigation:** A top-level `GET /profile-wire`, with server ALPN restricted to `h2`. The first non-ACK SETTINGS payload is decoded in frame order.
3. **H3 same-origin fetch:** An HTTPS navigation loads `/boot`; that HTTP/1.1 response advertises `Alt-Svc: h3=":<port>"; ma=60`. The document calls exactly `fetch('/profile-wire')`, with the default Fetch cache and credentials modes. It retries the same unmodified request a bounded number of times if the alternate protocol is still being established. The TCP origin stays available to finish Alt-Svc validation but responds 503 to attempts at the target path. `FIREFOX_REFERENCE_BOOTSTRAP=h2` selects the explicitly labeled H2 diagnostic bootstrap rather than the standard H1 bootstrap. Only the UDP observer can complete that request successfully. The raw bootstrap navigation and unsuccessful TCP attempts are recorded separately from the H3 request. Query nonces and the cache-bypass headers induced by `fetch(..., {cache:'no-store'})` are absent from this scenario.

The v1 per-slot JSON uses `captures.{159,160,161}.samples[]` with fresh `h1`, `h2`, `h3` records. Each request retains its own literal authority, port, path, UA and header values. Tie `Referer`, `Alt-Used`, and `Sec-Fetch-*` to the underlying context before normalizing dynamic authority; they are not interchangeable between navigation and fetch. H3 SETTINGS are kept in observed order; the separate `grease_settings` list records `[position, id, value]`. `h3.initial.version` is the first observed Initial version on the accepted connection, separate from `h3.quic_version` negotiated by the server. The capture includes the first Initial datagram and packet lengths, the packet-number width (not its value), CID and Initial token lengths rather than their bytes, transport-parameter IDs in wire order, and distinct selected remote values. ClientHello includes structural values and original extension order; it omits random bytes, session IDs, and ephemeral key material. A comparison may distinguish verified stable structure from sampled variation; it should not overwrite raw records with normalized data.

### Run a single release on its native host

In a Bash shell and a new ephemeral work/evidence directory, install the pinned [observer dependencies](../ci/firefox_reference_requirements.txt) and run (example: Windows 161.0):

```sh
python -m pip install -r ci/firefox_reference_requirements.txt
python ci/firefox_reference_selftest.py -q
python ci/firefox_reference_capture.py prepare win_amd64 161 "$RUNNER_TEMP/firefox-161"
bash ci/firefox_reference_isolate.sh win_amd64 161 "$RUNNER_TEMP/firefox-161" "$RUNNER_TEMP/firefox-references" --samples 2
```

Use `linux_x86_64`, `linux_aarch64`, `darwin_arm64`, or `darwin_x86_64` on the matching native system. Linux requires `sudo`, `unshare`, and `ip`. macOS requires `hdiutil`, `lipo`, `arch`, `sudo` access to PF, and the NSS `certutil` pointed to by `FIREFOX_REFERENCE_NSS_CERTUTIL` (see the workflow). Run the PF stage only on an ephemeral native host. Outside GitHub Actions, preconfigure the dedicated `com.apple/*` hook and set `FIREFOX_REFERENCE_DEDICATED_MAC=1`. The wrapper refuses to replace a pre-existing policy; only an empty verified Actions ruleset can load default anchors. The wrapper removes its PF rule and releases its enable lease when capture ends. Windows requires Git Bash, GnuPG, 7-Zip, and a runner account permitted to apply its scoped Windows Firewall rules. A complete slot can be combined with `python ci/firefox_reference_capture.py merge <slot> "$RUNNER_TEMP/firefox-references"`; an incomplete run emits a `*-partial.json` diagnostic and does not assemble a complete slot.

The workflow can be dispatched after registration on the default branch. Before registration, qualification used the existing CI dispatch ID on the explicit capture branch through a temporary branch-only shim. The shim is not part of the reusable workflow or release commits. [The admission script](../ci/firefox_reference_admit.py) verifies the exact workflow run, attempt, head SHA, successful slot job, artifact ID and ZIP digest before admitting an assembled slot. It retains both the artifact member digest and the Git JSON digest; they can differ only by CRLF-to-LF conversion. Diagnostics alone are not admitted references. The original v0.9.2 [Linux ARM64 comparison](firefox-profile-wire.md) remains historical: its H3 capture used a nonce query and an explicit cache-bypass fetch, so its request headers are a distinct context.

## Admitted observations

[Run 45766794582, attempt 1](https://github.com/Facetomyself/ruyihttp/actions/runs/45766794582) at `e7a89e45f883b541de3a6a86a4e4c263d7e76e7f` passed all five native jobs. Each slot captured Firefox 159.0, 160.0, and 161.0 twice, with a separate fresh profile for each case: 30 observations per protocol. The [receipt manifest](firefox-reference-receipts.json) identifies the exact jobs, artifacts, ZIP digests, and fixture digests. The earlier complete [run 45766579626](https://github.com/Facetomyself/ruyihttp/actions/runs/45766579626) is retained there as an independent diagnostic run from before packet-number width was recorded.

| Native slot and runner OS | Raw reference | Artifact ID |
| --- | --- | ---: |
| Linux x86_64, Ubuntu 24.04.5 | [Linux x86_64](../ci/firefox_wire_references/linux_x86_64.json) | 15091499644 |
| Linux AArch64, Ubuntu 24.04.5 | [Linux AArch64](../ci/firefox_wire_references/linux_aarch64.json) | 15092685534 |
| macOS 26.7.2, Apple Silicon | [Apple Silicon](../ci/firefox_wire_references/darwin_arm64.json) | 15092695759 |
| macOS 15.7.9, Intel | [Intel Mac](../ci/firefox_wire_references/darwin_x86_64.json) | 15092063357 |
| Windows Server 2025, AMD64 | [Windows AMD64](../ci/firefox_wire_references/win_amd64.json) | 15092451701 |

The Firefox build IDs were `20261022150525`, `20261104181552`, and `20261118180411`. Both Linux builds reported the reduced `X11; Linux x86_64` UA token; both Mac builds reported `Macintosh; Intel Mac OS X 10.15`. The Mac process CPU type (`arm64` versus `x86_64`) was separately verified by the running process's kernel record.

- H2 initial SETTINGS were `[[1,65536],[2,0],[4,131072],[5,16384]]`. H3 SETTINGS were `[[1,65536],[7,20],[727725890,0],[16765559,1],[51,1],[8,1]]` in literal frame order. No H3 SETTINGS GREASE slots were observed. QUIC version and transport-parameter GREASE are separate, preserved observations.
- Initial QUIC v1 and negotiated QUIC v2 (`0x6b3343cf`) were distinct in all samples. Every initial UDP payload was 1252 bytes and every initial SCID length was 3. The observed packet-number width was one byte in 25 cases and two bytes in five. The first packet length minus observed DCID length and packet-number width was 983 bytes in all 30 cases.
- H1, H2, and H3 each had one normalized ordered-header shape after accounting for literal authority and UA. H3 contained `Referer: https://localhost:<port>/boot`, `Alt-Used: localhost:<port>`, `Sec-Fetch-Dest: empty`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Site: same-origin`, and `Priority: u=4`. H1 and H2 remained navigation contexts. TCP ClientHello extension order was stable in these observations; H3 ClientHello extension order varied in all 30 captures despite identical extension membership.
