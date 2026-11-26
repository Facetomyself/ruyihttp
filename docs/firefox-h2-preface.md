# Supplemental Firefox HTTP/2 first-flight reference

[Run 45769558169, attempt 1](https://github.com/Facetomyself/ruyihttp/actions/runs/45769558169) at `53fe1a96d8a51a0eb17793be0d7679d8ea7e5326` collected the first client HTTP/2 flight from the same signed Firefox 159.0, 160.0, and 161.0 en-US executables as the [main wire references](firefox-reference-collection.md). Each of the five native slots ran two fresh top-level `GET /profile-wire` navigations over verified TLS with ALPN `h2` and a profile-local test CA. The observer recorded frame descriptors through the first request HEADERS and discarded HPACK payloads. This supplement leaves the previously admitted H1/H2/H3 JSON unchanged.

All 30 normalized flights had this order:

| Step | Frame | Observed fields |
| --- | --- | --- |
| 1 | SETTINGS, stream 0 | `[[1,65536],[2,0],[4,131072],[5,16384]]` in wire order |
| 2 | WINDOW_UPDATE, stream 0 | Increment `12517377`, raising the connection window from `65535` to `12582912` bytes (12 MiB) |
| 3 | First HEADERS, stream 3 | END_HEADERS and END_STREAM set; not padded; inline priority depends on stream `0`, decoded weight `42` (wire byte `41`), non-exclusive |

No separate PRIORITY frame preceded first HEADERS in these observations. An ACK for the server's SETTINGS was observed at zero-based wire frame ordinal `2` in all 30 samples. `settings_ack_positions` is separate from the client control-frame sequence because the time at which the server's SETTINGS arrive can change this ordinal. The capture ends at first HEADERS; a missing ordinal would only mean the ACK was absent before that cutoff.

| Native slot | Supplemental fixture | Artifact ID |
| --- | --- | ---: |
| Linux x86_64 | [Linux x86_64](../ci/firefox_h2_preface_references/linux_x86_64.json) | 15092919029 |
| Linux AArch64 | [Linux AArch64](../ci/firefox_h2_preface_references/linux_aarch64.json) | 15093522331 |
| Apple Silicon | [Apple Silicon](../ci/firefox_h2_preface_references/darwin_arm64.json) | 15093103770 |
| Intel Mac | [Intel Mac](../ci/firefox_h2_preface_references/darwin_x86_64.json) | 15093721173 |
| Windows AMD64 | [Windows AMD64](../ci/firefox_h2_preface_references/win_amd64.json) | 15093437767 |

The [receipt manifest](firefox-h2-preface-receipts.json) pins job IDs, artifact IDs, artifact SHA-256, member SHA-256, and the committed fixture SHA-256. Admission also verifies the Firefox BuildID, signed release manifest, archive SHA and executable SHA, plus the previously admitted slot's navigation UA and ordered SETTINGS. Both Linux runners remained on Ubuntu 24.04.5 LTS, with hosted kernel `7.0.0-1017-azure` in this supplement instead of `7.0.0-1018-aws` (x86_64) and `7.0.0-1020-azure` (AArch64) in the main run. Mac and Windows version records matched the earlier run.

Use `mode: h2-preface` in the [reusable workflow](../.github/workflows/firefox-reference.yml) for a dedicated capture. For a single release, use the [normal acquisition commands](firefox-reference-collection.md#run-a-single-release-on-its-native-host) and set `FIREFOX_REFERENCE_H2_PREFACE=1` for the isolation wrapper. Admit into a separate directory with `firefox_reference_admit.py --h2-preface-reference ci/firefox_wire_references/<slot>.json` alongside the usual slot, run, job, artifact, ZIP, and destination arguments.
