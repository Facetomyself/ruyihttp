# Official Firefox wire reference schema (v1)

The wheel gate reads `<slot>.json` here by default, or from the directory explicitly passed with `--references`. The five supported slots are `win_amd64`, `darwin_arm64`, `darwin_x86_64`, `linux_x86_64`, and `linux_aarch64`. The comparator fails before opening a listener if the exact slot is missing, if any of `159`, `160`, `161` is absent, or if a reference sample is incomplete. The historical [`firefox_wire_reference.json`](../firefox_wire_reference.json) is **not** an admission fixture. It lacks this matrix, raw header values, and equivalent HTTP/3 contexts.

## Reference record

The official collector writes one JSON object per slot. Its structure is:

```text
schema_version: 1
slot: <native wheel slot>
platform: linux | darwin | win32
arch: aarch64 | arm64 | x86_64 | amd64
source: official-firefox
ci: capture job provenance (an empty object for a local capture)
captures:
  "159" | "160" | "161":
    version, build_id, url, sha256, archive_locale
    manifest_url, manifest_sha256, signer, signing_primary
    source_tag, source_commit, source_stamp, source_archive, source_archive_sha256
    executable_sha256, executable_slices, executable_relative, packaged_executables
    runtime_host, acquired_unix
    samples: [at least two fresh complete captures of all three cases]
```

The browser collector, separate from the wheel observer, verifies Mozilla's signed archive manifest and executable identity at acquisition and launches the native browser slice. The comparator checks the exact archive, manifest and source pins, build ID and locale again. On macOS the universal archive SHA is common, but each native process and each fixture is separate; on Windows the capture verifies AMD64 without WoW translation. A package wheel or a fixture from another slot is not a substitute for these browser runs. The JSON encodes observations, not a packet digest or the cryptographic signature of the reference file itself.

Each entry in `samples` has exactly three named cases:

| Key | Mode | Required wire fields beyond `headers`, `port`, `mode`, `protocol` |
|---|---|---|
| `h1` | Top-level navigation GET | Request line, ClientHello vectors, ClientHello count, negotiated TCP TLS |
| `h2` | Top-level navigation GET | First non-ACK SETTINGS, ClientHello vectors, ClientHello count, negotiated TCP TLS |
| `h3` | Default same-origin JavaScript fetch GET | First SETTINGS, their reserved entries, parsed QUIC ClientHello, QUIC Initial metadata, negotiated QUIC version and selected peer transport parameters, verified H1 bootstrap receipt |

`headers` and `settings` are **ordered arrays of pairs**, not maps or sorted sets. Header names, including HTTP/1.1 casing, and the entire raw UA are asserted in that order. The observed H1 target is `GET /profile-wire HTTP/1.1`; HTTP/2 and HTTP/3 include the actual pseudo-header names, values and order. The only header change made by the comparator is mapping the captured ephemeral `localhost` port for `Host`, `:authority`, `Alt-Used`, and the authority within the same-origin `Referer`. A different host, incorrect port, path, or any added or missing header still mismatches. HTTP/1 delimiter whitespace is parsed as HTTP OWS, outside the value; headers are otherwise left intact.

From a verified `https://localhost:<port>/boot` document, the browser runs `fetch('/profile-wire')` with default headers and no added request cache directives. The wheel forms the same fetch via the public `Session(context="fetch", document_url=boot, user_activation=False)` over the authenticated alternative. No header is supplied by the observer, and serving `/profile-wire` over TCP cannot pass as HTTP/3. The H1 bootstrap is checked for the real verified TLS route, navigation context and target; its wire fields are preserved in the evidence for diagnostics and excluded from the three measured `/profile-wire` requests. The duplicated `user_agent` and `process` fields in browser receipts validate provenance; the header list remains the authority for the UA comparison.

## Projection policy and bounds

- A TLS ClientHello captures legacy version, session ID **length**, ordered ciphers, compression methods, extension IDs, supported versions/groups, key-share groups, signature algorithms, certificate compression algorithms, EC point formats, PSK key-exchange modes, SNI and offered ALPN. All vectors are checked, including their order. The outer extension-ID order is exact unless multiple official samples for the *same slot, release and case* exhibit a permutation with stable membership. In that case the comparator keeps the extension set, count, measured placement of QUIC transport parameters and ECH where stable, and enforces the TLS rule that pre-shared-key must be last when present. Known TLS GREASE code values are anonymized; positions and counts remain asserted when stable.
- The negotiated TCP TLS version/cipher and negotiated ALPN are checked for the pinned loopback server. For HTTP/3, the first UDP Initial version and the negotiated version are separate fields. The initial datagram size, packet envelope length excluding randomized DCID and packet-number widths, fixed SCID length, token presence, transport-parameter ID order and ordered compatible-version list are checked. Neqo [randomizes each cold Initial DCID length from 8–20](https://github.com/mozilla/neqo/blob/e302b43503f44e09f4257573dd320621516d1560/neqo-transport/src/cid.rs#L52-L58) and [chooses a random initial packet number](https://github.com/mozilla/neqo/blob/e302b43503f44e09f4257573dd320621516d1560/neqo-transport/src/crypto.rs#L1111-L1123) which [uses one or two encoded bytes](https://github.com/mozilla/neqo/blob/e302b43503f44e09f4257573dd320621516d1560/neqo-transport/src/connection/mod.rs#L2355-L2365). The receiver records and constrains both widths without retaining the CID bytes or packet number, then subtracts their exact contribution; the remaining packet size must match. QUIC reserved transport-parameter and version code values are anonymized with their original positions/counts intact. The selected numeric/boolean transport-parameter values and presence are checked separately from the ordered wire IDs (e.g. missing datagram or receive-window parameters are not filled with assumed defaults).
- The first non-ACK H2 SETTINGS frame and first H3 SETTINGS have their real order. All non-reserved IDs, including unknown or zero-valued settings, are asserted. The raw H3 receipt also retains RFC 9114 reserved SETTINGS; only their random identifier/value are dropped. Their observed count and position remain asserted except when the same-slot official samples establish movement, in which case count still matters.
- The operation is a new TLS connection and ordinary verified loopback GET. Cryptographic entropy (randoms, session IDs, key bytes, ECH ciphertext, CIDs, protected packet numbers, nonces and cryptographic padding), transient routing addresses, server certificate issuance material, and OS-dependent timing, packet/record segmentation or scheduling are outside this structured comparison. Resumption, Retry, 0-RTT, proxy paths, body uploads, cache revalidation, coalescing, application cookies and browser/UI activity are different transactions. HPACK/QPACK encoded bytes, ACK timing and other peer-state-dependent frames are not part of the ordered decoded header and initial-settings contract. Existing runtime, certificate, fallback, upgrade and negative smoke tests cover behaviors that are not this wire fixture; they do not turn the result into a full-network fingerprint.

## Reproduce and replay

Use the package's native CPython environment with the candidate wheel installed from the wheel artifact, `aioquic==1.3.0`, and a working native runtime. Run with `-I` outside the source tree to keep the product import inside the installed environment:

```sh
python -I /checkout/ci/smoke_firefox_profiles.py linux_aarch64 --output strict.jsonl
python -I /checkout/ci/smoke_firefox_profiles.py win_amd64 --collect --output stock.jsonl
python -I /checkout/ci/firefox_wire.py win_amd64 stock.jsonl
python -I /checkout/ci/firefox_wire.py linux_aarch64 old-profile-wire.txt --legacy
```

`--collect` works against stock packages with no fork runtime manifest. It still requires all actual protocol transactions; `--release 161` measures only that release for diagnostics. Collection mode is not qualification. The replay command checks a full slot's receipts. `--legacy` compares the fields present in original v0.9.2 smoke logs while explicitly retaining their H3 navigation context and reporting missing fields; legacy mode always exits nonzero. The strict installed-wheel command also checks package runtime identity and the platform-specific native TLS telemetry shape. A JSONL failure receipt can include `partial_wire`; it is diagnostic evidence only.
