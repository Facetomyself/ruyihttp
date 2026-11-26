#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Strict same-slot Firefox wire comparison; no product or network dependencies."""

import argparse
import json
import re
from pathlib import Path

SCHEMA_VERSION = 1
RELEASES = ("159", "160", "161")
SLOTS = {
    "win_amd64": ("win32", "amd64", "win64"),
    "darwin_arm64": ("darwin", "arm64", "mac"),
    "darwin_x86_64": ("darwin", "x86_64", "mac"),
    "linux_x86_64": ("linux", "x86_64", "linux-x86_64"),
    "linux_aarch64": ("linux", "aarch64", "linux-aarch64"),
}
# Exact signed Mozilla artifacts. The universal macOS binary is pinned once,
# while independent native ARM64 and x86_64 process observations are required.
MOZILLA_PINS = {
    "159": ("20261022150525", "5add844c26613d7e4d84c799d6e23cf987b1240d",
            "9c402489e6307e4cc1933ca1ebc01f6937f5ce1a9fb4354c2d212ab37eed26e5",
            "9a2dc53c369c7ae5172018b35988e1d2ffeff402", "3d98df785894057fce60603e845828e758a5411ad79aaaaff2b8230597f500d9",
            "54536fcd120af484d4c56272a5a1cf4af57b9c713d1a3b1e775da192dd541fcd",
            "de7b16588bf3ab11774f6c1b1461dafde943c1cf0ea93dc15aa5f7bd99aa1191",
            "0772404ae6e068d7cc03cecf4bb06a855f10287a77b624ffa41c6d092a64ea13",
            "8776887b79925abbdd407fcdfe257d8382b54e24be52a6466426b95a804d6790"),
    "160": ("20261104181552", "d84e7a6936554efe26097d9d9b24a0e11330e630",
            "cc24dd72af3c4aa3ad300cf9ce0641d8437a746b35db6c0de7549a8fe4077fbf",
            "2887d9de1f69c0e9776413da80e7ba0d1225dd9b", "2b23d2bf6716ea16b45c10aa5c275c78a1d7ff50ad53150809ab27424c58fd81",
            "fde774e9757c8878534c05ec210db592bf6a1b244c57941ffb2e364c04f35fcd",
            "0fd9e4fd7ab97f7b1eec42f70e809080679498ebabd78fd692f0b94f9b6bf92f",
            "b270ccc60eb899bd0277bd078d7bd8690f5c4fc3e44b4fa9ee78ed2a3e89f0ca",
            "8732312ee2d7960c6ea830a4e0d3c0ff5fe0b10856dab44e2c432fcdeb63ff63"),
    "161": ("20261118180411", "b00bde68873aedb80bea5c3ff8eba8344b50d3b4",
            "803a78b7c8f18d179d40e2b9dec1eeaafc3bb12059c7da61c7aa6b91bdc9f1fd",
            "9c70d5d48c866afc2e581d6b7ff6de98a1371d99", "c649de11e4dc6266bc905ce4b33eb8672a1947c2e210ec53dce285cb86296a5a",
            "3e9b1e5132d7b53b1ad968c7300281e90e6a0ef57d0656b1516202d686d25733",
            "b3c2992292efc4a2f7ab6abe2de0ba6e15a482d41813e469c255a2528cacf10a",
            "18f398ada9ba9faa5458dc01c2a68fc7df35517283be2e7a421a0867c5f47f83",
            "8368757b8e39ffe0441b2489e051d0d5ffc016c246ed5634495104da0e66fa83"),
}
MOZILLA_ORIGIN = "https://archive.mozilla.org/pub/firefox/releases"
SIGNER = "827E658608679618CD349F93678E455D76767AA3"
SIGNING_PRIMARY = "14F26682D0916CDD81E37B6D61B7B526D98F0353"
REFERENCE_DIR = Path(__file__).resolve().with_name("firefox_wire_references")
PATH = "/profile-wire"
BOOT = "/boot"
MODES = {"h1": "navigation", "h2": "navigation", "h3": "same-origin-fetch"}
TLS_GREASE = frozenset(range(0x0A0A, 0xFAFB, 0x1010))
TLS_LEGACY = {
    "legacy_version", "ciphers", "extensions", "groups", "signatures",
    "cert_compression", "supported_versions", "key_share_groups", "offered_alpn",
}
TLS_REQUIRED = TLS_LEGACY | {
    "compression_methods", "ec_point_formats", "psk_key_exchange_modes", "server_names", "session_id_length",
}
QUIC_PARAMETERS = frozenset({
    "ack_delay_exponent", "active_connection_id_limit", "disable_active_migration",
    "initial_max_data", "initial_max_stream_data_bidi_local", "initial_max_stream_data_bidi_remote",
    "initial_max_stream_data_uni", "initial_max_streams_bidi", "initial_max_streams_uni",
    "max_ack_delay", "max_datagram_frame_size", "max_idle_timeout", "max_udp_payload_size",
})
QUIC_REQUIRED = QUIC_PARAMETERS - {"ack_delay_exponent", "max_udp_payload_size"}
LEGACY_CASE = {
    "h1": {"request_line", "hello"},
    "h2": {"settings", "hello"},
    "h3": {"settings", "quic_version", "transport_parameters"},
}
CASE_FIELDS = {
    "h1": LEGACY_CASE["h1"] | {"client_hello_count", "negotiated_tls"},
    "h2": LEGACY_CASE["h2"] | {"client_hello_count", "negotiated_tls"},
    "h3": LEGACY_CASE["h3"] | {"hello", "initial", "grease_settings", "bootstrap"},
}
OFFICIAL_DIAGNOSTICS = {"user_agent", "process"}
OFFICIAL_BUILD = {
    "version", "manifest_sha256", "manifest_url", "signer", "signing_primary", "source_tag", "source_commit",
    "source_archive", "source_archive_sha256", "executable_sha256", "executable_slices", "runtime_host",
    "source_stamp", "archive_locale", "executable_relative", "acquired_unix",
}


class WireError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise WireError(message)


def no_duplicate_keys(items):
    obj = {}
    for key, value in items:
        require(key not in obj, f"duplicate JSON member: {key}")
        obj[key] = value
    return obj


def decode_json(data):
    return json.loads(data, object_pairs_hook=no_duplicate_keys)


def fields(obj, expected, label):
    require(isinstance(obj, dict), f"{label}: expected an object")
    require(obj.keys() == expected,
            f"{label}: missing fields {sorted(expected - obj.keys())}; unexpected fields {sorted(obj.keys() - expected)}")


def uint(value, limit=(1 << 62) - 1):
    return type(value) is int and 0 <= value <= limit


def pairs(source, predicate, label):
    require(isinstance(source, list) and bool(source), f"{label}: expected nonempty ordered pairs")
    result = []
    for pair in source:
        require(isinstance(pair, (list, tuple)) and len(pair) == 2 and predicate(*pair),
                f"{label}: malformed pair {pair!r}")
        result.append(list(pair))
    return result


def canonical_hello(hello, label, *, legacy=False):
    fields(hello, TLS_LEGACY if legacy else TLS_REQUIRED, label)
    result = dict(hello)
    require(uint(hello["legacy_version"], 65535), f"{label}: invalid legacy version")
    for name, values in hello.items():
        if name == "legacy_version":
            continue
        if name == "session_id_length":
            require(uint(values, 32), f"{label}: invalid session ID length")
            continue
        if name == "server_names":
            require(isinstance(values, list), f"{label}: invalid SNI vector")
            if values:
                result[name] = pairs(values, lambda k, v: uint(k, 255) and isinstance(v, str) and bool(v),
                                     f"{label}.server_names")
            continue
        require(isinstance(values, list), f"{label}: invalid {name} vector")
        if name == "offered_alpn":
            valid = all(isinstance(item, str) and bool(item) for item in values)
        else:
            limit = 255 if name in {"ec_point_formats", "psk_key_exchange_modes", "compression_methods"} else 65535
            valid = all(uint(item, limit) for item in values)
        require(valid, f"{label}: invalid {name} vector")
        if name in {"extensions", "ciphers", "groups", "supported_versions", "key_share_groups", "signatures"}:
            # Keep ordered positions and cardinality; only the reserved value varies.
            result[name] = ["GREASE" if value in TLS_GREASE else value for value in values]
    extensions = hello["extensions"]
    require(len(extensions) == len(set(extensions)), f"{label}: duplicate TLS extension")
    require(41 not in extensions or extensions[-1] == 41, f"{label}: pre_shared_key must be last")
    return result


def grease_settings(settings):
    return [[i, code, value] for i, (code, value) in enumerate(settings) if code >= 0x21 and (code - 0x21) % 0x1F == 0]


def canonical_initial(initial):
    counters = {"version", "udp_payload_bytes", "packet_bytes", "dcid_length", "scid_length", "token_length"}
    fields(initial, counters | {"transport_parameter_ids", "version_information"}, "h3.initial")
    require(all(uint(initial[name]) for name in counters) and initial["version"] != 0, "h3: malformed client Initial")
    require(initial["udp_payload_bytes"] >= 1200 and initial["packet_bytes"] <= initial["udp_payload_bytes"],
            "h3: malformed Initial packet or datagram length")
    require(initial["token_length"] == 0, "h3: expected cold Initial without token")
    require(8 <= initial["dcid_length"] <= 20 and initial["scid_length"] <= 20,
            "h3: invalid cold Initial connection ID length")
    ids = initial["transport_parameter_ids"]
    require(isinstance(ids, list) and bool(ids) and all(map(uint, ids)) and len(ids) == len(set(ids)),
            "h3: malformed transport parameter IDs")
    advertised = initial["version_information"]
    if advertised is not None:
        fields(advertised, {"chosen", "available"}, "h3.initial.version_information")
        require(uint(advertised["chosen"], 0xFFFFFFFF) and isinstance(advertised["available"], list)
                and all(uint(x, 0xFFFFFFFF) for x in advertised["available"]), "h3: malformed advertised QUIC versions")
    if advertised is not None:
        # RFC 9000 reserves versions of the form 0x?a?a?a?a. Keep the order
        # and position of each non-reserved version and each GREASE entry.
        advertised = {**advertised, "available": ["GREASE" if v & 0x0F0F0F0F == 0x0A0A0A0A else v
                                                   for v in advertised["available"]]}
    result = {**initial, "version_information": advertised,
              "transport_parameter_ids": ["GREASE" if p >= 27 and (p - 27) % 31 == 0 else p for p in ids]}
    # Neqo ConnectionId::generate_initial randomly sizes the destination ID
    # between 8 and 20 bytes. Its length is one-for-one in this packet size.
    result["packet_bytes_without_dcid"] = result.pop("packet_bytes") - result.pop("dcid_length")
    return result


def canonical_header(name, value, port):
    # Preserve even the lexical header name. Replace just the known ephemeral
    # listener port, and only for the routing/referrer values of this test.
    authority = f"localhost:{port}"
    if name.lower() in {"host", ":authority", "alt-used"} and value == authority:
        return name, {"ephemeral_authority": "localhost"}
    if name.lower() == "referer" and value.startswith(f"https://{authority}/"):
        return name, {"ephemeral_referrer_origin": "https://localhost", "suffix": value[len(f"https://{authority}"):]}
    return name, value


def stable_wire(wire, *, reference=False, legacy=False):
    fields(wire, MODES.keys(), "wire")
    result = {}
    for protocol, case in wire.items():
        required = (LEGACY_CASE if legacy else CASE_FIELDS)[protocol] | {"protocol", "headers", "port", "mode"}
        fields(case, required | (OFFICIAL_DIAGNOSTICS if reference else set()), protocol)
        port = case["port"]
        require(uint(port, 65535) and 0 < port != 443, f"{protocol}: missing ephemeral listener port")
        require(case["mode"] == MODES[protocol] or (legacy and protocol == "h3" and case["mode"] == "navigation"),
                f"{protocol}: expected mode {MODES[protocol]!r}, observed {case['mode']!r}")
        require(case["protocol"] in ({"http/1.1", None} if protocol == "h1" else {protocol}),
                f"{protocol}: invalid negotiated ALPN {case['protocol']!r}")
        # The bootstrap peer and target are validated below; browser process
        # provenance and duplicated UA are metadata, not request fields.
        current = {k: v for k, v in case.items() if k not in OFFICIAL_DIAGNOSTICS | {"port", "bootstrap", "grease_settings"}}
        headers = pairs(case["headers"], lambda k, v: isinstance(k, str) and bool(k) and isinstance(v, str),
                        f"{protocol}.headers")
        current["headers"] = [list(canonical_header(name, value, port)) for name, value in headers]
        raw_headers = {name.lower(): value for name, value in headers}
        require(len(raw_headers) == len(headers), f"{protocol}: duplicate request header")
        if reference:
            require(bool(raw_headers.get("user-agent")) and case["user_agent"] == raw_headers["user-agent"],
                    f"{protocol}: official UA missing or inconsistent")
            authority = f"localhost:{port}"
            require(raw_headers.get("host" if protocol == "h1" else ":authority") == authority,
                    f"{protocol}: official routing authority must use the test listener")
            if protocol == "h1":
                require(case["request_line"] == f"GET {PATH} HTTP/1.1", "h1: incorrect official request target")
            else:
                require([raw_headers.get(key) for key in (":method", ":scheme", ":path")] == ["GET", "https", PATH],
                        f"{protocol}: incorrect official pseudo-header values")
            if protocol == "h3":
                require(raw_headers.get("referer") == f"https://{authority}{BOOT}", "h3: wrong official document referrer")
                require(raw_headers.get("alt-used") == authority, "h3: wrong or missing official Alt-Used")
                require([raw_headers.get(key) for key in ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept")]
                        == ["same-origin", "cors", "empty", "*/*"] and "sec-fetch-user" not in raw_headers,
                        "h3: official request was not a default same-origin Fetch")
        if protocol == "h1":
            require(isinstance(case["request_line"], str) and bool(case["request_line"]), "h1: request-line missing")
        if "hello" in case:
            current["hello"] = canonical_hello(case["hello"], f"{protocol}.hello", legacy=legacy)
        if not legacy and protocol != "h3":
            require(case["client_hello_count"] == 1, f"{protocol}: expected one fresh ClientHello")
            tls = case["negotiated_tls"]
            fields(tls, {"version", "cipher"}, f"{protocol}.negotiated_tls")
            require(tls["version"] == "TLSv1.3" and isinstance(tls["cipher"], str) and bool(tls["cipher"]),
                    f"{protocol}: invalid negotiated TLS version or cipher")
        if protocol != "h1":
            settings = pairs(case["settings"], lambda k, v: uint(k) and uint(v), f"{protocol}.settings")
            require(len({key for key, _value in settings}) == len(settings), f"{protocol}: duplicate SETTINGS ID")
            if protocol == "h3":
                grease = grease_settings(settings)
                if not legacy:
                    require(case["grease_settings"] == grease, "h3: GREASE evidence disagrees with raw SETTINGS")
                    # Keep GREASE count and positions unless fresh official
                    # runs establish movement. Only the reserved pair varies.
                    current["settings_grease"] = [index for index, _key, _value in grease]
                omitted = {index for index, _key, _value in grease}
                settings = [pair for index, pair in enumerate(settings) if index not in omitted]
                require(bool(settings), "h3: no non-reserved SETTINGS")
            current["settings"] = settings
        if protocol == "h3":
            require(uint(case["quic_version"], 0xFFFFFFFF) and case["quic_version"] != 0, "h3: missing QUIC version")
            tp = case["transport_parameters"]
            require(isinstance(tp, dict) and tp.keys() <= QUIC_PARAMETERS,
                    "h3: malformed selected QUIC transport parameters")
            if reference:
                require(QUIC_REQUIRED <= tp.keys(), f"h3: missing selected QUIC parameters {sorted(QUIC_REQUIRED - tp.keys())}")
            require(all(type(v) is bool if k == "disable_active_migration" else uint(v) for k, v in tp.items()),
                    "h3: malformed selected QUIC parameter value")
            if not legacy:
                current["initial"] = canonical_initial(case["initial"])
                bootstraps = case["bootstrap"]
                require(isinstance(bootstraps, list) and len(bootstraps) == 1, "h3: required one verified H2 bootstrap")
                boot, = bootstraps
                fields(boot, CASE_FIELDS["h2"] | {"protocol", "headers", "port", "mode"}, "h3.bootstrap")
                boot_headers = dict(pairs(boot["headers"], lambda k, v: isinstance(k, str) and isinstance(v, str), "h3.bootstrap.headers"))
                require(boot["port"] == port and boot["protocol"] == "h2" and boot["mode"] == "navigation"
                        and boot["negotiated_tls"]["version"] == "TLSv1.3"
                        and [boot_headers.get(key) for key in (":method", ":scheme", ":authority", ":path", "sec-fetch-mode")]
                        == ["GET", "https", f"localhost:{port}", BOOT, "navigate"], "h3: wrong route or request context for H2 bootstrap")
        result[protocol] = current
    return result


def diff(expected, observed, prefix=""):
    """Report every changed leaf; lists constitute one ordered field."""
    if isinstance(expected, dict) and isinstance(observed, dict):
        changes = {}
        for name in sorted(expected.keys() | observed.keys()):
            field = f"{prefix}.{name}" if prefix else name
            if name not in expected:
                changes[field] = {"unexpected": observed[name]}
            elif name not in observed:
                changes[field] = {"missing": expected[name]}
            else:
                changes.update(diff(expected[name], observed[name], field))
        return changes
    return {prefix: {"official": expected, "observed": observed}} if type(expected) is not type(observed) or expected != observed else {}


class Reference:
    def __init__(self, samples, label):
        self.permuted_tls = {proto for proto in MODES if len({tuple(sample[proto]["hello"]["extensions"]) for sample in samples}) > 1}
        self.moving_tls_grease = {
            proto for proto in self.permuted_tls
            if len({tuple(i for i, x in enumerate(sample[proto]["hello"]["extensions"]) if x == "GREASE")
                    for sample in samples}) > 1
        }
        self.moving_h3_grease = len({tuple(sample["h3"]["settings_grease"]) for sample in samples}) > 1
        # NSS writes external/custom extensions after the built-in shuffled
        # list; Neqo adds QUIC TP (57), and NSS may append GREASE ECH (65037).
        # Preserve their measured positions if present in all fresh samples.
        self.anchored_tls_exts = {}
        for proto in self.permuted_tls:
            orders = [sample[proto]["hello"]["extensions"] for sample in samples]
            self.anchored_tls_exts[proto] = [code for code in (57, 65037)
                                           if all(code in order for order in orders)
                                           and len({order.index(code) for order in orders}) == 1]
        self.stable = self.project(samples[0])
        for sample in samples[1:]:
            changes = diff(self.stable, self.project(sample))
            require(not changes, f"{label}: official samples disagree: {json.dumps(changes, sort_keys=True)}")

    def project(self, stable):
        assert isinstance(stable, dict)
        result = dict(stable)
        for proto in self.permuted_tls:
            if "hello" not in stable[proto]:  # The old receipts had no H3 ClientHello.
                continue
            hello = stable[proto]["hello"].copy()
            extensions = hello["extensions"]
            grease = [i for i, x in enumerate(extensions) if x == "GREASE"]
            hello["extensions"] = sorted(code for code in extensions if code != "GREASE") + ["GREASE"] * len(grease)
            hello["extensions_anchored_positions"] = {str(code): extensions.index(code) for code in self.anchored_tls_exts[proto]
                                                     if code in extensions}
            if proto not in self.moving_tls_grease:
                hello["extensions_grease_positions"] = grease
            result[proto] = {**result[proto], "hello": hello}
        if self.moving_h3_grease and "settings_grease" in stable["h3"]:
            h3 = dict(result["h3"])
            h3["settings_grease_count"] = len(h3.pop("settings_grease"))
            result["h3"] = h3
        return result

    def compare(self, wire, *, legacy=False):
        return diff(self.stable, self.project(stable_wire(wire, legacy=legacy)))


def load_reference(directory, slot):
    """Load and validate the complete exact-slot release matrix before capture."""
    require(slot in SLOTS, f"unknown native slot: {slot}")
    path = directory / f"{slot}.json"
    try:
        ref = decode_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WireError(f"invalid or missing official Firefox reference for {slot}: {path}: {exc}") from exc
    return analyze_official(ref, slot, label=str(path))


def pinned_build(slot, release):
    _, _, archive_platform = SLOTS[slot]
    build_id, source_stamp, manifest, commit, source, linux_x64, linux_arm64, mac, windows = MOZILLA_PINS[release]
    base = f"{MOZILLA_ORIGIN}/{release}.0"
    archive_hash = {"linux-x86_64": linux_x64, "linux-aarch64": linux_arm64, "mac": mac, "win64": windows}[archive_platform]
    filename = {"mac": f"Firefox%20{release}.0.dmg", "win64": f"Firefox%20Setup%20{release}.0.exe"}.get(
        archive_platform, f"firefox-{release}.0.tar.xz")
    return {"version": f"{release}.0", "build_id": build_id, "source_stamp": source_stamp,
            "source_tag": f"FIREFOX_{release}_0_RELEASE", "archive_locale": "en-US",
            "sha256": archive_hash, "manifest_sha256": manifest, "source_commit": commit, "source_archive_sha256": source,
            "url": f"{base}/{archive_platform}/en-US/{filename}", "manifest_url": f"{base}/SHA256SUMS",
            "source_archive": f"{base}/source/firefox-{release}.0.source.tar.xz",
            "signer": SIGNER, "signing_primary": SIGNING_PRIMARY}


def analyze_official(ref, slot, *, releases=RELEASES, label="official Firefox capture"):
    """Compile same-slot official raw samples; a subset is for diagnostics only."""
    require(slot in SLOTS and bool(releases) and set(releases) <= set(RELEASES), "unknown reference slot or release")
    fields(ref, {"schema_version", "slot", "platform", "arch", "source", "captures", "ci"}, label)
    require(isinstance(ref["ci"], dict), f"{label}: malformed capture job provenance")
    os_name, arch, _ = SLOTS[slot]
    require(type(ref["schema_version"]) is int and ref["schema_version"] == SCHEMA_VERSION and
            (ref["slot"], ref["platform"], ref["arch"], ref["source"]) == (slot, os_name, arch, "official-firefox"),
            f"{label}: reference provenance/slot mismatch")
    fields(ref["captures"], set(releases), f"{label}.captures")
    stable, origin = {}, label
    for release, build in ref["captures"].items():
        label = f"{origin}:{release}"
        fields(build, OFFICIAL_BUILD | {"build_id", "sha256", "url", "samples"}, label)
        for key, value in pinned_build(slot, release).items():
            require(build[key] == value, f"{label}: Mozilla pin mismatch for {key}: expected {value!r}")
        require(isinstance(build["executable_sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", build["executable_sha256"]),
                f"{label}: invalid executable_sha256")
        require(isinstance(build["executable_slices"], list) and arch in build["executable_slices"]
                and isinstance(build["runtime_host"], dict) and build["runtime_host"].get("machine", "").lower() == arch,
                f"{label}: wrong executable or runtime architecture")
        if os_name == "darwin":
            require(build["runtime_host"].get("rosetta") == 0, f"{label}: translated macOS runtime")
        elif os_name == "win32":
            require(build["runtime_host"].get("wow_machine") == 0 and build["runtime_host"].get("host_machine") == 0x8664,
                    f"{label}: non-native Windows x64 runtime")
        samples = build["samples"]
        require(isinstance(samples, list) and len(samples) >= 2, f"{label}: fewer than two real browser samples")
        verified = []
        for index, sample in enumerate(samples):
            try:
                observed = stable_wire(sample, reference=True)
                for proto, case in sample.items():
                    process = case["process"]
                    require(isinstance(process, dict) and process.get("native") == arch,
                            f"{proto}: wrong official browser process architecture")
                    if os_name == "darwin":
                        require(process.get("launch_arch") == f"/usr/bin/arch -{arch}",
                                f"{proto}: missing native CPU launch evidence")
                    elif os_name == "win32":
                        require(process.get("wow_machine") == 0 and process.get("host_machine") == 0x8664,
                                f"{proto}: missing native Windows process evidence")
                    require(case["user_agent"].endswith(f" Firefox/{release}.0"), f"{proto}: official UA release mismatch")
                verified.append(observed)
            except WireError as exc:
                raise WireError(f"{label}: sample {index + 1}: {exc}") from exc
        stable[release] = Reference(verified, label)
    return stable


def legacy_wire(wire):
    """For historical receipts only: the old H3 request was a navigation."""
    adapted = {}
    for protocol, case in wire.items():
        hdrs = dict((k.lower(), v) for k, v in case["headers"])
        address = hdrs["host" if protocol == "h1" else ":authority"]
        host, _, raw_port = address.partition(":")
        require(host == "localhost" and raw_port.isdecimal(), f"legacy {protocol}: invalid local authority {address!r}")
        adapted[protocol] = {**case, "port": int(raw_port), "mode": "navigation"}
    return adapted


def cli():
    parser = argparse.ArgumentParser(description="Replay captured wheel JSONL against official same-slot references")
    parser.add_argument("slot", choices=SLOTS)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--references", type=Path, default=REFERENCE_DIR)
    parser.add_argument("--legacy", action="store_true", help="historical smoke log (H3 navigation, never admissible)")
    args = parser.parse_args()
    try:
        expected = load_reference(args.references, args.slot)
        seen = set()
        failed = args.legacy
        for line in args.receipt.read_text(encoding="utf-8").splitlines():
            if args.legacy and not line.startswith("{"):
                continue  # The legacy probe mixed JSON records with human output.
            record = decode_json(line)
            release = record.get("firefox")
            require(record.get("slot") == args.slot and release in RELEASES and release not in seen,
                    "wrong slot, unsupported release, or duplicate receipt")
            seen.add(release)
            if not args.legacy:
                expected_platform, expected_arch, _ = SLOTS[args.slot]
                require((record.get("schema_version"), record.get("source"), record.get("platform"), record.get("arch"))
                        == (SCHEMA_VERSION, "installed-wheel", expected_platform, expected_arch), "invalid receipt identity")
            wire = legacy_wire(record["wire"]) if args.legacy else record["wire"]
            changes = expected[release].compare(wire, legacy=args.legacy)
            print(json.dumps({"slot": args.slot, "firefox": release, "differences": changes}), flush=True)
            failed |= bool(changes)
        require(seen == set(RELEASES), f"receipt missing Firefox releases {sorted(set(RELEASES) - seen)}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"wire replay: {exc}\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(cli())
