#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Strict same-slot Firefox wire comparison; no product or network dependencies."""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
RELEASES = ("159", "160", "161")
SLOTS = {
    "win_amd64": ("win32", "amd64", "win64"),
    "darwin_arm64": ("darwin", "arm64", "mac"),
    "darwin_x86_64": ("darwin", "x86_64", "mac"),
    "linux_x86_64": ("linux", "x86_64", "linux-x86_64"),
    "linux_aarch64": ("linux", "aarch64", "linux-aarch64"),
}
REFERENCE_DIR = Path(__file__).resolve().with_name("firefox_wire_references")
PATH = "/profile-wire"
BOOT = "/boot"
MODES = {"h1": "navigation", "h2": "navigation", "h3": "same-origin-fetch"}
TLS_GREASE = frozenset(range(0x0A0A, 0xFAFB, 0x1010))
TLS_REQUIRED = {
    "legacy_version", "ciphers", "extensions", "groups", "signatures",
    "cert_compression", "supported_versions", "key_share_groups", "offered_alpn",
}
TLS_ADDITIONAL = {"compression_methods", "ec_point_formats", "psk_key_exchange_modes", "server_names"}
QUIC_PARAMETERS = frozenset({
    "ack_delay_exponent", "active_connection_id_limit", "disable_active_migration",
    "initial_max_data", "initial_max_stream_data_bidi_local", "initial_max_stream_data_bidi_remote",
    "initial_max_stream_data_uni", "initial_max_streams_bidi", "initial_max_streams_uni",
    "max_ack_delay", "max_datagram_frame_size", "max_idle_timeout", "max_udp_payload_size",
})
QUIC_REQUIRED = QUIC_PARAMETERS - {"ack_delay_exponent", "max_udp_payload_size"}
CASE_FIELDS = {
    "h1": {"request_line", "hello"},
    "h2": {"settings", "hello"},
    "h3": {"settings", "quic_version", "transport_parameters"},
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


def canonical_hello(hello, label):
    require(isinstance(hello, dict) and TLS_REQUIRED <= hello.keys() <= TLS_REQUIRED | TLS_ADDITIONAL,
            f"{label}: malformed ClientHello fields")
    result = dict(hello)
    require(uint(hello["legacy_version"], 65535), f"{label}: invalid legacy version")
    for name, values in hello.items():
        if name == "legacy_version":
            continue
        validate = (lambda item: isinstance(item, str) and bool(item)) if name in {
            "offered_alpn", "server_names",
        } else (lambda item: uint(item, 65535))
        require(isinstance(values, list) and all(map(validate, values)), f"{label}: invalid {name} vector")
        if name in {"ciphers", "groups", "supported_versions", "key_share_groups", "signatures"}:
            # Keep vector ordering (and GREASE position/presence), replacing only the reserved value itself.
            result[name] = ["GREASE" if value in TLS_GREASE else value for value in values]
    extensions = hello["extensions"]
    require(len(extensions) == len(set(extensions)), f"{label}: duplicate TLS extension")
    # Fresh official connections permute extension IDs. The ID set and number
    # of reserved GREASE slots remain asserted, as do the ordered inner vectors.
    result["extensions"] = sorted(code for code in extensions if code not in TLS_GREASE)
    result["extensions"] += ["GREASE"] * sum(code in TLS_GREASE for code in extensions)
    return result


def canonical_header(name, value, port):
    # Preserve even the lexical header name. Replace just the known ephemeral
    # listener port, and only for the routing/referrer values of this test.
    authority = f"localhost:{port}"
    if name.lower() in {"host", ":authority", "alt-used"} and value == authority:
        return name, "localhost:<PORT>"
    if name.lower() == "referer" and value.startswith(f"https://{authority}/"):
        return name, "https://localhost:<PORT>" + value[len(f"https://{authority}"):]
    return name, value


def stable_wire(wire, *, reference=False, legacy=False):
    fields(wire, MODES.keys(), "wire")
    result = {}
    for protocol, case in wire.items():
        fields(case, CASE_FIELDS[protocol] | {"protocol", "headers", "port", "mode"}, protocol)
        port = case["port"]
        require(uint(port, 65535) and 0 < port != 443, f"{protocol}: missing ephemeral listener port")
        require(case["mode"] == MODES[protocol] or (legacy and protocol == "h3" and case["mode"] == "navigation"),
                f"{protocol}: expected mode {MODES[protocol]!r}, observed {case['mode']!r}")
        require(case["protocol"] in ({"http/1.1", None} if protocol == "h1" else {protocol}),
                f"{protocol}: invalid negotiated ALPN {case['protocol']!r}")
        current = {k: v for k, v in case.items() if k != "port"}
        headers = pairs(case["headers"], lambda k, v: isinstance(k, str) and bool(k) and isinstance(v, str),
                        f"{protocol}.headers")
        current["headers"] = [list(canonical_header(name, value, port)) for name, value in headers]
        raw_headers = {name.lower(): value for name, value in headers}
        require(len(raw_headers) == len(headers), f"{protocol}: duplicate request header")
        if reference:
            require(bool(raw_headers.get("user-agent")), f"{protocol}: official UA missing")
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
        if protocol != "h3":
            current["hello"] = canonical_hello(case["hello"], f"{protocol}.hello")
        if protocol != "h1":
            settings = pairs(case["settings"], lambda k, v: uint(k) and uint(v), f"{protocol}.settings")
            require(len({key for key, _value in settings}) == len(settings), f"{protocol}: duplicate SETTINGS ID")
            if protocol == "h3":
                # HTTP/3 reserved settings have no application semantics. Keep
                # all other IDs/values, in the order on the control stream.
                settings = [pair for pair in settings if pair[0] < 0x21 or (pair[0] - 0x21) % 0x1F]
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


def load_reference(directory, slot):
    """Load and validate the complete exact-slot release matrix before capture."""
    require(slot in SLOTS, f"unknown native slot: {slot}")
    path = directory / f"{slot}.json"
    try:
        ref = decode_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WireError(f"invalid or missing official Firefox reference for {slot}: {path}: {exc}") from exc
    fields(ref, {"schema_version", "slot", "platform", "arch", "source", "captures"}, str(path))
    os_name, arch, archive_platform = SLOTS[slot]
    require(type(ref["schema_version"]) is int and ref["schema_version"] == SCHEMA_VERSION and
            (ref["slot"], ref["platform"], ref["arch"], ref["source"]) == (slot, os_name, arch, "official-firefox"),
            f"{path}: reference provenance/slot mismatch")
    fields(ref["captures"], set(RELEASES), f"{path}.captures")
    stable = {}
    for release, build in ref["captures"].items():
        label = f"{path}:{release}"
        fields(build, {"build_id", "sha256", "url", "samples"}, label)
        require(isinstance(build["build_id"], str) and re.fullmatch(r"[0-9]{14}", build["build_id"]),
                f"{label}: invalid Firefox build ID")
        require(isinstance(build["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", build["sha256"]),
                f"{label}: invalid archive SHA256")
        url = urlsplit(build["url"])
        prefix = f"/pub/firefox/releases/{release}.0/{archive_platform}/en-US/"
        require(url.scheme == "https" and url.netloc == "archive.mozilla.org" and url.path.startswith(prefix)
                and len(url.path) > len(prefix) and not (url.query or url.fragment), f"{label}: wrong Mozilla archive URL")
        samples = build["samples"]
        require(isinstance(samples, list) and bool(samples), f"{label}: no real browser samples")
        for index, sample in enumerate(samples):
            try:
                observed = stable_wire(sample, reference=True)
            except WireError as exc:
                raise WireError(f"{label}: sample {index + 1}: {exc}") from exc
            if index:
                changes = diff(stable[release], observed)
                require(not changes, f"{label}: official samples disagree: {json.dumps(changes, sort_keys=True)}")
            else:
                stable[release] = observed
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
            changes = diff(expected[release], stable_wire(wire, legacy=args.legacy))
            print(json.dumps({"slot": args.slot, "firefox": release, "differences": changes}), flush=True)
            failed |= bool(changes)
        require(seen == set(RELEASES), f"receipt missing Firefox releases {sorted(set(RELEASES) - seen)}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"wire replay: {exc}\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(cli())
