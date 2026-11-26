"""Grade the first H2 navigation's flow credit, stream ID and priority policy.

This independent gate supplements the existing H1/H2/H3 oracle. It checks
ordinary fresh navigations, never extrapolating to later application DATA or
post-response WINDOW_UPDATE scheduling. ACK positions depend on the peer.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

CI = Path(__file__).resolve().parent
sys.path.insert(0, str(CI))
from firefox_h2_preface import stable_flight
from firefox_wire import RELEASES, SLOTS, decode_json, diff, pinned_build, require

REFS = CI / "firefox_h2_preface_references"


def compile_supplement(slot, data, *, releases=RELEASES):
    require(
        slot in SLOTS and bool(releases) and set(releases) <= set(RELEASES),
        "unknown platform or release",
    )
    os_name, arch, _ = SLOTS[slot]
    require(
        (
            data.get("source"),
            data.get("scope"),
            data.get("slot"),
            data.get("platform"),
            data.get("arch"),
        )
        == ("official-firefox", "h2-preface", slot, os_name, arch),
        "unexpected H2 reference origin/platform",
    )
    require(
        set(data.get("captures", {})) == set(releases),
        "incomplete H2 reference releases",
    )
    expected = {}
    for release in releases:
        b = data["captures"][release]
        pin = pinned_build(slot, release)
        require(
            b.get("build_id") == pin["build_id"] and b.get("sha256") == pin["sha256"],
            "official H2 archive identity mismatch",
        )
        samples = b["samples"]
        require(
            isinstance(samples, list) and len(samples) >= 2,
            "missing repeated official H2 controls",
        )
        stable = [stable_flight(v) for v in samples]
        require(
            all(t == stable[0] for t in stable),
            "official H2 samples disagree on stable flow control",
        )
        expected[release] = stable[0]
    return expected


def grade(lines, expected, slot):
    require(
        [r["firefox"] for r in lines] == list(RELEASES),
        "incomplete first-flight capture series",
    )
    results = {}
    for r in lines:
        release = r["firefox"]
        require(
            r.get("slot") == slot
            and r.get("source") == "installed-wheel"
            and "capture_error" not in r,
            "incorrect installed capture identity",
        )
        raw = [s["responses"]["h2"]["first_flight"] for s in [r, *r.get("repeats", [])]]
        differences = [diff(expected[release], stable_flight(row)) for row in raw]
        results[release] = {
            "raw": raw,
            "official_stable": expected[release],
            "differences": differences,
        }
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("slot", choices=SLOTS)
    ap.add_argument("wire_receipts", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--references", type=Path, default=REFS)
    args = ap.parse_args()
    path = args.references / (args.slot + ".json")
    raw = path.read_bytes()
    expected = compile_supplement(args.slot, decode_json(raw.decode("utf-8")))
    results = grade(
        [
            decode_json(l)
            for l in args.wire_receipts.read_text(encoding="utf-8").splitlines()
        ],
        expected,
        args.slot,
    )
    out = {
        "scope": "h2-preface-through-first-navigation-HEADERS",
        "slot": args.slot,
        "reference_sha256": hashlib.sha256(raw).hexdigest(),
        "results": results,
    }
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    for major, row in results.items():
        print(
            args.slot,
            major,
            "official",
            row["official_stable"],
            "differences",
            row["differences"],
            flush=True,
        )
    if any(d for row in results.values() for d in row["differences"]):
        raise SystemExit("candidate H2 connection preface differs from official")
    print(
        "PASS: same-slot official first H2 flight: control frames, connection window, priority and first request stream"
    )
