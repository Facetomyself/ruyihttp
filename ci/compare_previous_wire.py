"""Record what the actual public 0.9.2 wheel did, using the new same-slot oracle."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

CI = Path(__file__).resolve().parent
sys.path.insert(0, str(CI))
from firefox_wire import REFERENCE_DIR, RELEASES, decode_json, load_reference
from release_inputs import OLD_COMMIT, asset_spec


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("slot")
    ap.add_argument("raw", type=Path)
    ap.add_argument("output", type=Path)
    args = ap.parse_args()
    slot = args.slot
    official = load_reference(REFERENCE_DIR, slot)
    records = [
        decode_json(line) for line in args.raw.read_text(encoding="utf-8").splitlines()
    ]
    if [r["firefox"] for r in records] != list(RELEASES):
        raise ValueError("incomplete old-wheel capture")
    results = {}
    for r in records:
        if (r["source"], r["slot"], r["package_version"]) != (
            "installed-wheel",
            slot,
            "0.9.2",
        ):
            raise ValueError("wrong old-wheel identity")
        profile = r["firefox"]
        wire = r["wire"]
        changes = official[profile].compare_receipt(wire, r["repeats"])
        settings = dict(wire["h3"]["settings"])
        tp = wire["h3"]["transport_parameters"]
        ua = next(v for n, v in wire["h1"]["headers"] if n.lower() == "user-agent")
        if slot == "linux_aarch64" and "X11; Linux aarch64;" not in ua:
            raise ValueError("previous ARM64 UA control is not the published behavior")
        if slot != "win_amd64" and (8 in settings or not changes):
            raise ValueError("previous POSIX missing Extended CONNECT control was lost")
        if slot.startswith("darwin_") and (
            wire["h3"]["quic_version"],
            tp["initial_max_data"],
            tp["initial_max_stream_data_bidi_local"],
        ) != (1, 2097152, 1048576):
            raise ValueError("previous macOS QUIC defaults control was lost")
        results[profile] = {
            "ua": ua,
            "initial_version": wire["h3"]["initial"]["version"],
            "negotiated_version": wire["h3"]["quic_version"],
            "h3_settings": wire["h3"]["settings"],
            "initial_max_data": tp["initial_max_data"],
            "initial_max_stream_data_bidi_local": tp[
                "initial_max_stream_data_bidi_local"
            ],
            "differences": changes,
        }
        print(slot, profile, "v0.9.2 stable difference fields:", sorted(changes))
    pin = asset_spec("fork-0.9.2", slot)
    args.output.write_text(
        json.dumps(
            {
                "baseline_commit": OLD_COMMIT,
                "wheel_name": pin["name"],
                "wheel_sha256": pin["sha256"],
                "raw_sha256": hashlib.sha256(args.raw.read_bytes()).hexdigest(),
                "slot": slot,
                "results": results,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
