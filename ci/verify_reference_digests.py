"""Require each enforced wire fixture to be the exact admitted artifact member (canonical LF)."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

CI = Path(__file__).resolve().parent
sys.path.insert(0, str(CI))
from firefox_wire import RELEASES, SLOTS, decode_json, pinned_build, require


def checked_result(slot, raw, receipt):
    digest = hashlib.sha256(raw).hexdigest()
    require(
        receipt.get("slot") == slot
        and receipt.get("fixture_digest") == "sha256:" + digest,
        "fixture differs from the admitted SHA-256",
    )
    ref = decode_json(raw.decode("utf-8"))
    require(
        ref["slot"] == slot and ref["source"] == "official-firefox",
        "wrong fixture slot or source",
    )
    ci = ref["ci"]
    rid = receipt["run_id"]
    attempt = receipt["run_attempt"]
    sha = receipt["run_head_sha"]
    require(
        (ci["sha"], ci["run_id"], ci["run_attempt"]) == (sha, str(rid), str(attempt)),
        "fixture run/attempt mismatch",
    )
    base = f"https://github.com/Facetomyself/ruyihttp/actions/runs/{rid}"
    require(
        receipt["run_url"] == base
        and receipt["job_url"] == f"{base}/job/{receipt['job_id']}",
        "unexpected reference job",
    )
    require(
        set(ref["captures"]) == set(RELEASES), "reference lacks a supported release"
    )
    for major, build in ref["captures"].items():
        pin = pinned_build(slot, major)
        require(
            all(build[k] == v for k, v in pin.items()),
            "unexpected Mozilla release identity",
        )
        require(len(build["samples"]) >= 2, "not enough fresh browser references")
    return ref, digest


def verify(slot):
    sources = [
        ("firefox_wire_references", "firefox-reference-receipts.json"),
        ("firefox_h2_preface_references", "firefox-h2-preface-receipts.json"),
    ]
    refs = []
    out = {}
    for dirname, name in sources:
        record = json.loads((CI.parent / "docs" / name).read_text(encoding="utf-8"))[
            "receipts"
        ][slot]
        raw = (CI / dirname / (slot + ".json")).read_bytes()
        ref, digest = checked_result(slot, raw, record)
        refs.append(ref)
        out[dirname] = {
            "sha256": digest,
            "job": record["job_url"],
            "artifact_id": record["artifact_id"],
            "artifact_digest": record["artifact_digest"],
        }
    require(refs[1]["scope"] == "h2-preface", "wrong supplemental reference type")
    for major in RELEASES:
        first, second = (r["captures"][major] for r in refs)
        for k in (
            "build_id",
            "source_commit",
            "sha256",
            "executable_sha256",
            "packaged_executables",
            "executable_slices",
        ):
            require(
                first[k] == second[k],
                f"{slot}/{major}: supplemental browser executable differs",
            )
    return out


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("slot", choices=SLOTS)
    slot = p.parse_args().slot
    print(
        json.dumps({"slot": slot, "admitted_references": verify(slot)}, sort_keys=True)
    )
