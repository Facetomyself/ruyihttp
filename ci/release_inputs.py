"""Pinned public binary inputs for fork upgrades and an unmodified upstream control.

These routines only download and verify specific public wheels. They neither
import donor modules into the verifier nor replace a current platform library.
"""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

CI = Path(__file__).resolve().parent
FORK_PIN = CI / "baselines/fork-0.9.2.json"
UPSTREAM_PIN = CI.parent / "native/win_amd64/provenance.json"
OLD_COMMIT = "656655d3cc6b2027eb0d8c148a855e97f817db53"
PREVIOUS_COMMIT = "e8f8b02703239a18a75760d791c15936af632c40"
UPSTREAM_SHA = "79eb2f08326c5f1e0a9ffddecef5136f45b50aefe952051f878e514a63939332"


def asset_spec(line, slot):
    if line in ("fork-0.9.2", "fork-0.9.3"):
        tag, commit, path = (
            ("v0.9.2", OLD_COMMIT, FORK_PIN)
            if line == "fork-0.9.2"
            else ("v0.9.3", PREVIOUS_COMMIT, CI / "baselines/fork-0.9.3.json")
        )
        pin = json.loads(path.read_text(encoding="utf-8"))
        if (pin["repo"], pin["tag"], pin["commit"]) != (
            "Facetomyself/ruyihttp",
            tag,
            commit,
        ):
            raise ValueError("Unexpected previous fork release")
        item = pin["wheels"][slot]
        return dict(
            item,
            url=f"https://github.com/Facetomyself/ruyihttp/releases/download/{tag}/"
            + item["name"],
        )
    if line != "upstream-0.11.0" or slot != "win_amd64":
        raise ValueError("Unsupported public release/target pair")
    pin = json.loads(UPSTREAM_PIN.read_text(encoding="utf-8"))
    if (
        pin["wheel_sha256"] != UPSTREAM_SHA
        or pin["wheel"] != "ruyihttp-0.11.0-py3-none-win_amd64.whl"
        or not pin["wheel_url"].startswith("https://files.pythonhosted.org/packages/")
    ):
        raise ValueError("Unexpected upstream control artifact")
    return dict(
        name=pin["wheel"],
        sha256=pin["wheel_sha256"],
        bytes=pin["wheel_size"],
        url=pin["wheel_url"],
    )


def check_bytes(spec, data):
    if len(data) != spec["bytes"] or hashlib.sha256(data).hexdigest() != spec["sha256"]:
        raise ValueError("Size or SHA-256 differs from the release: " + spec["name"])


def fetch(line, slot, directory):
    spec = asset_spec(line, slot)
    if spec["name"] != Path(spec["name"]).name or not 0 < spec["bytes"] < 16 * 1024**2:
        raise ValueError("Unexpected wheel filename or size")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / spec["name"]
    if path.exists():
        if not path.is_file() or path.is_symlink():
            raise ValueError("Invalid cached wheel path")
        check_bytes(spec, path.read_bytes())
        return path
    with urlopen(
        Request(spec["url"], headers={"User-Agent": "RuyiHttp-release-qualification"}),
        timeout=45,
    ) as response:
        data = response.read(spec["bytes"] + 1)
    check_bytes(spec, data)
    with path.open("xb") as wheel:
        wheel.write(data)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("line", choices=("fork-0.9.2", "fork-0.9.3", "upstream-0.11.0"))
    ap.add_argument("slot")
    ap.add_argument("directory", type=Path)
    args = ap.parse_args()
    selected = fetch(args.line, args.slot, args.directory)
    print(f"{selected.name}: sha256={asset_spec(args.line, args.slot)['sha256']}")
