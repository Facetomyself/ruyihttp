#!/usr/bin/env python3
"""In-place upgrade: original PyPI Windows wheel or previous, Git-pinned POSIX 0.9.0."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.request import urlretrieve
import venv
from zipfile import ZipFile

CI = Path(__file__).resolve().parent
PROVENANCE = CI.parent / "native/win_amd64/provenance.json"


def main():
    candidate = Path(sys.argv[1]).resolve(strict=True)
    candidate_version = candidate.name.split("-")[1]
    slot = sys.argv[2] if len(sys.argv) > 2 else "win_amd64"
    assert candidate_version != "0.9.0"
    with tempfile.TemporaryDirectory(prefix="ruyihttp-upgrade-") as directory:
        root = Path(directory)
        if slot == "win_amd64":
            provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
            baseline = root / provenance["wheel"]
            assert baseline.name == "ruyihttp-0.9.0-py3-none-win_amd64.whl"
            urlretrieve(provenance["wheel_url"], baseline)
            assert (
                hashlib.sha256(baseline.read_bytes()).hexdigest()
                == provenance["wheel_sha256"]
            )
            hashes = {k: value["sha256"] for k, value in provenance["files"].items()}
            source = "published PyPI wheel"
        else:
            previous = Path(os.environ["RUYIHTTP_PREVIOUS_BUILD"]).resolve(strict=True)
            (baseline,) = (previous / "wheels").glob("ruyihttp-0.9.0-*.whl")
            checkout = previous / "source"
            source = subprocess.check_output(
                ["git", "-C", checkout, "rev-parse", "HEAD"], text=True
            ).strip()
            assert source == "ea44f8fe4468bbee80996e4e73745d6d53c072cc", source
            origin = subprocess.check_output(
                ["git", "-C", checkout, "show", "HEAD:ruyihttp/runtime-manifest.json"]
            )
            hashes = json.loads(origin)["platforms"][slot]["files"]
        with ZipFile(baseline) as wheel:
            assert hashes and all(
                hashlib.sha256(wheel.read("ruyihttp/" + n)).hexdigest() == h
                for n, h in hashes.items()
            )
        print(
            f"baseline={baseline.name} source={source} sha256={hashlib.sha256(baseline.read_bytes()).hexdigest()}; {len(hashes)} native files matched",
            flush=True,
        )
        venv.EnvBuilder(with_pip=True).create(root / "venv")
        python = (
            root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        )

        def call(*args):
            subprocess.run([python, "-I", *args], cwd=root, check=True)

        def version(expected):
            call(
                "-c",
                """
import importlib.metadata as metadata
from pathlib import Path
import sys
import ruyihttp
expected = sys.argv[1]
versions = [dist.version for dist in metadata.distributions(name='ruyihttp')]
assert versions == [expected] and ruyihttp.__version__ == expected, (versions, ruyihttp.__version__)
root = Path(ruyihttp.__file__).resolve().parent
assert root.is_relative_to(Path(sys.prefix).resolve()), root
print(f'installed {expected} with Python {sys.version.split()[0]} in {root}', flush=True)
""",
                expected,
            )

        call("-m", "pip", "install", str(baseline))
        version("0.9.0")
        call(CI / "smoke_local.py")
        call("-m", "pip", "install", "--upgrade", str(candidate))
        call("-m", "pip", "check")
        version(candidate_version)
        call(CI / "verify_installed.py", slot, candidate)
        call(CI / "smoke_local.py")
        print(
            f"PASS: in-place 0.9.0 -> {candidate_version}; one distribution, native hashes, HTTP before and after",
            flush=True,
        )


if __name__ == "__main__":
    main()
