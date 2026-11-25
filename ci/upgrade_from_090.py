#!/usr/bin/env python3
"""Upgrade in place from the sole public 0.9.0 distribution (Windows x64)."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.request import urlretrieve
import venv

BASELINE = "ruyihttp-0.9.0-py3-none-win_amd64.whl"
BASELINE_URL = (
    "https://files.pythonhosted.org/packages/1d/a0/"
    "282d771e7311f8c3e166f5ccd67533a37033ecddd7c6ad31ac8dbc31f597/" + BASELINE
)
BASELINE_SHA256 = "95b67581b2538194b9fc9b41b7f7077f1cb2767dbc5c776d404e78cd11d42f48"
CI = Path(__file__).resolve().parent


def main():
    candidate = Path(sys.argv[1]).resolve(strict=True)
    candidate_version = candidate.name.split("-")[1]
    assert candidate_version != "0.9.0" and candidate.name.endswith("-win_amd64.whl")
    with tempfile.TemporaryDirectory(prefix="ruyihttp-upgrade-") as directory:
        root = Path(directory)
        baseline = root / BASELINE
        urlretrieve(BASELINE_URL, baseline)
        assert hashlib.sha256(baseline.read_bytes()).hexdigest() == BASELINE_SHA256
        print(f"baseline={BASELINE} sha256={BASELINE_SHA256}", flush=True)
        venv.EnvBuilder(with_pip=True).create(root / "venv")
        python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

        def call(*args):
            subprocess.run([python, "-I", *args], cwd=root, check=True)

        def version(expected):
            call("-c", """
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
""", expected)

        call("-m", "pip", "install", str(baseline))
        version("0.9.0")
        call(CI / "smoke_local.py")
        call("-m", "pip", "install", "--upgrade", str(candidate))
        call("-m", "pip", "check")
        version(candidate_version)
        call(CI / "verify_installed.py", "win_amd64")
        call(CI / "smoke_local.py")
        print(f"PASS: in-place 0.9.0 -> {candidate_version}; one distribution, native hashes, HTTP before and after", flush=True)


if __name__ == "__main__":
    main()
