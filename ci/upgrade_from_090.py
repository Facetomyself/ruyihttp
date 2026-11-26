#!/usr/bin/env python3
"""Check normal in-place upgrades from the original line or either pinned fork release."""

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
PROVENANCE = CI / "baselines/windows-0.9.0.json"


def main():
    candidate = Path(sys.argv[1]).resolve(strict=True)
    candidate_version = candidate.name.split("-")[1]
    slot = sys.argv[2] if len(sys.argv) > 2 else "win_amd64"
    mode = tuple(sys.argv[3:])
    old_version = {
        (): "0.9.0",
        ("--from-fork-091",): "0.9.1",
        ("--from-fork-092",): "0.9.2",
    }[mode]
    fork_baseline = old_version == "0.9.1"
    assert candidate_version != old_version
    with tempfile.TemporaryDirectory(prefix="ruyihttp-upgrade-") as directory:
        root = Path(directory)
        if old_version == "0.9.2":
            sys.path.insert(0, str(CI))
            from release_inputs import OLD_COMMIT, asset_spec

            spec = asset_spec("fork-0.9.2", slot)
            baseline = (
                Path(os.environ["RUYIHTTP_RELEASE_092_DIR"]).resolve(strict=True)
                / spec["name"]
            )
            assert (
                baseline.is_file()
                and hashlib.sha256(baseline.read_bytes()).hexdigest() == spec["sha256"]
            )
            with ZipFile(baseline) as archive:
                manifest = json.loads(archive.read("ruyihttp/runtime-manifest.json"))
            assert manifest["version"] == old_version
            hashes = manifest["platforms"][slot]["files"]
            source = f"public GitHub Release v0.9.2 at {OLD_COMMIT}"
        elif slot == "win_amd64" and not fork_baseline:
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
            env_key = (
                "RUYIHTTP_FORK_091_BUILD"
                if fork_baseline
                else "RUYIHTTP_PREVIOUS_BUILD"
            )
            previous = Path(os.environ[env_key]).resolve(strict=True)
            (baseline,) = (previous / "wheels").glob(f"ruyihttp-{old_version}-*.whl")
            checkout = previous / "source"
            source = subprocess.check_output(
                ["git", "-C", checkout, "rev-parse", "HEAD"], text=True
            ).strip()
            expected = (
                "fae13b0a9eabbafbcdbf5c59438875525fcc0d0b"
                if fork_baseline
                else "ea44f8fe4468bbee80996e4e73745d6d53c072cc"
            )
            assert source == expected, source
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
        version(old_version)
        call(CI / "smoke_local.py")
        call("-m", "pip", "install", "--upgrade", str(candidate))
        call("-m", "pip", "check")
        version(candidate_version)
        call(CI / "verify_installed.py", slot, candidate)
        if fork_baseline:
            call(CI / "verify_trust_transition.py", baseline)
        call(CI / "smoke_local.py")
        print(
            f"PASS: in-place {old_version} -> {candidate_version}; one distribution, native hashes, HTTP before and after",
            flush=True,
        )


if __name__ == "__main__":
    main()
