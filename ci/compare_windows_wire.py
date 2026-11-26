"""Measure the unmodified PyPI Windows wheel, published fork, and candidate independently.

Use fresh Python processes and verified input wheel hashes. A previous or
upstream difference is evidence, not a failure of that project's own contract.
The candidate is compared to Firefox (not to either other Python wheel).
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory
import venv
from zipfile import ZipFile

CI = Path(__file__).resolve().parent
sys.path.insert(0, str(CI))
from release_inputs import asset_spec, fetch

SLOT = "win_amd64"
IDENTITY = """import hashlib, importlib.metadata as metadata, json, sys
from pathlib import Path
from zipfile import ZipFile
import ruyihttp
root=Path(ruyihttp.__file__).resolve().parent
versions=[d.version for d in metadata.distributions(name='ruyihttp')]
assert versions==[sys.argv[2]] and ruyihttp.__version__==sys.argv[2] and root.is_relative_to(Path(sys.prefix).resolve()),(versions,root)
with ZipFile(sys.argv[1]) as z:
    native={Path(n).name:z.read(n) for n in z.namelist() if n.startswith('ruyihttp/') and n.endswith('.dll')}
    assert len(native)==6 and {p.name for p in root.glob('*.dll')}==set(native)
    assert all((root/n).read_bytes()==b for n,b in native.items())
    for n in z.namelist():
        if n.startswith('ruyihttp/') and n.endswith('.py'):
            assert (root.parent/n).read_bytes()==z.read(n),n
print(json.dumps({'version':versions[0],'default_firefox':ruyihttp.DEFAULT_FIREFOX,'dll_sha256':{n:hashlib.sha256(b).hexdigest() for n,b in native.items()},'python':sys.version.split()[0], 'dependencies':{n:metadata.version(n) for n in ('aioquic','h2','cryptography','requests')}}))"""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("candidate_wheel", type=Path)
    ap.add_argument("evidence", type=Path)
    ap.add_argument("--release", choices=["159", "160", "161"], default="161")
    args = ap.parse_args()
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        ap.error("the upstream 0.11.0 Windows binary requires native Windows x64")
    candidate = args.candidate_wheel.resolve(strict=True)
    if not candidate.name.startswith("ruyihttp-0.9.3-") or not candidate.name.endswith(
        "-win_amd64.whl"
    ):
        ap.error("expected the fork 0.9.3 Windows release-format candidate")
    args.evidence = args.evidence.resolve()
    args.evidence.mkdir(exist_ok=True, parents=True)
    env = dict(
        os.environ,
        PYTHONUTF8="1",
        PYTHONIOENCODING="utf-8",
        PIP_DISABLE_PIP_VERSION_CHECK="1",
    )
    for k in (
        "NECKO_CORE_LIBRARY",
        "NECKO_QUIC_LIBRARY",
        "NECKO_FIREFOX",
        "RUYIHTTP_MACHINE",
        "RUYIHTTP_PLATFORM",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ):
        env.pop(k, None)
    with TemporaryDirectory(prefix="ruyihttp-windows-wire-") as tmp:
        tmp = Path(tmp)
        wheels = {
            n: fetch(n, SLOT, tmp / "inputs") for n in ("upstream-0.11.0", "fork-0.9.2")
        }
        wheels["candidate"] = candidate
        venv.EnvBuilder(with_pip=True).create(tmp / "python")
        python = tmp / "python/Scripts/python.exe"

        def call(*args, stdout=None):
            return subprocess.run(
                [str(python), "-I", *map(str, args)],
                cwd=tmp,
                env=env,
                check=True,
                text=True,
                encoding="utf-8",
                stdout=stdout,
            )

        # Install ordinary dependencies once, then switch the client by its exact
        # wheel path with no resolution. Each measurement gets a fresh interpreter.
        call(
            "-m",
            "pip",
            "install",
            "aioquic==1.3.0",
            "h2==4.3.0",
            "cryptography==46.0.3",
            wheels["upstream-0.11.0"],
        )
        results = {}
        for label, wheel in wheels.items():
            version = wheel.name.split("-")[1]
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            if label != "candidate" and digest != asset_spec(label, SLOT)["sha256"]:
                raise ValueError("unexpected comparison wheel: " + label)
            if label != "upstream-0.11.0":
                call(
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--force-reinstall",
                    wheel,
                )
            call("-m", "pip", "check")
            identity = json.loads(
                call("-c", IDENTITY, wheel, version, stdout=subprocess.PIPE).stdout
            )
            with ZipFile(wheel) as z:
                if set(identity["dll_sha256"]) != {
                    Path(n).name for n in z.namelist() if n.endswith(".dll")
                }:
                    raise ValueError("invalid reported native inventory")
            output = args.evidence / (label + ".jsonl")
            call(
                CI / "smoke_firefox_profiles.py",
                SLOT,
                "--collect",
                "--release",
                args.release,
                "--output",
                output,
            )
            record = json.loads(output.read_text(encoding="utf-8").strip())
            if (
                record["source"],
                record["package_version"],
                record["firefox"],
                record["slot"],
            ) != ("installed-wheel", version, args.release, SLOT):
                raise ValueError("incorrect capture identity: " + label)
            results[label] = {
                "filename": wheel.name,
                "sha256": digest,
                "identity": identity,
                "wire_file": output.name,
                "wire_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            }
        if (
            results["upstream-0.11.0"]["identity"]["dll_sha256"]
            != results["candidate"]["identity"]["dll_sha256"]
        ):
            raise ValueError(
                "candidate is no longer using the verified upstream Windows runtime; re-evaluate comparator"
            )
    (args.evidence / "peers.json").write_text(
        json.dumps({"slot": SLOT, "firefox": args.release, "peers": results}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(
        "Measured original upstream, previous fork and candidate; same host, pinned binaries, independent installs."
    )


if __name__ == "__main__":
    main()
