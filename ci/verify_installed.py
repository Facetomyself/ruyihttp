"""Verify that a wheel job installed the native set for its actual runner."""

import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path

import ruyihttp
from ruyihttp._firefox import runtime_platform


def main(target):
    root = Path(ruyihttp.__file__).resolve().parent
    assert root.is_relative_to(Path(sys.prefix).resolve()), (
        f"not installed in interpreter: {root}"
    )
    assert runtime_platform() == target, (runtime_platform(), target)
    machine = platform.machine().lower()
    arches = {
        "win_amd64": {"amd64", "x86_64"},
        "linux_x86_64": {"x86_64"},
        "linux_aarch64": {"aarch64"},
        "darwin_arm64": {"arm64"},
        "darwin_x86_64": {"x86_64"},
    }
    assert machine in arches[target], (target, machine)
    manifest = json.loads((root / "runtime-manifest.json").read_text(encoding="utf-8"))
    version = importlib.metadata.version("ruyihttp")
    assert ruyihttp.__version__ == manifest["version"] == version
    assert set(importlib.metadata.metadata("ruyihttp").get_all("Project-URL")) == {
        "Homepage, https://github.com/Facetomyself/ruyihttp",
        "Repository, https://github.com/Facetomyself/ruyihttp",
        "Issues, https://github.com/Facetomyself/ruyihttp/issues",
        "Releases, https://github.com/Facetomyself/ruyihttp/releases",
    }
    if len(sys.argv) > 2:
        wheel_version = Path(sys.argv[2]).name.split("-")[1]
        assert version == wheel_version, (version, wheel_version)
    entry = manifest["platforms"][target]
    assert entry["status"] == "ready" and entry["files"], target
    libs = {
        p.name for p in root.iterdir() if p.suffix.lower() in (".dll", ".so", ".dylib")
    }
    assert libs == set(entry["files"]), libs.symmetric_difference(entry["files"])
    for name, digest in entry["files"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    print(
        f"installed ruyihttp {version} {target} on {platform.system()} {machine}: {len(libs)} native hashes verified in {root}"
    )


if __name__ == "__main__":
    main(sys.argv[1])
