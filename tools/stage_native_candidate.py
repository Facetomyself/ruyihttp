#!/usr/bin/env python3
"""Stage source-built native files in a disposable wheel-build checkout."""
import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from build_native import (NATIVE, PLATFORM_FILES, check_architecture, load_manifest,
                          sha256, write_manifest)

TARGETS = {"linux_aarch64": ("Linux", "aarch64"), "darwin_x86_64": ("Darwin", "x86_64")}


def macos_deployment(libs):
    floors = []
    for path in libs:
        info = subprocess.check_output(["xcrun", "vtool", "-show-build", path], text=True)
        versions = re.findall(r"^\s*(?:minos|version)\s+(\d+)\.(\d+)(?:\.(\d+))?$", info, re.M)
        if len(versions) != 1 or ("LC_BUILD_VERSION" in info and not re.search(r"platform\s+MACOS\b", info)):
            raise ValueError(f"missing or ambiguous macOS deployment target: {path.name}")
        floor = tuple(int(piece or 0) for piece in versions[0])
        floors.append(floor)
        deps = subprocess.check_output(["otool", "-L", path], text=True).splitlines()[1:]
        for line in deps:
            dep = line.strip().split(" (", 1)[0]
            if dep.startswith(("/usr/lib/", "/System/Library/")):
                continue
            if not any(dep == f"{prefix}/{sibling.name}" for sibling in libs
                       for prefix in ("@rpath", "@loader_path")):
                raise ValueError(f"{path.name}: non-system dependency outside bundle: {dep}")
        print(info.strip(), *deps, sep="\n")
    major, minor, patch = max(floors)
    if patch:
        # The wheel format cannot express a patch-level minimum.
        minor += 1
    return f"macosx_{major}_{minor}_x86_64"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=TARGETS)
    parser.add_argument("source", type=Path, help="directory holding the selected native libraries")
    parser.add_argument("--donor", required=True, help="donor Git commit")
    parser.add_argument("--firefox", required=True, help="Firefox Git commit")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != TARGETS[args.platform]:
        parser.error("staging requires execution on the selected native build host")
    if any(not re.fullmatch(r"[0-9a-f]{40}", rev) for rev in (args.donor, args.firefox)):
        parser.error("full Git commits are required")
    source = args.source.resolve(strict=True)
    dest = NATIVE / args.platform
    manifest = load_manifest()
    entry = manifest["platforms"][args.platform]
    names = PLATFORM_FILES[args.platform]
    if entry["status"] != "build-required" or any((dest / name).exists() for name in names):
        parser.error("candidate staging requires a fresh build-required slot")
    libs = [source / name for name in names]
    for path in libs:
        with path.open("rb") as stream:
            check_architecture(args.platform, path.name, stream.read(20))
    if args.platform == "linux_aarch64":
        from check_linux_candidate import check
        result = check(source, "aarch64")
        print(json.dumps(result, indent=2))
        tag = "manylinux_2_39_aarch64"
    else:
        tag = macos_deployment(libs)
    inventory = {}
    for path in libs:
        copied = Path(shutil.copy2(path, dest / path.name))
        inventory[path.name] = {"size": copied.stat().st_size, "sha256": sha256(copied)}
    runtime = {name: entry[name] for name in ("firefox", "nss", "nspr", "neqo")}
    provenance = {"platform": args.platform, "source": "source-built candidate, native verification required",
                  "ff_ruyijs_commit": args.donor, "firefox_source_commit": args.firefox,
                  "wheel_platform_tag": tag, "runtime_expected": runtime, "files": inventory}
    (dest / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    hashes = {name: item["sha256"] for name, item in inventory.items()}
    (dest / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in hashes.items()))
    entry.update(status="ready", wheel_platform_tag=tag, files=hashes)
    write_manifest(manifest)
    print(f"{args.platform} staged in disposable checkout, candidate tag {tag}")


if __name__ == "__main__":
    sys.exit(main())
