#!/usr/bin/env python3
"""Stage source-built native files in a disposable wheel-build checkout."""
import argparse
import json
import platform
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

from build_native import (NATIVE, PLATFORM_FILES, ROOT, check_architecture, load_manifest,
                          sha256, write_manifest)

TARGETS = {
    'linux_aarch64': ('Linux', 'aarch64'),
    'linux_x86_64': ('Linux', 'x86_64'),
    'darwin_x86_64': ('Darwin', 'x86_64'),
    'darwin_arm64': ('Darwin', 'arm64'),
}


def macho_deployment_and_rpaths(path, slot='darwin_x86_64'):
    """Read the thin Mach-O deployment command, not vtool's linker version."""
    with path.open('rb') as stream:
        header = stream.read(32)
        check_architecture(slot, path.name, header)
        if len(header) != 32:
            raise ValueError(f'truncated Mach-O header: {path.name}')
        count, length = struct.unpack_from('<II', header, 16)
        if not 0 < count <= length // 8 or length > 1024**2:
            raise ValueError(f'oversize Mach-O load commands: {path.name}')
        commands = stream.read(length)
        if len(commands) != length:
            raise ValueError(f'truncated Mach-O load commands: {path.name}')
    offset, floors, rpaths = 0, [], []
    for _ in range(count):
        if offset + 8 > length:
            raise ValueError(f'truncated Mach-O load command: {path.name}')
        command, size = struct.unpack_from('<II', commands, offset)
        if size < 8 or size % 8 or offset + size > length:
            raise ValueError(f'invalid Mach-O load command: {path.name}')
        if command == 0x32:  # LC_BUILD_VERSION
            if size < 24 or struct.unpack_from('<I', commands, offset + 8)[0] != 1:
                raise ValueError(f'Mach-O does not specify macOS: {path.name}')
            floors.append(struct.unpack_from('<I', commands, offset + 12)[0])
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX
            if size != 16:
                raise ValueError(f'invalid Mach-O deployment command: {path.name}')
            floors.append(struct.unpack_from('<I', commands, offset + 8)[0])
        elif command == 0x8000001C:  # LC_RPATH
            if size < 16:
                raise ValueError(f'invalid Mach-O RPATH command: {path.name}')
            start = struct.unpack_from('<I', commands, offset + 8)[0]
            if not 12 <= start < size:
                raise ValueError(f'invalid Mach-O RPATH offset: {path.name}')
            rpaths.append(commands[offset + start:offset + size].split(b'\0', 1)[0])
        offset += size
    if offset != length or len(floors) != 1 or not floors[0]:
        raise ValueError(f'missing or ambiguous macOS deployment target: {path.name}')
    floor = floors[0]
    return (floor >> 16, (floor >> 8) & 255, floor & 255), rpaths


def macos_deployment(libs, slot):
    floors = {}
    for path in libs:
        info = subprocess.check_output(["xcrun", "vtool", "-show-build", path], text=True)
        print(info.strip(), flush=True)
        floor, rpaths = macho_deployment_and_rpaths(path, slot)
        floors[path.name] = floor
        if (any(rpath != b'@loader_path' for rpath in rpaths) or
                (path.name.startswith('libnecko_') and b'@loader_path' not in rpaths)):
            raise ValueError(f'{path.name}: loader search path is not limited to the sibling directory')
        deps = subprocess.check_output(["otool", "-L", path], text=True).splitlines()[1:]
        for line in deps:
            dep = line.strip().split(" (", 1)[0]
            if dep.startswith(("/usr/lib/", "/System/Library/")):
                continue
            if not any(dep == f"{prefix}/{sibling.name}" for sibling in libs
                       for prefix in ("@rpath", "@loader_path")):
                raise ValueError(f"{path.name}: non-system dependency outside bundle: {dep}")
        print(*deps, sep="\n", flush=True)
    major, minor, patch = max(floors.values())
    minimum = '.'.join(map(str, (major, minor, patch)))
    if major >= 11 and (minor or patch):
        # Modern pip emits major_0 tags; round up rather than claiming an
        # earlier release or emitting a tag no target can install.
        major, minor = major + 1, 0
    elif patch:
        minor += 1
    arch = TARGETS[slot][1]
    return f'macosx_{major}_{minor}_{arch}', minimum, {
        name: '.'.join(map(str, floor)) for name, floor in floors.items()}



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=TARGETS)
    parser.add_argument("source", type=Path, help="directory holding the selected native libraries")
    parser.add_argument("--donor", required=True, help="donor Git commit")
    parser.add_argument("--firefox", required=True, help="Firefox Git commit")
    parser.add_argument("--source-patch", type=Path, action='append', required=True,
                        help="applied donor patch under this repository (repeat in apply order)")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != TARGETS[args.platform]:
        parser.error("staging requires execution on the selected native build host")
    if any(not re.fullmatch(r"[0-9a-f]{40}", rev) for rev in (args.donor, args.firefox)):
        parser.error("full Git commits are required")
    patches = []
    for source_patch in args.source_patch:
        path = source_patch.resolve(strict=True)
        patches.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': sha256(path)})
    names_expected = ['h3-body-abi-v1.patch']
    if args.platform.startswith('darwin_'):
        names_expected.insert(0, 'macos-necko-quic-tls-info.patch')
        names_expected.append('macos-h3-global-handles.patch')
    if [p['path'] for p in patches] != [f'native/patches/{name}' for name in names_expected]:
        parser.error('expected pinned patches in build application order')
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
    deployment = {}
    if args.platform.startswith('linux_'):
        from check_linux_candidate import check
        arch = TARGETS[args.platform][1]
        result = check(source, arch)
        print(json.dumps(result, indent=2))
        tag = f'manylinux_2_39_{arch}'
    else:
        tag, minimum, floors = macos_deployment(libs, args.platform)
        deployment = {'minimum_macos': minimum, 'macho_minimum_macos': floors}
    inventory = {}
    for path in libs:
        copied = Path(shutil.copy2(path, dest / path.name))
        inventory[path.name] = {"size": copied.stat().st_size, "sha256": sha256(copied)}
    runtime = {name: entry[name] for name in ("firefox", "nss", "nspr", "neqo")}
    provenance = {"platform": args.platform, "source": "source-built candidate, native verification required",
                  "ff_ruyijs_commit": args.donor, "firefox_source_commit": args.firefox,
                  "wheel_platform_tag": tag, "runtime_expected": runtime, "files": inventory,
                  "source_patches": patches, "h3_body_abi_expected": 1, **deployment}
    (dest / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    hashes = {name: item["sha256"] for name, item in inventory.items()}
    (dest / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in hashes.items()))
    entry.update(status='ready', wheel_platform_tag=tag, files=hashes,
                 h3_tls='nss', h3_body_abi=1, **deployment)
    write_manifest(manifest)
    print(f"{args.platform} staged in disposable checkout, candidate tag {tag}")


if __name__ == "__main__":
    sys.exit(main())
