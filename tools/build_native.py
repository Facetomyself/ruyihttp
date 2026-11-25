#!/usr/bin/env python3
"""Import or verify ruyihttp native runtimes.

This is a private maintenance helper. It does not rebuild Firefox or NSS; it
imports a pinned ruyijs/ff-ruyijs wheel into native/<platform>/ and records the
provenance and hashes in ruyihttp/runtime-manifest.json.

Examples:
    python tools/build_native.py --wheel path/to/ruyijs.whl --platform linux_x86_64
    python tools/build_native.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import struct
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
MANIFEST = ROOT / "ruyihttp" / "runtime-manifest.json"

PLATFORM_FILES = {
    "win_amd64": [
        "necko_core.dll",
        "necko_quic.dll",
        "nss3.dll",
        "softokn3.dll",
        "freebl3.dll",
        "mozglue.dll",
    ],
    "darwin_arm64": [
        "libnecko_core.dylib",
        "libnecko_quic.dylib",
        "libnss3.dylib",
        "libsoftokn3.dylib",
        "libfreebl3.dylib",
        "libmozglue.dylib",
    ],
    "linux_x86_64": [
        "libnecko_core.so",
        "libnecko_quic.so",
        "libnss3.so",
        "libnssutil3.so",
        "libssl3.so",
        "libnspr4.so",
        "libplc4.so",
        "libplds4.so",
        "libsoftokn3.so",
        "libfreebl3.so",
        "libfreeblpriv3.so",
        "libsqlite3.so",
        "libnssckbi.so",
        "libnsssysinit.so",
    ],
}

# These two slots use the same native ABI/closure as their sibling architecture.
PLATFORM_FILES["linux_aarch64"] = PLATFORM_FILES["linux_x86_64"]
PLATFORM_FILES["darwin_x86_64"] = PLATFORM_FILES["darwin_arm64"]

DEFAULT_RUNTIME = {
    "win_amd64": {"firefox": "159.0", "nss": "3.131", "nspr": "4.40", "neqo": "0.32.0"},
    "darwin_arm64": {"firefox": "159.0", "nss": "3.132", "nspr": "4.40", "neqo": "0.33.0"},
    "linux_x86_64": {"firefox": "159.0", "nss": "3.132", "nspr": "4.40", "neqo": "0.33.0"},
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def write_manifest(data: dict) -> None:
    MANIFEST.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def bound_zip(stream) -> None:
    """Check the ordinary single-disk ZIP directory before zipfile allocates it."""
    size = stream.seek(0, 2)
    if not 22 <= size <= 256 * 1024**2:
        raise ValueError('wheel size exceeds the native inspection budget')
    start = max(0, size - 65557)
    stream.seek(start)
    trailer = stream.read(65557)
    pos = trailer.rfind(b'PK\x05\x06')
    if pos < 0 or len(trailer) - pos < 22:
        raise ValueError('missing bounded wheel directory')
    disk, directory_disk, here, all_members, directory_bytes, offset, comment = struct.unpack_from('<HHHHIIH', trailer, pos + 4)
    if (disk or directory_disk or here != all_members or all_members > 16384 or
            directory_bytes > 4 * 1024**2 or offset + directory_bytes != start + pos or pos + comment + 22 != len(trailer)):
        raise ValueError('wheel central directory exceeds the directory budget or is not an ordinary ZIP')


def wheel_members(wheel: Path, expected: list[str]) -> dict[str, bytes]:
    with wheel.open('rb') as stream:
        bound_zip(stream)
        with zipfile.ZipFile(stream) as archive:
            return selected_members(archive, wheel.name, expected)


def selected_members(archive: zipfile.ZipFile, wheel_name: str, expected: list[str]) -> dict[str, bytes]:
    if len(archive.infolist()) > 16384:
        raise ValueError('wheel central directory exceeds the member budget')
    selected = {}
    total = 0
    for item in archive.infolist():
        path = PurePosixPath(item.filename.replace('\\', '/'))
        name = path.name
        if name not in expected:
            continue
        kind = stat.S_IFMT(item.external_attr >> 16)
        if (name in selected or path.is_absolute() or '..' in path.parts or item.orig_filename != path.as_posix()
                or item.is_dir() or kind not in (0, stat.S_IFREG) or item.flag_bits & 1
                or not 0 < item.file_size <= 32 * 1024**2):
            raise ValueError('ambiguous, linked or oversized native wheel member: ' + item.filename)
        total += item.file_size
        if total > 64 * 1024**2:
            raise ValueError('native wheel members exceed the read budget')
        selected[name] = item
    if missing := sorted(set(expected) - selected.keys()):
        raise ValueError(f'{wheel_name} is missing: {", ".join(missing)}')
    # ZipFile.read verifies CRC when the selected ZipExtFile reaches EOF.
    return {name: archive.read(item) for name, item in selected.items()}


def inspect_wheel(wheel: Path, platform: str) -> dict[str, bytes]:
    expected = PLATFORM_FILES.get(platform)
    if not expected:
        raise ValueError(f'{platform} is build-required; no wheel import list is defined')
    members = wheel_members(wheel, expected)
    for name, data in members.items():
        check_architecture(platform, name, data)
    return members


def check_architecture(platform: str, name: str, data: bytes) -> None:
    if platform.startswith("linux_"):
        machine = {"linux_x86_64": 62, "linux_aarch64": 183}[platform]
        if (data[:7] != b'\x7fELF\x02\x01\x01' or
                data[16:20] != struct.pack('<HH', 3, machine)):
            raise ValueError(f'{name}: not a little-endian {platform} ELF shared library')
    if platform.startswith('darwin_'):
        machine = {'darwin_x86_64': 0x01000007, 'darwin_arm64': 0x0100000C}[platform]
        if (data[:8] != struct.pack('<II', 0xFEEDFACF, machine) or
                data[12:16] != struct.pack('<I', 6)):
            raise ValueError(f'{name}: not a thin {platform} Mach-O dylib')
    if platform == 'win_amd64':
        pe = int.from_bytes(data[0x3c:0x40], 'little')
        if (data[:2] != b'MZ' or not 0x40 <= pe <= len(data) - 26 or
                data[pe:pe + 6] != b'PE\x00\x00\x64\x86' or
                not int.from_bytes(data[pe + 22:pe + 24], 'little') & 0x2000 or
                data[pe + 24:pe + 26] != b'\x0b\x02'):
            raise ValueError(f'{name}: not a Windows x64 PE32+ DLL')


def inspect_stable_wheel(wheel: Path, platform: str) -> tuple[dict[str, bytes], str]:
    if not wheel.is_file() or not 22 <= wheel.stat().st_size <= 256 * 1024**2:
        raise ValueError('wheel size exceeds the native inspection budget')
    before = sha256(wheel)
    members = inspect_wheel(wheel, platform)
    if sha256(wheel) != before:
        raise ValueError('wheel bytes changed during inspection')
    return members, before


def import_wheel(wheel: Path, platform: str) -> None:
    if platform not in DEFAULT_RUNTIME:
        raise ValueError(f'{platform}: use stage_native_candidate.py on the target host')
    members, wheel_sha256 = inspect_stable_wheel(wheel, platform)
    expected = PLATFORM_FILES[platform]

    destination = NATIVE / platform
    destination.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in expected:
        data = members[name]
        path = destination / name
        path.write_bytes(data)
        files[name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    runtime = DEFAULT_RUNTIME.get(platform, {})
    provenance = {
        "platform": platform,
        "source": wheel.name,
        "wheel_sha256": wheel_sha256,
        "runtime": runtime,
        "files": files,
        "license": (
            "ruyijs/ff-ruyijs is AGPL-3.0-only or commercial; "
            "Mozilla-derived parts are MPL-2.0. Private use only until relicensed."
        ),
    }
    (destination / "provenance.json").write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (destination / "SHA256SUMS").write_text(
        "".join(f"{item['sha256']}  {name}\n" for name, item in files.items()),
        encoding="utf-8",
        newline="\n",
    )

    manifest = load_manifest()
    entry = manifest.setdefault("platforms", {}).setdefault(platform, {})
    entry.update(runtime)
    entry["status"] = "ready"
    entry["files"] = {name: item["sha256"] for name, item in files.items()}
    write_manifest(manifest)
    print(f"imported {len(files)} files into {destination}")


def check() -> int:
    manifest = load_manifest()
    failed = 0
    for platform, entry in manifest.get("platforms", {}).items():
        if entry.get("status") != "ready":
            print(f"{platform}: build-required")
            continue
        directory = NATIVE / platform
        if not directory.is_dir():
            print(f"{platform}: missing directory {directory}")
            failed += 1
            continue
        for name, expected in entry.get("files", {}).items():
            path = directory / name
            if not path.is_file():
                print(f"{platform}: missing {name}")
                failed += 1
                continue
            actual = sha256(path)
            if actual != expected:
                print(f"{platform}: hash mismatch {name}")
                failed += 1
        print(f"{platform}: {len(entry.get('files', {}))} files checked")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--wheel", type=Path, help="historical wheel import into the selected platform slot")
    source.add_argument("--inspect-wheel", type=Path, help="read-only inspection of a wheel; no imports or manifest changes")
    parser.add_argument("--platform", choices=sorted(PLATFORM_FILES))
    parser.add_argument("--check", action="store_true", help="verify manifest hashes")
    args = parser.parse_args()

    if args.check:
        return check()
    if not (args.wheel or args.inspect_wheel) or not args.platform:
        parser.print_help()
        return 2
    try:
        if args.inspect_wheel:
            members, digest = inspect_stable_wheel(args.inspect_wheel, args.platform)
            print(json.dumps(dict(scope='read-only wheel members',platform=args.platform,wheel_sha256=digest,
                                  files={name:dict(size=len(data),sha256=hashlib.sha256(data).hexdigest())
                                         for name,data in sorted(members.items())}),indent=2))
            return 0
        import_wheel(args.wheel, args.platform)
        return check()
    except (OSError,ValueError,zipfile.BadZipFile) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
