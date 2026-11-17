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
import sys
import zipfile
from pathlib import Path

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

DEFAULT_RUNTIME = {
    "win_amd64": {"firefox": "159.0", "nss": "3.131", "nspr": "4.40", "neqo": "0.32.0"},
    "darwin_arm64": {"firefox": "159.0", "nss": "3.132", "nspr": "4.40", "neqo": "0.33.0"},
    "linux_x86_64": {"firefox": "159.0", "nss": "3.132", "nspr": "4.40", "neqo": "0.33.0"},
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def write_manifest(data: dict) -> None:
    MANIFEST.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def wheel_members(wheel: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel) as archive:
        return {Path(name).name: archive.read(name) for name in archive.namelist()}


def import_wheel(wheel: Path, platform: str) -> None:
    expected = PLATFORM_FILES.get(platform)
    if not expected:
        raise SystemExit(
            f"{platform} is build-required; no wheel import list is defined. "
            "Build the native runtime first, then add it to PLATFORM_FILES."
        )
    members = wheel_members(wheel)
    missing = [name for name in expected if name not in members]
    if missing:
        raise SystemExit(f"{wheel.name} is missing: {', '.join(missing)}")

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
        "wheel_sha256": sha256(wheel),
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
    parser.add_argument("--wheel", type=Path, help="ruyijs/ff-ruyijs wheel to import")
    parser.add_argument("--platform", choices=sorted(PLATFORM_FILES))
    parser.add_argument("--check", action="store_true", help="verify manifest hashes")
    args = parser.parse_args()

    if args.check:
        return check()
    if not args.wheel or not args.platform:
        parser.print_help()
        return 2
    import_wheel(args.wheel, args.platform)
    return check()


if __name__ == "__main__":
    sys.exit(main())
