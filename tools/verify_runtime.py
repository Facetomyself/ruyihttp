#!/usr/bin/env python3
"""Check native ABI symbols and runtime versions for each ready platform.

This is intentionally read-only. It uses PE/Mach-O/ELF parsing from lief when
installed, and falls back to byte scans for the version markers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
MANIFEST = ROOT / "ruyihttp" / "runtime-manifest.json"

CORE_SYMBOLS = {
    "necko_tls_open_profile",
    "necko_tls_nss_version",
    "necko_socket_open",
    "necko_exchange_open",
}
QUIC_SYMBOLS = {"necko_quic_call", "necko_quic_set_decoder"}
BODY_V1_SYMBOLS = {"necko_quic_body_abi_version", "necko_quic_body_read_v1", "necko_quic_body_write_v1"}


def names(platform: str) -> tuple[str, str]:
    if platform == "win_amd64":
        return "necko_core.dll", "necko_quic.dll"
    if platform.startswith("darwin"):
        return "libnecko_core.dylib", "libnecko_quic.dylib"
    return "libnecko_core.so", "libnecko_quic.so"


def read_export_names(path: Path) -> set[str]:
    try:
        import lief
    except ImportError:
        return set()
    binary = lief.parse(str(path))
    if binary is None:
        return set()
    if hasattr(binary, "exported_symbols"):
        names = {symbol.name.lstrip("_") for symbol in binary.exported_symbols}
        if names:
            return names
    return {symbol.name.lstrip("_") for symbol in binary.get_export().entries}


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failed = 0
    for platform, entry in manifest["platforms"].items():
        if entry.get("status") != "ready":
            continue
        core_name, quic_name = names(platform)
        core = NATIVE / platform / core_name
        quic = NATIVE / platform / quic_name
        print(f"{platform}: {entry['nss']} / {entry['neqo']}")
        quic_required = QUIC_SYMBOLS | (BODY_V1_SYMBOLS if entry.get('h3_body_abi') == 1 else set())
        for path, required in ((core, CORE_SYMBOLS), (quic, quic_required)):
            if not path.is_file():
                print(f"  missing {path.name}")
                failed += 1
                continue
            exported = read_export_names(path)
            if exported:
                missing = sorted(required - exported)
                if missing:
                    print(f"  {path.name}: missing exports {missing}")
                    failed += 1
                else:
                    print(f"  {path.name}: exports OK")
            else:
                data = path.read_bytes()
                missing = [name for name in required if name.encode() not in data]
                if missing:
                    print(f"  {path.name}: missing marker {missing}")
                    failed += 1
                else:
                    print(f"  {path.name}: markers OK (lief unavailable)")
        # The bridge calls NSS_GetVersion; it need not embed the library's
        # current release number. Check the NSS binary's own version record.
        nss = NATIVE / platform / ('nss3.dll' if platform == 'win_amd64' else
                                   'libnss3.dylib' if platform.startswith('darwin') else 'libnss3.so')
        expected = b'Version: NSS ' + entry['nss'].encode('ascii') + b'\x00'
        if not nss.is_file() or expected not in nss.read_bytes():
            print(f"  {nss.name}: missing NSS {entry['nss']} version record")
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
