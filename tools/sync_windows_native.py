#!/usr/bin/env python3
"""Inspect or import only the six Windows x64 DLLs from pinned PyPI ruyihttp 0.11.0."""

import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
import stat
import struct
import sys
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from build_native import MANIFEST, NATIVE, PLATFORM_FILES, ROOT, bound_zip, check_architecture

SLOT = "win_amd64"
VERSION = "0.11.0"
NAMES = tuple(sorted(PLATFORM_FILES[SLOT]))
WHEEL = f"ruyihttp-{VERSION}-py3-none-{SLOT}.whl"
WHEEL_SIZE = 4020032
WHEEL_SHA256 = "79eb2f08326c5f1e0a9ffddecef5136f45b50aefe952051f878e514a63939332"
RECORD_SHA256 = "07cc82f7c2cec08b1bae1a834774ec92127054ccb797f4a015aea452193904ca"
METADATA_SHA256 = "4710e57c9d60a235a5eac5e217252e4409f46a97fda7c17e3355413972a2652c"
UPSTREAM_MANIFEST_SHA256 = "300c07d7b8cd0075ad7184aa1f2c15522b15bef06f691033ed01790f4a614d8a"
PYPI_METADATA = f"https://pypi.org/pypi/ruyihttp/{VERSION}/json"
SOURCE_REPOSITORY = "https://github.com/charlesval/ruyiHttp"
WHEEL_URL = ("https://files.pythonhosted.org/packages/f5/76/"
             "5e918b50ec3021414d525993add261f54dafa107bc64128bdc3cf29d79b1/" + WHEEL)
BASELINE = ROOT / "ci/baselines/windows-0.9.0.json"
RUNTIME = {"firefox": "161.0", "nss": "3.133", "nspr": "4.40", "neqo": "0.34.0"}
H3_VERSION = {"type": "ascii", "value": "neqo-0.34.0/nss-3.133"}
CORE_ABI_VERSION = 1
DLL_SHA256 = {
    "freebl3.dll": "1e85ef195eb594307cd14a6ef4b3925a65cea145dbe5ff4c7d3c6aa9566001f7",
    "mozglue.dll": "951e5c58d4124ef7b1aa6f561bb2a9b603a0621c5729cd906d633aa8396b4628",
    "necko_core.dll": "91a730b6a94b796567d1a0673e9d9cfbaee00f7c6a87dfbf5ad149732eebd7c7",
    "necko_quic.dll": "e46605309069e4acf4222e145c81d21a94bb185d2dadac4dbf557740aa36adad",
    "nss3.dll": "4572738240953cd79cb738bd07181b7df752b11d865124b7037ddb5424fccbf1",
    "softokn3.dll": "ca89dc62645d8ac56d37ea2323fbef6fc24f852b42486f32db2ff0526bdec105",
}
# SHA-256 of sorted ASCII named exports, one per LF-terminated line. Identical
# to the corresponding bridge sets in the original Windows 0.9.0 wheel.
BRIDGES = {
    "necko_core.dll": (50, "e74f75e86e6a6dce674e3ac85a4bac12ffb16633082d0f74c1e72e6e71711796"),
    "necko_quic.dll": (4, "14b26c69c6e9fbe1dc3b657861309fff770ee647373fa37a9b54a672b7e286e9"),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record_hash(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def json_text(doc):
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def pe_inventory(name, data):
    """Read named imports/exports from a PE32+ file without loading any DLL."""
    check_architecture(SLOT, name, data)

    def u16(at):
        return struct.unpack_from("<H", data, at)[0]

    def u32(at):
        return struct.unpack_from("<I", data, at)[0]

    pe = u32(0x3C)
    opt = pe + 24
    if u16(pe + 20) < 128 or u32(opt + 108) < 2 or not 1 <= u16(pe + 6) <= 96:
        raise ValueError(f"{name}: invalid PE headers")
    sections = opt + u16(pe + 20)
    ranges = [struct.unpack_from("<III", data, sections + 40 * i + 12)
              for i in range(u16(pe + 6))]

    def location(rva, size):
        hits = [(start + rva - address, start + length) for address, length, start in ranges
                if address <= rva and rva + size <= address + length and start + length <= len(data)]
        if len(hits) != 1:
            raise ValueError(f"{name}: invalid PE RVA {rva:#x}")
        return hits[0]

    def string(rva):
        start, stop = location(rva, 1)
        return data[start:data.index(0, start, min(stop, start + 4096))].decode("ascii")

    export, _ = location(u32(opt + 112), 40)
    count = u32(export + 24)
    if not 1 <= count <= 10000:
        raise ValueError(f"{name}: invalid PE export count")
    table, _ = location(u32(export + 32), 4 * count)
    exports = [string(u32(table + 4 * i)) for i in range(count)]
    if len(set(exports)) != count or any(not symbol for symbol in exports):
        raise ValueError(f"{name}: invalid named PE exports")

    import_size = u32(opt + 124)
    if not 20 <= import_size <= 4096 or import_size % 20:
        raise ValueError(f"{name}: invalid PE import size")
    imports, _ = location(u32(opt + 120), import_size)
    dependencies = []
    for entry in range(imports, imports + import_size, 20):
        if data[entry:entry + 20] == bytes(20):
            break
        dependencies.append(string(u32(entry + 12)))
    else:
        raise ValueError(f"{name}: unterminated PE imports")

    if name in BRIDGES:
        fingerprint = sha(("\n".join(sorted(exports)) + "\n").encode("ascii"))
        if (count, fingerprint) != BRIDGES[name]:
            raise ValueError(f"{name}: Windows bridge named exports differ from the 0.9.0 ABI")
    return {"file": name, "sha256": sha(data), "bytes": len(data), "machine": "0x8664",
            "image_base": hex(struct.unpack_from("<Q", data, opt + 24)[0]),
            "imports": dependencies, "exports": exports}


def inspect_wheel(path):
    if path.name != WHEEL or not path.is_file():
        raise ValueError(f"expected {WHEEL}")
    with path.open("rb") as source:
        raw = source.read(WHEEL_SIZE + 1)
    if len(raw) != WHEEL_SIZE or sha(raw) != WHEEL_SHA256:
        raise ValueError("wheel size or SHA-256 differs from the pinned PyPI release")
    stream = io.BytesIO(raw)
    bound_zip(stream)
    dist = f"ruyihttp-{VERSION}.dist-info/"
    manifest_path = "ruyihttp/runtime-manifest.json"
    selected_paths = {f"ruyihttp/{name}" for name in NAMES}

    with ZipFile(stream) as archive:
        members = {m.filename: m for m in archive.infolist()}
        if len(members) != len(archive.infolist()):
            raise ValueError("duplicate ZIP member")
        native_paths = {p for p in members if Path(p).suffix.lower() in {".dll", ".so", ".dylib"}}
        if native_paths != selected_paths:
            raise ValueError("unexpected wheel native member inventory")

        def checked_read(p, limit):
            member = members[p]
            if (member.orig_filename != p or member.is_dir() or member.flag_bits & 1
                    or stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG)
                    or not 0 < member.file_size <= limit):
                raise ValueError(f"invalid ZIP member: {p}")
            return archive.read(member)

        record = checked_read(dist + "RECORD", 65536)
        if sha(record) != RECORD_SHA256:
            raise ValueError("wheel RECORD SHA-256 differs from the reviewed release")
        rows = {}
        for p, digest, size in csv.reader(io.StringIO(record.decode("utf-8"), newline=""), strict=True):
            if p in rows:
                raise ValueError(f"duplicate RECORD entry: {p}")
            rows[p] = (digest, size)
        if rows.keys() != members.keys() or rows[dist + "RECORD"] != ("", ""):
            raise ValueError("wheel RECORD inventory differs from ZIP inventory")

        def verified_read(p, limit):
            data = checked_read(p, limit)
            if rows[p] != (record_hash(data), str(len(data))):
                raise ValueError(f"wheel RECORD mismatch: {p}")
            return data

        meta = verified_read(dist + "METADATA", 65536)
        if sha(meta) != METADATA_SHA256:
            raise ValueError("wheel METADATA differs from PyPI core-metadata SHA-256")
        meta = BytesParser().parsebytes(meta)
        if (meta["Name"], meta["Version"], meta["Author"]) != ("ruyihttp", VERSION, "LoseNine"):
            raise ValueError("unexpected upstream project identity")
        wheel_info = BytesParser().parsebytes(verified_read(dist + "WHEEL", 4096))
        if wheel_info.get_all("Tag") != [f"py3-none-{SLOT}"] or wheel_info["Root-Is-Purelib"] != "false":
            raise ValueError("wheel is not the expected platform build")
        donor = verified_read(manifest_path, 65536)
        if sha(donor) != UPSTREAM_MANIFEST_SHA256:
            raise ValueError("unexpected upstream native manifest")
        donor = json.loads(donor)
        if (donor["version"], donor["platform"]) != (VERSION, SLOT):
            raise ValueError("unexpected upstream native manifest identity")
        dlls = {name: verified_read(f"ruyihttp/{name}", 8 * 1024**2) for name in NAMES}
        if any(donor["sha256"][n] != sha(data) for n, data in dlls.items()):
            raise ValueError("wheel DLL SHA-256 differs from upstream manifest")
    return dlls


def provenance(dlls):
    return {
        "platform": SLOT,
        "source": "LoseNine's official ruyihttp 0.11.0 PyPI wheel; unmodified DLL import",
        "source_kind": "pypi-wheel-import",
        "pypi_metadata_url": PYPI_METADATA,
        "pypi_upload_time_utc": "2026-11-25T01:46:00.223121Z",
        "wheel": WHEEL, "wheel_url": WHEEL_URL, "wheel_sha256": WHEEL_SHA256,
        "wheel_size": WHEEL_SIZE, "wheel_record_sha256": RECORD_SHA256,
        "pypi_core_metadata_sha256": METADATA_SHA256,
        "wheel_runtime_manifest_sha256": UPSTREAM_MANIFEST_SHA256,
        "upstream_source_repository": SOURCE_REPOSITORY,
        "source_rebuild_performed": False,
        "firefox_reference_declared_by_upstream": {
            "tag": "FIREFOX_161_0_RELEASE", "sourcestamp": "001da97dd5c0", "build_id": "20261125000922",
        },
        "wheel_platform_tag": SLOT, "runtime_expected": RUNTIME,
        "core_abi_version": CORE_ABI_VERSION, "h3_version_export": H3_VERSION,
        "h3_tls_policy": "windows-legacy", "h3_body_abi": None,
        "files": {n: {"size": len(b), "sha256": sha(b), "wheel_member": f"ruyihttp/{n}",
                      "record_hash": record_hash(b)} for n, b in dlls.items()},
    }


def artifacts(dlls):
    if {n: sha(b) for n, b in dlls.items()} != DLL_SHA256:
        raise ValueError("Windows DLL SHA-256 differs from the pinned six-file donor set")
    report = [pe_inventory(n, dlls[n]) for n in NAMES]
    if H3_VERSION["value"].encode("ascii") + b"\0" not in dlls["necko_quic.dll"]:
        raise ValueError("Windows QUIC bridge version marker differs from expected")
    record = provenance(dlls)
    hashes = {n: f["sha256"] for n, f in record["files"].items()}
    manifest_subset = {**RUNTIME, "status": "ready", "wheel_platform_tag": SLOT,
                       "files": hashes, "core_abi_version": CORE_ABI_VERSION,
                       "h3_version_export": H3_VERSION, "h3_tls": "windows-legacy", "h3_body_abi": None}
    return record, report, manifest_subset


def slot_paths():
    folder = NATIVE / SLOT
    if folder.resolve(strict=True) != folder or not folder.is_dir():
        raise ValueError("Windows slot is not a regular checkout directory")
    libs = {p.name for p in folder.iterdir() if p.suffix.lower() in {".dll", ".so", ".dylib"}}
    if libs != set(NAMES):
        raise ValueError("unexpected Windows slot native inventory")
    for path in [MANIFEST, *(folder / n for n in (*NAMES, "SHA256SUMS", "provenance.json", "exports.json"))]:
        if path.resolve(strict=True) != path or not path.is_file():
            raise ValueError(f"not a regular tracked slot file: {path}")
    return folder


def check_slot(expected_dlls=None):
    folder = slot_paths()
    dlls = {n: (folder / n).read_bytes() for n in NAMES}
    if expected_dlls is not None and dlls != expected_dlls:
        raise ValueError("tracked Windows DLL bytes differ from the pinned wheel")
    record, report, expected = artifacts(dlls)
    current = read_json(MANIFEST)["platforms"][SLOT]
    stored = read_json(folder / "provenance.json")
    sums = "".join(f"{h}  {n}\n" for n, h in expected["files"].items())
    if (any(current.get(k) != v for k, v in expected.items())
            or any(stored.get(k) != v for k, v in record.items())
            or read_json(folder / "exports.json") != report
            or (folder / "SHA256SUMS").read_text(encoding="utf-8") != sums):
        raise ValueError("tracked Windows runtime metadata disagrees with DLLs or ABI policy")
    return record


def apply(dlls):
    folder = slot_paths()
    record, report, expected = artifacts(dlls)
    manifest = read_json(MANIFEST)
    entry = manifest["platforms"][SLOT]
    baseline = {n: f["sha256"] for n, f in read_json(BASELINE)["files"].items()}
    actual = {n: sha((folder / n).read_bytes()) for n in NAMES}
    if actual == expected["files"]:
        # Keep the original evidence receipt after a successful qualification.
        check_slot(dlls)
        return
    if actual != baseline or entry["files"] != baseline:
        raise ValueError("Windows staging requires the exact clean 0.9.0 native set")
    entry.update(expected)
    for name, data in dlls.items():
        (folder / name).write_bytes(data)
    (folder / "provenance.json").write_text(json_text(record), encoding="utf-8", newline="\n")
    (folder / "exports.json").write_text(json_text(report), encoding="utf-8", newline="\n")
    (folder / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in expected["files"].items()),
                                     encoding="utf-8", newline="\n")
    MANIFEST.write_text(json_text(manifest), encoding="utf-8", newline="\n")
    check_slot(dlls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, help="local copy of the pinned PyPI wheel")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="update only the tracked Windows native slot")
    mode.add_argument("--check-slot", action="store_true", help="check the tracked Windows files and metadata")
    args = parser.parse_args()
    if not args.wheel and not args.check_slot:
        parser.error("--wheel is required for inspection or apply")
    try:
        dlls = inspect_wheel(args.wheel) if args.wheel else None
        if args.apply:
            apply(dlls)
        report = check_slot(dlls) if args.check_slot else artifacts(dlls)[0]
        print(json_text(report), end="")
    except (BadZipFile, OSError, ValueError, KeyError, struct.error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
