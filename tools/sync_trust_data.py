"""Check (default) or install only the reviewed Firefox roots, cutoffs and PSL.

All inputs are local files, matched by pinned SHA-256. Never import or run donor
code, extract a wheel to the package, or change profiles/native runtime entries.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "docs/upstream-0.11.0-data.json"


def digest(b):
    return hashlib.sha256(b).hexdigest()


def pinned(path, expected):
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"SHA-256 mismatch: {path.name}")
    return data


def octets(block, field):
    expr = rf"^{field} MULTILINE_OCTAL\n((?:[\\0-7]+\n)+)END$"
    match = re.search(expr, block, re.M)
    if not match:
        return None
    flat = match[1].replace("\n", "")
    if not re.fullmatch(r"(?:\\[0-7]{3})+", flat):
        raise ValueError(f"invalid octal bytes in {field}")
    return bytes(int(x, 8) for x in re.findall(r"\\([0-7]{3})", flat))


def server_anchors(certdata):
    certs, cutoffs, trusted = {}, {}, set()
    for block in re.split(
        r"(?=^CKA_CLASS CK_OBJECT_CLASS )", certdata.decode(), flags=re.M
    ):
        kind = block.split("\n", 1)[0]
        if kind == "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE":
            der = octets(block, "CKA_VALUE")
            if der is None:
                raise ValueError("missing DER certificate")
            # NSS certdata identifies a CKO_NSS_TRUST object's certificate by
            # CKA_CERT_SHA1_HASH. Report and compare identities using SHA-256.
            oid = hashlib.sha1(der, usedforsecurity=False).digest()
            if oid in certs:
                raise ValueError("duplicate NSS certificate identity")
            certs[oid] = digest(der)
            cutoff = octets(block, "CKA_NSS_SERVER_DISTRUST_AFTER")
            if cutoff is not None:
                cutoffs[oid] = cutoff.decode("ascii")
        elif kind == "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST" and re.search(
            r"^CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR$", block, re.M
        ):
            oid = octets(block, "CKA_CERT_SHA1_HASH")
            if oid is None or oid in trusted:
                raise ValueError("missing or duplicate server trust binding")
            trusted.add(oid)
    return {certs[t] for t in trusted}, {
        certs[t]: cutoffs[t] for t in trusted & cutoffs.keys()
    }


def pem_fingerprints(data):
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----\n(.*?)\n-----END CERTIFICATE-----",
        data.replace(b"\r\n", b"\n"),
        re.S,
    )
    fps = [digest(base64.b64decode(b"".join(b.split()), validate=True)) for b in blocks]
    if not fps or len(set(fps)) != len(fps):
        raise ValueError("empty or duplicate PEM anchors")
    return set(fps)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for arg in ("wheel", "certdata", "psl"):
        ap.add_argument("--" + arg, type=Path, required=True)
    ap.add_argument(
        "--apply",
        action="store_true",
        help="update the three data files and their manifest digests only",
    )
    args = ap.parse_args()
    pin = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    pinned(args.wheel, pin["upstream_wheel"]["sha256"])
    anchors, constraints = server_anchors(
        pinned(args.certdata, pin["mozilla"]["certdata_sha256"])
    )
    psl = pinned(args.psl, pin["mozilla"]["psl_sha256"])
    names = (
        "firefox-roots.pem",
        "firefox-root-constraints.json",
        "firefox-suffixes.dat",
    )
    with ZipFile(args.wheel) as z:
        files = {n: z.read("ruyihttp/" + n).replace(b"\r\n", b"\n") for n in names}
    if (
        pem_fingerprints(files[names[0]]) != anchors
        or len(anchors) != pin["server_root_count"]
        or json.loads(files[names[1]]) != constraints
        or files[names[2]] != psl
    ):
        raise ValueError("donor data differs from Mozilla server trust policy or PSL")
    hashes = {n: digest(b) for n, b in files.items()}
    if hashes != pin["installed_sha256"]:
        raise ValueError("normalized sidecar digests differ from the reviewed snapshot")
    package = ROOT / "ruyihttp"
    mf = package / "runtime-manifest.json"
    manifest = json.loads(mf.read_text(encoding="utf-8"))
    for name in names:
        if args.apply:
            (package / name).write_bytes(files[name])
            manifest["data"][name] = hashes[name]
        elif (package / name).read_bytes() != files[name] or manifest["data"][
            name
        ] != hashes[name]:
            raise SystemExit(f"outdated: {name}")
    if args.apply:
        mf.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    print(
        f"{len(anchors)} DER-identical TLS server anchors, {len(constraints)} issuer cutoff(s); PSL byte-identical to Mozilla; data OK"
    )


if __name__ == "__main__":
    main()
