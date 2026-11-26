"""Exercise the three retired anchors, with an unchanged anchor as a positive control.

This is a CA trust-store membership check using each anchor as a self-signed
path, not evidence of revocation or validation of a real site's leaf.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile

RETIRED = {
    "emSign Root CA - C1": "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f",
    "emSign ECC Root CA - G3": "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "emSign ECC Root CA - C3": "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3",
}
CONTROL = (
    "ISRG Root X1",
    "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
)
# Fixed audit date inside the validity intervals, so expiry cannot masquerade as removal.
AT = int(datetime(2026, 11, 26, tzinfo=timezone.utc).timestamp())


def verify(previous, current):
    with ZipFile(previous) as baseline:
        before = baseline.read("ruyihttp/firefox-roots.pem")
    certs = {}
    for pem in re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", before, re.S
    ):
        body = b"".join(pem.splitlines()[1:-1])
        certs[hashlib.sha256(base64.b64decode(body, validate=True)).hexdigest()] = (
            pem + b"\n"
        )
    with TemporaryDirectory(prefix="ruyihttp-root-control-") as temp:
        root = Path(temp)
        old_bundle = root / "previous.pem"
        old_bundle.write_bytes(before)
        for name, fingerprint in [*RETIRED.items(), CONTROL]:
            anchor = root / (fingerprint + ".pem")
            anchor.write_bytes(certs[fingerprint])
            results = []
            for bundle in (old_bundle, current):
                p = subprocess.run(
                    [
                        "openssl",
                        "verify",
                        "-no-CAfile",
                        "-no-CApath",
                        "-no-CAstore",
                        "-CAfile",
                        str(bundle),
                        "-attime",
                        str(AT),
                        str(anchor),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                results.append((p.returncode, p.stdout))
            if results[0][0] or (name == CONTROL[0] and results[1][0]):
                raise RuntimeError(
                    f"{name}: retained/baseline control failed: {results}"
                )
            if name in RETIRED and (
                results[1][0] == 0
                or not re.search(r"error 18 at 0 depth lookup:", results[1][1])
            ):
                raise RuntimeError(
                    f"{name}: expected self-signed/untrusted, got {results[1]}"
                )
            print(
                f"{name}: previous trusted; candidate "
                + ("untrusted" if name in RETIRED else "trusted")
            )


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("previous_wheel", type=Path)
    ap.add_argument("--bundle", type=Path)
    args = ap.parse_args()
    if args.bundle is None:
        import ruyihttp

        args.bundle = Path(ruyihttp.__file__).resolve().parent / "firefox-roots.pem"
    verify(args.previous_wheel, args.bundle.resolve(strict=True))
