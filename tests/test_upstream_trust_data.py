"""The Firefox 161 data selection is independent of any particular native slot."""

import base64
import hashlib
import json
from pathlib import Path
import re
import unittest

import ruyihttp
from ruyihttp import Request, Session


class UpstreamTrustDataTests(unittest.TestCase):
    def test_anchors_and_active_distrust_cutoff(self):
        package = Path(ruyihttp.__file__).resolve().parent
        bundle = (package / "firefox-roots.pem").read_bytes()
        blocks = re.findall(
            rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", bundle, re.S
        )
        fingerprints = {
            hashlib.sha256(
                base64.b64decode(b"".join(b.split()), validate=True)
            ).hexdigest()
            for b in blocks
        }
        self.assertEqual(len(blocks), 118)
        self.assertEqual(len(fingerprints), 118)
        for removed in (
            "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f",
            "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
            "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3",
        ):
            self.assertNotIn(removed, fingerprints)
        constraints = json.loads(
            (package / "firefox-root-constraints.json").read_text()
        )
        self.assertEqual(
            constraints,
            {
                "2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f": "260415235959Z"
            },
        )
        self.assertLessEqual(set(constraints), fingerprints)

    def test_updated_psl_is_used_by_fetch_metadata_and_strict_cookies(self):
        for source, target, relation in [
            ("one.abyme.dev", "two.abyme.dev", "cross-site"),
            ("app.one.abyme.dev", "api.one.abyme.dev", "same-site"),
            ("app.example.co.uk", "api.example.co.uk", "same-site"),
            ("10.1.2.3", "10.9.2.3", "cross-site"),
        ]:
            with (
                self.subTest(source=source, target=target),
                Session(context="fetch", document_url=f"https://{source}/") as session,
            ):
                session.trust_env = False
                session.cookies.set(
                    "marker",
                    "target",
                    domain=target,
                    path="/",
                    secure=True,
                    rest={"SameSite": "Strict"},
                )
                r = session.prepare_request(Request("GET", f"https://{target}/"))
                self.assertEqual(r.headers["Sec-Fetch-Site"], relation)
                self.assertEqual(
                    r.headers.get("Cookie"),
                    "marker=target" if relation == "same-site" else None,
                )
