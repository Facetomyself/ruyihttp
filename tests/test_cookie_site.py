# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
from email.message import Message
from types import SimpleNamespace
from urllib.request import Request as CookieRequest

from ruyihttp import Request, Session


class CookieSiteTests(unittest.TestCase):
    def prepare(
        self, document_url, target, *, context="fetch", method="GET", same_sites=("Strict",)
    ):
        with Session(context=context, document_url=document_url) as session:
            # Model cookies set by the target, independent of the initiating document.
            headers = Message()
            for same_site in same_sites:
                headers.add_header(
                    "Set-Cookie",
                    f"{same_site.lower()}=target; Path=/; Secure; SameSite={same_site}",
                )
            session.cookies.extract_cookies(
                SimpleNamespace(info=lambda: headers), CookieRequest(target)
            )
            self.assertCountEqual(
                [cookie.name for cookie in session.cookies],
                [same_site.lower() for same_site in same_sites],
            )
            self.assertTrue(
                all(not cookie.domain_specified for cookie in session.cookies)
            )
            return session.prepare_request(Request(method, target)).headers

    def test_schemeful_site_controls(self):
        cases = (
            ("cross IPv4", "https://10.1.2.3/", "https://10.9.2.3/", "cross-site"),
            ("IPv4 ports", "https://10.1.2.3:8443/", "https://10.1.2.3/", "same-site"),
            ("IPv4 scheme", "http://10.1.2.3/", "https://10.1.2.3/", "cross-site"),
            ("IPv4 final dot", "https://10.1.2.3.:8443/", "https://10.1.2.3/",
             "same-site"),
            ("cross octal IPv4", "https://010.1.2.3/", "https://010.9.2.3/",
             "cross-site"),
            ("octal IPv4 alias", "https://010.1.2.3:8443/", "https://8.1.2.3/",
             "same-site"),
            ("hex shorthand vs integer IPv4", "https://0x8.0x010203:8443/",
             "https://134283779/", "same-site"),
            ("ambiguous numeric hosts", "https://09.1.2.3/", "https://09.9.2.3/",
             "cross-site"),
            ("related DNS", "https://www.example.co.uk/", "https://api.example.co.uk/",
             "same-site"),
            ("unrelated DNS", "https://www.example.co.uk/", "https://api.other.co.uk/",
             "cross-site"),
            ("private suffix", "https://alpha.github.io/", "https://beta.github.io/",
             "cross-site"),
            ("IPv6 same origin", "https://[2001:0DB8:0:0:0:0:0:1]:443/",
             "https://[2001:db8::1]/", "same-origin"),
            ("IPv6 ports", "https://[2001:0DB8:0:0:0:0:0:1]:8443/",
             "https://[2001:db8::1]/", "same-site"),
            ("cross IPv6", "https://[2001:db8::1]/", "https://[2001:db8::2]/",
             "cross-site"),
            ("mapped IPv6 spelling", "https://[::FFFF:10.1.2.3]:8443/",
             "https://[::ffff:a01:203]/", "same-site"),
            ("cross mapped IPv6", "https://[::ffff:10.1.2.3]/",
             "https://[::ffff:10.9.2.3]/", "cross-site"),
            ("IPv4 vs mapped IPv6", "https://10.1.2.3/",
             "https://[::ffff:10.1.2.3]/", "cross-site"),
            ("no document", None, "https://10.1.2.3/", "none"),
        )
        for name, document_url, target, relationship in cases:
            with self.subTest(case=name):
                headers = self.prepare(document_url, target)
                with self.subTest(header="Sec-Fetch-Site"):
                    self.assertEqual(headers["Sec-Fetch-Site"], relationship)
                with self.subTest(header="Cookie"):
                    self.assertEqual(
                        headers.get("Cookie"),
                        None if relationship == "cross-site" else "strict=target",
                    )

    def test_cross_site_cookie_modes(self):
        for context, method, expected in (
            ("fetch", "GET", ["none=target"]),
            ("navigation", "GET", ["lax=target", "none=target"]),
            ("navigation", "POST", ["none=target"]),
        ):
            with self.subTest(context=context, method=method):
                headers = self.prepare(
                    "https://10.1.2.3/", "https://10.9.2.3/", context=context,
                    method=method, same_sites=("Strict", "Lax", "None"),
                )
                self.assertEqual(headers["Sec-Fetch-Site"], "cross-site")
                self.assertCountEqual(headers["Cookie"].split("; "), expected)
