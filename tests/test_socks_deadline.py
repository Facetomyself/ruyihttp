# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""SOCKS DNS/encoding checks with PySocks and an in-memory proxy stream."""

import importlib.util
import io
import socket
import threading
import time
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

from requests.exceptions import ConnectTimeout, ProxyError

from ruyihttp._connect import Attempt
from ruyihttp._socks import negotiate

_TARGET = urlsplit("https://origin.test/")
_V4_REPLY = b"\x00\x5a\x00\x00\x00\x00\x00\x00"
_V5_REPLY = b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"
_V4_ADDRESS = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443))
_V6_ADDRESS = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", 443, 0, 5))


class _Stream:
    def __init__(self, scheme, attempt=None, response=None):
        self.attempt = attempt if attempt is not None else Attempt(None)
        self.writes = bytearray()
        if response is None:
            response = _V5_REPLY if scheme.startswith("socks5") else _V4_REPLY
        self.response = io.BytesIO(response)

    def read(self, size):
        return self.response.read(size)

    def write(self, data):
        self.writes.extend(data)


def _proxy(scheme):
    return urlsplit(f"{scheme}://proxy.test:1080/")


@unittest.skipUnless(importlib.util.find_spec("socks"), "Install ruyihttp[socks]")
class SocksDeadlineTests(unittest.TestCase):
    def test_local_dns_returns_on_deadline_while_lookup_is_blocked(self):
        for scheme in ("socks4", "socks5"):
            with self.subTest(scheme=scheme):
                entered = threading.Event()
                release = threading.Event()
                exited = threading.Event()
                errors = []
                stream = _Stream(scheme)

                def blocked(result):
                    entered.set()
                    try:
                        release.wait(3)
                        return result
                    finally:
                        exited.set()

                def connect():
                    stream.attempt = Attempt(time.monotonic() + 0.15)
                    try:
                        negotiate(stream, _proxy(scheme), _TARGET)
                    except Exception as error:
                        errors.append(error)

                with (
                    patch(
                        "socket.gethostbyname",
                        side_effect=lambda *args: blocked("192.0.2.10"),
                    ),
                    patch(
                        "socket.getaddrinfo",
                        side_effect=lambda *args, **kwargs: blocked([_V4_ADDRESS]),
                    ),
                ):
                    worker = threading.Thread(target=connect, daemon=True)
                    try:
                        worker.start()
                        self.assertTrue(
                            entered.wait(1), "local DNS lookup never started"
                        )
                        worker.join(0.85)
                        self.assertFalse(
                            worker.is_alive(), "SOCKS waited for unbounded target DNS"
                        )
                        self.assertEqual(len(errors), 1)
                        self.assertIsInstance(errors[0], ConnectTimeout)
                        self.assertEqual(stream.writes, b"")
                    finally:
                        release.set()
                        worker.join(1)
                        self.assertTrue(exited.wait(1))

    def test_remote_dns_sends_original_hostname_without_local_lookup(self):
        for scheme, request in (
            ("socks4a", b"\x04\x01\x01\xbb\x00\x00\x00\x01\x00origin.test\x00"),
            ("socks5h", b"\x05\x01\x00\x05\x01\x00\x03\x0borigin.test\x01\xbb"),
        ):
            with self.subTest(scheme=scheme):
                stream = _Stream(scheme)
                with (
                    patch(
                        "socket.gethostbyname",
                        side_effect=AssertionError("unexpected DNS"),
                    ),
                    patch(
                        "socket.getaddrinfo",
                        side_effect=AssertionError("unexpected DNS"),
                    ),
                ):
                    negotiate(stream, _proxy(scheme), _TARGET)
                self.assertEqual(stream.writes, request)

    def test_local_dns_uses_the_numeric_wire_address_for_each_version(self):
        for scheme, request in (
            ("socks4", b"\x04\x01\x01\xbb\xc0\x00\x02\x0a\x00"),
            (
                "socks5",
                b"\x05\x01\x00\x05\x01\x00\x04"
                + socket.inet_pton(socket.AF_INET6, "fe80::1")
                + b"\x01\xbb",
            ),
        ):
            with self.subTest(scheme=scheme):
                stream = _Stream(scheme)
                with (
                    patch(
                        "socket.gethostbyname",
                        side_effect=AssertionError("unexpected second DNS lookup"),
                    ),
                    patch(
                        "socket.getaddrinfo", return_value=[_V6_ADDRESS, _V4_ADDRESS]
                    ) as dns,
                ):
                    negotiate(stream, _proxy(scheme), _TARGET)
                lookup = (
                    {"family": socket.AF_INET}
                    if scheme == "socks4"
                    else {"proto": socket.IPPROTO_TCP, "flags": socket.AI_ADDRCONFIG}
                )
                dns.assert_called_once_with(
                    "origin.test", 443, type=socket.SOCK_STREAM, **lookup
                )
                self.assertEqual(stream.writes, request)

    def test_socks4_ipv6_only_answer_raises_address_error_before_negotiation(self):
        stream = _Stream("socks4")
        with (
            patch("socket.getaddrinfo", return_value=[_V6_ADDRESS]),
            patch("socket.gethostbyname", side_effect=socket.gaierror("no IPv4")),
        ):
            with self.assertRaisesRegex(socket.gaierror, "SOCKS4.*IPv4"):
                negotiate(stream, _proxy("socks4"), _TARGET)
        self.assertEqual(stream.writes, b"")

    def test_dns_oserror_and_proxy_protocol_failure_keep_their_types(self):
        stream = _Stream("socks5")
        failure = socket.gaierror(socket.EAI_NONAME, "no address")
        with patch("socket.getaddrinfo", side_effect=failure):
            with self.assertRaises(socket.gaierror) as caught:
                negotiate(stream, _proxy("socks5"), _TARGET)
        self.assertIs(caught.exception, failure)
        stream = _Stream("socks5h", response=b"\x05\xff")
        with self.assertRaises(ProxyError):
            negotiate(stream, _proxy("socks5h"), _TARGET)


if __name__ == "__main__":
    unittest.main()
