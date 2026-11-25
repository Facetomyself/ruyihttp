# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Opt-in loopback test: RUYIHTTP_TEST_NATIVE_H3=1 python -m unittest discover
-s tests -p test_http3_native.py -v. Requires aioquic and the native runtime.
Set NECKO_CORE_LIBRARY if running from source rather than an installed wheel.
"""

import asyncio
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import unittest
from concurrent.futures import Future
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from urllib3.exceptions import ProtocolError

import ruyihttp
from ruyihttp._firefox import runtime_platform
from ruyihttp._http3 import Connection, Exchange
from ruyihttp._nss import Context
from ruyihttp._transport import _load_library

_ENABLED = os.environ.get("RUYIHTTP_TEST_NATIVE_H3") == "1"
if _ENABLED:
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import HandshakeCompleted, ProtocolNegotiated
else:
    QuicConnectionProtocol = object

_HOST = "h3.test"
_IP = "127.0.0.1"
_IPV6 = "::1"
_DATA = bytes(range(256)) * 1024


def _ca(label, now):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def _leaf(ca, ca_key, now, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _HOST)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=-1 if expired else 10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(_HOST),
                    x509.IPAddress(ipaddress.ip_address(_IP)),
                    x509.IPAddress(ipaddress.ip_address(_IPV6)),
                ]
            ),
            False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return certificate, key


class _Protocol(QuicConnectionProtocol):
    def __init__(self, *args, origin, **kwargs):
        super().__init__(*args, **kwargs)
        self.origin = origin
        self.number = origin.connections
        origin.connections += 1
        self.http = None
        self.requests = {}
        self.finished = set()

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if isinstance(event, HandshakeCompleted):
            self.origin.negotiated.append((self.number, event.alpn_protocol))
        if self.http is None:
            return
        for part in self.http.handle_event(event):
            stream = part.stream_id
            if isinstance(part, HeadersReceived):
                self.requests[stream] = (dict(part.headers), bytearray())
            elif isinstance(part, DataReceived):
                # aioquic can deliver an empty data event again on stream teardown.
                if stream in self.finished and not part.data:
                    continue
                self.requests[stream][1].extend(part.data)
            else:
                continue
            if not part.stream_ended:
                continue
            headers, body = self.requests.pop(stream)
            self.finished.add(stream)
            path = headers[b":path"]
            payload = bytes(body)
            self.origin.requests.append((self.number, stream, headers, payload))
            if path == b"/reset":
                self._quic.reset_stream(stream, 0x10C)
            elif path != b"/stall":
                if path == b"/body":
                    payload = _DATA
                elif path != b"/echo?native=1":
                    payload = b""
                self.http.send_headers(
                    stream,
                    [
                        (b":status", b"200"),
                        (b"content-length", str(len(payload)).encode()),
                        (b"x-origin", b"udp-only-h3"),
                        (b"x-repeat", b"one"),
                        (b"x-repeat", b"two"),
                    ],
                    end_stream=not payload,
                )
                if payload:
                    self.http.send_data(stream, payload, end_stream=True)
            self.transmit()


class _Origin:
    def __init__(self, cert, key, ip):
        self.ip = ip
        self.negotiated = []
        self.requests = []
        self.connections = 0
        self.errors = []
        self.ready = Future()
        self.cert = cert
        self.key = key
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.address = (self.ip, self.ready.result(timeout=5))

    def _run(self):
        try:
            asyncio.run(self._serve())
        except Exception as error:
            if not self.ready.done():
                self.ready.set_exception(error)
            else:
                self.errors.append(error)

    async def _serve(self):
        self.loop = asyncio.get_running_loop()
        self.loop.set_exception_handler(
            lambda _loop, event: self.errors.append(
                event.get("exception", event["message"])
            )
        )
        self.stop = asyncio.Event()
        config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        config.certificate, config.private_key = self.cert, self.key
        server = await serve(
            self.ip, 0, configuration=config, create_protocol=self._protocol
        )
        try:
            self.ready.set_result(server._transport.get_extra_info("sockname")[1])
            await self.stop.wait()
        finally:
            server.close()

    def _protocol(self, *args, **kwargs):
        return _Protocol(*args, origin=self, **kwargs)

    def close(self):
        if not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError("H3 origin did not stop")
        if self.errors:
            raise AssertionError(f"H3 origin errors: {self.errors!r}")


@unittest.skipUnless(
    _ENABLED, "set RUYIHTTP_TEST_NATIVE_H3=1 for loopback native integration"
)
class NativeHTTP3Tests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.core = _load_library()._name
        self.runtime = json.loads(
            Path(ruyihttp.__file__).with_name("runtime-manifest.json").read_text(encoding="utf-8")
        )["platforms"][runtime_platform()]
        now = datetime.now(timezone.utc)
        ca, ca_key = _ca("RuyiHttp H3 test CA", now)
        other_ca, _ = _ca("RuyiHttp unrelated test CA", now)
        self.good_ca = self._write(
            "ca.pem", ca.public_bytes(serialization.Encoding.PEM)
        )
        self.bad_ca = self._write(
            "other.pem", other_ca.public_bytes(serialization.Encoding.PEM)
        )
        self.leaf, self.key = _leaf(ca, ca_key, now)
        self.expired_leaf, self.expired_key = _leaf(ca, ca_key, now, expired=True)

    def _write(self, name, data):
        path = self.directory / name
        path.write_bytes(data)
        return path

    def _origin(self, expired=False, ip=_IP):
        origin = _Origin(
            self.expired_leaf if expired else self.leaf,
            self.expired_key if expired else self.key,
            ip,
        )
        self.addCleanup(origin.close)
        return origin

    def _assert_no_tcp(self, *addresses):
        for address in addresses:
            with self.subTest(tcp_negative=address[:2]):
                # The Windows loopback refusal arrives after its initial TCP
                # retransmit interval. A timeout is not proof of refusal.
                with self.assertRaises(ConnectionRefusedError):
                    socket.create_connection(address[:2], timeout=5).close()

    def _connect(self, origin, host=_HOST, cafile=None, firefox=None):
        connection = Connection(
            host,
            origin.address[1],
            Context(cafile or self.good_ca, None),
            self.core,
            3,
            endpoint=origin.address,
            firefox=firefox,
        )
        self.addCleanup(connection.close)
        return connection

    def _exchange(self, connection, path, method="GET", body=None, timeout=3):
        exchange = Exchange(
            connection,
            method,
            f"https://{_HOST}{path}",
            {"Host": _HOST},
            body is not None,
            timeout,
        )
        self.addCleanup(exchange.close)
        if body is not None:
            exchange.write(body)
        exchange.receive()
        return exchange

    def _read(self, exchange):
        result = b"".join(iter(lambda: exchange.read(32768), b""))
        exchange.close()
        return result

    def _assert_tls(self, info, firefox=None):
        shape = self.runtime["h3_tls"]
        if shape == "null":
            # Historical Apple Silicon bridge reports certificates, but no TLS
            # metadata. The UDP origin must independently observe negotiated h3.
            self.assertIsNone(info)
        elif shape == "windows-legacy":
            self.assertEqual(info, {"backend": "NSS/Neqo", "alpn": "h3", "version": 0x0304,
                                    "cipher_suite": 0x1302, "resumed": False})
        else:
            self.assertEqual(shape, "nss")
            self.assertEqual(info["alpn"], "h3", info)
            self.assertEqual(info["backend"], "NSS", info)
            self.assertEqual(info["version"], 0x0304, info)
            self.assertEqual(info["nss"], self.runtime["nss"], info)
            if firefox is not None:
                self.assertEqual(info["profile"], f"firefox-{firefox}", info)

    def test_udp_only_handshake_get_and_post(self):
        origin = self._origin()
        self._assert_no_tcp(origin.address)
        connection = self._connect(origin)
        response = self._exchange(connection, "/body")
        self.assertEqual((response.status, response.version), (200, 30))
        self.assertEqual(response.headers.getlist("x-repeat"), ["one", "two"])
        self.assertEqual(self._read(response), _DATA)
        response = self._exchange(connection, "/echo?native=1", "POST", _DATA)
        self.assertEqual(self._read(response), _DATA)
        self.assertEqual(origin.negotiated, [(0, "h3")])
        self.assertEqual([item[1] for item in origin.requests], [0, 4])
        self.assertEqual(origin.requests[1][2][b":method"], b"POST")
        self.assertEqual(origin.requests[1][3], _DATA)
        print(
            f"native={connection.library._name} TLS={connection.info} streams=0,4 "
            f"GET/POST={len(_DATA)} bytes sha256={hashlib.sha256(_DATA).hexdigest()}",
            flush=True,
        )

        self._assert_tls(connection.info, firefox="159")

    def test_nondefault_profile_connects_and_reports_native_telemetry(self):
        origin = self._origin()
        connection = self._connect(origin, firefox="158")
        self.assertEqual(self._read(self._exchange(connection, "/body")), _DATA)
        self.assertEqual(origin.negotiated, [(0, "h3")])
        print(f"native nondefault profile: {connection.info}", flush=True)
        self._assert_tls(connection.info, firefox="158")

    def test_public_session_alt_svc_ipv4_upgrade_and_reuse(self):
        self._exercise_alt_svc(_IP, socket.AF_INET)

    def test_public_session_alt_svc_ipv6_upgrade_and_reuse(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 loopback unavailable")
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((_IPV6, 0))
            except OSError as error:
                self.skipTest(f"IPv6 loopback unavailable: {error}")
        self._exercise_alt_svc(_IPV6, socket.AF_INET6)

    def _exercise_alt_svc(self, ip, family):
        origin = self._origin(ip=ip)
        host = f"[{ip}]" if family == socket.AF_INET6 else ip
        cert = self._write(
            "leaf.pem", self.leaf.public_bytes(serialization.Encoding.PEM)
        )
        key = self._write(
            "leaf.key",
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        port = origin.address[1]
        tcp_requests = []

        class Bootstrap(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                tcp_requests.append(self.path)
                self.send_response(200)
                self.send_header("Alt-Svc", f'h3=":{port}"; ma=60')
                self.send_header("Connection", "close")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        class TCPOrigin(ThreadingHTTPServer):
            address_family = family

        with TCPOrigin((ip, 0), Bootstrap) as server:
            address = server.server_address
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            context.set_alpn_protocols(["http/1.1"])
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.02}
            )
            thread.start()
            session = ruyihttp.Session(library_path=self.core, verify=str(self.good_ca))
            self.addCleanup(session.close)
            session.trust_env = False
            url = f"https://{host}:{address[1]}"
            try:
                with session.get(
                    url + "/advertise", timeout=3, allow_redirects=False
                ) as first:
                    self.assertEqual((first.status_code, first.raw.version), (200, 11))
                    self.assertIn('h3=":', first.headers["Alt-Svc"])
            finally:
                server.shutdown()
                thread.join(5)
        self._assert_no_tcp(address, origin.address)
        tls_reports = []
        for path, payload in [("/body", _DATA), ("/empty", b"")]:
            with session.get(
                url + path, timeout=3, allow_redirects=False, stream=True
            ) as response:
                self.assertEqual(
                    (response.status_code, response.raw.version), (200, 30)
                )
                tls_reports.append(response.tls)
                self.assertEqual(response.headers["X-Origin"], "udp-only-h3")
                self.assertEqual(b"".join(response.iter_content(16384)), payload)
        self.assertEqual(tcp_requests, ["/advertise"])
        self.assertEqual(origin.negotiated, [(0, "h3")])
        self.assertEqual([item[1] for item in origin.requests], [0, 4])
        for _, _, headers, _ in origin.requests:
            self.assertEqual(headers[b":authority"], f"{host}:{address[1]}".encode())
            self.assertEqual(headers[b"alt-used"], f"{host}:{port}".encode())
        print(
            f"public Session {host}: HTTP/1.1 Alt-Svc → TCP listeners closed → HTTP/3 "
            f"versions=30,30; origin observed one h3 connection with streams 0,4; TLS={tls_reports!r}",
            flush=True,
        )
        for info in tls_reports:
            self._assert_tls(info)

    def test_strict_certificate_rejections(self):
        for case, host, ca, expired, reason in [
            ("hostname", "different.test", self.good_ca, False, "subjectAltName"),
            ("untrusted", _HOST, self.bad_ca, False, "candidates exhausted|chain"),
            (
                "expired",
                _HOST,
                self.good_ca,
                True,
                "not valid at validation time|expired|validity",
            ),
        ]:
            with self.subTest(case=case):
                origin = self._origin(expired)
                with self.assertRaisesRegex(
                    ssl.SSLCertVerificationError, reason
                ) as raised:
                    self._connect(origin, host, ca)
                self.assertEqual(origin.requests, [])
                print(
                    f"strict h3 {case}: {raised.exception}; origin HTTP requests=0",
                    flush=True,
                )

    def test_stream_reset_and_timeout_leave_connection_usable(self):
        origin = self._origin()
        connection = self._connect(origin)
        with self.assertRaisesRegex(ProtocolError, "HTTP/3 reset: 268"):
            self._exchange(connection, "/reset")
        with self.assertRaisesRegex(TimeoutError, "HTTP/3 response headers timed out"):
            self._exchange(connection, "/stall", timeout=0.3)
        response = self._exchange(connection, "/empty")
        self.assertEqual((response.status, self._read(response)), (200, b""))
        self.assertEqual(origin.negotiated, [(0, "h3")])
        self.assertEqual([item[1] for item in origin.requests], [0, 4, 8])
        print(
            "h3 stream reset=0x10c, header timeout=0.3s, then empty 200 on stream 8",
            flush=True,
        )
