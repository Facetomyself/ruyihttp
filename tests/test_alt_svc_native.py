# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Opt-in Alt-Svc tests against real local TLS, H2 and QUIC endpoints."""

import contextlib
import socket
import socketserver
import ssl
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from requests.exceptions import RequestException

import ruyihttp
import test_http3_native as fixture
from ruyihttp import _transport


class _TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


@unittest.skipUnless(fixture._ENABLED, "set RUYIHTTP_TEST_NATIVE_H3=1 for native tests")
class NativeAltSvcTests(unittest.TestCase):
    setUp = fixture.NativeHTTP3Tests.setUp
    _write = fixture.NativeHTTP3Tests._write
    _origin = fixture.NativeHTTP3Tests._origin

    @contextlib.contextmanager
    def _tcp_origin(self, alpn, port):
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
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols([alpn])
        connections = []
        requests = []
        hint = f'h3=":{port}"; ma=60'

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    with context.wrap_socket(self.request, server_side=True) as sock:
                        connections.append(sock.getpeername())
                        cid = len(connections)
                        sock.settimeout(2)
                        if alpn == "h2":
                            self.h2(sock, cid)
                        else:
                            self.h1(sock, cid)
                except (ConnectionError, TimeoutError):
                    pass

            def h1(self, sock, cid):
                with sock.makefile("rb") as source:
                    while line := source.readline():
                        method, path, _ = line.split()
                        length = 0
                        while (header := source.readline()) not in (b"\r\n", b""):
                            if header.lower().startswith(b"content-length:"):
                                length = int(header.split(b":", 1)[1])
                        requests.append((cid, method, path, source.read(length)))
                        sock.sendall(
                            f"HTTP/1.1 200 OK\r\nx-conn: {cid}\r\nAlt-Svc: {hint}\r\n"
                            "Content-Length: 2\r\n\r\nok".encode()
                        )

            def h2(self, sock, cid):
                from h2.config import H2Configuration
                from h2.connection import H2Connection
                from h2.events import DataReceived, RequestReceived, StreamEnded

                conn = H2Connection(config=H2Configuration(client_side=False))
                conn.initiate_connection()
                sock.sendall(conn.data_to_send())
                streams = {}
                while data := sock.recv(65536):
                    for event in conn.receive_data(data):
                        if isinstance(event, RequestReceived):
                            streams[event.stream_id] = (
                                dict(event.headers),
                                bytearray(),
                            )
                        elif isinstance(event, DataReceived):
                            streams[event.stream_id][1].extend(event.data)
                            conn.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id
                            )
                        elif isinstance(event, StreamEnded):
                            headers, body = streams.pop(event.stream_id)
                            requests.append(
                                (
                                    cid,
                                    headers[b":method"],
                                    headers[b":path"],
                                    bytes(body),
                                )
                            )
                            conn.send_headers(
                                event.stream_id,
                                [
                                    (":status", "200"),
                                    ("content-length", "2"),
                                    ("alt-svc", hint),
                                    ("x-conn", str(cid)),
                                ],
                            )
                            conn.send_data(event.stream_id, b"ok", end_stream=True)
                    out = conn.data_to_send()
                    if out:
                        sock.sendall(out)

        with _TCPServer((fixture._IP, 0), Handler) as server:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}
            )
            thread.start()
            try:
                yield (
                    f"https://{fixture._IP}:{server.server_address[1]}",
                    connections,
                    requests,
                )
            finally:
                server.shutdown()
                thread.join(3)

    @contextlib.contextmanager
    def _session(self):
        with ruyihttp.Session(
            library_path=self.core, verify=str(self.good_ca)
        ) as session:
            session.trust_env = False
            yield session

    @staticmethod
    def _udp_count(sock):
        count = 0
        while True:
            try:
                sock.recvfrom(65535)
                count += 1
            except BlockingIOError:
                return count

    def test_blocked_udp_reuses_same_warm_tcp_and_cools_identical_hints(self):
        for alpn, version in (("http/1.1", 11), ("h2", 20)):
            with self.subTest(alpn=alpn), socket.socket(type=socket.SOCK_DGRAM) as sink:
                sink.bind((fixture._IP, 0))
                sink.setblocking(False)  # Silent blackhole, not an ICMP port rejection.
                port = sink.getsockname()[1]
                with (
                    self._tcp_origin(alpn, port) as (url, connections, requests),
                    self._session() as session,
                ):
                    timings, udp = [], []
                    try:
                        for index, budget in enumerate((2, 0.05, 0.8, 0.05, 0.8)):
                            started = time.perf_counter()
                            try:
                                with session.post(
                                    f"{url}/{index}", data=b"once", timeout=(budget, 2)
                                ) as response:
                                    outcome = response.headers["x-conn"]
                                    self.assertEqual(
                                        (
                                            response.status_code,
                                            response.raw.version,
                                            response.content,
                                        ),
                                        (200, version, b"ok"),
                                    )
                            except RequestException as exc:
                                outcome = type(exc).__name__
                            timings.append(
                                (
                                    budget,
                                    outcome,
                                    round((time.perf_counter() - started) * 1000, 3),
                                )
                            )
                            udp.append(self._udp_count(sink))
                    finally:
                        print(
                            f"{alpn} blocked UDP: (budget_s, conn/error, elapsed_ms)={timings}; datagrams={udp}; TCP connections={len(connections)}",
                            flush=True,
                        )
                    self.assertEqual([row[1] for row in timings], ["1"] * 5)
                    # A short budget uses the warm lease without probing. The
                    # next adequately budgeted request must actually probe, then
                    # the last two requests exercise the real failure cooldown.
                    self.assertEqual(udp[:2], [0, 0])
                    self.assertGreater(udp[2], 0)
                    self.assertEqual(udp[3:], [0, 0])
                    self.assertEqual(len(connections), 1)
                    self.assertEqual(
                        requests,
                        [(1, b"POST", f"/{i}".encode(), b"once") for i in range(5)],
                    )

    def test_same_endpoint_can_upgrade_after_its_cooldown(self):
        # Advance only the cache clock; the real network deadlines still tick.
        clock = SimpleNamespace(now=1.0)
        clock.monotonic = lambda: clock.now
        with (
            socket.socket(type=socket.SOCK_DGRAM) as sink,
            patch.object(_transport, "time", clock),
        ):
            sink.bind((fixture._IP, 0))
            port = sink.getsockname()[1]
            with (
                self._tcp_origin("http/1.1", port) as (url, connections, requests),
                self._session() as session,
            ):
                for path, budget in (("/bootstrap", 2), ("/blocked", 0.8)):
                    with session.get(url + path, timeout=(budget, 2)) as response:
                        self.assertEqual(
                            (response.raw.version, response.content), (11, b"ok")
                        )
                sink.setblocking(False)
                self.assertGreater(self._udp_count(sink), 0)
                sink.close()
                serve = fixture.serve

                async def listen(host, _port, **kwargs):
                    return await serve(host, port, **kwargs)

                with patch.object(fixture, "serve", listen):
                    origin = self._origin()
                self.assertEqual(origin.address[1], port)
                with session.get(url + "/cooling", timeout=2) as response:
                    self.assertEqual(
                        (response.raw.version, response.content), (11, b"ok")
                    )
                self.assertEqual(origin.connections, 0)
                clock.now += _transport._ALT_SVC_COOLDOWN
                with session.get(url + "/recovered", timeout=2) as response:
                    self.assertEqual(
                        (response.raw.version, response.tls["alpn"]), (30, "h3")
                    )
                self.assertEqual(len(connections), 1)
                self.assertEqual(
                    [path for _, _, path, _ in requests],
                    [b"/bootstrap", b"/blocked", b"/cooling"],
                )
                self.assertEqual(
                    [headers[b":path"] for _, _, headers, _ in origin.requests],
                    [b"/recovered"],
                )
                print(
                    "same UDP endpoint recovered: H1 during cooldown, verified H3 at cooldown expiry",
                    flush=True,
                )

    def test_verified_h3_wins_and_reuses_while_bootstrap_tcp_remains_live(self):
        origin = self._origin()
        for alpn, version in (("http/1.1", 11), ("h2", 20)):
            with (
                self.subTest(alpn=alpn),
                self._tcp_origin(alpn, origin.address[1]) as (
                    url,
                    connections,
                    requests,
                ),
                self._session() as session,
            ):
                started = time.perf_counter()
                with session.get(url + "/bootstrap", timeout=2) as bootstrap:
                    self.assertEqual(
                        (bootstrap.raw.version, bootstrap.content), (version, b"ok")
                    )
                times = []
                for path in ("/body", "/empty"):
                    request_started = time.perf_counter()
                    with session.get(url + path, timeout=2) as response:
                        self.assertEqual(
                            (response.raw.version, response.tls["alpn"]), (30, "h3")
                        )
                        self.assertEqual(
                            response.content, fixture._DATA if path == "/body" else b""
                        )
                    times.append(
                        round((time.perf_counter() - request_started) * 1000, 3)
                    )
                pool = next(iter(session.get_adapter(url)._pools.values()))
                self.assertEqual(pool.leased, 0)
                self.assertFalse(pool.connecting)
                warm = pool.shared if alpn == "h2" else pool.idle
                self.assertTrue(any(c.alpn == alpn and c.idle() for c in warm))
                self.assertEqual(len(connections), 1)
                self.assertEqual(requests, [(1, b"GET", b"/bootstrap", b"")])
                print(
                    f"{alpn} remains warm; verified h3 upgrade and reuse elapsed_ms={times}, total_ms={(time.perf_counter() - started) * 1000:.3f}",
                    flush=True,
                )
        self.assertEqual(origin.negotiated, [(0, "h3"), (1, "h3")])
        self.assertEqual(
            [(cid, stream) for cid, stream, _, _ in origin.requests],
            [(0, 0), (0, 4), (1, 0), (1, 4)],
        )
