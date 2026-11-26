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
from ruyihttp import _connect, _transport


class _TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


@unittest.skipUnless(fixture._ENABLED, "set RUYIHTTP_TEST_NATIVE_H3=1 for native tests")
class NativeAltSvcTests(unittest.TestCase):
    setUp = fixture.NativeHTTP3Tests.setUp
    _write = fixture.NativeHTTP3Tests._write
    _origin = fixture.NativeHTTP3Tests._origin

    @contextlib.contextmanager
    def _tcp_origin(self, alpn, port, *, close_after=None):
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
                        close = path == close_after
                        connection_header = "Connection: close\r\n" if close else ""
                        sock.sendall(
                            f"HTTP/1.1 200 OK\r\nx-conn: {cid}\r\nAlt-Svc: {hint}\r\n"
                            f"{connection_header}Content-Length: 2\r\n\r\nok".encode()
                        )
                        if close:
                            return

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
            workers = []
            run_h3 = fixture.Connection._run

            def track_udp_owner(connection):
                if connection.endpoint == (fixture._IP, port):
                    workers.append(threading.current_thread())
                run_h3(connection)

            with self._session() as session:
                with self._tcp_origin("http/1.1", port, close_after=b"/cooling") as tcp:
                    url, connections, requests = tcp
                    with patch.object(fixture.Connection, "_run", track_udp_owner):
                        for path, budget in (("/bootstrap", 2), ("/blocked", 0.8)):
                            with session.get(url + path, timeout=(budget, 2)) as response:
                                self.assertEqual(
                                    (response.raw.version, response.content), (11, b"ok")
                                )
                    # The warm TCP winner returns before its cancelled H3 loser
                    # exits. Native QUIC close can still send an Initial packet;
                    # leave the blackhole bound until its UDP owner has exited.
                    self.assertEqual(len(workers), 1)
                    worker, = workers
                    worker.join(timeout=3)
                    self.assertFalse(worker.is_alive(), "blocked H3 UDP owner did not exit")
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
                        self.assertEqual(response.headers["Connection"], "close")
                # The same Session and cache remain active, but the last H1
                # response closed its warm connection and the TCP listener has
                # stopped. Recovery measures H3 eligibility, not race timing.
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
                self.assertEqual(origin.negotiated, [(0, "h3")])
                self.assertEqual(
                    [headers[b":path"] for _, _, headers, _ in origin.requests],
                    [b"/recovered"],
                )
                print(
                    "same UDP endpoint recovered: H1 during cooldown, verified H3 at cooldown expiry",
                    flush=True,
                )

    @contextlib.contextmanager
    def _order_healthy_race(self, alpn):
        # Both lanes run the real factories. Require TCP to borrow the warm
        # lease, but hold its result until the coordinator has selected H3.
        # The host scheduler need not let QUIC finish inside its 100 ms lead.
        borrowed = threading.Event()
        released = threading.Event()
        real_race = _connect.race

        def ordered_race(primary, backup, *args, **kwargs):
            def quic(attempt):
                candidate = primary(attempt)
                try:
                    self.assertTrue(
                        borrowed.wait(attempt.remaining()), "no warm TCP result"
                    )
                except Exception:
                    candidate.close()
                    raise
                return candidate

            def tcp(attempt):
                lease = backup(attempt)
                close = lease.close

                def return_lease():
                    close()
                    released.set()

                lease.close = return_lease
                try:
                    self.assertIsInstance(lease, _transport._BorrowedConnection)
                    self.assertEqual(lease.alpn, alpn)
                    remaining = attempt.remaining()
                    borrowed.set()
                    self.assertTrue(
                        attempt.cancelled.wait(remaining), "warm TCP was not cancelled"
                    )
                    # Let the real race close this late result and return its lease.
                    return lease
                except Exception:
                    lease.close()
                    raise

            candidate = real_race(quic, tcp, *args, **kwargs)
            if not released.wait(2):
                candidate.close()
                self.fail("losing warm TCP lease was not returned")
            return candidate

        with patch.object(_connect, "race", ordered_race):
            yield
        self.assertTrue(borrowed.is_set() and released.is_set())

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
                    order = (
                        self._order_healthy_race(alpn) if path == "/body"
                        else contextlib.nullcontext()
                    )
                    with order, session.get(url + path, timeout=2) as response:
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
