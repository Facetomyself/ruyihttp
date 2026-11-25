# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""H3 body ABI contracts and native loopback checks (including legacy fallback)."""

import ctypes as ct
import hashlib
import io
import json
import os
import queue
import ssl
import threading
import time
import unittest
from collections import Counter
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from urllib3.exceptions import ProtocolError

import ruyihttp
from ruyihttp import _http3

import test_http3_native as fixture


class BodyABIContracts(unittest.TestCase):
    def test_negotiation_requires_exact_version_and_both_functions(self):
        library = SimpleNamespace(necko_quic_body_abi_version=lambda: 1)
        self.assertIsNone(_http3._BodyABI.negotiate(library))
        library.necko_quic_body_read_v1 = lambda *args: None
        library.necko_quic_body_write_v1 = lambda *args: None
        self.assertIsInstance(_http3._BodyABI.negotiate(library), _http3._BodyABI)
        library.necko_quic_body_abi_version = lambda: 2
        self.assertIsNone(_http3._BodyABI.negotiate(library))

    def test_binary_pointer_offset_nuls_partial_and_invalid_outputs(self):
        def read(handle, stream, output, limit, count, fin):
            self.assertEqual((handle, stream, limit), (7, 4, 8))
            ct.memmove(output, b"\x00abc\x00", 5)
            ct.cast(count, ct.POINTER(ct.c_size_t))[0] = 5
            ct.cast(fin, ct.POINTER(ct.c_uint8))[0] = 1

        def write(handle, stream, data, size, count):
            self.assertEqual((handle, stream, size), (7, 4, 5))
            self.assertEqual(ct.string_at(data, size), b"\x00abc\x00")
            ct.cast(count, ct.POINTER(ct.c_size_t))[0] = 2

        abi = _http3._BodyABI(read, write)
        self.assertEqual(abi.write(7, 4, b"first\x00abc\x00", 5), 2)
        self.assertEqual(abi.read(7, 4, 8), (b"\x00abc\x00", True))
        abi._read = lambda *args: None
        abi._write = lambda *args: None
        with self.assertRaisesRegex(ProtocolError, "read result"):
            abi.read(7, 4, 8)
        with self.assertRaisesRegex(ProtocolError, "write count"):
            abi.write(7, 4, b"1234", 2)
        abi._read = lambda *args: b"native stream error"
        with self.assertRaisesRegex(ProtocolError, "native stream error"):
            abi.read(7, 4, 8)

    def test_pump_wakes_blocked_read_and_write_before_next_select(self):
        connection = object.__new__(_http3.Connection)
        connection._input_epoch = 0
        connection._stopping = threading.Event()
        connection._wake_read = object()
        connection.commands = queue.Queue()
        connection.handle = 1
        udp = object()
        exchange = object.__new__(_http3.Exchange)
        exchange.stream_id, exchange.error, exchange.closed = 4, None, False
        exchange.ended = exchange.send_stopped = exchange.readable = False
        exchange.write_epoch, exchange.write_blocked_at = 0, (0, 0)
        exchange.write_probe_at = time.monotonic() + 10
        connection.streams = {4: exchange}
        read = _http3._Call("read", exchange, 1, size=8)
        write = _http3._Call("write", exchange, 1, data=b"b", offset=0)
        connection.pending = [read, write]
        connection._body_abi = SimpleNamespace(
            read=lambda *args: (b"a", False),
            write=lambda *args: 1,
        )
        delivered = False
        selects = 0

        def native(op):
            nonlocal delivered
            if op == "pump":
                return {"delay": 0.1}
            self.assertEqual(op, "events")
            if selects and not delivered:
                delivered = True
                return {
                    "events": [
                        {"stream": 4, "type": "readable"},
                        {"stream": 4, "type": "writable"},
                    ]
                }
            return {"events": []}

        def select(timeout):
            nonlocal selects
            selects += 1
            if selects == 1:
                self.assertFalse(read.done.is_set())
                self.assertFalse(write.done.is_set())
                return [(SimpleNamespace(fileobj=udp), 1)]
            self.assertTrue(read.done.is_set() and write.done.is_set())
            self.assertEqual((read.result, write.result), (b"a", 1))
            connection._stopping.set()
            return []

        connection._call = native
        connection._run_loop(udp, SimpleNamespace(select=select))
        self.assertEqual(selects, 2)

    def test_zero_retry_reuses_exact_json_frame_and_stop_wins(self):
        connection = object.__new__(_http3.Connection)
        connection._body_abi = None
        connection._input_epoch = 0
        frames = []
        count = 0

        def json_frame(frame):
            frames.append(frame)
            return {"count": count}

        connection._json_frame = json_frame
        exchange = object.__new__(_http3.Exchange)
        exchange.stream_id, exchange.error, exchange.closed = 0, None, False
        exchange.send_stopped, exchange.write_epoch = False, 0
        exchange.write_probe_at, exchange.write_blocked_at = 0, None
        call = _http3._Call("write", exchange, 1, data=b"\x00\xffABC", offset=1)
        with patch.object(_http3, "_WRITE_PROBE_DELAY", 60):
            self.assertFalse(connection._execute(call))
            self.assertFalse(connection._execute(call))
            self.assertEqual(len(frames), 1)  # No retry on an unrelated wake.
            exchange.write_epoch += 1
            count = 3
            self.assertTrue(connection._execute(call))
            self.assertEqual(call.result, 3)
            self.assertIs(frames[0], frames[1])
            self.assertEqual(json.loads(frames[0])["data"], "/0FCQw==")
            remaining = _http3._Call(
                "write", exchange, 1, data=b"\x00\xffABC", offset=4
            )
            self.assertFalse(connection._execute(remaining))
            self.assertIsNone(remaining.frame)
            exchange.send_stopped = True
            self.assertTrue(connection._execute(remaining))
            self.assertIsNone(remaining.result)
            self.assertEqual(len(frames), 2)
            exchange.error = ProtocolError("peer reset")
            with self.assertRaisesRegex(ProtocolError, "peer reset"):
                connection._execute(remaining)
            expired = _http3._Call("write", exchange, 0, data=b"x", offset=0)
            with self.assertRaises(TimeoutError):
                connection._execute(expired)
            self.assertIsNone(expired.frame)


@unittest.skipUnless(fixture._ENABLED, "set RUYIHTTP_TEST_NATIVE_H3=1")
class NativeBodyABI(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.NativeHTTP3Tests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def test_native_byte_echo_and_json_control(self):
        origin = self.fixture._origin()
        con = self.fixture._connect(origin)
        abi = con._body_abi
        if os.environ.get("RUYIHTTP_REQUIRE_H3_BODY_ABI") == "1":
            self.assertIsNotNone(abi, "rebuilt QUIC bridge must negotiate body ABI v1")
        modes = (abi, None) if abi is not None else (None,)
        payload = bytes(range(256)) * 4096 + b"\xf0\x00\xff"
        for selected in modes:
            with self.subTest(binary=selected is not None), ExitStack() as stack:
                json_ops = Counter()
                writes, reads = [], []
                native_json = con.library.necko_quic_call

                def count_json(handle, data, size):
                    json_ops[json.loads(data)["op"]] += 1
                    return native_json(handle, data, size)

                stack.enter_context(
                    patch.object(con.library, "necko_quic_call", count_json)
                )
                stack.enter_context(patch.object(con, "_body_abi", selected))
                if selected is not None:
                    native_write, native_read = abi._write, abi._read

                    def count_write(handle, stream, data, size, count):
                        err = native_write(handle, stream, data, size, count)
                        if err is None:
                            writes.append(ct.cast(count, ct.POINTER(ct.c_size_t))[0])
                        return err

                    def count_read(handle, stream, data, size, count, fin):
                        err = native_read(handle, stream, data, size, count, fin)
                        if err is None:
                            reads.append(ct.cast(count, ct.POINTER(ct.c_size_t))[0])
                        return err

                    stack.enter_context(patch.object(abi, "_write", count_write))
                    stack.enter_context(patch.object(abi, "_read", count_read))
                response = self.fixture._exchange(
                    con, "/echo?native=1", "POST", payload, timeout=8
                )
                self.assertEqual((response.status, response.version), (200, 30))
                self.assertEqual(self.fixture._read(response), payload)
                self.assertEqual(origin.requests[-1][3], payload)
                for op in ("fetch", "pump", "events", "finish"):
                    self.assertGreater(json_ops[op], 0)
                if selected is not None:
                    self.assertEqual(json_ops["read"] + json_ops["write"], 0)
                    self.assertEqual(sum(writes), len(payload))
                    self.assertEqual(sum(reads), len(payload))
                else:
                    self.assertGreater(json_ops["read"], 0)
                    self.assertGreater(json_ops["write"], 0)
                print(
                    f"h3 body {'binary-v1' if selected else 'JSON'}: "
                    f"bytes={len(payload)} sha256={hashlib.sha256(payload).hexdigest()} "
                    f"binary_reads={len(reads)} binary_writes={len(writes)} "
                    f"json_ops={dict(json_ops)}",
                    flush=True,
                )

    def test_native_body_argument_bounds_and_thread_owner(self):
        origin = self.fixture._origin()
        connection = self.fixture._connect(origin)
        abi = connection._body_abi
        if abi is None:
            self.skipTest("legacy bridge has no binary body ABI")
        exchange = self.fixture._exchange(connection, "/body")
        handle, stream = connection.handle, exchange.stream_id
        one = ct.create_string_buffer(b"a", 1)
        count, fin = ct.c_size_t(99), ct.c_uint8(99)
        for wrong in (None, one):
            with self.subTest(null=wrong is None):
                self.assertIn(
                    b"Invalid HTTP/3 body write arguments",
                    abi._write(handle, stream, wrong, 65537, ct.byref(count)),
                )
                self.assertIn(
                    b"Invalid HTTP/3 body read arguments",
                    abi._read(handle, stream, wrong, 0, ct.byref(count), ct.byref(fin)),
                )
        self.assertIn(
            b"Invalid HTTP/3 body read arguments",
            abi._read(handle, 1 << 62, one, 1, ct.byref(count), ct.byref(fin)),
        )
        self.assertIn(
            b"Invalid HTTP/3 body write arguments",
            abi._write(handle, stream, one, 1, None),
        )
        # The handle works on the connection pump thread, not this test thread.
        error = abi._read(handle, stream, one, 1, ct.byref(count), ct.byref(fin))
        self.assertIn(b"handle", error.lower())
        self.assertEqual((one.raw, count.value, fin.value), (b"a", 99, 99))
        self.assertEqual(self.fixture._read(exchange), fixture._DATA)

    def _early_origin(self, control):
        class EarlyProtocol(fixture.QuicConnectionProtocol):
            def __init__(self, *args, origin, **kwargs):
                super().__init__(*args, **kwargs)
                self.http = None
                self.paths = {}

            def quic_event_received(self, event):
                if isinstance(event, fixture.ProtocolNegotiated):
                    self.http = fixture.H3Connection(self._quic)
                if self.http is None:
                    return
                for part in self.http.handle_event(event):
                    stream = part.stream_id
                    if isinstance(part, fixture.HeadersReceived):
                        self.paths[stream] = dict(part.headers)[b":path"]
                        if self.paths[stream] == b"/warm":
                            self.http.send_headers(
                                stream,
                                [(b":status", b"200"), (b"content-length", b"0")],
                                end_stream=True,
                            )
                            self.transmit()
                    elif (
                        isinstance(part, fixture.DataReceived)
                        and self.paths.get(stream) == b"/early"
                    ):
                        self.paths.pop(stream)
                        if control in ("complete", "truncated"):
                            self.http.send_headers(
                                stream,
                                [
                                    (b":status", b"413"),
                                    (
                                        b"content-length",
                                        b"7" if control == "complete" else b"700",
                                    ),
                                ],
                            )
                            self.http.send_data(stream, b"too big", end_stream=True)
                        self._quic.stop_stream(
                            stream, 0x10C if control == "cancel" else 0x100
                        )
                        self.transmit()

        class Origin(fixture._Origin):
            def _protocol(self, *args, **kwargs):
                return EarlyProtocol(*args, origin=self, **kwargs)

        origin = Origin(self.fixture.leaf, self.fixture.key, fixture._IP)
        self.addCleanup(origin.close)
        return origin

    def _bootstrap(self, udp_port):
        cert = self.fixture._write(
            "leaf.pem", self.fixture.leaf.public_bytes(serialization.Encoding.PEM)
        )
        key = self.fixture._write(
            "leaf.key",
            self.fixture.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

        class Bootstrap(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.send_response(200)
                self.send_header("Alt-Svc", f'h3=":{udp_port}"; ma=60')
                self.send_header("Connection", "close")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer((fixture._IP, 0), Bootstrap)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["http/1.1"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.02}
        )
        thread.start()

        def close():
            server.shutdown()
            thread.join(5)
            server.server_close()

        self.addCleanup(close)
        return f"https://{fixture._IP}:{server.server_port}"

    def test_real_stop_upload_preserves_final_response_and_stream_errors(self):
        for control, file_body in (
            ("complete", False),
            ("complete", True),
            ("no-final", False),
            ("cancel", False),
            ("truncated", False),
        ):
            with self.subTest(control=control, file=file_body):
                origin = self._early_origin(control)
                url = self._bootstrap(origin.address[1])
                observed = threading.Event()
                original_events = _http3.Connection._events
                pulls, after = [], []

                def events(connection):
                    result = original_events(connection)
                    if any(
                        x.upload_stopped and not x.closed
                        for x in connection.streams.values()
                    ):
                        observed.set()
                    return result

                def note_pull():
                    if observed.is_set():
                        after.append(len(pulls))
                        raise AssertionError(
                            "upload source entered after STOP/cancel was processed"
                        )
                    pulls.append(1)
                    # Accept that one pull may already be running when STOP arrives.
                    if len(pulls) == 2:
                        self.assertTrue(
                            observed.wait(3), "peer STOP/cancel was never processed"
                        )

                def sections():
                    for _ in range(5):
                        note_pull()
                        yield b"x" * 4096

                class File(io.BytesIO):
                    def read(self, size=-1):
                        note_pull()
                        return super().read(size)

                body = File(b"x" * 250_000) if file_body else sections()
                with ruyihttp.Session(
                    verify=str(self.fixture.good_ca), timeout=4
                ) as session:
                    session.trust_env = False
                    self.assertEqual(session.get(url + "/warm").raw.version, 11)
                    self.assertEqual(session.get(url + "/warm").raw.version, 30)
                    with patch.object(_http3.Connection, "_events", events):
                        if control == "no-final":
                            with self.assertRaisesRegex(
                                ruyihttp.exceptions.ReadTimeout, "headers timed out"
                            ):
                                session.post(
                                    url + "/early",
                                    data=body,
                                    timeout=3.5,
                                    allow_redirects=False,
                                )
                        elif control == "cancel":
                            with self.assertRaisesRegex(
                                ruyihttp.exceptions.ConnectionError, "stop_sending: 268"
                            ):
                                session.post(
                                    url + "/early", data=body, allow_redirects=False
                                )
                        elif control == "truncated":
                            with self.assertRaisesRegex(
                                ruyihttp.exceptions.ChunkedEncodingError,
                                r"IncompleteRead\(7 bytes read, 693 more expected\)",
                            ):
                                session.post(
                                    url + "/early", data=body, allow_redirects=False
                                )
                        else:
                            response = session.post(
                                url + "/early", data=body, allow_redirects=False
                            )
                            self.assertEqual(
                                (
                                    response.status_code,
                                    response.raw.version,
                                    response.content,
                                ),
                                (413, 30, b"too big"),
                            )
                    self.assertTrue(observed.is_set())
                    self.assertGreaterEqual(len(pulls), 1)
                    self.assertLessEqual(len(pulls), 2)
                    self.assertEqual(after, [])
