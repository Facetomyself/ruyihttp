# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
from types import SimpleNamespace

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import DataReceived, StreamEnded

from ruyihttp._http2 import Connection, Exchange, _Call, _Protocol
from ruyihttp._retry import Reset


class WireConnection(Connection):
    """Pump real H2 frames against a peer, with no native thread or socket."""

    def __init__(self):
        self.protocol = _Protocol(H2Configuration(client_side=True))
        self.peer = H2Connection(H2Configuration(client_side=False))
        self.transport = SimpleNamespace(h2=self, read=self.peer.data_to_send)
        self._output = bytearray()
        self._write_buffer = b""
        self.streams = {}
        self.priority_tree = self.goaway = self.closed = False
        self.error = None
        self.protocol.initiate_connection()
        self.peer.initiate_connection()
        self.flush()
        self.receive()

    def submit(self, operation, exchange, **arguments):
        call = _Call(operation, exchange, None, **arguments)
        if not self._execute(call):
            raise AssertionError(f"unexpected blocked {operation}")
        return call.result

    def flush(self):
        return self.peer.receive_data(self.protocol.data_to_send())


class EarlyResponseTests(unittest.TestCase):
    def setUp(self):
        self.connection = WireConnection()
        self.exchange = Exchange(
            self.connection.transport,
            "POST",
            "https://example.com/",
            {"Host": "example.com"},
            True,
        )
        self.connection.flush()

    def complete_response(self, *, reset=True):
        stream_id = self.exchange.stream_id
        peer = self.connection.peer
        peer.send_headers(stream_id, [(b":status", b"413"), (b"x-result", b"large")])
        peer.send_data(stream_id, b"too large", end_stream=True)
        if reset:
            peer.reset_stream(stream_id, ErrorCodes.NO_ERROR)
        self.connection.receive()

    def test_pending_upload_operations_complete_even_under_backpressure(self):
        connection = self.connection
        write = _Call("write", self.exchange, None, data=b"upload")
        finish = _Call("finish", self.exchange, None)
        connection._output.extend(b"x" * 65536)
        self.assertFalse(connection._execute(write))
        self.assertFalse(connection._execute(finish))

        self.complete_response()
        self.assertTrue(connection._execute(write))
        self.assertEqual(write.result, 0)
        self.assertTrue(connection._execute(finish))
        self.assertFalse(self.exchange.sent_end)
        self.assertEqual(self.exchange.status, 413)
        self.assertEqual(self.exchange.headers["x-result"], "large")
        self.assertEqual(self.exchange.read(64), b"too large")

    def test_completed_reset_survives_peer_close_for_pending_calls(self):
        self.complete_response(reset=False)
        connection, exchange = self.connection, self.exchange
        connection.peer.reset_stream(exchange.stream_id, ErrorCodes.NO_ERROR)
        connection.receive()
        connection.closed = True
        connection.error = Reset("TLS closed")
        write = _Call("write", exchange, None, data=b"upload")
        self.assertEqual(connection._after_close(write), 0)
        for operation in ("finish", "headers"):
            self.assertIsNone(connection._after_close(_Call(operation, exchange, None)))
        self.assertEqual(
            connection._after_close(_Call("read", exchange, None, size=64)), b"too large"
        )
        self.assertEqual(connection._after_close(_Call("read", exchange, None, size=64)), b"")

    def test_early_end_stream_without_reset_leaves_upload_open(self):
        self.complete_response(reset=False)
        self.assertFalse(self.exchange.upload_stopped)
        self.exchange.write(b"upload")
        self.exchange.receive()
        events = self.connection.flush()
        self.assertEqual([e.data for e in events if isinstance(e, DataReceived)], [b"upload", b""])
        self.assertTrue(any(isinstance(e, StreamEnded) for e in events))
        self.assertTrue(self.exchange.sent_end)
