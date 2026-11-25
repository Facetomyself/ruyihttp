# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Retry policy checks and opt-in native H1 loopback coverage.

Run the loopback tests with RUYIHTTP_TEST_NATIVE_RETRY=1 and an installed
native runtime, or point NECKO_CORE_LIBRARY at a compatible runtime.
"""

import io
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock, patch

from h2.errors import ErrorCodes
from h2.events import ConnectionTerminated, StreamReset
from urllib3.exceptions import ProtocolError
from urllib3.util import Retry

import ruyihttp
from ruyihttp._http2 import Connection as H2Connection
from ruyihttp._http3 import Connection as H3Connection
from ruyihttp._retry import (
    DirectRouteReset,
    Http1Required,
    Http1RequiredUnprocessed,
    Http3ProtocolError,
    Rejected,
    Reset,
    restartable,
)


class RetryPolicyTests(unittest.TestCase):
    def test_sent_or_uncertain_requests_are_not_implicitly_replayed(self):
        for reason in (Reset, Http1Required, DirectRouteReset, Http3ProtocolError):
            for method in ("POST", "PATCH", "DELETE", "PUT"):
                for exchange in (None, SimpleNamespace(sent_data=True)):
                    with self.subTest(reason=reason, method=method, exchange=exchange):
                        self.assertFalse(restartable(reason(), method, exchange))

    def test_safe_methods_unsent_requests_and_explicit_rejections_retry(self):
        sent = SimpleNamespace(sent_data=True)
        unsent = SimpleNamespace(sent_data=False)
        safe = ("GET", "HEAD", "OPTIONS", "TRACE", "PROPFIND", "REPORT", "SEARCH")
        for reason in (Reset, Http1Required, DirectRouteReset, Http3ProtocolError):
            for method in safe:
                with self.subTest(reason=reason, method=method):
                    self.assertTrue(restartable(reason(), method, sent))
            with self.subTest(reason=reason, sent=False):
                self.assertTrue(restartable(reason(), "POST", unsent))
        self.assertTrue(restartable(Rejected(), "POST", sent))
        self.assertFalse(restartable(ProtocolError(), "GET", unsent))

    def test_reply_bytes_override_even_explicit_rejection(self):
        replied = SimpleNamespace(received_data=True, sent_data=True)
        for reason in (
            Reset, Rejected, Http1Required, DirectRouteReset, Http3ProtocolError,
        ):
            with self.subTest(reason=reason):
                self.assertFalse(restartable(reason(), "GET", replied))
        self.assertFalse(restartable(Rejected(), "POST", replied))

    def test_exchange_construction_failure_uses_exception_wire_state(self):
        error = Reset()
        error._necko_sent = False
        self.assertTrue(restartable(error, "POST", None))
        error._necko_received = True
        self.assertFalse(restartable(error, "GET", None))

    def test_replay_with_non_rewindable_body_fails_before_second_attempt(self):
        with ruyihttp.Session() as session:
            session.trust_env = False
            adapter = session.get_adapter("http://127.0.0.1/")
            # Model a guaranteed rejection, for which even POST would otherwise retry.
            error = ruyihttp.ConnectionError(Rejected("request rejected"))
            error._necko_restartable = True
            with patch.object(adapter, "_send_once", side_effect=error) as send:
                with self.assertRaises(ruyihttp.exceptions.UnrewindableBodyError):
                    session.post("http://127.0.0.1/", data=iter([b"payload"]))
            send.assert_called_once()


class RetryClassificationTests(unittest.TestCase):
    def receive_h2(self, streams, event):
        connection = object.__new__(H2Connection)
        connection.streams = streams
        connection._buffered = 0
        connection.protocol = Mock()
        connection.protocol.receive_data.return_value = [event]
        connection.transport = SimpleNamespace(read=lambda n: b"frames")
        connection.receive()

    def test_http2_goaway_at_processing_boundary_preserves_http1_fallback(self):
        accepted = Mock(ended=False)
        later = Mock(ended=False, sent_data=True, received_data=False, buffer=bytearray())
        event = ConnectionTerminated()
        event.error_code = ErrorCodes.HTTP_1_1_REQUIRED
        event.last_stream_id = 3
        self.receive_h2({3: accepted, 5: later}, event)
        accepted.fail.assert_not_called()
        error = later.fail.call_args.args[0]
        self.assertIsInstance(error, Http1Required)
        self.assertTrue(restartable(error, "POST", later))

    def test_http2_prefetch_drain_preserves_http1_fallback(self):
        exchange = SimpleNamespace(closed=False, error=None)
        call = SimpleNamespace(
            exchange=exchange, operation="fetch", cancelled=False, deadline=None
        )
        connection = object.__new__(H2Connection)
        connection.goaway = True
        connection.goaway_error = ErrorCodes.HTTP_1_1_REQUIRED
        connection._output = connection._write_buffer = b""
        with self.assertRaises(Http1RequiredUnprocessed) as exception:
            connection._execute(call)
        self.assertTrue(restartable(exception.exception, "POST", None))

    def test_http2_refused_stream_is_distinct_from_http1_required_reset(self):
        for code, expected, can_restart in (
            (ErrorCodes.REFUSED_STREAM, Rejected, True),
            (ErrorCodes.HTTP_1_1_REQUIRED, Http1Required, False),
            (ErrorCodes.CANCEL, ProtocolError, False),
        ):
            with self.subTest(code=code):
                exchange = Mock(sent_data=True, received_data=False, buffer=bytearray())
                event = StreamReset(stream_id=3, error_code=code)
                self.receive_h2({3: exchange}, event)
                error = exchange.fail.call_args.args[0]
                self.assertIsInstance(error, expected)
                self.assertEqual(restartable(error, "POST", exchange), can_restart)

    def test_http3_rejected_stream_is_distinct_from_fallback_and_cancel(self):
        for code, expected, can_restart in (
            (0x10B, Rejected, True),  # H3_REQUEST_REJECTED
            (0x110, Http1Required, False),  # H3_VERSION_FALLBACK
            (0x10C, ProtocolError, False),  # H3_REQUEST_CANCELLED
            (0x102, DirectRouteReset, False),  # H3_INTERNAL_ERROR
        ):
            for kind in ("reset", "stop_sending"):
                with self.subTest(code=code, kind=kind):
                    exchange = Mock(sent_data=True, received_data=False)
                    connection = Mock(streams={4: exchange})
                    connection._call.return_value = {
                        "events": [{"type": kind, "stream": 4, "error": code}]
                    }
                    H3Connection._events(connection)
                    error = exchange.fail.call_args.args[0]
                    self.assertIsInstance(error, expected)
                    self.assertEqual(restartable(error, "POST", exchange), can_restart)

    def test_http3_goaway_rejects_at_and_beyond_threshold(self):
        accepted = Mock()
        later = Mock(sent_data=True, received_data=False)
        connection = Mock(streams={0: accepted, 4: later})
        connection._call.return_value = {
            "events": [{"type": "state", "state": "going_away", "last": 4}]
        }
        H3Connection._events(connection)
        accepted.fail.assert_not_called()
        self.assertTrue(restartable(later.fail.call_args.args[0], "POST", later))


class _DropFirstHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with self.server.lock:
            self.server.requests.append((self.client_address, self.command, self.path, body))
            drop = self.path == "/drop" and not self.server.dropped
            self.server.dropped |= drop
        if drop:
            # The HTTP request is complete; close the socket before writing a response.
            self.close_connection = True
            return
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _handle

    def log_message(self, *args):
        pass


@unittest.skipUnless(
    os.environ.get("RUYIHTTP_TEST_NATIVE_RETRY") == "1",
    "Set RUYIHTTP_TEST_NATIVE_RETRY=1 with a compatible native runtime",
)
class NativeRetryLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _DropFirstHandler)
        self.server.lock = threading.Lock()
        self.server.requests = []
        self.server.dropped = False
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.shutdown)
        self.session = ruyihttp.Session()
        self.session.trust_env = False
        self.addCleanup(self.session.close)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def _prime(self):
        self.assertEqual(self.session.get(self.url + "/prime", timeout=5).content, b"ok")

    def _check_dropped_requests(self, method, bodies):
        with self.server.lock:
            prime, *dropped = self.server.requests
        self.assertEqual(
            [record[1:] for record in dropped],
            [(method, "/drop", body) for body in bodies],
        )
        self.assertEqual(prime[0], dropped[0][0], "the first attempt must use pooled H1")
        if len(dropped) == 2:
            self.assertNotEqual(dropped[0][0], dropped[1][0])

    def test_read_post_body_is_not_replayed_at_default_retry_setting(self):
        self._prime()
        body = b"one side effect"
        try:
            self.session.post(self.url + "/drop", data=body, timeout=5)
        except ruyihttp.ConnectionError as error:
            failure = error
        else:
            failure = None
        self._check_dropped_requests("POST", [body])
        self.assertIsInstance(failure, ruyihttp.ConnectionError)

    def test_bodyless_post_is_treated_as_sent(self):
        self._prime()
        with self.assertRaises(ruyihttp.ConnectionError):
            self.session.post(self.url + "/drop", timeout=5)
        self._check_dropped_requests("POST", [b""])

    def test_retry_with_default_methods_does_not_allow_post(self):
        self.session.get_adapter(self.url).max_retries = Retry(total=1, read=1)
        self._prime()
        with self.assertRaises(ruyihttp.ConnectionError):
            self.session.post(self.url + "/drop", data=b"payload", timeout=5)
        self._check_dropped_requests("POST", [b"payload"])

    def test_safe_get_still_restarts_on_a_pooled_connection(self):
        self._prime()
        self.assertEqual(self.session.get(self.url + "/drop", timeout=5).content, b"ok")
        self._check_dropped_requests("GET", [b"", b""])

    def test_explicit_retry_allows_post_and_rewinds_body(self):
        adapter = self.session.get_adapter(self.url)
        adapter.max_retries = Retry(total=1, read=1, allowed_methods={"POST"})
        body = io.BytesIO(b"skip-payload")
        body.seek(5)
        self._prime()
        response = self.session.post(self.url + "/drop", data=body, timeout=5)
        self.assertEqual(response.content, b"ok")
        self._check_dropped_requests("POST", [b"payload", b"payload"])
        self.assertEqual(len(response.raw.retries.history), 1)


if __name__ == "__main__":
    unittest.main()
