# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from h2.errors import ErrorCodes
from h2.events import StreamReset, WindowUpdated
from h2.settings import SettingCodes
from hyperframe.frame import DataFrame, GoAwayFrame
from urllib3.exceptions import ProtocolError

from ruyihttp._http2 import (
    _BUFFER_LIMIT,
    _CONNECTION_WINDOW,
    _CREDIT_BATCH,
    _MAX_BOOSTS,
    _MAX_STREAMS,
    _STREAM_BOOST,
    _STREAM_WINDOW,
    Exchange,
    _Call,
)
from ruyihttp._retry import Rejected
from ruyihttp._transport import _Pool, _NEEDS_DNS
from test_http2_early_response import WireConnection


class ReceiveFlowTests(unittest.TestCase):
    def setUp(self):
        self.conn = WireConnection()
        self.peer = self.conn.peer

    def start(self, method="GET"):
        exchange = Exchange(
            self.conn.transport,
            method,
            "https://example.com/",
            {"Host": "example.com"},
            method == "POST",
        )
        self.conn.flush()
        self.peer.send_headers(exchange.stream_id, [(b":status", b"200")])
        self.conn.receive()
        return exchange

    def wire_data(self, exchange, size, block=16384):
        while size:
            batch = min(size, 32768)
            left = batch
            while left:
                n = min(block, left)
                self.peer.send_data(exchange.stream_id, b"x" * n)
                left -= n
            self.conn.receive()
            size -= batch

    def windows(self, sid):
        return (
            self.peer.outbound_flow_control_window,
            self.peer.streams[sid].outbound_flow_control_window,
        )

    def update_windows(self):
        return [
            (e.stream_id, e.delta)
            for e in self.conn.flush()
            if isinstance(e, WindowUpdated)
        ]

    def test_advertised_stream_reservations_fit_even_when_every_body_is_unread(self):
        exchanges = [self.start() for _ in range(_MAX_STREAMS)]
        for i, exchange in enumerate(exchanges):
            limit = _STREAM_WINDOW + (_STREAM_BOOST if i < _MAX_BOOSTS else 0)
            self.assertEqual(exchange.receive_limit, limit)
            self.assertEqual(self.windows(exchange.stream_id)[1], limit)
            self.wire_data(exchange, limit)
            self.assertEqual(
                (len(exchange.buffer), self.windows(exchange.stream_id)[1]), (limit, 0)
            )
        self.assertEqual(self.conn._buffered, _BUFFER_LIMIT)
        self.assertEqual(
            self.peer.outbound_flow_control_window, _CONNECTION_WINDOW - _BUFFER_LIMIT
        )
        self.assertFalse(self.conn.has_capacity(_MAX_STREAMS))
        blocked = _Call("fetch", SimpleNamespace(closed=False, error=None), None)
        self.assertFalse(self.conn._execute(blocked))

        first = exchanges[0]
        self.conn._execute(_Call("cancel", first, None))
        self.assertEqual(self.conn._buffered, _BUFFER_LIMIT - first.receive_limit)
        self.assertEqual(self.update_windows(), [(0, first.receive_limit)])
        replacement = self.start()
        self.assertEqual(replacement.receive_limit, first.receive_limit)
        self.wire_data(replacement, first.receive_limit)
        self.assertEqual(self.conn._buffered, _BUFFER_LIMIT)
        self.assertEqual(
            self.peer.outbound_flow_control_window, _CONNECTION_WINDOW - _BUFFER_LIMIT
        )

    def test_padding_recycles_without_application_reads_or_window_inflation(self):
        exchange = self.start()
        sid = exchange.stream_id
        original = self.windows(sid)
        released = 0
        # More than two whole stream windows of padding, none of it payload.
        for _ in range(32):
            for _ in range(192):
                self.peer.send_data(sid, b"", pad_length=255)
            self.conn.receive()
            released += sum(n for stream, n in self.update_windows() if stream == 0)
            self.assertEqual(self.conn._buffered, 0)
            self.assertLessEqual(self.windows(sid)[0], original[0])
            self.assertLessEqual(self.windows(sid)[1], original[1])
        self.assertEqual(released, 32 * 192 * 256)
        self.assertEqual(self.windows(sid)[0], original[0])
        waiting = _Call("read", exchange, None, size=1)
        self.assertFalse(self.conn._execute(waiting), "padding must not appear as EOF")
        self.assertEqual(exchange.read(0), b"")
        self.peer.send_data(sid, b"ok", end_stream=True)
        self.conn.receive()
        self.assertEqual(exchange.read(1), b"o")
        self.assertEqual(exchange.read(8), b"k")
        self.assertEqual(exchange.read(8), b"")
        self.assertEqual(self.conn._buffered, 0)

    def test_partial_consumption_releases_only_consumed_credit(self):
        exchange = self.start()
        sid = exchange.stream_id
        limit = exchange.receive_limit
        self.wire_data(exchange, limit)
        root = _CONNECTION_WINDOW - limit
        self.assertEqual(self.windows(sid), (root, 0))
        self.assertEqual(exchange.read(1), b"x")
        self.assertEqual(self.update_windows(), [])
        self.assertEqual(exchange.read(_CREDIT_BATCH - 1), b"x" * (_CREDIT_BATCH - 1))
        self.assertEqual(
            self.update_windows(), [(0, _CREDIT_BATCH), (sid, _CREDIT_BATCH)]
        )
        self.assertEqual(self.windows(sid), (root + _CREDIT_BATCH, _CREDIT_BATCH))
        self.assertEqual(self.conn._buffered, limit - _CREDIT_BATCH)

    def test_cancel_and_late_data_return_connection_credit_once(self):
        exchange = self.start(method="POST")
        sid = exchange.stream_id
        self.wire_data(exchange, _CREDIT_BATCH)
        # Simulate peer data already in flight when the app cancels.
        for _ in range(4):
            self.peer.send_data(sid, b"y" * 16384)
        self.conn.wire.extend(self.peer.data_to_send())
        self.conn._execute(_Call("cancel", exchange, None))
        events = self.conn.flush()
        self.assertTrue(
            any(isinstance(e, StreamReset) and e.stream_id == sid for e in events)
        )
        self.assertEqual(
            [(e.stream_id, e.delta) for e in events if isinstance(e, WindowUpdated)],
            [(0, _CREDIT_BATCH)],
        )
        self.conn.receive()
        self.assertEqual(
            self.update_windows(), [], "fourth frame straddles the TLS read"
        )
        self.conn.receive()
        self.assertEqual(self.update_windows(), [(0, _CREDIT_BATCH)])
        self.assertEqual(self.peer.outbound_flow_control_window, _CONNECTION_WINDOW)
        self.assertEqual((self.conn._buffered, self.conn._boosted_streams), (0, 0))
        self.assertEqual(self.start().receive_limit, _STREAM_WINDOW + _STREAM_BOOST)

    def test_reset_discards_unread_data_but_does_not_kill_the_other_stream(self):
        reset = self.start()
        keep = self.start()
        self.wire_data(reset, _CREDIT_BATCH)
        self.peer.reset_stream(reset.stream_id, ErrorCodes.CANCEL)
        self.peer.send_data(keep.stream_id, b"ok", end_stream=True)
        self.conn.receive()
        self.assertEqual(self.update_windows(), [(0, _CREDIT_BATCH)])
        self.assertEqual((self.conn._buffered, len(reset.buffer)), (2, 0))
        with self.assertRaisesRegex(ProtocolError, "stream reset: 8"):
            reset.read(10)
        self.assertEqual(keep.read(10), b"ok")

    def test_cancel_after_remote_end_still_resets_unfinished_upload(self):
        exchange = self.start(method="POST")
        self.peer.send_data(exchange.stream_id, b"ok", end_stream=True)
        self.conn.receive()
        self.assertTrue(exchange.ended)
        self.assertFalse(exchange.sent_end)
        self.conn._execute(_Call("cancel", exchange, None))
        self.assertTrue(any(isinstance(e, StreamReset) for e in self.conn.flush()))
        self.assertEqual(self.conn._buffered, 0)

    def test_peer_cannot_exceed_stream_budget_using_raw_data_frames(self):
        exchange = self.start()
        self.wire_data(exchange, exchange.receive_limit)
        frame = DataFrame(exchange.stream_id, data=b"x")
        self.conn.wire.extend(frame.serialize())
        with self.assertRaisesRegex(ProtocolError, "window shrunk below 0"):
            self.conn.receive()
        self.assertEqual(self.conn._buffered, exchange.receive_limit)

    def test_goaway_discards_an_unprocessed_exchange_but_serves_accepted_stream(self):
        accepted = self.start()
        rejected = self.start()
        self.wire_data(rejected, _CREDIT_BATCH)
        self.peer.send_data(accepted.stream_id, b"ok", end_stream=True)
        self.conn.wire.extend(self.peer.data_to_send())
        self.conn.wire.extend(
            GoAwayFrame(0, last_stream_id=accepted.stream_id).serialize()
        )
        self.conn.receive()
        self.assertFalse(self.conn.idle())
        self.assertEqual(self.update_windows(), [(0, _CREDIT_BATCH)])
        with self.assertRaises(Rejected):
            rejected.read(64)
        self.assertEqual(accepted.read(64), b"ok")
        self.assertEqual(self.conn._buffered, 0)

    def test_profile_without_enable_push_still_refuses_unconsumed_push(self):
        self.conn = WireConnection(firefox="128")
        self.peer = self.conn.peer
        exchange = self.start()
        self.assertNotIn(SettingCodes.ENABLE_PUSH, self.conn.protocol.local_settings)
        self.peer.push_stream(
            exchange.stream_id,
            2,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/pushed"),
            ],
        )
        self.peer.send_headers(2, [(b":status", b"200")])
        self.peer.send_data(2, b"unconsumed")
        self.conn.receive()
        self.assertTrue(
            any(
                isinstance(e, StreamReset) and e.stream_id == 2
                for e in self.conn.flush()
            )
        )
        self.assertEqual(self.conn._buffered, 0)
        self.peer.send_data(exchange.stream_id, b"ok", end_stream=True)
        self.conn.receive()
        self.assertEqual(exchange.read(8), b"ok")

    def test_settings_shrink_to_zero_blocks_fetch_until_increased(self):
        self.peer.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: 0})
        self.conn.receive()
        self.conn.flush()
        exchange = SimpleNamespace(
            closed=False, error=None, sent_end=True, receive_limit=_STREAM_WINDOW
        )
        fetch = _Call(
            "fetch",
            exchange,
            None,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/"),
            ],
            document=False,
            weight=22,
        )
        self.assertFalse(self.conn.has_capacity(0))
        self.assertFalse(self.conn._execute(fetch))
        self.assertFalse(self.conn.streams)
        self.peer.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: 1})
        self.conn.receive()
        self.assertTrue(self.conn.has_capacity(0))
        self.assertFalse(self.conn.has_capacity(1))
        self.assertTrue(self.conn._execute(fetch))


class LeaseTests(unittest.TestCase):
    def h2(self, limit):
        h2 = Mock(received_settings=True, origins=None)
        h2.has_capacity.side_effect = lambda leases: leases < limit
        return Mock(
            h2=h2,
            multiplexed=True,
            alpn="h2",
            origin_port=443,
            peer_address="127.0.0.1",
            coalescing_denied=set(),
        )

    def test_reserved_leases_spill_before_stream_creation_and_trim_idle_cache(self):
        pool = _Pool(maximum=1, block=False)
        first, second = self.h2(1), self.h2(2)
        self.assertIsNone(pool.acquire())
        pool.register(first)
        self.assertIsNone(pool.acquire(), "first lease has not submitted HEADERS yet")
        pool.register(second)
        self.assertIs(pool.acquire(), second)
        pool.release(first)
        pool.release(second)
        pool.release(second)
        self.assertEqual(pool.shared, {first: 0})
        second.close.assert_called_once()
        self.assertEqual(pool.leased, 0)
        self.assertIs(pool.acquire(), first)

    def test_coalescing_skips_saturated_peer_even_before_dns(self):
        pool = _Pool(maximum=2, block=False)
        first = self.h2(1)
        self.assertIsNone(pool.acquire())
        pool.register(first)
        self.assertIsNone(pool.borrow("other.example", 443, None))
        pool.release(first)
        self.assertIs(pool.borrow("other.example", 443, None), _NEEDS_DNS)
        self.assertIs(pool.borrow("other.example", 443, {"127.0.0.1"}), first)
        self.assertIsNone(pool.borrow("third.example", 443, {"127.0.0.1"}))
        first.context.verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
