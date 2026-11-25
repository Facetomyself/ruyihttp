# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Deterministic Alt-Svc selection, lease, and protocol cache checks."""

import ssl
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from requests import Request
from requests.exceptions import ConnectionError, ConnectTimeout
from urllib3.exceptions import ProtocolError

from ruyihttp import _connect, _transport
from ruyihttp._connect import Attempt


def key(host="127.0.0.1", *, proxy=None, verify="True", cert="None"):
    return ("https", host, None, proxy, verify, cert, False)


class AltSvcTests(unittest.TestCase):
    def setUp(self):
        self.adapter = _transport.HTTPAdapter()
        self.addCleanup(self.adapter.close)
        self.adapter._library = SimpleNamespace(_name="/tmp/libnecko_core.so")
        self.request = Request("GET", "https://127.0.0.1/").prepare()

    def advertise(self, route, port=8443, age=60):
        self.adapter._remember_alternative(
            route, route[1], {"Alt-Svc": f'h3=":{port}"; ma={age}'}
        )

    def test_same_route_cools_without_refreshing_failure_and_recovers(self):
        route = key()
        with patch.object(_transport.time, "monotonic", return_value=1) as clock:
            self.advertise(route, age=1)
            original = self.adapter._active_alternative(route)
            self.adapter._cool_alternative(route, original)
            expires = 1 + _transport._ALT_SVC_COOLDOWN
            clock.return_value = 2
            self.assertIsNone(self.adapter._active_alternative(route))
            self.advertise(
                route
            )  # Same endpoint, even after the original hint expired.
            self.assertIsNone(self.adapter._active_alternative(route))
            self.advertise(route, port=9443)  # Different authority bypasses cooldown.
            self.assertEqual(
                self.adapter._active_alternative(route)[0], (route[1], 9443)
            )
            self.adapter._cool_alternative(
                route, original
            )  # Late failure must not cool the new authority.
            self.assertIsNotNone(self.adapter._active_alternative(route))
            self.advertise(route)
            self.assertIsNone(self.adapter._active_alternative(route))
            clock.return_value = expires
            self.assertEqual(self.adapter._active_alternative(route)[0], original[0])
            self.assertFalse(self.adapter._alt_cooldowns)

    def test_probe_crossing_hint_expiry_still_cools_same_endpoint(self):
        route = key()
        with patch.object(_transport.time, "monotonic", return_value=1) as clock:
            self.advertise(route, age=1)
            original = self.adapter._active_alternative(route)
            clock.return_value = 2
            self.adapter._cool_alternative(route, original)
            self.assertFalse(self.adapter._alt_svc)
            self.advertise(route)
            self.assertIsNone(self.adapter._active_alternative(route))

    def test_alt_bounds_ttl_clear_and_partition(self):
        routes = [key("a.test"), key("a.test", verify="/ca-b.pem"), key("b.test")]
        a, b, c = routes
        with (
            patch.object(_transport, "_ALT_SVC_LIMIT", 2),
            patch.object(_transport.time, "monotonic", return_value=1) as clock,
        ):
            self.advertise(a, age=9999999)
            self.advertise(b, age=3)
            self.assertEqual(
                self.adapter._active_alternative(a)[1], 1 + _transport._ALT_SVC_MAX_AGE
            )
            self.advertise(c, age=1)
            self.assertNotIn(b, self.adapter._alt_svc)  # a was used most recently.
            clock.return_value = 2
            self.assertIsNotNone(self.adapter._active_alternative(a))
            self.assertNotIn(
                c, self.adapter._alt_svc
            )  # Opportunistic eviction of untouched expired records.
            self.adapter._remember_alternative(a, a[1], {"Alt-Svc": "clear"})
            self.assertIsNone(self.adapter._active_alternative(a))
            self.assertFalse(self.adapter._alt_svc)

    def test_cooldown_table_bound(self):
        with patch.object(_transport, "_ALT_SVC_LIMIT", 2):
            route = key()
            for port in (8443, 8444, 8445):
                self.advertise(route, port=port)
                self.adapter._cool_alternative(
                    route, self.adapter._active_alternative(route)
                )
            self.assertEqual(len(self.adapter._alt_cooldowns), 2)
            self.advertise(route, port=8443)
            self.assertEqual(
                self.adapter._active_alternative(route)[0], (route[1], 8443)
            )

    def test_token_entry_byte_size_and_ttl_bounds(self):
        a, b, c, d = [key(f"{i}.test") for i in range(4)]
        with (
            patch.object(_transport, "_QUIC_TOKEN_LIMIT", 2),
            patch.object(_transport, "_QUIC_TOKEN_BYTES", 7),
            patch.object(_transport, "_QUIC_TOKEN_MAX_SIZE", 5),
            patch.object(_transport, "_QUIC_TOKEN_MAX_AGE", 4),
            patch.object(_transport.time, "monotonic", return_value=1) as clock,
        ):
            save, read = self.adapter._save_quic_token, self.adapter._quic_token
            save(a, "aa", 4000)
            save(b, "bbb", 4000)
            self.assertEqual(read(a), "aa")
            save(c, "cccc", 4000)
            self.assertEqual((read(a), read(b), read(c)), ("aa", "", "cccc"))
            save(d, "zzzzz", 1)  # Byte limit forces eviction even below entry limit.
            self.assertEqual((read(a), read(c), read(d)), ("", "", "zzzzz"))
            save(d, "oversized", 5)
            self.assertEqual(read(d), "zzzzz")
            clock.return_value = 2
            self.assertEqual(read(a), "")
            self.assertFalse(self.adapter._quic_tokens)
            self.assertEqual(self.adapter._quic_token_bytes, 0)
            for route in (a, b, c):
                save(route, "x", 4000)
            self.assertEqual((read(a), read(b), read(c)), ("", "x", "x"))
            clock.return_value = 6
            save(a, "a", 4)
            self.assertEqual(list(self.adapter._quic_tokens), [a])
            self.assertEqual(self.adapter._quic_token_bytes, 1)
        self.adapter.close()
        self.assertEqual(self.adapter._quic_token_bytes, 0)

    def test_failed_token_record_cannot_delete_fresh_replacement(self):
        route = key()
        save = self.adapter._save_quic_token
        save(route, "same-value", 10)
        stale = self.adapter._quic_token_record(route)
        # Even identical token values/expiries can be from distinct callbacks.
        with patch.object(_transport.time, "monotonic", return_value=stale[1] - 10):
            save(route, "same-value", 10)
            self.adapter._forget_quic_token(route, stale)
            self.assertEqual(self.adapter._quic_token(route), "same-value")
            self.adapter._forget_quic_token(
                route, self.adapter._quic_token_record(route)
            )
            self.assertEqual(self.adapter._quic_token(route), "")
            self.assertEqual(self.adapter._quic_token_bytes, 0)

    def test_no_warm_tcp_starts_with_time_left_under_short_budget(self):
        route = key()
        self.advertise(route)
        tcp = Mock(alpn="http/1.1")
        dial_remaining = []

        def stall(*args, attempt, **kwargs):
            attempt.cancelled.wait(1)
            raise OSError("blocked UDP")

        def dial(url, proxy, verify, cert, timeout, attempt, **kwargs):
            dial_remaining.append(timeout)
            return tcp

        with (
            patch("ruyihttp._http3.Connection", side_effect=stall),
            patch.object(_transport, "_ssl_context"),
            patch.object(self.adapter, "_connect", side_effect=dial),
        ):
            result = self.adapter._connect_alternative(
                self.request,
                route,
                self.adapter._alt_svc[route],
                True,
                Attempt(time.monotonic() + 0.05),
                None,
            )
        self.assertIs(result, tcp)
        self.assertGreater(dial_remaining[0], 0)
        self.assertLess(dial_remaining[0], 0.05)
        self.assertIsNone(self.adapter._active_alternative(route))

    def test_closed_and_busy_tcp_are_not_leased(self):
        pool = self.adapter._pool(key())
        dead = Mock(alpn="http/1.1", multiplexed=False)
        dead.idle.return_value = False
        leased = Mock(alpn="http/1.1", multiplexed=False)
        leased.idle.return_value = True
        pool.idle.extend([dead, leased])
        self.assertIs(pool.acquire(), leased)
        self.assertIsNone(pool.acquire("h3"))
        self.assertIsNone(pool.borrow_tcp())
        dead.close.assert_called_once()
        pool.release(leased, reuse=False)
        self.assertTrue(
            pool.connecting, "returning an unrelated H1 lease leaves the dial reserved"
        )
        self.assertEqual(pool.leased, 1)
        pool.release(None)
        self.assertEqual(pool.leased, 0)
        pool.close()
        self.assertIsNone(pool.borrow_tcp())

    def test_waiter_rechecks_cooldown_before_dialing(self):
        route = key()
        self.advertise(route)
        pool = self.adapter._pool(route)
        tcp = Mock(alpn="http/1.1", multiplexed=False)
        tcp.idle.return_value = True
        pool.idle.append(tcp)
        self.assertIsNone(
            pool.acquire("h3")
        )  # Leader already owns the dial reservation.
        entered, outcomes = threading.Event(), []
        acquire = pool.acquire

        def wait(prefer, **kwargs):
            outcomes.append(prefer)
            entered.set()
            return acquire(prefer, **kwargs)

        def request():
            try:
                self.adapter._send_once(self.request, False, (2, 2), True, None, None)
            except Exception as error:
                outcomes.append(error)

        with (
            patch.object(pool, "acquire", side_effect=wait),
            patch.object(self.adapter, "_connect_alternative") as probe,
            patch.object(self.adapter, "_connect") as dial,
            patch.object(
                _transport, "_Exchange", side_effect=ConnectionError("after lease")
            ) as exchange,
        ):
            waiter = threading.Thread(target=request, daemon=True)
            waiter.start()
            try:
                self.assertTrue(entered.wait(1))
                self.adapter._cool_alternative(route, self.adapter._alt_svc[route])
            finally:
                pool.release(None)
                waiter.join(2)
            self.assertFalse(waiter.is_alive())
            self.assertEqual(
                outcomes[0], "h3"
            )  # The waiter had observed a previously usable hint.
            self.assertEqual(str(outcomes[1]), "after lease")
            probe.assert_not_called()
            dial.assert_not_called()
            self.assertIs(exchange.call_args.args[1], tcp)
        self.assertEqual(pool.leased, 0)
        self.assertFalse(pool.connecting)

    def test_deadline_after_warm_selection_preserves_unused_h1(self):
        route = key()
        self.advertise(route)
        pool = self.adapter._pool(route)
        tcp = Mock(alpn="http/1.1", multiplexed=False)
        tcp.idle.return_value = True
        pool.idle.append(tcp)
        clock = SimpleNamespace(monotonic=time.monotonic)
        cool = self.adapter._cool_alternative

        def expire_after_warm_wins(*args):
            cool(*args)
            clock.monotonic = lambda: time.monotonic() + 5

        with (
            patch.object(_connect, "time", clock),
            patch.object(
                self.adapter, "_cool_alternative", side_effect=expire_after_warm_wins
            ),
            patch.object(self.adapter, "_connect") as dial,
            patch.object(_transport, "_ssl_context"),
            patch.object(_transport, "_Exchange") as exchange,
            patch(
                "ruyihttp._http3.Connection", side_effect=ProtocolError("UDP failed")
            ),
        ):
            with self.assertRaises(ConnectTimeout):
                self.adapter._send_once(self.request, False, (1, 2), True, None, None)
        dial.assert_not_called()
        exchange.assert_not_called()
        tcp.close.assert_not_called()
        self.assertEqual(pool.leased, 0)
        self.assertFalse(pool.connecting)
        self.assertIs(pool.acquire(), tcp)
        pool.release(tcp)

    def test_constructor_timeout_drops_h1_even_without_exchange_object(self):
        pool = self.adapter._pool(key())
        tcp = Mock(alpn="http/1.1", multiplexed=False)
        tcp.idle.return_value = True
        pool.idle.append(tcp)
        request = Request("POST", "https://127.0.0.1/", data=b"once").prepare()
        with (
            patch.object(self.adapter, "_connect") as dial,
            patch.object(
                _transport, "_Exchange", side_effect=ConnectTimeout("after write")
            ) as exchange,
        ):
            with self.assertRaises(ConnectTimeout):
                self.adapter.send(request, timeout=(1, 2))
        dial.assert_not_called()
        exchange.assert_called_once()
        tcp.close.assert_called_once()
        self.assertFalse(pool.idle)
        self.assertEqual(pool.leased, 0)
        self.assertFalse(pool.connecting)

    def test_warm_h2_at_capacity_does_not_displace_idle_h1(self):
        pool = self.adapter._pool(key())
        h2 = Mock(alpn="h2", multiplexed=True)
        h2.h2.has_capacity.side_effect = lambda leased: leased < 1
        pool.shared[h2] = pool.leased = 1
        tcp = Mock(alpn="http/1.1", multiplexed=False)
        tcp.idle.return_value = True
        pool.idle.append(tcp)
        self.assertIsNone(pool.acquire("h3"))
        self.assertIs(pool.borrow_tcp(), tcp)
        self.assertEqual(pool.shared[h2], 1)
        pool.release(None)
        pool.release(tcp)
        pool.release(h2)
        self.assertEqual(pool.leased, 0)
        self.assertFalse(pool.connecting)

    def test_losing_warm_backup_is_returned_to_pool(self):
        route = key()
        self.advertise(route)
        pool = self.adapter._pool(route)
        tcp = Mock(alpn="http/1.1", multiplexed=False)
        tcp.idle.return_value = True
        h3 = Mock(alpn="h3")
        pool.idle.append(tcp)
        self.assertIsNone(pool.acquire("h3"))
        fallback_ready, allow_fallback, returned = [threading.Event() for _ in range(3)]
        borrow, release = pool.borrow_tcp, pool.release

        def warm():
            connection = borrow()
            fallback_ready.set()
            allow_fallback.wait(1)
            return connection

        def release_and_signal(connection, **kwargs):
            release(connection, **kwargs)
            if connection is tcp:
                returned.set()

        def quic(*args, **kwargs):
            if not fallback_ready.wait(1):
                raise AssertionError("backup not started")
            return h3

        with (
            patch.object(pool, "borrow_tcp", side_effect=warm),
            patch.object(pool, "release", side_effect=release_and_signal),
            patch("ruyihttp._http3.Connection", side_effect=quic),
            patch.object(_transport, "_ssl_context"),
        ):
            try:
                result = self.adapter._connect_alternative(
                    self.request,
                    route,
                    self.adapter._alt_svc[route],
                    True,
                    Attempt(time.monotonic() + 1),
                    None,
                    pool=pool,
                )
                self.assertIs(result, h3)
            finally:
                allow_fallback.set()
            self.assertTrue(returned.wait(1))
        pool.release(None)
        self.assertEqual(pool.leased, 0)
        self.assertFalse(pool.connecting)
        self.assertEqual(pool.idle, [tcp])
        tcp.close.assert_not_called()
        self.assertIsNotNone(self.adapter._active_alternative(route))

    def test_coalesced_warm_backup_verifies_origin_and_preserves_source_lease(self):
        route = key()
        self.advertise(route)
        pool = self.adapter._pool(route)
        source = self.adapter._pool(key("other.test"))
        h2 = Mock(alpn="h2", multiplexed=True, origin_port=443, coalescing_denied=set())
        h2.h2 = SimpleNamespace(
            received_settings=True,
            origins={(route[1], 443)},
            has_capacity=lambda leased: leased == 0,
        )
        h2.idle.return_value = True
        source.shared[h2] = 0
        dial = Mock(alpn="http/1.1")
        self.assertIsNone(pool.acquire("h3"))
        with (
            patch(
                "ruyihttp._http3.Connection", side_effect=ProtocolError("UDP failed")
            ),
            patch.object(_transport, "_ssl_context"),
            patch.object(self.adapter, "_connect", return_value=dial) as connect,
        ):
            result = self.adapter._connect_alternative(
                self.request,
                route,
                self.adapter._alt_svc[route],
                True,
                Attempt(None),
                None,
                pool=pool,
            )
            self.assertIs(result.connection, h2)
            self.assertIs(result.pool, source)
            self.assertEqual((source.leased, source.shared[h2], pool.leased), (1, 1, 1))
            result.close()
            h2.context.verify.assert_called_once_with(route[1], h2.certificate_chain)
            connect.assert_not_called()
            self.advertise(route, port=9443)
            h2.context.verify.side_effect = ssl.SSLCertVerificationError("wrong origin")
            result = self.adapter._connect_alternative(
                self.request,
                route,
                self.adapter._alt_svc[route],
                True,
                Attempt(None),
                None,
                pool=pool,
            )
            self.assertIs(result, dial)
            connect.assert_called_once()
        pool.release(None)
        self.assertEqual((source.leased, source.shared[h2], pool.leased), (0, 0, 0))
        self.assertFalse(pool.connecting)
