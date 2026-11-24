# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from requests.exceptions import ConnectionError, ConnectTimeout

from ruyihttp._connect import Attempt, connect_tcp
from ruyihttp._transport import _NativeSocket


def record(address, scope=0):
    if ":" in address:
        return socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 443, 0, scope)
    return socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)


class TcpDialTests(unittest.TestCase):
    def test_stalled_first_family_loses_and_late_socket_is_closed(self):
        primary_started = threading.Event()
        loser_closed = threading.Event()
        winner_interrupted = threading.Event()
        winner_closed = threading.Event()
        calls = []
        winner = SimpleNamespace(close=winner_closed.set)

        def open_socket(address, limit, attempt):
            calls.append(address)
            if address == "::1":
                primary_started.set()
                if not attempt.cancelled.wait(2):
                    raise AssertionError("the losing dial was not cancelled")
                return SimpleNamespace(close=loser_closed.set)
            if not primary_started.wait(2):
                raise AssertionError("the first resolver family did not start")
            self.assertGreater(limit, 0)
            attempt.set_interrupt(winner_interrupted.set)
            return winner

        with patch(
            "ruyihttp._connect.socket.getaddrinfo",
            return_value=[record("::1"), record("127.0.0.1")],
        ) as resolver:
            result = connect_tcp(
                "dual.test", 443, Attempt(time.monotonic() + 2), open_socket
            )
        self.assertIs(result, winner)
        self.assertEqual(calls, ["::1", "127.0.0.1"])
        resolver.assert_called_once_with("dual.test", 443, type=socket.SOCK_STREAM)
        self.assertTrue(loser_closed.wait(1), "late success was not closed")
        self.assertFalse(winner_interrupted.is_set(), "winner was interrupted")
        self.assertFalse(winner_closed.is_set(), "winner was closed")

    def test_numeric_addresses_bypass_dns(self):
        def open_socket(address, _limit, attempt):
            self.assertIsNone(attempt.remaining())
            return address

        with patch("ruyihttp._connect.socket.getaddrinfo") as resolver:
            for host in ("127.0.0.1", "::1", "fe80::1%7"):
                with self.subTest(host=host):
                    self.assertEqual(
                        connect_tcp(host, 443, Attempt(None), open_socket), host
                    )
        resolver.assert_not_called()

    def test_cancelled_parent_releases_both_family_workers(self):
        ready = [threading.Event(), threading.Event()]
        closed = [threading.Event(), threading.Event()]
        attempt = Attempt(None)
        errors = []

        def open_socket(address, _limit, lane):
            index = 0 if address == "::1" else 1
            ready[index].set()
            if not lane.cancelled.wait(2):
                raise AssertionError("parent cancellation did not reach the worker")
            return SimpleNamespace(close=closed[index].set)

        def run():
            try:
                connect_tcp("dual.test", 443, attempt, open_socket)
            except Exception as error:
                errors.append(error)

        with patch(
            "ruyihttp._connect.socket.getaddrinfo",
            return_value=[record("::1"), record("127.0.0.1")],
        ):
            driver = threading.Thread(target=run, daemon=True)
            driver.start()
            try:
                self.assertTrue(all(event.wait(1) for event in ready))
            finally:
                attempt.cancel()
                driver.join(1)
        self.assertFalse(driver.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertRegex(str(errors[0]), "cancelled")
        self.assertTrue(all(event.wait(1) for event in closed))

    def test_one_deadline_even_when_dns_is_stalled(self):
        entered = threading.Event()
        release = threading.Event()
        exited = threading.Event()

        def blocked_resolve(*_args, **_kwargs):
            entered.set()
            try:
                release.wait(2)
                return [record("127.0.0.1")]
            finally:
                exited.set()

        start = time.monotonic()
        try:
            with patch(
                "ruyihttp._connect.socket.getaddrinfo", side_effect=blocked_resolve
            ):
                with self.assertRaises(ConnectTimeout):
                    connect_tcp("dual.test", 443, Attempt(start + 0.1), self.fail)
            elapsed = time.monotonic() - start
            self.assertTrue(entered.is_set())
            self.assertLess(elapsed, 0.5)
        finally:
            release.set()
            self.assertTrue(exited.wait(1))

    def test_saturated_resolver_slots_respect_deadline_without_more_workers(self):
        entered = threading.Event()
        release = threading.Event()
        exited = threading.Event()

        def blocked_resolve(*_args, **_kwargs):
            entered.set()
            try:
                release.wait(2)
                return [record("127.0.0.1")]
            finally:
                exited.set()

        with (
            patch("ruyihttp._connect._DNS_SLOTS", threading.BoundedSemaphore(1)),
            patch(
                "ruyihttp._connect.socket.getaddrinfo", side_effect=blocked_resolve
            ) as resolver,
        ):
            try:
                for host in ("first.test", "second.test"):
                    with self.assertRaises(ConnectTimeout):
                        connect_tcp(
                            host, 443, Attempt(time.monotonic() + 0.1), self.fail
                        )
                    self.assertTrue(entered.is_set())
                resolver.assert_called_once_with(
                    "first.test", 443, type=socket.SOCK_STREAM
                )
            finally:
                release.set()
                self.assertTrue(exited.wait(1))

    def test_same_family_deduplicates_and_reserves_time_for_later_addresses(self):
        records = [record("fe80::1", 7), record("fe80::1", 7), record("::1")]
        calls = []
        winner = object()

        def open_socket(address, limit, attempt):
            calls.append((address, limit))
            if address != "::1":
                self.assertLess(limit, 0.55)
                raise ConnectTimeout("controlled address timeout")
            self.assertGreater(attempt.remaining(), 0)
            return winner

        with patch("ruyihttp._connect.socket.getaddrinfo", return_value=records):
            result = connect_tcp(
                "dual.test", 443, Attempt(time.monotonic() + 1), open_socket
            )
        self.assertIs(result, winner)
        self.assertEqual([address for address, _ in calls], ["fe80::1%7", "::1"])

    def test_null_handle_is_a_connect_error_before_peer_lookup(self):
        def null_open(*_args):
            return 0

        library = SimpleNamespace(
            necko_socket_open=null_open,
            necko_socket_open_cancellable=null_open,
            necko_socket_peer=lambda *_: self.fail("peer lookup on null pointer"),
        )
        for attempt in (None, Attempt(None)):
            with self.subTest(cancellable=attempt is not None):
                with self.assertRaisesRegex(
                    ConnectionError, "returned a null handle"
                ) as result:
                    _NativeSocket(library, "127.0.0.1", 443, 1, attempt)
                self.assertTrue(result.exception._necko_connect)
