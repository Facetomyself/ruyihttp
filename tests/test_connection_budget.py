"""A request attempt has one connect budget, including optional pool coalescing."""

import socket
import ssl
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from requests import Request
from requests.exceptions import ConnectionError, ConnectTimeout

from ruyihttp._connect import Attempt
from ruyihttp._transport import HTTPAdapter


def key(host, port=None):
    return ("https", host, port, None, "True", "None", False)


class ConnectionBudgetTests(unittest.TestCase):
    def setUp(self):
        self.adapter = HTTPAdapter()
        # The socket factory is intercepted before any native I/O.
        self.adapter._library = object()
        self.addCleanup(self.adapter.close)
        self.request = Request("GET", "https://target.test/").prepare()

    def send(self, budget):
        return self.adapter._send_once(
            self.request, False, (budget, 5), True, None, None
        )

    def shared_h2(self, *, port=443, origins=None, address="127.0.0.1"):
        candidate = Mock(
            alpn="h2",
            origin_port=port,
            peer_address=address,
            coalescing_denied=set(),
            certificate_chain=b"fixture",
        )
        candidate.h2 = SimpleNamespace(received_settings=True, origins=origins)
        candidate.idle.return_value = True
        self.adapter._pool(key("other.test")).shared[candidate] = 0
        return candidate

    def assert_released(self):
        pool = self.adapter._pool(key("target.test"))
        self.assertEqual(pool.leased, 0)
        self.assertFalse(pool.connecting)

    def test_an_empty_pool_never_triggers_speculative_dns(self):
        self.adapter._pool(key("closed-origin.test"))
        with (
            patch(
                "socket.getaddrinfo",
                side_effect=AssertionError("unexpected coalescing lookup"),
            ),
            patch.object(self.adapter, "_connect", side_effect=ConnectionError("dial")),
        ):
            with self.assertRaisesRegex(ConnectionError, "dial"):
                self.send(1)
        self.assert_released()

    def test_wrong_port_is_not_a_candidate_for_dns(self):
        self.shared_h2(port=8443)
        with (
            patch(
                "socket.getaddrinfo",
                side_effect=AssertionError("unexpected coalescing lookup"),
            ),
            patch.object(self.adapter, "_connect", side_effect=ConnectionError("dial")),
        ):
            with self.assertRaisesRegex(ConnectionError, "dial"):
                self.send(1)
        self.assert_released()

    def test_authorized_origin_frame_skips_dns_but_still_checks_certificate(self):
        c = self.shared_h2(origins={("target.test", 443)})
        key_ = key("target.test")
        pool = self.adapter._pool(key_)
        with patch(
            "socket.getaddrinfo", side_effect=AssertionError("unnecessary lookup")
        ):
            source, transport, answers = self.adapter._coalesce(
                pool, key_, None, True, Attempt(None)
            )
        self.assertIs(transport, c)
        self.assertIsNone(answers)
        c.context.verify.assert_called_once_with("target.test", b"fixture")
        source.release(transport)
        self.assertEqual(source.leased, 0)

    def test_dns_failure_is_reported_once_and_returns_origin_lease(self):
        self.shared_h2()
        with (
            patch(
                "socket.getaddrinfo",
                side_effect=socket.gaierror("controlled DNS failure"),
            ) as dns,
            patch.object(self.adapter, "_connect") as dial,
        ):
            with self.assertRaisesRegex(
                ConnectionError, "Could not resolve target.test"
            ) as failure:
                self.send(1)
        self.assertTrue(failure.exception._necko_connect)
        dns.assert_called_once()
        dial.assert_not_called()
        self.assert_released()

    def test_alt_svc_dns_uses_remaining_deadline_and_bounded_worker(self):
        entered, release, exited = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )

        def blocked(*_args, **_kwargs):
            entered.set()
            try:
                release.wait(3)
                return []
            finally:
                exited.set()

        with (
            patch("socket.getaddrinfo", side_effect=blocked) as resolver,
            patch.object(
                self.adapter, "_connect", side_effect=ConnectionError("TCP unavailable")
            ),
        ):
            try:
                budget = Attempt(time.monotonic() + 0.25)
                with self.assertRaises(ConnectTimeout):
                    self.adapter._connect_alternative(
                        self.request,
                        key("target.test"),
                        (("alt.test", 8443), 0),
                        True,
                        budget,
                        None,
                    )
                self.assertTrue(entered.is_set())
                self.assertFalse(exited.is_set())
                resolver.assert_called_once_with(
                    "alt.test", 8443, type=socket.SOCK_DGRAM
                )
            finally:
                release.set()
                self.assertTrue(exited.wait(1))

    def test_dial_reuses_dns_result_and_only_the_remaining_time(self):
        c = self.shared_h2()
        c.context.verify.side_effect = ssl.SSLCertVerificationError(
            "not valid for target"
        )
        lookup_threads = []

        def resolve(host, port, **kwargs):
            lookup_threads.append(threading.current_thread())
            time.sleep(0.06)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        with (
            patch("socket.getaddrinfo", side_effect=resolve) as dns,
            patch(
                "ruyihttp._transport._NativeSocket",
                side_effect=ConnectionError("numeric dial"),
            ) as dial,
        ):
            with self.assertRaisesRegex(ConnectionError, "numeric dial"):
                self.send(2)
        c.context.verify.assert_called_once_with("target.test", b"fixture")
        self.assertEqual(dns.call_count, 1)
        self.assertNotIn(threading.current_thread(), lookup_threads)
        _, address, port, remaining, _ = dial.call_args.args
        self.assertEqual((address, port), ("127.0.0.1", 443))
        self.assertLess(remaining, 1.96)
        self.assert_released()

    def test_coalescing_lookup_times_out_and_returns_lease_before_dns_completes(self):
        self.shared_h2()
        entered, release, exited = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        outcome = []

        def resolve(*_args, **_kwargs):
            entered.set()
            try:
                release.wait(2)
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.2", 443))]
            finally:
                exited.set()

        def send():
            try:
                self.send(0.08)
            except Exception as exc:
                outcome.append(exc)

        with (
            patch("socket.getaddrinfo", side_effect=resolve),
            patch.object(
                self.adapter,
                "_connect",
                side_effect=AssertionError("dial after deadline"),
            ) as dial,
        ):
            worker = threading.Thread(target=send, daemon=True)
            try:
                worker.start()
                self.assertTrue(entered.wait(1))
                worker.join(0.65)
                self.assertFalse(worker.is_alive(), "waiting for unbounded DNS")
                self.assertEqual(len(outcome), 1)
                self.assertIsInstance(outcome[0], ConnectTimeout)
                self.assert_released()
                dial.assert_not_called()
            finally:
                release.set()
                worker.join(2)
                self.assertTrue(exited.wait(1))

    def test_pool_wait_is_bounded_without_stealing_first_lease(self):
        pool = self.adapter._pool(key("target.test"))
        self.assertIsNone(pool.acquire())
        outcome = []

        def send():
            try:
                self.send(0.08)
            except Exception as exc:
                outcome.append(exc)

        with patch.object(
            self.adapter, "_connect", side_effect=AssertionError("unexpected dial")
        ):
            worker = threading.Thread(target=send, daemon=True)
            try:
                worker.start()
                worker.join(0.65)
                self.assertFalse(
                    worker.is_alive(),
                    "waiting indefinitely behind a connecting request",
                )
                self.assertEqual(len(outcome), 1)
                self.assertIsInstance(outcome[0], ConnectTimeout)
                self.assertTrue(pool.connecting)
                self.assertEqual(pool.leased, 1)
            finally:
                pool.release(None)
                worker.join(2)
        self.assert_released()
