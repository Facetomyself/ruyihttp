"""The explicit MASQUE route is a pool, credential and redirect boundary."""

import importlib
import os
from pathlib import Path
import pickle
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from requests import Request, Response
from requests.adapters import BaseAdapter
from requests.exceptions import InvalidSchema, ProxyError, SSLError

from ruyihttp import Session
from ruyihttp._transport import HTTPAdapter, is_masque_proxy, masque_route_id


class MasqueRouteTests(unittest.TestCase):
    @staticmethod
    def req(url="https://origin.invalid/item"):
        return Request("GET", url).prepare()

    def test_only_explicit_route_and_redacted_partition(self):
        p = "masque://fixture:private@proxy.invalid:8443"
        self.assertTrue(is_masque_proxy(p))
        self.assertTrue(is_masque_proxy("MASQUE://a"))
        for other in (
            "https://proxy.invalid",
            "http://proxy.invalid",
            "socks5h://proxy.invalid",
            None,
        ):
            self.assertFalse(is_masque_proxy(other))
        ids = [
            masque_route_id(p),
            masque_route_id(p, "True"),
            masque_route_id(p, True, "/custom/{target_host}/{target_port}"),
            masque_route_id(p.replace("private", "changed")),
        ]
        self.assertEqual(len(set(ids)), 4)
        self.assertTrue(all(isinstance(x, bytes) and len(x) == 32 for x in ids))
        self.assertEqual(
            masque_route_id(p, "local-CA"),
            masque_route_id(p, Path("local-CA").absolute()),
        )
        for trust in (None, False, 1, b"bytes", ""):
            with self.subTest(trust=trust), self.assertRaises(ValueError):
                masque_route_id(p, trust)

    def test_selected_route_never_calls_normal_tcp_dial_or_alt_svc(self):
        p = "masque://user:special-fixture@proxy.invalid:8443"
        a = HTTPAdapter()
        req = self.req()
        with (
            patch.object(
                a, "_connect_masque", side_effect=ProxyError("upstream status 407")
            ) as relay,
            patch.object(a, "_connect") as tcp,
            patch.object(a, "_coalesce") as pool_scan,
            patch.object(a, "_active_alternative") as alt,
        ):
            for ca in (True, Path("other-ca")):
                with self.assertRaisesRegex(ProxyError, "407"):
                    a.send(req, proxies={"https": p}, proxy_verify=ca, timeout=1)
            self.assertEqual(relay.call_count, 2)
            tcp.assert_not_called()
            pool_scan.assert_not_called()
            alt.assert_not_called()
            self.assertEqual(len(a._pools), 2)
            self.assertNotIn("special-fixture", repr(a._pools))
            self.assertTrue(
                all(
                    pool.leased == 0 and not pool.connecting
                    for pool in a._pools.values()
                )
            )
        a.close()

    def test_proxy_unusable_before_any_network_io(self):
        a = HTTPAdapter()
        p = {"all": "masque://proxy.invalid"}
        with patch.object(a, "_pool") as pool:
            for req, opts, exc in [
                (self.req("http://origin.invalid/"), {}, ProxyError),
                (self.req(), {"verify": False}, SSLError),
                (self.req(), {"cert": "identity.pem"}, InvalidSchema),
                (self.req(), {"proxy_verify": False}, ValueError),
            ]:
                with self.subTest(opts=opts), self.assertRaises(exc):
                    a.send(req, proxies=p, **opts)
            pool.assert_not_called()
        a.close()

    def test_redirect_route_cannot_be_downgraded_or_changed(self):
        p = "masque://proxy.invalid:9443"
        tpl = "/custom/{target_host}/{target_port}"
        with Session(proxy_verify="proxy-root.pem", masque_path_template=tpl) as s:
            s.trust_env = False
            original = Response()
            original.request = self.req()
            original._ruyi_masque_route = masque_route_id(p, "proxy-root.pem", tpl)
            for url, proxies in [
                ("http://origin.invalid/next", {"https": p}),
                ("https://other.invalid/next", {}),
                ("https://other.invalid/next", {"https": "masque://another.invalid"}),
            ]:
                redirect = self.req(url)
                redirect.headers["Proxy-Authorization"] = "never-forward"
                s.rebuild_auth(redirect, original)
                self.assertNotIn("Proxy-Authorization", redirect.headers)
                with (
                    patch.object(HTTPAdapter, "send") as dial,
                    self.assertRaisesRegex(ProxyError, "leave"),
                ):
                    s.send(redirect, proxies=proxies)
                dial.assert_not_called()
            same = self.req("https://other.invalid/next")
            s.rebuild_auth(same, original)
            with (
                patch.object(HTTPAdapter, "send") as dial,
                self.assertRaisesRegex(ProxyError, "leave"),
            ):
                s.send(same, proxies={"https": p}, proxy_verify="different-root.pem")
            dial.assert_not_called()
            with (
                patch.object(
                    HTTPAdapter,
                    "send",
                    side_effect=ProxyError("expected selected route"),
                ) as dial,
                self.assertRaisesRegex(ProxyError, "expected selected route"),
            ):
                s.send(same, proxies={"https": p})
            self.assertEqual(dial.call_args.kwargs["masque_path_template"], tpl)
            self.assertEqual(dial.call_args.kwargs["proxy_verify"], "proxy-root.pem")

    def test_unrelated_custom_adapter_does_not_receive_masque_keywords(self):
        class Custom(BaseAdapter):
            def send(
                self,
                request,
                stream=False,
                timeout=None,
                verify=True,
                cert=None,
                proxies=None,
            ):
                rep = Response()
                rep.status_code = 200
                rep._content = b"ok"
                rep.request = request
                rep.url = request.url
                return rep

            def close(self):
                pass

        with Session(proxy_verify="unrelated.pem") as s:
            s.trust_env = False
            s.mount("https://", Custom())
            self.assertEqual(s.get("https://origin.invalid").status_code, 200)
            with self.assertRaisesRegex(ProxyError, "adapter"):
                s.get(
                    "https://origin.invalid",
                    proxies={"https": "masque://relay.invalid"},
                )

    def test_explicit_session_route_wins_over_environment_in_get_and_send(self):
        from requests.utils import select_proxy

        url = "https://origin.invalid/test"
        udp, tcp = "masque://fixture.invalid:8443", "https://environment.invalid:8443"
        with (
            patch.dict(
                os.environ,
                {
                    "https_proxy": tcp,
                    "HTTPS_PROXY": tcp,
                    "NO_PROXY": "",
                    "no_proxy": "",
                },
            ),
            Session(verify="origin-only.pem") as s,
        ):
            for key in ("all", "https", "https://origin.invalid"):
                s.proxies = {key: udp}
                with patch(
                    "requests.sessions.get_environ_proxies",
                    side_effect=AssertionError("origin used system proxy discovery"),
                ):
                    result = s.merge_environment_settings(url, {}, None, None, None)
                    self.assertEqual(select_proxy(url, result["proxies"]), udp)
                    self.assertEqual(result["verify"], "origin-only.pem")
                    with (
                        patch.object(
                            HTTPAdapter,
                            "send",
                            side_effect=ProxyError("stop before dial"),
                        ) as dial,
                        self.assertRaises(ProxyError),
                    ):
                        s.send(self.req(url))
                    self.assertEqual(
                        select_proxy(url, dial.call_args.kwargs["proxies"]), udp
                    )
                    self.assertEqual(
                        select_proxy(
                            url, s.rebuild_proxies(self.req(url), result["proxies"])
                        ),
                        udp,
                    )
            s.proxies = {"https": udp}
            self.assertEqual(
                select_proxy(
                    url,
                    s.merge_environment_settings(url, {"https": tcp}, None, None, None)[
                        "proxies"
                    ],
                ),
                tcp,
            )

    def test_interrupted_connect_releases_reservation(self):
        a = HTTPAdapter()
        opts = {"proxies": {"https": "masque://proxy.invalid"}, "timeout": 0.1}
        with (
            patch.object(a, "_connect_masque", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            a.send(self.req(), **opts)
        (pool,) = a._pools.values()
        self.assertEqual((pool.leased, pool.connecting), (0, False))
        with (
            patch.object(
                a, "_connect_masque", side_effect=ProxyError("fresh dial")
            ) as dial,
            self.assertRaisesRegex(ProxyError, "fresh dial"),
        ):
            a.send(self.req(), **opts)
        dial.assert_called_once()
        a.close()

    def test_pool_observes_latched_tunnel_error_before_native_owner_wakes(self):
        from ruyihttp._http3 import Connection
        from ruyihttp._transport import _Pool

        pool = _Pool(2, False)
        self.assertIsNone(pool.acquire("h3"))
        c = Connection.__new__(Connection)
        c._tunnel = SimpleNamespace(error=None)
        c.closed = c.goaway = False
        stop = Event()
        c.close = stop.set
        pool.register(c)
        pool.release(c)
        c._tunnel.error = ProxyError("outer connection retired")
        self.assertIsNone(pool.acquire("h3"))
        self.assertTrue(stop.is_set())
        pool.release(None)
        pool.close()

    def test_api_options_do_not_change_default_direct_behavior(self):
        with Session(
            proxy_verify="outer.pem",
            masque_path_template="/udp/{target_host}/{target_port}",
        ) as s:
            restored = pickle.loads(pickle.dumps(s))
            try:
                self.assertEqual(restored.proxy_verify, "outer.pem")
                self.assertEqual(restored.masque_path_template, s.masque_path_template)
            finally:
                restored.close()
        module = importlib.import_module("ruyihttp.api")
        with patch.object(module.sessions, "Session") as ctor:
            module.get(
                "https://origin.invalid",
                firefox="160",
                proxy_verify="proxy.pem",
                masque_path_template="/udp/{target_host}/{target_port}",
            )
            self.assertEqual(ctor.call_args.kwargs["proxy_verify"], "proxy.pem")
            self.assertEqual(ctor.call_args.kwargs["firefox"], "160")
