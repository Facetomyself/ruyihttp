"""The explicit MASQUE route is a pool, credential and redirect boundary."""

import importlib
from pathlib import Path
import pickle
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
