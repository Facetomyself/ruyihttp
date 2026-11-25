"""Loopback installed-wheel check: an optional H2 reuse probe shares the dial deadline."""

import socket
import tempfile
import threading
import time
from unittest.mock import patch

import ruyihttp
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived
from requests.exceptions import ConnectTimeout, SSLError

from smoke_proxy_chain import listener, tls_fixtures


def main():
    names = ("first.invalid", "also-valid.invalid", "invalid-cert.invalid")
    hits = []
    accepted = []
    controls = []
    entered, release, exited = threading.Event(), threading.Event(), threading.Event()
    real_lookup = socket.getaddrinfo
    stall = False

    def resolve(host, port, *args, **kwargs):
        if host not in names:
            return real_lookup(host, port, *args, **kwargs)
        controls.append((host, threading.current_thread().name))
        if stall:
            entered.set()
            try:
                # The HTTP call must return while this resolver is still blocked.
                release.wait(3)
            finally:
                exited.set()
        return real_lookup("127.0.0.1", port, *args, **kwargs)

    def serve(peer):
        assert peer.selected_alpn_protocol() == "h2"
        accepted.append(1)
        wire = H2Connection(config=H2Configuration(client_side=False))
        wire.initiate_connection()
        peer.sendall(wire.data_to_send())
        while data := peer.recv(16384):
            for event in wire.receive_data(data):
                if isinstance(event, RequestReceived):
                    authority = dict(event.headers)[b":authority"]
                    hits.append(authority.split(b":")[0].decode("ascii"))
                    wire.send_headers(
                        event.stream_id,
                        [(b":status", b"200"), (b"content-length", b"2")],
                    )
                    wire.send_data(event.stream_id, b"ok", end_stream=True)
            peer.sendall(wire.data_to_send())

    with tempfile.TemporaryDirectory() as directory:
        ca, _, tls, _ = tls_fixtures(
            directory, origin_san="DNS:first.invalid,DNS:also-valid.invalid"
        )
        tls.set_alpn_protocols(["h2"])
        with (
            listener(serve, tls) as (_, port),
            ruyihttp.Session(verify=str(ca)) as s,
            patch("socket.getaddrinfo", resolve),
        ):
            s.trust_env = False

            def fetch(name, budget=2):
                return s.get(
                    f"https://{name}:{port}/",
                    timeout=(budget, 2),
                    allow_redirects=False,
                )

            first = fetch(names[0])
            assert (first.status_code, first.content, first.raw.version) == (
                200,
                b"ok",
                20,
            )
            stall = True
            start = time.monotonic()
            try:
                try:
                    fetch(names[1], 0.12)
                except ConnectTimeout:
                    assert entered.is_set() and not exited.is_set(), (
                        "caller waited for libc resolver"
                    )
                else:
                    raise AssertionError("coalescing bypassed connect timeout")
                elapsed = time.monotonic() - start
                assert elapsed < 1.5 and hits == [names[0]], (elapsed, hits)
                print(
                    f"Blocked DNS: connect budget 0.12s, elapsed {elapsed:.3f}s, target HTTP requests=0",
                    flush=True,
                )
            finally:
                release.set()
                assert exited.wait(3)
            stall = False
            controls.clear()
            shared = fetch(names[1])
            assert (shared.status_code, shared.content, shared.raw.version) == (
                200,
                b"ok",
                20,
            )
            assert (
                shared._necko_coalesced
                and len(accepted) == 1
                and hits == list(names[:2])
            ), (accepted, hits)
            assert len(controls) == 1 and controls[0][0] == names[1], controls
            controls.clear()
            try:
                fetch(names[2])
            except SSLError:
                pass
            else:
                raise AssertionError(
                    "different hostname coalesced despite mismatched SAN"
                )
            assert (
                len(controls) == 1
                and controls[0][0] == names[2]
                and names[2] not in hits
            ), (hits, controls)
            print(
                "PASS: matching SAN reused verified H2, mismatched SAN rejected; one DNS answer per target",
                flush=True,
            )


if __name__ == "__main__":
    main()
