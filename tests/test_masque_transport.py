# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import asyncio
import ipaddress
import socket
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

try:
    import pytest
except ModuleNotFoundError:
    import unittest
    raise unittest.SkipTest('MASQUE fixture tests use pytest; wheel qualification installs it')

from ruyihttp._masque import (
    _MAX_PENDING, MasqueError, Tunnel, _MtuSearch, _Relay, _resolve, _sending_limit,
    _udp_pair, _verify_path, open_tunnel,
)
from ruyihttp._masque_codec import parse_proxy
from requests.exceptions import ConnectTimeout, SSLError


def test_tunnel_owns_private_pair_and_latches_failure_once():
    observed = []
    tunnel = Tunnel(lambda: observed.append(tunnel.error))
    try:
        assert tunnel.socket.getpeername() == tunnel._relay.getsockname()
        assert tunnel._relay.getpeername() == tunnel.socket.getsockname()
        assert tunnel.socket.getblocking() is False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stranger:
            stranger.sendto(b"stray", tunnel.socket.getsockname())
            stranger.sendto(b"stray", tunnel._relay.getsockname())
        for sock in (tunnel.socket, tunnel._relay):
            with pytest.raises(BlockingIOError):
                sock.recv(32)
        error = MasqueError("first error")
        tunnel._fail(error)
        tunnel._fail(MasqueError("second error"))
        assert tunnel.error is error
        assert observed == [error]
    finally:
        tunnel.close()
        tunnel.close()
    assert tunnel.socket.fileno() == tunnel._relay.fileno() == -1


@pytest.mark.parametrize("from_owner", [False, True])
def test_stop_discards_remaining_prepared_udp_packets(from_owner):
    relay = _Relay.__new__(_Relay)
    relay.cancel_event = threading.Event()
    relay.tunnel = SimpleNamespace(_stop=threading.Event())
    stopped = relay.tunnel._stop if from_owner else relay.cancel_event
    sent, builds = [], []

    def build(**_):
        builds.append(True)
        return [(b"first", ()), (b"second", ())]

    class Socket:
        def send(self, data):
            sent.append(data)
            stopped.set()

    relay.connection = SimpleNamespace(datagrams_to_send=build)
    relay._flush(Socket())
    relay._flush(Socket())
    assert sent == [b"first"]
    assert builds == [True]


def test_udp_backpressure_and_oversized_packets_have_bounded_loss():
    sock, peer = _udp_pair()
    try:
        connection = SimpleNamespace(_datagrams_pending=deque())
        relay = object.__new__(_Relay)
        relay.accepted = True
        relay.tunnel = SimpleNamespace(_relay=peer)
        relay.limit = 1252
        relay.request = 0
        relay.connection = connection
        relay.h3 = SimpleNamespace(send_datagram=lambda _id, data: connection._datagrams_pending.append(data))
        sock.send(b"x" * 1253)
        sock.send(b"y" * 1252)
        relay._drain_local()
        assert list(connection._datagrams_pending) == [b"\x00" + b"y" * 1252]
        for _ in range(_MAX_PENDING * 2):
            sock.send(b"z")
            relay._drain_local()
        assert len(connection._datagrams_pending) == _MAX_PENDING
    finally:
        sock.close()
        peer.close()


def test_resolution_uses_only_proxy_name_and_bypasses_literal_dns(monkeypatch):
    lookups = []

    def lookup(host, port, **options):
        lookups.append((host, port, options))
        return [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", port))]

    import time
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    assert _resolve(parse_proxy("masque://proxy.invalid:9443"), time.monotonic() + 5, None) == [
        (socket.AF_INET, ("127.0.0.1", 9443))
    ]
    assert _resolve(parse_proxy("masque://[::1]"), time.monotonic() + 5, None) == [
        (socket.AF_INET6, ("::1", 443, 0, 0))
    ]
    assert lookups == [("proxy.invalid", 9443, {"type": socket.SOCK_DGRAM})]


@pytest.mark.parametrize("value", [False, None, 1, "", b"pem"])
def test_insecure_outer_verification_is_rejected(value):
    with pytest.raises(ValueError, match="proxy_verify"):
        _verify_path(value)


@pytest.mark.parametrize("frame,size,valid", [(1256, 1400, False), (1257, 1400, True),
                                             (65535, 1297, False), (65535, 1298, True)])
def test_remote_packet_limits_must_carry_native_initial(frame, size, valid):
    from enum import IntEnum

    class Setting(IntEnum):
        ENABLE_CONNECT_PROTOCOL = 8
        H3_DATAGRAM = 51

    args = ({8: 1, 51: 1}, Setting, frame, size)
    if valid:
        assert _sending_limit(*args) == (size, 1252)
    else:
        with pytest.raises(MasqueError, match="1252-byte"):
            _sending_limit(*args)
    with pytest.raises(MasqueError, match="H3_DATAGRAM"):
        _sending_limit({8: 1, 51: True}, Setting, frame, size)


def test_mtu_search_ignores_stale_small_and_unrelated_pings():
    search = _MtuSearch(1400, deadline=20)
    high = search.advance(now=1, pto=0.04)
    assert high[1] == 1400
    assert search.acknowledged(1) is None
    assert search.advance(now=1.01, pto=0.04) is None
    search.rejected(high[0])  # e.g. synchronous EMSGSIZE
    medium = search.advance(now=1.01, pto=0.04)
    assert medium[1] == 1360
    assert search.acknowledged(high[0]) is None
    assert search.acknowledged(medium[0]) == 1360
    assert search.advance(now=1.02, pto=0.04) is None
    with pytest.raises(ConnectTimeout, match="acknowledge"):
        search.advance(now=20, pto=0.04)


def _tls_files(directory, *, loopback, right_name, server_usage, issuer_usage):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)

    def issue(label, path_len, *, parent=None, usage=None):
        private = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        issuer, signer = (name, private) if parent is None else (parent[0].subject, parent[1])
        ca = path_len is not None
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(private.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .add_extension(x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False), critical=True)
        )
        if usage is not None:
            cert = cert.add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if usage else ExtendedKeyUsageOID.CLIENT_AUTH,
            ]), critical=True)
        if not ca:
            cert = cert.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(
                loopback if right_name else "127.0.0.2"))]), critical=False)
        return cert.sign(signer, hashes.SHA256()), private

    root = issue("fixed loopback MASQUE test CA", 1)
    issuer = issue("fixed loopback MASQUE test issuer", 0, parent=root, usage=issuer_usage)
    cert, private = issue("fixed loopback MASQUE test peer", None, parent=issuer, usage=server_usage)
    cafile, certfile, keyfile = directory / "root.pem", directory / "proxy.pem", directory / "proxy.key"
    cafile.write_bytes(root[0].public_bytes(serialization.Encoding.PEM))
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + issuer[0].public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    return cafile, certfile, keyfile


def _wire_test(tmp_path, mode):
    pytest.importorskip("aioquic")
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.buffer import Buffer, encode_uint_var
    from aioquic.h3.connection import FrameType, H3Connection, HeadersState, Setting, encode_frame
    from aioquic.h3.events import DatagramReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import HandshakeCompleted, ProtocolNegotiated, StreamReset
    from aioquic.quic.packet import pull_quic_transport_parameters, push_quic_transport_parameters
    from aioquic.tls import CipherSuite

    loopback = "::1" if mode == "ipv6" else "127.0.0.1"
    authority_host = "[::1]" if mode == "ipv6" else loopback
    if mode == "ipv6":
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
                probe.bind((loopback, 0))
        except OSError:
            pytest.skip("IPv6 UDP loopback is unavailable")
    cafile, certfile, keyfile = _tls_files(
        tmp_path, loopback=loopback, right_name=mode != "name", server_usage=mode != "eku",
        issuer_usage=mode != "intermediate-eku",
    )
    wire_ceiling = {"mtu-1330": 1330, "mtu-1300": 1300, "mtu-blackhole": 1297}.get(mode, 1400)
    advertised_ceiling = {"peer-udp": 1308, "peer-udp-small": 1297}.get(mode)
    config = QuicConfiguration(
        is_client=False, alpn_protocols=["doq" if mode == "alpn" else "h3"],
        max_datagram_size=min(wire_ceiling, advertised_ceiling or 1400),
        max_datagram_frame_size=1256 if mode == "small-datagram" else 1400,
    )
    if mode == "cipher":
        config.cipher_suites = [CipherSuite.EMPTY_RENEGOTIATION_INFO_SCSV]
    config.load_cert_chain(certfile, keyfile)
    seen = SimpleNamespace(headers=[], payloads=[], outer_sizes=[], drops=[], handshakes=[], resets=[], tickets=[])

    class H3(H3Connection):
        def _get_local_settings(self):
            settings = super()._get_local_settings()
            if mode == "no-connect":
                settings.pop(Setting.ENABLE_CONNECT_PROTOCOL)
            elif mode == "invalid-connect":
                settings[Setting.ENABLE_CONNECT_PROTOCOL] = 2
            if mode != "no-datagram":
                settings[Setting.H3_DATAGRAM] = 1
            return settings

    class FixedPeer(QuicConnectionProtocol):
        h3 = None

        def __init__(self, connection, **options):
            super().__init__(connection, **options)
            if advertised_ceiling is not None:
                original = connection._serialize_transport_parameters

                def serialize():
                    params = pull_quic_transport_parameters(Buffer(data=original()))
                    params.max_udp_payload_size = advertised_ceiling
                    encoded = Buffer(capacity=2048)
                    push_quic_transport_parameters(encoded, params)
                    return encoded.data

                connection._serialize_transport_parameters = serialize

        def datagram_received(self, data, addr):
            seen.outer_sizes.append(len(data))
            if len(data) > wire_ceiling:
                seen.drops.append(len(data))
                return
            super().datagram_received(data, addr)
            if self._quic._close_event is not None:
                seen.closing.set()

        def quic_event_received(self, event):
            if isinstance(event, ProtocolNegotiated):
                self.h3 = H3(self._quic)
                if mode == "goaway":
                    self._quic.send_stream_data(self.h3._local_control_stream_id, encode_frame(FrameType.GOAWAY, b"\x00"))
            if isinstance(event, HandshakeCompleted):
                seen.handshakes.append(event)
            if isinstance(event, StreamReset):
                seen.resets.append(event.error_code)
            if self.h3 is None:
                return
            for part in self.h3.handle_event(event):
                if isinstance(part, HeadersReceived):
                    seen.headers.append(dict(part.headers))
                    seen.request.set()
                    if mode in ("coalesced", "interim"):
                        self.h3.send_headers(part.stream_id, [(b":status", b"103")])
                        # aioquic 1.3 also conflates interim and final on send.
                        self.h3._stream[part.stream_id].headers_send_state = HeadersState.INITIAL
                    if mode == "interim":
                        asyncio.get_running_loop().call_later(0.12, self.respond, part.stream_id)
                    else:
                        self.respond(part.stream_id)
                elif isinstance(part, DatagramReceived):
                    seen.payloads.append(part.data)
                    if mode == "bad-capsule":
                        self.h3.send_data(part.stream_id, b"\x00\x01\xff", end_stream=False)
                    else:
                        self.h3.send_datagram(part.stream_id, encode_uint_var(33) + b"discard")
                        self.h3.send_datagram(part.stream_id, b"\xff")
                        self.h3.send_data(part.stream_id, b"\x09\x02na\x00\x03\x00", end_stream=False)
                        self.h3.send_data(part.stream_id, b"ok", end_stream=False)
                        self.h3.send_datagram(part.stream_id, b"\x00" + b"d" * 1252)
                    self.transmit()

        def respond(self, stream):
            status = {"deny": b"407", "invalid-status": b"204"}.get(mode, b"200")
            fields = [(b":status", status)]
            if mode == "deny":
                fields += [(b"proxy-authenticate", b'Basic realm="fixture"')]
            if mode == "forbidden-content":
                fields += [(b"content-type", b"application/octet-stream")]
            # No echoed capsule-protocol: RFC 9297 makes that field a SHOULD.
            self.h3.send_headers(stream, fields, end_stream=mode == "deny")
            self.transmit()

    async def run():
        seen.request = asyncio.Event()
        seen.closing = asyncio.Event()
        woke = threading.Event()
        server = await serve(loopback, 0, configuration=config, create_protocol=FixedPeer,
                            session_ticket_handler=seen.tickets.append)
        port = server._transport.get_extra_info("sockname")[1]
        task = asyncio.create_task(asyncio.to_thread(
            open_tunnel, f"masque://unit:p%40ss@{authority_host}:{port}", "unresolved-target.invalid", 443,
            proxy_verify=True if mode == "untrusted" else cafile, timeout=3, on_error=woke.set,
        ))
        try:
            if mode == "interim":
                await asyncio.wait_for(seen.request.wait(), timeout=2)
                assert not task.done()
                assert seen.payloads == []
            expected = {
                "deny": (MasqueError, "407"), "invalid-status": (MasqueError, "successful"),
                "forbidden-content": (MasqueError, "successful"),
                "no-connect": (MasqueError, "ENABLE_CONNECT_PROTOCOL"),
                "no-datagram": (MasqueError, "H3_DATAGRAM"),
                "small-datagram": (MasqueError, "1252-byte"),
                "invalid-connect": (MasqueError, "0x109"), "name": (SSLError, "certificate"),
                "untrusted": (SSLError, "certificate"), "eku": (SSLError, "server authentication"),
                "intermediate-eku": (SSLError, "chain failed TLS server authentication"),
                "alpn": (SSLError, "TLS handshake"), "cipher": (SSLError, "TLS handshake"),
                "goaway": (MasqueError, "GOAWAY"),
                "peer-udp-small": (MasqueError, "1252-byte"),
                "mtu-blackhole": (ConnectTimeout, "acknowledge a probe"),
            }.get(mode)
            if expected:
                with pytest.raises(expected[0], match=expected[1]) as error:
                    await task
                assert seen.payloads == []
                assert b"p@ss" not in str(error.value).encode()
                if mode not in ("deny", "invalid-status", "forbidden-content"):
                    assert seen.headers == []
                if mode == "mtu-blackhole":
                    assert seen.drops == [1400, 1360, 1320, 1298, 1298]
                    assert len(seen.handshakes) == 1
                elif mode == "peer-udp-small":
                    assert max(seen.outer_sizes) <= 1200
                return
            tunnel = await task
            try:
                assert tunnel.error is None
                assert tunnel.info["verified"] is True
                expected_mtu = {"mtu-1330": 1320, "mtu-1300": 1298, "peer-udp": 1308}.get(mode, 1400)
                assert tunnel.info["outer_udp_payload_size"] == expected_mtu
                assert tunnel.info["max_inner_udp_payload_size"] == expected_mtu - 46
                assert expected_mtu in seen.outer_sizes
                assert seen.outer_sizes[0] == 1200
                assert seen.drops == {"mtu-1330": [1400, 1360], "mtu-1300": [1400, 1360, 1320]}.get(mode, [])
                packets_before_data = len(seen.outer_sizes)
                assert len(seen.handshakes) == 1 and not seen.handshakes[0].session_resumed
                assert not seen.handshakes[0].early_data_accepted and seen.tickets == []
                assert seen.headers == [{
                    b":method": b"CONNECT", b":protocol": b"connect-udp", b":scheme": b"https",
                    b":authority": f"{authority_host}:{port}".encode(),
                    b":path": b"/.well-known/masque/udp/unresolved-target.invalid/443/",
                    b"capsule-protocol": b"?1", b"proxy-authorization": b"Basic dW5pdDpwQHNz",
                }]
                tunnel.socket.send(b"x" * 1252)
                if mode == "bad-capsule":
                    assert await asyncio.to_thread(woke.wait, 1)
                    assert isinstance(tunnel.error, MasqueError)
                    assert "Context ID" in str(tunnel.error)
                    await asyncio.sleep(0.03)
                    assert 0x10E in seen.resets
                else:
                    loop = asyncio.get_running_loop()
                    received = {await asyncio.wait_for(loop.sock_recv(tunnel.socket, 1500), 1) for _ in range(2)}
                    assert received == {b"ok", b"d" * 1252}
                assert seen.payloads == [b"\x00" + b"x" * 1252]
                assert max(seen.outer_sizes[packets_before_data:]) <= expected_mtu
            finally:
                tunnel.close()
            assert woke.is_set() == (mode == "bad-capsule")
            await asyncio.wait_for(seen.closing.wait(), timeout=1)
        finally:
            server.close()

    asyncio.run(run())


@pytest.mark.parametrize("mode", [
    "ok", "coalesced", "interim", "bad-capsule", "deny", "invalid-status", "forbidden-content",
    "no-connect", "no-datagram", "small-datagram", "invalid-connect", "name", "untrusted", "eku",
    "intermediate-eku", "alpn", "cipher",
    "goaway", "ipv6", "mtu-1330", "mtu-1300", "mtu-blackhole", "peer-udp", "peer-udp-small",
])
def test_real_loopback_outer_h3(mode, tmp_path):
    _wire_test(tmp_path, mode)


def test_cancel_and_deadline_close_worker():
    pytest.importorskip("aioquic")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
        sink.bind(("127.0.0.1", 0))
        url = f"masque://127.0.0.1:{sink.getsockname()[1]}"
        with pytest.raises(ConnectTimeout, match="deadline"):
            open_tunnel(url, "remote.invalid", 443, proxy_verify=True, timeout=0.08)
        cancelled = threading.Event()
        timer = threading.Timer(0.04, cancelled.set)
        timer.start()
        try:
            with pytest.raises(MasqueError, match="cancelled"):
                open_tunnel(url, "remote.invalid", 443, proxy_verify=True, timeout=3, cancel_event=cancelled)
        finally:
            timer.join()
    assert not any(thread.name == "ruyihttp-masque-outer" for thread in threading.enumerate())
