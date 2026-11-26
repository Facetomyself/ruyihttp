#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Installed-wheel RFC 9298 wire gate; run with Python -I and aioquic==1.3.0.

The independent QUIC/H3 peers listen on loopback. The relay implements only a
single authenticated CONNECT-UDP tunnel to one synthetic name at one fixed UDP
endpoint. Its egress socket is connected to that address and is never created
from request data. The UDP-only H3 origin accepts only that socket as its peer.
The companion TCP canary logs and closes TCP contacts; it serves no HTTP/TLS.
"""

import argparse
import asyncio
import base64
import builtins
import contextlib
import hashlib
import importlib.metadata
import ipaddress
import json
import platform
import secrets
import socket
import ssl
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, urlsplit
from urllib.request import url2pathname

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.asyncio.server import QuicServer
from aioquic.buffer import Buffer, BufferReadError, encode_uint_var
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import DataReceived, DatagramReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated, DatagramFrameReceived, HandshakeCompleted,
    ProtocolNegotiated, StopSendingReceived, StreamReset,
)
from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion, pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LOOP = "127.0.0.1"
ORIGIN = "h3-origin.invalid"
WRONG_ORIGIN = "wrong-origin.invalid"
AUTH_USER = "fixture"
AUTH_PASSWORD = f"relay-only:{secrets.token_hex(8)}@local"
AUTH = b"Basic " + base64.b64encode(f"{AUTH_USER}:{AUTH_PASSWORD}".encode("ascii"))
URL_AUTH = f"{AUTH_USER}:{quote(AUTH_PASSWORD, safe='')}@"
OUTER_PACKET_SIZE = 1472  # >= 1252 bytes of inner Firefox UDP plus outer overhead
FIREFOX = "161"
DOWNLOAD = hashlib.shake_256(b"ruyihttp/masque/dl/v1").digest(256 * 1024)
UPLOAD = hashlib.shake_256(b"ruyihttp/masque/up/v1").digest(256 * 1024)
SMALL = b"h3-via-relay"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check(condition, *details):
    if not condition:
        raise AssertionError(" ".join(map(repr, details)))


def target_path(port):
    return f"/.well-known/masque/udp/{ORIGIN}/{port}/".encode("ascii")


def issue(directory, prefix, san):
    """Return PEM paths and leaf fingerprint; distinct ECDSA CA per boundary."""
    now = datetime.now(timezone.utc)

    def builder(subject, issuer, key):
        return (
            x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
        )

    def name(label):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = name(f"MASQUE smoke {prefix} test root")
    root = (
        builder(root_name, root_name, root_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), False)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    def leaf(label, subject_alt_name):
        cert = (
            builder(name(label), root_name, leaf_key)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([subject_alt_name]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
            .sign(root_key, hashes.SHA256())
        )
        leaf_path = directory / f"{prefix}-{label}.pem"
        leaf_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return leaf_path, sha256(cert.public_bytes(serialization.Encoding.DER))

    root_path = directory / f"{prefix}-root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    key_path = directory / f"{prefix}-leaf.key"
    key_path.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    return {
        "root": root_path, "key": key_path,
        "good": leaf("right", san), "wrong": leaf("wrong", x509.DNSName(WRONG_ORIGIN)),
    }


def certs(directory):
    return (
        issue(directory, "origin", x509.DNSName(ORIGIN)),
        issue(directory, "relay", x509.IPAddress(ipaddress.ip_address(LOOP))),
    )


class Traffic:
    def __init__(self):
        self.count = self.octets = self.maximum = 0
        self._digest = hashlib.sha256()

    def observe(self, payload):
        self.count += 1
        self.octets += len(payload)
        self.maximum = max(len(payload), self.maximum)
        self._digest.update(len(payload).to_bytes(4, "big"))
        self._digest.update(payload)

    def receipt(self):
        return {
            "packets": self.count, "bytes": self.octets, "max_packet": self.maximum,
            "framed_sha256": self._digest.hexdigest(),
        }


class DatagramH3(H3Connection):
    """Advertise RFC 9297 without enabling the aioquic WebTransport extension."""
    def __init__(self, quic, *, extended=True, datagrams=True):
        self.extended = extended
        self.datagrams = datagrams
        super().__init__(quic)

    def _get_local_settings(self):
        settings = super()._get_local_settings()
        if not self.extended:
            settings.pop(Setting.ENABLE_CONNECT_PROTOCOL, None)
        if self.datagrams:
            settings[Setting.H3_DATAGRAM] = 1
        return settings


class GuardedOrigin(QuicServer):
    def __init__(self, *args, state, **kwargs):
        self.state = state
        super().__init__(*args, **kwargs)

    def datagram_received(self, data, addr):
        if addr != self.state.egress_address:
            self.state.rejected_udp.append(addr)
            return
        self.state.origin_peers.add(addr)
        self.state.ingress.observe(data)
        if self.state.initial is None:
            header = pull_quic_header(Buffer(data=data), host_cid_length=self._configuration.connection_id_length)
            check(header.packet_type == QuicPacketType.INITIAL, header)
            self.state.initial = {"udp_bytes": len(data), "version": int(header.version), "scid_bytes": len(header.source_cid)}
        super().datagram_received(data, addr)


class OriginProtocol(QuicConnectionProtocol):
    def __init__(self, *args, state, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.connection_number = state.origin_connections
        state.origin_connections += 1
        self.http = None
        self.requests = {}
        self.finished = set()
        self.concurrent = {}

    def quic_event_received(self, event):
        state = self.state
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if isinstance(event, HandshakeCompleted):
            state.origin_tls.append({"alpn": event.alpn_protocol, "quic_version": int(self._quic._version)})
        if isinstance(event, (StopSendingReceived, StreamReset)):
            state.origin_cancelled.append((type(event).__name__, self.connection_number, event.stream_id))
        if self.http is None:
            return
        for message in self.http.handle_event(event):
            stream = message.stream_id
            if stream in self.finished and isinstance(message, DataReceived) and not message.data:
                continue
            if isinstance(message, HeadersReceived):
                check(stream not in self.requests and stream not in self.finished, "duplicate origin HEADERS", stream)
                headers = dict(message.headers)
                self.requests[stream] = (headers, bytearray())
                state.origin_headers.append({
                    "connection": self.connection_number, "stream": stream,
                    "method": headers[b":method"].decode("ascii"),
                    "path": headers[b":path"].decode("ascii"),
                    "authority": headers[b":authority"].decode("ascii"),
                    "proxy_credentials_present": b"proxy-authorization" in headers,
                    "origin_authorization": headers.get(b"authorization", b"").decode("ascii"),
                    "user_agent": headers.get(b"user-agent", b"").decode("ascii"),
                })
            elif isinstance(message, DataReceived):
                received = self.requests[stream][1]
                check(len(received) + len(message.data) <= len(UPLOAD), "unexpected large origin upload")
                received.extend(message.data)
            else:
                continue
            if message.stream_ended:
                self.finished.add(stream)
                headers, uploaded = self.requests.pop(stream)
                state.origin_bodies.append({"stream": stream, "bytes": len(uploaded), "sha256": sha256(uploaded)})
                self._respond(stream, headers[b":path"], uploaded)
        if self.http.received_settings is not None:
            state.origin_settings = {str(int(k)): v for k, v in self.http.received_settings.items()}

    def _respond(self, stream, path, uploaded):
        status = b"200"
        headers = [(b"x-wire-origin", b"udp-only")]
        if path == b"/download":
            body = DOWNLOAD
        elif path == b"/upload":
            body = bytes(uploaded)
        elif path == b"/cancel":
            self.http.send_headers(stream, [(b":status", b"200"), *headers])
            self.http.send_data(stream, b"cancel-ready", end_stream=False)
            self.transmit()
            return
        elif path == b"/stall":
            return
        elif path == b"/redirect-http":
            status, body = b"302", b""
            location = f"http://{LOOP}:{self.state.origin_address[1]}/tcp-forbidden".encode("ascii")
            headers.append((b"location", location))
        elif path in (b"/concurrent-a", b"/concurrent-b"):
            check(path not in self.concurrent, "duplicate concurrent path", path)
            self.concurrent[path] = stream
            if len(self.concurrent) < 2:
                return
            # Neither response is sent before both requests are on the wire.
            pending = next(s for s in self.concurrent.values() if s != stream)
            self.state.overlap_proven = True
            self._respond(pending, b"/small", b"")
            body = SMALL
        elif path in (b"/small", b"/reference"):
            body = SMALL
        else:
            status, body = b"404", b"unexpected path"
        self.http.send_headers(stream, [(b":status", status), (b"content-length", str(len(body)).encode()), *headers], end_stream=not body)
        if body:
            self.http.send_data(stream, body, end_stream=True)
        self.transmit()


class Egress(asyncio.DatagramProtocol):
    def __init__(self, state):
        self.state = state

    def datagram_received(self, data, addr):
        state = self.state
        check(addr == state.origin_address, "relay egress got an unexpected peer", addr)
        if state.active:
            state.reverse.observe(data)
            protocol, stream = state.active
            protocol.return_udp(stream, data)
        else:
            state.late_origin_datagrams += 1

    def error_received(self, error):
        self.state.errors.append(f"relay UDP error: {error}")


class RelayProtocol(QuicConnectionProtocol):
    def __init__(self, *args, state, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.http = None
        self.transport_caps = None
        state.relay_connections += 1

    def datagram_received(self, data, addr):
        self.state.outer_peers.add(addr)
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        state = self.state
        if isinstance(event, ProtocolNegotiated):
            self.http = DatagramH3(self._quic, extended=state.mode != "no-connect", datagrams=state.mode != "no-datagram")
            state.relay_settings = {str(int(k)): v for k, v in self.http.sent_settings.items()}
        if isinstance(event, HandshakeCompleted):
            self.transport_caps = self._quic._remote_max_datagram_frame_size
            state.outer_tls.append({"alpn": event.alpn_protocol, "peer_quic_datagram_max": self.transport_caps})
        if isinstance(event, ConnectionTerminated):
            state.outer_terminations.append({"code": event.error_code, "reason": event.reason_phrase})
            self._retire_active("connection-close")
        if isinstance(event, (StreamReset, StopSendingReceived)):
            self._retire_active(type(event).__name__, event.stream_id)
        if self.http is None:
            return
        if self.http.received_settings is not None:
            state.client_settings = {str(int(k)): v for k, v in self.http.received_settings.items()}
        wire_id = None
        if isinstance(event, DatagramFrameReceived):
            try:
                wire_id = Buffer(data=event.data).pull_uint_var()
            except (BufferReadError, ValueError):
                state.invalid_client_datagrams += 1
        for part in self.http.handle_event(event):
            if isinstance(part, HeadersReceived):
                self._connect_udp(part)
            elif isinstance(part, DatagramReceived):
                self._forward_udp(part, wire_id)
            elif isinstance(part, DataReceived):
                state.relay_capsule_bytes += len(part.data)
                if part.stream_ended:
                    self._retire_active("stream-fin", part.stream_id)
        if self.http.received_settings is not None:
            state.client_settings = {str(int(k)): v for k, v in self.http.received_settings.items()}

    def _retire_active(self, reason, stream=None):
        active = self.state.active
        if active is not None and active[0] is self and (stream is None or stream == active[1]):
            self.state.tunnel_ends.append({"stream": active[1], "reason": reason})
            self.state.active = None

    def _connect_udp(self, part):
        state = self.state
        stream = part.stream_id
        headers = dict(part.headers)
        proxy_auth = [v for k, v in part.headers if k == b"proxy-authorization"]
        event = {
            "stream": stream, "method": headers.get(b":method", b"").decode("ascii"),
            "scheme": headers.get(b":scheme", b"").decode("ascii"),
            "protocol": headers.get(b":protocol", b"").decode("ascii"),
            "authority": headers.get(b":authority", b"").decode("ascii"),
            "path": headers.get(b":path", b"").decode("ascii"),
            "capsule_protocol": headers.get(b"capsule-protocol", b"").decode("ascii"),
            "auth_matches": proxy_auth == [AUTH], "auth_header_count": len(proxy_auth),
            "origin_authorization_present": b"authorization" in headers,
            "forbidden_content_fields": [name.decode() for name in (b"content-length", b"content-type", b"transfer-encoding") if name in headers],
            "request_fin": part.stream_ended,
        }
        state.connects.append(event)
        expected = {
            b":method": b"CONNECT", b":protocol": b"connect-udp", b":scheme": b"https",
            b":authority": f"{LOOP}:{state.relay_address[1]}".encode("ascii"),
            b":path": target_path(state.origin_address[1]),
        }
        additional = []
        if any(headers.get(key) != value for key, value in expected.items()):
            status = 403
        elif proxy_auth != [AUTH]:
            status = 407
            additional = [(b"proxy-authenticate", b'Basic realm="test-only"')]
        elif state.mode in ("no-connect", "no-datagram", "small-quic-datagram"):
            # Strict product policy rejects before opening a request to this peer.
            status = 501
        elif state.mode == "deny":
            status = 403
        elif state.mode == "bad-gateway":
            status = 502
            additional = [(b"proxy-status", b"fixture; error=dns_error")]
        elif state.tunnel_used:
            status = 429
        elif part.stream_ended or event["forbidden_content_fields"]:
            status = 400
        else:
            status = 200
            additional = [(b"capsule-protocol", b"?1")]
            state.active = (self, stream)
            state.tunnel_used = True
        event["status"] = status
        self.http.send_headers(stream, [(b":status", str(status).encode("ascii")), *additional], end_stream=(status != 200))
        self.transmit()

    def _forward_udp(self, part, wire_id):
        state = self.state
        if state.active != (self, part.stream_id):
            state.unassociated_client_datagrams += 1
            return
        try:
            payload = Buffer(data=part.data)
            context_id = payload.pull_uint_var()
        except (BufferReadError, ValueError):
            state.invalid_client_datagrams += 1
            return
        if context_id != 0:
            state.invalid_client_datagrams += 1
            return
        check(wire_id == part.stream_id // 4, "unexpected quarter stream ID", wire_id, part.stream_id)
        udp = payload.pull_bytes(payload.capacity - payload.tell())
        state.client_quarter_ids.add(wire_id)
        state.forward_input.observe(udp)
        if state.mode == "blackhole":
            return
        state.egress.sendto(udp)  # Connected UDP socket: destination cannot vary.
        state.forward_sent.observe(udp)

    def return_udp(self, stream, data):
        state = self.state
        check(self.http.received_settings.get(Setting.H3_DATAGRAM) == 1 and self.transport_caps,
              "CONNECT-UDP client did not negotiate DATAGRAM")
        if state.mode in ("contexts", "bad-context"):
            if state.mode == "bad-context" or not state.injected_contexts:
                # Put real inner QUIC in an unregistered, otherwise valid context.
                # When all datagrams have this context, stripping just the prefix
                # would complete TLS and reach the app instead of timing out.
                self.http.send_datagram(stream, encode_uint_var(513) + data)
                state.injected_contexts["unknown_513"] += 1
            if not state.injected_contexts["truncated_varint"]:
                self.http.send_datagram(stream, b"\xff")
                state.injected_contexts["truncated_varint"] += 1
        if state.mode == "capsule-reverse":
            payload = encode_uint_var(0) + data
            capsule = encode_uint_var(0) + encode_uint_var(len(payload)) + payload
            # DATA framing must not imply a Capsule boundary.
            self.http.send_data(stream, capsule[:2], end_stream=False)
            self.http.send_data(stream, capsule[2:], end_stream=False)
            state.capsules_sent += 1
            state.reverse_sent.observe(data)
        elif state.mode != "bad-context":
            self.http.send_datagram(stream, encode_uint_var(0) + data)
            state.reverse_sent.observe(data)
        self.transmit()


class Wire:
    def __init__(self, mode):
        self.mode = mode
        self.overlap_proven = self.tunnel_used = False
        self.capsules_sent = self.late_origin_datagrams = 0
        self.active = self.egress_address = self.initial = None
        self.origin_peers = set()
        self.outer_peers = set()
        self.client_quarter_ids = set()
        self.connects, self.origin_headers, self.origin_bodies = [], [], []
        self.outer_tls, self.origin_tls, self.outer_terminations, self.tunnel_ends = [], [], [], []
        self.origin_cancelled, self.rejected_udp, self.tcp_contacts, self.errors = [], [], [], []
        self.relay_connections = self.origin_connections = 0
        self.invalid_client_datagrams = self.unassociated_client_datagrams = self.relay_capsule_bytes = 0
        self.relay_settings, self.origin_settings, self.client_settings = {}, {}, {}
        self.relay_quic_datagram_max = None
        self.injected_contexts = Counter()
        self.forward_input, self.forward_sent, self.ingress = Traffic(), Traffic(), Traffic()
        self.reverse, self.reverse_sent = Traffic(), Traffic()

    def receipt(self):
        return {
            "mode": self.mode,
            "sockets": {"relay": self.relay_address, "relay_egress": self.egress_address, "origin_udp": self.origin_address},
            "outer": {"connections": self.relay_connections, "client_peers": sorted(self.outer_peers), "tls": self.outer_tls,
                      "settings": self.relay_settings, "client_settings": self.client_settings, "connects": self.connects,
                      "quic_datagram_max": self.relay_quic_datagram_max,
                      "terminations": self.outer_terminations, "tunnel_ends": self.tunnel_ends},
            "origin": {"connections": self.origin_connections, "peer_sockets": sorted(self.origin_peers), "tls": self.origin_tls,
                       "settings": self.origin_settings, "initial": self.initial, "headers": self.origin_headers,
                       "bodies": self.origin_bodies, "cancelled_streams": self.origin_cancelled, "overlap_proven": self.overlap_proven,
                       "rejected_udp": self.rejected_udp, "tcp_contacts": self.tcp_contacts},
            "datagrams": {"rx_quarter_stream_ids": sorted(self.client_quarter_ids), "client_invalid": self.invalid_client_datagrams,
                          "client_unassociated": self.unassociated_client_datagrams, "client_capsule_bytes": self.relay_capsule_bytes,
                          "client_to_relay": self.forward_input.receipt(), "relay_to_origin": self.forward_sent.receipt(),
                          "origin_ingress": self.ingress.receipt(), "origin_to_relay": self.reverse.receipt(),
                          "relay_to_client": self.reverse_sent.receipt(), "injected_contexts": dict(self.injected_contexts),
                          "reverse_capsules_sent": self.capsules_sent, "late_origin_after_tunnel": self.late_origin_datagrams},
            "fixture_errors": self.errors,
        }


def configuration(pem, *, relay=False, wrong=False, datagram_limit=65536):
    config = QuicConfiguration(
        is_client=False, alpn_protocols=["h3"], idle_timeout=15,
        max_datagram_size=OUTER_PACKET_SIZE if relay else 1200,
        max_datagram_frame_size=datagram_limit if relay else None,
        supported_versions=[QuicProtocolVersion.VERSION_1, QuicProtocolVersion.VERSION_2],
    )
    config.load_cert_chain(pem["wrong" if wrong else "good"][0], pem["key"])
    return config


@contextlib.asynccontextmanager
async def fixture(origin_pem, relay_pem, mode="ok"):
    state = Wire(mode)
    loop = asyncio.get_running_loop()
    old_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: state.errors.append(repr(ctx.get("exception", ctx["message"]))))

    async def tcp_canary(_reader, writer):
        state.tcp_contacts.append(writer.get_extra_info("peername"))
        writer.close()
        await writer.wait_closed()

    try:
        with contextlib.ExitStack() as cleanup:
            origin_conf = configuration(origin_pem, wrong=mode == "wrong-origin-name")
            for _ in range(5):
                _, origin = await loop.create_datagram_endpoint(
                    lambda: GuardedOrigin(configuration=origin_conf, state=state,
                                          create_protocol=partial(OriginProtocol, state=state)),
                    local_addr=(LOOP, 0),
                )
                state.origin_address = origin._transport.get_extra_info("sockname")
                try:
                    trap = await asyncio.start_server(tcp_canary, *state.origin_address)
                    break
                except OSError:
                    origin.close()
            else:
                raise RuntimeError("failed to reserve matching UDP/TCP loopback port")
            cleanup.callback(origin.close)
            cleanup.callback(trap.close)
            egress, _ = await loop.create_datagram_endpoint(
                lambda: Egress(state), local_addr=(LOOP, 0), remote_addr=state.origin_address,
            )
            cleanup.callback(egress.close)
            state.egress = egress
            state.egress_address = egress.get_extra_info("sockname")
            relay_conf = configuration(relay_pem, relay=True, wrong=mode == "wrong-relay-name",
                                       datagram_limit=1200 if mode == "small-quic-datagram" else 65536)
            state.relay_quic_datagram_max = relay_conf.max_datagram_frame_size
            _, relay = await loop.create_datagram_endpoint(
                lambda: QuicServer(configuration=relay_conf, create_protocol=partial(RelayProtocol, state=state)),
                local_addr=(LOOP, 0),
            )
            cleanup.callback(relay.close)
            state.relay_address = relay._transport.get_extra_info("sockname")
            state.certificates = {"origin_leaf_sha256": origin_pem["wrong" if mode == "wrong-origin-name" else "good"][1],
                                  "relay_leaf_sha256": relay_pem["wrong" if mode == "wrong-relay-name" else "good"][1]}
            yield state
    finally:
        await asyncio.sleep(0)  # Dispatch socket closure notifications before restoring the handler.
        loop.set_exception_handler(old_handler)


class ReferenceOuter(QuicConnectionProtocol):
    """Fixture-only calibration: encode CONNECT/DATAGRAM independently of product."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = self.inner = None
        self.pending = {}

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = DatagramH3(self._quic, extended=False)
        if self.http is None:
            return
        for part in self.http.handle_event(event):
            if isinstance(part, HeadersReceived):
                self.pending[part.stream_id].put_nowait(dict(part.headers))
            elif isinstance(part, DatagramReceived):
                check(part.stream_id == self.stream and part.data[:1] == b"\0", part)
                self.inner.datagram_received(part.data[1:], (LOOP, 9))

    async def request(self, relay_port, path):
        stream = self._quic.get_next_available_stream_id()
        self.pending[stream] = asyncio.Queue()
        self.http.send_headers(stream, [(b":method", b"CONNECT"), (b":protocol", b"connect-udp"),
                                        (b":scheme", b"https"), (b":authority", f"{LOOP}:{relay_port}".encode()),
                                        (b":path", path), (b"capsule-protocol", b"?1"),
                                        (b"proxy-authorization", AUTH)])
        self.transmit()
        return stream, await asyncio.wait_for(self.pending[stream].get(), 4)

    def sendto(self, data, addr):
        check(addr == (LOOP, 9), addr)
        self._quic.send_datagram_frame(encode_uint_var(self.stream // 4) + b"\0" + data)
        self.transmit()


class ReferenceInner(QuicConnectionProtocol):
    def __init__(self, quic):
        super().__init__(quic)
        self.http = H3Connection(quic)
        self.body = bytearray()
        self.response = asyncio.get_running_loop().create_future()

    def quic_event_received(self, event):
        for part in self.http.handle_event(event):
            if isinstance(part, HeadersReceived):
                check(dict(part.headers)[b":status"] == b"200", part.headers)
            elif isinstance(part, DataReceived):
                self.body.extend(part.data)
                if part.stream_ended and not self.response.done():
                    self.response.set_result(bytes(self.body))


async def fixture_self_test(origin_pem, relay_pem):
    from aioquic.quic.connection import QuicConnection

    async with fixture(origin_pem, relay_pem) as state:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stray:
            # A real UDP packet from another loopback socket must reach the gate
            # and be discarded before any QUIC parser/protocol handles it.
            stray.bind((LOOP, 0))
            wrong_source = stray.getsockname()
            stray.sendto(b"wrong-peer-proof", state.origin_address)
            await wait_for(lambda: bool(state.rejected_udp))
            check(state.rejected_udp == [wrong_source] and not state.initial,
                  "origin accepted wrong-source UDP", state.receipt())
        _, writer = await asyncio.open_connection(*state.origin_address)
        await wait_for(lambda: bool(state.tcp_contacts))
        check(writer.get_extra_info("sockname") == state.tcp_contacts[0], state.tcp_contacts)
        writer.close()
        await writer.wait_closed()

        outer_config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name=LOOP,
                                         verify_mode=ssl.CERT_REQUIRED, cafile=str(relay_pem["root"]),
                                         max_datagram_size=OUTER_PACKET_SIZE, max_datagram_frame_size=65536)
        async with connect(*state.relay_address, configuration=outer_config, create_protocol=ReferenceOuter) as outer:
            stream, response = await outer.request(state.relay_address[1], b"/.well-known/masque/udp/not-allowed.invalid/53/")
            check(stream == 0 and response[b":status"] == b"403" and state.active is None,
                  "relay allowed a different target", stream, response)
            outer.stream, response = await outer.request(state.relay_address[1], target_path(state.origin_address[1]))
            check(outer.stream == 4 and response == {b":status": b"200", b"capsule-protocol": b"?1"}, response)
            inner_config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name=ORIGIN,
                                             verify_mode=ssl.CERT_REQUIRED, cafile=str(origin_pem["root"]))
            inner = outer.inner = ReferenceInner(QuicConnection(configuration=inner_config))
            # Only the outer QUIC connection has a client network socket.
            inner.connection_made(outer)
            inner.connect((LOOP, 9))
            try:
                await asyncio.wait_for(inner.wait_connected(), 4)
                stream = inner._quic.get_next_available_stream_id()
                inner.http.send_headers(stream, [(b":method", b"GET"), (b":scheme", b"https"),
                                                (b":authority", f"{ORIGIN}:{state.origin_address[1]}".encode()),
                                                (b":path", b"/reference")], end_stream=True)
                inner.transmit()
                check(await asyncio.wait_for(inner.response, 4) == SMALL, state.receipt())
            finally:
                inner.close()
        check(state.client_quarter_ids == {1}, state.receipt())
        check(state.origin_peers == {state.egress_address} and len(state.outer_peers) == 1, state.receipt())
        check(state.forward_input.count > 1 and state.reverse_sent.count > 1, state.receipt())
    check(not state.errors, state.errors)
    return {"verdict": "passed", "client": "aioquic reference (fixture calibration, not product evidence)", **state.receipt()}


async def wait_for(predicate, seconds=3):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while not predicate() and loop.time() < deadline:
        await asyncio.sleep(0.005)
    return bool(predicate())


@contextlib.contextmanager
def watch_client(state):
    from ruyihttp import _http3

    dns_attempts = []
    counters = Counter()
    original_dns = socket.getaddrinfo
    read, write = _http3._BodyABI.read, _http3._BodyABI.write
    json_frame = _http3.Connection._json_frame
    clients = []
    native_init = _http3.Connection.__init__

    def guarded_dns(host, *args, **kwargs):
        name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
        if isinstance(name, str) and name.lower().rstrip(".") in (ORIGIN, WRONG_ORIGIN):
            dns_attempts.append(name)
            raise socket.gaierror(socket.EAI_NONAME, "wire gate intercepted local origin resolution")
        return original_dns(host, *args, **kwargs)

    def observe_read(self, *args, **kwargs):
        data, end = read(self, *args, **kwargs)
        counters["binary_read_calls"] += 1
        counters["binary_read_bytes"] += len(data)
        return data, end

    def observe_write(self, *args, **kwargs):
        count = write(self, *args, **kwargs)
        counters["binary_write_calls"] += 1
        counters["binary_write_bytes"] += count
        return count

    def observe_json(self, data):
        # Count calls to the existing C-ABI JSON body fallback, not control frames.
        if b'"op": "read"' in data:
            counters["legacy_json_read_calls"] += 1
        elif b'"op": "write"' in data:
            counters["legacy_json_write_calls"] += 1
        return json_frame(self, data)

    def observe_init(self, *args, **kwargs):
        clients.append(self)
        return native_init(self, *args, **kwargs)

    with patch.object(socket, "getaddrinfo", guarded_dns), patch.object(_http3._BodyABI, "read", observe_read), \
         patch.object(_http3._BodyABI, "write", observe_write), patch.object(_http3.Connection, "_json_frame", observe_json), \
         patch.object(_http3.Connection, "__init__", observe_init):
        yield dns_attempts, counters, clients


def wheel_identity():
    product = importlib.metadata.distribution("ruyihttp")
    result = {"product_version": product.version}
    direct = json.loads(product.read_text("direct_url.json") or "{}")
    archive = direct.get("archive_info", {})
    wheel_hash = archive.get("hashes", {}).get("sha256")
    local = urlsplit(direct.get("url", ""))
    if local.scheme == "file" and not local.netloc:
        wheel = Path(url2pathname(local.path))
        if wheel.suffix == ".whl" and wheel.is_file():
            result["wheel_filename"] = wheel.name
            with wheel.open("rb") as binary:
                digest = hashlib.sha256()
                for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                    digest.update(chunk)
            if wheel_hash:
                check(wheel_hash == digest.hexdigest(), "installed wheel hash differs from local archive", wheel.name)
            wheel_hash = digest.hexdigest()
    if wheel_hash:
        result["wheel_sha256"] = wheel_hash
    return result


def runtime():
    import ruyihttp
    from ruyihttp._firefox import runtime_platform

    slot = runtime_platform()
    manifest = Path(ruyihttp.__file__).with_name("runtime-manifest.json")
    return ruyihttp, slot, json.loads(manifest.read_text(encoding="utf-8"))["platforms"][slot]


def response_receipt(response, expected, runtime_slot):
    check(response.status_code == 200 and response.raw.version == 30, response.status_code, response.raw.version)
    check(response.headers.get("x-wire-origin") == "udp-only", response.headers)
    check(response.content == expected, "payload mismatch", len(response.content), sha256(response.content), sha256(expected))
    tls = response.tls
    shape = runtime_slot["h3_tls"]
    backend = "NSS/Neqo" if shape == "windows-legacy" else "NSS"
    check(tls and tls["backend"] == backend and tls["alpn"] == "h3" and tls["version"] == 0x0304, tls)
    if shape != "windows-legacy":
        check(tls["profile"] == f"firefox-{FIREFOX}" and tls["nss"] == runtime_slot["nss"], tls)
    outer = response.proxy_tls
    check(outer and outer["transport"] == "masque" and outer["alpn"] == "h3" and outer["protocol"] == "connect-udp"
          and outer["datagram_mode"] == "quic" and outer["verified"] is True
          and 1252 <= outer["max_inner_udp_payload_size"] < outer["outer_udp_payload_size"], outer)
    return {"status": response.status_code, "http_version": response.raw.version, "body_bytes": len(response.content),
            "body_sha256": sha256(response.content), "tls": tls, "proxy_tls": outer}


@contextlib.contextmanager
def mask_optional_dependency(mode):
    if mode != "missing-extra":
        yield
        return
    from ruyihttp import _masque

    importer = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "aioquic" or name.startswith("aioquic."):
            raise ModuleNotFoundError("fixture masks the optional aioquic dependency", name="aioquic")
        return importer(name, *args, **kwargs)

    # The fixture still needs its already-imported server library. Mask the
    # product's fresh lazy import; do not stub its network or public client.
    _masque._aioquic.cache_clear()
    try:
        with patch.object(builtins, "__import__", guarded_import):
            yield
    finally:
        _masque._aioquic.cache_clear()


def client_call(state, origin_pem, relay_pem, runtime_slot, *, positive=False):
    import ruyihttp
    from requests.exceptions import RequestException

    mode = state.mode
    roots = relay_pem["root"] if mode == "wrong-origin-ca" else origin_pem["root"]
    relay_roots = origin_pem["root"] if mode == "wrong-relay-ca" else relay_pem["root"]
    user_info = "" if mode == "auth-required" else URL_AUTH
    proxy = f"masque://{user_info}{LOOP}:{state.relay_address[1]}"
    uri = f"https://{ORIGIN}:{state.origin_address[1]}"
    budget = (1.5, 3) if mode in ("blackhole", "bad-context") else (8, 1.5) if mode == "post-stall" else (8, 12)
    options = {"proxies": {"https": proxy}, "allow_redirects": mode == "redirect-http"}
    if mode == "client-certificate":
        options["cert"] = (str(origin_pem["good"][0]), str(origin_pem["key"]))
    start = time.monotonic()
    try:
        with mask_optional_dependency(mode), ruyihttp.Session(
            firefox=FIREFOX, verify=str(roots), proxy_verify=str(relay_roots), timeout=budget,
        ) as session:
            session.trust_env = False
            if positive:
                receipts = {}
                for path, body in (("download", DOWNLOAD), ("upload", UPLOAD)):
                    if path == "download":
                        # Authorization is ordinary origin auth; Proxy-Authorization stays at relay.
                        response = session.get(uri + "/download", headers={"Authorization": "Bearer origin-fixture"}, **options)
                    else:
                        response = session.post(uri + "/upload", data=body, **options)
                    try:
                        receipts[path] = response_receipt(response, body, runtime_slot)
                    finally:
                        response.close()
                response = session.get(uri + "/cancel", stream=True, **options)
                try:
                    check(response.raw.version == 30 and next(response.iter_content(chunk_size=12)) == b"cancel-ready", response)
                finally:
                    response.close()
                check(not state.tcp_contacts, state.tcp_contacts)
                barrier = threading.Barrier(2, timeout=5)

                def fetch(path):
                    barrier.wait()
                    with session.get(uri + path, **options) as response:
                        return response_receipt(response, SMALL, runtime_slot)

                with ThreadPoolExecutor(max_workers=2) as workers:
                    a = workers.submit(fetch, "/concurrent-a")
                    b = workers.submit(fetch, "/concurrent-b")
                    receipts["concurrent-a"] = a.result(timeout=15)
                    receipts["concurrent-b"] = b.result(timeout=15)
                with session.get(uri + "/small", **options) as response:
                    receipts["after_cancel"] = response_receipt(response, SMALL, runtime_slot)
            elif mode == "post-stall":
                with session.post(uri + "/stall", data=UPLOAD, **options) as response:
                    receipts = {"post": response_receipt(response, SMALL, runtime_slot)}
            else:
                path = "/redirect-http" if mode == "redirect-http" else "/small"
                with session.get(uri + path, **options) as response:
                    receipts = {"small": response_receipt(response, SMALL, runtime_slot)}
        return {"responses": receipts, "elapsed_seconds": round(time.monotonic() - start, 4)}
    except RequestException as error:
        text = str(error).replace(URL_AUTH, "[fixture]@").replace(AUTH_PASSWORD, "[fixture]")
        return {"error": type(error).__name__, "message": text, "elapsed_seconds": round(time.monotonic() - start, 4), "exception": error}


def check_route(state):
    check(not state.errors, "async fixture exception", state.errors)
    check(not state.rejected_udp, "unexpected direct origin UDP", state.rejected_udp)
    check(not state.tcp_contacts, "unexpected origin TCP", state.tcp_contacts)
    check(not state.invalid_client_datagrams and not state.unassociated_client_datagrams and not state.relay_capsule_bytes,
          "unexpected outer DATAGRAM framing/Capsule traffic", state.receipt()["datagrams"])


def check_tunnel(state):
    check(state.relay_connections == 1 and len(state.outer_peers) == 1 and len(state.outer_tls) == 1, state.receipt()["outer"])
    peer, = state.outer_peers
    check(peer[0] == LOOP and peer not in (state.origin_address, state.relay_address, state.egress_address), peer)
    check(state.outer_tls[0]["alpn"] == "h3" and state.outer_tls[0]["peer_quic_datagram_max"] >= 1254, state.outer_tls)
    check(state.relay_settings.get("8") == 1 and state.relay_settings.get("51") == 1 and state.client_settings.get("51") == 1,
          state.relay_settings, state.client_settings)
    check(len(state.connects) == 1, state.connects)
    event, = state.connects
    check(event["status"] == 200 and event["auth_matches"] and event["auth_header_count"] == 1 and not event["request_fin"]
          and event["capsule_protocol"] == "?1" and not event["origin_authorization_present"], event)
    check(event["path"] == target_path(state.origin_address[1]).decode() and event["authority"] == f"{LOOP}:{state.relay_address[1]}", event)
    check(event["stream"] % 4 == 0 and state.client_quarter_ids == {event["stream"] // 4}, event, state.client_quarter_ids)
    check(state.tunnel_ends and state.active is None, "session close did not retire CONNECT stream", state.receipt()["outer"])


def check_origin(state, runtime_slot, body_calls):
    check(state.origin_connections == 1 and state.origin_peers == {state.egress_address}, state.receipt()["origin"])
    initial = state.initial
    check(initial["version"] == int(QuicProtocolVersion.VERSION_1) and initial["scid_bytes"] == 3 and initial["udp_bytes"] == 1252,
          "Firefox 161 initial UDP profile", initial)
    check(len(state.origin_tls) == 1 and state.origin_tls[0]["alpn"] == "h3", state.origin_tls)
    if runtime_slot.get("h3_protocol_policy") == 1:
        check(state.origin_settings.get("8") == 1 and state.origin_tls[0]["quic_version"] == int(QuicProtocolVersion.VERSION_2),
              "Firefox 161 inner HTTPS presentation", state.origin_tls, state.origin_settings)
    expected_paths = ["/download", "/upload", "/cancel", "/small", "/concurrent-a", "/concurrent-b"]
    check(Counter(row["path"] for row in state.origin_headers) == Counter(expected_paths), state.origin_headers)
    check(state.overlap_proven and len({row["stream"] for row in state.origin_headers}) == len(expected_paths),
          "native streams were not concurrent and reused", state.origin_headers)
    for row in state.origin_headers:
        check(row["connection"] == 0 and row["authority"] == f"{ORIGIN}:{state.origin_address[1]}" and "Firefox/161.0" in row["user_agent"], row)
        check(not row["proxy_credentials_present"], "proxy credentials reached origin", row)
        check(row["origin_authorization"] == ("Bearer origin-fixture" if row["path"] == "/download" else ""), row)
        check(row["method"] == ("POST" if row["path"] == "/upload" else "GET"), row)
    uploader, = (row for row in state.origin_headers if row["method"] == "POST")
    uploaded, = (row for row in state.origin_bodies if row["stream"] == uploader["stream"])
    check(uploaded == {"stream": uploader["stream"], "bytes": len(UPLOAD), "sha256": sha256(UPLOAD)}, uploaded)
    cancelled, = (row for row in state.origin_headers if row["path"] == "/cancel")
    check(any(stream == cancelled["stream"] for _, _, stream in state.origin_cancelled), "origin never received stream cancellation", state.origin_cancelled)
    if runtime_slot["h3_body_abi"] == 1:
        check(body_calls["binary_read_bytes"] >= len(DOWNLOAD) + len(UPLOAD) and body_calls["binary_write_bytes"] == len(UPLOAD)
              and body_calls["binary_read_calls"] > 1 and body_calls["binary_write_calls"] > 1
              and not body_calls["legacy_json_read_calls"] and not body_calls["legacy_json_write_calls"], body_calls)
    else:
        check(body_calls["legacy_json_read_calls"] > 1 and body_calls["legacy_json_write_calls"] > 1
              and not body_calls["binary_read_calls"] and not body_calls["binary_write_calls"], body_calls)


def check_end_to_end(state, runtime_slot, body_calls):
    check_tunnel(state)
    check_origin(state, runtime_slot, body_calls)
    check(state.forward_input.count > 1 and state.forward_sent.octets > len(UPLOAD) and state.reverse_sent.octets > len(DOWNLOAD) + len(UPLOAD),
          state.receipt()["datagrams"])
    check(state.forward_input.receipt() == state.forward_sent.receipt() == state.ingress.receipt()
          and state.reverse.receipt() == state.reverse_sent.receipt(), "UDP bytes changed across fixture relay", state.receipt()["datagrams"])


def check_scenario(state, result, error):
    from requests.exceptions import InvalidSchema, ProxyError, ReadTimeout, SSLError, Timeout

    mode = state.mode
    status = {"auth-required": 407, "deny": 403, "bad-gateway": 502}.get(mode)
    if status is not None:
        check(isinstance(error, ProxyError) and str(status) in result["message"], result)
        check(len(state.connects) == 1 and state.connects[0]["status"] == status, state.connects)
        check(not state.forward_input.count and not state.origin_headers, state.receipt())
    elif mode in ("no-connect", "no-datagram", "small-quic-datagram"):
        check(isinstance(error, ProxyError), result)
        check(len(state.outer_tls) == 1 and state.outer_tls[0]["alpn"] == "h3", state.receipt())
        if mode == "small-quic-datagram":
            check(state.relay_settings.get("51") == 1 and state.relay_settings.get("8") == 1
                  and state.relay_quic_datagram_max == 1200, state.relay_settings, state.relay_quic_datagram_max)
        else:
            missing = "8" if mode == "no-connect" else "51"
            check(state.relay_settings.get(missing, 0) == 0, state.relay_settings)
        check(not state.connects and not state.forward_input.count and not state.origin_headers, state.receipt())
    elif mode in ("wrong-relay-ca", "wrong-relay-name"):
        check(isinstance(error, SSLError) and state.relay_connections == 1, result, state.receipt()["outer"])
        check(not state.connects and not state.forward_input.count and not state.ingress.count and not state.origin_headers, state.receipt())
    elif mode in ("wrong-origin-ca", "wrong-origin-name"):
        check(isinstance(error, SSLError), result)
        check_tunnel(state)
        check(state.ingress.count and state.reverse_sent.count and state.origin_connections == 1 and not state.origin_headers, state.receipt())
    elif mode in ("blackhole", "bad-context"):
        check(isinstance(error, Timeout), result)
        check_tunnel(state)
        check(0.5 <= result["elapsed_seconds"] <= 5 and state.forward_input.count and not state.origin_headers, result, state.receipt())
        if mode == "blackhole":
            check(not state.ingress.count and not state.reverse_sent.count, state.receipt()["datagrams"])
        else:
            check(state.ingress.count and state.reverse.count and not state.reverse_sent.count, state.receipt()["datagrams"])
            check(state.injected_contexts["unknown_513"] > 0 and state.injected_contexts["truncated_varint"] == 1, state.injected_contexts)
    elif mode == "contexts":
        check(error is None and result["responses"]["small"]["http_version"] == 30, result)
        check_tunnel(state)
        check([row["path"] for row in state.origin_headers] == ["/small"], state.origin_headers)
        check(state.injected_contexts == {"unknown_513": 1, "truncated_varint": 1} and state.reverse_sent.count, state.receipt())
    elif mode == "capsule-reverse":
        check(error is None and result["responses"]["small"]["http_version"] == 30, result)
        check_tunnel(state)
        check(state.capsules_sent > 1 and state.capsules_sent == state.reverse_sent.count, state.receipt()["datagrams"])
        check([row["path"] for row in state.origin_headers] == ["/small"], state.origin_headers)
    elif mode == "redirect-http":
        check(isinstance(error, ProxyError), result)
        check_tunnel(state)
        check([row["path"] for row in state.origin_headers] == ["/redirect-http"], state.origin_headers)
    elif mode in ("missing-extra", "client-certificate"):
        expected = ProxyError if mode == "missing-extra" else InvalidSchema
        check(isinstance(error, expected), result)
        if mode == "missing-extra":
            check("ruyihttp[masque]" in result["message"], result)
        check(not state.relay_connections and not state.ingress.count and not state.origin_headers, state.receipt())
    elif mode == "post-stall":
        check(isinstance(error, ReadTimeout), result)
        check_tunnel(state)
        request, = state.origin_headers
        check(request["path"] == "/stall" and request["method"] == "POST", request)
        check(state.origin_bodies == [{"stream": request["stream"], "bytes": len(UPLOAD), "sha256": sha256(UPLOAD)}],
              "timed-out POST was replayed or incomplete", state.origin_bodies)
    else:
        raise AssertionError(f"unknown wire scenario: {mode}")


MODES = ("ok", "auth-required", "deny", "bad-gateway", "wrong-relay-ca", "wrong-relay-name", "wrong-origin-ca",
         "wrong-origin-name", "no-connect", "no-datagram", "small-quic-datagram", "blackhole", "contexts",
         "bad-context", "capsule-reverse", "redirect-http", "missing-extra", "client-certificate", "post-stall")


async def qualify(receipt, origin_pem, relay_pem, modes):
    ruyihttp, slot, manifest = runtime()
    receipt.update({"platform_slot": slot, "manifest_h3_body_abi": manifest["h3_body_abi"], "firefox": FIREFOX,
                    "product_path": str(Path(ruyihttp.__file__).resolve())})
    for mode in modes:
        case = {"name": mode, "verdict": "running"}
        receipt["cases"].append(case)
        print(f"MASQUE wire: {mode}", flush=True)
        async with fixture(origin_pem, relay_pem, mode) as state:
            try:
                with watch_client(state) as (dns, abi, native_clients):
                    result = await asyncio.to_thread(client_call, state, origin_pem, relay_pem, manifest, positive=(mode == "ok"))
                error = result.pop("exception", None)
                case["request"] = result
                # Evidence is sampled only after the peer sees release. This also drains
                # queued valid QUIC datagrams before comparing relay and origin counts.
                if any(row["status"] == 200 for row in state.connects):
                    await wait_for(lambda: state.active is None)
                case["origin_dns_attempts"] = list(dns)
                case["native_body_calls"] = dict(abi)
                live = [conn._thread.name for conn in native_clients if hasattr(conn, "_thread") and conn._thread.is_alive()]
                outer_workers = [thread.name for thread in threading.enumerate() if thread.name.startswith("ruyihttp-masque-")]
                case["live_native_workers_after_session_close"] = live
                case["live_outer_workers_after_session_close"] = outer_workers
                check(not dns and not live and not outer_workers, "client origin DNS attempt or leaked worker", dns, live, outer_workers)
                check_route(state)
                if mode == "ok":
                    check(error is None, result)
                    check_end_to_end(state, manifest, abi)
                else:
                    check_scenario(state, result, error)
            finally:
                case.update({"wire": state.receipt(), "leaf_fingerprints": state.certificates})
        check(not state.errors, state.errors)
        case["verdict"] = "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--fixture-self-test", action="store_true", help="calibrate the relay with independent aioquic endpoints")
    parser.add_argument("--case", choices=MODES, action="append", help="run specific cases (default: full gate)")
    args = parser.parse_args()
    aioquic_version = importlib.metadata.version("aioquic")
    receipt = {
        "schema": "ruyihttp-masque-wire/v1", "verdict": "failed", "cases": [], "python": platform.python_version(),
        "os": platform.platform(), "asyncio_policy": type(asyncio.get_event_loop_policy()).__name__,
        "protocol": {"outer": "aioquic H3, RFC 9298 CONNECT-UDP + RFC 9297 QUIC DATAGRAM",
                     "origin": "native NSS/Neqo H3", "aioquic_version": aioquic_version,
                     "mode": "QUIC DATAGRAM required; reverse DATAGRAM capsules accepted"},
    }
    try:
        check(aioquic_version == "1.3.0", "fixture requires aioquic==1.3.0", aioquic_version)
        with tempfile.TemporaryDirectory(prefix="ruyi-masque-") as temp:
            origin_pem, relay_pem = certs(Path(temp))
            if args.fixture_self_test:
                receipt["fixture_calibration"] = asyncio.run(fixture_self_test(origin_pem, relay_pem))
            else:
                receipt.update(wheel_identity())
                asyncio.run(qualify(receipt, origin_pem, relay_pem, args.case or MODES))
        receipt["verdict"] = "passed"
    except BaseException as error:
        receipt["failure"] = {"type": type(error).__name__, "message": str(error).replace(URL_AUTH, "[fixture]@")}
        if receipt["cases"] and receipt["cases"][-1]["verdict"] == "running":
            receipt["cases"][-1]["verdict"] = "failed"
        raise
    finally:
        if args.json_output:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("PASS: " + ("fixture calibration (not native product qualification)" if args.fixture_self_test else "native H3 over authenticated MASQUE CONNECT-UDP"), flush=True)


if __name__ == "__main__":
    main()
