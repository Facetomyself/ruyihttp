# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Explicit, client-only CONNECT-UDP via HTTP/3 (RFC 9297/9298).

Sends HTTP Datagrams in QUIC DATAGRAM frames. Receives them in either QUIC
DATAGRAM or DATAGRAM capsules; a capsule-only proxy is not a supported route.
The outer TLS peer is the proxy; the caller owns the inner protocol and trust.
"""

import errno
import logging
import math
import os
import queue
import selectors
import socket
import ssl
import sys
import threading
import time
from functools import lru_cache
from importlib.metadata import version

from requests.exceptions import ConnectTimeout, ProxyError, SSLError

from ._masque_codec import (
    CapsuleDecoder,
    CapsuleError,
    connect_headers,
    parse_proxy,
    target_path,
    udp_payload,
)

_OUTER_MAX = 1400
_OUTER_MIN = 1200
_INNER_INITIAL = 1252
# Short header: 1 flags + at most 20 DCID + at most 4 packet number + 16 tag.
_SHORT_OVERHEAD = 41
# aioquic emits DATAGRAM_WITH_LENGTH: 1 type + 2 length at this MTU;
# the first request has Quarter Stream ID zero and we send Context ID zero.
_FRAME_OVERHEAD = 5
_OUTER_FLOOR = _INNER_INITIAL + _SHORT_OVERHEAD + _FRAME_OVERHEAD
_INNER_MAX = _OUTER_MAX - _SHORT_OVERHEAD - _FRAME_OVERHEAD
_MTU_STEPS = (1360, 1320, _OUTER_FLOOR)
_IDLE_TIMEOUT = 60.0
_DEFAULT_CONNECT_TIMEOUT = 30.0
_POLL = 0.05
_BURST = 32
_MAX_PENDING = 64
_MAX_H3_BUFFER = 32768
_MAX_H3_FIELDS = 16384
_MAX_STREAMS = 32
_DNS_SLOTS = threading.BoundedSemaphore(8)
# aioquic logs peer-provided close reasons, which may echo request headers.
# Use a detached logger for this transport; public errors use only local text/codes.
_QUIET_QUIC = logging.Logger("ruyihttp.masque.quic", logging.CRITICAL + 1)


class MasqueError(ProxyError):
    """A failure of the explicit proxy route, not an origin response."""


def _verify_path(proxy_verify):
    if proxy_verify is True:
        # aioquic performs IP-SAN/hostname and chain verification using its
        # certifi trust store. This is independent of inner Firefox/NSS trust.
        return None
    if not isinstance(proxy_verify, (str, os.PathLike)):
        raise ValueError("MASQUE proxy_verify must be True or a CA bundle file path")
    path = os.fspath(proxy_verify)
    if not isinstance(path, str) or not path or not os.path.isfile(path):
        raise ValueError("MASQUE proxy_verify must identify a readable CA bundle file")
    # Check the explicit trust bundle before dialing; never fall back to defaults.
    try:
        ssl.create_default_context(cafile=path)
    except (OSError, ValueError):
        raise SSLError("MASQUE proxy CA bundle could not be loaded") from None
    return os.path.abspath(path)


def _remaining(deadline, *events):
    if any(event is not None and event.is_set() for event in events):
        raise MasqueError("MASQUE proxy connection cancelled")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ConnectTimeout("MASQUE proxy connection deadline elapsed")
    return remaining


def _resolve(proxy, deadline, cancel_event):
    # Preserve IP literals without a DNS query. libc DNS cannot be interrupted;
    # bound abandoned resolver workers and wait only within the caller's budget.
    if ":" in proxy.host:
        return [(socket.AF_INET6, (proxy.host, proxy.port, 0, 0))]
    try:
        socket.inet_pton(socket.AF_INET, proxy.host)
    except OSError:
        pass
    else:
        return [(socket.AF_INET, (proxy.host, proxy.port))]

    _remaining(deadline, cancel_event)
    if not _DNS_SLOTS.acquire(blocking=False):
        raise MasqueError("MASQUE proxy resolver is busy")
    result = queue.Queue(maxsize=1)

    def run():
        try:
            addresses = socket.getaddrinfo(proxy.host, proxy.port, type=socket.SOCK_DGRAM)
            result.put(list(dict.fromkeys((family, sockaddr)
                                           for family, _, _, _, sockaddr in addresses
                                           if family in (socket.AF_INET, socket.AF_INET6))))
        except Exception:
            result.put([])
        finally:
            _DNS_SLOTS.release()

    try:
        threading.Thread(target=run, name="ruyihttp-masque-dns", daemon=True).start()
    except BaseException:
        _DNS_SLOTS.release()
        raise
    while True:
        try:
            addresses = result.get(timeout=min(_POLL, _remaining(deadline, cancel_event)))
        except queue.Empty:
            continue
        if not addresses:
            raise MasqueError("MASQUE proxy DNS resolution failed")
        return addresses


def _udp_pair():
    first = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        second = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for sock in (first, second):
                # Ephemeral loopback ports, no reuse and no wildcard listener.
                sock.bind(("127.0.0.1", 0))
                sock.setblocking(False)
            first.connect(second.getsockname())
            second.connect(first.getsockname())
            # Remove packets hypothetically queued in the tiny pre-connect window.
            for sock in (first, second):
                for _ in range(_BURST):
                    try:
                        sock.recv(65536)
                    except BlockingIOError:
                        break
                else:
                    raise MasqueError("MASQUE private socket pair was unexpectedly busy")
        except BaseException:
            second.close()
            raise
    except BaseException:
        first.close()
        raise
    return first, second


def _no_fragment(sock, family):
    # RFC 9000 §14: use unfragmented UDP and set DF on IPv4 where possible.
    if sys.platform.startswith("linux"):
        if family == socket.AF_INET:
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 2)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_MTU_DISCOVER", 23), 2)
    elif sys.platform == "win32":
        level, name = (socket.IPPROTO_IP, "IP_DONTFRAGMENT") if family == socket.AF_INET else (
            socket.IPPROTO_IPV6, "IPV6_DONTFRAG")
        sock.setsockopt(level, getattr(socket, name, 14), 1)
    elif sys.platform == "darwin":
        if family == socket.AF_INET:
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_DONTFRAG", 28), 1)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_DONTFRAG", 62), 1)
    else:
        level, name = (socket.IPPROTO_IP, "IP_DONTFRAG") if family == socket.AF_INET else (
            socket.IPPROTO_IPV6, "IPV6_DONTFRAG")
        option = getattr(socket, name, None)
        if option is not None:
            sock.setsockopt(level, option, 1)


def _response_status(headers):
    if sum(len(k) + len(v) + 32 for k, v in headers) > _MAX_H3_FIELDS:
        raise MasqueError("MASQUE proxy response headers exceed the local limit")
    values = [value for name, value in headers if name == b":status"]
    if (len(values) != 1 or len(values[0]) != 3 or not values[0].isdigit()
            or not 100 <= int(values[0]) <= 599 or values[0] == b"101"):
        raise MasqueError("Malformed MASQUE proxy response status")
    return int(values[0])


@lru_cache(maxsize=1)
def _aioquic():
    # Imports and 1.3-series compatibility shims are restricted to an explicit
    # proxy route. They are qualified against aioquic 1.3.0, not a QUIC backend
    # substitution for direct or tunneled origin traffic.
    try:
        import pylsqpack
        from aioquic.buffer import Buffer, BufferReadError
        from aioquic.h3 import connection as h3
        from aioquic.h3 import events as http
        from aioquic.quic import events as quic
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.packet import QuicFrameType, pull_quic_transport_parameters
        from aioquic.quic.packet_builder import QuicDeliveryState, QuicPacketBuilderStop
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
    except ImportError:
        raise MasqueError("HTTP/3 MASQUE requires the ruyihttp[masque] extra") from None
    if version("aioquic").split(".", 2)[:2] != ["1", "3"]:
        raise MasqueError("HTTP/3 MASQUE requires aioquic >=1.3,<1.4")

    class OuterQuic(QuicConnection):
        peer_udp_size = 65527  # RFC 9000 §18.2 default in absence of parameter.
        _queued_probe = None
        built_probe = None

        def __init__(self, *, endpoint, cafile):
            super().__init__(configuration=QuicConfiguration(
                # TLS SNI is a DNS name without the final root dot (RFC 6066).
                is_client=True, alpn_protocols=["h3"], server_name=endpoint.host.rstrip("."),
                verify_mode=ssl.CERT_REQUIRED, cafile=cafile, session_ticket=None,
                idle_timeout=_IDLE_TIMEOUT, max_datagram_size=_OUTER_MAX,
                max_datagram_frame_size=_OUTER_MAX, max_data=131072, max_stream_data=32768,
            ))
            self._logger = logging.LoggerAdapter(_QUIET_QUIC, {})
            self._max_datagram_size = _OUTER_MIN
            self._local_max_streams_bidi.value = self._local_max_streams_bidi.sent = 0
            self._local_max_streams_uni.value = self._local_max_streams_uni.sent = 8

        def _parse_transport_parameters(self, data, from_session_ticket=False):
            super()._parse_transport_parameters(data, from_session_ticket)
            # aioquic 1.3 validates, but does not retain/enforce peer UDP payload size.
            params = pull_quic_transport_parameters(Buffer(data=data))
            if params.max_udp_payload_size is not None:
                self.peer_udp_size = params.max_udp_payload_size

        def check_server_certificate_usage(self):
            # aioquic's TLS verifier authenticates the name and chain, but its
            # OpenSSL store context has no declared leaf purpose. Enforce any
            # restrictions on the authenticated leaf before sending a request.
            cert = self.tls._peer_certificate
            if cert is None:
                raise SSLError("MASQUE proxy TLS did not authenticate a certificate")
            try:
                usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            except x509.ExtensionNotFound:
                pass
            else:
                if not usage.digital_signature:
                    raise SSLError("MASQUE proxy certificate disallows TLS signing")
            try:
                usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except x509.ExtensionNotFound:
                pass
            else:
                if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
                    raise SSLError("MASQUE proxy certificate disallows TLS server authentication")

        def start_probe(self, uid, size):
            # Each generation has its own private PING UID; it is not sent on wire.
            self._queued_probe = (uid, size)
            self.send_ping(uid)

        def cancel_probe(self):
            if self._queued_probe is not None:
                uid, _ = self._queued_probe
                self._queued_probe = None
                self._ping_pending.remove(uid)

        def datagrams_to_send(self, now):
            self.built_probe = None
            if self._queued_probe is None:
                return super().datagrams_to_send(now)
            # Raise the packet builder's ceiling only for this probe. A normal
            # QUIC PTO PING and the control streams use the validated ceiling.
            saved = self._max_datagram_size
            self._max_datagram_size = self._queued_probe[1]
            try:
                packets = super().datagrams_to_send(now)
            finally:
                self._max_datagram_size = saved
            if self.built_probe is not None:
                if len(packets) != 1 or len(packets[0][0]) != self.built_probe[1]:
                    raise MasqueError("Unexpected MASQUE MTU probe packet size")
            elif any(len(data) > saved for data, _ in packets):
                raise MasqueError("MASQUE QUIC packet exceeded the validated path size")
            return packets

        def _write_ping_frame(self, builder, uids=(), comment=""):
            probe = self._queued_probe
            if probe is None or probe[0] not in uids:
                return super()._write_ping_frame(builder, uids, comment)
            uid, size = probe
            # Handshake is confirmed; only 1-RTT short packets are emitted.
            # Include the actual AEAD tag in the size of the UDP payload.
            space = size - builder._buffer.tell() - builder._packet_crypto.aead_tag_size
            if space < 1 or min(builder.remaining_buffer_space, builder.remaining_flight_space) < space:
                raise QuicPacketBuilderStop
            super()._write_ping_frame(builder, (uid,), comment)
            if space > 1:
                buf = builder.start_frame(QuicFrameType.PADDING, capacity=space - 1)
                buf.push_bytes(bytes(space - 2))
            self.cancel_probe()
            self.built_probe = probe
            # Stop building at one padded datagram. This also keeps any STREAM
            # data from being sent in a probe and skips upstream's clear().
            raise QuicPacketBuilderStop

        def _on_ping_delivery(self, delivery, uids):
            if delivery != QuicDeliveryState.ACKED:
                # Recovery may probe again, but it may not replay a PMTU UID
                # in a shorter packet after the MASQUE search has moved on.
                uids = tuple(uid for uid in uids if uid >= 0)
            super()._on_ping_delivery(delivery, uids)

        def check_buffers(self):
            if len(self._streams) + len(self._streams_finished) > _MAX_STREAMS:
                self.close(error_code=h3.ErrorCode.H3_EXCESSIVE_LOAD)
            if any(len(stream.receiver._buffer) > _MAX_H3_BUFFER for stream in self._streams.values()):
                self.close(error_code=h3.ErrorCode.H3_EXCESSIVE_LOAD)

    class OuterHttp(h3.H3Connection):
        goaway = None

        def _init_connection(self):
            # This connection hosts one request. Static QPACK removes blocked
            # streams from consideration; no push grant or WebTransport is needed.
            self._max_push_id = None
            self._max_table_capacity = self._blocked_streams = 0
            self._decoder = pylsqpack.Decoder(0, 0)
            super()._init_connection()

        def _get_local_settings(self):
            settings = super()._get_local_settings()
            settings.pop(h3.Setting.ENABLE_CONNECT_PROTOCOL, None)
            settings[h3.Setting.H3_DATAGRAM] = 1
            settings[h3.Setting.MAX_FIELD_SECTION_SIZE] = _MAX_H3_FIELDS
            return settings

        def _handle_request_or_push_frame(self, frame_type, frame_data, stream, stream_ended):
            initial = stream.headers_recv_state == h3.HeadersState.INITIAL
            events = super()._handle_request_or_push_frame(frame_type, frame_data, stream, stream_ended)
            # aioquic 1.3 otherwise misclassifies the eventual final HEADERS as
            # trailers; reset inside the parser so coalesced HEADERS also work.
            if initial and frame_type == h3.FrameType.HEADERS:
                try:
                    status = _response_status(events[0].headers)
                except MasqueError as error:
                    raise h3.MessageError(str(error)) from None
                if status < 200:
                    stream.headers_recv_state = h3.HeadersState.INITIAL
                    stream.expected_content_length = None
            return events

        def handle_event(self, event):
            # The request-stream message error is stream-scoped in RFC 9114,
            # unlike H3 framing and SETTINGS errors. aioquic 1.3 closes the
            # connection for both; let the relay send the stream reset first.
            if self._is_done:
                return []
            try:
                if isinstance(event, quic.StreamDataReceived):
                    return self._receive_stream_data(event)
                if isinstance(event, quic.DatagramFrameReceived):
                    return self._receive_datagram(event.data)
            except h3.MessageError:
                raise CapsuleError("Malformed HTTP/3 response on MASQUE CONNECT stream") from None
            except BufferReadError:
                self._is_done = True
                self._quic.close(error_code=h3.ErrorCode.H3_FRAME_ERROR)
            except h3.ProtocolError as error:
                self._is_done = True
                self._quic.close(error_code=error.error_code)
            return []

        def _receive_datagram(self, data):
            events = super()._receive_datagram(data)
            if any(event.stream_id >= (1 << 62) for event in events):
                raise h3.DatagramError("Quarter Stream ID is too large")
            return events

        def _handle_control_frame(self, frame_type, frame_data):
            super()._handle_control_frame(frame_type, frame_data)
            if frame_type == h3.FrameType.GOAWAY:
                buf = Buffer(data=frame_data)
                try:
                    stream_id = buf.pull_uint_var()
                except BufferReadError:
                    stream_id = None
                if stream_id is None or not buf.eof():
                    error = h3.ProtocolError("Malformed GOAWAY frame")
                    error.error_code = h3.ErrorCode.H3_FRAME_ERROR
                    raise error
                if stream_id % 4 or (self.goaway is not None and stream_id > self.goaway):
                    error = h3.ProtocolError("Invalid GOAWAY stream ID")
                    error.error_code = h3.ErrorCode.H3_ID_ERROR
                    raise error
                self.goaway = stream_id

        def check_buffers(self):
            if any(len(stream.buffer) > _MAX_H3_BUFFER for stream in self._stream.values()):
                self._quic.close(error_code=h3.ErrorCode.H3_EXCESSIVE_LOAD)

    return OuterQuic, OuterHttp, quic, http, h3.ErrorCode, h3.Setting


def _network_error(event):
    code = event.error_code
    # TLS alert number in a QUIC CRYPTO_ERROR (RFC 9001 §4.8).
    if 0x100 <= code <= 0x1ff and event.frame_type == 0x06:
        if code - 0x100 in (42, 43, 44, 45, 46, 48, 116):
            return SSLError(f"MASQUE proxy TLS certificate verification failed (0x{code:x})")
        return SSLError(f"MASQUE proxy TLS handshake rejected (0x{code:x})")
    # Never include a peer-controlled reason string in exceptions or logs.
    return MasqueError(f"MASQUE outer QUIC/HTTP/3 connection closed (0x{code:x})")


class Tunnel:
    """Owns the connected loopback sockets; the caller must not close `.socket`."""

    def __init__(self, on_error):
        self.socket, self._relay = _udp_pair()
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._error = None
        self._info = {}
        self._thread = None
        self._on_error = on_error

    @property
    def error(self):
        with self._lock:
            return self._error

    @property
    def info(self):
        with self._lock:
            return self._info.copy()

    def _established(self, *, mtu, payload):
        with self._lock:
            self._info = {
                "transport": "masque", "alpn": "h3", "protocol": "connect-udp",
                "datagram_mode": "quic", "outer_udp_payload_size": mtu,
                "max_inner_udp_payload_size": payload, "verified": True,
            }
        self._ready.set()

    def _fail(self, error):
        with self._lock:
            if self._stop.is_set() or self._error is not None:
                return
            self._error = error
            callback = self._on_error
        self._ready.set()
        if callback is not None:
            try:
                callback()
            except Exception:
                pass  # Error remains latched for the consumer to observe.

    def close(self):
        with self._lock:
            self._stop.set()
            self._on_error = None
            self.socket.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join()
        self._relay.close()


def _sending_limit(settings, setting, remote_frame_size, peer_udp_size):
    for key in (setting.ENABLE_CONNECT_PROTOCOL, setting.H3_DATAGRAM):
        if type(settings.get(key)) is not int or settings[key] != 1:
            raise MasqueError(f"MASQUE proxy did not enable {key.name}")
    if type(remote_frame_size) is not int or remote_frame_size <= 0:
        raise MasqueError("MASQUE proxy did not enable QUIC DATAGRAM frames")
    path_size = min(peer_udp_size, _OUTER_MAX)
    limit = _path_payload_limit(path_size, remote_frame_size)
    if limit < _INNER_INITIAL:
        raise MasqueError("MASQUE proxy transport limits cannot carry the native 1252-byte QUIC Initial")
    return path_size, limit


def _path_payload_limit(size, frame_limit):
    return min(size - _SHORT_OVERHEAD - _FRAME_OVERHEAD, frame_limit - _FRAME_OVERHEAD)


class _MtuSearch:
    """Bounded, establishment-only forward path discovery (RFC 9000 §14.3)."""

    def __init__(self, ceiling, deadline):
        self._sizes = (ceiling, *(size for size in _MTU_STEPS if size < ceiling), _OUTER_FLOOR)
        self._index = 0
        self._deadline = deadline
        self.current = None
        self.due = 0.0

    def advance(self, now, pto):
        if self.current is not None and now < self.due:
            return None
        if self._index == len(self._sizes) or now >= self._deadline:
            raise ConnectTimeout("MASQUE outer path did not acknowledge a probe large enough for nested QUIC")
        size = self._sizes[self._index]
        self._index += 1
        self.current = (-self._index, size)
        # Reserve time for every later size (including one floor retry) and
        # the CONNECT response, while allowing several PTOs at each size.
        remaining_slots = len(self._sizes) - self._index + 2
        wait = min(max(3 * pto, 0.075), 0.75, (self._deadline - now) / remaining_slots)
        self.due = now + wait
        return self.current

    def acknowledged(self, uid):
        return self.current[1] if self.current is not None and self.current[0] == uid else None

    def rejected(self, uid):
        if self.acknowledged(uid) is not None:
            self.due = 0.0


class _Relay:
    def __init__(self, tunnel, proxy, headers, cafile, deadline, cancel_event, types):
        self.tunnel, self.proxy, self.headers = tunnel, proxy, headers
        self.deadline, self.cancel_event = deadline, cancel_event
        outer_quic, self.outer_http, self.quic, self.http, self.code, self.setting = types
        self.connection = outer_quic(endpoint=proxy, cafile=cafile)
        self.h3 = None
        self.request = None
        self.accepted = False
        self.limit = None
        self.mtu_size = None
        self.mtu_search = None
        self.capsules = CapsuleDecoder(_INNER_MAX)
        self.interim = 0

    def _reset(self, code):
        if self.request is not None:
            self.connection.reset_stream(self.request, code)
            if self.request in self.connection._streams:
                self.connection.stop_stream(self.request, code)

    def _maybe_request(self):
        if self.h3 is None or self.h3.received_settings is None:
            return
        if self.h3.goaway == 0:
            raise MasqueError("MASQUE proxy excluded CONNECT-UDP (HTTP/3 GOAWAY)")
        if self.request is not None:
            return
        now = time.monotonic()
        if self.mtu_search is None:
            ceiling, _ = _sending_limit(self.h3.received_settings, self.setting,
                self.connection._remote_max_datagram_frame_size, self.connection.peer_udp_size)
            if not self.connection._handshake_confirmed:
                return
            self.mtu_search = _MtuSearch(ceiling, self.deadline)
        if self.mtu_size is None:
            probe = self.mtu_search.advance(now, self.connection._loss.get_probe_timeout())
            if probe is not None:
                self.connection.cancel_probe()
                self.connection.start_probe(*probe)
        else:
            _remaining(self.deadline, self.cancel_event, self.tunnel._stop)
            self.request = self.connection.get_next_available_stream_id()
            self.h3.send_headers(self.request, self.headers, end_stream=False)
            self.headers = None

    def _incoming(self, datagram):
        try:
            self.tunnel._relay.send(datagram)
        except OSError as error:
            if not _would_block(error):
                raise

    def _handle_http(self, event):
        if self.request is None or event.stream_id != self.request:
            return
        if isinstance(event, self.http.HeadersReceived):
            if self.accepted:
                raise CapsuleError("Unexpected HEADERS after MASQUE CONNECT success")
            status = _response_status(event.headers)
            if status < 200:
                self.interim += 1
                if event.stream_ended or self.interim > 16:
                    raise CapsuleError("Invalid sequence of interim MASQUE responses")
                return
            if not 200 <= status <= 299:
                self._reset(self.code.H3_REQUEST_CANCELLED)
                raise MasqueError(f"MASQUE proxy CONNECT-UDP returned HTTP {status}")
            # RFC 9297 §§3.2/3.4: the recognized upgrade protocol establishes the
            # capsule data stream; echoing Capsule-Protocol is a SHOULD, not MUST.
            if status in (204, 205, 206) or any(name in (b"content-length", b"content-type",
                    b"transfer-encoding") for name, _ in event.headers):
                raise CapsuleError("Malformed successful MASQUE CONNECT-UDP response")
            self.accepted = True
        elif isinstance(event, self.http.DatagramReceived):
            if self.accepted and self.h3.received_settings.get(self.setting.H3_DATAGRAM) == 1:
                datagram = udp_payload(event.data, _INNER_MAX)
                if datagram is not None:
                    self._incoming(datagram)
            return
        elif isinstance(event, self.http.DataReceived):
            if not self.accepted:
                raise CapsuleError("MASQUE CONNECT stream ended before a final response")
            for datagram in self.capsules.feed(event.data):
                self._incoming(datagram)
        else:
            raise CapsuleError("Unexpected frame on MASQUE CONNECT stream")
        if event.stream_ended:
            self.capsules.finish()
            raise MasqueError("MASQUE proxy closed the CONNECT-UDP stream")

    def _process_events(self):
        self.connection.check_buffers()
        while True:
            if self.connection._close_event is not None:
                raise _network_error(self.connection._close_event)
            event = self.connection.next_event()
            if event is None:
                break
            if isinstance(event, self.quic.HandshakeCompleted):
                if event.alpn_protocol != "h3" or event.session_resumed or event.early_data_accepted:
                    raise SSLError("MASQUE proxy requires fresh authenticated h3 TLS without early data")
                self.connection.check_server_certificate_usage()
                self.h3 = self.outer_http(self.connection)
            elif isinstance(event, self.quic.PingAcknowledged) and self.mtu_search is not None:
                size = self.mtu_search.acknowledged(event.uid)
                if self.mtu_size is None and size is not None:
                    self.mtu_size = size
                    self.limit = _path_payload_limit(size, self.connection._remote_max_datagram_frame_size)
                    self.connection._max_datagram_size = size
            elif isinstance(event, (self.quic.StreamReset, self.quic.StopSendingReceived)):
                if self.request is not None and event.stream_id == self.request:
                    raise MasqueError(f"MASQUE proxy stopped the CONNECT-UDP stream (0x{event.error_code:x})")
                if self.h3 is not None and event.stream_id in (self.h3._peer_control_stream_id,
                        self.h3._peer_encoder_stream_id, self.h3._peer_decoder_stream_id,
                        self.h3._local_control_stream_id, self.h3._local_encoder_stream_id,
                        self.h3._local_decoder_stream_id):
                    self.connection.close(error_code=self.code.H3_CLOSED_CRITICAL_STREAM)
            if self.h3 is not None:
                try:
                    for part in self.h3.handle_event(event):
                        self._handle_http(part)
                    if (self.request is not None and isinstance(event, self.quic.StreamDataReceived)
                            and event.stream_id == self.request and event.end_stream):
                        raise CapsuleError("Truncated HTTP/3 frame on MASQUE CONNECT stream")
                except CapsuleError as error:
                    self._reset(self.code.H3_MESSAGE_ERROR)
                    raise MasqueError(str(error)) from None
                self.h3.check_buffers()
        self._maybe_request()
        if self.accepted and not self.tunnel._ready.is_set():
            self.tunnel._established(mtu=self.mtu_size, payload=self.limit)

    def _local_stop_requested(self):
        return self.tunnel._stop.is_set() or (
            self.cancel_event is not None and self.cancel_event.is_set()
        )

    def _flush(self, sock, *, teardown=False):
        if not teardown and self._local_stop_requested():
            return
        for packet, _address in self.connection.datagrams_to_send(now=time.monotonic()):
            # A caller may stop the tunnel while QUIC builds or sends a burst.
            # Do not submit the remaining prebuilt packets to the OS after stop.
            if not teardown and self._local_stop_requested():
                return
            # Connected socket fixes the UDP peer. QUIC migration to a different
            # address is deliberately outside the scope of this proxy session.
            try:
                sock.send(packet)
            except OSError as error:
                if _would_block(error):
                    continue  # Bound buffering; UDP/QUIC loss recovery applies.
                if error.errno == errno.EMSGSIZE or getattr(error, "winerror", None) == 10040:
                    probe = self.connection.built_probe
                    if probe is not None and self.mtu_size is None:
                        self.mtu_search.rejected(probe[0])
                        continue
                    raise MasqueError("MASQUE outer path MTU is too small for nested QUIC") from None
                raise

    def _drain_local(self):
        if not self.accepted:
            return
        for _ in range(_BURST):
            try:
                data = self.tunnel._relay.recv(65536)
            except BlockingIOError:
                break
            # A UDP datagram larger than the negotiated/path limit, or one
            # arriving at a full unreliable queue, is a deliberate UDP loss.
            if len(data) <= self.limit and len(self.connection._datagrams_pending) < _MAX_PENDING:
                self.h3.send_datagram(self.request, b"\x00" + data)

    def run(self, sock, address):
        with selectors.DefaultSelector() as selector:
            selector.register(sock, selectors.EVENT_READ)
            selector.register(self.tunnel._relay, selectors.EVENT_READ)
            self.connection.connect(address, now=time.monotonic())
            try:
                while not self.tunnel._stop.is_set():
                    wait = _POLL
                    if not self.accepted:
                        try:
                            wait = min(wait, _remaining(self.deadline, self.cancel_event, self.tunnel._stop))
                        except ConnectTimeout:
                            if self.mtu_search is not None and self.mtu_size is None:
                                raise ConnectTimeout("MASQUE outer path did not acknowledge a probe large enough for nested QUIC") from None
                            raise
                    elif self.cancel_event is not None and self.cancel_event.is_set():
                        return
                    timer = self.connection.get_timer()
                    now = time.monotonic()
                    if timer is not None and timer <= now:
                        self.connection.handle_timer(now=now)
                    self._process_events()
                    self._flush(sock)
                    timer = self.connection.get_timer()
                    now = time.monotonic()
                    if timer is not None:
                        wait = min(wait, max(0.0, timer - now))
                    if self.mtu_search is not None and self.mtu_size is None:
                        wait = min(wait, max(0.0, self.mtu_search.due - now))
                    for key, _ in selector.select(wait):
                        if key.fileobj is sock:
                            for _ in range(_BURST):
                                try:
                                    packet = sock.recv(65536)
                                except BlockingIOError:
                                    break
                                self.connection.receive_datagram(packet, address, now=time.monotonic())
                                self._process_events()
                        else:
                            self._drain_local()
            finally:
                self.connection.cancel_probe()
                self.connection._datagrams_pending.clear()
                try:
                    # With queued payloads cleared, still emit a requested
                    # stream reset and the final QUIC CONNECTION_CLOSE.
                    self._flush(sock, teardown=True)
                    self.connection.close(error_code=self.code.H3_NO_ERROR)
                    self._flush(sock, teardown=True)
                except Exception:
                    pass  # The socket is still closed by the worker's context.


def _would_block(error):
    return (isinstance(error, BlockingIOError) or error.errno == errno.ENOBUFS
            or getattr(error, "winerror", None) == 10055)


def open_tunnel(proxy_url, target_host, target_port, *, proxy_verify, timeout,
                cancel_event=None, on_error=None, path_template=None):
    """Open one explicit tunnel under a monotonic connect budget.

    `proxy_url` is an authority-only masque:// (or https://) URL. The named
    placeholders in an optional `path_template` may occur in its path or query.
    `on_error()` is a prompt wake callback; read the latched `.error` separately.
    """
    now = time.monotonic()
    if timeout is None:
        timeout = _DEFAULT_CONNECT_TIMEOUT
    if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout):
        raise ValueError("Invalid MASQUE connection timeout")
    deadline = now + timeout
    _remaining(deadline, cancel_event)
    proxy = parse_proxy(proxy_url)
    headers = connect_headers(proxy, target_path(target_host, target_port, path_template))
    cafile = _verify_path(proxy_verify)
    types = _aioquic()
    addresses = _resolve(proxy, deadline, cancel_event)
    _remaining(deadline, cancel_event)
    tunnel = Tunnel(on_error)

    def worker():
        try:
            # Only retry pre-handshake local setup/reachability failures, using
            # a different address of the same explicitly configured proxy.
            for family, address in addresses:
                _remaining(deadline, cancel_event, tunnel._stop)
                try:
                    sock = socket.socket(family, socket.SOCK_DGRAM)
                except OSError:
                    continue
                with sock:
                    try:
                        _no_fragment(sock, family)
                        sock.setblocking(False)
                        sock.connect(address)
                    except OSError:
                        continue
                    relay = _Relay(tunnel, proxy, headers, cafile, deadline, cancel_event, types)
                    try:
                        relay.run(sock, address)
                    except OSError as error:
                        # An immediately unreachable IPv6 address can otherwise
                        # hide a viable IPv4 address for the same proxy hostname.
                        if relay.h3 is None and (error.errno in (
                                errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH)
                                or getattr(error, "winerror", None) in (10051, 10054, 10065)):
                            continue
                        raise
                    return
            raise MasqueError("MASQUE proxy UDP socket setup failed")
        except (MasqueError, SSLError, ConnectTimeout) as error:
            tunnel._fail(error)
        except Exception:
            tunnel._fail(MasqueError("MASQUE outer transport failed"))
        finally:
            tunnel._relay.close()

    started = False
    try:
        tunnel._thread = threading.Thread(target=worker, name="ruyihttp-masque-outer", daemon=True)
        tunnel._thread.start()
        started = True
        while not tunnel._ready.is_set():
            if cancel_event is not None and cancel_event.is_set():
                raise MasqueError("MASQUE proxy connection cancelled")
            # The worker enforces the same budget and reports the failed phase.
            if time.monotonic() > deadline + _POLL:
                raise ConnectTimeout("MASQUE proxy connection deadline elapsed")
            tunnel._ready.wait(_POLL)
        if tunnel.error is not None:
            raise tunnel.error
        _remaining(deadline, cancel_event)
        return tunnel
    except BaseException:
        if not started:
            tunnel._thread = None
        tunnel.close()
        raise
