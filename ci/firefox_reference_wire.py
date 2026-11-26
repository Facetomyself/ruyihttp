#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Independent loopback observers; retain native wire order and structural fields."""

import asyncio
import ssl
from collections import deque
from weakref import WeakKeyDictionary

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.buffer import Buffer
from aioquic.h3.connection import FrameType, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, StreamEnded

from firefox_quic_initial import QuicInitialObservation

IP = '127.0.0.1'
PATH = '/profile-wire'
BOOT = '/boot'
TP = frozenset({
    'ack_delay_exponent', 'active_connection_id_limit', 'disable_active_migration',
    'initial_max_data', 'initial_max_stream_data_bidi_local', 'initial_max_stream_data_bidi_remote',
    'initial_max_stream_data_uni', 'initial_max_streams_bidi', 'initial_max_streams_uni',
    'max_ack_delay', 'max_datagram_frame_size', 'max_idle_timeout', 'max_udp_payload_size',
})
BOOT_BODY = b'''<!doctype html><meta charset=utf-8><link rel=icon href="data:,"><script>
(async () => {
  for (let attempt = 0; attempt < 20; attempt++) {
    await new Promise(resolve => setTimeout(resolve, attempt ? 350 : 700));
    try {
      const r = await fetch('/profile-wire');
      if (r.ok && await r.text() === 'h3') return;
    } catch (_) {}
  }
})();
</script>'''
NAV_BODY = b'<!doctype html><link rel=icon href="data:,">wire reference'


class Vector:
    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    def __bool__(self):
        return self.pos < len(self.data)

    def take(self, size):
        result = self.data[self.pos:self.pos + size]
        if len(result) != size:
            raise ValueError('truncated TLS vector')
        self.pos += size
        return result

    def uint(self, size):
        return int.from_bytes(self.take(size), 'big')

    def vector(self, width):
        return Vector(self.take(self.uint(width)))

    def integers(self, width):
        values = []
        while self:
            values.append(self.uint(width))
        return values


def client_hello(message):
    handshake = Vector(message)
    if handshake.uint(1) != 1:
        raise ValueError('expected TLS ClientHello')
    body = handshake.vector(3)
    legacy = body.uint(2)
    body.take(32)  # Random bytes.
    session_id_length = len(body.vector(1).data)
    ciphers = body.vector(2).integers(2)
    compression = body.vector(1).integers(1)
    extensions = {}
    items = body.vector(2)
    while items:
        code = items.uint(2)
        if code in extensions:
            raise ValueError(f'duplicate TLS extension {code}')
        extensions[code] = items.vector(2)
    if body or handshake:
        raise ValueError('trailing TLS ClientHello bytes')

    def numbers(code, length_width, item_width=2):
        return extensions[code].vector(length_width).integers(item_width) if code in extensions else []

    share_groups, alpn, names = [], [], []
    if 51 in extensions:
        shares = extensions[51].vector(2)
        while shares:
            share_groups.append(shares.uint(2))
            shares.vector(2)  # Ephemeral key bytes.
    if 16 in extensions:
        offered = extensions[16].vector(2)
        while offered:
            alpn.append(bytes(offered.vector(1).data).decode('ascii'))
    if 0 in extensions:
        offered = extensions[0].vector(2)
        while offered:
            kind, name = offered.uint(1), bytes(offered.vector(2).data).decode('ascii')
            if name != 'localhost':
                raise ValueError('unexpected non-fixture TLS server name')
            names.append([kind, name])
    return {
        'legacy_version': legacy, 'session_id_length': session_id_length, 'ciphers': ciphers,
        'compression_methods': compression, 'extensions': list(extensions), 'groups': numbers(10, 2),
        'signatures': numbers(13, 2), 'cert_compression': numbers(27, 1), 'supported_versions': numbers(43, 1),
        'key_share_groups': share_groups, 'offered_alpn': alpn, 'ec_point_formats': numbers(11, 1, 1),
        'psk_key_exchange_modes': numbers(45, 1, 1), 'server_names': names,
    }


def headers_text(headers):
    return [[name.decode('ascii'), value.decode('latin-1')] for name, value in headers]


def alpn_context(leaf, key, alpn, hellos):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_alpn_protocols([alpn])
    context.load_cert_chain(leaf, key)

    def on_message(tls, direction, _version, content, message, data):
        if direction == 'read' and content == 22 and message == 1:
            hellos.setdefault(tls, []).append(client_hello(data))

    context._msg_callback = on_message
    return context


def grease_settings(settings):
    return [[i, code, value] for i, (code, value) in enumerate(settings) if code >= 0x21 and (code - 0x21) % 0x1F == 0]


class WireH3(H3Connection):
    """Tap the unmodified SETTINGS frame payload before aioquic parses it."""

    def __init__(self, quic):
        self.raw_settings = None
        super().__init__(quic)

    def _handle_control_frame(self, frame_type, frame_data):
        if frame_type == FrameType.SETTINGS and self.raw_settings is None:
            buffer = Buffer(data=frame_data)
            self.raw_settings = []
            while not buffer.eof():
                self.raw_settings.append([buffer.pull_uint_var(), buffer.pull_uint_var()])
        return super()._handle_control_frame(frame_type, frame_data)


class Origin:
    def __init__(self, case, leaf, key):
        self.case = case
        self.leaf, self.key = leaf, key
        self.result = asyncio.get_running_loop().create_future()
        self.hellos = WeakKeyDictionary()
        self.bootstrap = []
        self.other_paths = []
        self.errors = deque(maxlen=10)
        self.tasks = set()
        self.tcp = self.udp = None
        self.quic_log = QuicLogger() if case == 'h3' else None

    async def __aenter__(self):
        alpn = 'http/1.1' if self.case == 'h1' else 'h2'
        context = alpn_context(self.leaf, self.key, alpn, self.hellos)
        self.tcp = await asyncio.start_server(self.accept, IP, 0, ssl=context, ssl_handshake_timeout=8)
        self.port = self.tcp.sockets[0].getsockname()[1]
        if self.case == 'h3':
            try:
                conf = QuicConfiguration(is_client=False, alpn_protocols=['h3'], quic_logger=self.quic_log)
                conf.load_cert_chain(self.leaf, self.key)
                self.udp = await serve(IP, self.port, configuration=conf, create_protocol=self.h3_protocol())
            except BaseException:
                self.tcp.close()
                await self.tcp.wait_closed()
                raise
        return self

    async def __aexit__(self, *_exc):
        if self.udp is not None:
            self.udp.close()
        self.tcp.close()
        await self.tcp.wait_closed()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    @property
    def url(self):
        return f'https://localhost:{self.port}' + (BOOT if self.case == 'h3' else PATH)

    def finish(self, record):
        if not self.result.done():
            self.result.set_result(record)

    def accept(self, reader, writer):
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def handle(self, reader, writer):
        try:
            tls = writer.get_extra_info('ssl_object')
            base = {'hello': self.hellos[tls][0], 'client_hello_count': len(self.hellos[tls]),
                    'protocol': tls.selected_alpn_protocol(), 'port': self.port, 'mode': 'navigation',
                    'negotiated_tls': {'version': tls.version(), 'cipher': tls.cipher()[0]}}
            if self.case == 'h1':
                await self.h1(reader, writer, base)
            else:
                await self.h2(reader, writer, base)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError) as exc:
            self.errors.append(type(exc).__name__)
        except Exception as exc:
            self.errors.append(repr(exc))
        finally:
            writer.close()

    def extra(self, protocol, path):
        if len(self.other_paths) < 10:
            self.other_paths.append([protocol, path])

    async def h1(self, reader, writer, base):
        line = (await reader.readline()).rstrip(b'\r\n')
        if not line:
            return
        headers = []
        while (row := await reader.readline()) not in (b'\r\n', b''):
            name, value = row.rstrip(b'\r\n').split(b':', 1)
            headers.append((name, value.strip(b' \t')))
        if row != b'\r\n':
            return
        if line != f'GET {PATH} HTTP/1.1'.encode('ascii'):
            self.extra('h1', line.decode('ascii'))
            return
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nConnection: close\r\n'
                     + f'Content-Length: {len(NAV_BODY)}\r\n\r\n'.encode('ascii') + NAV_BODY)
        await writer.drain()
        self.finish(dict(base, request_line=line.decode('ascii'), headers=headers_text(headers)))

    async def h2(self, reader, writer, base):
        if base['protocol'] != 'h2':
            raise ValueError('H2 fixture negotiated another application protocol')
        http = H2Connection(H2Configuration(client_side=False, normalize_inbound_headers=False))
        http.initiate_connection()
        writer.write(http.data_to_send())
        await writer.drain()
        http.receive_data(await reader.readexactly(24))
        settings = None
        requests = {}
        while True:
            head = await reader.readexactly(9)
            payload = await reader.readexactly(int.from_bytes(head[:3], 'big'))
            if head[3] == 4 and not head[4] & 1 and settings is None:
                settings = [[int.from_bytes(payload[i:i+2], 'big'), int.from_bytes(payload[i+2:i+6], 'big')]
                            for i in range(0, len(payload), 6)]
            for event in http.receive_data(head + payload):
                if isinstance(event, RequestReceived):
                    requests[event.stream_id] = headers_text(event.headers)
                if not isinstance(event, StreamEnded):
                    continue
                stream = event.stream_id
                headers = requests.pop(stream)
                fields = dict(headers)
                expected = BOOT if self.case == 'h3' else PATH
                if (fields.get(':method'), fields.get(':path')) != ('GET', expected):
                    self.extra('h2', fields.get(':path'))
                    http.send_headers(stream, [(b':status', b'404')], end_stream=True)
                    continue
                body = BOOT_BODY if self.case == 'h3' else NAV_BODY
                response = [(b':status', b'200'), (b'content-type', b'text/html'), (b'cache-control', b'no-store'),
                            (b'content-length', str(len(body)).encode('ascii'))]
                record = dict(base, settings=settings, headers=headers)
                if self.case == 'h3':
                    response += [(b'alt-svc', f'h3=":{self.port}"; ma=60'.encode('ascii'))]
                    self.bootstrap.append(record)
                    self.tcp.close()  # No TCP route can satisfy the strict H3 fetch.
                http.send_headers(stream, response)
                http.send_data(stream, body, end_stream=True)
                if self.case == 'h3':
                    http.close_connection(error_code=0, last_stream_id=stream)
                writer.write(http.data_to_send())
                await writer.drain()
                if self.case == 'h2':
                    self.finish(record)
                return
            writer.write(http.data_to_send())
            await writer.drain()

    def h3_protocol(self):
        origin = self

        class Protocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.initial = QuicInitialObservation(self._quic)
                self.http = WireH3(self._quic)
                self.handshake = None
                self.hello = None
                initialize = self._quic._initialize

                def tap_initialize(*init_args):
                    initialize(*init_args)
                    handler = self._quic.tls._server_handle_hello

                    def tap_hello(input_buf, *output_bufs):
                        self.hello = client_hello(input_buf.data_slice(input_buf.tell(), input_buf.capacity))
                        return handler(input_buf, *output_bufs)

                    self._quic.tls._server_handle_hello = tap_hello

                self._quic._initialize = tap_initialize

            def quic_event_received(self, event):
                if isinstance(event, HandshakeCompleted):
                    self.handshake = event
                for message in self.http.handle_event(event):
                    if not isinstance(message, HeadersReceived) or message.push_id is not None:
                        continue
                    headers = headers_text(message.headers)
                    fields = dict(headers)
                    if fields.get(':path') != PATH or fields.get(':method') != 'GET':
                        origin.extra('h3', fields.get(':path'))
                        self.http.send_headers(message.stream_id, [(b':status', b'404')], end_stream=True)
                        continue
                    log = self._quic._quic_logger.to_dict()
                    remote = [event['data'] for event in log['events']
                              if event['name'] == 'transport:parameters_set' and event['data']['owner'] == 'remote']
                    settings = self.http.raw_settings
                    if len(remote) != 1 or settings is None or self.handshake is None or self.hello is None:
                        origin.errors.append('missing QUIC handshake, peer parameters, H3 SETTINGS or ClientHello')
                        return
                    try:
                        initial = self.initial.result()
                    except ValueError as exc:
                        origin.errors.append(f'Initial observer: {exc}')
                        return
                    self.http.send_headers(message.stream_id, [(b':status', b'200'), (b'content-length', b'2'),
                                                               (b'cache-control', b'no-store')])
                    self.http.send_data(message.stream_id, b'h3', end_stream=True)
                    self.transmit()
                    origin.finish({'port': origin.port, 'mode': 'same-origin-fetch', 'protocol': self.handshake.alpn_protocol,
                                   'quic_version': int(self._quic._version), 'initial': initial, 'hello': self.hello,
                                   'settings': settings, 'grease_settings': grease_settings(settings), 'headers': headers,
                                   'transport_parameters': {k: remote[0][k] for k in sorted(TP & remote[0].keys())},
                                   'bootstrap': list(origin.bootstrap)})

        return Protocol

    def diagnostics(self):
        return {'case': self.case, 'port': self.port, 'bootstrap': self.bootstrap,
                'other_paths': self.other_paths, 'server_errors': list(self.errors),
                'quic_traces': len(self.quic_log.to_dict()['traces']) if self.quic_log else 0}
