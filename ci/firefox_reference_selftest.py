#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Observer integration checks with independent CPython/h2/aioquic test clients."""

import asyncio
import ssl
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection
from aioquic.quic.configuration import QuicConfiguration
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ResponseReceived, StreamEnded

from firefox_reference_capture import certificate, validate
from firefox_reference_wire import BOOT, IP, PATH, Origin, grease_settings

UA = 'Mozilla/5.0 (test; rv:161.0) Gecko/20100101 Firefox/161.0'


def request(port, path, fetch=False):
    fields = [(':method', 'GET'), (':scheme', 'https'), (':authority', f'localhost:{port}'), (':path', path),
              ('user-agent', UA)]
    if fetch:
        fields += [('accept', '*/*'), ('referer', f'https://localhost:{port}/boot'), ('sec-fetch-dest', 'empty'),
                   ('sec-fetch-mode', 'cors'), ('sec-fetch-site', 'same-origin')]
    else:
        fields += [('sec-fetch-mode', 'navigate')]
    return [(key.encode(), value.encode()) for key, value in fields]


def verified(root, alpn):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=root.read_bytes())
    context.set_alpn_protocols([alpn])
    return context


async def h2_get(port, path, root):
    reader, writer = await asyncio.open_connection(IP, port, ssl=verified(root, 'h2'), server_hostname='localhost')
    try:
        http = H2Connection(H2Configuration(client_side=True))
        http.initiate_connection()
        http.send_headers(1, request(port, path), end_stream=True)
        writer.write(http.data_to_send())
        await writer.drain()
        status = None
        while data := await reader.read(65536):
            for event in http.receive_data(data):
                if isinstance(event, ResponseReceived):
                    status = int(dict(event.headers)[b':status'])
                if isinstance(event, StreamEnded):
                    return status
            writer.write(http.data_to_send())
            await writer.drain()
        raise RuntimeError('no fixture response')
    finally:
        writer.close()
        await writer.wait_closed()


async def h1_get(port, path, root):
    reader, writer = await asyncio.open_connection(IP, port, ssl=verified(root, 'http/1.1'), server_hostname='localhost')
    try:
        writer.write(f'GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n'.encode())
        await writer.drain()
        first_line = await reader.readline()
        return int(first_line.split()[1])
    finally:
        writer.close()
        await writer.wait_closed()


class ClientH3(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)

    def quic_event_received(self, event):
        self.http.handle_event(event)

    def get(self, port):
        stream = self._quic.get_next_available_stream_id()
        self.http.send_headers(stream, request(port, PATH, fetch=True), end_stream=True)
        self.transmit()


class CaptureObserverTest(unittest.IsolatedAsyncioTestCase):
    async def test_h1_trust_and_capture(self):
        with TemporaryDirectory() as directory:
            leaf, key, root = certificate(Path(directory))
            async with Origin('h1', leaf, key) as fixture:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    await asyncio.open_connection(IP, fixture.port, ssl=ssl.create_default_context(), server_hostname='localhost')
                reader, writer = await asyncio.open_connection(IP, fixture.port, ssl=verified(root, 'http/1.1'),
                                                               server_hostname='localhost')
                try:
                    writer.write(f'GET {PATH} HTTP/1.1\r\nHost: localhost:{fixture.port}\r\nUser-Agent: {UA}\r\n'
                                 'Sec-Fetch-Mode: navigate\r\n\r\n'.encode())
                    await writer.drain()
                    self.assertTrue((await reader.readline()).startswith(b'HTTP/1.1 200'))
                    observed = await asyncio.wait_for(fixture.result, 3)
                    validate('h1', observed, '161')
                    self.assertEqual(observed['headers'][1], ['User-Agent', UA])
                finally:
                    writer.close()
                    await writer.wait_closed()

    async def test_h2_order(self):
        with TemporaryDirectory() as directory:
            leaf, key, root = certificate(Path(directory))
            async with Origin('h2', leaf, key) as fixture:
                await h2_get(fixture.port, PATH, root)
                observed = await asyncio.wait_for(fixture.result, 3)
                validate('h2', observed, '161')
                self.assertEqual(observed['settings'][:3], [[1, 4096], [2, 1], [4, 65535]])

    async def test_h3_udp_only_and_raw_settings(self):
        with TemporaryDirectory() as directory:
            leaf, key, root = certificate(Path(directory))
            async with Origin('h3', leaf, key) as fixture:
                self.assertEqual(await h1_get(fixture.port, BOOT, root), 200)
                self.assertEqual(await h1_get(fixture.port, PATH, root), 503)
                conf = QuicConfiguration(is_client=True, alpn_protocols=['h3'], server_name='localhost',
                                         cadata=ssl.DER_cert_to_PEM_cert(root.read_bytes()).encode())
                async with connect(IP, fixture.port, configuration=conf, create_protocol=ClientH3) as client:
                    client.get(fixture.port)
                    observed = await asyncio.wait_for(fixture.result, 3)
                    validate('h3', observed, '161')
                    self.assertEqual(observed['grease_settings'], grease_settings(observed['settings']))
                    self.assertEqual(observed['hello']['offered_alpn'], ['h3'])
                    self.assertEqual(observed['quic_version'], 1)
                    self.assertEqual(observed['initial']['version'], 1)
                    self.assertGreaterEqual(observed['initial']['udp_payload_bytes'], 1200)
                    self.assertIn(observed['initial']['packet_number_length'], range(1, 5))
                    self.assertIn(4, observed['initial']['transport_parameter_ids'])


if __name__ == '__main__':
    unittest.main()
