#!/usr/bin/env python3
"""Verify native versions and real loopback HTTP/2 and QUIC from an installed wheel."""
import asyncio
import ctypes
import hashlib
import json
import platform
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import ruyihttp
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamEnded
from ruyihttp._transport import _load_library


class H3Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)

    def quic_event_received(self, event):
        for message in self.http.handle_event(event):
            if isinstance(message, HeadersReceived):
                self.http.send_headers(message.stream_id, [(b':status', b'200'), (b'content-length', b'2')])
                self.http.send_data(message.stream_id, b'h3', end_stream=True)
                self.transmit()


def certificate(directory):
    key = directory / 'key.pem'
    leaf = directory / 'leaf.pem'
    root = directory / 'ca.pem'
    req = directory / 'leaf.csr'
    extensions = directory / 'leaf-extensions.cnf'
    extensions.write_text('subjectAltName=DNS:localhost\nkeyUsage=digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n')
    def run(*args):
        subprocess.run(['openssl', *args], cwd=directory, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run('req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-keyout', 'ca-key.pem', '-out', root,
        '-days', '2', '-subj', '/CN=RuyiHttp native test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    run('req', '-nodes', '-newkey', 'rsa:2048', '-keyout', key, '-out', req, '-subj', '/CN=localhost')
    run('x509', '-req', '-in', req, '-CA', root, '-CAkey', 'ca-key.pem', '-set_serial', '1',
        '-out', leaf, '-days', '1', '-extfile', extensions)
    return leaf, key, root


def serve_h2_once(listener, context, port, completed):
    try:
        listener.settimeout(10)
        client, _ = listener.accept()
        with client, context.wrap_socket(client, server_side=True) as tls:
            assert tls.selected_alpn_protocol() == 'h2'
            protocol = H2Connection(config=H2Configuration(client_side=False))
            protocol.initiate_connection()
            tls.sendall(protocol.data_to_send())
            while data := tls.recv(65536):
                for event in protocol.receive_data(data):
                    if isinstance(event, StreamEnded):
                        protocol.send_headers(event.stream_id, [(b':status', b'200'), (b'content-length', b'2'),
                            (b'alt-svc', f'h3="127.0.0.1:{port}"; ma=60'.encode())])
                        protocol.send_data(event.stream_id, b'h2', end_stream=True)
                        tls.sendall(protocol.data_to_send())
                        return
                tls.sendall(protocol.data_to_send())
            raise AssertionError('no HTTP/2 request received')
    finally:
        listener.close()
        completed.set()


def fetch(url, roots, completed):
    with ruyihttp.Session(firefox='159', verify=str(roots), timeout=10) as session:
        session.trust_env = False
        for expected in ('h2', 'h3'):
            response = session.get(url)
            assert response.status_code == 200 and response.content == expected.encode(), response
            assert response.tls.get('alpn') == expected, response.tls
            assert response.tls.get('backend') == 'NSS' and response.tls.get('nss') == '3.132', response.tls
            print(expected, response.status_code, response.tls, flush=True)
            assert completed.wait(10)


async def test_transactions():
    with tempfile.TemporaryDirectory() as temp, socket.socket() as tcp, ThreadPoolExecutor(1) as executor:
        leaf, key, roots = certificate(Path(temp))
        tcp.bind(('127.0.0.1', 0))
        tcp.listen()
        port = tcp.getsockname()[1]
        quic = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        quic.load_cert_chain(leaf, key)
        server = await serve('127.0.0.1', port, configuration=quic, create_protocol=H3Server)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_alpn_protocols(['h2'])
        context.load_cert_chain(leaf, key)
        completed = threading.Event()
        h2_worker = executor.submit(serve_h2_once, tcp, context, port, completed)
        try:
            await asyncio.to_thread(fetch, f'https://localhost:{port}/', roots, completed)
            h2_worker.result(10)
        finally:
            server.close()


def main():
    target = sys.argv[1]
    expected = {'linux_aarch64': ('Linux', 'aarch64', '.so', 14),
                'darwin_x86_64': ('Darwin', 'x86_64', '.dylib', 6)}
    os_name, arch, suffix, count = expected[target]
    assert (platform.system(), platform.machine()) == (os_name, arch)
    root = Path(ruyihttp.__file__).resolve().parent
    assert root.is_relative_to(Path(sys.prefix).resolve()), root
    manifest = json.loads((root / 'runtime-manifest.json').read_text())['platforms'][target]
    files = manifest['files']
    assert len(files) == count and {p.name for p in root.glob('*' + suffix)} == files.keys()
    for name, digest in files.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    library = _load_library()
    assert Path(library._name).resolve() == root / ('libnecko_core' + suffix)
    assert library.necko_tls_nss_version().decode() == manifest['nss']
    assert library.necko_tls_nspr_version().decode() == manifest['nspr']
    quic = ctypes.CDLL(str(root / ('libnecko_quic' + suffix)))
    assert quic.necko_quic_call and quic.necko_quic_set_decoder
    print(target, sys.version.split()[0], root, manifest['wheel_platform_tag'],
          'native hashes', count, 'NSS', manifest['nss'], 'NSPR', manifest['nspr'], flush=True)
    asyncio.run(test_transactions())


if __name__ == '__main__':
    main()
