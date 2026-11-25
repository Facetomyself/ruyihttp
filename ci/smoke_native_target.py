#!/usr/bin/env python3
"""Verify native versions and real loopback HTTP/2 and QUIC from an installed wheel."""
import asyncio
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import json
import platform
import socket
import ssl
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
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
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
    ca_key = generate_private_key(SECP256R1())
    server_key = generate_private_key(SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'RuyiHttp native test CA')])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)

    def builder(subject, public_key, ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))

    ca = builder(ca_name, ca_key.public_key(), True).sign(ca_key, hashes.SHA256())
    cert = (builder(server_name, server_key.public_key(), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    root.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return leaf, key, root


def serve_h2_once(listener, context, port, completed, release):
    try:
        listener.settimeout(10)
        client, _ = listener.accept()
        # Close the listener to make the second request's TCP fallback fail,
        # while keeping this TLS session alive until the H2 reader consumes it.
        listener.close()
        client.settimeout(10)
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
                        completed.set()
                        if not release.wait(25):
                            raise TimeoutError('client did not finish native protocol smoke')
                        return
                tls.sendall(protocol.data_to_send())
            raise AssertionError('no HTTP/2 request received')
    finally:
        listener.close()
        completed.set()


def fetch(url, roots, completed, manifest):
    with ruyihttp.Session(firefox='159', verify=str(roots), timeout=10) as session:
        session.trust_env = False
        for expected in ('h2', 'h3'):
            response = session.get(url)
            assert response.status_code == 200 and response.content == expected.encode(), response
            assert response.raw.version == (20 if expected == 'h2' else 30), response.raw.version
            print(expected, response.status_code, response.raw.version, response.tls, flush=True)
            shape = manifest.get('h3_tls', 'nss') if expected == 'h3' else 'nss'
            if shape == 'null':
                assert response.tls is None, response.tls
            elif shape == 'windows-legacy':
                assert response.tls['backend'] == 'NSS/Neqo' and response.tls['alpn'] == 'h3', response.tls
            else:
                assert shape == 'nss', shape
                assert response.tls['alpn'] == expected and response.tls['backend'] == 'NSS', response.tls
                assert response.tls['nss'] == manifest['nss'], response.tls
            assert completed.wait(10)


async def test_transactions(manifest):
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
        completed, release = threading.Event(), threading.Event()
        h2_worker = executor.submit(serve_h2_once, tcp, context, port, completed, release)
        try:
            await asyncio.to_thread(fetch, f'https://localhost:{port}/', roots, completed, manifest)
        finally:
            release.set()
            server.close()
        h2_worker.result(10)


def check_loaded_libraries(root, target, files):
    if target == 'win_amd64':
        from ctypes import wintypes

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel.GetModuleHandleW.restype = wintypes.HMODULE
        kernel.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
        kernel.GetModuleFileNameW.restype = wintypes.DWORD
        paths = set()
        for name in files:
            module = kernel.GetModuleHandleW(name)
            if module:
                dest = ctypes.create_unicode_buffer(32768)
                assert 0 < kernel.GetModuleFileNameW(module, dest, len(dest)) < len(dest)
                paths.add(Path(dest.value).resolve())
        required = {'necko_core.dll', 'necko_quic.dll', 'nss3.dll', 'mozglue.dll'}
    elif target.startswith('linux_'):
        maps = Path('/proc/self/maps').read_text().splitlines()
        paths = {Path(row.split(maxsplit=5)[5]).resolve() for row in maps
                 if len(row.split(maxsplit=5)) == 6 and row.split(maxsplit=5)[5].startswith('/')}
        required = {'libnecko_core.so', 'libnecko_quic.so', 'libnss3.so', 'libnspr4.so'}
    else:
        dyld = ctypes.CDLL(None)
        dyld._dyld_image_count.restype = ctypes.c_uint32
        dyld._dyld_get_image_name.argtypes = [ctypes.c_uint32]
        dyld._dyld_get_image_name.restype = ctypes.c_char_p
        paths = {Path(p.decode()).resolve() for p in
                 (dyld._dyld_get_image_name(i) for i in range(dyld._dyld_image_count())) if p}
        required = {'libnecko_core.dylib', 'libnecko_quic.dylib', 'libnss3.dylib', 'libmozglue.dylib'}
    observed = {path for path in paths if path.name in files}
    assert required <= {path.name for path in observed}, observed
    assert all(path.parent == root for path in observed), observed
    print('loaded sibling libraries:', ', '.join(sorted(p.name for p in observed)), flush=True)


def main():
    target = sys.argv[1]
    expected = {'win_amd64': ('Windows', {'amd64', 'x86_64'}, '.dll', 6),
                'linux_aarch64': ('Linux', {'aarch64'}, '.so', 14),
                'linux_x86_64': ('Linux', {'x86_64'}, '.so', 14),
                'darwin_x86_64': ('Darwin', {'x86_64'}, '.dylib', 6),
                'darwin_arm64': ('Darwin', {'arm64'}, '.dylib', 6)}
    os_name, arches, suffix, count = expected[target]
    assert platform.system() == os_name and platform.machine().lower() in arches
    if os_name == 'Darwin':
        translated = __import__('subprocess').check_output(['sysctl', '-in', 'sysctl.proc_translated'], text=True).strip()
        assert translated in ('', '0'), translated
        print(f'Rosetta translation: {translated or 0}', flush=True)
    root = Path(ruyihttp.__file__).resolve().parent
    assert root.is_relative_to(Path(sys.prefix).resolve()), root
    manifest = json.loads((root / 'runtime-manifest.json').read_text())['platforms'][target]
    files = manifest['files']
    assert len(files) == count and {p.name for p in root.glob('*' + suffix)} == files.keys()
    for name, digest in files.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    library = _load_library()
    prefix = '' if os_name == 'Windows' else 'lib'
    assert Path(library._name).resolve() == root / (prefix + 'necko_core' + suffix)
    nss = library.necko_tls_nss_version().decode()
    nspr = library.necko_tls_nspr_version().decode()
    assert (nss, nspr) == (manifest['nss'], manifest['nspr']), (nss, nspr)
    quic = ctypes.CDLL(str(root / (prefix + 'necko_quic' + suffix)))
    assert quic.necko_quic_call and quic.necko_quic_set_decoder
    quic.necko_quic_version.argtypes = []
    quic.necko_quic_version.restype = ctypes.c_char_p
    quic_version = quic.necko_quic_version().decode()
    print(target, sys.version.split()[0], root, manifest.get('wheel_platform_tag'),
          'native hashes', count, 'NSS', nss, 'NSPR', nspr, 'QUIC', quic_version, flush=True)
    assert quic_version == f"neqo-{manifest['neqo']}/nss-{nss}", quic_version
    body_version = getattr(quic, 'necko_quic_body_abi_version', None)
    actual_abi = None
    if body_version is not None:
        body_version.argtypes = []
        body_version.restype = ctypes.c_uint32
        actual_abi = body_version()
        assert quic.necko_quic_body_read_v1 and quic.necko_quic_body_write_v1
    print(f'H3 binary body ABI: {actual_abi!r}', flush=True)
    assert actual_abi == manifest.get('h3_body_abi'), (actual_abi, manifest.get('h3_body_abi'))
    asyncio.run(test_transactions(manifest))
    check_loaded_libraries(root, target, files)


if __name__ == '__main__':
    main()
