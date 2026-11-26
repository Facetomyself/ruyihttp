#!/usr/bin/env python3
"""Drive the installed POSIX QUIC bridge against real QUIC/H3 peers on loopback."""

import asyncio
import base64
import ctypes as ct
import json
from pathlib import Path
import socket
import sys
import tempfile

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicProtocolVersion
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import ruyihttp
from ruyihttp._firefox import PROFILES, quic_profile
from ruyihttp._transport import _load_library

# Import a trusted CI helper even under Python -I; product imports stay installed.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_native_target import certificate

V1, V2 = QuicProtocolVersion.VERSION_1, QuicProtocolVersion.VERSION_2
CONNECT = Setting.ENABLE_CONNECT_PROTOCOL
WT = Setting.ENABLE_WEBTRANSPORT
MAX_WINDOWS = {'initial_max_data': 25165824, 'initial_max_stream_data_bidi_local': 12582912}


class Origin(QuicConnectionProtocol):
    def __init__(self, *args, peer_connect, observed, **kwargs):
        super().__init__(*args, **kwargs)
        self.observed = observed

        class PeerHTTP3(H3Connection):
            def _get_local_settings(self):
                settings = super()._get_local_settings()
                if not peer_connect:
                    del settings[CONNECT]
                return settings

        self.http = PeerHTTP3(self._quic)
        assert (self.http.sent_settings.get(CONNECT) == 1) == peer_connect

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            assert event.alpn_protocol == 'h3'
            version_info = self._quic._remote_version_information
            # RFC 9368 reserves versions with low nibble 0xa in each byte.
            # Retain every real advertised version and its offered order.
            versions = [v for v in version_info.available_versions if v & 0x0f0f0f0f != 0x0a0a0a0a]
            self.observed.update(version=int(self._quic._version),
                                 initial=int(version_info.chosen_version), available=versions)
        for message in self.http.handle_event(event):
            if isinstance(message, HeadersReceived):
                self.observed.setdefault('requests', []).append(dict(message.headers))
                self.http.send_headers(message.stream_id, [(b':status', b'204')], end_stream=True)
                self.transmit()
        if self.http.received_settings is not None:
            self.observed['settings'] = {
                int(key): value for key, value in self.http.received_settings.items()
                if key < 0x21 or (key - 0x21) % 0x1f
            }


def bridge(slot):
    root = Path(ruyihttp.__file__).resolve().parent
    core = _load_library()
    assert Path(core._name).resolve().parent == root
    assert core.necko_tls_nss_version() == b'3.133' and core.necko_tls_nspr_version() == b'4.40'
    suffix = '.dylib' if slot.startswith('darwin_') else '.so'
    library = ct.CDLL(str(root / ('libnecko_quic' + suffix)))
    abi = library.necko_quic_body_abi_version
    abi.argtypes, abi.restype = [], ct.c_uint32
    assert abi() == 1 and library.necko_quic_body_read_v1 and library.necko_quic_body_write_v1
    call = library.necko_quic_call
    call.argtypes = [ct.c_uint64, ct.c_char_p, ct.c_size_t]
    call.restype = ct.c_char_p

    def command(handle, op, **fields):
        data = json.dumps({'op': op, **fields}, separators=(',', ':')).encode('ascii')
        return json.loads(call(handle, data, len(data)))

    return command


def profile_contract():
    for version in range(100, 162):
        key = str(version)
        original = PROFILES[key]['quic']
        assert quic_profile(key, 'win_amd64') == original
        for platform in ('linux', 'darwin'):
            profile = quic_profile(key, platform)
            assert {k: profile[k] for k in original} == original
            assert profile['version2'] is (version >= 155)
            assert profile['h3_connect'] is (version >= 145)
            assert (profile['max_data'], profile['max_stream_data_bidi_local']) == (25165824, 12582912)


async def transactions(call, cert, version, profile, offered, peer_connect=True):
    leaf, key, _ = cert
    der = x509.load_pem_x509_certificate(leaf.read_bytes()).public_bytes(Encoding.DER)
    log = QuicLogger()
    config = QuicConfiguration(is_client=False, alpn_protocols=['h3'], quic_logger=log,
                               supported_versions=list(offered))
    config.load_cert_chain(leaf, key)
    observed = {}
    server = await serve('127.0.0.1', 0, configuration=config,
                         create_protocol=lambda *a, **kw: Origin(*a, observed=observed,
                                                                  peer_connect=peer_connect, **kw))
    port = server._transport.get_extra_info('sockname')[1]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.connect(('127.0.0.1', port))
            udp.setblocking(False)
            args = dict(host='localhost', local=f'127.0.0.1:{udp.getsockname()[1]}',
                        remote=f'127.0.0.1:{port}', firefox=version, profile=profile)
            reply = call(0, 'new', **args)
            assert 'handle' in reply, reply
            handle = reply['handle']

            def ok(op, **fields):
                reply = call(handle, op, **fields)
                assert 'error' not in reply, (op, reply)
                return reply

            async def wait(predicate):
                deadline = asyncio.get_running_loop().time() + 8
                while asyncio.get_running_loop().time() < deadline:
                    ok('pump')
                    for event in ok('events')['events']:
                        if event['type'] == 'auth':
                            assert base64.b64decode(event['certificates'][0]) == der
                            ok('auth', accepted=True)
                        if predicate(event):
                            return event
                        assert event.get('state') != 'closed', event
                    await asyncio.sleep(0.002)
                raise AssertionError(f'{version}: native QUIC did not reach expected state: {observed!r}')

            try:
                ok('attach', socket=udp.fileno())
                await wait(lambda event: event.get('state') == 'connected')
                fields = dict(authority=f'localhost:{port}', path='/policy', headers=[])
                stream = ok('fetch', method='GET', **fields)['stream']
                ok('finish', stream=stream)
                response = await wait(lambda event: event['type'] == 'headers' and event['stream'] == stream)
                assert [':status', 'MjA0'] in response['headers'], response

                # The bridge is client-only. Ordinary fetch cannot create a
                # tunnel and the H3 knob does not grant a generic CONNECT or WT op.
                assert 'error' in call(handle, 'fetch', method='CONNECT', **fields)
                assert 'error' in call(handle, 'connect', **fields)
                assert 'error' in call(handle, 'webtransport', action='open', **fields)
                ok('pump')
                await asyncio.sleep(0.01)
                assert len(observed['requests']) == 1 and observed['requests'][0][b':method'] == b'GET'
                assert b':protocol' not in observed['requests'][0]
            finally:
                call(handle, 'close')
    finally:
        server.close()

    transport = [event['data'] for trace in log.to_dict()['traces'] for event in trace['events']
                 if event['name'] == 'transport:parameters_set' and event['data']['owner'] == 'remote']
    parameters, = transport
    return {**observed, 'windows': {key: parameters[key] for key in MAX_WINDOWS}}


def invalid_preferences(call, profile):
    for field, value in (('max_data', -1), ('max_data', 1 << 62),
                         ('max_stream_data_bidi_local', True), ('max_stream_data_bidi_local', 1 << 62),
                         ('h3_connect', 'true')):
        reply = call(0, 'new', host='localhost', local='127.0.0.1:31111', remote='127.0.0.1:31112',
                     firefox='161', profile=dict(profile, **{field: value}))
        if 'handle' in reply:
            call(reply['handle'], 'close')
        assert reply.get('error') == f'Invalid {field} preference', reply


async def policy(slot):
    call = bridge(slot)
    profile_contract()
    platform = 'darwin' if slot.startswith('darwin_') else 'linux'
    current = quic_profile('161', platform)
    both = (V1, V2)
    with tempfile.TemporaryDirectory() as temp:
        cert = certificate(Path(temp))
        for version in ('144', '145', '154', '155', '159', '160', '161'):
            profile = quic_profile(version, platform)
            observed = await transactions(call, cert, version, profile, both)
            assert observed['initial'] == V1, observed
            assert observed['available'] == ([V2, V1] if profile['version2'] else [V1]), observed
            assert observed['version'] == (V2 if profile['version2'] else V1), observed
            assert observed['settings'].get(CONNECT) == (1 if profile['h3_connect'] else None), observed
            assert observed['settings'].get(WT, 0) == 0 and observed['windows'] == MAX_WINDOWS, observed
            print(f'Firefox {version}: Initial=v1 negotiated=0x{observed["version"]:08x} '
                  f'CONNECT={observed["settings"].get(CONNECT)} windows={observed["windows"]}', flush=True)

        observed = await transactions(call, cert, '161', current, (V1,), peer_connect=False)
        assert observed['initial'] == observed['version'] == V1 and observed['available'] == [V2, V1], observed
        assert observed['settings'][CONNECT] == 1 and observed['settings'].get(WT, 0) == 0, observed
        print('v1-only peer without CONNECT: negotiated v1; client advertises id8, GET only', flush=True)

        missing = {key: value for key, value in current.items() if key != 'h3_connect'}
        observed = await transactions(call, cert, '161', missing, both)
        assert CONNECT not in observed['settings'] and observed['settings'].get(WT, 0) == 0, observed
        print('Missing h3_connect preference: id8 absent', flush=True)

        shuffled = dict(reversed(tuple(current.items())))
        shuffled.update(max_data=37901531, max_stream_data_bidi_local=8780123)
        observed = await transactions(call, cert, '161', shuffled, both)
        assert observed['windows'] == {'initial_max_data': 37901531,
                                       'initial_max_stream_data_bidi_local': 8780123}, observed
        assert observed['settings'][CONNECT] == 1 and observed['version'] == V2, observed
        print('Shuffled profile keys: explicit receive windows reached the correct wire fields', flush=True)

    invalid_preferences(call, current)
    print('PASS: native POSIX QUIC policy, negotiated versions, flow control, and CONNECT scope', flush=True)


if __name__ == '__main__':
    asyncio.run(policy(sys.argv[1]))
