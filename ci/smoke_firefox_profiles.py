#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Capture selected Firefox profiles at a loopback origin from an installed wheel.

Run with the qualification interpreter: python -I ci/smoke_firefox_profiles.py <slot>.
Only structured fields are compared: no randoms, key bytes, tickets, packet
numbers or order of randomized TLS extensions are part of the fingerprint.
"""

import asyncio
import json
import runpy
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RemoteSettingsChanged, RequestReceived, StreamEnded

import ruyihttp
from ruyihttp._firefox import runtime_platform


SELECTIONS = ("159", "160", "161")
PATH = "/profile-wire"
IP = "127.0.0.1"
UA_SYSTEM = {
    "win_amd64": "Windows NT 10.0; Win64; x64",
    "darwin_arm64": "Macintosh; Intel Mac OS X 10.15",
    "darwin_x86_64": "Macintosh; Intel Mac OS X 10.15",
    "linux_x86_64": "X11; Linux x86_64",
    "linux_aarch64": "X11; Linux aarch64",
}
# Stable navigation fields shared by H1, H2 and H3, as seen by the server.
NAV_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br, zstd",
    "upgrade-insecure-requests": "1",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "priority": "u=0, i",
}
REFERENCE_PATH = Path(__file__).with_name("firefox_wire_reference.json")
QUIC_PARAMETERS = {
    "ack_delay_exponent", "active_connection_id_limit", "disable_active_migration",
    "initial_max_data", "initial_max_stream_data_bidi_local", "initial_max_stream_data_bidi_remote",
    "initial_max_stream_data_uni", "initial_max_streams_bidi", "initial_max_streams_uni",
    "max_ack_delay", "max_datagram_frame_size", "max_idle_timeout", "max_udp_payload_size",
}


class Vector:
    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    def __bool__(self):
        return self.pos < len(self.data)

    def take(self, size):
        result = self.data[self.pos:self.pos + size]
        if len(result) != size:
            raise ValueError("truncated TLS vector")
        self.pos += size
        return result

    def uint(self, size):
        return int.from_bytes(self.take(size), "big")

    def vector(self, length_bytes):
        return Vector(self.take(self.uint(length_bytes)))

    def integers(self, width):
        result = []
        while self:
            number = self.uint(width)
            # RFC 8701 GREASE values are uninformative and can vary by handshake.
            if width != 2 or number not in range(0x0A0A, 0xFAFB, 0x1010):
                result.append(number)
        return result


def client_hello(message):
    handshake = Vector(message)
    assert handshake.uint(1) == 1  # ClientHello
    body = handshake.vector(3)
    assert not handshake
    legacy_version = body.uint(2)
    body.take(32)  # random
    body.vector(1)  # session ID
    ciphers = body.vector(2).integers(2)
    body.vector(1)  # compression methods
    extensions = {}
    items = body.vector(2)
    assert not body
    while items:
        code = items.uint(2)
        assert code not in extensions, code
        extensions[code] = items.vector(2)

    def numbers(code, length_width, number_width=2):
        if code not in extensions:
            return []
        return extensions[code].vector(length_width).integers(number_width)

    groups = numbers(10, 2)
    signatures = numbers(13, 2)
    compression = numbers(27, 1)
    versions = numbers(43, 1)
    share_groups = []
    if 51 in extensions:
        shares = extensions[51].vector(2)
        while shares:
            share_groups.append(shares.uint(2))
            shares.vector(2)  # ephemeral public key bytes
    alpn = []
    if 16 in extensions:
        names = extensions[16].vector(2)
        while names:
            alpn.append(bytes(names.vector(1).data).decode("ascii"))
    return {
        "legacy_version": legacy_version,
        "ciphers": ciphers,
        "extensions": sorted(code for code in extensions if code not in range(0x0A0A, 0xFAFB, 0x1010)),
        "groups": groups,
        "signatures": signatures,
        "cert_compression": compression,
        "supported_versions": versions,
        "key_share_groups": share_groups,
        "offered_alpn": alpn,
    }


def context_for(leaf, key, alpn, hellos):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_alpn_protocols([alpn])
    context.load_cert_chain(leaf, key)

    # Qualification is explicitly CPython. The SSL message callback yields the
    # complete received handshake even if it spanned TCP segments or TLS records.
    def on_message(_socket, direction, _protocol, content_type, message_type, data):
        if direction == "read" and content_type == 22 and message_type == 1:
            hellos.append(client_hello(data))

    context._msg_callback = on_message
    return context


def listener():
    tcp = socket.socket()
    tcp.settimeout(15)
    tcp.bind((IP, 0))
    tcp.listen()
    return tcp


def decode_headers(headers):
    return [(key.decode("ascii"), value.decode("latin-1")) for key, value in headers]


def h1_origin(tcp, context):
    client, _ = tcp.accept()
    with client:
        client.settimeout(10)
        with context.wrap_socket(client, server_side=True) as tls, tls.makefile("rb") as inbound:
            # Some native builds report empty ALPN for H1 even though a real
            # H1 transaction follows; the raw request line is independently checked.
            first_line = inbound.readline(65536).rstrip(b"\r\n")
            headers = []
            while line := inbound.readline(65536):
                if line == b"\r\n":
                    break
                name, value = line.rstrip(b"\r\n").split(b":", 1)
                headers.append((name, value.strip()))
            assert line == b"\r\n", "missing H1 end of headers"
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nh1")
            return {"protocol": tls.selected_alpn_protocol(), "request_line": first_line.decode("ascii"),
                    "headers": decode_headers(headers)}


def h2_origin(tcp, context, port, release):
    client, _ = tcp.accept()
    # Leave no fallback listener. Drain the warm H2 connection after one request.
    tcp.close()
    with client:
        client.settimeout(10)
        with context.wrap_socket(client, server_side=True) as tls:
            assert tls.selected_alpn_protocol() == "h2"
            protocol = H2Connection(H2Configuration(client_side=False, normalize_inbound_headers=False))
            protocol.initiate_connection()
            tls.sendall(protocol.data_to_send())
            settings = []
            headers = {}
            while data := tls.recv(65536):
                for event in protocol.receive_data(data):
                    if isinstance(event, RemoteSettingsChanged) and not settings:
                        settings.extend((int(code), change.new_value) for code, change in event.changed_settings.items())
                    if isinstance(event, RequestReceived):
                        headers[event.stream_id] = decode_headers(event.headers)
                    if isinstance(event, StreamEnded):
                        stream = event.stream_id
                        protocol.send_headers(stream, [(b":status", b"200"), (b"content-length", b"2"),
                                                        (b"alt-svc", f'h3="127.0.0.1:{port}"; ma=60'.encode())])
                        protocol.send_data(stream, b"h2", end_stream=True)
                        protocol.close_connection(error_code=0, last_stream_id=stream)
                        tls.sendall(protocol.data_to_send())
                        assert release.wait(20), "client did not release H2 bootstrap"
                        return {"protocol": "h2", "settings": settings, "headers": headers[stream]}
                tls.sendall(protocol.data_to_send())
    raise AssertionError("origin received no complete H2 request")


class H3Origin(QuicConnectionProtocol):
    def __init__(self, *args, observed, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.observed = observed

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.observed["protocol"] = event.alpn_protocol
            # The aioquic version is pinned by the wheel gate. This is the
            # server's negotiated wire version, not the client's version label.
            self.observed["quic_version"] = int(self._quic._version)
        for message in self.http.handle_event(event):
            if isinstance(message, HeadersReceived):
                assert "headers" not in self.observed, "unexpected additional H3 request"
                self.observed["headers"] = decode_headers(message.headers)
                self.observed["settings"] = sorted(
                    (int(code), value) for code, value in self.http.received_settings.items()
                    if code < 0x21 or (code - 0x21) % 0x1F  # discard H3 GREASE identifiers
                )
                self.http.send_headers(message.stream_id, [(b":status", b"200"), (b"content-length", b"2")])
                self.http.send_data(message.stream_id, b"h3", end_stream=True)
                self.transmit()


def fetch(profile, roots, url1, url2, entry):
    result = {}
    with ruyihttp.Session(firefox=profile, verify=str(roots), timeout=10) as session:
        session.trust_env = False
        for protocol, url, version in (("h1", url1, 11), ("h2", url2, 20), ("h3", url2, 30)):
            response = session.get(url)
            assert (response.status_code, response.raw.version, response.content) == (200, version, protocol.encode()), response
            info = response.tls
            shape = entry["h3_tls"] if protocol == "h3" else "nss"
            if shape == "null":
                assert info is None, info
            elif shape == "windows-legacy":
                assert set(info) == {"backend", "alpn", "version", "cipher_suite", "resumed"}, info
                assert info["backend"] == "NSS/Neqo" and info["alpn"] == "h3", info
                assert info["version"] == 0x0304 and info["cipher_suite"] in (0x1301, 0x1302, 0x1303), info
                assert not info["resumed"], info
            else:
                assert shape == "nss", shape
                assert info["backend"] == "NSS" and info["nss"] == entry["nss"], info
                assert info["profile"] == f"firefox-{profile}" and info["version"] == 0x0304, info
                if protocol == "h1":
                    assert info["alpn"] in ("", "http/1.1"), info
                else:
                    assert info["alpn"] == protocol, info
            result[protocol] = {"status": response.status_code, "http_version": response.raw.version, "tls": info}
    return result


async def capture(profile, entry, cert):
    leaf, key, roots = cert
    with listener() as tcp1, listener() as tcp2, ThreadPoolExecutor(2) as executor:
        observations, hellos1, hellos2 = {}, [], []
        port1, port2 = tcp1.getsockname()[1], tcp2.getsockname()[1]
        quic_log = QuicLogger()
        quic = QuicConfiguration(is_client=False, alpn_protocols=["h3"], quic_logger=quic_log)
        quic.load_cert_chain(leaf, key)
        server = await serve(IP, port2, configuration=quic,
                             create_protocol=lambda *a, **k: H3Origin(*a, observed=observations, **k))
        release = Event()
        h1 = executor.submit(h1_origin, tcp1, context_for(leaf, key, "http/1.1", hellos1))
        h2 = executor.submit(h2_origin, tcp2, context_for(leaf, key, "h2", hellos2), port2, release)
        try:
            responses = await asyncio.to_thread(fetch, profile, roots, f"https://localhost:{port1}{PATH}",
                                                f"https://localhost:{port2}{PATH}", entry)
        finally:
            release.set()
            server.close()
        traces = quic_log.to_dict()["traces"]
        parameters = [event["data"] for trace in traces for event in trace["events"]
                      if event["name"] == "transport:parameters_set" and event["data"]["owner"] == "remote"]
        assert len(hellos1) == len(hellos2) == len(parameters) == 1, (hellos1, hellos2, parameters)
        observations["transport_parameters"] = {key: parameters[0][key] for key in sorted(QUIC_PARAMETERS & parameters[0].keys())}
        wire = {"h1": h1.result(10), "h2": h2.result(10), "h3": observations}
        wire["h1"]["hello"], wire["h2"]["hello"] = hellos1[0], hellos2[0]
        return wire, responses


def verify(profile, slot, wire):
    expected_agent = f"Mozilla/5.0 ({UA_SYSTEM[slot]}; rv:{profile}.0) Gecko/20100101 Firefox/{profile}.0"
    assert wire["h1"]["request_line"] == f"GET {PATH} HTTP/1.1", wire["h1"]
    assert wire["h3"]["protocol"] == "h3" and wire["h3"]["quic_version"] in (1, 0x6B3343CF), wire["h3"]
    assert wire["h3"]["settings"] and wire["h3"]["transport_parameters"], wire["h3"]
    for protocol, observation in wire.items():
        headers = [(name.lower(), value) for name, value in observation["headers"]]
        fields = dict(headers)
        assert len(headers) == len(fields), headers
        assert fields["user-agent"] == expected_agent, headers
        assert [(name, value) for name, value in headers if name in NAV_HEADERS] == list(NAV_HEADERS.items()), headers
        if protocol != "h1":
            assert (fields[":method"], fields[":scheme"], fields[":path"]) == ("GET", "https", PATH), headers
        if protocol != "h3":
            hello = observation["hello"]
            assert hello["supported_versions"][0] == 0x0304, hello
            assert hello["ciphers"][:3] == [0x1301, 0x1303, 0x1302], hello
            assert hello["groups"][:2] == [0x11EC, 0x001D] and hello["key_share_groups"][:2] == [0x11EC, 0x001D], hello
            assert ("h2" if protocol == "h2" else "http/1.1") in hello["offered_alpn"], hello


def comparable(wire):
    """Strip expected per-run differences while preserving field order and values."""
    return {
        protocol: {**observation, "headers": [
            (name, "<version-specific>" if name.lower() == "user-agent" else
             "<loopback-authority>" if name.lower() in ("host", ":authority", "alt-used") else value)
            for name, value in observation["headers"]
        ]}
        for protocol, observation in wire.items()
    }


def reference_comparison(profile, wire, reference):
    stable = comparable(wire)
    report = {"source": reference["source"], "firefox": profile}
    for protocol in ("h1", "h2"):
        observed = stable[protocol]
        expected = reference["observations"][protocol]
        report[protocol] = {
            "headers_match": [list(item) for item in observed["headers"]] == expected["headers"],
            "client_hello_differences": {
                field: {"reference": value, "wheel": observed["hello"][field]}
                for field, value in reference["observations"]["client_hello"].items()
                if observed["hello"][field] != value
            },
        }
    actual_ua = next(value for key, value in wire["h1"]["headers"] if key.lower() == "user-agent")
    expected_ua = reference["observations"]["user_agent_template"].replace("{major}", profile)
    if actual_ua != expected_ua:
        report["user_agent_difference"] = {"reference": expected_ua, "wheel": actual_ua}
    report["h2"]["settings_match"] = (
        [list(pair) for pair in stable["h2"]["settings"]] == reference["observations"]["h2"]["settings"]
    )
    h3 = stable["h3"]
    ref_h3 = reference["observations"]["h3_fetch"]
    actual_settings = set(h3["settings"])
    expected_settings = set(map(tuple, ref_h3["settings"]))
    report["h3"] = {
        "reference_firefox": ref_h3["firefox"],
        "headers_compared": False,  # Browser JS fetch vs. wheel navigation.
        "quic_version_matches": h3["quic_version"] == ref_h3["quic_version"],
        "transport_parameters_match": h3["transport_parameters"] == ref_h3["transport_parameters"],
        "settings_reference_only": sorted(expected_settings - actual_settings),
        "settings_wheel_only": sorted(actual_settings - expected_settings),
    }
    return report


def main(slot):
    assert runtime_platform() == slot, (runtime_platform(), slot)
    root = Path(ruyihttp.__file__).resolve().parent
    assert root.is_relative_to(Path(sys.prefix).resolve()), root
    manifest = json.loads((root / "runtime-manifest.json").read_text(encoding="utf-8"))
    entry = manifest["platforms"][slot]
    reference = json.loads(REFERENCE_PATH.read_text(encoding="utf-8"))
    assert tuple(reference["captures"]) == SELECTIONS
    # Reuse the other installed-wheel gate's local CA fixture without making
    # the source tree importable under the isolation required by this gate.
    certificate = runpy.run_path(str(Path(__file__).with_name("smoke_native_target.py")))["certificate"]
    with TemporaryDirectory() as directory:
        cert = certificate(Path(directory))
        baseline = None
        for firefox in SELECTIONS:
            wire, responses = asyncio.run(capture(firefox, entry, cert))
            comparison = reference_comparison(firefox, wire, reference)
            print(json.dumps({"slot": slot, "firefox": firefox, "native_source": entry["firefox"],
                              "nss": entry["nss"], "neqo": entry["neqo"], "responses": responses,
                              "wire": wire, "reference_comparison": comparison}), flush=True)
            verify(firefox, slot, wire)
            # H1/H2 navigation and initial SETTINGS must match the reference.
            # Other TLS/QUIC deltas are recorded explicitly per native slot;
            # the structural checks and the slot's own 159 control still apply.
            assert comparison["h1"]["headers_match"] and comparison["h2"]["headers_match"], comparison
            assert comparison["h2"]["settings_match"], comparison
            stable = comparable(wire)
            if baseline is None:
                baseline = stable
            else:
                assert stable == baseline, f"Firefox {firefox} changed non-UA wire fields versus the 159 control"
    print(f"{slot}: explicit 159/160/161 passed H1, H2 and UDP-only H3 with identical selected non-UA fields", flush=True)


if __name__ == "__main__":
    main(sys.argv[1])
