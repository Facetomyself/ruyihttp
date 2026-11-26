#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Measure an installed RuyiHttp wheel at verified local TLS origins.

`python -I ci/smoke_firefox_profiles.py <slot>` is the strict fork gate.
Use `--collect` for an upstream/old wheel without fork runtime metadata.
"""

import argparse
import asyncio
import json
import platform
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, StreamEnded

# Resolve the installed product before explicitly exposing these CI helpers to
# the isolated qualification interpreter. Never add the product checkout.
import ruyihttp

sys.path.insert(0, str(Path(__file__).resolve().parent))
from firefox_quic_initial import QuicInitialObservation
from firefox_wire import (
    BOOT, MODES, PATH, QUIC_PARAMETERS, REFERENCE_DIR, RELEASES, SCHEMA_VERSION,
    SLOTS, WireError, grease_settings, load_reference, require, stable_wire,
)

IP = "127.0.0.1"


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
            result.append(self.uint(width))
        return result


def client_hello(message):
    handshake = Vector(message)
    require(handshake.uint(1) == 1, "expected ClientHello")
    body = handshake.vector(3)
    require(not handshake, "unexpected trailing handshake bytes")
    legacy_version = body.uint(2)
    body.take(32)  # random
    session_id_length = len(body.vector(1).data)
    ciphers = body.vector(2).integers(2)
    compression_methods = body.vector(1).integers(1)
    extensions = {}
    items = body.vector(2)
    require(not body, "unexpected trailing ClientHello bytes")
    while items:
        code = items.uint(2)
        require(code not in extensions, f"duplicate TLS extension {code}")
        extensions[code] = items.vector(2)

    def payload(code, length_width):
        if code not in extensions:
            return Vector(b"")
        extension = extensions[code]
        vector = extension.vector(length_width)
        require(not extension, f"trailing bytes in TLS extension {code}")
        return vector

    groups = payload(10, 2).integers(2)
    signatures = payload(13, 2).integers(2)
    compression = payload(27, 1).integers(2)
    versions = payload(43, 1).integers(2)
    share_groups = []
    shares = payload(51, 2)
    while shares:
        share_groups.append(shares.uint(2))
        shares.vector(2)  # ephemeral public key bytes
    alpn = []
    names = payload(16, 2)
    while names:
        alpn.append(bytes(names.vector(1).data).decode("ascii"))
    server_names = []
    names = payload(0, 2)
    while names:
        server_names.append([names.uint(1), bytes(names.vector(2).data).decode("ascii")])
    return {
        "legacy_version": legacy_version,
        "session_id_length": session_id_length,
        "ciphers": ciphers,
        "compression_methods": compression_methods,
        "extensions": list(extensions),
        "groups": groups,
        "signatures": signatures,
        "cert_compression": compression,
        "supported_versions": versions,
        "key_share_groups": share_groups,
        "offered_alpn": alpn,
        "ec_point_formats": payload(11, 1).integers(1),
        "psk_key_exchange_modes": payload(45, 1).integers(1),
        "server_names": server_names,
    }


def certificate(directory):
    """Ephemeral private CA and localhost leaf; the client must verify both."""
    ca_key = generate_private_key(SECP256R1())
    server_key = generate_private_key(SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Firefox profile wire test CA")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)

    def builder(subject, public_key, ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                    crl_sign=False, encipher_only=False, decipher_only=False), critical=True))

    ca = builder(ca_name, ca_key.public_key(), True).sign(ca_key, hashes.SHA256())
    leaf = (builder(server_name, server_key.public_key(), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    leaf_path, key_path, ca_path = (directory / name for name in ("leaf.pem", "key.pem", "ca.pem"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return leaf_path, key_path, ca_path


def context_for(leaf, key, alpn, hellos):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_alpn_protocols([alpn])
    context.load_cert_chain(leaf, key)

    # The CPython callback delivers a complete handshake independently of TCP
    # and TLS-record segmentation.
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
            first_line = inbound.readline(65536)
            require(first_line.endswith(b"\r\n"), "h1: malformed request line")
            headers = []
            while line := inbound.readline(65536):
                if line == b"\r\n":
                    break
                require(line.endswith(b"\r\n"), "h1: malformed header line")
                name, value = line[:-2].split(b":", 1)
                # H1 delimiter whitespace is not part of the field value.
                headers.append((name, value.strip(b" \t")))
            require(line == b"\r\n", "h1: missing end of headers")
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nh1")
            return {"protocol": tls.selected_alpn_protocol(), "request_line": first_line[:-2].decode("ascii"),
                    "negotiated_tls": {"version": tls.version(), "cipher": tls.cipher()[0]},
                    "headers": decode_headers(headers)}


class FirstH2Settings:
    """Observe the actual frame, preserving order (unlike a SETTINGS dict)."""
    PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def __init__(self):
        self.buffer = bytearray()
        self.settings = None

    def feed(self, data):
        if self.settings is not None:
            return
        self.buffer.extend(data)
        offset = len(self.PREFACE)
        if len(self.buffer) < offset + 9:
            return
        require(self.buffer[:offset] == self.PREFACE, "h2: wrong client connection preface")
        frame = self.buffer[offset:offset + 9]
        length = int.from_bytes(frame[:3], "big")
        require(frame[3] == 4 and not frame[4] & 1 and frame[5:] == b"\0" * 4 and length % 6 == 0,
                "h2: missing initial client SETTINGS frame")
        offset += 9
        if len(self.buffer) < offset + length:
            return
        self.settings = [(int.from_bytes(self.buffer[pos:pos + 2], "big"),
                          int.from_bytes(self.buffer[pos + 2:pos + 6], "big"))
                         for pos in range(offset, offset + length, 6)]
        self.buffer.clear()


def h2_origin(tcp, context, *, boot_port=None, release=None):
    client, _ = tcp.accept()
    # In the bootstrap case, retire both the listener and the H2 connection so
    # a silent TCP fallback can never look like successful H3.
    tcp.close()
    with client:
        client.settimeout(10)
        with context.wrap_socket(client, server_side=True) as tls:
            require(tls.selected_alpn_protocol() == "h2", "h2: server did not negotiate h2")
            protocol = H2Connection(H2Configuration(client_side=False, normalize_inbound_headers=False))
            protocol.initiate_connection()
            tls.sendall(protocol.data_to_send())
            settings = FirstH2Settings()
            headers = {}
            while data := tls.recv(65536):
                settings.feed(data)
                for event in protocol.receive_data(data):
                    if isinstance(event, RequestReceived):
                        headers[event.stream_id] = decode_headers(event.headers)
                    if isinstance(event, StreamEnded):
                        stream = event.stream_id
                        body = b"boot" if boot_port else b"h2"
                        response = [(b":status", b"200"), (b"content-length", str(len(body)).encode())]
                        if boot_port:
                            require(dict(headers[stream]).get(":path") == BOOT, "h3: wrong TCP bootstrap target")
                            response.append((b"alt-svc", f'h3=":{boot_port}"; ma=60'.encode()))
                        protocol.send_headers(stream, response)
                        protocol.send_data(stream, body, end_stream=True)
                        protocol.close_connection(error_code=0, last_stream_id=stream)
                        tls.sendall(protocol.data_to_send())
                        if release is not None:
                            require(release.wait(20), "h2: client did not release the bootstrap")
                        return {"protocol": tls.selected_alpn_protocol(), "settings": settings.settings,
                                "negotiated_tls": {"version": tls.version(), "cipher": tls.cipher()[0]},
                                "headers": headers[stream]}
                tls.sendall(protocol.data_to_send())
    raise WireError("h2: observed no complete request")


class H3Origin(QuicConnectionProtocol):
    def __init__(self, *args, observed, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.initial = QuicInitialObservation(self._quic)
        self.observed = observed
        initialize = self._quic._initialize

        def tap_initialize(*args):
            initialize(*args)
            handler = self._quic.tls._server_handle_hello

            def tap_hello(input_buf, *output_bufs):
                require("hello" not in self.observed, "h3: unexpected second ClientHello")
                payload = input_buf.data_slice(input_buf.tell(), input_buf.capacity)
                self.observed["hello"] = client_hello(payload)
                return handler(input_buf, *output_bufs)

            self._quic.tls._server_handle_hello = tap_hello

        self._quic._initialize = tap_initialize

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            require("protocol" not in self.observed, "h3: unexpected second handshake")
            self.observed["protocol"] = event.alpn_protocol
            self.observed["quic_version"] = int(self._quic._version)
        for message in self.http.handle_event(event):
            if isinstance(message, HeadersReceived):
                require("headers" not in self.observed, "h3: unexpected additional request")
                self.observed["headers"] = decode_headers(message.headers)
                self.observed["initial"] = self.initial.result()
                # aioquic's H3 parser rejects duplicates, then preserves control
                # stream order in its dictionary. Save reserved IDs in raw data.
                self.http.send_headers(message.stream_id, [(b":status", b"200"), (b"content-length", b"2")])
                self.http.send_data(message.stream_id, b"h3", end_stream=True)
                self.transmit()
        if self.http.received_settings is not None:
            self.observed["settings"] = [(int(code), value) for code, value in self.http.received_settings.items()]
            self.observed["grease_settings"] = grease_settings(self.observed["settings"])


def response_receipt(profile, response, protocol, body, entry):
    version_number = {"h1": 11, "h2": 20, "h3": 30}[protocol]
    require((response.status_code, response.raw.version, response.content) == (200, version_number, body),
            f"{protocol}: unexpected status, version or body ({response.status_code}, {response.raw.version})")
    info = getattr(response, "tls", None)
    if entry is not None:
        shape = entry["h3_tls"] if protocol == "h3" else "nss"
        if shape == "null":
            require(info is None, f"{protocol}: expected null TLS telemetry, got {info}")
        elif shape == "windows-legacy":
            require(set(info) == {"backend", "alpn", "version", "cipher_suite", "resumed"}
                    and info["backend"] == "NSS/Neqo" and info["alpn"] == "h3" and info["version"] == 0x0304
                    and info["cipher_suite"] in (0x1301, 0x1302, 0x1303) and not info["resumed"], f"h3: {info}")
        else:
            require(shape == "nss" and isinstance(info, dict) and info["backend"] == "NSS" and info["nss"] == entry["nss"]
                    and info["profile"] == f"firefox-{profile}" and info["version"] == 0x0304
                    and info["alpn"] in (("", "http/1.1") if protocol == "h1" else (protocol,)), f"{protocol}: {info}")
    return {"status": response.status_code, "http_version": response.raw.version, "tls": info}


def fetch(profile, roots, ports, entry):
    result = {}
    options = {"firefox": profile, "verify": str(roots), "timeout": 10}
    origin = f"https://localhost:{ports['h3']}"
    boot = origin + BOOT
    with ruyihttp.Session(**options) as navigation:
        navigation.trust_env = False
        for protocol in ("h1", "h2"):
            url = f"https://localhost:{ports[protocol]}{PATH}"
            result[protocol] = response_receipt(profile, navigation.get(url), protocol, protocol.encode(), entry)
        response_receipt(profile, navigation.get(boot), "h2", b"boot", entry)
        # Reuse the ordinary HTTPS adapter, which owns the authenticated
        # Alt-Svc state. The second Session supplies the real fetch defaults,
        # reference and cookie policy rather than hand-constructing headers.
        with ruyihttp.Session(context="fetch", document_url=boot, user_activation=False, **options) as browser_fetch:
            browser_fetch.trust_env = False
            browser_fetch.get_adapter(boot).close()
            browser_fetch.mount("https://", navigation.get_adapter(boot))
            result["h3"] = response_receipt(profile, browser_fetch.get(origin + PATH), "h3", b"h3", entry)
    return result


async def capture(profile, entry, cert):
    leaf, key, roots = cert
    with listener() as tcp1, listener() as tcp2, listener() as tcp3, ThreadPoolExecutor(3) as executor:
        observations, hellos1, hellos2, hellos3 = {}, [], [], []
        ports = {protocol: listener.getsockname()[1] for protocol, listener in zip(MODES, (tcp1, tcp2, tcp3))}
        quic_log = QuicLogger()
        quic = QuicConfiguration(is_client=False, alpn_protocols=["h3"], quic_logger=quic_log)
        quic.load_cert_chain(leaf, key)
        server = await serve(IP, ports["h3"], configuration=quic,
                             create_protocol=lambda *a, **k: H3Origin(*a, observed=observations, **k))
        release = Event()
        h1 = executor.submit(h1_origin, tcp1, context_for(leaf, key, "http/1.1", hellos1))
        h2 = executor.submit(h2_origin, tcp2, context_for(leaf, key, "h2", hellos2))
        boot = executor.submit(h2_origin, tcp3, context_for(leaf, key, "h2", hellos3), boot_port=ports["h3"], release=release)
        try:
            responses = await asyncio.to_thread(fetch, profile, roots, ports, entry)
        finally:
            release.set()
            server.close()
        traces = quic_log.to_dict()["traces"]
        parameters = [event["data"] for trace in traces for event in trace["events"]
                      if event["name"] == "transport:parameters_set" and event["data"]["owner"] == "remote"]
        require(len(hellos1) == len(hellos2) == len(hellos3) == len(parameters) == 1,
                f"expected one handshake per origin: {list(map(len, (hellos1, hellos2, hellos3, parameters)))}")
        observations["transport_parameters"] = {key: value for key, value in parameters[0].items() if key in QUIC_PARAMETERS}
        observed_bootstrap = boot.result(10)
        observed_bootstrap.update(port=ports["h3"], mode=MODES["h2"], hello=hellos3[0], client_hello_count=len(hellos3))
        observations["bootstrap"] = [observed_bootstrap]
        wire = {"h1": h1.result(10), "h2": h2.result(10), "h3": observations}
        wire["h1"].update(hello=hellos1[0], client_hello_count=len(hellos1))
        wire["h2"].update(hello=hellos2[0], client_hello_count=len(hellos2))
        for protocol, case in wire.items():
            case.update(port=ports[protocol], mode=MODES[protocol])
        return wire, responses


def installed_product(slot, collect):
    actual = {"arm64": "aarch64", "amd64": "x86_64"}.get(platform.machine().lower(), platform.machine().lower())
    target_platform, target_arch, _ = SLOTS[slot]
    normalized_target = {"arm64": "aarch64", "amd64": "x86_64"}.get(target_arch, target_arch)
    require(sys.platform == target_platform and actual == normalized_target,
            f"{slot}: unexpected interpreter platform {sys.platform}/{platform.machine()}")
    root = Path(ruyihttp.__file__).resolve().parent
    require(root.is_relative_to(Path(sys.prefix).resolve()), f"expected installed wheel within {sys.prefix}, got {root}")
    if collect:
        return None
    # Keep import-time capture compatibility with unmodified upstream wheels.
    from ruyihttp._firefox import runtime_platform

    require(runtime_platform() == slot, f"manifest runtime slot {runtime_platform()!r} != {slot!r}")
    manifest = json.loads((root / "runtime-manifest.json").read_text(encoding="utf-8"))
    return manifest["platforms"][slot]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slot", choices=SLOTS)
    parser.add_argument("--references", type=Path, default=REFERENCE_DIR)
    parser.add_argument("--collect", action="store_true", help="measure an installed wheel without qualifying it")
    parser.add_argument("--release", choices=RELEASES, help="collect only one release; strict gate always checks all three")
    parser.add_argument("--output", type=Path, help="also write JSONL receipts to this file")
    args = parser.parse_args()
    if args.release and not args.collect:
        parser.error("--release requires --collect")
    try:
        expected = None if args.collect else load_reference(args.references, args.slot)
        entry = installed_product(args.slot, args.collect)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"firefox wire: {exc}\n")
    target_platform, target_arch, _ = SLOTS[args.slot]
    failed = []
    releases = (args.release,) if args.release else RELEASES
    output = args.output.open("w", encoding="utf-8") if args.output is not None else None
    try:
        with TemporaryDirectory() as directory:
            cert = certificate(Path(directory))
            for firefox in releases:
                record = {"schema_version": SCHEMA_VERSION, "source": "installed-wheel", "package_version": version("ruyihttp"),
                          "slot": args.slot, "platform": target_platform, "arch": target_arch, "firefox": firefox}
                if entry is not None:
                    record.update(native_source=entry["firefox"], nss=entry["nss"], neqo=entry["neqo"])
                try:
                    wire, responses = asyncio.run(capture(firefox, entry, cert))
                    record.update(wire=wire, responses=responses)
                    if expected is None:
                        stable_wire(wire)  # Validate even capture-only data.
                    else:
                        record["differences"] = expected[firefox].compare(wire)
                        if record["differences"]:
                            failed.append(firefox)
                except Exception as exc:
                    record["capture_error"] = f"{type(exc).__name__}: {exc}"
                    failed.append(firefox)
                line = json.dumps(record)
                print(line, flush=True)
                if output is not None:
                    output.write(line + "\n")
                    output.flush()
    finally:
        if output is not None:
            output.close()
    if failed:
        parser.exit(1, f"{args.slot}: Firefox {', '.join(failed)} wire capture/comparison failed\n")
    if not args.collect:
        print(f"{args.slot}: explicit 159/160/161 passed H1, H2 and UDP-only H3 against same-slot official Firefox", flush=True)


if __name__ == "__main__":
    main()
