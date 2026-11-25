"""Independent, loopback-only H1/H2/H3 origin for installed-wheel benchmarks."""

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import itertools
import socket
import ssl
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, StreamEnded, StreamReset
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BIG = bytes(range(256)) * 1024
SMALL = BIG[:128]
BODIES = {b"/small": SMALL, b"/big": BIG}
EXPECTED = {k: hashlib.sha256(v).digest() for k, v in BODIES.items()}


def issue(d):
    now = datetime.now(timezone.utc)
    priv = ec.generate_private_key(ec.SECP256R1())
    leafpriv = ec.generate_private_key(ec.SECP256R1())

    def dn(s):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, s)])

    issuer = dn("Ruyi performance fixture")

    def builder(name, key, ca):
        return (
            x509.CertificateBuilder()
            .issuer_name(issuer)
            .subject_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(priv.public_key()),
                False,
            )
            .add_extension(
                x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False),
                True,
            )
        )

    ca = builder(issuer, priv, True).sign(priv, hashes.SHA256())
    leaf = (
        builder(dn("loopback"), leafpriv, False)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(priv, hashes.SHA256())
    )
    for name, data in [
        ("ca.pem", ca.public_bytes(serialization.Encoding.PEM)),
        ("leaf.pem", leaf.public_bytes(serialization.Encoding.PEM)),
        (
            "leaf.key",
            leafpriv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        ),
    ]:
        (d / name).write_bytes(data)


def origin(pipe, d):
    async def main():
        ids = itertools.count(1)
        progress = {}

        class QUIC(QuicConnectionProtocol):
            def __init__(self, *args, **kw):
                super().__init__(*args, **kw)
                self.http = None
                self.cid = str(next(ids)).encode()
                self.uploads = {}

            def quic_event_received(self, event):
                if isinstance(event, ProtocolNegotiated):
                    self.http = H3Connection(self._quic)
                if self.http is None:
                    return
                for part in self.http.handle_event(event):
                    if not isinstance(part, (HeadersReceived, DataReceived)):
                        continue
                    sid = part.stream_id
                    if isinstance(part, HeadersReceived):
                        path = dict(part.headers)[b":path"]
                        if path == b"/upload":
                            self.uploads[sid] = hashlib.sha256()
                            if not part.stream_ended:
                                continue
                        else:
                            self.reply(sid, BODIES[path])
                            continue
                    elif sid in self.uploads:
                        self.uploads[sid].update(part.data)
                        if not part.stream_ended:
                            continue
                    else:
                        continue
                    self.reply(sid, self.uploads.pop(sid).hexdigest().encode("ascii"))

            def reply(self, stream, body):
                self.http.send_headers(
                    stream,
                    [
                        (b":status", b"200"),
                        (b"content-length", str(len(body)).encode()),
                        (b"x-conn", self.cid),
                    ],
                )
                self.http.send_data(stream, body, end_stream=True)
                self.transmit()

        q = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        q.load_cert_chain(d / "leaf.pem", d / "leaf.key")
        quic = await serve("127.0.0.1", 0, configuration=q, create_protocol=QUIC)
        udp = quic._transport.get_extra_info("sockname")[1]

        large_body = BIG * 48  # Allocated in the origin, not the measured client.

        def ctx(alpn):
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            c.load_cert_chain(d / "leaf.pem", d / "leaf.key")
            c.set_alpn_protocols([alpn])
            return c

        async def handle(reader, writer, proto):
            cid = str(next(ids)).encode()
            writer.get_extra_info("socket").setsockopt(
                socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
            )
            try:
                if proto == "h2":
                    h = H2Connection(config=H2Configuration(client_side=False))
                    h.initiate_connection()
                    writer.write(h.data_to_send())
                    await writer.drain()
                    tasks = {}
                    while chunk := await reader.read(65536):
                        for e in h.receive_data(chunk):
                            if isinstance(e, RequestReceived):
                                path = dict(e.headers)[b":path"]
                                body = (
                                    large_body
                                    if path == b"/slow-stream"
                                    else BODIES[path]
                                )
                                tasks[e.stream_id] = [body, 0, False]
                            elif isinstance(e, StreamReset):
                                tasks.pop(e.stream_id, None)
                            if isinstance(e, StreamEnded):
                                payload = tasks[e.stream_id][0]
                                h.send_headers(
                                    e.stream_id,
                                    [
                                        (b":status", b"200"),
                                        (b"content-length", str(len(payload)).encode()),
                                        (b"x-conn", cid),
                                    ],
                                )
                                tasks[e.stream_id][2] = True
                        for sid in list(tasks):
                            data, off, ready = tasks[sid]
                            if not ready:
                                continue
                            while off < len(data):
                                n = min(
                                    h.local_flow_control_window(sid),
                                    h.max_outbound_frame_size,
                                    len(data) - off,
                                )
                                if n <= 0:
                                    break
                                h.send_data(
                                    sid,
                                    data[off : off + n],
                                    end_stream=off + n == len(data),
                                )
                                off += n
                            if data is large_body:
                                progress["large_bytes"] = off
                            if off == len(data):
                                del tasks[sid]
                            else:
                                tasks[sid][1] = off
                        writer.write(h.data_to_send())
                        await writer.drain()
                else:
                    while True:
                        headers = await reader.readuntil(b"\r\n\r\n")
                        path = headers.split(b" ", 2)[1]
                        body = BODIES.get(path, b"")
                        boot = proto == "bootstrap"
                        prefix = (
                            b"HTTP/1.1 200 OK\r\nx-conn: "
                            + cid
                            + b"\r\nContent-Length: "
                            + str(len(body)).encode()
                            + b"\r\n"
                        )
                        if boot:
                            prefix += f'Alt-Svc: h3=":{udp}"; ma=120\r\nConnection: close\r\n'.encode()
                        writer.write(prefix + b"\r\n" + body)
                        await writer.drain()
                        if boot:
                            return
            except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
                pass
            finally:
                writer.close()

        servers = {}
        for key, alpn in [("h1", "http/1.1"), ("h2", "h2"), ("bootstrap", "http/1.1")]:
            servers[key] = await asyncio.start_server(
                lambda r, w, key=key: handle(r, w, key), "127.0.0.1", 0, ssl=ctx(alpn)
            )
        pipe.send({k: s.sockets[0].getsockname()[1] for k, s in servers.items()})
        while True:
            if pipe.poll():
                event = pipe.recv()
                if event == "stats":
                    pipe.send(dict(progress))
                if event == "stop":
                    break
            await asyncio.sleep(0.05)
        for s in servers.values():
            s.close()
            await s.wait_closed()
        quic.close()

    asyncio.run(main())
