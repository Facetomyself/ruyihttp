"""Opt-in installed-wheel test: run this script with the native wheel's Python."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from io import BytesIO
import socket
import ssl
import tempfile

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import DataReceived, RequestReceived, StreamEnded
from hyperframe.frame import RstStreamFrame
from requests.exceptions import RequestException

import ruyihttp
from smoke_proxy_chain import tls_fixtures


REPLY = b"upload too large"
PART = b"x" * (256 * 1024)
WINDOW = 65535  # Default H2 send window; the peer grants no further credit.
NORMAL = (b"normal ", b"request ", b"body")


@dataclass(frozen=True)
class Case:
    name: str
    reply: str
    source: str = "generator"
    close: bool = False
    error: str | None = None


CASES = (
    Case("early-generator", "early"),
    Case("early-file-peer-close", "early", source="file", close=True),
    Case("normal-upload", "normal"),
    Case("NO_ERROR-after-success", "normal-reset", close=True),
    Case("NO_ERROR-before-final", "reset-first", error="stream reset: 0"),
    Case("NO_ERROR-before-END_STREAM", "partial-reset", error="stream reset: 0"),
    Case("CANCEL-after-END_STREAM", "cancel", error="stream reset: 8"),
    Case("short-content-length", "short", error="InvalidBodyLengthError"),
    Case("truncated-peer-close", "partial", close=True, error="HTTP/2"),
)


class CountingFile(BytesIO):
    reads = 0

    def read(self, size=-1):
        self.reads += 1
        return super().read(size)


def send_reply(wire, stream_id, reply):
    if reply == "reset-first":
        wire.send_headers(stream_id, [(b":status", b"103")])
    else:
        normal = reply.startswith("normal")
        wire.send_headers(
            stream_id,
            [
                (b":status", b"200" if normal else b"413"),
                (b"content-length", str(len(REPLY)).encode()),
                (b"x-h2-early-smoke", b"present"),
            ],
        )
        wire.send_data(
            stream_id,
            REPLY[:3] if reply in ("partial", "partial-reset", "short") else REPLY,
            end_stream=reply not in ("partial", "partial-reset"),
        )
    if reply == "cancel":
        wire.reset_stream(stream_id, ErrorCodes.CANCEL)
    elif reply in ("early", "reset-first", "partial-reset", "short"):
        wire.reset_stream(stream_id, ErrorCodes.NO_ERROR)
    output = wire.data_to_send()
    if reply == "normal-reset":
        # Both directions already sent END_STREAM; hyper-h2 will not send this
        # redundant reset itself. Encode it explicitly to exercise late NO_ERROR.
        output += RstStreamFrame(stream_id, error_code=ErrorCodes.NO_ERROR).serialize()
    return output


def serve(listener, tls, case):
    with (
        listener,
        listener.accept()[0] as raw,
        tls.wrap_socket(raw, server_side=True) as peer,
    ):
        peer.settimeout(4)
        assert peer.selected_alpn_protocol() == "h2"
        wire = H2Connection(config=H2Configuration(client_side=False))
        wire.initiate_connection()
        peer.sendall(wire.data_to_send())
        upload = bytearray()
        while data := peer.recv(65536):
            for event in wire.receive_data(data):
                if isinstance(event, RequestReceived):
                    assert dict(event.headers)[b":method"] == b"POST"
                if isinstance(event, DataReceived):
                    upload.extend(event.data)
                if case.reply.startswith("normal"):
                    if not isinstance(event, StreamEnded):
                        continue
                    assert upload == b"".join(NORMAL)
                else:
                    # Exhaust the client's window before replying. Its first
                    # upload write is still pending, with no in-flight DATA
                    # left to disrupt the subsequent TLS close_notify.
                    if not isinstance(event, DataReceived) or len(upload) < WINDOW:
                        continue
                    assert len(upload) == WINDOW
                peer.sendall(send_reply(wire, event.stream_id, case.reply))
                try:
                    if case.close:
                        peer.unwrap().close()  # Send TLS close_notify directly after the frames.
                    else:
                        while peer.recv(65536):
                            pass
                except (ssl.SSLError, ConnectionError):
                    pass
                return len(upload)
            peer.sendall(wire.data_to_send())
        raise AssertionError("origin saw no upload")


def run_case(executor, ca, tls, case):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.settimeout(5)
        port = sock.getsockname()[1]
        server = executor.submit(serve, sock, tls, case)
        produced = []

        def generate():
            for part in NORMAL if case.reply.startswith("normal") else (PART,) * 3:
                produced.append(len(part))
                yield part

        body = CountingFile(PART * 3) if case.source == "file" else generate()
        try:
            with ruyihttp.Session(firefox="159", verify=str(ca)) as session:
                session.trust_env = False
                try:
                    response = session.post(f"https://127.0.0.1:{port}/", data=body, timeout=4)
                except RequestException as exc:
                    assert case.error and case.error in str(exc), repr(exc)
                    result = f"rejected: {exc}"
                else:
                    assert case.error is None, f"accepted invalid response: {response!r}"
                    expected = 200 if case.reply.startswith("normal") else 413
                    assert (response.status_code, response.raw.version) == (expected, 20)
                    assert response.headers["x-h2-early-smoke"] == "present"
                    assert response.content == REPLY
                    result = f"HTTP/2 {expected}, headers and {len(REPLY)} body bytes preserved"
        finally:
            received = server.result(timeout=6)
        if case.source == "file":
            assert body.reads == 1, body.reads
            pulled = body.reads
        else:
            pulled = len(produced)
            assert pulled == (3 if case.reply.startswith("normal") else 1), produced
        print(f"PASS {case.name}: {result}; pulls={pulled}; server saw {received} upload bytes")


def main():
    failures = 0
    with tempfile.TemporaryDirectory() as d, ThreadPoolExecutor(max_workers=1) as executor:
        ca, tls, *_ = tls_fixtures(d)
        tls.set_alpn_protocols(["h2"])
        for case in CASES:
            try:
                run_case(executor, ca, tls, case)
            except Exception as exc:
                failures += 1
                print(f"FAIL {case.name}: {exc!r}", flush=True)
    print(f"{len(CASES) - failures}/{len(CASES)} native H2 cases passed", flush=True)
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
