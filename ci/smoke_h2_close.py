"""An installed wheel must retain completed H2 responses across immediate TLS EOF."""

from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
import tempfile

import ruyihttp
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamEnded
from requests.exceptions import RequestException
from smoke_proxy_chain import tls_fixtures

BODY = b"native-h2-eof-control"


def serve(listener, tls, complete):
    with (
        listener,
        listener.accept()[0] as raw,
        tls.wrap_socket(raw, server_side=True) as peer,
    ):
        peer.settimeout(3)
        assert peer.selected_alpn_protocol() == "h2"
        wire = H2Connection(config=H2Configuration(client_side=False))
        wire.initiate_connection()
        peer.sendall(wire.data_to_send())
        while chunk := peer.recv(16384):
            events = wire.receive_data(chunk)
            for event in events:
                if isinstance(event, StreamEnded):
                    wire.send_headers(
                        event.stream_id,
                        [
                            (b":status", b"200"),
                            (b"content-length", str(len(BODY)).encode()),
                        ],
                    )
                    wire.send_data(
                        event.stream_id,
                        BODY if complete else BODY[:3],
                        end_stream=complete,
                    )
                    peer.sendall(wire.data_to_send())
                    # Send TLS close_notify after the final frame; wait for client close.
                    try:
                        peer.unwrap().close()
                    except (ssl.SSLError, TimeoutError, ConnectionError):
                        pass
                    return
            peer.sendall(wire.data_to_send())
        raise AssertionError("origin did not receive H2 request")


def main():
    with (
        tempfile.TemporaryDirectory() as d,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        ca, tls, *_ = tls_fixtures(d)
        tls.set_alpn_protocols(["h2"])
        for complete in [True] * 12 + [False] * 3:
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sock.listen()
            sock.settimeout(4)
            port = sock.getsockname()[1]
            server = executor.submit(serve, sock, tls, complete)
            try:
                with ruyihttp.Session(firefox="159", verify=str(ca)) as session:
                    session.trust_env = False
                    resp = session.get(f"https://127.0.0.1:{port}/", timeout=4)
                    assert complete, "truncated stream accepted"
                    assert (resp.status_code, resp.raw.version, resp.content) == (
                        200,
                        20,
                        BODY,
                    )
            except RequestException as exc:
                if complete:
                    raise
                assert "HTTP/2" in str(exc), exc
            finally:
                server.result(timeout=6)
    print(
        "PASS: END_STREAM then TLS close 12/12; truncated stream rejected 3/3",
        flush=True,
    )


if __name__ == "__main__":
    main()
