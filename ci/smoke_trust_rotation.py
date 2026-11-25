"""Exercise trust-store reuse and same-path rotation across real verified TLS handshakes."""

import os
from pathlib import Path
import tempfile

from requests.exceptions import SSLError
import ruyihttp
from smoke_proxy_chain import head, listener, tls_fixtures


def respond(conn):
    head(conn)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


def check(session, port, allowed):
    try:
        with session.get(f"https://127.0.0.1:{port}/", allow_redirects=False) as r:
            assert allowed and (r.status_code, r.content) == (200, b"ok"), (
                allowed,
                r.status_code,
            )
            assert r.tls.get("backend") == "NSS"
    except SSLError as error:
        if allowed:
            raise
        assert "valid" in str(error).lower() or "cert" in str(error).lower(), error
        return
    if not allowed:
        raise AssertionError("untrusted peer returned an HTTP response")


def main():
    with tempfile.TemporaryDirectory() as work:
        path = Path(work)
        first_dir = path / "first"
        second_dir = path / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        first_ca, first_tls, *_ = tls_fixtures(first_dir)
        second_ca, second_tls, *_ = tls_fixtures(second_dir)
        first, second = first_ca.read_bytes(), second_ca.read_bytes()
        size = max(len(first), len(second)) + 8
        verify = path / "active.pem"
        verify.write_bytes(first.ljust(size, b"\n"))
        stamp = verify.stat()
        with (
            listener(respond, first_tls) as (_, a),
            listener(respond, second_tls) as (_, b),
            ruyihttp.Session(verify=str(verify), timeout=4) as session,
        ):
            session.trust_env = False
            check(session, a, True)
            check(session, a, True)
            check(session, b, False)
            verify.write_bytes(second.ljust(size, b"\n"))
            os.utime(verify, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            check(session, a, False)
            check(session, b, True)
        print(
            "PASS: repeated verified handshakes; same-path same-size same-mtime CA rotation rejected old root, accepted new root"
        )


if __name__ == "__main__":
    main()
