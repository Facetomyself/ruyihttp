"""Installed-wheel integration test. All listeners are loopback-only and fixed-route.

Requires trustme and ruyihttp[socks]. No outside service, DNS, or proxy credentials.
"""
import base64
import contextlib
import json
import os
import secrets
import select
import socket
import socketserver
import ssl
import tempfile
import threading
from pathlib import Path

import ruyihttp
import trustme
from requests.exceptions import ProxyError, SSLError

HOST = 'origin.invalid'
LOOP = '127.0.0.1'


def exact(s, n):
    blob = bytearray()
    while len(blob) < n:
        part = s.recv(n - len(blob))
        if not part:
            raise EOFError('premature socket EOF')
        blob.extend(part)
    return bytes(blob)


def head(s):
    buf = bytearray()
    while not buf.endswith(b'\r\n\r\n'):
        if len(buf) > 16384:
            raise ValueError('header limit exceeded')
        buf.extend(exact(s, 1))
    first, *lines = buf.decode('latin1').split('\r\n')
    return first, {k.lower(): v.strip() for k, v in (s.split(':', 1) for s in lines if s)}


def splice(a, b):
    # Each side is confined to a pre-selected loopback test listener.
    while True:
        pending = [s for s in (a,b) if isinstance(s, ssl.SSLSocket) and s.pending()]
        ready = pending or select.select([a, b], [], [], 8)[0]
        if not ready:
            return
        for src in ready:
            chunk = src.recv(32768)
            if not chunk:
                return
            (b if src is a else a).sendall(chunk)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


@contextlib.contextmanager
def listener(handle, tls=None):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(8)
            try:
                if tls is None:
                    handle(self.request)
                else:
                    with tls.wrap_socket(self.request, server_side=True) as conn:
                        handle(conn)
            except (EOFError, OSError):
                pass  # A negative test or a completed client may close first.
    with Server((LOOP, 0), Handler) as srv:
        thread = threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        try:
            yield srv.server_address
        finally:
            srv.shutdown(); thread.join()


def context(cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_alpn_protocols(['http/1.1'])
    cert.configure_cert(ctx)
    return ctx


def run(scheme, mode, ca_file, proxy_tls, origin_tls):
    events = []; marker = secrets.token_hex(16).encode(); path = '/proof/' + marker.decode()
    def origin(s):
        line, headers = head(s)
        events.append(['origin', line, 'proxy-authorization' in headers])
        s.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 32\r\n\r\n' + marker)

    with contextlib.ExitStack() as stack:
        addr = stack.enter_context(listener(origin, origin_tls)); authority = f'{HOST}:{addr[1]}'
        def exit_proxy(s):
            line, _ = head(s)
            if line != f'CONNECT {authority} HTTP/1.1':
                raise ValueError('unexpected exit target')
            events.append(['exit', authority, mode])
            if mode == 'cut':
                s.sendall(b'HTTP/1.1 502 Link cut\r\nContent-Length: 0\r\n\r\n'); return
            with socket.create_connection(addr, 5) as up:
                s.sendall(b'HTTP/1.1 200 OK\r\n\r\n'); splice(s, up)
        hop2 = stack.enter_context(listener(exit_proxy))
        def entry(s):
            if scheme == 'socks5h':
                assert exact(s,1) == b'\x05'; methods=exact(s,exact(s,1)[0]); assert 0 in methods
                s.sendall(b'\x05\x00'); assert exact(s,4) == b'\x05\x01\x00\x03'
                name = exact(s,exact(s,1)[0]).decode(); port = int.from_bytes(exact(s,2),'big'); assert f'{name}:{port}' == authority
            else:
                line, headers = head(s); assert line == f'CONNECT {authority} HTTP/1.1'
                assert headers.get('proxy-authorization') == 'Basic ' + base64.b64encode(b'fixture:demo').decode()
            events.append(['entry', scheme, authority]);
            with socket.create_connection(hop2, 5) as up:
                up.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode()); status, _ = head(up)
                ok = status.startswith('HTTP/1.1 200 ')
                if scheme == 'socks5h':
                    s.sendall(bytes([5, 0 if ok else 5, 0, 1]) + bytes(6))
                else:
                    s.sendall((status + '\r\n\r\n').encode())
                if ok:
                    splice(s, up)
        addr1=stack.enter_context(listener(entry, proxy_tls if scheme=='https' else None))
        info = None; error = None; uri=f'https://{authority}{path}'
        auth = '' if scheme == 'socks5h' else 'fixture:demo@'
        with ruyihttp.Session(firefox='159',verify=str(ca_file)) as session:
            session.trust_env=False
            try:
                r=session.get(uri, proxies={'https':f'{scheme}://{auth}{LOOP}:{addr1[1]}'},timeout=6,allow_redirects=False)
                info = r.tls
                assert mode=='ok' and r.status_code==200 and r.content==marker
                assert info['backend']=='NSS' and info['alpn']=='http/1.1'
            except (ProxyError,SSLError) as exc:
                error=f'{type(exc).__name__}: {exc}'
                assert (mode=='cut' and isinstance(exc,ProxyError)) or (mode=='bad-origin' and isinstance(exc,SSLError)), error
        assert [e[0] for e in events] == (['entry','exit','origin'] if mode=='ok' else ['entry','exit']), events
        if mode=='ok':
            assert events[-1]==['origin',f'GET {path} HTTP/1.1',False]
        else:
            assert error, 'expected an explicit failure'
        print(json.dumps(dict(scheme=scheme, mode=mode, events=events, tls=info, error=error)),flush=True)


def main():
    assert not os.environ.get('PYTHONOPTIMIZE') and __debug__, 'run with assertions enabled'
    ca=trustme.CA(); proxy=context(ca.issue_cert(LOOP)); origin=context(ca.issue_cert(HOST)); wrong=context(ca.issue_cert('wrong.invalid'))
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'test-ca.pem'; ca.cert_pem.write_to_path(p)
        failed=[]
        for scheme in ('http','https','socks5h'):
            for mode in ('ok','cut','bad-origin'):
                try:
                    run(scheme,mode,p,proxy,wrong if mode=='bad-origin' else origin)
                except Exception as exc:
                    import traceback
                    traceback.print_exc(); failed.append((scheme,mode,type(exc).__name__))
        if failed:
            raise SystemExit(f'failed cases: {failed}')
    print('PASS: 9 two-hop integration cases')


if __name__=='__main__':
    main()
