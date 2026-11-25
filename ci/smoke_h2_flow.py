"""TLS loopback regressions for stream fairness, pool capacity and H2 polling."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from hashlib import sha256
from itertools import count
import queue
import select
import socket
import tempfile
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import PingAckReceived, RequestReceived, StreamReset, WindowUpdated
from h2.settings import SettingCodes
from hyperframe.frame import ExtensionFrame, GoAwayFrame
from requests.exceptions import ConnectTimeout, ReadTimeout

import ruyihttp
from smoke_proxy_chain import listener, tls_fixtures

LARGE = 12 * 1024**2
PART = b"a" * 16384
SMALL = b"ok"


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f"no progress within {timeout}s")
        time.sleep(0.002)


@contextmanager
def origin(tls, limit=None):
    # Based on edges.py's large-first sender: advance A until blocked before
    # visiting B, including when both streams remain active on one connection.
    cids = count(1)
    requests, updates, resets, blocked = [], [], [], []
    controls = queue.Queue()
    acks = []

    def serve(sock):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(3)
        assert sock.selected_alpn_protocol() == "h2"
        cid = next(cids)
        wire = H2Connection(H2Configuration(client_side=False))
        wire.initiate_connection()
        if limit is not None:
            wire.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: limit})
        sock.sendall(wire.data_to_send())
        jobs, held = {}, {}
        while True:
            try:
                command = controls.get_nowait()
            except queue.Empty:
                pass
            else:
                if command == "probe":
                    wire.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: 3})
                    wire.ping(b"passive!")
                    sent_origin = b"https://example.test"
                    payload = len(sent_origin).to_bytes(2, "big") + sent_origin
                    frame = ExtensionFrame(0xC, 0, body=payload)
                    frame.body_len = len(payload)
                    sock.sendall(wire.data_to_send() + frame.serialize())
                elif command == "goaway":
                    sock.sendall(
                        GoAwayFrame(
                            0, last_stream_id=wire.highest_inbound_stream_id
                        ).serialize()
                    )
                elif command == "reply":
                    sid = held.pop(b"/paused")
                    wire.send_headers(
                        sid, [(b":status", b"200"), (b"content-length", b"2")]
                    )
                    wire.send_data(sid, SMALL, end_stream=True)
                    sock.sendall(wire.data_to_send())
                else:
                    raise AssertionError(command)

            if not sock.pending() and not select.select([sock], [], [], 0.015)[0]:
                continue
            data = sock.recv(65536)
            if not data:
                return
            for event in wire.receive_data(data):
                if isinstance(event, RequestReceived):
                    sid = event.stream_id
                    path = dict(event.headers)[b":path"]
                    requests.append((cid, sid, path))
                    if path == b"/paused":
                        held[path] = sid
                        continue
                    length = LARGE if path == b"/large" else len(SMALL)
                    wire.send_headers(
                        sid,
                        [
                            (b":status", b"200"),
                            (b"content-length", str(length).encode()),
                            (b"x-conn", str(cid).encode()),
                            (b"x-stream", str(sid).encode()),
                        ],
                    )
                    jobs[sid] = path, length
                elif isinstance(event, WindowUpdated):
                    updates.append((cid, event.stream_id, event.delta))
                elif isinstance(event, StreamReset):
                    resets.append((cid, event.stream_id, event.error_code))
                    jobs.pop(event.stream_id, None)
                elif isinstance(event, PingAckReceived):
                    acks.append(event.ping_data)
            for sid, (path, left) in list(jobs.items()):
                body = PART if path == b"/large" else SMALL
                while left > 0:
                    n = min(wire.local_flow_control_window(sid), len(body), left)
                    if n <= 0:
                        row = (
                            cid,
                            sid,
                            path,
                            LARGE - left,
                            wire.outbound_flow_control_window,
                            wire.streams[sid].outbound_flow_control_window,
                        )
                        if not blocked or blocked[-1] != row:
                            blocked.append(row)
                        break
                    wire.send_data(sid, body[:n], end_stream=n == left)
                    sock.sendall(wire.data_to_send())
                    left -= n
                if left:
                    jobs[sid] = path, left
                else:
                    jobs.pop(sid)
            remaining = wire.data_to_send()
            if remaining:
                sock.sendall(remaining)

    with listener(serve, tls) as (host, port):
        yield (
            f"https://{host}:{port}",
            requests,
            updates,
            resets,
            blocked,
            controls,
            acks,
        )


def session(ca):
    client = ruyihttp.Session(firefox="159", verify=str(ca), timeout=4)
    client.trust_env = False
    return client


def fairness(ca, tls):
    from ruyihttp._http2 import (
        _BUFFER_LIMIT,
        _CONNECTION_WINDOW,
        _STREAM_BOOST,
        _STREAM_WINDOW,
    )

    with (
        origin(tls) as (url, requests, updates, resets, blocked, _, _),
        session(ca) as client,
    ):
        with client.get(url + "/large", stream=True) as a:
            conn = a._necko_transport.h2
            exchange = a.raw._fp.exchange
            sid = exchange.stream_id
            limit = _STREAM_WINDOW + _STREAM_BOOST
            wait_for(lambda: len(exchange.buffer) == limit and blocked)
            cid, _, path, sent, available, stream_available = blocked[0]
            assert a.raw.version == 20 and not exchange.ended
            assert (path, sent, stream_available) == (b"/large", limit, 0), blocked
            assert available == _CONNECTION_WINDOW - limit, blocked
            assert all(
                delta == _CONNECTION_WINDOW - 65535 or stream
                for _, stream, delta in updates
            ), updates
            started = time.monotonic()
            with client.get(url + "/small") as b:
                elapsed_ms = (time.monotonic() - started) * 1000
                assert b.raw.version == 20 and b.content == SMALL
                assert b.headers["x-conn"] == a.headers["x-conn"]
                assert b.headers["x-stream"] != a.headers["x-stream"]
                assert conn._buffered == len(exchange.buffer) == limit < _BUFFER_LIMIT
                assert not exchange.ended, "A completed without consumption"
            print(
                f"PASS fairness: B={b.content!r} on connection {cid} in {elapsed_ms:.2f} ms; "
                f"A unread {sent}/{LARGE} bytes, connection credit {available}, stream credit 0"
            )
            digest, read = sha256(), 0
            for chunk in a.iter_content(65536):
                digest.update(chunk)
                read += len(chunk)
            assert read == LARGE and digest.digest() == sha256(b"a" * LARGE).digest()
            assert a.raw.read(1) == b"" and conn._buffered == 0
            assert not any(event[:2] == (cid, sid) for event in resets), resets

        with client.get(url + "/large", stream=True) as cancelled:
            conn = cancelled._necko_transport.h2
            exchange = cancelled.raw._fp.exchange
            cid = int(cancelled.headers["x-conn"])
            sid = exchange.stream_id
            wait_for(lambda: len(exchange.buffer) == limit)
            before = len(updates)
            cancelled.close()
            wait_for(lambda: any(e[:2] == (cid, sid) for e in resets))
            assert (cid, sid, 8) in resets
            assert conn._buffered == 0 and not exchange.buffer
            wait_for(
                lambda: any(
                    c == cid and s == 0 and d >= limit for c, s, d in updates[before:]
                )
            )
            assert not any(c == cid and s == sid for c, s, _ in updates[before:])
        with client.get(url + "/small") as next_response:
            assert (next_response.content, int(next_response.headers["x-conn"])) == (
                SMALL,
                cid,
            )
        assert all(c == cid for c, *_ in requests), requests
        print(
            f"PASS EOF and cancel: read/hash {read} bytes, cancel recycled {limit} bytes on connection {cid}"
        )


def capacity(ca, tls, block):
    with origin(tls, limit=1) as (url, requests, *rest), session(ca) as client:
        adapter = client.get_adapter(url)
        adapter._pool_maxsize = 1
        adapter._pool_block = block
        with client.get(url + "/large", stream=True) as a:
            conn = a._necko_transport.h2
            wait_for(
                lambda: (
                    conn.received_settings and conn.protocol.open_outbound_streams == 1
                )
            )
            assert conn._peer_stream_limit == 1
            if block:
                try:
                    client.get(url + "/small", timeout=(0.16, 3))
                except ConnectTimeout:
                    assert len(requests) == 1, requests
                else:
                    raise AssertionError("pool_block opened an extra connection")
            else:
                with client.get(url + "/small", timeout=2) as b:
                    assert b.raw.version == 20 and b.content == SMALL
                    assert b.headers["x-conn"] != a.headers["x-conn"]
                assert len(requests) == 2, requests
        pool = next(iter(adapter._pools.values()))
        assert pool.leased == 0 and len(pool.shared) <= 1
        print(
            f"PASS peer capacity 1, block={block}: server connections {[r[0] for r in requests]}; "
            f"idle H2 connections {len(pool.shared)}"
        )


def polling(ca, tls):
    with (
        origin(tls) as (url, requests, _, resets, _, controls, acks),
        session(ca) as client,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        with client.get(url + "/small") as warm:
            transport = warm._necko_transport
            conn = transport.h2
        library = transport.library
        pending = library.necko_tls_pending
        probes = [0]

        def probe(handle):
            probes[0] += 1
            return pending(handle)

        library.necko_tls_pending = probe
        try:
            time.sleep(0.09)  # reach the passive cap
            probes[0] = 0
            cpu_at = time.process_time()
            timer_at = time.monotonic()
            time.sleep(0.4)
            quiet_cpu_ms = (time.process_time() - cpu_at) * 1000
            idle_rate = probes[0] / (time.monotonic() - timer_at)
            assert 0 < idle_rate <= 60, idle_rate

            active = executor.submit(client.get, url + "/paused")
            wait_for(lambda: any(row[2] == b"/paused" for row in requests))
            time.sleep(0.03)  # reach the active cap
            probes[0] = 0
            timer_at = time.monotonic()
            time.sleep(0.3)
            active_rate = probes[0] / (time.monotonic() - timer_at)
            assert not active.done(), "paused stream got a fabricated EOF"
            assert 0 < active_rate < 350, active_rate
            controls.put("reply")
            with active.result(timeout=2) as delayed:
                assert delayed.raw.version == 20 and delayed.content == SMALL

            try:
                client.get(url + "/paused", timeout=(1, 0.16))
            except ReadTimeout:
                cid, sid, path = requests[-1]
                assert path == b"/paused"
                wait_for(lambda: (cid, sid, 8) in resets)
            else:
                raise AssertionError("paused read did not time out")
            with client.get(url + "/small") as after_timeout:
                assert after_timeout._necko_transport is transport
                assert after_timeout.content == SMALL

            at = time.monotonic()
            controls.put("probe")
            wait_for(
                lambda: conn._peer_stream_limit == 3 and acks and conn.origins,
                timeout=0.7,
            )
            assert acks == [b"passive!"] and conn.origins == frozenset(
                {("example.test", 443)}
            )
            passive_ms = (time.monotonic() - at) * 1000
            controls.put("goaway")
            wait_for(lambda: conn.goaway, timeout=0.7)
            with client.get(url + "/small") as fresh:
                assert (
                    fresh._necko_transport is not transport and fresh.content == SMALL
                )
        finally:
            library.necko_tls_pending = pending
        print(
            f"PASS scheduler: idle {idle_rate:.1f} probes/s ({quiet_cpu_ms:.2f} ms CPU / 400 ms), "
            f"paused {active_rate:.1f} probes/s; passive SETTINGS, ORIGIN and PING ACK "
            f"in {passive_ms:.1f} ms; GOAWAY moved next request to a new TLS connection"
        )


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        ca, tls, *_ = tls_fixtures(tempdir)
        tls.set_alpn_protocols(["h2"])
        fairness(ca, tls)
        capacity(ca, tls, block=False)
        capacity(ca, tls, block=True)
        polling(ca, tls)


if __name__ == "__main__":
    main()
