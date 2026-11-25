"""Authenticated loopback benchmark: run with the installed wheel outside the source tree."""

import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import math
import multiprocessing as mp
import os
from pathlib import Path
import platform
import resource
import statistics
import sys
import tempfile
import time
from importlib.metadata import version
from unittest.mock import patch
import warnings
import zipfile

from cryptography.utils import CryptographyDeprecationWarning
import ruyihttp
from ruyihttp import _nss
from _origin import EXPECTED, SMALL as EXPECTED_SMALL, issue, origin


def stats(values):
    return {
        "n": len(values),
        "p50": round(statistics.median(values), 4),
        "p95": round(sorted(values)[math.ceil(0.95 * len(values)) - 1], 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def benchmark(d, ports):
    ca = d / "ca.pem"
    root_bundle = Path(ruyihttp.__file__).with_name("firefox-roots.pem")
    full = d / "fixture-plus-roots.pem"
    full.write_bytes(root_bundle.read_bytes() + b"\n" + ca.read_bytes())
    v = {"h1": 11, "h2": 20, "h3": 30}
    sessions = {}
    rows = {}
    last_conn = {}

    def new(verify):
        s = ruyihttp.Session(firefox="159", verify=str(verify), timeout=8)
        s.trust_env = False
        return s

    def bootstrap(s):
        with s.get(
            f"https://127.0.0.1:{ports['bootstrap']}/advertise", allow_redirects=False
        ) as r:
            assert r.status_code == 200 and r.raw.version == 11 and r.content == b""
            assert 'h3="' in r.headers["Alt-Svc"]

    def req(s, proto, path=b"/small", chunk=65536):
        url = (
            f"https://127.0.0.1:{ports['bootstrap' if proto == 'h3' else proto]}"
            + path.decode()
        )
        sha = hashlib.sha256()
        byte_count = 0
        with s.get(url, stream=True, allow_redirects=False) as r:
            for data in r.iter_content(chunk):
                sha.update(data)
                byte_count += len(data)
            assert (r.status_code, r.raw.version) == (200, v[proto])
            assert r.tls["alpn"] == {"h1": "http/1.1", "h2": "h2", "h3": "h3"}[proto]
            assert sha.digest() == EXPECTED[path]
            return byte_count, r.headers["x-conn"]

    try:
        for proto in v:
            s = sessions[proto] = new(ca)
            if proto == "h3":
                bootstrap(s)
            for _ in range(3):
                _, last_conn[proto] = req(s, proto)

        def measure(label, count, action):
            wall = []
            cpu = []
            sz = 0
            for _ in range(count):
                tw = time.perf_counter_ns()
                tc = time.process_time_ns()
                sz = action()
                cpu.append((time.process_time_ns() - tc) / 1e6)
                wall.append((time.perf_counter_ns() - tw) / 1e6)
            row = rows.setdefault(label, dict(wall_ms=[], client_cpu_ms=[], bytes=sz))
            row["wall_ms"].extend(wall)
            row["client_cpu_ms"].extend(cpu)

        for turn in range(3):
            protos = list(v)
            protos = protos[turn:] + protos[:turn]
            for proto in protos:
                cases = [
                    (b"/small", 65536, 20),
                    (b"/big", 4096, 6),
                    (b"/big", 65536, 6),
                ]
                cases = cases[turn:] + cases[:turn]
                for path, chunk, count in cases:

                    def same():
                        size, c = req(sessions[proto], proto, path, chunk)
                        assert c == last_conn[proto], (proto, c, last_conn[proto])
                        return size

                    measure(f"{proto}:warm:{path.decode()[1:]}:{chunk}", count, same)
            for root, lab in (
                (ca, "fixture-ca"),
                (full, "fixture-plus-packaged-roots"),
            ):
                for proto in protos:

                    def fresh():
                        with new(root) as session:
                            if proto == "h3":
                                # This timed sample includes an empty H1 bootstrap before QUIC.
                                bootstrap(session)
                            return req(session, proto)[0]

                    kind = "bootstrap-and-small" if proto == "h3" else "small"
                    measure(f"{proto}:new-session:{kind}:{lab}", 8, fresh)
        output = {}
        for k, row in rows.items():
            w = row["wall_ms"]
            sz = row["bytes"]
            output[k] = {
                "elapsed_ms": stats(w),
                "client_cpu_ms": stats(row["client_cpu_ms"]),
                "bytes": sz,
                "aggregate_MiB_per_s": round(
                    sz * len(w) * 1000 / (sum(w) * 1024**2), 3
                ),
                "samples_ms": [round(x, 5) for x in w],
                "client_cpu_ms_per_MiB": round(
                    sum(row["client_cpu_ms"]) / (sz * len(w) / 1024**2), 4
                ),
            }
        # Independent operation-level cost with the production roots vs a one-CA test bundle.
        micro = {}
        for label, verification in [
            ("fixture", str(ca)),
            ("default", True),
            ("fixture-plus-packaged-roots", str(full)),
        ]:
            ns = []
            proc = []
            for _ in range(80):
                t = time.perf_counter_ns()
                c = time.process_time_ns()
                _nss.Context(verification, None)
                proc.append((time.process_time_ns() - c) / 1e6)
                ns.append((time.perf_counter_ns() - t) / 1e6)
            micro[label] = {"elapsed_ms": stats(ns), "cpu_ms": stats(proc)}
        return {
            "scenarios": output,
            "h3_upload": h3_counters(sessions["h3"], ports["bootstrap"]),
            "trust_construction": micro,
            "packaged_roots": root_bundle.read_bytes().count(
                b"-----BEGIN CERTIFICATE-----"
            ),
        }
    finally:
        for s in sessions.values():
            s.close()


def h3_counters(session, port):
    """Count body handoffs outside the timed section; this is not wire traffic."""
    base = f"https://127.0.0.1:{port}"
    with session.get(base + "/small") as warm:
        assert warm.raw.version == 30
        connection = warm._necko_transport
    native = connection.library.necko_quic_call
    counters = Counter()
    payload = bytes(range(256)) * 4096

    def json_call(handle, frame, length):
        reply = native(handle, frame, length)
        command = json.loads(frame)
        if command["op"] == "write":
            accepted = json.loads(reply)["count"]
            counters["json_write_calls"] += 1
            counters["json_frame_bytes"] += length
            counters["json_write_accepted"] += accepted
            counters["zero_writes"] += accepted == 0
        return reply

    abi = getattr(connection, "_body_abi", None)
    with ExitStack() as trace:
        trace.enter_context(
            patch.object(connection.library, "necko_quic_call", json_call)
        )
        if abi is not None:
            native_write = abi.write

            def binary(handle, stream, data, offset):
                accepted = native_write(handle, stream, data, offset)
                counters["binary_write_calls"] += 1
                counters["binary_bytes_offered"] += len(data) - offset
                counters["binary_bytes_accepted"] += accepted
                counters["zero_writes"] += accepted == 0
                return accepted

            trace.enter_context(patch.object(abi, "write", binary))
        with session.post(base + "/upload", data=payload, allow_redirects=False) as r:
            assert (
                r.raw.version == 30
                and r.content == hashlib.sha256(payload).hexdigest().encode()
            )
    assert counters["json_write_accepted"] + counters["binary_bytes_accepted"] == len(
        payload
    )
    return dict(
        body_abi=1 if abi is not None else 0,
        effective_bytes=len(payload),
        json_bytes_per_effective_byte=counters["json_frame_bytes"] / len(payload),
        **counters,
    )


def rss_kib():
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise RuntimeError("VmRSS missing")


def fairness(d, ports, control):
    url = f"https://127.0.0.1:{ports['h2']}"
    with ruyihttp.Session(verify=str(d / "ca.pem"), timeout=4) as s:
        s.trust_env = False
        before = rss_kib()
        with s.get(url + "/slow-stream", stream=True) as unread:
            assert unread.status_code == 200 and unread.raw.version == 20
            # The origin reports bytes released by its real H2 peer. Wait for
            # stable backpressure, without consuming this large response.
            levels = []
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                control.send("stats")
                assert control.poll(2)
                levels.append(control.recv().get("large_bytes", 0))
                if (
                    len(levels) >= 3
                    and levels[-1] > 0
                    and levels[-3:] == [levels[-1]] * 3
                ):
                    break
                time.sleep(0.025)
            assert len(levels) >= 3 and levels[-1] > 0
            held = rss_kib()
            samples = []
            same = True
            error = None
            for _ in range(32):
                t = time.perf_counter_ns()
                try:
                    with s.get(url + "/small", timeout=(1, 0.6)) as small:
                        assert (
                            small.status_code == 200
                            and small.raw.version == 20
                            and small.content == EXPECTED_SMALL
                        )
                        same &= small.headers["x-conn"] == unread.headers["x-conn"]
                except ruyihttp.RequestException as ex:
                    error = type(ex).__name__
                    break
                samples.append((time.perf_counter_ns() - t) / 1e6)
        return dict(
            unread_response_bytes_reported_by_peer=levels[-1],
            small_completed=len(samples),
            small_latency_ms=stats(samples) if samples else None,
            same_connection=same if samples else None,
            error=error,
            rss_before_kib=before,
            rss_while_unread_kib=held,
            rss_after_release_kib=rss_kib(),
        )


def idle(d, ports):
    out = []
    url = f"https://127.0.0.1:{ports['h2']}/small"
    for n in (0, 1, 4):
        with ExitStack() as stack:
            pools = []
            for _ in range(n):
                s = stack.enter_context(
                    ruyihttp.Session(verify=str(d / "ca.pem"), timeout=5)
                )
                s.trust_env = False
                with s.get(url) as r:
                    assert r.content == EXPECTED_SMALL and r.raw.version == 20
                pools.append(s.get_adapter(url).library)
            time.sleep(0.20)
            start = time.perf_counter()
            cpu = time.process_time()
            time.sleep(1.2)
            cpu = time.process_time() - cpu
            elapsed = time.perf_counter() - start
            count = 0
            with ExitStack() as instrument:
                for lib in pools:
                    orig = lib.necko_tls_pending

                    def pending(handle, _fn=orig):
                        nonlocal count
                        count += 1
                        return _fn(handle)

                    instrument.enter_context(
                        patch.object(lib, "necko_tls_pending", pending)
                    )
                start = time.perf_counter()
                time.sleep(0.8)
                counted = time.perf_counter() - start
            out.append(
                dict(
                    connections=n,
                    client_cpu_fraction=round(cpu / elapsed, 6),
                    pending_polls_per_sec=round(count / counted, 2),
                )
            )
    return out


def artifact(path):
    installed = Path(ruyihttp.__file__).resolve().parent
    with zipfile.ZipFile(path) as z:
        files = [
            n for n in z.namelist() if n.startswith("ruyihttp/") and not n.endswith("/")
        ]
        for name in files:
            if (
                z.read(name)
                != (installed / name.removeprefix("ruyihttp/")).read_bytes()
            ):
                raise RuntimeError(
                    f"installed package differs from measured wheel: {name}"
                )
    return {
        "wheel": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "checked_members": len(files),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wheel", required=True, type=Path)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if sys.platform != "linux" or not __debug__:
        ap.error("Linux and enabled assertions are required")
    identity = artifact(args.wheel)
    warnings.filterwarnings("once", category=CryptographyDeprecationWarning)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        issue(d)
        ctx = mp.get_context("fork")
        c, ch = ctx.Pipe()
        p = ctx.Process(target=origin, args=(ch, d), daemon=True)
        p.start()
        ch.close()
        try:
            assert c.poll(10)
            ports = c.recv()
            t = datetime.now(timezone.utc).isoformat()
            report = benchmark(d, ports)
            report["stream_fairness"] = fairness(d, ports, c)
            report["idle_h2"] = idle(d, ports)
            report["environment"] = {
                **identity,
                "commit": args.commit,
                "started_utc": t,
                "arch": platform.machine(),
                "affinity": len(os.sched_getaffinity(0)),
                "load": os.getloadavg(),
                "libc": os.confstr("CS_GNU_LIBC_VERSION"),
                "python": platform.python_version(),
                "versions": {
                    n: version(n)
                    for n in (
                        "ruyihttp",
                        "requests",
                        "h2",
                        "cryptography",
                        "aioquic",
                        "urllib3",
                    )
                },
                "client_high_water_rss_kib": resource.getrusage(
                    resource.RUSAGE_SELF
                ).ru_maxrss,
            }
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(
                json.dumps(
                    {k: v for k, v in report.items() if k != "scenarios"}, indent=2
                ),
                flush=True,
            )
        finally:
            if p.is_alive():
                c.send("stop")
            p.join(4)
            if p.is_alive():
                p.terminate()
                p.join(2)
            c.close()
