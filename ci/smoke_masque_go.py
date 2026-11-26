#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Optional installed-wheel MASQUE interop against pinned masque-go/quic-go.

Build the fixture with `go build -trimpath -o /absolute/path/to/relay .` from
ci/masque_interop, then pass that executable path to this script. The Go
process's stdout is the relay-side record, and only its one fixed egress UDP
socket is admitted by the independent aioquic origin. Every peer is loopback.
"""

import argparse
import asyncio
import hashlib
import json
import os
from functools import partial
from pathlib import Path
import sys
import tempfile

# Make the sibling CI helper available under -I, without adding the source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_masque import (
    AUTH, DOWNLOAD, LOOP, OriginProtocol, GuardedOrigin, UPLOAD, Wire,
    certs, check, check_origin, check_route, client_call, configuration,
    runtime, target_path, watch_client, wheel_identity,
)

EXPECTED_MODULES = {
    "github.com/quic-go/masque-go": "v0.6.0",
    "github.com/quic-go/quic-go": "v0.63.0",
}


class CountedOriginTransport:
    def __init__(self, transport, state):
        self.transport, self.state = transport, state

    def sendto(self, data, addr):
        check(addr == self.state.egress_address, "origin replied to an unapproved peer", addr)
        self.state.reverse.observe(data)
        return self.transport.sendto(data, addr)

    def __getattr__(self, attr):
        return getattr(self.transport, attr)


class CountedOrigin(GuardedOrigin):
    def connection_made(self, transport):
        super().connection_made(CountedOriginTransport(transport, self.state))


async def process_event(process, timeout=5):
    line = await asyncio.wait_for(process.stdout.readline(), timeout)
    if not line:
        raise RuntimeError(f"Go fixture quit before emitting its expected event (returncode={process.returncode})")
    return json.loads(line)


async def exercise(relay_binary, receipt, origin_pem, relay_pem):
    _, slot, metadata = runtime()
    receipt["platform_slot"] = slot
    state = Wire("ok")
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, ctx: state.errors.append(repr(ctx.get("exception", ctx["message"]))))
    env = {**os.environ, "RUYIHTTP_FIXTURE_RELAY_AUTH": AUTH.decode("ascii")}
    _, origin = await loop.create_datagram_endpoint(
        lambda: CountedOrigin(configuration=configuration(origin_pem), state=state,
                              create_protocol=partial(OriginProtocol, state=state)),
        local_addr=(LOOP, 0),
    )
    state.origin_address = origin._transport.get_extra_info("sockname")
    process = None
    trap = None
    go_errors = None

    def canary(_reader, writer):
        state.tcp_contacts.append(writer.get_extra_info("peername"))
        writer.close()

    try:
        trap = await asyncio.start_server(canary, *state.origin_address)
        process = await asyncio.create_subprocess_exec(
            str(relay_binary), "--origin-port", str(state.origin_address[1]),
            "--cert", str(relay_pem["good"][0]), "--key", str(relay_pem["key"]),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
        )
        go_errors = asyncio.create_task(process.stderr.read())
        info = await process_event(process)
        receipt["go_fixture"] = info
        check(info["modules"] == EXPECTED_MODULES, info)
        state.relay_address = (LOOP, info["relay_port"])
        state.egress_address = (LOOP, info["egress_port"])
        with watch_client(state) as (dns, abi, native):
            result = await asyncio.to_thread(client_call, state, origin_pem, relay_pem, metadata, positive=True)
        error = result.pop("exception", None)
        receipt.update({"requests": result, "origin_dns_attempts": dns, "native_body_calls": dict(abi)})
        check(error is None, result)
        accepted = await process_event(process)
        retired = await process_event(process)
        receipt["go_events"] = [accepted, retired]
        check(accepted == {"accepted_connect_udp": target_path(state.origin_address[1]).decode(), "alpn": "h3", "proxy_auth_matched": True}, accepted)
        check(retired == {"tunnel_retired": True}, retired)
        check(not dns and native and not any(connection._thread.is_alive() for connection in native), dns, native)
        check_route(state)
        check_origin(state, metadata, abi)
        check(state.ingress.count > 1 and state.ingress.octets > len(UPLOAD) and state.reverse.count > 1
              and state.reverse.octets > len(DOWNLOAD) + len(UPLOAD), state.ingress.receipt(), state.reverse.receipt())
    finally:
        if process:
            if process.returncode is None:
                process.stdin.close()
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            receipt["go_exit_code"] = process.returncode
            receipt["go_stderr"] = (await go_errors).decode("utf-8", "replace")
        origin.close()
        if trap:
            trap.close()
            await trap.wait_closed()
        # The Go relay has its own authenticated handshake/CONNECT events; only
        # copy counters the Python peer actually observed, not synthetic zeros.
        if hasattr(state, "relay_address"):
            wire = state.receipt()
            receipt["origin_peer"] = wire["origin"]
            receipt["sockets"] = wire["sockets"]
            receipt["udp_at_origin"] = {"in": state.ingress.receipt(), "out": state.reverse.receipt()}
        receipt["fixture_errors"] = state.errors
    check(not state.errors and receipt["go_exit_code"] == 0, receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("relay_binary", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.relay_binary.resolve(strict=True)
    receipt = {"verdict": "failed", "schema": "ruyihttp-masque-go-interop/v1",
               "fixture_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    try:
        receipt.update(wheel_identity())
        with tempfile.TemporaryDirectory(prefix="ruyi-masque-go-") as temp:
            asyncio.run(exercise(binary, receipt, *certs(Path(temp))))
        receipt["verdict"] = "passed"
    except BaseException as error:
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS: native H3 through pinned quic-go/masque-go CONNECT-UDP relay", flush=True)


if __name__ == "__main__":
    main()
