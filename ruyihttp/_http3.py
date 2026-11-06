# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import ctypes as ct
import json
import os
import queue
import selectors
import socket
import ssl
import struct
import sys
import threading
import time
from email.message import Message
from pathlib import Path
from urllib.parse import urlsplit

from urllib3._collections import HTTPHeaderDict
from urllib3.exceptions import ProtocolError

from ._firefox import DEFAULT_FIREFOX, PROFILES, quic_profile
from ._nss import TLS
from ._retry import DirectRouteReset, Http1Required, Http3ProtocolError, Rejected

_Decoder = ct.CFUNCTYPE(
    ct.c_int, ct.c_uint16, ct.c_void_p, ct.c_size_t, ct.c_void_p, ct.c_size_t
)


class _Call:
    def __init__(self, operation, exchange, timeout, **arguments):
        self.operation = operation
        self.exchange = exchange
        self.arguments = arguments
        self.deadline = None if timeout is None else time.monotonic() + timeout
        self.done = threading.Event()
        self.result = None
        self.error = None
        self.cancelled = False


def _address(address):
    host, port = address[:2]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


class Connection:
    alpn = "h3"
    multiplexed = True

    def __init__(
        self,
        host,
        port,
        context,
        library_path,
        timeout,
        endpoint=None,
        token="",
        token_callback=None,
        attempt=None,
        firefox=None,
    ):
        self.firefox = firefox or DEFAULT_FIREFOX
        name = (
            "necko_quic.dll"
            if os.name == "nt"
            else "libnecko_quic.dylib"
            if sys.platform == "darwin"
            else "libnecko_quic.so"
        )
        path = Path(
            os.environ.get(
                "NECKO_QUIC_LIBRARY", Path(library_path).with_name(name)
            )
        )
        self._dll_directory = (
            os.add_dll_directory(str(Path(library_path).parent))
            if os.name == "nt"
            else None
        )
        try:
            self.library = ct.CDLL(str(path))
        except Exception:
            if self._dll_directory:
                self._dll_directory.close()
            raise
        self.library.necko_quic_call.argtypes = [ct.c_uint64, ct.c_char_p, ct.c_size_t]
        self.library.necko_quic_call.restype = ct.c_char_p
        self.library.necko_quic_set_decoder.argtypes = [_Decoder]
        self.library.necko_quic_set_decoder.restype = None
        self.host, self.port, self.context = host, port, context
        self.endpoint = endpoint or (host, port)
        self.token = token
        self.token_callback = token_callback
        self.timeout = timeout
        self.info = None
        self.error = None
        self.closed = False
        self.goaway = False
        self.streams = {}
        self.commands = queue.Queue()
        self._command_lock = threading.Lock()
        self.pending = []
        self.ready = threading.Event()
        self._stopping = threading.Event()
        self._wake_read, self._wake_write = socket.socketpair()
        self._wake_read.setblocking(False)
        self._wake_write.setblocking(False)
        self._thread = threading.Thread(
            target=self._run, name="necko-http3", daemon=True
        )
        self._thread.start()
        if attempt is not None:
            attempt.set_interrupt(self._cancel_connect)
        if not self.ready.wait(timeout):
            self.close()
            raise TimeoutError("HTTP/3 handshake timed out")
        if self.error:
            self.close()
            raise self.error
        if attempt is not None and attempt.cancelled.is_set():
            self.close()
            raise OSError("HTTP/3 connection attempt cancelled")

    def _cancel_connect(self):
        self._stopping.set()
        self._wake()

    def _call(self, operation, **arguments):
        data = json.dumps({"op": operation, **arguments}).encode()
        result = json.loads(self.library.necko_quic_call(self.handle, data, len(data)))
        if "error" in result:
            raise ProtocolError(result["error"])
        return result

    def _wake(self):
        try:
            self._wake_write.send(b"x")
        except (BlockingIOError, OSError):
            pass

    def submit(self, operation, exchange, timeout, **arguments):
        call = _Call(operation, exchange, timeout, **arguments)
        with self._command_lock:
            if self.closed:
                raise (
                    exchange.error
                    or self.error
                    or ProtocolError("HTTP/3 connection closed")
                )
            self.commands.put(call)
        self._wake()
        if not call.done.wait(timeout):
            call.cancelled = True
            self.cancel(exchange)
            raise TimeoutError("HTTP/3 stream timed out")
        if call.error:
            raise call.error
        return call.result

    def cancel(self, exchange):
        with self._command_lock:
            if exchange.closed:
                return
            exchange.closed = True
            if not self.closed:
                self.commands.put(_Call("cancel", exchange, None))
        self._wake()

    def _decode(self, algorithm, data, length, output, capacity):
        return TLS._decode(self, None, algorithm, data, length, output, capacity)

    def _events(self):
        for event in self._call("events")["events"]:
            kind = event["type"]
            exchange = self.streams.get(event.get("stream"))
            if kind == "auth":
                certificates = [
                    base64.b64decode(value) for value in event["certificates"]
                ]
                self.certificate_chain = b"".join(
                    struct.pack("!I", len(der)) + der for der in certificates
                )
                try:
                    self.context.verify(self.host, self.certificate_chain)
                except Exception as error:
                    self._call("auth", accepted=False)
                    raise ssl.SSLCertVerificationError(str(error)) from error
                self._call("auth", accepted=True)
            elif kind == "state":
                if event["state"] == "connected":
                    info = self._call("info")
                    self.info = info.get("tls")
                    if not hasattr(self, "certificate_chain"):
                        certificates = [
                            base64.b64decode(value)
                            for value in info.get("certificates", [])
                        ]
                        self.certificate_chain = b"".join(
                            struct.pack("!I", len(der)) + der for der in certificates
                        )
                        try:
                            self.context.verify(self.host, self.certificate_chain)
                        except Exception as error:
                            raise ssl.SSLCertVerificationError(str(error)) from error
                    self.ready.set()
                elif event["state"] == "going_away":
                    self.goaway = True
                    for stream, current in self.streams.items():
                        if stream >= event["last"]:
                            current.fail(
                                Rejected("HTTP/3 GOAWAY rejected this request")
                            )
                elif event["state"] == "closed":
                    error = (
                        Http3ProtocolError
                        if event.get("protocol_error")
                        else ProtocolError
                    )
                    raise error(event.get("reason", "HTTP/3 connection closed"))
            elif kind == "ech_retry":
                raise ssl.SSLError(
                    "HTTP/3 ECH retry requires updated DNS configuration"
                )
            elif kind == "token" and self.token_callback:
                self.token_callback(event["data"], event["expires_in"])
            elif exchange is not None:
                if kind in ("headers", "readable"):
                    exchange.received_data = True
                if kind == "headers" and not event["interim"]:
                    exchange.response_headers(event["headers"])
                    exchange.ended |= event["fin"]
                    exchange.headers_ready.set()
                elif kind == "readable":
                    exchange.readable = True
                elif kind == "stop_sending" and event["error"] == 0x100:
                    exchange.send_stopped = True
                elif kind in ("reset", "stop_sending"):
                    error = (
                        Rejected
                        if event["error"] == 0x10B
                        else Http1Required
                        if event["error"] == 0x110
                        else ProtocolError
                        if event["error"] == 0x10C
                        else DirectRouteReset
                    )
                    exchange.fail(error(f"HTTP/3 {kind}: {event['error']}"))

    def _execute(self, call):
        exchange = call.exchange
        if call.deadline is not None and time.monotonic() >= call.deadline:
            raise TimeoutError("HTTP/3 stream timed out")
        if exchange.error and call.operation != "cancel":
            raise exchange.error
        operation = call.operation
        if operation != "cancel" and exchange.closed:
            raise exchange.error or ProtocolError("HTTP/3 response closed")
        if call.cancelled:
            raise TimeoutError("HTTP/3 request operation cancelled")
        if operation == "fetch":
            if self.goaway:
                raise Rejected("HTTP/3 connection is draining")
            try:
                result = self._call("fetch", **call.arguments)
            except ProtocolError as error:
                if (
                    "stream limit" in str(error).lower()
                    or "streamlimit" in str(error).lower()
                ):
                    return False
                raise
            exchange.stream_id = result["stream"]
            exchange.sent_data = True
            self.streams[exchange.stream_id] = exchange
        elif operation == "read":
            if exchange.ended:
                call.result = b""
                return True
            if not exchange.readable:
                return False
            result = self._call("read", stream=exchange.stream_id, **call.arguments)
            call.result = base64.b64decode(result["data"])
            exchange.ended |= result["fin"]
            if not call.result and not exchange.ended:
                exchange.readable = False
                return False
        elif operation == "write":
            if exchange.send_stopped:
                call.result = len(base64.b64decode(call.arguments["data"]))
                return True
            result = self._call("write", stream=exchange.stream_id, **call.arguments)
            if not result["count"]:
                return False
            call.result = result["count"]
        elif operation == "cancel":
            self.streams.pop(exchange.stream_id, None)
            if exchange.stream_id is not None and not exchange.ended:
                try:
                    self._call("cancel", stream=exchange.stream_id)
                except ProtocolError:
                    pass
            exchange.fail(ProtocolError("HTTP/3 response closed"))
        elif operation == "finish":
            if not exchange.send_stopped:
                self._call("finish", stream=exchange.stream_id)
        return True

    def _run(self):
        udp = None
        selector = None
        self.handle = 0
        try:
            addresses = socket.getaddrinfo(*self.endpoint, type=socket.SOCK_DGRAM)
            family, kind, protocol, _, address = addresses[0]
            udp = socket.socket(family, kind, protocol)
            udp.connect(address)
            udp.setblocking(False)
            selector = selectors.DefaultSelector()
            selector.register(udp, selectors.EVENT_READ)
            selector.register(self._wake_read, selectors.EVENT_READ)
            self.peer_address = udp.getpeername()[0]
            self._decode_callback = _Decoder(self._decode)
            self.library.necko_quic_set_decoder(self._decode_callback)
            self.handle = self._call(
                "new",
                host=self.host,
                local=_address(udp.getsockname()),
                remote=_address(udp.getpeername()),
                token=self.token,
                profile=quic_profile(self.firefox),
            )["handle"]
            self._call("attach", socket=udp.fileno())
            while not self._stopping.is_set():
                self._events()
                while True:
                    try:
                        self.pending.append(self.commands.get_nowait())
                    except queue.Empty:
                        break
                waiting = []
                for call in self.pending:
                    try:
                        if not self._execute(call):
                            waiting.append(call)
                            continue
                    except Exception as error:
                        call.error = error
                    call.done.set()
                self.pending = waiting
                delay = min(0.1, self._call("pump")["delay"])
                self._events()
                readable = {key.fileobj for key, _ in selector.select(delay)}
                if self._wake_read in readable:
                    try:
                        while self._wake_read.recv(4096):
                            pass
                    except BlockingIOError:
                        pass
                if udp in readable:
                    self._call("pump")
        except Exception as error:
            self.error = error
        finally:
            with self._command_lock:
                self.closed = True
            self.ready.set()
            error = self.error or ProtocolError("HTTP/3 connection closed")
            for exchange in self.streams.values():
                exchange.fail(error)
            while True:
                try:
                    self.pending.append(self.commands.get_nowait())
                except queue.Empty:
                    break
            for call in self.pending:
                call.error = call.exchange.error or error
                call.done.set()
            try:
                if self.handle:
                    self._call("close")
            except (OSError, ProtocolError) as close_error:
                if self.error is None:
                    self.error = close_error
            finally:
                if selector:
                    selector.close()
                if udp:
                    udp.close()
                self._wake_read.close()
                self._wake_write.close()
                if self._dll_directory:
                    self._dll_directory.close()

    def idle(self):
        return not self.closed and not self.goaway

    def close(self):
        self._stopping.set()
        self._wake()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=1)


class Exchange:
    multiplexed = True

    def __init__(self, transport, method, url, headers, has_body, timeout=None):
        self.transport = self.connection = transport
        self.timeout = timeout
        self.stream_id = None
        self.status = None
        self.version, self.reason = 30, ""
        self.headers = HTTPHeaderDict()
        self.msg = Message()
        self.error = None
        self.received_data = False
        self.sent_data = False
        self.ended = False
        self.readable = False
        self.send_stopped = False
        self.closed = False
        self.headers_ready = threading.Event()
        self.sent_end = False
        target = urlsplit(url)
        path = (target.path or "/") + ("?" + target.query if target.query else "")
        excluded = {
            "host",
            "connection",
            "proxy-connection",
            "keep-alive",
            "upgrade",
            "transfer-encoding",
            "te",
        }
        excluded.update(
            item.strip().lower() for item in headers.get("Connection", "").split(",")
        )
        fields = []
        for raw_name, raw_value in headers.items():
            name = raw_name.decode("ascii") if isinstance(raw_name, bytes) else raw_name
            if name.lower() not in excluded:
                value = (
                    raw_value
                    if isinstance(raw_value, bytes)
                    else raw_value.encode("latin1")
                )
                fields.append((name.lower(), base64.b64encode(value).decode()))
        legacy = PROFILES[getattr(transport, "firefox", DEFAULT_FIREFOX)]["h3_priority"]
        if legacy and "Priority" not in headers:
            value = legacy[headers.get("Sec-Fetch-Dest") != "document"]
            fields.insert(0, ("priority", base64.b64encode(value.encode()).decode()))
        priority = headers.get("Priority", "u=4")
        urgency = next(
            (
                int(item[2:])
                for item in priority.replace(" ", "").split(",")
                if item.startswith("u=") and item[2:].isdigit()
            ),
            4,
        )
        try:
            transport.submit(
                "fetch",
                self,
                timeout,
                method=method,
                authority=headers["Host"],
                path=path,
                headers=fields,
                urgency=min(7, urgency),
                incremental="i" in [item.strip() for item in priority.split(",")],
            )
            if not has_body:
                self._finish()
        except Exception:
            self.close()
            raise

    def fail(self, error):
        if self.error is None:
            self.error = error
        self.headers_ready.set()

    def response_headers(self, fields):
        for name, encoded in fields:
            value = base64.b64decode(encoded)
            if name == ":status":
                self.status = int(value)
            elif not name.startswith(":"):
                self.headers.add(name, value.decode("latin1"))
                self.msg[name] = value.decode("latin1")

    def _finish(self):
        if not self.sent_end:
            self.transport.submit("finish", self, self.timeout)
            self.sent_end = True

    def write(self, data):
        data = data.encode() if isinstance(data, str) else data
        view = memoryview(data)
        while view:
            count = self.transport.submit(
                "write",
                self,
                self.timeout,
                data=base64.b64encode(view[:65536]).decode(),
            )
            view = view[count:]

    def receive(self):
        self._finish()
        if not self.headers_ready.wait(self.timeout):
            self.close()
            raise TimeoutError("HTTP/3 response headers timed out")
        if self.error:
            raise self.error

    def read(self, size):
        return self.transport.submit("read", self, self.timeout, size=size)

    def reusable(self):
        return self.ended

    def close(self):
        self.connection.cancel(self)
