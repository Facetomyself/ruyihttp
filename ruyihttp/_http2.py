# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import queue
import ssl
import threading
import time
from email.message import Message
from urllib.parse import urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    InformationalResponseReceived,
    PushedStreamReceived,
    RemoteSettingsChanged,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
    UnknownFrameReceived,
)
from h2.exceptions import H2Error
from h2.settings import SettingCodes, Settings
from h2.windows import WindowManager
from hpack import Encoder
from hpack.hpack import INDEX_INCREMENTAL, INDEX_NEVER
from hyperframe.frame import WindowUpdateFrame
from urllib3._collections import HTTPHeaderDict
from urllib3.exceptions import ProtocolError

from ._firefox import DEFAULT_FIREFOX, PROFILES
from ._http3 import _Call
from ._retry import Http1Required, Http1RequiredUnprocessed, Rejected, Reset


_CONNECTION_WINDOW = 12 * 1024**2
_STREAM_WINDOW = 128 * 1024  # Firefox SETTINGS_INITIAL_WINDOW_SIZE
_MAX_STREAMS = 64  # also counts completed responses until their bodies are released
_STREAM_BOOST = 512 * 1024
_MAX_BOOSTS = 7
_CREDIT_BATCH = 64 * 1024
# Reserve each stream's whole receive window, rather than betting on a peer's
# DATA scheduling. Leave 512 KiB of the Firefox connection window unassigned.
_BUFFER_LIMIT = _MAX_STREAMS * _STREAM_WINDOW + _MAX_BOOSTS * _STREAM_BOOST
_OUTPUT_LIMIT = 64 * 1024
_ACTIVE_POLL = (0.001, 0.008)
_PASSIVE_POLL = (0.005, 0.040)


class FirefoxEncoder(Encoder):
    @Encoder.header_table_size.setter
    def header_table_size(self, value):
        self.header_table.maxsize = value
        self.header_table.resized = True
        minimum = (
            min(value, *self.table_size_changes) if self.table_size_changes else value
        )
        self.table_size_changes = [minimum, value] if minimum < value else [value]

    def add(self, to_add, sensitive, huffman=False):
        name, value = to_add
        never = name == b"authorization" or name == b"cookie" and len(value) < 20
        plain = (
            name == b":path"
            or len(name) + len(value) + 32 > self.header_table_size // 2
            or self.header_table_size < 128
        )
        entries = (*self.header_table.STATIC_TABLE, *self.header_table.dynamic_entries)
        reference = 0
        matched = None
        for index, (entry_name, entry_value) in enumerate(entries, 1):
            if entry_name == name:
                reference = index
                if entry_value == value:
                    matched = index
                    break
        if matched and not never and not plain:
            return self._encode_indexed(matched)
        mode = INDEX_NEVER if never else b"\x00" if plain else INDEX_INCREMENTAL
        encoded = (
            self._encode_indexed_literal(reference, value, mode, True)
            if reference
            else self._encode_literal(name, value, mode, True)
        )
        if not never and not plain:
            self.header_table.add(name, value)
        return encoded


class _ConnectionWindow(WindowManager):
    def _maybe_update_window(self):
        # Use the same bookkeeping for application reads and the late DATA
        # hyper-h2 itself discards after RST_STREAM. Its default half-window
        # batching would let several MiB of consumed credit obscure our reserve.
        if self._bytes_processed < _CREDIT_BATCH:
            return None
        increment = min(
            self._bytes_processed, self.max_window_size - self.current_window_size
        )
        self._bytes_processed = 0
        self.window_opened(increment)
        return increment


class _LocalSettings(Settings):
    @Settings.enable_push.getter
    def enable_push(self):
        # Older profiles omit the setting. RFC 9113 gives that omission the
        # value 1; preserve the wire profile without leaving a lookup hole.
        return self.get(SettingCodes.ENABLE_PUSH, 1)


class _Protocol(H2Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._inbound_flow_control_window_manager = _ConnectionWindow(
            self.inbound_flow_control_window
        )

    def release_connection_credit(self, count):
        increment = self._inbound_flow_control_window_manager.process_bytes(count)
        if increment:
            frame = WindowUpdateFrame(0)
            frame.window_increment = increment
            self._prepare_for_sending([frame])

    def _receive_goaway_frame(self, frame):
        event = ConnectionTerminated()
        event.error_code = frame.error_code
        event.last_stream_id = frame.last_stream_id
        event.additional_data = frame.additional_data
        return [], [event]


class Connection:
    def __init__(self, transport):
        self.transport = transport
        self.transport.enable_nonblocking()
        self._output = bytearray()
        self._write_buffer = b""
        self._tls_pending = False
        self.protocol = _Protocol(
            H2Configuration(client_side=True, header_encoding=None)
        )
        self.protocol.encoder = FirefoxEncoder()
        profile = PROFILES[getattr(transport, "firefox", None) or DEFAULT_FIREFOX]
        wanted = dict(profile["h2_settings"])
        self.protocol.local_settings = _LocalSettings(
            client=True, initial_values=wanted
        )
        # hyper-h2 adds defaults Firefox omits; keep exactly the profile's.
        for code in list(self.protocol.local_settings):
            if code not in wanted:
                del self.protocol.local_settings[code]
        self.protocol.decoder.max_allowed_table_size = 65536
        self.protocol.initiate_connection()
        self.protocol.increment_flow_control_window(_CONNECTION_WINDOW - 65535)
        # Firefox before 132 (except 128) groups streams under idle "class"
        # streams 3-13: (stream, depends_on, weight).
        self.priority_tree = profile["h2_priority_tree"]
        if self.priority_tree:
            for stream, depends_on, weight in (
                (3, 0, 201),
                (5, 0, 101),
                (7, 0, 1),
                (9, 7, 1),
                (11, 3, 1),
                (13, 0, 241),
            ):
                self.protocol.prioritize(stream, weight=weight, depends_on=depends_on)
        self.streams = {}
        self._boosted_streams = 0
        self._buffered = 0
        # Permit one lease before peer SETTINGS, so the initial request can
        # still be written alongside the preface. Only the worker updates this.
        self._peer_stream_limit = 1
        self.closed = False
        self.goaway = False
        self.goaway_error = 0
        self.error = None
        self.received_settings = False
        self.origins = None
        self.commands = queue.Queue()
        self._command_lock = threading.Lock()
        self.pending = []
        self.wake = threading.Event()
        self._stopping = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="necko-http2", daemon=True
        )
        self._thread.start()

    def submit(self, operation, exchange, **arguments):
        call = _Call(operation, exchange, exchange.timeout, **arguments)
        with self._command_lock:
            if self.closed:
                return self._after_close(call)
            self.commands.put(call)
        self.wake.set()
        if not call.done.wait(exchange.timeout):
            call.cancelled = True
            self.cancel(exchange)
            raise TimeoutError("HTTP/2 stream timed out")
        if call.error:
            raise call.error
        return call.result

    def _after_close(self, call):
        # The peer may send END_STREAM and TLS close_notify back-to-back. A
        # queued headers/read operation has the same result as a later caller:
        # serve the fully received response, never invent EOF for a partial one.
        exchange = call.exchange
        if call.cancelled:
            raise TimeoutError("HTTP/2 request operation cancelled")
        if exchange.ended and not exchange.error:
            if call.operation == "read":
                return self._take_body(exchange, call.arguments["size"])
            if call.operation == "write" and exchange.upload_stopped:
                return 0
            if call.operation in ("headers", "finish", "cancel"):
                return None
        raise exchange.error or self.error or ProtocolError("HTTP/2 connection closed")

    def cancel(self, exchange):
        with self._command_lock:
            if exchange.closed:
                return
            exchange.closed = True
            if self.closed:
                self._discard_body(exchange)
                return
            self.commands.put(_Call("cancel", exchange, None))
        self.wake.set()

    def _take_body(self, exchange, size):
        data = bytes(memoryview(exchange.buffer)[:size])
        del exchange.buffer[: len(data)]
        self._buffered -= len(data)
        return data

    def _discard_body(self, exchange):
        count = len(exchange.buffer)
        exchange.buffer.clear()
        self._buffered -= count
        return count

    def _fail_exchange(self, exchange, error):
        exchange.fail(error)
        count = self._discard_body(exchange)
        if count:
            self.protocol.release_connection_credit(count)

    def _output_size(self):
        return len(self._output) + len(self._write_buffer)

    def flush(self):
        self._output.extend(self.protocol.data_to_send())
        if not (self._output or self._write_buffer or self._tls_pending):
            return
        for _ in range(32):
            if not self._write_buffer:
                if not self._output:
                    try:
                        self.transport.write_some(b"")
                        self._tls_pending = False
                    except BlockingIOError:
                        self._tls_pending = True
                    return
                self._write_buffer = bytes(self._output[:16384])
                del self._output[:16384]
            try:
                count = self.transport.write_some(self._write_buffer)
            except BlockingIOError:
                self._tls_pending = True
                return
            if not count:
                return
            self._write_buffer = self._write_buffer[count:]

    def receive(self):
        # A TLS read can produce ciphertext (e.g. a key update) even if no
        # HTTP/2 control frame is due. Give the native transport one flush.
        self._tls_pending = True
        data = self.transport.read(65536)
        if not data:
            raise Reset("HTTP/2 connection ended before stream completion")
        try:
            events = self.protocol.receive_data(data)
            for event in events:
                if isinstance(event, ConnectionTerminated):
                    self.goaway = True
                    self.goaway_error = event.error_code
                    for stream, exchange in self.streams.items():
                        if stream > event.last_stream_id and not exchange.ended:
                            error = (
                                Http1RequiredUnprocessed
                                if event.error_code == 13
                                else Rejected
                            )
                            self._fail_exchange(
                                exchange, error("HTTP/2 GOAWAY rejected this request")
                            )
                elif isinstance(event, StreamReset):
                    exchange = self.streams.get(event.stream_id)
                    if exchange is not None:
                        # RFC 9113 §8.1: NO_ERROR after a complete response asks
                        # us to stop uploading, not to discard the response.
                        if (
                            event.error_code == ErrorCodes.NO_ERROR
                            and exchange.ended
                            and exchange.status is not None
                        ):
                            exchange.upload_stopped = True
                            continue
                        error = (
                            Rejected
                            if event.error_code == 7
                            else Http1Required
                            if event.error_code == 13
                            else ProtocolError
                            if event.error_code in (0, 8)
                            else Reset
                        )
                        self._fail_exchange(
                            exchange, error(f"HTTP/2 stream reset: {event.error_code}")
                        )
                        if event.error_code == 9:
                            self.goaway = True
                elif isinstance(event, RemoteSettingsChanged):
                    self._peer_stream_limit = min(
                        _MAX_STREAMS,
                        self.protocol.remote_settings.max_concurrent_streams,
                    )
                    self.received_settings = True
                elif isinstance(event, PushedStreamReceived):
                    # Older profiles omit ENABLE_PUSH; the Requests API has
                    # no consumer for pushes. Never grant them receive budget.
                    stream = self.protocol.streams.get(event.pushed_stream_id)
                    if stream is not None and not stream.closed:
                        self.protocol.reset_stream(
                            event.pushed_stream_id, ErrorCodes.CANCEL
                        )
                elif (
                    isinstance(event, UnknownFrameReceived) and event.frame.type == 0xC
                ):
                    self.receive_origins(event.frame)
                elif isinstance(
                    event,
                    (
                        ResponseReceived,
                        InformationalResponseReceived,
                        DataReceived,
                        StreamEnded,
                        TrailersReceived,
                    ),
                ):
                    exchange = self.streams.get(event.stream_id)
                    if exchange is None or exchange.closed or exchange.error:
                        if isinstance(event, DataReceived):
                            self.protocol.release_connection_credit(
                                event.flow_controlled_length
                            )
                        continue
                    exchange.received_data = True
                    if isinstance(event, ResponseReceived):
                        exchange.response_headers(event.headers)
                    elif isinstance(event, DataReceived):
                        size = len(event.data)
                        if (
                            len(exchange.buffer) + size > exchange.receive_limit
                            or self._buffered + size > _BUFFER_LIMIT
                        ):
                            raise ProtocolError("HTTP/2 receive buffer limit exceeded")
                        exchange.buffer.extend(event.data)
                        self._buffered += size
                        # Padding occupies wire credit but never occupies the body
                        # buffer. Return it even when the application does not read.
                        padding = event.flow_controlled_length - size
                        if padding:
                            self.protocol.acknowledge_received_data(
                                padding, event.stream_id
                            )
                    elif isinstance(event, StreamEnded):
                        exchange.ended = True
        except H2Error as error:
            raise ProtocolError(str(error)) from error

    def receive_origins(self, frame):
        if (
            frame.stream_id
            or frame.flag_byte & 0x0F
            or getattr(self.transport, "using_proxy", False)
        ):
            return
        origins = set(self.origins or ())
        data = frame.body
        while len(data) >= 2:
            size = int.from_bytes(data[:2], "big")
            data = data[2:]
            if size > len(data):
                break
            value, data = data[:size], data[size:]
            try:
                origin = urlsplit(value.decode("ascii"))
                if origin.scheme != "https" or not origin.hostname:
                    continue
                host = origin.hostname.encode("idna").decode("ascii")
                if any(character in host for character in "*\\\x00\r\n\t "):
                    continue
                origins.add((host, origin.port or 443))
            except (ValueError, UnicodeError):
                continue
        self.origins = frozenset(origins)

    def idle(self):
        return not (self.closed or self.goaway or self._stopping.is_set())

    def has_capacity(self, leased):
        # The pool counts leases before a fetch is enqueued and until the body
        # is released. The worker rechecks actual wire capacity after SETTINGS.
        return leased < self._peer_stream_limit

    def _execute(self, call):
        exchange = call.exchange
        operation = call.operation
        if call.cancelled:
            raise TimeoutError("HTTP/2 request operation cancelled")
        if operation != "cancel" and exchange.closed:
            raise exchange.error or ProtocolError("HTTP/2 response closed")
        if operation != "cancel" and exchange.error:
            raise exchange.error
        if operation in ("write", "finish") and exchange.upload_stopped:
            if operation == "write":
                call.result = 0
            return True
        if call.deadline is not None and time.monotonic() >= call.deadline:
            raise TimeoutError("HTTP/2 stream timed out")
        if (
            operation in ("fetch", "write", "finish")
            and self._output_size() >= _OUTPUT_LIMIT
        ):
            return False
        if operation == "fetch":
            if self.goaway:
                if self.goaway_error == 13:
                    raise Http1RequiredUnprocessed("HTTP/2 peer requires HTTP/1.1")
                raise Rejected("HTTP/2 connection is draining")
            if (
                len(self.streams) >= _MAX_STREAMS
                or self.protocol.open_outbound_streams >= self._peer_stream_limit
            ):
                return False
            # Requests follow the priority tree's idle streams when there is one.
            first = 15 if self.priority_tree else 3
            exchange.stream_id = max(
                first, self.protocol.get_next_available_stream_id()
            )
            exchange.sent_data = True
            self.protocol.send_headers(
                exchange.stream_id,
                call.arguments["headers"],
                end_stream=exchange.sent_end,
                priority_weight=call.arguments["weight"],
                priority_depends_on=(
                    (13 if call.arguments["document"] else 11)
                    if self.priority_tree
                    else 0
                ),
                priority_exclusive=False,
            )
            if self._boosted_streams < _MAX_BOOSTS:
                self.protocol.increment_flow_control_window(
                    _STREAM_BOOST, exchange.stream_id
                )
                exchange.receive_limit += _STREAM_BOOST
                self._boosted_streams += 1
            self.streams[exchange.stream_id] = exchange
        elif operation == "write":
            window = self.protocol.local_flow_control_window(exchange.stream_id)
            if window <= 0:
                return False
            data = call.arguments["data"]
            count = min(len(data), window, self.protocol.max_outbound_frame_size, 16000)
            self.protocol.send_data(exchange.stream_id, data[:count])
            call.result = count
        elif operation == "finish":
            if not exchange.sent_end:
                self.protocol.end_stream(exchange.stream_id)
                exchange.sent_end = True
        elif operation == "headers":
            if exchange.status is None:
                return False
        elif operation == "read":
            size = call.arguments["size"]
            if size and not exchange.buffer and not exchange.ended:
                return False
            call.result = self._take_body(exchange, size)
            count = len(call.result)
            if count:
                if exchange.ended:
                    self.protocol.release_connection_credit(count)
                else:
                    self.protocol.acknowledge_received_data(count, exchange.stream_id)
        elif operation == "cancel":
            if self.streams.pop(exchange.stream_id, None) is not None:
                self._boosted_streams -= exchange.receive_limit > _STREAM_WINDOW
            if exchange.stream_id is not None and not (
                exchange.ended and exchange.sent_end
            ):
                try:
                    self.protocol.reset_stream(
                        exchange.stream_id, error_code=ErrorCodes.CANCEL
                    )
                except H2Error:
                    pass
            self._fail_exchange(exchange, ProtocolError("HTTP/2 response closed"))
        return True

    def _run(self):
        delay = 0
        try:
            while not self._stopping.is_set():
                self.wake.clear()
                while True:
                    try:
                        self.pending.append(self.commands.get_nowait())
                        delay = 0
                    except queue.Empty:
                        break
                waiting = []
                completed = False
                for call in self.pending:
                    try:
                        if not self._execute(call):
                            waiting.append(call)
                            continue
                    except Exception as error:
                        call.error = error
                    # Count queued control/data against the same output limit
                    # before running another call, without flushing per call.
                    self._output.extend(self.protocol.data_to_send())
                    call.done.set()
                    completed = True
                self.pending = waiting
                self.flush()
                received = False
                for _ in range(32):
                    # Bound control replies when a peer sends but stops reading.
                    if self._output_size() >= _OUTPUT_LIMIT or self._stopping.is_set():
                        break
                    pending = self.transport.library.necko_tls_pending(
                        self.transport.handle
                    )
                    if pending < 0:
                        cause = getattr(self.transport, "error", None)
                        raise Reset(
                            f"HTTP/2 transport closed: {cause}"
                            if cause
                            else "HTTP/2 transport closed"
                        )
                    if not pending:
                        break
                    try:
                        self.receive()
                    except BlockingIOError:
                        break
                    received = True
                    self.flush()
                else:
                    delay = 0
                    continue
                if self._stopping.is_set():
                    break
                if received or completed:
                    delay = 0
                    if self.pending:
                        # Headers, END_STREAM, SETTINGS, and upload credit can
                        # satisfy already queued calls without another poll.
                        continue
                active = bool(self.pending or self._output_size() or self._tls_pending)
                minimum, maximum = _ACTIVE_POLL if active else _PASSIVE_POLL
                delay = min(maximum, max(minimum, delay * 2))
                deadline = min(
                    (
                        call.deadline
                        for call in self.pending
                        if call.deadline is not None
                    ),
                    default=None,
                )
                remaining = (
                    delay if deadline is None else max(0, deadline - time.monotonic())
                )
                # Native TLS exposes a nonblocking pending probe, not a socket
                # descriptor. Commands and close interrupt the bounded wait.
                if self.wake.wait(min(delay, remaining)):
                    delay = 0
            if self._stopping.is_set() and not self.closed:
                self.protocol.close_connection(error_code=0)
                self.flush()
        except Exception as error:
            if isinstance(error, OSError) and not isinstance(
                error, (TimeoutError, ssl.SSLError)
            ):
                error = Reset(str(error))
            self.error = error
        finally:
            with self._command_lock:
                self.closed = True
                error = self.error or ProtocolError("HTTP/2 connection closed")
                for exchange in self.streams.values():
                    if not exchange.ended:
                        exchange.fail(error)
                    if exchange.closed or exchange.error:
                        self._discard_body(exchange)
                self.streams.clear()
                self._boosted_streams = 0
                while True:
                    try:
                        self.pending.append(self.commands.get_nowait())
                    except queue.Empty:
                        break
                for call in self.pending:
                    if not call.done.is_set():
                        try:
                            call.result = self._after_close(call)
                        except Exception as exc:
                            call.error = exc
                        call.done.set()
            self.transport._close_native()

    def close(self):
        self._stopping.set()
        self.wake.set()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=1)


class Exchange:
    multiplexed = True

    def __init__(self, transport, method, url, headers, has_body, timeout=None):
        self.transport = transport
        if not getattr(transport, "h2", None):
            transport.h2 = Connection(transport)
        self.connection = transport.h2
        self.stream_id = None
        self.timeout = timeout
        self.error = None
        self.received_data = False
        self.sent_data = False
        self.closed = False
        self.buffer = bytearray()
        self.receive_limit = _STREAM_WINDOW
        self.ended = False
        self.sent_end = not has_body
        self.upload_stopped = False
        self.status = None
        self.version = 20
        self.reason = ""
        self.headers = HTTPHeaderDict()
        self.msg = Message()
        target = urlsplit(url)
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        fields = [
            (b":method", method.encode("ascii")),
            (b":path", path.encode("ascii")),
            (b":authority", headers["Host"].encode("ascii")),
            (b":scheme", target.scheme.encode("ascii")),
        ]
        excluded = {
            "host",
            "connection",
            "proxy-connection",
            "keep-alive",
            "upgrade",
            "transfer-encoding",
        }
        excluded.update(
            item.strip().lower() for item in headers.get("Connection", "").split(",")
        )
        for raw_name, raw_value in headers.items():
            name = raw_name.decode("ascii") if isinstance(raw_name, bytes) else raw_name
            value = (
                raw_value
                if isinstance(raw_value, bytes)
                else raw_value.encode("latin1")
            )
            if name.lower() not in excluded:
                if name.lower() == "cookie":
                    fields.extend((b"cookie", part) for part in value.split(b"; "))
                else:
                    fields.append((name.lower().encode("ascii"), value))
        try:
            self.connection.submit(
                "fetch",
                self,
                headers=fields,
                document=headers.get("Sec-Fetch-Dest") == "document",
                weight=42 if headers.get("Sec-Fetch-Dest") == "document" else 22,
            )
        except Exception:
            self.close()
            raise

    def fail(self, error):
        if self.error is None:
            self.error = error

    def response_headers(self, fields):
        for name, value in fields:
            if name == b":status":
                self.status = int(value)
            elif not name.startswith(b":"):
                decoded_name, decoded_value = (
                    name.decode("ascii"),
                    value.decode("latin1"),
                )
                self.headers.add(decoded_name, decoded_value)
                self.msg[decoded_name] = decoded_value

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        view = memoryview(data)
        while view and not self.upload_stopped:
            size = self.connection.submit("write", self, data=bytes(view[:16000]))
            if not size:
                break
            view = view[size:]

    def receive(self):
        self.connection.submit("finish", self)
        self.connection.submit("headers", self)

    def read(self, size):
        return self.connection.submit("read", self, size=size)

    def reusable(self):
        return self.ended and not self.buffer

    def close(self):
        self.connection.cancel(self)
