# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Requests API transport backed by NSS and native HTTP/1 or hyper-h2."""

import ctypes
import hashlib
import io
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import uuid
import warnings
from collections import OrderedDict
from email.parser import Parser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography.x509.verification import VerificationError
from requests.adapters import HTTPAdapter as RequestsAdapter
from requests.auth import _basic_auth_str
from requests.exceptions import (
    ConnectionError,
    ConnectTimeout,
    InvalidHeader,
    InvalidProxyURL,
    InvalidSchema,
    ProxyError,
    ReadTimeout,
    RequestException,
    RetryError,
    SSLError,
    UnrewindableBodyError,
)
from requests.structures import CaseInsensitiveDict
from requests.utils import prepend_scheme_if_needed, select_proxy
from urllib3._collections import HTTPHeaderDict
from urllib3.exceptions import (
    ConnectTimeoutError,
    InsecureRequestWarning,
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
    ReadTimeoutError,
)
from urllib3.exceptions import (
    ProxyError as UrllibProxyError,
)
from urllib3.exceptions import (
    SSLError as UrllibSSLError,
)
from urllib3.response import HTTPResponse
from urllib3.util import Timeout

from ._connect import Attempt, connect_tcp, resolve_addresses
from ._firefox import PROFILES, firefox_version, wire_headers
from ._native_buffer import read_bytes
from ._nss import TLS as _TLS
from ._nss import Context as _ssl_context
from ._nss import configure_library
from ._retry import (
    MAX_REQUEST_ATTEMPTS,
    DirectRouteReset,
    Http1Required,
    Http3ProtocolError,
    Reset,
    restartable,
)

_Pointer = ctypes.c_void_p
_Bytes = ctypes.POINTER(ctypes.c_uint8)
_Read = ctypes.CFUNCTYPE(
    ctypes.c_int, _Pointer, _Bytes, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)
)
_Write = ctypes.CFUNCTYPE(ctypes.c_int, _Pointer, _Bytes, ctypes.c_uint32)
_Cancel = ctypes.CFUNCTYPE(ctypes.c_int, _Pointer)

_ALT_SVC_LIMIT = 256
_ALT_SVC_MAX_AGE = 86400
_ALT_SVC_COOLDOWN = 5
_ALT_SVC_RACE_DELAY = 0.1
_QUIC_TOKEN_LIMIT = 128
_QUIC_TOKEN_BYTES = 512 * 1024
_QUIC_TOKEN_MAX_SIZE = 16 * 1024
_QUIC_TOKEN_MAX_AGE = 86400


def is_masque_proxy(proxy):
    # An ordinary HTTPS CONNECT proxy remains a TCP proxy, not a MASQUE URI.
    return isinstance(proxy, str) and proxy.partition(':')[0].lower() == 'masque' and ':' in proxy


def masque_route_id(proxy, proxy_verify=True, path_template=None):
    # Length prefixes separate fields, including the default CA vs. a file named
    # 'True'. Never put Basic credentials or a template query in a pool key.
    if proxy_verify is True:
        trust = b'default'
    elif isinstance(proxy_verify, (str, os.PathLike)) and isinstance(os.fspath(proxy_verify), str) and os.fspath(proxy_verify):
        trust = b'file:' + os.fsencode(os.path.abspath(proxy_verify))
    else:
        raise ValueError('MASQUE proxy_verify must be True or a CA bundle file path')
    if path_template is not None and (not isinstance(path_template, str) or not path_template or len(path_template) > 4096):
        raise ValueError('Invalid MASQUE path template')
    if len(proxy) > 4096:
        raise InvalidProxyURL('Invalid MASQUE proxy URL')
    key = hashlib.sha256(b'ruyihttp:connect-udp:v1')
    for item in (proxy.encode('utf-8'), trust, (path_template or '').encode('utf-8')):
        key.update(len(item).to_bytes(4, 'big'))
        key.update(item)
    return key.digest()


def _expired_records(cache, now):
    return [key for key, (_, expiry) in cache.items() if expiry <= now]


def _socket_error(result, operation):
    """Build an OSError for a failed native socket call, with the OS reason.

    Must be called on the thread that made the call, before other socket work.
    """
    if os.name == "nt":
        code = ctypes.windll.ws2_32.WSAGetLastError()
        if code:
            return OSError(None, f"Native socket {operation} failed", None, code)
    return OSError(f"Native socket {operation} error {result}")


def _load_library(path=None):
    if path is None:
        path = os.environ.get("NECKO_CORE_LIBRARY")
    if not path:
        name = (
            "necko_core.dll"
            if os.name == "nt"
            else (
                "libnecko_core.dylib"
                if sys.platform == "darwin"
                else "libnecko_core.so"
            )
        )
        path = Path(__file__).with_name(name)
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(
            f"Native Necko runtime not found at {path}. Install the ruyihttp "
            "wheel for your platform, set NECKO_CORE_LIBRARY to a compatible "
            "native library file, or pass Session(library_path=...)."
        )
    try:
        if os.name == "nt":
            with os.add_dll_directory(str(path.parent)):
                library = ctypes.CDLL(str(path))
        else:
            library = ctypes.CDLL(str(path))
    except OSError as error:
        raise OSError(
            f"Failed to load the native Necko runtime at {path}. Check that "
            "its architecture matches Python and its runtime dependencies "
            f"are installed: {error}"
        ) from error
    configure_library(library)
    signatures = {
        "socket_open": (
            [
                ctypes.c_char_p,
                ctypes.c_uint16,
                ctypes.c_uint32,
                ctypes.POINTER(_Pointer),
            ],
            ctypes.c_int,
        ),
        "socket_close": ([_Pointer], None),
        "socket_interrupt": ([_Pointer], None),
        "socket_open_cancellable": (
            [
                ctypes.c_char_p,
                ctypes.c_uint16,
                ctypes.c_uint32,
                _Cancel,
                _Pointer,
                ctypes.POINTER(_Pointer),
            ],
            ctypes.c_int,
        ),
        "socket_idle": ([_Pointer], ctypes.c_int),
        "socket_read": (
            [
                _Pointer,
                _Bytes,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
            ],
            ctypes.c_int,
        ),
        "socket_write": (
            [_Pointer, _Bytes, ctypes.c_uint32, ctypes.c_uint32],
            ctypes.c_int,
        ),
        "exchange_open": (
            [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_char_p,
                _Read,
                _Write,
                _Pointer,
                ctypes.POINTER(_Pointer),
            ],
            ctypes.c_int,
        ),
        "exchange_write": ([_Pointer, _Bytes, ctypes.c_uint32], ctypes.c_int),
        "exchange_receive": ([_Pointer], ctypes.c_int),
        "exchange_headers": ([_Pointer], ctypes.c_char_p),
        "exchange_read": (
            [_Pointer, _Bytes, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)],
            ctypes.c_int,
        ),
        "exchange_reusable": ([_Pointer], ctypes.c_int),
        "exchange_close": ([_Pointer], None),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(library, "necko_" + name)
        function.argtypes = arguments
        function.restype = result
    if hasattr(library, "necko_socket_peer"):
        library.necko_socket_peer.argtypes = [
            _Pointer,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint16),
        ]
        library.necko_socket_peer.restype = ctypes.c_int
    library.necko_socket_write_some.argtypes = [
        _Pointer,
        _Bytes,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.necko_socket_write_some.restype = ctypes.c_int
    return library


def _milliseconds(value):
    if value is None:
        return 0xFFFFFFFF
    if not math.isfinite(value) or value <= 0 or value * 1000 >= 0xFFFFFFFF:
        raise ValueError("timeout must be positive, finite, and below 4294967 seconds")
    return max(1, math.ceil(value * 1000))


class _NativeSocket:
    def __init__(self, library, host, port, timeout, attempt=None):
        self.library = library
        self.handle = _Pointer()
        self._handle_lock = threading.Lock()
        self.attempt = attempt
        self.timeout = timeout
        if attempt is None:
            result = library.necko_socket_open(
                host.encode("idna"),
                port,
                _milliseconds(timeout),
                ctypes.byref(self.handle),
            )
        else:
            cancelled = _Cancel(lambda _: int(attempt.cancelled.is_set()))
            remaining = attempt.remaining()
            if remaining is not None:
                timeout = remaining if timeout is None else min(timeout, remaining)
            result = library.necko_socket_open_cancellable(
                host.encode("idna"),
                port,
                _milliseconds(timeout),
                cancelled,
                None,
                ctypes.byref(self.handle),
            )
        if result or not self.handle:
            self.close()
            if result == 5:
                raise ConnectTimeout(f"Connection to {host}:{port} timed out")
            reason = f"error {result}" if result else "returned a null handle"
            error = ConnectionError(f"Native connection {reason} for {host}:{port}")
            error._necko_connect = True
            raise error
        if attempt is not None:
            attempt.set_interrupt(self.interrupt)
        self.peer_address = None
        self.peer_port = None
        if hasattr(library, "necko_socket_peer"):
            host_buffer = ctypes.create_string_buffer(128)
            peer_port = ctypes.c_uint16()
            if not library.necko_socket_peer(
                self.handle, host_buffer, 128, ctypes.byref(peer_port)
            ):
                self.peer_address = host_buffer.value.decode("ascii")
                self.peer_port = peer_port.value

    def idle(self):
        return bool(self.handle and self.library.necko_socket_idle(self.handle))

    def read(self, size):
        buffer = (ctypes.c_uint8 * size)()
        length = ctypes.c_uint32()
        result = self.library.necko_socket_read(
            self.handle,
            buffer,
            size,
            _milliseconds(self._timeout()),
            ctypes.byref(length),
        )
        if result == 5:
            raise TimeoutError("Read timed out")
        if result:
            raise _socket_error(result, "read")
        return read_bytes(buffer, length.value)

    def write(self, data):
        buffer = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        result = self.library.necko_socket_write(
            self.handle, buffer, len(data), _milliseconds(self._timeout())
        )
        if result == 5:
            raise TimeoutError("Write timed out")
        if result:
            raise _socket_error(result, "write")

    def read_some(self, size):
        buffer = (ctypes.c_uint8 * size)()
        length = ctypes.c_uint32()
        result = self.library.necko_socket_read(
            self.handle, buffer, size, 0, ctypes.byref(length)
        )
        if result == 5:
            raise BlockingIOError("Socket read would block")
        if result:
            raise _socket_error(result, "read")
        return read_bytes(buffer, length.value)

    def write_some(self, data):
        buffer = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        length = ctypes.c_uint32()
        result = self.library.necko_socket_write_some(
            self.handle, buffer, len(data), ctypes.byref(length)
        )
        if result == 5:
            raise BlockingIOError("Socket write would block")
        if result:
            raise _socket_error(result, "write")
        return length.value

    def _timeout(self):
        return self.attempt.remaining() if self.attempt is not None else self.timeout

    def interrupt(self):
        with self._handle_lock:
            if self.handle:
                self.library.necko_socket_interrupt(self.handle)

    def close(self):
        with self._handle_lock:
            if self.handle:
                self.library.necko_socket_close(self.handle)
                self.handle = _Pointer()

    def __del__(self):
        self.close()


# First-pass result: a live multiplexed connection could be borrowed if DNS agrees.
_NEEDS_DNS = object()


class _BorrowedConnection:
    """An existing lease returned by a race lane. A losing lane returns it to its pool."""

    def __init__(self, pool, connection):
        self.pool = pool
        self.connection = connection
        self.alpn = connection.alpn

    def close(self):
        self.pool.release(self.connection)


class _Pool:
    def __init__(self, maximum, block):
        self.maximum = maximum
        self.block = block
        self.idle = []
        self.shared = {}
        self.connecting = False
        self.leased = 0
        self.closed = False
        self.condition = threading.Condition()

    def _has_capacity(self, connection):
        # Check under condition; a lease occupies a slot even before its
        # Exchange submits HEADERS, so concurrent callers cannot double-book.
        h2 = getattr(connection, "h2", None)
        return h2 is None or h2.has_capacity(self.shared.get(connection, 0))

    def acquire(self, prefer=None, http3=True, *, attempt=None):
        with self.condition:
            while True:
                remaining = attempt.remaining() if attempt is not None else None
                if self.closed:
                    raise ConnectionError("Connection pool closed")
                for connection in list(self.shared):
                    if (
                        connection.idle()
                        and (prefer is None or connection.alpn == prefer)
                        and (http3 or connection.alpn != "h3")
                        and self._has_capacity(connection)
                    ):
                        self.shared[connection] += 1
                        self.leased += 1
                        return connection
                    if self.shared[connection] == 0 and not connection.idle():
                        self.shared.pop(connection)
                        connection.close()
                if (
                    prefer == "h3"
                    and remaining is not None
                    and remaining <= _ALT_SVC_RACE_DELAY
                    and (not self.block or self.leased < self.maximum)
                ):
                    # An established H3 still wins above. With no room for a
                    # normal QUIC head start, use a warm TCP lease directly,
                    # even if another request is already probing the route.
                    warm = self.borrow_tcp()
                    if warm is not None:
                        return warm
                if self.connecting or self.block and self.leased >= self.maximum:
                    self.condition.wait(attempt.remaining() if attempt is not None else None)
                    continue
                self.leased += 1
                for index in range(len(self.idle) - 1, -1, -1):
                    connection = self.idle[index]
                    if not connection.idle():
                        self.idle.pop(index).close()
                    elif prefer is None or getattr(connection, "alpn", None) == prefer:
                        return self.idle.pop(index)
                self.connecting = True
                return None

    def register(self, connection):
        with self.condition:
            if getattr(connection, "multiplexed", False):
                self.shared[connection] = self.shared.get(connection, 0) + 1
            self.connecting = False
            self.condition.notify_all()

    def borrow_tcp(self):
        """Take a live TCP lease without waiting for or replacing the dial reservation."""
        with self.condition:
            if self.closed:
                return None
            for connection in self.shared:
                if (
                    connection.alpn == "h2"
                    and connection.idle()
                    and self._has_capacity(connection)
                ):
                    self.shared[connection] += 1
                    self.leased += 1
                    return connection
            for index in range(len(self.idle) - 1, -1, -1):
                connection = self.idle.pop(index)
                if connection.idle():
                    self.leased += 1
                    return connection
                connection.close()
            return None

    def borrow(self, host, port, addresses, prefer=None, http3=True):
        result = None
        with self.condition:
            if self.closed:
                return None
            for connection in self.shared:
                if not connection.idle() or prefer and connection.alpn != prefer:
                    continue
                if not http3 and connection.alpn == "h3":
                    continue
                if getattr(connection, "origin_port", None) != port:
                    continue
                if host in getattr(connection, "coalescing_denied", set()):
                    continue
                if not self._has_capacity(connection):
                    continue
                protocol = getattr(connection, "h2", None)
                origin_allowed = False
                if protocol is not None:
                    if not protocol.received_settings:
                        continue
                    if protocol.origins is not None:
                        if (host, port) not in protocol.origins:
                            continue
                        origin_allowed = True
                if not origin_allowed:
                    peer = getattr(connection, "peer_address", None)
                    if not peer:
                        continue
                    if addresses is None:
                        result = _NEEDS_DNS
                        continue
                    if peer not in addresses:
                        continue
                try:
                    connection.context.verify(host, connection.certificate_chain)
                except (AttributeError, ValueError, ssl.SSLError, VerificationError):
                    continue
                self.shared[connection] += 1
                self.leased += 1
                return connection
        return result

    def release(self, connection, *, reuse=True):
        with self.condition:
            self.leased -= 1
            if connection in self.shared:
                self.shared[connection] -= 1
                if self.shared[connection] == 0 and (
                    self.closed
                    or not connection.idle()
                    or (
                        getattr(connection, "h2", None) is not None
                        and sum(
                            not leases and getattr(peer, "h2", None) is not None
                            for peer, leases in self.shared.items()
                        ) > self.maximum
                    )
                ):
                    # Nonblocking pools may spill to extra live connections,
                    # but retain at most pool_maxsize idle H2 connections.
                    self.shared.pop(connection)
                    connection.close()
                self.condition.notify_all()
                return
            if connection is None:
                # Only a dial reservation is returned as None. A discarded H1
                # lease must not clear another request's in-progress dial.
                self.connecting = False
                self.condition.notify_all()
            else:
                if not reuse or self.closed or len(self.idle) >= self.maximum:
                    connection.close()
                else:
                    self.idle.append(connection)
                self.condition.notify()

    def close(self):
        with self.condition:
            self.closed = True
            for connection in self.idle:
                connection.close()
            for connection, users in list(self.shared.items()):
                if not users:
                    connection.close()
                    self.shared.pop(connection)
            self.idle.clear()
            self.condition.notify_all()


class _Exchange:
    def __init__(self, library, transport, method, target, headers):
        self.library = library
        self.transport = transport
        self.handle = _Pointer()
        self.error = None
        self.sent_data = False
        self.received_data = False
        self._read_callback = _Read(self._read)
        self._write_callback = _Write(self._write)
        wire = "".join(
            f"{name.decode('ascii') if isinstance(name, bytes) else name}: "
            f"{value.decode('latin1') if isinstance(value, bytes) else value}\r\n"
            for name, value in headers.items()
        )
        if "\x00" in wire or "\x00" in method or "\x00" in target:
            raise InvalidHeader("NUL in request")
        result = library.necko_exchange_open(
            method.encode("ascii"),
            target.encode("ascii"),
            wire.encode("latin1"),
            self._read_callback,
            self._write_callback,
            None,
            ctypes.byref(self.handle),
        )
        self.check(result)

    def _read(self, _closure, buffer, capacity, length):
        try:
            data = self.transport.read(capacity)
            self.received_data |= bool(data)
            if not data and not self.received_data:
                raise Reset("HTTP/1 connection ended before a response")
            ctypes.memmove(buffer, data, len(data))
            length[0] = len(data)
            return 0
        except Exception as error:
            self.error = error
            return 6

    def _write(self, _closure, buffer, length):
        try:
            self.sent_data |= bool(length)
            self.transport.write(ctypes.string_at(buffer, length))
            return 0
        except Exception as error:
            self.error = error
            return 6

    def check(self, result):
        if self.error is not None:
            error, self.error = self.error, None
            if isinstance(error, OSError) and not isinstance(
                error, (TimeoutError, ssl.SSLError)
            ):
                error = Reset(str(error))
            error._necko_sent = self.sent_data
            error._necko_received = self.received_data
            raise error
        if result == 1:
            raise InvalidHeader("Invalid native request framing or Content-Length")
        if result:
            raise ProtocolError(f"Native HTTP framing error {result}")

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        view = memoryview(data)
        for start in range(0, len(view), 65536):
            part = view[start : start + 65536]
            buffer = (ctypes.c_uint8 * len(part)).from_buffer_copy(part)
            self.check(
                self.library.necko_exchange_write(self.handle, buffer, len(part))
            )

    def receive(self):
        self.check(self.library.necko_exchange_receive(self.handle))
        wire = self.library.necko_exchange_headers(self.handle).decode("latin1")
        status, _, fields = wire.partition("\r\n")
        version, code, *reason = status.split(" ", 2)
        self.version = 11 if version == "HTTP/1.1" else 10
        self.status = int(code)
        self.reason = reason[0] if reason else ""
        self.msg = Parser().parsestr(fields)
        self.headers = HTTPHeaderDict()
        for name, value in self.msg.items():
            self.headers.add(name, value)

    def read(self, size):
        buffer = (ctypes.c_uint8 * size)()
        length = ctypes.c_uint32()
        self.check(
            self.library.necko_exchange_read(
                self.handle, buffer, size, ctypes.byref(length)
            )
        )
        return read_bytes(buffer, length.value)

    def close(self):
        if self.handle:
            self.library.necko_exchange_close(self.handle)
            self.handle = _Pointer()
        self._read_callback = self._write_callback = None

    def reusable(self):
        return bool(self.library.necko_exchange_reusable(self.handle))


class _Body(io.RawIOBase):
    def __init__(self, exchange, pool):
        super().__init__()
        self.exchange = exchange
        self.pool = pool
        self.msg = exchange.msg

    def isclosed(self):
        return self.closed

    def read(self, size=-1):
        if self.closed or size == 0:
            return b""
        pieces = []
        remaining = size
        try:
            while remaining != 0:
                chunk = self.exchange.read(
                    65536
                    if remaining is None or remaining < 0
                    else min(remaining, 65536)
                )
                if not chunk:
                    self.close()
                    break
                pieces.append(chunk)
                if remaining is not None and remaining > 0:
                    remaining -= len(chunk)
                if self.exchange.reusable():
                    self.close()
                    break
            return b"".join(pieces)
        except Exception:
            self.close(reuse=False)
            raise

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def read1(self, size=-1):
        if self.closed or size == 0:
            return b""
        try:
            data = self.exchange.read(
                65536 if size is None or size < 0 else min(size, 65536)
            )
            if not data or self.exchange.reusable():
                self.close()
            return data
        except Exception:
            self.close(reuse=False)
            raise

    def close(self, reuse=True):
        if not self.closed:
            exchange = self.exchange
            connection = exchange.transport
            reusable = reuse and exchange.reusable()
            exchange.close()
            self.pool.release(connection, reuse=reusable)
            super().close()


class HeaderMap(CaseInsensitiveDict):
    def __init__(self, items=(), **kwargs):
        self._values = HTTPHeaderDict()
        super().__init__()
        for name, value in items.items() if hasattr(items, "items") else items:
            self._values.add(name, value)
            super().__setitem__(name, self._values[name])
        self.update(kwargs)

    def __setitem__(self, key, value):
        self._values[key] = value
        super().__setitem__(key, value)

    def __delitem__(self, key):
        del self._values[key]
        super().__delitem__(key)

    def get_all(self, name, default=None):
        return self._values.getlist(name) or ([] if default is None else default)

    def getlist(self, name):
        return self.get_all(name)


class HTTPAdapter(RequestsAdapter):
    __attrs__ = RequestsAdapter.__attrs__ + ["library_path", "firefox"]

    def __init__(
        self,
        pool_connections=10,
        pool_maxsize=10,
        max_retries=0,
        pool_block=False,
        library_path=None,
        firefox=None,
    ):
        if pool_connections < 1 or pool_maxsize < 1:
            raise ValueError("pool sizes must be positive")
        self.library_path = library_path
        self.firefox = firefox_version(firefox)
        self._library = None
        self._pools = OrderedDict()
        self._lock = threading.Lock()
        self._tls_partition = uuid.uuid4().hex
        self._alt_svc = OrderedDict()
        self._alt_cooldowns = OrderedDict()
        self._quic_tokens = OrderedDict()
        self._quic_token_bytes = 0
        self._token_lock = threading.Lock()
        super().__init__(pool_connections, pool_maxsize, max_retries, pool_block)

    def __setstate__(self, state):
        self._tls_partition = uuid.uuid4().hex
        self._alt_svc = OrderedDict()
        self._alt_cooldowns = OrderedDict()
        self._quic_tokens = OrderedDict()
        self._quic_token_bytes = 0
        self._token_lock = threading.Lock()
        self._library = None
        self._pools = OrderedDict()
        self._lock = threading.Lock()
        state.setdefault("firefox", firefox_version(None))
        super().__setstate__(state)

    @property
    def library(self):
        with self._lock:
            if self._library is None:
                self._library = _load_library(self.library_path)
            return self._library

    def _pool(self, key):
        with self._lock:
            if key not in self._pools:
                self._pools[key] = _Pool(self._pool_maxsize, self._pool_block)
            self._pools.move_to_end(key)
            pool = self._pools[key]
            while len(self._pools) > self._pool_connections:
                self._pools.popitem(last=False)[1].close()
            return pool

    def _coalesce(self, pool, key, prefer, http3, attempt):
        host, port = key[1], key[2] or 443
        with self._lock:
            candidates = [
                other for other_key, other in self._pools.items()
                if other is not pool and other_key[0] == "https" and other_key[3:] == key[3:]
            ]
        awaiting_dns = []
        for other in candidates:
            attempt.remaining()
            connection = other.borrow(host, port, None, prefer, http3=http3)
            if connection is _NEEDS_DNS:
                awaiting_dns.append(other)
            elif connection is not None:
                return other, connection, None
        if not awaiting_dns:
            return None, None, None
        try:
            resolved = resolve_addresses(host, port, attempt)
        except socket.gaierror as error:
            failure = ConnectionError(f"Could not resolve {host}: {error}")
            failure._necko_connect = True
            raise failure from error
        peers = {ip for ips in resolved.values() for ip in ips}
        for other in awaiting_dns:
            attempt.remaining()
            connection = other.borrow(host, port, peers, prefer, http3=http3)
            if connection is not None:
                return other, connection, resolved
        # A failed certificate/address match must not trigger a second DNS lookup
        # or reset the timeout when we open a new connection for the original host.
        return None, None, resolved

    def _connect(self, url, proxy, verify, cert, timeout, attempt=None, http2=True, resolved=None):
        target = urlsplit(url)
        endpoint = urlsplit(proxy) if proxy else target
        socks = endpoint.scheme in ("socks4", "socks4a", "socks5", "socks5h")
        if endpoint.scheme not in ("http", "https") and not socks:
            raise InvalidSchema(f"Unsupported proxy scheme: {endpoint.scheme}")
        port = endpoint.port or (
            1080 if socks else 443 if endpoint.scheme == "https" else 80
        )
        own_attempt = attempt is None
        if own_attempt:
            attempt = Attempt(None if timeout is None else time.monotonic() + timeout)
        library = self.library

        def open_socket(address, limit, candidate):
            return _NativeSocket(library, address, port, limit, candidate)

        # Only resolve and race the TCP hop. Proxy tunnelling, SNI, and
        # certificate validation still use the original endpoint or origin.
        try:
            connection = connect_tcp(endpoint.hostname, port, attempt, open_socket, resolved)
        except socket.gaierror as error:
            failure = ConnectionError(f"Could not resolve {endpoint.hostname}: {error}")
            failure._necko_connect = True
            raise failure from error
        socket_transport = connection
        try:
            socket_transport.timeout = timeout
            socket_transport.attempt = attempt
            attempt.set_interrupt(socket_transport.interrupt)
            attempt.remaining()
            if socks:
                from ._socks import negotiate

                negotiate(connection, endpoint, target)
            if proxy and endpoint.scheme == "https":
                connection = _TLS(
                    connection,
                    _ssl_context(verify, None, Path(self.library._name).parent),
                    endpoint.hostname,
                    self.library,
                    self._tls_partition + ":proxy:" + endpoint.netloc,
                    http2=False,
                    firefox=self.firefox,
                )
            if proxy and not socks and target.scheme == "https":
                host = (
                    f"[{target.hostname}]"
                    if ":" in target.hostname
                    else target.hostname
                )
                authority = f"{host}:{target.port or 443}"
                headers = {"Host": authority}
                if endpoint.username is not None:
                    headers["Proxy-Authorization"] = _basic_auth_str(
                        unquote(endpoint.username), unquote(endpoint.password or "")
                    )
                tunnel = _Exchange(
                    self.library, connection, "CONNECT", authority, headers
                )
                try:
                    tunnel.receive()
                    if tunnel.status != 200:
                        raise ProxyError(f"Proxy CONNECT returned {tunnel.status}")
                finally:
                    tunnel.close()
            if target.scheme == "https":
                connection = _TLS(
                    connection,
                    _ssl_context(verify, cert, Path(self.library._name).parent),
                    target.hostname,
                    self.library,
                    self._tls_partition + ":origin:" + target.netloc + ":" + str(proxy),
                    http2=http2,
                    firefox=self.firefox,
                )
                if connection.alpn == "h2":
                    from ._http2 import Connection as H2Connection

                    connection.multiplexed = True
                    connection.using_proxy = bool(proxy)
                    connection.h2 = H2Connection(connection)
                connection.origin_port = target.port or 443
                connection.peer_address = getattr(
                    connection.transport, "peer_address", None
                )
            attempt.remaining()
            socket_transport.attempt = None
            return connection
        except TimeoutError as error:
            connection.close()
            raise ConnectTimeout(error) from error
        except Exception:
            connection.close()
            raise
        finally:
            if own_attempt:
                attempt.detach()

    def _connect_alternative(
        self, request, key, alternate, verify, budget, resolved, *, pool=None
    ):
        remaining = budget.remaining()
        if pool is not None and remaining is not None and remaining <= _ALT_SVC_RACE_DELAY:
            # The remaining budget or warm pool can change after acquire().
            # No QUIC probe means no failure to record in the cooldown cache.
            warm = pool.borrow_tcp()
            if warm is not None:
                return _BorrowedConnection(pool, warm)

        from ._connect import race
        from ._http3 import Connection as H3Connection

        target = urlsplit(request.url)
        endpoint = alternate[0]
        token_key = (key, endpoint)

        def quic(attempt):
            if pool is not None and verify:
                try:
                    other, connection, _ = self._coalesce(pool, key, "h3", True, attempt)
                except ConnectionError:
                    # Origin DNS is optional for the advertised alternate hop.
                    pass
                else:
                    if connection is not None:
                        return _BorrowedConnection(other, connection)
            last_error = None
            alt_host, alt_port = endpoint
            answers = resolve_addresses(alt_host, alt_port, attempt, socket.SOCK_DGRAM)
            for address in (ip for family in answers.values() for ip in family):
                token = self._quic_token_record(token_key)
                try:
                    connection = H3Connection(
                        target.hostname,
                        target.port or 443,
                        _ssl_context(verify, None, Path(self.library._name).parent),
                        self.library._name,
                        attempt.remaining(),
                        (address, alt_port),
                        token[0] if token is not None else "",
                        lambda value, age: self._save_quic_token(token_key, value, age),
                        attempt=attempt,
                        firefox=self.firefox,
                    )
                    connection.origin_port = target.port or 443
                    connection.alternate_endpoint = endpoint
                    return connection
                except (OSError, ProtocolError) as error:
                    if attempt.cancelled.is_set():
                        raise
                    self._forget_quic_token(token_key, token)
                    last_error = error
            raise last_error or OSError("No HTTP/3 endpoint addresses")

        def tcp(attempt):
            answers = resolved
            if pool is not None:
                connection = pool.borrow_tcp()
                if connection is not None:
                    return _BorrowedConnection(pool, connection)
                if verify:
                    other, connection, coalescing_answers = self._coalesce(
                        pool, key, "h2", False, attempt
                    )
                    if connection is not None:
                        return _BorrowedConnection(other, connection)
                    if coalescing_answers is not None:
                        answers = coalescing_answers
            return self._connect(
                request.url, None, verify, None, attempt.remaining(), attempt, resolved=answers
            )

        remaining = budget.remaining()
        delay = _ALT_SVC_RACE_DELAY
        if remaining is not None:
            delay = min(delay, remaining / 2)
        # The deadline covers both lanes; a cancelled loser releases any late
        # lease/result itself rather than delaying the usable winner.
        connection = race(quic, tcp, delay=delay, parent=budget)
        if connection.alpn != "h3":
            self._cool_alternative(key, alternate)
        return connection

    def _connect_masque(self, request, proxy, verify, proxy_verify, path_template, budget):
        from ._http3 import Connection as H3Connection
        from ._masque import open_tunnel

        target = urlsplit(request.url)
        host, port = target.hostname, target.port if target.port is not None else 443
        library = self.library
        context = _ssl_context(verify, None, Path(library._name).parent)

        def via_proxy(cancel_event, on_error):
            return open_tunnel(proxy, host, port, proxy_verify=proxy_verify,
                               timeout=budget.remaining(), cancel_event=cancel_event, on_error=on_error,
                               path_template=path_template)

        try:
            conn = H3Connection(host, port, context, library._name, budget.remaining(),
                                attempt=budget, firefox=self.firefox, tunnel_factory=via_proxy)
        except TimeoutError as error:
            raise ConnectTimeout('HTTP/3 connection through the MASQUE proxy timed out', request=request) from error
        conn.origin_port = port
        return conn

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None, proxy_verify=True,
        masque_path_template=None,
    ):
        retries = self.max_retries
        masque = is_masque_proxy(select_proxy(request.url, proxies or {}))
        body_position = None
        if hasattr(request.body, "tell"):
            try:
                body_position = request.body.tell()
            except OSError:
                body_position = None
        attempted = False
        protocol_retries = 0
        http1 = False
        http3 = True
        while True:
            if (
                attempted
                and request.body is not None
                and not isinstance(request.body, (str, bytes, bytearray, memoryview))
            ):
                if body_position is None or not hasattr(request.body, "seek"):
                    raise UnrewindableBodyError(
                        "Request body cannot be replayed for retry", request=request
                    )
                try:
                    request.body.seek(body_position)
                except (OSError, ValueError) as error:
                    raise UnrewindableBodyError(
                        "Request body could not be rewound for retry", request=request
                    ) from error
            attempted = True
            try:
                response = self._send_once(
                    request, stream, timeout, verify, cert, proxies, http1, http3,
                    **({'proxy_verify': proxy_verify, 'masque_path_template': masque_path_template} if masque else {}),
                )
            except (ConnectionError, ReadTimeout) as error:
                if not masque:
                    http1 |= getattr(error, "_necko_http1", False)
                    http3 &= not getattr(error, "_necko_direct", False)
                elif getattr(error, '_necko_http1', False) or getattr(error, '_necko_direct', False):
                    # A mandatory UDP route has no TCP fallback. In particular,
                    # a reset on this route must not replay a POST over TCP.
                    raise
                if (
                    getattr(error, "_necko_restartable", False)
                    and protocol_retries < MAX_REQUEST_ATTEMPTS - 1
                ):
                    protocol_retries += 1
                    continue
                if isinstance(error, SSLError):
                    cause = UrllibSSLError(str(error))
                elif isinstance(error, ProxyError):
                    cause = UrllibProxyError(
                        str(error), NewConnectionError(None, str(error))
                    )
                elif isinstance(error, ConnectTimeout):
                    cause = ConnectTimeoutError(str(error))
                elif getattr(error, "_necko_connect", False):
                    cause = NewConnectionError(None, str(error))
                elif isinstance(error, ReadTimeout):
                    cause = ReadTimeoutError(None, request.url, str(error))
                else:
                    cause = ProtocolError(str(error))
                try:
                    retries = retries.increment(
                        request.method, request.url, error=cause
                    )
                except (
                    MaxRetryError,
                    ProtocolError,
                    ReadTimeoutError,
                    ConnectTimeoutError,
                    UrllibSSLError,
                    UrllibProxyError,
                ):
                    raise error
                retries.sleep()
                continue
            response.raw.retries = retries
            if (
                response.status_code == 421
                and getattr(response, "_necko_coalesced", False)
                and protocol_retries < MAX_REQUEST_ATTEMPTS - 1
            ):
                protocol_retries += 1
                transport = response._necko_transport
                denied = getattr(transport, "coalescing_denied", set())
                denied.add(urlsplit(request.url).hostname)
                transport.coalescing_denied = denied
                response.close()
                continue
            if not retries.is_retry(
                request.method, response.status_code, "Retry-After" in response.headers
            ):
                return response
            try:
                next_retries = retries.increment(
                    request.method, request.url, response=response.raw
                )
            except MaxRetryError as error:
                if not retries.raise_on_status:
                    return response
                response.close()
                raise RetryError(error, request=request) from error
            try:
                response.content
            finally:
                response.close()
            retries = next_retries
            retries.sleep(response.raw)

    def _send_once(
        self, request, stream, timeout, verify, cert, proxies, http1=False, http3=True, *, proxy_verify=True,
        masque_path_template=None,
    ):
        if isinstance(timeout, tuple):
            if len(timeout) != 2:
                raise ValueError("timeout must contain (connect, read)")
            timeouts = Timeout(connect=timeout[0], read=timeout[1])
        elif isinstance(timeout, Timeout):
            timeouts = timeout.clone()
        else:
            timeouts = Timeout(connect=timeout, read=timeout)
        connect_timeout = Timeout.resolve_default_timeout(timeouts.connect_timeout)
        started = timeouts.start_connect()
        read_timeout = timeouts.read_timeout
        _milliseconds(connect_timeout)
        _milliseconds(read_timeout)
        budget = Attempt(None if connect_timeout is None else started + connect_timeout)
        target = urlsplit(request.url)
        proxy = select_proxy(request.url, proxies or {})
        masque = is_masque_proxy(proxy)
        route = None
        origin_trust = str(verify)
        if masque:
            if target.scheme != 'https':
                raise ProxyError('MASQUE requires an HTTPS origin', request=request)
            if not verify:
                raise SSLError('MASQUE requires verification of the origin certificate', request=request)
            if cert:
                raise InvalidSchema('HTTP/3 origin client certificates are not implemented', request=request)
            if verify is True:
                origin_trust = ('packaged',)
            elif isinstance(verify, (str, os.PathLike)) and isinstance(os.fspath(verify), str):
                origin_trust = ('ca', os.path.abspath(verify))
            else:
                raise ValueError('MASQUE origin verify must be True or a CA path')
            route = masque_route_id(proxy, proxy_verify, masque_path_template)
            if http1 or not http3:
                raise ProxyError('A MASQUE route requires end-to-end HTTP/3', request=request)
        elif proxy:
            proxy = prepend_scheme_if_needed(proxy, "http")
            if not urlsplit(proxy).hostname:
                raise InvalidProxyURL(f"Invalid proxy URL: {proxy}")
        if not verify and (
            target.scheme == "https" or proxy and proxy.startswith("https:")
        ):
            warnings.warn(
                f"Unverified HTTPS request to {target.hostname}",
                InsecureRequestWarning,
                stacklevel=2,
            )
        key = (
            target.scheme,
            target.hostname,
            target.port,
            ('masque', route) if masque else proxy,
            origin_trust,
            str(cert),
            http1,
        )
        pool = self._pool(key)
        direct_tls = target.scheme == "https" and not (proxy or cert or http1)
        prefer = "h3" if masque or (direct_tls and http3 and self._active_alternative(key)) else None
        transport = pool.acquire(prefer, http3=http3, attempt=budget)
        unused_pooled_lease = transport is not None
        coalesced = False
        exchange = None
        try:
            if transport is None:
                try:
                    # acquire() may have waited behind a handshake which cooled
                    # the route, or the advertised route may have expired meanwhile.
                    alternate = self._active_alternative(key) if prefer and not masque else None
                    if masque:
                        candidate = self._connect_masque(request, proxy, verify, proxy_verify, masque_path_template, budget)
                    elif alternate:
                        candidate = self._connect_alternative(
                            request, key, alternate, verify, budget, None, pool=pool
                        )
                    else:
                        resolved = None
                        warm = pool.borrow_tcp() if prefer else None
                        candidate = (
                            _BorrowedConnection(pool, warm) if warm is not None else None
                        )
                        if candidate is None and direct_tls and verify:
                            other, connection, resolved = self._coalesce(
                                pool, key, None, http3, budget
                            )
                            if connection is not None:
                                candidate = _BorrowedConnection(other, connection)
                        if candidate is None:
                            candidate = self._connect(
                                request.url,
                                proxy,
                                verify,
                                cert,
                                budget.remaining(),
                                attempt=budget,
                                http2=not http1,
                                resolved=resolved,
                            )
                    if isinstance(candidate, _BorrowedConnection):
                        pool.release(None)
                        coalesced = pool is not candidate.pool
                        pool, transport = candidate.pool, candidate.connection
                        unused_pooled_lease = True
                    else:
                        transport = candidate
                        pool.register(transport)
                except ConnectionError as error:
                    if proxy and not isinstance(error, (SSLError, ProxyError)) and not (masque and isinstance(error, ConnectTimeout)):
                        raise ProxyError(error, request=request) from error
                    raise
                finally:
                    budget.detach()
            budget.remaining()
            read_timeout = timeouts.read_timeout
            if read_timeout is not None and read_timeout <= 0:
                raise ReadTimeout(
                    "Total timeout elapsed during connection", request=request
                )
            if not getattr(transport, "multiplexed", False):
                transport.timeout = read_timeout
            self.add_headers(
                request,
                stream=stream,
                timeout=timeout,
                verify=verify,
                cert=cert,
                proxies=proxies,
            )
            headers = request.headers.copy()
            if "Host" not in headers:
                host = (
                    f"[{target.hostname}]"
                    if ":" in target.hostname
                    else target.hostname
                )
                if target.port and target.port != (
                    443 if target.scheme == "https" else 80
                ):
                    host += f":{target.port}"
                headers["Host"] = host
            if request.body is not None and "Content-Length" not in headers:
                headers["Transfer-Encoding"] = "chunked"
            if proxy and not proxy.startswith("socks") and target.scheme == "http":
                endpoint = urlsplit(proxy)
                if endpoint.username is not None:
                    headers["Proxy-Authorization"] = _basic_auth_str(
                        unquote(endpoint.username), unquote(endpoint.password or "")
                    )
            elif "Proxy-Authorization" in headers:
                del headers["Proxy-Authorization"]
            protocol = getattr(transport, "alpn", None)
            endpoint = getattr(transport, "alternate_endpoint", None)
            if protocol == "h3" and endpoint is not None:
                host, port = endpoint
                host = f"[{host}]" if ":" in host and not host.startswith("[") else host
                headers["Alt-Used"] = host if port == 443 else f"{host}:{port}"
            headers = wire_headers(headers, protocol == "h2")
            # A constructor can start writing before it returns an Exchange.
            unused_pooled_lease = False
            if protocol in ("h2", "h3"):
                if protocol == "h3":
                    from ._http3 import Exchange
                else:
                    from ._http2 import Exchange

                exchange = Exchange(
                    transport,
                    request.method,
                    request.url,
                    headers,
                    request.body is not None,
                    read_timeout,
                )
            else:
                exchange = _Exchange(
                    self.library,
                    transport,
                    request.method,
                    self.request_url(request, proxies),
                    headers,
                )
            body = request.body
            if isinstance(body, (str, bytes, bytearray, memoryview)):
                exchange.write(body)
            elif hasattr(body, "read"):
                while not getattr(exchange, "upload_stopped", False):
                    part = body.read(65536)
                    if not part:
                        break
                    exchange.write(part)
            elif body is not None and not getattr(exchange, "upload_stopped", False):
                parts = iter(body)
                while not getattr(exchange, "upload_stopped", False):
                    try:
                        part = next(parts)
                    except StopIteration:
                        break
                    exchange.write(part)
            exchange.receive()
            if target.scheme == "https" and not proxy and not cert:
                self._remember_alternative(key, target.hostname, exchange.headers)
            native_body = _Body(exchange, pool)
            raw = HTTPResponse(
                body=native_body,
                headers=exchange.headers,
                status=exchange.status,
                version=exchange.version,
                reason=exchange.reason,
                preload_content=False,
                decode_content=False,
                original_response=native_body,
                request_method=request.method,
                request_url=request.url,
            )
            response = self.build_response(request, raw)
            response.headers = HeaderMap(exchange.headers.items())
            response.tls = getattr(transport, "info", None)
            if masque:
                # This never substitutes proxy ALPN/TLS for the origin proof.
                response.proxy_tls = dict(transport.proxy_tls)
                response._ruyi_masque_route = route
            response._necko_coalesced = coalesced
            response._necko_transport = transport
            return response
        except Exception as error:
            if (
                isinstance(error, Http3ProtocolError)
                and not PROFILES[self.firefox]["h3_protocol_error_fallback"]
            ):
                error = ProtocolError(str(error))
            should_restart = restartable(error, request.method, exchange)
            if exchange is not None:
                exchange.close()
            pool.release(
                transport,
                reuse=unused_pooled_lease
                and isinstance(error, (ConnectTimeout, ReadTimeout))
                and transport.idle(),
            )
            if isinstance(error, ssl.SSLError):
                raise SSLError(error, request=request) from error
            if isinstance(error, TimeoutError):
                raise ReadTimeout(error, request=request) from error
            if isinstance(error, ConnectionError):
                error.request = request
            if isinstance(error, ProtocolError):
                converted = ConnectionError(error, request=request)
                converted._necko_restartable = should_restart
                converted._necko_http1 = isinstance(error, Http1Required)
                converted._necko_direct = isinstance(
                    error, (DirectRouteReset, Http3ProtocolError)
                )
                raise converted from error
            if isinstance(error, OSError) and not isinstance(error, RequestException):
                if transport is not None:
                    raise ConnectionError(error, request=request) from error
            raise

    def _drop_quic_token(self, key):
        record = self._quic_tokens.pop(key, None)
        if record is not None:
            self._quic_token_bytes -= len(record[0])

    def _expire_quic_tokens(self, now):
        for key in _expired_records(self._quic_tokens, now):
            self._drop_quic_token(key)

    def _quic_token_record(self, key):
        with self._token_lock:
            self._expire_quic_tokens(time.monotonic())
            record = self._quic_tokens.get(key)
            if record is not None:
                self._quic_tokens.move_to_end(key)
            return record

    def _quic_token(self, key):
        record = self._quic_token_record(key)
        return record[0] if record is not None else ""

    def _save_quic_token(self, key, token, age):
        # Neqo supplies an ASCII base64 string; account for its encoded size.
        if (
            not isinstance(token, str)
            or not token
            or len(token) > _QUIC_TOKEN_MAX_SIZE
            or not token.isascii()
            or not age > 0
        ):
            return
        with self._token_lock:
            now = time.monotonic()
            self._expire_quic_tokens(now)
            self._drop_quic_token(key)
            self._quic_tokens[key] = (token, now + min(age, _QUIC_TOKEN_MAX_AGE))
            self._quic_token_bytes += len(token)
            while (
                len(self._quic_tokens) > _QUIC_TOKEN_LIMIT
                or self._quic_token_bytes > _QUIC_TOKEN_BYTES
            ):
                self._drop_quic_token(next(iter(self._quic_tokens)))

    def _forget_quic_token(self, key, record):
        with self._token_lock:
            # Another handshake/connection may have replaced the token while
            # this handshake was in flight, even with an identical value.
            if record is not None and self._quic_tokens.get(key) is record:
                self._drop_quic_token(key)

    def _expire_alternatives(self, now):
        for cache in (self._alt_svc, self._alt_cooldowns):
            for key in _expired_records(cache, now):
                del cache[key]

    def _active_alternative(self, key):
        with self._lock:
            self._expire_alternatives(time.monotonic())
            alternate = self._alt_svc.get(key)
            if alternate is not None:
                self._alt_svc.move_to_end(key)
                if (key, alternate[0]) not in self._alt_cooldowns:
                    return alternate
            return None

    def _cool_alternative(self, key, alternate):
        with self._lock:
            now = time.monotonic()
            self._expire_alternatives(now)
            route = (key, alternate[0])
            # Keep failures separate from announcements: the hint can expire
            # during the race, and another authority can be advertised meanwhile.
            # Repeated announcements/failures do not extend an active cooldown.
            self._alt_cooldowns.setdefault(route, (None, now + _ALT_SVC_COOLDOWN))
            if len(self._alt_cooldowns) > _ALT_SVC_LIMIT:
                self._alt_cooldowns.popitem(last=False)

    def _remember_alternative(self, key, host, headers):
        value = headers.get("Alt-Svc", "")
        if value.strip() == "clear":
            with self._lock:
                self._expire_alternatives(time.monotonic())
                self._alt_svc.pop(key, None)
            return
        for entry in re.split(r",(?=\s*[a-zA-Z0-9-]+=)", value):
            match = re.fullmatch(r'\s*h3="([^"\\]+)"\s*((?:;[^,]*)?)', entry)
            if not match:
                continue
            authority, parameters = match.groups()
            if authority.startswith(":"):
                # urlsplit(...).hostname strips IPv6 brackets; URI authorities need them.
                origin = f"[{host}]" if ":" in host else host
                authority = origin + authority
            try:
                endpoint = urlsplit("https://" + authority)
                port = endpoint.port
                if (
                    not endpoint.hostname
                    or len(endpoint.hostname) > 253
                    or not port
                    or endpoint.username is not None
                    or endpoint.path
                    or endpoint.query
                    or endpoint.fragment
                ):
                    continue
                age_match = re.search(r";\s*ma\s*=\s*(\d+)", parameters)
                age = int(age_match.group(1)) if age_match else 86400
            except ValueError:
                continue
            with self._lock:
                now = time.monotonic()
                self._expire_alternatives(now)
                if age:
                    self._alt_svc[key] = (
                        (endpoint.hostname, port),
                        now + min(age, _ALT_SVC_MAX_AGE),
                    )
                    self._alt_svc.move_to_end(key)
                    if len(self._alt_svc) > _ALT_SVC_LIMIT:
                        self._alt_svc.popitem(last=False)
                else:
                    self._alt_svc.pop(key, None)
            return

    def close(self):
        with self._lock:
            for pool in self._pools.values():
                pool.close()
            self._pools.clear()
            self._alt_svc.clear()
            self._alt_cooldowns.clear()
            with self._token_lock:
                self._quic_tokens.clear()
                self._quic_token_bytes = 0
        super().close()
