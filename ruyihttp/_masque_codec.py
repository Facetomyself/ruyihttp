# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Private, dependency-free-of-QUIC pieces of the CONNECT-UDP client."""

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit

import idna

DEFAULT_PATH = "/.well-known/masque/udp/{target_host}/{target_port}/"
_MAX_UDP = 65527
_TEMPLATE_VARIABLE = re.compile(r"\{(target_host|target_port)\}")
_PATH_LITERAL = re.compile(r"(?:[a-zA-Z0-9._~!$&'()*+,;=:@/?-]|%[a-fA-F0-9]{2})*\Z")
_USERINFO = re.compile(r"(?:[a-zA-Z0-9._~!$&'()*+,;=:-]|%[a-fA-F0-9]{2})*\Z")


@dataclass(frozen=True)
class ProxyEndpoint:
    host: str
    port: int
    authority: str
    authorization: bytes | None = field(default=None, repr=False)


def _host(value):
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("Invalid MASQUE host")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
        if ":" not in value:
            raise ValueError("Invalid MASQUE bracketed host")
    if "%" in value:  # scoped IPv6 literals have no CONNECT-UDP URI representation
        raise ValueError("Invalid MASQUE host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        return idna.encode(value, uts46=True, std3_rules=True).decode("ascii")
    except (UnicodeError, idna.IDNAError):
        raise ValueError("Invalid MASQUE host") from None


def _authorization(userinfo):
    if not _USERINFO.fullmatch(userinfo):
        raise ValueError("Invalid MASQUE proxy userinfo")
    user, _, credential = userinfo.partition(":")
    try:
        user, credential = (unquote(item, errors="strict") for item in (user, credential))
    except UnicodeError:
        raise ValueError("Invalid MASQUE proxy userinfo") from None
    if not user or ":" in user or any(ord(c) < 32 or ord(c) == 127 for c in user + credential):
        raise ValueError("Invalid MASQUE proxy userinfo")
    return b"Basic " + base64.b64encode(f"{user}:{credential}".encode("utf-8"))


def parse_proxy(proxy_url):
    if (
        not isinstance(proxy_url, str)
        or len(proxy_url) > 4096
        or any(ord(c) <= 32 or ord(c) == 127 for c in proxy_url)
        or "?" in proxy_url
        or "#" in proxy_url
    ):
        raise ValueError("Invalid MASQUE proxy URL")
    try:
        uri = urlsplit(proxy_url)
        port = uri.port
        host = uri.hostname
    except ValueError:
        raise ValueError("Invalid MASQUE proxy URL") from None
    if uri.scheme not in ("masque", "https") or host is None or uri.path not in ("", "/"):
        raise ValueError("Expected a MASQUE proxy authority URL, without a path or query")
    userinfo, at, hostport = uri.netloc.rpartition("@")
    if hostport.endswith(":") or (port is not None and port == 0):
        raise ValueError("Invalid MASQUE proxy port")
    # urlsplit extracts `[::1]` even when followed by junk. Validate the
    # bracket/port boundary ourselves before accepting its parsed hostname.
    if "[" in hostport or "]" in hostport:
        if not re.fullmatch(r"\[[^\[\]]+\](?::[0-9]+)?", hostport) or ":" not in host:
            raise ValueError("Invalid MASQUE proxy authority")
    host = _host(host)
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority = f"{authority}:{port}"
    return ProxyEndpoint(host, port if port is not None else 443, authority,
                         _authorization(userinfo) if at else None)


def target_path(target_host, target_port, template=None):
    if type(target_port) is not int or not 1 <= target_port <= 65535:
        raise ValueError("Invalid MASQUE target port")
    template = DEFAULT_PATH if template is None else template
    if (
        not isinstance(template, str) or not template.startswith("/")
        or template.startswith("//") or len(template) > 4096
        or set(_TEMPLATE_VARIABLE.findall(template)) != {"target_host", "target_port"}
        or not _PATH_LITERAL.fullmatch(_TEMPLATE_VARIABLE.sub("", template))
    ):
        raise ValueError("Invalid MASQUE path template; use literal URI path/query and both simple target variables")
    values = {"target_host": quote(_host(target_host), safe=""), "target_port": str(target_port)}
    path = _TEMPLATE_VARIABLE.sub(lambda match: values[match[1]], template)
    if len(path) > 4096 or any(part in (".", "..") for part in path.split("?", 1)[0].split("/")):
        raise ValueError("Invalid expanded MASQUE path")
    return path


def connect_headers(proxy, path):
    headers = [
        (b":method", b"CONNECT"),
        (b":protocol", b"connect-udp"),
        (b":scheme", b"https"),
        (b":authority", proxy.authority.encode("ascii")),
        (b":path", path.encode("ascii")),
        (b"capsule-protocol", b"?1"),
    ]
    if proxy.authorization is not None:
        headers.append((b"proxy-authorization", proxy.authorization))
    return headers


class CapsuleError(ValueError):
    """Malformed CONNECT-UDP payload or capsule."""


def _varint(data, offset=0):
    if offset < len(data):
        end = offset + (1 << (data[offset] >> 6))
        if end <= len(data):
            return int.from_bytes(data[offset:end], "big") & ((1 << (8 * (end - offset) - 2)) - 1), end
    return None


def udp_payload(data, maximum):
    prefix = _varint(data)
    if prefix is None:
        # An unreliable datagram with no usable Context ID has no route.
        # Capsule boundaries are reliable framing and are validated separately.
        return None
    context, end = prefix
    if context != 0:
        return None
    size = len(data) - end
    if size > _MAX_UDP:
        raise CapsuleError("CONNECT-UDP payload exceeds RFC 9298 limit")
    return data[end:] if size <= maximum else None


class CapsuleDecoder:
    """RFC 9297 incremental decoder; hold only varints and bounded UDP payloads."""

    def __init__(self, maximum):
        self._maximum = maximum
        self._header = bytearray()
        self._payload = bytearray()
        self._type = None
        self._left = None
        self._keep = None

    def _number(self, data, offset, end):
        if not self._header and offset < end:
            self._header.append(data[offset])
            offset += 1
        if not self._header:
            return None, offset
        length = 1 << (self._header[0] >> 6)
        take = min(length - len(self._header), end - offset)
        self._header.extend(data[offset:offset + take])
        offset += take
        if len(self._header) == length:
            value, _ = _varint(self._header)
            self._header.clear()
            return value, offset
        return None, offset

    def feed(self, chunk):
        data = memoryview(chunk)
        offset = 0
        while offset < len(data):
            if self._type is None:
                self._type, offset = self._number(data, offset, len(data))
                if self._type is None:
                    break
            if self._left is None:
                self._left, offset = self._number(data, offset, len(data))
                if self._left is None:
                    break
                self._keep = False if self._type != 0 else None
            if self._keep is None:
                # A DATAGRAM capsule must contain a complete Context ID even
                # when its UDP payload is empty or we will drop the context.
                start = offset
                context, offset = self._number(data, offset, min(len(data), offset + self._left))
                self._left -= offset - start
                if context is None:
                    if self._left == 0:
                        raise CapsuleError("Truncated DATAGRAM capsule Context ID")
                    break
                if context == 0 and self._left > _MAX_UDP:
                    raise CapsuleError("DATAGRAM capsule UDP payload exceeds RFC 9298 limit")
                self._keep = context == 0 and self._left <= self._maximum
            take = min(self._left, len(data) - offset)
            if self._keep:
                self._payload.extend(data[offset:offset + take])
            offset += take
            self._left -= take
            if self._left == 0:
                packet = bytes(self._payload) if self._keep else None
                self._payload.clear()
                self._type = self._left = self._keep = None
                if packet is not None:
                    yield packet

    def finish(self):
        if self._header or self._type is not None:
            raise CapsuleError("CONNECT-UDP stream ended inside a capsule")
