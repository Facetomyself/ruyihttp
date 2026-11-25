# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import io
import socket
from urllib.parse import unquote

from requests.exceptions import InvalidSchema, ProxyError

from ._connect import resolve_addresses


def negotiate(connection, proxy, target):
    try:
        import socks
    except ImportError as error:
        raise InvalidSchema(
            "Install ruyihttp[socks] for SOCKS proxy support"
        ) from error

    version = socks.SOCKS5 if proxy.scheme.startswith("socks5") else socks.SOCKS4
    remote_dns = proxy.scheme in ("socks5h", "socks4a")
    host = target.hostname
    port = target.port or (443 if target.scheme == "https" else 80)
    if not remote_dns:
        # PySocks resolves synchronously for local DNS. Hand it a numeric
        # target resolved within the same attempt as the proxy connection.
        options = (
            {"family": socket.AF_INET}
            if version == socks.SOCKS4
            else {"proto": socket.IPPROTO_TCP, "flags": socket.AI_ADDRCONFIG}
        )
        families = resolve_addresses(host, port, connection.attempt, **options)
        if version == socks.SOCKS4:
            addresses = families.get(socket.AF_INET)
            if not addresses:
                raise socket.gaierror(
                    socket.EAI_NONAME, f"SOCKS4 requires an IPv4 address for {host}"
                )
        else:
            addresses = next(iter(families.values()))
        # SOCKS5 carries the IPv6 address, not the client's scope identifier.
        host = addresses[0].partition("%")[0]

    class Stream(io.RawIOBase):
        def readable(self):
            return True

        def writable(self):
            return True

        def readinto(self, buffer):
            data = connection.read(len(buffer))
            buffer[: len(data)] = data
            return len(data)

        def write(self, buffer):
            connection.write(bytes(buffer))
            return len(buffer)

    class Negotiator(socks.socksocket):
        def makefile(self, mode="r", buffering=-1, **kwargs):
            stream = Stream()
            return io.BufferedWriter(stream) if "w" in mode else stream

    with Negotiator() as negotiator:
        negotiator.set_proxy(
            version,
            proxy.hostname,
            proxy.port or 1080,
            rdns=remote_dns,
            username=unquote(proxy.username) if proxy.username else None,
            password=unquote(proxy.password) if proxy.password else None,
        )
        try:
            if version == socks.SOCKS5:
                negotiator._negotiate_SOCKS5(host, port)
            else:
                negotiator._negotiate_SOCKS4(host, port)
        except socks.ProxyError as error:
            raise ProxyError(error) from error
