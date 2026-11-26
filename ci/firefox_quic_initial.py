"""Metadata from a fresh client's Initial and received QUIC transport parameters.

Used on our loopback test server only. Keep lengths, IDs and public versions,
not connection IDs, token contents, TLS keys, or application payloads. Distinct
from the final version chosen by the peer. The two aioquic 1.3.0 hooks delegate
unmodified bytes/addresses to their originals even on an observation error.
"""

V1 = 0x00000001
V2 = 0x6B3343CF


def _uintvar(data, at):
    if at >= len(data):
        raise ValueError("missing QUIC variable-length integer")
    width = 1 << (data[at] >> 6)
    if width > len(data) - at:
        raise ValueError("short QUIC variable-length integer")
    return int.from_bytes(data[at : at + width], "big") & (
        (1 << (8 * width - 2)) - 1
    ), at + width


def initial_metadata(data):
    if len(data) < 7 or not data[0] & 0x80:
        raise ValueError("missing initial long header")
    version = int.from_bytes(data[1:5], "big")
    # RFC 9000 and RFC 9369 use different long-header type encodings.
    if (version, (data[0] >> 4) & 3) not in {(V1, 0), (V2, 1)}:
        raise ValueError("first datagram must contain a v1/v2 Initial")
    dcid = data[5]
    pos = 6 + dcid
    if dcid > 20 or pos >= len(data):
        raise ValueError("invalid DCID length")
    scid = data[pos]
    pos += 1 + scid
    if scid > 20 or pos >= len(data):
        raise ValueError("invalid SCID length")
    token_size, pos = _uintvar(data, pos)
    if token_size > len(data) - pos:
        raise ValueError("short Initial token")
    rest, pos = _uintvar(data, pos + token_size)
    if not 0 < rest <= len(data) - pos:
        raise ValueError("short Initial packet")
    return dict(
        version=version,
        udp_payload_bytes=len(data),
        packet_bytes=pos + rest,
        dcid_length=dcid,
        scid_length=scid,
        token_length=token_size,
    )


def parameter_metadata(data):
    keys = []
    seen = set()
    versions = None
    pos = 0
    while pos < len(data):
        key, pos = _uintvar(data, pos)
        size, pos = _uintvar(data, pos)
        if key in seen or size > len(data) - pos:
            raise ValueError("duplicate or truncated peer transport parameter")
        seen.add(key)
        keys.append(key)
        if key == 0x11:  # RFC 9368 version_information; preserve order on the wire.
            if size < 4 or size % 4:
                raise ValueError("malformed version_information")
            numbers = [
                int.from_bytes(data[i : i + 4], "big")
                for i in range(pos, pos + size, 4)
            ]
            versions = {"chosen": numbers[0], "available": numbers[1:]}
        pos += size
    if not keys:
        raise ValueError("empty peer transport-parameters extension")
    return {"transport_parameter_ids": keys, "version_information": versions}


class QuicInitialObservation:
    def __init__(self, connection):
        self._first = self._peer = self._error = None
        receive = connection.receive_datagram
        parse = connection._parse_transport_parameters

        def receive_observed(data, addr, now):
            if self._first is None and self._error is None:
                try:
                    self._first = initial_metadata(data)
                except ValueError as exc:
                    self._error = str(exc)
            return receive(data, addr, now=now)

        def parse_observed(data, from_session_ticket=False):
            if not from_session_ticket:
                try:
                    current = parameter_metadata(data)
                    if self._peer is not None and self._peer != current:
                        raise ValueError(
                            "peer supplied conflicting transport parameters"
                        )
                    self._peer = current
                except ValueError as exc:
                    self._error = str(exc)
            return parse(data, from_session_ticket=from_session_ticket)

        connection.receive_datagram = receive_observed
        connection._parse_transport_parameters = parse_observed

    def result(self):
        if self._error is not None or self._first is None or self._peer is None:
            raise ValueError(
                self._error
                or "missing first Initial or actual peer transport parameters"
            )
        return dict(self._first, **self._peer)
