"""Passive HTTP/2 first-flight observer for our authenticated loopback origins.

Only looks through the first request HEADERS. Do not collect HPACK data, PING
opaque bytes or DATA. Preserve the order of client-originated control frames;
record server-dependent SETTINGS ACK positions separately from that sequence.
"""

from copy import deepcopy

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def priority(data):
    require(len(data) == 5, "wrong HTTP/2 PRIORITY length")
    bits = int.from_bytes(data[:4], "big")
    return {
        "depends_on": bits & 0x7FFFFFFF,
        "exclusive": bool(bits >> 31),
        "weight": data[4] + 1,
    }


class FirstH2Flight:
    def __init__(self):
        self._buffer = bytearray()
        self._preface = False
        self._frames = []
        self._acks = []
        self._request = None

    def feed(self, chunk):
        if self._request is not None:
            return
        self._buffer.extend(chunk)
        if not self._preface:
            prefix = self._buffer[: len(PREFACE)]
            require(PREFACE.startswith(prefix), "invalid HTTP/2 connection preface")
            if len(prefix) < len(PREFACE):
                return
            del self._buffer[: len(PREFACE)]
            self._preface = True
        while len(self._buffer) >= 9:
            head = self._buffer[:9]
            length = int.from_bytes(head[:3], "big")
            frame_type, flags = head[3:5]
            stream = int.from_bytes(head[5:], "big") & 0x7FFFFFFF
            require(
                length <= 65536 and len(self._frames) + len(self._acks) < 128,
                "oversized initial frame or too many preface frames",
            )
            if len(self._buffer) < 9 + length:
                return
            data = self._buffer[9 : 9 + length]
            del self._buffer[: 9 + length]
            if not self._frames:
                require(
                    frame_type == 4 and not flags & 1,
                    "first frame must be non-ACK SETTINGS",
                )
            if frame_type == 4:
                require(stream == 0 and length % 6 == 0, "malformed SETTINGS")
                if flags & 1:
                    require(length == 0, "nonempty SETTINGS ACK")
                    self._acks.append(len(self._frames) + len(self._acks))
                    continue
                item = {
                    "type": "SETTINGS",
                    "stream": stream,
                    "values": [
                        [
                            int.from_bytes(data[i : i + 2], "big"),
                            int.from_bytes(data[i + 2 : i + 6], "big"),
                        ]
                        for i in range(0, length, 6)
                    ],
                }
            elif frame_type == 8:
                require(length == 4, "malformed WINDOW_UPDATE")
                inc = int.from_bytes(data, "big") & 0x7FFFFFFF
                require(inc > 0, "zero WINDOW_UPDATE")
                item = {"type": "WINDOW_UPDATE", "stream": stream, "increment": inc}
            elif frame_type == 2:
                require(stream != 0, "zero PRIORITY stream")
                item = {"type": "PRIORITY", "stream": stream, **priority(data)}
            elif frame_type == 1:
                require(stream != 0 and stream % 2 == 1, "invalid first request stream")
                offset = 1 if flags & 8 else 0
                require(
                    length >= offset and (not offset or data[0] <= length - offset),
                    "malformed HEADERS padding",
                )
                prio = None
                if flags & 32:
                    require(
                        length - offset - (data[0] if offset else 0) >= 5,
                        "short HEADERS priority",
                    )
                    prio = priority(data[offset : offset + 5])
                self._request = {
                    "stream": stream,
                    "end_headers": bool(flags & 4),
                    "end_stream": bool(flags & 1),
                    "padded": bool(flags & 8),
                    "priority": prio,
                }
                self._buffer.clear()
                return
            else:
                item = {
                    "type": frame_type,
                    "stream": stream,
                    "flags": flags,
                    "size": length,
                }
            self._frames.append(item)

    def result(self):
        require(self._request is not None, "no first HTTP/2 request HEADERS")
        return deepcopy(
            {
                "frames": self._frames,
                "settings_ack_positions": self._acks,
                "first_headers": self._request,
            }
        )


def stable_flight(flight):
    require(
        isinstance(flight, dict)
        and set(flight) == {"frames", "settings_ack_positions", "first_headers"},
        "invalid flight",
    )
    frames = flight["frames"]
    header = flight["first_headers"]
    acks = flight["settings_ack_positions"]
    require(
        isinstance(frames, list)
        and frames
        and len(frames) < 128
        and frames[0].get("type") == "SETTINGS",
        "missing client preface frames",
    )
    require(
        isinstance(acks, list)
        and all(type(i) is int and 0 < i < len(frames) + len(acks) for i in acks)
        and acks == sorted(set(acks)),
        "bad SETTINGS ACK ordinals",
    )
    require(
        isinstance(header, dict)
        and set(header) == {"stream", "end_headers", "end_stream", "padded", "priority"}
        and type(header["stream"]) is int
        and header["stream"] > 0
        and header["stream"] % 2 == 1,
        "bad first HEADERS descriptor",
    )
    return {"frames": frames, "first_headers": header}
