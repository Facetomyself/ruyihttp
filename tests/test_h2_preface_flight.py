from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
from firefox_h2_preface import FirstH2Flight, PREFACE, stable_flight


def frame(code, flags, stream, body):
    return (
        len(body).to_bytes(3, "big")
        + bytes([code, flags])
        + stream.to_bytes(4, "big")
        + body
    )


class FirstFlightTests(unittest.TestCase):
    def test_lossless_non_ack_control_order_and_implicit_header_priority(self):
        settings = frame(4, 0, 0, b"\0\x01\0\x01\0\0")
        ack = frame(4, 1, 0, b"")
        window = frame(8, 0, 0, (12 * 1024**2 - 65535).to_bytes(4, "big"))
        pri = frame(2, 0, 3, b"\x80\0\0\0\xff")
        hdr = frame(1, 5, 1, b"compressed")
        rows = []
        for middle in ((ack, window), (window, ack)):
            f = FirstH2Flight()
            data = (
                PREFACE
                + settings
                + b"".join(middle)
                + pri
                + hdr
                + frame(8, 0, 1, (524288).to_bytes(4, "big"))
            )
            for byte in data:
                f.feed(bytes([byte]))
            r = f.result()
            rows.append(r)
            self.assertEqual(
                [x["type"] for x in r["frames"]],
                ["SETTINGS", "WINDOW_UPDATE", "PRIORITY"],
            )
            self.assertEqual(r["frames"][1]["increment"], 12517377)
            self.assertEqual(
                r["frames"][2],
                {
                    "type": "PRIORITY",
                    "stream": 3,
                    "weight": 256,
                    "depends_on": 0,
                    "exclusive": True,
                },
            )
            self.assertEqual(
                r["first_headers"],
                {
                    "stream": 1,
                    "end_headers": True,
                    "end_stream": True,
                    "padded": False,
                    "priority": None,
                },
            )
        self.assertEqual(stable_flight(rows[0]), stable_flight(rows[1]))
        self.assertNotEqual(
            rows[0]["settings_ack_positions"], rows[1]["settings_ack_positions"]
        )
        rows[1]["frames"][1]["increment"] += 1
        self.assertNotEqual(stable_flight(rows[0]), stable_flight(rows[1]))

    def test_headers_with_priority_and_bad_frames_fail_closed(self):
        s = frame(4, 0, 0, b"")
        h = frame(1, 0x2D, 5, b"\x01\x80\0\0\x03\x0f" + b"X" + b"\0")
        f = FirstH2Flight()
        f.feed(PREFACE + s + h)
        self.assertEqual(
            f.result()["first_headers"]["priority"],
            {"weight": 16, "exclusive": True, "depends_on": 3},
        )
        for raw in (
            b"BAD!",
            PREFACE + h,
            PREFACE + s + frame(8, 0, 0, b"\0" * 4),
            PREFACE + s + frame(1, 4, 0, b""),
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                FirstH2Flight().feed(raw)
        with self.assertRaises(ValueError):
            FirstH2Flight().result()
