from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
from firefox_quic_initial import (
    V1,
    V2,
    QuicInitialObservation,
    initial_metadata,
    parameter_metadata,
)


class InitialObservationTests(unittest.TestCase):
    @staticmethod
    def header(version=V1):
        kind = 0xC0 if version == V1 else 0xD0
        return (
            bytes([kind])
            + version.to_bytes(4, "big")
            + b"\x08abcdefgh\x03xyz\x00\x03ABC"
        )

    def test_initial_does_not_expose_identifiers_and_keeps_coalescing_separate(self):
        for v in (V1, V2):
            data = self.header(v)
            self.assertEqual(
                initial_metadata(data + b"NEXT"),
                dict(
                    version=v,
                    udp_payload_bytes=len(data) + 4,
                    packet_bytes=len(data),
                    dcid_length=8,
                    scid_length=3,
                    token_length=0,
                ),
            )
        for data in (
            b"",
            b"\x43" + bytes(25),
            self.header()[:-1],
            b"\xd0" + self.header()[1:],
            self.header()[0:5] + b"\xff",
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                initial_metadata(data)

    def test_observe_tp_wire_order_without_recording_values_or_resumption_data(self):
        offer = (
            b"\x11\x0c"
            + V1.to_bytes(4, "big")
            + V2.to_bytes(4, "big")
            + V1.to_bytes(4, "big")
        )
        encoded = b"\x0f\x03xyz" + offer + b"\x04\x01\x3f"
        self.assertEqual(
            parameter_metadata(encoded),
            {
                "transport_parameter_ids": [15, 17, 4],
                "version_information": {"chosen": V1, "available": [V2, V1]},
            },
        )
        for data in (b"\x00", offer + offer, b"\x00\x02x", b"\x11\x01x"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parameter_metadata(data)
        calls = []

        class MockEndpointReader:
            def decrypt_packet(self, packet, encrypted_offset, expected_packet_number):
                # Only this test double invents a successful parse. Production
                # observes the result of aioquic's ordinary endpoint processing.
                return (
                    b"\xc1" + bytes(encrypted_offset + 1),
                    b"payload",
                    expected_packet_number,
                )

        class Connection:
            def _initialize(self, _cid):
                self._cryptos_initial = {V1: MockEndpointReader()}

            def receive_datagram(self, data, addr, now):
                calls.append(("data", data, addr, now))
                self._initialize("test")
                _header, payload, pn = self._cryptos_initial[V1].decrypt_packet(
                    data, 7, 12
                )
                return payload, pn

            def _parse_transport_parameters(self, data, from_session_ticket=False):
                calls.append(("tp", data, from_session_ticket))

        conn = Connection()
        obs = QuicInitialObservation(conn)
        packet = self.header()
        self.assertEqual(
            conn.receive_datagram(packet, "loopback", now=1), (b"payload", 12)
        )
        conn._parse_transport_parameters(b"ignored", from_session_ticket=True)
        with self.assertRaisesRegex(ValueError, "missing"):
            obs.result()
        conn._parse_transport_parameters(encoded)
        self.assertEqual(obs.result()["version_information"]["available"], [V2, V1])
        self.assertEqual(obs.result()["packet_number_length"], 2)
        self.assertIsNone(obs._first_in_call)
        self.assertEqual(
            calls,
            [
                ("data", packet, "loopback", 1),
                ("tp", b"ignored", True),
                ("tp", encoded, False),
            ],
        )
