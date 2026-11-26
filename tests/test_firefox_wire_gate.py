# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Comparator controls. Synthetic records here are never admission fixtures."""

import copy
import json
import runpy
import tempfile
import unittest
from pathlib import Path

GATE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "ci/firefox_wire.py"))
load_reference = GATE["load_reference"]
stable_wire = GATE["stable_wire"]
diff = GATE["diff"]
WireError = GATE["WireError"]
Reference = GATE["Reference"]
grease_settings = GATE["grease_settings"]


def wire(port=12345):
    # Intentionally small record; the admission matrix uses real raw samples.
    a = f"localhost:{port}"
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0"
    h2h3 = [[":method", "GET"], [":path", "/profile-wire"], [":authority", a], [":scheme", "https"],
            ["user-agent", ua]]
    hello = {
        "legacy_version": 771, "ciphers": [4865, 4867, 4866], "extensions": [43, 0, 16, 51],
        "groups": [4588, 29], "signatures": [1027], "cert_compression": [1, 2, 3],
        "supported_versions": [772, 771], "key_share_groups": [4588, 29], "offered_alpn": ["h2", "http/1.1"],
        "compression_methods": [0], "ec_point_formats": [0], "psk_key_exchange_modes": [1],
        "server_names": [[0, "localhost"]], "session_id_length": 32,
    }
    tcp = {"port": port, "mode": "navigation", "client_hello_count": 1,
           "negotiated_tls": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"}}
    h2 = {**tcp, "protocol": "h2", "hello": copy.deepcopy(hello),
          "headers": copy.deepcopy(h2h3), "settings": [[1, 65536], [2, 0], [4, 131072], [5, 16384]]}
    bootstrap = copy.deepcopy(h2)
    bootstrap["headers"][1][1] = "/boot"
    bootstrap["headers"].append(["sec-fetch-mode", "navigate"])
    settings = [[51, 1], [1, 65536], [33, 5], [8, 1], [7, 20], [16765559, 1], [727725890, 0]]
    return {
        "h1": {**tcp, "protocol": "http/1.1", "request_line": "GET /profile-wire HTTP/1.1",
               "hello": copy.deepcopy(hello), "headers": [["Host", a], ["User-Agent", ua], ["Connection", "keep-alive"]]},
        "h2": h2,
        "h3": {"port": port, "protocol": "h3", "mode": "same-origin-fetch", "headers": [*h2h3, ["accept", "*/*"],
               ["referer", f"https://{a}/boot"], ["alt-used", a], ["sec-fetch-dest", "empty"], ["sec-fetch-mode", "cors"],
               ["sec-fetch-site", "same-origin"]], "quic_version": 0x6B3343CF, "hello": copy.deepcopy(hello),
               "settings": settings, "grease_settings": grease_settings(settings), "bootstrap": [bootstrap],
               "initial": {"version": 0x6B3343CF, "udp_payload_bytes": 1357, "packet_bytes": 1357,
                           "dcid_length": 8, "scid_length": 3, "token_length": 0, "transport_parameter_ids": [17, 14, 4],
                           "version_information": {"chosen": 0x6B3343CF, "available": [0x6B3343CF, 1]}},
               "transport_parameters": {"active_connection_id_limit": 8, "disable_active_migration": False,
                   "initial_max_data": 25165824, "initial_max_stream_data_bidi_local": 12582912,
                   "initial_max_stream_data_bidi_remote": 1048576, "initial_max_stream_data_uni": 1048576,
                   "initial_max_streams_bidi": 100, "initial_max_streams_uni": 100, "max_ack_delay": 20,
                   "max_datagram_frame_size": 65535, "max_idle_timeout": 30000}},
    }


def official(sample, release="159"):
    for case in sample.values():
        for row in case["headers"]:
            if row[0].lower() == "user-agent":
                row[1] = row[1].replace("159", release)
                case["user_agent"] = row[1]
        case["process"] = {"native": "aarch64"}
    return sample


def reference():
    releases = {}
    for release in ("159", "160", "161"):
        samples = [official(wire(12345), release), official(wire(43210), release)]
        meta = dict.fromkeys(GATE["OFFICIAL_BUILD"], "test-metadata")
        meta.update(executable_slices=["aarch64"], runtime_host={"machine": "aarch64"}, executable_sha256="d" * 64)
        releases[release] = {**meta, **GATE["pinned_build"]("linux_aarch64", release), "samples": samples}
    return {"schema_version": 1, "source": "official-firefox", "slot": "linux_aarch64", "platform": "linux",
            "arch": "aarch64", "captures": releases, "ci": {}}


class WireComparisonTests(unittest.TestCase):
    def setUp(self):
        self.expected = stable_wire(wire())
        self.observed = wire(54321)

    def assertWireMismatch(self, field):
        self.assertEqual(set(diff(self.expected, stable_wire(self.observed))), {field})

    def test_only_ephemeral_authority_and_document_authority_are_mapped(self):
        self.assertEqual(diff(self.expected, stable_wire(self.observed)), {})

    def test_wrong_ua_in_any_protocol(self):
        for protocol in ("h1", "h2", "h3"):
            with self.subTest(protocol=protocol):
                self.observed = wire(54321)
                ua = next(row for row in self.observed[protocol]["headers"] if row[0].lower() == "user-agent")
                ua[1] = ua[1].replace("x86_64", "aarch64")
                self.assertWireMismatch(f"{protocol}.headers")

    def test_missing_h3_connect_protocol_setting(self):
        self.observed["h3"]["settings"].remove([8, 1])
        self.assertWireMismatch("h3.settings")

    def test_quic_v1_vs_v2(self):
        self.observed["h3"]["quic_version"] = 1
        self.assertWireMismatch("h3.quic_version")

    def test_windows_2m_vs_1m_quic_receive_window(self):
        self.observed["h3"]["transport_parameters"]["initial_max_stream_data_bidi_remote"] = 2097152
        self.assertWireMismatch("h3.transport_parameters.initial_max_stream_data_bidi_remote")

    def test_unexpected_quic_optional_parameter(self):
        self.observed["h3"]["transport_parameters"]["max_udp_payload_size"] = 1200
        self.assertWireMismatch("h3.transport_parameters.max_udp_payload_size")

    def test_missing_required_quic_parameter_in_reference(self):
        del self.observed["h3"]["transport_parameters"]["max_idle_timeout"]
        with self.assertRaisesRegex(WireError, "missing selected QUIC parameters"):
            stable_wire(official(self.observed), reference=True)

    def test_header_order_is_observed_for_every_protocol(self):
        for protocol in ("h1", "h2", "h3"):
            with self.subTest(protocol=protocol):
                self.observed = wire(54321)
                self.observed[protocol]["headers"].reverse()
                self.assertWireMismatch(f"{protocol}.headers")

    def test_wrong_http_target_and_negotiated_alpn_are_mismatches(self):
        self.observed["h1"]["request_line"] = "GET https://localhost:54321/profile-wire HTTP/1.1"
        self.assertWireMismatch("h1.request_line")
        self.observed = wire(54321)
        self.observed["h1"]["protocol"] = None
        self.assertWireMismatch("h1.protocol")

    def test_authority_map_does_not_hide_missing_wrong_or_swap_values(self):
        for header, wrong in ((":authority", "127.0.0.1:54321"), ("alt-used", "localhost:54322"),
                              ("referer", "https://localhost:54321/bad-path"), ("referer", "https://localhost:54322/boot")):
            with self.subTest(header=header, wrong=wrong):
                self.observed = wire(54321)
                row = next(row for row in self.observed["h3"]["headers"] if row[0] == header)
                row[1] = wrong
                self.assertWireMismatch("h3.headers")
        self.observed = wire(54321)
        self.observed["h3"]["headers"].remove(["alt-used", "localhost:54321"])
        self.assertWireMismatch("h3.headers")

    def test_unrelated_header_port_is_not_erased(self):
        expected = wire()
        expected["h3"]["headers"].append(["test", "localhost:12345"])
        self.expected = stable_wire(expected)
        self.observed["h3"]["headers"].append(["test", "localhost:54321"])
        self.assertWireMismatch("h3.headers")

    def test_mismatched_fetch_mode_is_invalid(self):
        self.observed["h3"]["mode"] = "navigation"
        with self.assertRaisesRegex(WireError, "same-origin-fetch"):
            stable_wire(self.observed)

    def test_settings_order_and_unexpected_non_grease_are_asserted(self):
        for protocol in ("h2", "h3"):
            with self.subTest(protocol=protocol):
                self.observed = wire(54321)
                rows = self.observed[protocol]["settings"]
                rows[0], rows[1] = rows[1], rows[0]
                self.assertWireMismatch(f"{protocol}.settings")
                self.observed = wire(54321)
                self.observed[protocol]["settings"].append([8001, 0])
                self.assertWireMismatch(f"{protocol}.settings")

    def test_conditionally_allow_observed_tls_and_h3_grease_movement(self):
        self.observed["h2"]["hello"]["extensions"].reverse()
        self.observed["h3"]["settings"].remove([33, 5])
        self.observed["h3"]["settings"].insert(0, [64, 2000])
        self.observed["h3"]["grease_settings"] = grease_settings(self.observed["h3"]["settings"])
        self.assertEqual(set(diff(self.expected, stable_wire(self.observed))), {"h2.hello.extensions", "h3.settings_grease"})
        gate = Reference([self.expected, stable_wire(self.observed)], "two fresh official runs")
        self.assertEqual(gate.compare(self.observed), {})
        self.observed["h3"]["settings"].pop(0)
        self.observed["h3"]["grease_settings"] = []
        self.assertEqual(set(gate.compare(self.observed)), {"h3.settings_grease_count"})

    def test_tls_psk_extension_must_remain_last(self):
        self.observed["h2"]["hello"]["extensions"].insert(0, 41)
        with self.assertRaisesRegex(WireError, "pre_shared_key must be last"):
            stable_wire(self.observed)

    def test_first_initial_version_and_advertised_order_are_separate(self):
        self.observed["h3"]["initial"]["version"] = 1
        self.assertWireMismatch("h3.initial.version")
        self.observed = wire(54321)
        self.observed["h3"]["initial"]["version_information"]["available"].reverse()
        self.assertWireMismatch("h3.initial.version_information.available")

    def test_tls_extension_membership_and_inner_list_order_are_asserted(self):
        self.observed["h2"]["hello"]["extensions"].append(15)
        self.assertWireMismatch("h2.hello.extensions")
        self.observed = wire(54321)
        self.observed["h2"]["hello"]["key_share_groups"].reverse()
        self.assertWireMismatch("h2.hello.key_share_groups")


class WireReferenceTests(unittest.TestCase):
    def test_rejects_nonexistent_slot_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(WireError, "missing official Firefox reference"):
                load_reference(Path(tmp), "linux_aarch64")

    def test_rejects_wrong_platform_release_or_capture_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "linux_aarch64.json"
            for field, mutation in (
                ("provenance/slot", lambda record: record.update(arch="x86_64")),
                ("missing fields", lambda record: record["captures"].pop("161")),
                ("Mozilla pin mismatch for url", lambda record: record["captures"]["161"].update(url=record["captures"]["160"]["url"])),
                ("Mozilla pin mismatch for sha256", lambda record: record["captures"]["161"].update(sha256="1" * 64)),
                ("Mozilla pin mismatch for build_id", lambda record: record["captures"]["161"].update(build_id="00000000000000")),
                ("default same-origin Fetch", lambda record: record["captures"]["161"]["samples"][0]["h3"]["headers"].append(["sec-fetch-user", "?1"])),
                ("fewer than two real browser samples", lambda record: record["captures"]["159"].update(samples=[])),
            ):
                with self.subTest(field=field):
                    record = reference()
                    mutation(record)
                    path.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(WireError, field):
                        load_reference(root, "linux_aarch64")

    def test_different_observed_stable_fields_across_official_runs_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = reference()
            record["captures"]["160"]["samples"][1]["h3"]["quic_version"] = 1
            (root / "linux_aarch64.json").write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(WireError, r"official samples disagree.*h3.quic_version"):
                load_reference(root, "linux_aarch64")

    def test_complete_reference_preserves_release_specific_raw_user_agents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "linux_aarch64.json").write_text(json.dumps(reference()), encoding="utf-8")
            loaded = load_reference(root, "linux_aarch64")
            for release in ("159", "160", "161"):
                self.assertTrue(dict(loaded[release].stable["h1"]["headers"])["User-Agent"].endswith(f"Firefox/{release}.0"))


if __name__ == "__main__":
    unittest.main()
