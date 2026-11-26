import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
from firefox_wire import RELEASES, pinned_build
from verify_h2_first_flight import compile_supplement, grade


class SupplementalAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.slot = "linux_aarch64"
        self.flight = {
            "frames": [
                {
                    "type": "SETTINGS",
                    "stream": 0,
                    "values": [[1, 65536], [2, 0], [4, 131072], [5, 16384]],
                },
                {"type": "WINDOW_UPDATE", "stream": 0, "increment": 12517377},
            ],
            "settings_ack_positions": [],
            "first_headers": {
                "stream": 1,
                "end_headers": True,
                "end_stream": True,
                "padded": False,
                "priority": None,
            },
        }
        self.source = {
            "source": "official-firefox",
            "scope": "h2-preface",
            "slot": self.slot,
            "platform": "linux",
            "arch": "aarch64",
            "captures": {},
        }
        for major in RELEASES:
            pin = pinned_build(self.slot, major)
            self.source["captures"][major] = {
                "build_id": pin["build_id"],
                "sha256": pin["sha256"],
                "samples": [copy.deepcopy(self.flight) for _ in range(2)],
            }

    def test_matches_primary_and_every_repeat_and_never_falls_back_to_other_slot(self):
        reference = compile_supplement(self.slot, self.source)
        rows = [
            {
                "source": "installed-wheel",
                "slot": self.slot,
                "firefox": major,
                "responses": {"h2": {"first_flight": copy.deepcopy(self.flight)}},
                "repeats": [
                    {"responses": {"h2": {"first_flight": copy.deepcopy(self.flight)}}}
                ],
            }
            for major in RELEASES
        ]
        self.assertFalse(
            any(
                d
                for r in grade(rows, reference, self.slot).values()
                for d in r["differences"]
            )
        )
        for label, change in [
            ("flow", lambda v: v["frames"][1].update(increment=100000)),
            (
                "priority",
                lambda v: v["frames"].insert(
                    1,
                    {
                        "type": "PRIORITY",
                        "stream": 3,
                        "weight": 16,
                        "depends_on": 0,
                        "exclusive": False,
                    },
                ),
            ),
            ("stream", lambda v: v["first_headers"].update(stream=7)),
        ]:
            changed = copy.deepcopy(rows)
            change(changed[-1]["repeats"][0]["responses"]["h2"]["first_flight"])
            with self.subTest(case=label):
                self.assertTrue(
                    grade(changed, reference, self.slot)["161"]["differences"][1]
                )
        with self.assertRaises(ValueError):
            compile_supplement("linux_x86_64", self.source)
        self.source["captures"]["161"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            compile_supplement(self.slot, self.source)
