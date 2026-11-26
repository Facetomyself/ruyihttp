"""The portable UI is allowed to change a restart command, never the findings."""

import json
import unittest

from tools.refresh_architecture_analysis import portable_html


class WorkbenchPortabilityTests(unittest.TestCase):
    def document(self, command, finding):
        data = {
            "ui": {"resume": {"command": command, "shell": "POSIX sh"}},
            "findings": [finding],
            "snippets": {"path": "ruyihttp/api.py"},
        }
        return (
            '<!doctype html><script id="bauify-analysis" type="application/json">'
            + json.dumps(data, ensure_ascii=False)
            + "</script><aside>源码</aside>"
        )

    def test_exactly_one_ui_string_changes(self):
        old, new = "archify start /checkout", "archify start ."
        expected = self.document(new, "inspect the runtime state")
        self.assertEqual(
            portable_html(self.document(old, "inspect the runtime state"), old, new),
            expected.encode(),
        )

    def test_duplicate_in_captured_evidence_is_not_rewritten(self):
        old = "archify start /checkout"
        with self.assertRaisesRegex(ValueError, "not unique"):
            portable_html(self.document(old, old), old, "archify start .")

    def test_receipt_from_another_run_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected resume"):
            portable_html(
                self.document("archify start /first", "unchanged"),
                "archify start /second",
                "archify start .",
            )
