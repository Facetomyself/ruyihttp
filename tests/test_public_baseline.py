from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
import release_inputs


class PublicBaselineTests(unittest.TestCase):
    def test_distinct_original_and_fork_artifacts(self):
        donor = release_inputs.asset_spec("upstream-0.11.0", "win_amd64")
        fork = release_inputs.asset_spec("fork-0.9.2", "win_amd64")
        self.assertNotEqual(donor["sha256"], fork["sha256"])
        self.assertIn("/releases/download/v0.9.2/", fork["url"])
        self.assertTrue(donor["url"].startswith("https://files.pythonhosted.org/"))
        with self.assertRaises(ValueError):
            release_inputs.asset_spec("upstream-0.11.0", "darwin_arm64")
        with self.assertRaises(ValueError):
            release_inputs.check_bytes(donor, b"not a stock wheel")

    def test_changed_cached_wheel_fails_without_replacing_it(self):
        with TemporaryDirectory() as tmp:
            row = release_inputs.asset_spec("fork-0.9.2", "linux_aarch64")
            path = Path(tmp) / row["name"]
            path.write_bytes(b"changed fixture")
            with (
                patch.object(release_inputs, "urlopen") as remote,
                self.assertRaisesRegex(ValueError, "SHA-256"),
            ):
                release_inputs.fetch("fork-0.9.2", "linux_aarch64", tmp)
            remote.assert_not_called()
            self.assertEqual(path.read_bytes(), b"changed fixture")
