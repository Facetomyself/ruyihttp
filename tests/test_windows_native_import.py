"""Static guards for the imported Windows native set and immutable upgrade baseline."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_native
import sync_windows_native as sync


class WindowsNativeImportTests(unittest.TestCase):
    def test_tracked_candidate_matches_the_pinned_pe_inventories(self):
        provenance = sync.check_slot()
        self.assertEqual(provenance["source_kind"], "pypi-wheel-import")
        self.assertFalse(provenance["source_rebuild_performed"])
        self.assertEqual(provenance["wheel_sha256"], sync.WHEEL_SHA256)
        self.assertEqual(provenance["core_abi_version"], 1)
        self.assertIsNone(provenance["h3_body_abi"])
        self.assertEqual(set(provenance["files"]), set(sync.NAMES))

    def test_windows_upgrade_source_remains_the_unchanged_pypi_090_baseline(self):
        baseline = sync.read_json(sync.BASELINE)
        self.assertEqual(baseline["wheel"], "ruyihttp-0.9.0-py3-none-win_amd64.whl")
        self.assertEqual(baseline["wheel_sha256"],
                         "95b67581b2538194b9fc9b41b7f7077f1cb2767dbc5c776d404e78cd11d42f48")
        self.assertEqual(baseline["runtime_expected"]["nss"], "3.131")
        self.assertEqual(set(baseline["files"]), set(sync.NAMES))
        for name, old in baseline["files"].items():
            self.assertNotEqual(old["sha256"], sync.DLL_SHA256[name], name)

    def test_unpinned_wheel_is_rejected_before_opening_its_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / sync.WHEEL
            wheel.write_bytes(b"untrusted")
            with patch.object(sync, "WHEEL_SIZE", wheel.stat().st_size), patch.object(sync, "ZipFile") as reader:
                with self.assertRaisesRegex(ValueError, "pinned PyPI release"):
                    sync.inspect_wheel(wheel)
                reader.assert_not_called()

    def test_generic_import_has_no_windows_write_path(self):
        with self.assertRaisesRegex(ValueError, "pinned sync_windows_native.py importer"):
            build_native.import_wheel(Path("arbitrary.whl"), sync.SLOT)

    def test_replacing_a_dll_fails_even_with_a_valid_pe_header(self):
        slot = sync.NATIVE / sync.SLOT
        dlls = {n: (slot / n).read_bytes() for n in sync.NAMES}
        name = "nss3.dll"
        dlls[name] = dlls[name][:-1] + bytes([dlls[name][-1] ^ 1])
        build_native.check_architecture(sync.SLOT, name, dlls[name])
        with self.assertRaisesRegex(ValueError, "pinned six-file donor set"):
            sync.artifacts(dlls)


if __name__ == "__main__":
    unittest.main()
