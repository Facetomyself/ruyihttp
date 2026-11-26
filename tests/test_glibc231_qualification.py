"""Offline checks for the exact-wheel / ELF portions of the Linux floor gate."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

SPEC = importlib.util.spec_from_file_location(
    "qualify_glibc231", Path(__file__).resolve().parents[1] / "ci/qualify_glibc231.py"
)
FLOOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLOOR)


class QualificationTests(unittest.TestCase):
    def wheel(self, root, version="0.9.4", tag="py3-none-manylinux_2_31_aarch64", internal=None):
        path = root / f"ruyihttp-{version}-{tag}.whl"
        with ZipFile(path, "w") as wheel:
            wheel.writestr(f"ruyihttp-{version}.dist-info/WHEEL", f"Wheel-Version: 1.0\nTag: {internal or tag}\n")
            wheel.writestr(f"ruyihttp-{version}.dist-info/METADATA", f"Version: {version}\nProvides-Extra: masque\n")
        return path

    def test_release_identity_rejects_generic_and_internal_tag_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheel = self.wheel(root)
            self.assertEqual(FLOOR.wheel_info(root, "aarch64", "release"), (wheel, "0.9.4", {"masque"}))
            self.wheel(root, internal="py3-none-manylinux_2_39_aarch64")
            with self.assertRaisesRegex(RuntimeError, "internal wheel tags"):
                FLOOR.wheel_info(root, "aarch64", "release")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.wheel(root, tag="py3-none-linux_aarch64")
            with self.assertRaisesRegex(RuntimeError, "expected actual py3-none-manylinux_2_31_aarch64"):
                FLOOR.wheel_info(root, "aarch64", "candidate")

    def test_dev_wheel_is_candidate_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.wheel(root, version="0.9.4.dev45791880820+gha.1")
            FLOOR.wheel_info(root, "aarch64", "candidate")
            with self.assertRaisesRegex(RuntimeError, "incorrect release wheel version"):
                FLOOR.wheel_info(root, "aarch64", "release")

    def test_proposed_native_manifest_cannot_be_used_for_release(self):
        arch = "aarch64"
        tag = f"manylinux_2_31_{arch}"
        record = {"policy": "manylinux_2_31", "candidate_tag": tag, "elf_sha256": "a" * 64, "build_sha256": "b" * 64}
        manifest = {"wheel_platform_tag": f"manylinux_2_39_{arch}", "linux_baseline_candidate": record,
                    "h3_body_abi": 1, "h3_protocol_policy": 1}
        self.assertEqual(FLOOR.native_tag_record(manifest, arch, "candidate")["kind"], "linux_baseline_candidate")
        with self.assertRaisesRegex(RuntimeError, "admitted glibc 2.31 native manifest"):
            FLOOR.native_tag_record(manifest, arch, "release")
        manifest["linux_baseline"] = manifest.pop("linux_baseline_candidate")
        manifest["wheel_platform_tag"] = tag
        self.assertEqual(FLOOR.native_tag_record(manifest, arch, "release")["kind"], "linux_baseline")

    def test_required_symbol_caps_ignore_exports_and_reject_future_or_private_needs(self):
        need = "Version needs section '.gnu.version_r':\n   Name: GLIBC_2.31\n   Name: GLIBCXX_3.4.28\n   Name: CXXABI_1.3.12\n"
        exported = "Version definition section '.gnu.version_d':\n   Name: GLIBC_2.39\n"
        self.assertEqual(FLOOR.check_needed_versions(exported + need, "fixture"),
                         {"GLIBC": "2.31", "GLIBCXX": "3.4.28", "CXXABI": "1.3.12"})
        for symbol in ("GLIBC_2.32", "GLIBCXX_3.4.29", "CXXABI_1.3.13", "GLIBC_PRIVATE", "GLIBC_ABI_DT_RELR"):
            with self.subTest(symbol=symbol), self.assertRaisesRegex(RuntimeError, symbol):
                FLOOR.check_needed_versions(need + f"   Name: {symbol}\n", "fixture")

    def test_pip_report_rejects_wrong_candidate_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheel = self.wheel(root)
            report = root / "install.json"
            document = {"install": [{"metadata": {"name": "ruyihttp", "version": "0.9.4"},
                                    "download_info": {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": FLOOR.sha(wheel)}}}}]}
            FLOOR.json_file(report, document)
            self.assertEqual(FLOOR.dependencies(report, wheel)["ruyihttp"]["sha256"], FLOOR.sha(wheel))
            document["install"][0]["download_info"]["archive_info"]["hashes"]["sha256"] = "0" * 64
            report.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "pip selected wrong wheel bytes"):
                FLOOR.dependencies(report, wheel)


if __name__ == "__main__":
    unittest.main()
