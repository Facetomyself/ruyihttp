"""The four profile/trust sidecars are part of the binary wheel contract, including on Windows."""

import hashlib
from pathlib import Path
import tempfile
import unittest

import setup


class ProfileInventoryTests(unittest.TestCase):
    def test_missing_changed_or_omitted_input_fails_packaging(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            data = {}
            for name in setup.PROFILE_DATA:
                payload = (name + "\n").encode("ascii")
                (directory / name).write_bytes(payload)
                data[name] = hashlib.sha256(payload).hexdigest()
            setup.verify_profile_data(directory, {"data": data})
            for name in sorted(data):
                path = directory / name
                original = path.read_bytes()
                path.write_bytes(original.replace(b"\n", b"\r\n"))
                with (
                    self.subTest(name=name),
                    self.assertRaisesRegex(SystemExit, "hash differs"),
                ):
                    setup.verify_profile_data(directory, {"data": data})
                path.write_bytes(original)
            (directory / "firefox-roots.pem").unlink()
            with self.assertRaisesRegex(SystemExit, "hash differs"):
                setup.verify_profile_data(directory, {"data": data})
            with self.assertRaisesRegex(SystemExit, "inventory differs"):
                setup.verify_profile_data(directory, {"data": {}})
