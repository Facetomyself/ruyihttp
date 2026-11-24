"""Synthetic Mach-O load command parser fixtures (no native execution)."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage_native_candidate import macho_deployment_and_rpaths


class MacDeploymentTests(unittest.TestCase):
    def image(self, *commands):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'synthetic.dylib'
            body = b''.join(commands)
            path.write_bytes(struct.pack('<8I', 0xFEEDFACF, 0x01000007, 3, 6,
                                         len(commands), len(body), 0, 0) + body)
            return macho_deployment_and_rpaths(path)

    def test_modern_command_ignores_linker_tool_version(self):
        build = struct.pack('<8I', 0x32, 32, 1, 15 << 16, 26 << 16, 1, 3, 0x050201)
        loader_path = struct.pack('<3I', 0x8000001C, 32, 12) + b'@loader_path\0'.ljust(20, b'\0')
        self.assertEqual(self.image(build, loader_path), ((15, 0, 0), [b'@loader_path']))

    def test_legacy_command_retains_patch(self):
        build = struct.pack('<4I', 0x24, 16, 0x0A0F01, 0x0F0000)
        self.assertEqual(self.image(build), ((10, 15, 1), []))

    def test_rejects_ambiguous_or_nonmacos(self):
        legacy = struct.pack('<4I', 0x24, 16, 0x0A0F01, 0x0F0000)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.image(legacy, legacy)
        with self.assertRaisesRegex(ValueError, 'does not specify macOS'):
            self.image(struct.pack('<6I', 0x32, 24, 2, 0x0F0000, 0x130000, 0))

    def test_rejects_truncated_command(self):
        with self.assertRaisesRegex(ValueError, 'invalid Mach-O load command'):
            self.image(struct.pack('<4I', 0x24, 24, 0x0A0F01, 0x0F0000))
