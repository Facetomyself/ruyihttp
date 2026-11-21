"""Verify wheel inventory guards without importing a reference runtime."""
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import build_native as tool

ELF=b'\x7fELF\x02\x01\x01'+bytes(9)+b'\x03\x00\x3e\x00'


class NativeWheelTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name);self.wheel=self.root/'fixture.whl'

    def wheel_with(self, files):
        with zipfile.ZipFile(self.wheel,'w',compression=zipfile.ZIP_DEFLATED) as f:
            for k,v in files:f.writestr(k,v)

    def test_decompresses_only_the_declared_members(self):
        self.wheel_with([('native/libwanted.so',ELF),('unrelated/large_payload',b'x'*2000)])
        original=zipfile.ZipFile.read;seen=[]
        def observed(archive,item,**opts):
            seen.append(item.filename);return original(archive,item,**opts)
        with patch.object(zipfile.ZipFile,'read',observed):self.assertEqual(tool.wheel_members(self.wheel,['libwanted.so']),{'libwanted.so':ELF})
        self.assertEqual(seen,['native/libwanted.so'])

    def test_rejects_conflicting_basenames_links_and_traversal(self):
        link=zipfile.ZipInfo('native/libwanted.so');link.create_system=3;link.external_attr=(stat.S_IFLNK|0o777)<<16
        for files in ([('one/libwanted.so',ELF),('two/libwanted.so',ELF)],[(link,b'target')],[('../libwanted.so',ELF)],[(r'native\libwanted.so',ELF)]):
            self.wheel_with(files)
            with self.subTest(files=files),self.assertRaisesRegex(ValueError,'ambiguous, linked or oversized'):
                tool.wheel_members(self.wheel,['libwanted.so'])

    def test_invalid_linux_arch_leaves_native_tree_and_manifest_absent(self):
        arch='linux_x86_64';self.wheel_with([(name,ELF if i else ELF[:18]+b'\xb7\x00') for i,name in enumerate(tool.PLATFORM_FILES[arch])])
        with patch.object(tool,'NATIVE',self.root/'new-native'),patch.object(tool,'MANIFEST',self.root/'manifest.json'):
            with self.assertRaisesRegex(ValueError,'x86_64 ELF shared library'):tool.import_wheel(self.wheel,arch)
        self.assertFalse((self.root/'new-native').exists());self.assertFalse((self.root/'manifest.json').exists())

    def test_bad_central_directory_is_rejected_before_zipfile_allocation(self):
        self.wheel_with([('native/libwanted.so',ELF)])
        raw=self.wheel.read_bytes();at=raw.rindex(b'PK\x05\x06')+12
        self.wheel.write_bytes(raw[:at]+(5*1024**2).to_bytes(4,'little')+raw[at+4:])
        with patch.object(zipfile,'ZipFile',side_effect=AssertionError('archive must not be opened')):
            with self.assertRaisesRegex(ValueError,'directory budget'):
                tool.wheel_members(self.wheel,['libwanted.so'])

    def test_hash_change_invalidates_inspection(self):
        self.wheel_with([('native/libwanted.so',ELF)])
        with patch.object(tool,'sha256',side_effect=['1','2']),patch.object(tool,'inspect_wheel',return_value={'file':ELF}):
            with self.assertRaisesRegex(ValueError,'wheel bytes changed'):tool.inspect_stable_wheel(self.wheel,'linux_x86_64')


if __name__=='__main__':unittest.main()
