"""Test read-only Linux ELF preflight with non-product shared-library fixtures."""
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from check_linux_candidate import (CORE, QUIC, PLATFORM_FILES, baseline_versions, check,
                                   function_exports, needed_versions, version_needs)


class LinuxCandidateTests(unittest.TestCase):
    def test_only_defined_dynamic_functions_count(self):
        rows='''
1: 0000000000000000 0 FUNC GLOBAL DEFAULT UND necko_missing@X
2: 0000000000000010 4 FUNC GLOBAL DEFAULT 9 necko_real@@X
3: 0000000000000011 8 OBJECT GLOBAL DEFAULT 9 necko_data
4: 0000000000000012 4 FUNC GLOBAL HIDDEN 9 necko_private
'''
        self.assertEqual(function_exports(rows),{'necko_real'})
        self.assertEqual(version_needs('Name: GLIBC_2.99\nVersion needs section .gnu.version_r\nName: GLIBC_2.38'),{(2,38)})
        with self.assertRaisesRegex(ValueError,'unsupported glibc'):version_needs('Version needs section\nName: GLIBC_PRIVATE')

    def test_bullseye_symbol_versions_and_providers_are_enforced_individually(self):
        report = '''Version definition section
  Name: GLIBC_9.99
Version needs section
  File: libc.so.6  Cnt: 1
  Name: GLIBC_2.31  Flags: none  Version: 2
  File: libstdc++.so.6  Cnt: 2
  Name: GLIBCXX_3.4.28  Flags: none  Version: 3
  Name: CXXABI_1.3.12  Flags: none  Version: 4
  File: libgcc_s.so.1  Cnt: 1
  Name: GCC_7.0.0  Flags: none  Version: 5
'''
        inputs = needed_versions(report)
        self.assertEqual(baseline_versions(inputs, 'x86_64', 'fixture.so'), {
            'GLIBC': ['GLIBC_2.31'], 'GLIBCXX': ['GLIBCXX_3.4.28'],
            'CXXABI': ['CXXABI_1.3.12'], 'GCC': ['GCC_7.0.0'],
        })
        for old, unsupported in (('GLIBC_2.31', 'GLIBC_2.32'), ('GLIBCXX_3.4.28', 'GLIBCXX_3.4.29'),
                                 ('CXXABI_1.3.12', 'CXXABI_1.3.13'), ('GCC_7.0.0', 'GCC_8.0.0')):
            with self.subTest(symbol=unsupported), self.assertRaisesRegex(ValueError, 'exceeds Bullseye'):
                baseline_versions(needed_versions(report.replace(old, unsupported)), 'aarch64', 'fixture.so')
        for unsupported in ('GLIBC_ABI_DT_RELR', 'GLIBC_PRIVATE'):
            with self.assertRaisesRegex(ValueError, 'unsupported GLIBC'):
                baseline_versions({'libc.so.6': {unsupported}}, 'aarch64', 'fixture.so')
        with self.assertRaisesRegex(ValueError, 'incorrect provider'):
            baseline_versions({'libgcc_s.so.1': {'CXXABI_1.3.12'}}, 'aarch64', 'fixture.so')

    @unittest.skipUnless(sys.platform=='linux' and platform.machine() in ('x86_64','aarch64') and shutil.which('cc') and Path('/usr/bin/readelf').is_file(),'native ELF toolchain unavailable')
    def test_real_elf_fixture_and_mixed_architecture(self):
        arch=platform.machine();other='aarch64' if arch=='x86_64' else 'x86_64'
        with tempfile.TemporaryDirectory(prefix='test-only-native-candidate-') as tmp:
            w=Path(tmp).resolve();payload=w/'runtime';payload.mkdir();src=w/'fixture.c';binary=w/'fixture.so'
            names=CORE|QUIC
            fixture = '#include <stdio.h>\nint witness(void) { return puts("fixture"); }\n'
            src.write_text(fixture + '\n'.join(f'int {name}(void) {{ return 0; }}' for name in sorted(names)))
            subprocess.run(['cc','-fPIC','-shared','-Wl,-rpath,$ORIGIN',src,'-o',binary],check=True,timeout=20)
            for name in PLATFORM_FILES['linux_x86_64']:shutil.copyfile(binary,payload/name)
            r=check(payload,arch);self.assertTrue(r['passed']);self.assertFalse(r['runtime_proven']);self.assertEqual(len(r['libraries']),14)
            with self.assertRaisesRegex(ValueError,'expected native '+other):check(payload,other)
            baseline = check(payload, arch, baseline=True)
            self.assertEqual(baseline['allowed_glibc_max'], '2.31')
            self.assertTrue(all(row['version_families']['GLIBC'] for row in baseline['libraries'].values()))
            subprocess.run(['cc', '-fPIC', '-shared', src, '-o', payload / 'libnss3.so'], check=True, timeout=20)
            with self.assertRaisesRegex(ValueError, 'DT_RUNPATH'):
                check(payload, arch, baseline=True)
            shutil.copyfile(binary, payload / 'libnss3.so')
            src.write_text('int fixture_only(void){return 0;}\n')
            subprocess.run(['cc','-fPIC','-shared','-Wl,-rpath,$ORIGIN',src,'-o',payload/'libnecko_core.so'],check=True,timeout=20)
            with self.assertRaisesRegex(ValueError,'missing defined ABI functions'):check(payload,arch)


if __name__=='__main__':unittest.main()
