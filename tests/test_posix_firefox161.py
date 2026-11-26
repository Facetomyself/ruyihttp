"""Exercise POSIX source-recipe admission without running a candidate binary."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import posix_firefox161 as recipe


class PosixRecipeTests(unittest.TestCase):
    def setUp(self):
        self.slot = 'darwin_x86_64'
        self.runtime = recipe.runtime_expected(self.slot)
        self.provenance = {
            'ff_ruyijs_commit': recipe.DONOR_COMMIT,
            'ff_ruyijs_firefox_gitlink': recipe.DONOR_FIREFOX,
            'firefox_source_commit': recipe.FIREFOX_COMMIT,
            'firefox_source_tag': recipe.FIREFOX_TAG,
            'runtime_expected': dict(recipe.VERSIONS),
            'neqo_source_commit': recipe.NEQO_COMMIT,
            'nss_rs_source_commit': recipe.NSS_RUST_COMMIT,
            'source_patches': [
                {'path': p, 'sha256': recipe.digest(recipe.ROOT / p)}
                for p in recipe.source_patches(self.slot)
            ],
        }

    def test_three_native_version_exports_remain_distinct(self):
        self.assertEqual(self.runtime['h3_version_export'], {'type': 'ascii', 'value': 'neqo-0.34.0/nss-3.133'})
        self.assertEqual(recipe.runtime_expected('linux_aarch64')['h3_version_export'], {'type': 'u32', 'value': 32})
        with self.assertRaisesRegex(ValueError, 'Unsupported POSIX slot'):
            recipe.runtime_expected('win_amd64')

    def test_rejects_old_genuine_firefox_source_and_metadata(self):
        recipe.validate_candidate(self.slot, self.runtime, self.provenance)
        old_receipt = dict(self.provenance, firefox_source_commit=recipe.DONOR_FIREFOX)
        with self.assertRaisesRegex(ValueError, 'source provenance'):
            recipe.validate_candidate(self.slot, self.runtime, old_receipt)
        with self.assertRaisesRegex(ValueError, 'runtime versions'):
            recipe.validate_candidate(self.slot, dict(self.runtime, nss='3.132'), self.provenance)

    def test_rejects_missing_reordered_or_changed_patch(self):
        for change in ('missing', 'reordered', 'changed'):
            with self.subTest(change=change):
                receipt = deepcopy(self.provenance)
                patches = receipt['source_patches']
                if change == 'missing':
                    patches.pop()
                elif change == 'reordered':
                    patches.reverse()
                else:
                    patches[0]['sha256'] = '0' * 64
                with self.assertRaisesRegex(ValueError, 'patch names, order or bytes'):
                    recipe.validate_candidate(self.slot, self.runtime, receipt)
