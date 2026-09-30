"""Tests for the lock-policy gate, including actual tampering cases."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import dependencies as gate


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for relative in ['Cargo.toml', 'Cargo.lock', 'vendor-metadata/fedimint-Cargo.lock',
                         'vendor-metadata/provenance.json',
                         'vendor-metadata/reviewed-extra-versions.json']:
            target = self.root / relative
            target.parent.mkdir(exist_ok=True)
            target.write_bytes((gate.ROOT / relative).read_bytes())
        self.settings = patch.multiple(gate, ROOT=self.root,
                                       BASELINE=self.root / 'vendor-metadata/fedimint-Cargo.lock')
        self.settings.start()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.settings.stop)

    def check(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                gate.check()
            except SystemExit:
                pass
        return json.loads(out.getvalue())

    def alter(self, file, old, new):
        p = self.root / file
        text = p.read_text()
        self.assertIn(old, text)
        p.write_text(text.replace(old, new, 1))

    def test_current_resolution_matches_baseline(self):
        self.assertEqual(self.check()['errors'], [])

    def test_manifest_default_features_cannot_change(self):
        self.alter('Cargo.toml', 'default-features = false', 'default-features = true')
        self.assertTrue(self.check()['errors'])

    def test_detached_engine_in_stale_lock_fails(self):
        self.alter('Cargo.lock', ' "fedimint-aleph-bft",', ' "not-the-engine",')
        self.assertTrue(self.check()['errors'])

    def test_engine_checksum_tamper_fails(self):
        self.alter('Cargo.lock', '8b21015ab681cdddedd866fe4af9169901012e9a8bd4745da8423131cccae025', '0' * 64)
        self.assertTrue(self.check()['errors'])

    def test_baseline_tamper_fails_before_comparison(self):
        with (self.root / 'vendor-metadata/fedimint-Cargo.lock').open('a') as f:
            f.write('\n# altered\n')
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            self.check()

    def test_transitive_version_change_fails(self):
        self.alter('Cargo.lock', 'name = "futures-timer"\nversion = "3.0.3"',
                   'name = "futures-timer"\nversion = "3.0.4"')
        self.assertTrue(self.check()['errors'])

    def test_engine_feature_forwarding_fails(self):
        with (self.root / 'Cargo.toml').open('a') as f:
            f.write('\n[features]\ndefault = ["fedimint-aleph-bft/default"]\n')
        self.assertTrue(self.check()['errors'])

    def test_renamed_build_dependency_fails(self):
        with (self.root / 'Cargo.toml').open('a') as f:
            f.write('\n[build-dependencies]\nengine = {package = "fedimint-aleph-bft", version = "=0.36.0"}\n')
        self.assertTrue(self.check()['errors'])

    def test_target_dependency_fails(self):
        with (self.root / 'Cargo.toml').open('a') as f:
            f.write('\n[target.\'cfg(unix)\'.dependencies]\nfedimint-aleph-bft = "=0.36.0"\n')
        self.assertTrue(self.check()['errors'])

    def test_seed_refuses_to_overwrite_lock(self):
        before = (self.root / 'Cargo.lock').read_bytes()
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            gate.seed()
        self.assertEqual((self.root / 'Cargo.lock').read_bytes(), before)

    def test_extra_version_requires_exact_review(self):
        path = self.root / 'vendor-metadata/reviewed-extra-versions.json'
        reviews = json.loads(path.read_text())
        reviews[0]['checksum'] = '0' * 64
        path.write_text(json.dumps(reviews))
        self.assertTrue(self.check()['errors'])

    def test_missing_reviews_fail_closed(self):
        (self.root / 'vendor-metadata/reviewed-extra-versions.json').unlink()
        self.assertTrue(self.check()['errors'])

    def test_review_cannot_approve_engine_upgrade(self):
        import tomllib
        self.alter('Cargo.lock', 'name = "futures-timer"\nversion = "3.0.3"',
                   'name = "futures-timer"\nversion = "3.0.4"')
        packages = tomllib.loads((self.root / 'Cargo.lock').read_text())['package']
        changed = next(p for p in packages if p['name'] == 'futures-timer')
        path = self.root / 'vendor-metadata/reviewed-extra-versions.json'
        reviews = json.loads(path.read_text())
        reviews.append({**changed, 'reason': 'invalid attempt to approve engine change'})
        path.write_text(json.dumps(reviews))
        self.assertTrue(any('outside baseline' in error for error in self.check()['errors']))


if __name__ == '__main__':
    unittest.main()
