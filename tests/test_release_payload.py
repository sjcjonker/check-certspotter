"""Validate release metadata without GitHub requests or credentials."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publish_release', ROOT / 'scripts/publish-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

class ReleaseMetadataTests(unittest.TestCase):
    def test_release_targets_exact_tested_commit_and_versioned_notes(self):
        previous = Path.cwd()
        try:
            os.chdir(ROOT)
            payload = release.release_payload('sjcjonker/check-certspotter', 'abc123')
        finally:
            os.chdir(previous)
        self.assertEqual(payload['tag_name'], 'v1.1.0')
        self.assertEqual(payload['target_commitish'], 'abc123')
        self.assertTrue(payload['body'].startswith('# 1.1.0'))
        self.assertFalse(payload['draft'])
        self.assertFalse(payload['prerelease'])

    def test_untrusted_branch_cannot_publish(self):
        with mock.patch.dict(os.environ, {'GITHUB_REF':'refs/heads/untrusted'}), \
             mock.patch.object(release.urllib.request, 'urlopen') as request:
            with self.assertRaisesRegex(RuntimeError, 'tested main'):
                release.main()
            request.assert_not_called()
