import unittest
from validate_source_scope import validate_frozen_tree


class FrozenVendorTests(unittest.TestCase):
    def manifest(self):
        return {'frozen_entries': {'upstream/main.go': {'mode': '100644', 'blob': 'a' * 40},
                                   'upstream/build.sh': {'mode': '100755', 'blob': 'b' * 40},
                                   '.github/workflows/old.yml': {'mode': '100644', 'blob': 'c' * 40},
                                   'CODESTRA_UPSTREAM_LOCK.json': {'mode': '100644', 'blob': 'd' * 40}},
                'frozen_prefixes': ['upstream/']}

    def entries(self):
        return dict(self.manifest()['frozen_entries'])

    def test_identical_reviewed_executable_vendor_is_frozen(self):
        self.assertEqual([], validate_frozen_tree(self.entries(), self.manifest()))

    def test_changed_vendor_source_rejected(self):
        entries = self.entries(); entries['upstream/main.go'] = {'mode': '100644', 'blob': 'e' * 40}
        self.assertTrue(validate_frozen_tree(entries, self.manifest()))

    def test_new_vendor_file_rejected_even_if_markdown(self):
        entries = self.entries(); entries['upstream/new.md'] = {'mode': '100644', 'blob': 'e' * 40}
        self.assertTrue(validate_frozen_tree(entries, self.manifest()))

    def test_removed_vendor_rejected(self):
        entries = self.entries(); del entries['upstream/main.go']
        self.assertTrue(validate_frozen_tree(entries, self.manifest()))

    def test_changed_mode_rejected(self):
        for mode in ('100755', '120000', '160000'):
            entries = self.entries(); entries['upstream/main.go'] = {'mode': mode, 'blob': 'a' * 40}
            self.assertTrue(validate_frozen_tree(entries, self.manifest()))

    def test_original_workflow_and_lock_cannot_change(self):
        for name in ('.github/workflows/old.yml', 'CODESTRA_UPSTREAM_LOCK.json'):
            entries = self.entries(); entries[name] = {'mode': '100644', 'blob': 'e' * 40}
            self.assertTrue(validate_frozen_tree(entries, self.manifest()))

    def test_new_owned_docs_do_not_change_frozen_tree(self):
        entries = self.entries(); entries['docs/review.md'] = {'mode': '100644', 'blob': 'e' * 40}
        self.assertEqual([], validate_frozen_tree(entries, self.manifest()))


if __name__ == '__main__':
    unittest.main()

from types import SimpleNamespace
from unittest.mock import patch
from validate_source_scope import FROZEN_VENDOR_BASES, frozen_vendor_manifest, validate


class FrozenBootstrapTests(unittest.TestCase):
    repo, base = next(iter(FROZEN_VENDOR_BASES))

    def make(self, tree=None, entries=None):
        expected = FROZEN_VENDOR_BASES[(self.repo, self.base)]
        raw = entries or ('100644 blob ' + 'a' * 40 + '\tAGENTS.md\0' +
                          '100755 blob ' + 'b' * 40 + '\tupstream/build.sh\0')
        def git(args):
            return ((tree or expected) if args[1] == 'rev-parse' else raw).encode()
        with patch('validate_source_scope.subprocess.check_output', side_effect=git):
            return frozen_vendor_manifest(self.base, self.repo, self.base)

    def test_exact_reviewed_root_derives_blob_mode_inventory(self):
        manifest = self.make()
        self.assertEqual({'mode': '100755', 'blob': 'b' * 40}, manifest['frozen_entries']['upstream/build.sh'])
        self.assertIn('AGENTS.md', manifest['frozen_entries'])
        self.assertEqual(['upstream/'], manifest['frozen_prefixes'])

    def test_wrong_repository_or_base_cannot_inherit_vendor_allowance(self):
        for repo, base, bootstrap in [('appolon1908/unreviewed', self.base, self.base),
                                      (self.repo, 'd' * 40, 'd' * 40),
                                      (self.repo, self.base, 'd' * 40)]:
            with self.assertRaises(ValueError):
                frozen_vendor_manifest(base, repo, bootstrap)

    def test_wrong_root_tree_rejected(self):
        with self.assertRaises(ValueError): self.make(tree='d' * 40)

    def test_submodule_not_silently_trusted(self):
        with self.assertRaises(ValueError): self.make(entries='160000 commit ' + 'a' * 40 + '\tupstream/submodule\0')

    def test_baseline_requires_both_authority_and_vendor(self):
        for raw in ['100644 blob ' + 'a' * 40 + '\tAGENTS.md\0',
                    '100644 blob ' + 'a' * 40 + '\tupstream/main.go\0']:
            with self.assertRaises(ValueError): self.make(entries=raw)

    def test_candidate_blob_inventory_is_required_before_file_read(self):
        from pathlib import Path
        self.assertTrue(validate(Path('/nonexistent'), {'upstream/build.sh': '100755'}, self.make()))

    def test_frozen_config_raw_bytes_and_modes_are_mandatory(self):
        manifest = {'frozen_entries': {'config.json': {'mode': '100644', 'blob': 'a' * 40}}}
        self.assertTrue(validate_frozen_tree({'config.json': {'mode': '100644', 'blob': 'b' * 40}}, manifest))
        self.assertTrue(validate_frozen_tree({}, manifest))


class FrozenAdditionTests(unittest.TestCase):
    def test_unreviewed_github_and_agent_authority_additions_are_rejected(self):
        from pathlib import Path
        for name in ('.gitignore', '.github/new.md', 'docs/AGENTS.md', '.codestra/authority.md', 'governance/new.md'):
            manifest = {'frozen_entries': {'existing': {'mode': '100644', 'blob': 'a' * 40}}}
            entries = dict(manifest['frozen_entries']); entries[name] = {'mode': '100644', 'blob': 'b' * 40}
            tracked = {key: value['mode'] for key, value in entries.items()}
            self.assertTrue(validate(Path('/nonexistent'), tracked, manifest, tracked_blobs=entries))

    def test_new_document_can_link_to_proven_frozen_markdown_heading(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'docs').mkdir()
            (root / 'README.md').write_text('# Existing heading\n')
            (root / 'docs/review.md').write_text('[review](../README.md#existing-heading)')
            frozen = {'README.md': {'mode': '100644', 'blob': 'a' * 40}}
            entries = dict(frozen); entries['docs/review.md'] = {'mode': '100644', 'blob': 'b' * 40}
            manifest = {'frozen_entries': frozen}
            tracked = {name: entry['mode'] for name, entry in entries.items()}
            self.assertEqual([], validate(root, tracked, manifest, tracked_blobs=entries))
            (root / 'docs/review.md').write_text('[review](../README.md#missing)')
            self.assertTrue(validate(root, tracked, manifest, tracked_blobs=entries))
