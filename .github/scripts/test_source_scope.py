import json
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path
from validate_source_scope import validate, trusted_from_git, structured, source_policy


class SourceScopeTests(unittest.TestCase):
    def check(self, files, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            manifest = {'repository': 'appolon1908/example', 'structured_files': {},
                        'required_text': {}, 'baseline_files': []}
            manifest.update(extra or {})
            return validate(root, {p: '100644' for p in files}, manifest)

    def test_application_source_cannot_enter_documentation_lane(self):
        self.assertTrue(self.check({'src/server.py': 'print(1)'}))

    def test_unknown_configuration_cannot_silently_enter_lane(self):
        self.assertTrue(self.check({'deploy/config.yaml': 'enabled: true'}))

    def test_markdown_extension_cannot_hide_executable(self):
        self.assertTrue(self.check({'README.md': '#!/bin/sh\necho unsafe'}))

    def test_broken_internal_link_is_rejected(self):
        self.assertTrue(self.check({'README.md': '[missing](docs/absent.md)'}))

    def test_reference_style_broken_link_is_rejected(self):
        self.assertTrue(self.check({'README.md': '[missing][ref]\n\n[ref]: missing.md'}))

    def test_missing_heading_is_rejected(self):
        self.assertTrue(self.check({'README.md': '[wrong](#missing)\n\n# Existing'}))

    def test_valid_heading_and_reference_links_pass(self):
        self.assertEqual([], self.check({'README.md': '# Hello World\n[ok][ref]\n\n[ref]: #hello-world'}))

    def test_duplicate_json_keys_are_rejected(self):
        self.assertTrue(self.check({'known.json': '{"a":1,"a":2}'}, {'structured_files': {'known.json': {}}}))

    def test_duplicate_yaml_keys_are_rejected(self):
        self.assertTrue(self.check({'known.yaml': 'a: 1\na: 2'}, {'structured_files': {'known.yaml': {}}}))

    def test_required_authority_cannot_disappear(self):
        self.assertTrue(self.check({'README.md': '# Changed'}, {'required_text': {'README.md': ['production effects remain separately gated']}}))

    def test_contract_semantics_cannot_change(self):
        self.assertTrue(self.check({'known.json': '{"enabled": true}'}, {'structured_files': {'known.json': {'enabled': False}}}))

    def test_symlink_or_executable_mode_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('# Docs')
            for mode in ('100755', '120000', '160000'):
                self.assertTrue(validate(root, {'README.md': mode}, {'structured_files': {}, 'required_text': {}, 'baseline_files': []}))

    def test_candidate_cannot_remove_trusted_manifest_restrictions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('# Docs')
            trusted = {'baseline_files': ['README.md'], 'structured_files': {}, 'authority_hashes': {'README.md': 'fixed'}}
            self.assertTrue(validate(root, {'README.md': '100644'}, {}, trusted_manifest=trusted))

    def test_candidate_cannot_rewrite_contract_expectation_with_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'known.json').write_text('{"enabled": true}')
            trusted = {'baseline_files': ['known.json'], 'structured_files': {'known.json': {'enabled': False}}}
            candidate = {'baseline_files': [], 'structured_files': {'known.json': {'enabled': True}}}
            self.assertTrue(validate(root, {'known.json': '100644'}, candidate, trusted_manifest=trusted))


class ExistingAuthorityTests(unittest.TestCase):
    repo = 'appolon1908/Codestra-Device-Forge'
    base = 'a1646d9504a10db42f19d4665c7801b625e41300'
    name = '.github/copilot-instructions.md'
    blob = 'b377a31eb1f063ad7583864774218e579dbb9511'

    def trusted(self, repo=None, base=None, name=None, blob=None):
        repo, base = repo or self.repo, base or self.base
        name, blob = name or self.name, blob or self.blob
        tree = f'100644 blob {"a" * 40}\tAGENTS.md\0' + f'100644 blob {blob}\t{name}\0'

        def git(args):
            if args[1] == 'ls-tree':
                return tree.encode()
            return b'# Existing authority\n'

        with patch('validate_source_scope.subprocess.run', return_value=SimpleNamespace(returncode=1)), \
                patch('validate_source_scope.subprocess.check_output', side_effect=git):
            return trusted_from_git(base, repo, base)

    def test_exact_reviewed_legacy_file_is_frozen(self):
        manifest = self.trusted()
        self.assertIn(self.name, manifest['authority_hashes'])
        self.assertIn(self.name, manifest['baseline_files'])

    def test_wrong_repository_cannot_inherit_legacy_allowance(self):
        with self.assertRaises(ValueError):
            self.trusted(repo='appolon1908/unreviewed')

    def test_wrong_original_base_cannot_inherit_legacy_allowance(self):
        with self.assertRaises(ValueError):
            self.trusted(base='b' * 40)

    def test_wrong_legacy_blob_is_rejected(self):
        with self.assertRaises(ValueError):
            self.trusted(blob='b' * 40)

    def test_unknown_legacy_path_is_rejected(self):
        with self.assertRaises(ValueError):
            self.trusted(name='.github/workflows/unreviewed.yml')

    def test_workflow_on_is_string_and_true_value_is_boolean(self):
        self.assertEqual({'on': {'pull_request': None}, 'enabled': True},
                         structured('workflow.yml', 'on:\n  pull_request:\nenabled: true\n'))

    def test_yaml_numeric_keys_cannot_collapse_in_json_manifest(self):
        with self.assertRaises(ValueError):
            structured('workflow.yml', '1: unsafe\n"1": safe\n')

    def test_existing_import_contract_validation_stays_required(self):
        contexts = {item['context'] for item in source_policy('appolon1908/Meltano-Leads-Importer')['required_checks']}
        self.assertEqual({'documentation-contract-source-v2', 'validate'}, contexts)


if __name__ == '__main__':
    unittest.main()
