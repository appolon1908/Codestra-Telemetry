import copy
import unittest
from verify_secret_findings import VERIFIED_FIXTURES, CORPUS_PATH, CORPUS_COMMIT, CORPUS_BLOB, verify_findings


class SecretFindingTests(unittest.TestCase):
    def fixture(self, kind='tree'):
        path, spec = next(iter(VERIFIED_FIXTURES.items()))
        commit = spec['history_commit'] if kind == 'history' else ''
        finding = {'File': path, 'RuleID': 'private-key', 'StartLine': 1, 'Commit': commit,
                   'Fingerprint': (commit + ':' if commit else '') + path + ':private-key:1'}
        identity = {'mode': '100644', 'blob': spec['blob'], 'sha256': spec['sha256']}
        return finding, identity

    def check(self, findings, status=1, kind='tree', identity=None):
        _, expected = self.fixture(kind)
        return verify_findings(findings, kind, status, lambda *_: identity or expected)

    def test_exact_public_fixture_blob_and_fingerprint_is_classified(self):
        for kind in ('tree', 'history'):
            finding, _ = self.fixture(kind)
            self.assertEqual([], self.check([finding], kind=kind))

    def test_adjacent_unapproved_credential_still_blocks(self):
        known, _ = self.fixture(); other = dict(known, File='docs/adjacent.key')
        other['Fingerprint'] = 'docs/adjacent.key:private-key:1'
        self.assertTrue(self.check([known, other]))

    def test_same_path_changed_blob_or_content_hash_or_mode_blocks(self):
        finding, identity = self.fixture()
        for key, value in [('blob', 'a' * 40), ('sha256', 'b' * 64), ('mode', '100755')]:
            changed = dict(identity); changed[key] = value
            self.assertTrue(self.check([finding], identity=changed))

    def test_same_fixture_new_commit_rule_line_or_fingerprint_blocks(self):
        finding, _ = self.fixture('history')
        for key, value in [('Commit', 'f' * 40), ('RuleID', 'jwt'), ('StartLine', 2), ('Fingerprint', 'forged')]:
            changed = dict(finding); changed[key] = value
            self.assertTrue(self.check([changed], kind='history'))

    def test_new_test_path_is_not_generically_exempt(self):
        finding, _ = self.fixture(); finding['File'] = 'upstream/config/configgrpc/testdata/new.key'
        self.assertTrue(self.check([finding]))

    def test_duplicate_or_malformed_reports_fail_closed(self):
        finding, _ = self.fixture()
        self.assertTrue(self.check([finding, copy.deepcopy(finding)]))
        for malformed in ({}, None, 'not-a-finding'):
            self.assertTrue(self.check([malformed]))

    def test_scanner_errors_and_status_report_mismatch_are_fatal(self):
        finding, _ = self.fixture()
        for status in (2, 127, -1): self.assertTrue(self.check([], status=status))
        self.assertTrue(self.check([], status=1))
        self.assertTrue(self.check([finding], status=0))
        self.assertEqual([], self.check([], status=0))

    def test_exact_historical_planted_corpus_has_bounded_counts(self):
        def finding(rule, line):
            return {'File': CORPUS_PATH, 'Commit': CORPUS_COMMIT, 'RuleID': rule, 'StartLine': line,
                    'Fingerprint': f'{CORPUS_COMMIT}:{CORPUS_PATH}:{rule}:{line}'}
        jwt, stripe = finding('jwt', 47), finding('stripe-access-token', 62)
        lookup = lambda *_: {'mode': '100644', 'blob': CORPUS_BLOB}
        self.assertEqual([], verify_findings([jwt, stripe, stripe], 'history', 1, lookup))
        self.assertTrue(verify_findings([jwt, stripe, stripe, stripe], 'history', 1, lookup))
        self.assertTrue(verify_findings([jwt], 'history', 1, lambda *_: {'mode': '100644', 'blob': 'f' * 40}))

    def test_owned_historical_corpus_never_allows_current_tree_credentials(self):
        finding = {'File': 'scripts/validate_middleware_v3_trace_pipeline.py', 'Commit': '',
                   'RuleID': 'jwt', 'StartLine': 47,
                   'Fingerprint': 'scripts/validate_middleware_v3_trace_pipeline.py:jwt:47'}
        self.assertTrue(self.check([finding]))


if __name__ == '__main__': unittest.main()
