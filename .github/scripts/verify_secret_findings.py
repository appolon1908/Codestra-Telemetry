"""Classify exact public synthetic fixtures; every other credential/error is fatal.

No path, rule or value regex exemptions. Official upstream provenance is recorded
in docs/PUBLIC-FIXTURE-PROVENANCE.md. Full Gitleaks scans remain unchanged.
"""
import argparse
import hashlib
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

VERIFIED_FIXTURES = {'upstream/config/configgrpc/testdata/client.key': {'blob': '5590878ab576232cb9eabd0be17b15a449f7b005',
                                                    'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                    'sha256': '172f437ede31deab25759573183bcceada1c972e8df691cdba187cb5944194bb'},
 'upstream/config/configgrpc/testdata/server.key': {'blob': '164775c4a8cc708e94e486730d873042fd88bfb0',
                                                    'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                    'sha256': 'a9cb71645e41e38c0f7d1b35cb0cd7fda97c97a15a8872fee933af34dcfb134a'},
 'upstream/config/confighttp/testdata/client.key': {'blob': 'e15ea84e6821a0c204c6f1c9f27f60c7f56e528c',
                                                    'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                    'sha256': 'afef8d12d8b4376b244127d986ef9a6ee4ae17bd6c2177c97c3f48da6d50ba40'},
 'upstream/config/confighttp/testdata/server.key': {'blob': '16818a16599531b894bc3f10772e14f6d8682dd4',
                                                    'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                    'sha256': 'f00c1869541a45a56e123c63c9b1cb306096073c61f0294771ef423d9e58da48'},
 'upstream/config/configtls/testdata/client-1.key': {'blob': '842bc70ee553364a7f68bb596a9009517b6dfce5',
                                                     'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                     'sha256': 'c510bdb039886c0ab0f7a2a00c85f4f6e1115cd52fd664aa57cdc379acd4e626'},
 'upstream/config/configtls/testdata/client-2.key': {'blob': '4b2bd7ddbe15adac3cd70a37bb2ea639264c5512',
                                                     'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                     'sha256': '97231f48738c9218ab9d951ed9082a162bfacab4a1f5e10716644d67a883627a'},
 'upstream/config/configtls/testdata/server-1.key': {'blob': 'aa10b8f7a323b4b8173d5cb1b29520f54640926c',
                                                     'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                     'sha256': '0e86126d19cf4aea66cc3a70f2ad5f5f5b780e3c83578695aa44cc269debc13e'},
 'upstream/config/configtls/testdata/server-2.key': {'blob': '251ff318a1da083a12e098f671de1570c822805c',
                                                     'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                     'sha256': 'cc2160fd3872386895fee2a62b60754588b53dea1e9ffe0ada29cce617ca17ae'},
 'upstream/exporter/otlpexporter/testdata/test_key.pem': {'blob': 'dedfad3df6e3d7146900ab6d89c3b08e5e15764c',
                                                          'history_commit': 'cb1e628913378886859b463844ba82c5222a833a',
                                                          'sha256': '55b24046768c40af0b5215862236f632beab67b4f36ae069e0f7f929d1071cc5'}}

CORPUS_PATH = 'scripts/validate_middleware_v3_trace_pipeline.py'
CORPUS_COMMIT = 'cbe175cb3f86567694a9158cc44df9331a10ea2c'
CORPUS_BLOB = 'af4bee0eedae1a5d1fe9f044eabf1ee02193b830'
CORPUS_CASES = {('jwt', 47): 1, ('stripe-access-token', 62): 2}


def git_identity(kind, commit, path, root=Path('.')):
    if kind == 'history':
        raw = subprocess.check_output(['git', 'ls-tree', '-z', commit, '--', path], cwd=root)
        entries = [entry for entry in raw.decode().split('\0') if entry]
        if len(entries) != 1: raise ValueError('Missing historical Git object')
        metadata, observed = entries[0].split('\t', 1)
        mode, object_type, blob = metadata.split()
        if observed != path or object_type != 'blob': raise ValueError('Unexpected historical object')
        content = subprocess.check_output(['git', 'cat-file', 'blob', blob], cwd=root)
    else:
        raw = subprocess.check_output(['git', 'ls-files', '--stage', '-z', '--', path], cwd=root)
        entries = [entry for entry in raw.decode().split('\0') if entry]
        if len(entries) != 1: raise ValueError('Missing current Git object')
        metadata, observed = entries[0].split('\t', 1)
        mode, indexed_blob, stage = metadata.split()
        file = root / path
        if observed != path or stage != '0' or file.is_symlink(): raise ValueError('Unexpected current object')
        content = file.read_bytes()
        blob = hashlib.sha1(f'blob {len(content)}\0'.encode() + content).hexdigest()
        if blob != indexed_blob: raise ValueError('Current working tree differs from Git index')
    return {'mode': mode, 'blob': blob, 'sha256': hashlib.sha256(content).hexdigest()}


def verify_findings(findings, kind, status, lookup=git_identity):
    if kind not in ('history', 'tree') or status not in (0, 1):
        return ['Scanner execution failed or unknown scan scope']
    if not isinstance(findings, list) or (status == 1) != bool(findings):
        return ['Scanner status/report mismatch']
    errors, counts = [], Counter()
    for finding in findings:
        if not isinstance(finding, dict):
            errors.append('Malformed scanner finding'); continue
        path, rule, line = finding.get('File'), finding.get('RuleID'), finding.get('StartLine')
        commit = finding.get('Commit')
        if not all(isinstance(value, str) for value in (path, rule, commit)):
            errors.append('Malformed scanner identity'); continue
        if not isinstance(line, int) or isinstance(line, bool):
            errors.append('Malformed scanner line'); continue
        expected, maximum = None, 1
        if path in VERIFIED_FIXTURES and rule == 'private-key' and line == 1:
            spec = VERIFIED_FIXTURES[path]
            expected_commit = spec['history_commit'] if kind == 'history' else ''
            if commit == expected_commit:
                expected = {'mode': '100644', 'blob': spec['blob'], 'sha256': spec['sha256']}
        elif kind == 'history' and path == CORPUS_PATH and commit == CORPUS_COMMIT:
            maximum = CORPUS_CASES.get((rule, line), 0)
            if maximum: expected = {'mode': '100644', 'blob': CORPUS_BLOB}
        fingerprint = (commit + ':' if kind == 'history' and isinstance(commit, str) else '') + str(path) + ':' + str(rule) + ':' + str(line)
        if expected is None or finding.get('Fingerprint') != fingerprint:
            errors.append('Unapproved finding: ' + fingerprint); continue
        counts[fingerprint] += 1
        if counts[fingerprint] > maximum:
            errors.append('Unexpected duplicate finding: ' + fingerprint); continue
        try:
            actual = lookup(kind, commit, path)
            if any(actual.get(key) != value for key, value in expected.items()):
                errors.append('Fixture Git blob/mode/content differs: ' + fingerprint)
        except (OSError, ValueError, subprocess.SubprocessError):
            errors.append('Fixture Git identity proof failed: ' + fingerprint)
    return errors


def scanner_regression(scanner):
    """Real scanner proof: an approved fixture cannot mask an adjacent new key."""
    original = Path.cwd()
    path = next(iter(VERIFIED_FIXTURES))
    public_fixture = (original / path).read_bytes()
    with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as reports:
        root = Path(directory); fixture = root / path
        fixture.parent.mkdir(parents=True); fixture.write_bytes(public_fixture)
        subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
        subprocess.run(['git', 'add', '.'], cwd=root, check=True)
        def scan():
            report = Path(reports) / 'findings.json'
            result = subprocess.run([str(Path(scanner).resolve()), 'dir', '--no-banner', '--redact=100',
                                     '--exit-code', '1', '--report-format', 'json', '--report-path', str(report), '.'],
                                    cwd=root, capture_output=True)
            return verify_findings(json.loads(report.read_text()), 'tree', result.returncode,
                                   lambda kind, commit, name: git_identity(kind, commit, name, root))
        if scan(): raise ValueError('Exact public fixture control failed')
        adjacent = fixture.parent / 'new-active-credential.key'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024',
                        '-out', str(adjacent)], check=True, capture_output=True)
        subprocess.run(['git', 'add', '.'], cwd=root, check=True)
        if not scan(): raise ValueError('Adjacent unapproved credential escaped scanning')
    print('REAL_SCANNER_ADJACENT_CREDENTIAL_REJECTED=PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--history-report', required=True)
    parser.add_argument('--tree-report', required=True)
    parser.add_argument('--history-status', type=int, required=True)
    parser.add_argument('--tree-status', type=int, required=True)
    parser.add_argument('--self-test-scanner', required=True)
    args = parser.parse_args()
    errors = []
    for kind in ('history', 'tree'):
        try:
            findings = json.loads(Path(getattr(args, kind + '_report')).read_text())
            failures = verify_findings(findings, kind, getattr(args, kind + '_status'))
            errors.extend(failures)
            print(f'{kind.upper()}_UNAPPROVED_FINDINGS={len(failures)}')
        except (OSError, ValueError): errors.append(kind + ' scanner report missing or malformed')
    if errors: raise SystemExit('\n'.join(errors))
    scanner_regression(args.self_test_scanner)
    print('Only exact immutable public synthetic fixtures classified; every other finding remains fatal')


if __name__ == '__main__': main()
