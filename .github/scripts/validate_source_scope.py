"""Documentation/contract validation only. Application source is denied by default."""
import hashlib
import json
import os
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml
from markdown_it import MarkdownIt

CI_FILES = {
    '.github/workflows/source-scope.yml',
    '.github/scripts/validate_source_scope.py',
    '.github/scripts/test_source_scope.py',
    '.github/scripts/test_frozen_vendor.py',
    '.github/source-scope.json',
    '.github/requirements-source-scope.txt',
    'governance/interim-release-policy.json',
}

# Independently reviewed pre-existing authority. No generic .github bootstrap.
LEGACY_GITHUB_AUTHORITY = {
    ('appolon1908/Codestra-Device-Forge', 'a1646d9504a10db42f19d4665c7801b625e41300'): {
        '.github/copilot-instructions.md': 'b377a31eb1f063ad7583864774218e579dbb9511',
    },
    ('appolon1908/Meltano-Leads-Importer', 'da2b43cb2c07830a3dfcdb8234fa9374e19e2e99'): {
        '.github/workflows/contracts.yml': 'ee15f158185b43f1eb4bf46c83e150a6b4a20b9c',
    },
}


FROZEN_VENDOR_BASES = {
    ('appolon1908/Codestra-Telemetry', '69b58c62545efb272cd5b29a1f1a501aabfca066'): 'e803ff82d2bcef8d84da5e05dc391cea59bbea11',
    ('appolon1908/Codestra-Redis-Exporter', '88ce80c34e35985ee118933cac344b6526aeba4e'): 'ceee2092a10fe8bc01cca6540e381f101edcf71f',
    ('appolon1908/Codestra-Blackbox-Exporter', 'c4353d18214b24e0406b8e597edb6b8276f6ccbf'): 'c1d1be4b72e3cb27f5cd53e1fca6656ebbd8ee8d',
    ('appolon1908/Codestra-cAdvisor', '53e1e388e961b48047296b69f8d3a747cb0703ec'): '921f9f06b251f12edcce5f82e2dabdddd876bb7d',
}

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate mapping key')
        result[key] = value
    return result


class UniqueLoader(yaml.SafeLoader):
    pass


# GitHub workflows use YAML 1.2: the `on` trigger key is a string, not True.
UniqueLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in entries
          if tag != 'tag:yaml.org,2002:bool']
    for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
UniqueLoader.add_implicit_resolver(
    'tag:yaml.org,2002:bool', re.compile(r'^(?:true|True|TRUE|false|False|FALSE)$'),
    list('tTfF'))


def unique_yaml(loader, node):
    if any(not isinstance(loader.construct_object(key, deep=True), str)
           for key, _ in node.value):
        raise ValueError('YAML mapping keys must be strings')
    return unique_pairs((loader.construct_object(key, deep=True),
                         loader.construct_object(value, deep=True))
                        for key, value in node.value)


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_yaml)


def structured(path, text):
    if path.endswith('.json'):
        return json.loads(text, object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    return yaml.load(text, Loader=UniqueLoader)


class HtmlLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ('href', 'src') and value:
                self.links.append(value)
            if key == 'id' or (tag == 'a' and key == 'name'):
                self.ids.append(value)


def markdown_info(text):
    tokens = MarkdownIt('commonmark', {'html': True}).parse(text)
    links, anchors, counts = [], set(), {}
    for index, token in enumerate(tokens):
        if token.type == 'heading_open':
            raw = tokens[index + 1].content
            raw = re.sub(r'<[^>]*>', '', raw).lower()
            slug = re.sub(r'[^\w\- ]', '', raw).replace(' ', '-')
            count = counts.get(slug, 0)
            counts[slug] = count + 1
            anchors.add(slug + (f'-{count}' if count else ''))
        for child in token.children or []:
            if child.type == 'link_open':
                links.append(child.attrGet('href'))
            elif child.type == 'image':
                links.append(child.attrGet('src'))
            elif child.type == 'html_inline':
                parser = HtmlLinks()
                parser.feed(child.content)
                links.extend(parser.links)
                anchors.update(parser.ids)
        if token.type == 'html_block':
            parser = HtmlLinks()
            parser.feed(token.content)
            links.extend(parser.links)
            anchors.update(parser.ids)
    return links, anchors


def validate_frozen_tree(entries, manifest):
    errors = []
    frozen = manifest.get('frozen_entries', {})
    for name, expected in frozen.items():
        if entries.get(name) != expected:
            errors.append(f'Frozen baseline path/blob/mode changed or removed: {name}')
    for name in entries:
        if any(name.startswith(prefix) for prefix in manifest.get('frozen_prefixes', [])) and name not in frozen:
            errors.append(f'New file in frozen vendor tree: {name}')
    return errors


def frozen_vendor_manifest(base, repository, bootstrap):
    reviewed_tree = FROZEN_VENDOR_BASES.get((repository, base))
    if base != bootstrap or reviewed_tree is None:
        raise ValueError('Unreviewed frozen-vendor repository/base')
    actual_tree = subprocess.check_output(['git', 'rev-parse', f'{base}^{{tree}}']).decode().strip()
    if actual_tree != reviewed_tree:
        raise ValueError('Frozen-vendor root tree differs from reviewed immutable tree')
    entries = {}
    raw = subprocess.check_output(['git', 'ls-tree', '-rz', '--full-tree', base]).decode()
    for entry in raw.split('\0'):
        if not entry:
            continue
        metadata, name = entry.split('\t', 1)
        mode, kind, blob = metadata.split()
        if kind != 'blob' or mode not in ('100644', '100755', '120000'):
            raise ValueError('Unreviewed baseline object type/mode')
        entries[name] = {'mode': mode, 'blob': blob}
    if 'AGENTS.md' not in entries or not any(name.startswith('upstream/') for name in entries):
        raise ValueError('Frozen-vendor baseline lacks authority or vendor tree')
    return {
        'schema_version': 1, 'repository': repository,
        'scope': 'frozen-vendor-documentation-additions-only', 'application_source_allowed': False,
        'reviewed_base_sha': base, 'reviewed_base_tree': reviewed_tree,
        'baseline_files': sorted(entries), 'frozen_entries': entries,
        'frozen_prefixes': ['upstream/'], 'authority_hashes': {}, 'required_text': {},
        'structured_files': {'governance/interim-release-policy.json': source_policy(repository)},
    }


def validate(root, tracked, manifest, trusted_manifest=None, tracked_blobs=None):
    errors, texts, markdown = [], {}, {}
    if trusted_manifest is not None:
        if json.dumps(manifest, sort_keys=True) != json.dumps(trusted_manifest, sort_keys=True):
            errors.append('Candidate scope manifest differs from trusted Git base; authority review required')
        manifest = trusted_manifest
    frozen = manifest.get('frozen_entries', {})
    if frozen:
        if tracked_blobs is None:
            return ['Missing trusted candidate Git blob/mode inventory']
        errors.extend(validate_frozen_tree(tracked_blobs, manifest))
        if errors:
            return errors  # Compare every immutable Git object before reading candidate files.
    root = root.resolve()
    allowed_structured = manifest.get('structured_files', {})
    for name, mode in tracked.items():
        if name in frozen:
            continue  # Frozen vendor/authority bytes are never executed or semantically reinterpreted.
        if frozen and name not in CI_FILES:
            doc_addition = (name == 'README.md' or (name.startswith('docs/') and name.endswith('.md')))
            if not doc_addition or Path(name).name in ('AGENTS.md', 'CLAUDE.md'):
                errors.append(f'Outside reviewed documentation-additions lane: {name}')
                continue
        path = root / name
        if mode != '100644' or path.is_symlink():
            errors.append(f'Forbidden executable/symlink/submodule: {name}')
            continue
        allowed = (name.endswith('.md') or name in CI_FILES or name == '.gitignore'
                   or name in allowed_structured)
        if not allowed:
            errors.append(f'Outside documentation/contract scope; product CI required: {name}')
            continue
        try:
            text = path.read_text(encoding='utf-8')
            if '\0' in text or (text.startswith('#!') and name not in CI_FILES):
                raise ValueError('binary or disguised executable')
            texts[name] = text
            if name.endswith('.md'):
                markdown[name] = markdown_info(text)
            elif name.endswith(('.json', '.yaml', '.yml')):
                structured(name, text)
        except (ValueError, OSError, yaml.YAMLError) as exc:
            errors.append(f'{name}: {exc}')
    for name in manifest.get('baseline_files', []):
        if name not in tracked:
            errors.append(f'Baseline authority/contract removed: {name}')
    for name, phrases in manifest.get('required_text', {}).items():
        for phrase in phrases:
            if phrase not in texts.get(name, ''):
                errors.append(f'Authority requirement missing: {name}')
    for name, expected in allowed_structured.items():
        try:
            if json.dumps(structured(name, texts[name]), sort_keys=True) != json.dumps(expected, sort_keys=True):
                errors.append(f'Contract semantics changed; explicit contract review required: {name}')
        except (KeyError, ValueError, yaml.YAMLError):
            errors.append(f'Contract missing or malformed: {name}')
    for name, digest in manifest.get('authority_hashes', {}).items():
        actual = hashlib.sha256(texts.get(name, '').encode()).hexdigest()
        if actual != digest:
            errors.append(f'Authority changed; explicit authority review required: {name}')
    for name, (links, _) in markdown.items():
        for link in links:
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                continue  # Public URLs are not fetched and cannot produce external effects.
            target = root / unquote(parsed.path.lstrip('/')) if parsed.path.startswith('/') else (root / name).parent / unquote(parsed.path)
            if not parsed.path:
                target = root / name
            target = target.resolve()
            if not target.is_relative_to(root):
                errors.append(f'Internal link escapes repository: {name}')
                continue
            relative = target.relative_to(root).as_posix()
            exists = relative in tracked or any(p.startswith(relative.rstrip('/') + '/') for p in tracked)
            if not exists:
                errors.append(f'Broken internal link in {name}')
            elif parsed.fragment and relative.endswith('.md'):
                if relative in frozen and frozen[relative]['mode'] == '100644':
                    # Immutable blob/mode and clean worktree were proven before any read.
                    anchors = markdown_info(target.read_text(encoding='utf-8'))[1]
                else:
                    anchors = markdown.get(relative, ([], set()))[1]
                if unquote(parsed.fragment) not in anchors:
                    errors.append(f'Broken heading link in {name}')
    return errors


def source_policy(repository):
    policy = {
        'schema_version': 1, 'policy_kind': 'source_merge', 'repository': repository,
        'authorization_date': '2026-11-02',
        'required_checks': [{'context': 'documentation-contract-source', 'integration_id': 15368,
                             'workflow': '.github/workflows/source-scope.yml'}],
        'replaces_contexts': ['codestra-control-plane', 'codestra/control-plane'],
        'preserve': ['other_required_checks', 'review_requirements', 'ref_conditions',
                     'bypass_actors', 'enforcement', 'force_push_protection',
                     'deletion_protection', 'deployment_authority'],
        'production_activation_authorized': False,
        'note': 'GitHub rulesets remain the enforcement authority. Documentation/contract-only validation denies application sources until vetted product CI is separately reviewed; it does not certify runtime or authorize deployment.',
    }
    if repository in {repo for repo, _ in FROZEN_VENDOR_BASES}:
        policy['required_checks'][0]['context'] = 'frozen-vendor-documentation-source'
        policy['note'] = 'Only documentation additions outside the frozen baseline are validated. Every original vendor, config, lock and authority Git blob/mode remains immutable. This does not certify vendor code, runtime or vendor security and does not authorize deployment.'
    if repository == 'appolon1908/Meltano-Leads-Importer':
        policy['required_checks'].append({
            'context': 'validate', 'integration_id': 15368,
            'workflow': '.github/workflows/contracts.yml',
        })
    return policy


def trusted_from_git(base, repository, bootstrap):
    """Never derive authority from candidate-supplied expected values."""
    if not re.fullmatch('[a-f0-9]{40}', base):
        raise ValueError('Missing/invalid trusted event base SHA')
    existing = subprocess.run(['git', 'show', f'{base}:.github/source-scope.json'],
                              capture_output=True, check=False)
    if existing.returncode == 0:
        # Existing authority is immutable in the ordinary documentation lane.
        changed = subprocess.check_output(['git', 'diff', '--name-only', base, '--',
                                           '.github', 'governance/interim-release-policy.json'])
        if changed.strip():
            raise ValueError('CI/scope authority changed; independent authority-review lane required')
        return json.loads(existing.stdout)
    if base != bootstrap or not re.fullmatch('[a-f0-9]{40}', bootstrap):
        raise ValueError('Unrecognized bootstrap base; no permissive fallback')
    if (repository, base) in FROZEN_VENDOR_BASES:
        return frozen_vendor_manifest(base, repository, bootstrap)
    raw = subprocess.check_output(['git', 'ls-tree', '-rz', '--full-tree', base]).decode()
    documents = {}
    for entry in raw.split('\0'):
        if not entry:
            continue
        metadata, name = entry.split('\t', 1)
        mode, kind, blob = metadata.split()
        if mode != '100644' or kind != 'blob':
            raise ValueError('Bootstrap base has executable/symlink/submodule')
        if not (name.endswith(('.md', '.json', '.yaml', '.yml')) or name == '.gitignore'):
            raise ValueError('Bootstrap base is not documentation/contract-only')
        if name.startswith('.github/'):
            reviewed = LEGACY_GITHUB_AUTHORITY.get((repository, base), {})
            if reviewed.get(name) != blob:
                raise ValueError('Bootstrap base already has unreviewed CI authority')
        documents[name] = subprocess.check_output(['git', 'show', f'{base}:{name}']).decode().replace('\r\n', '\n')
    if 'AGENTS.md' not in documents or not documents:
        raise ValueError('Bootstrap base lacks reviewed repository authority')
    expected = {
        'schema_version': 1, 'repository': repository,
        'scope': 'documentation-contract-only', 'application_source_allowed': False,
        'baseline_files': sorted(documents),
        'authority_hashes': {name: hashlib.sha256(text.encode()).hexdigest()
                             for name, text in documents.items()
                             if name.startswith('.github/') or name in ('AGENTS.md', 'ARCHITECTURE.md', '.codestra/MIDDLEWARE-INTEGRATION-CONTRACT.md')},
        'required_text': {},
        'structured_files': {name: structured(name, text) for name, text in documents.items()
                             if name.endswith(('.json', '.yaml', '.yml'))},
    }
    expected['structured_files']['governance/interim-release-policy.json'] = source_policy(repository)
    return expected


def main():
    root = Path.cwd()
    raw = subprocess.check_output(['git', 'ls-files', '--stage', '-z']).decode()
    tracked = {}
    tracked_blobs = {}
    subprocess.run(['git', 'diff', '--exit-code'], check=True)
    for entry in raw.split('\0'):
        if entry:
            metadata, name = entry.split('\t', 1)
            mode, blob, stage = metadata.split()
            if stage != '0':
                raise SystemExit('Unmerged index rejected')
            tracked[name] = mode
            tracked_blobs[name] = {'mode': mode, 'blob': blob}
    manifest = json.loads(Path('.github/source-scope.json').read_text())
    trusted = trusted_from_git(os.environ.get('BASE_SHA', ''), os.environ['GITHUB_REPOSITORY'],
                               os.environ.get('BOOTSTRAP_BASE_SHA', ''))
    errors = validate(root, tracked, manifest, trusted_manifest=trusted, tracked_blobs=tracked_blobs)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        raise SystemExit(1)
    print('Documentation/contract scope PASS; application and runtime certification NOT granted')


if __name__ == '__main__':
    main()
