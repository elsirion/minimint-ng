#!/usr/bin/env python3
"""Compare locked identities; never fetch or inspect implementation sources."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'vendor-metadata/fedimint-Cargo.lock'


def read_baseline():
    raw = BASELINE.read_bytes()
    provenance = json.loads((ROOT / 'vendor-metadata/provenance.json').read_text())
    if hashlib.sha256(raw).hexdigest() != provenance['sha256']:
        raise ValueError('baseline lockfile digest differs from recorded provenance')
    return raw.decode(), tomllib.loads(raw.decode())['package']


def identity(package):
    return package['name'], package['version'], package.get('source')


def closure(packages):
    selected = {}
    roots = [p for p in packages if p['name'] == 'fedimint-aleph-bft' and p['version'] == '0.36.0']
    if len(roots) != 1:
        raise ValueError('expected exactly one fedimint-aleph-bft 0.36.0 lock entry')
    todo = roots
    while todo:
        p = todo.pop()
        if identity(p) in selected:
            continue
        selected[identity(p)] = p
        for dependency in p.get('dependencies', []):
            parts = dependency.split(' ', 2)
            matches = [q for q in packages if q['name'] == parts[0]
                       and (len(parts) < 2 or q['version'] == parts[1])
                       and (len(parts) < 3 or q.get('source') == parts[2].strip('()'))]
            if len(matches) != 1:
                raise ValueError(f'ambiguous or missing baseline dependency: {dependency}')
            todo.extend(matches)
    return selected


def seed():
    raw, packages = read_baseline()
    selected = closure(packages)
    chunks = []
    for block in re.split(r'(?m)^\[\[package\]\]\n', raw)[1:]:
        package = tomllib.loads('[[package]]\n' + block)['package'][0]
        if identity(package) in selected:
            chunks.append('[[package]]\n' + block.strip() + '\n')
    root = '[[package]]\nname = "minimint-ng"\nversion = "0.1.0"\ndependencies = ["fedimint-aleph-bft"]\n'
    destination = ROOT / 'Cargo.lock'
    if destination.exists():
        raise ValueError('refusing to overwrite existing Cargo.lock; seed is for initial bootstrap only')
    destination.write_text('# Generated from the pinned baseline agreement closure.\nversion = 4\n\n' + '\n'.join(chunks) + '\n' + root)
    print(f'Seeded {len(selected)} exact agreement dependency identities')


def manifest_errors(actual):
    manifest = tomllib.loads((ROOT / 'Cargo.toml').read_text())
    expected = {'version': '=0.36.0', 'default-features': False}
    errors = []
    if manifest.get('dependencies', {}).get('fedimint-aleph-bft') != expected:
        errors.append('manifest must pin engine =0.36.0 with defaults off and no extra features/overrides')
    for feature_values in manifest.get('features', {}).values():
        if any(v.startswith(('fedimint-aleph-bft/', 'fedimint-aleph-bft?/', 'dep:fedimint-aleph-bft')) for v in feature_values):
            errors.append('forwarding agreement features requires explicit review')

    def inspect_tables(table, path=()):
        for name, value in table.items():
            if name in {'dependencies', 'dev-dependencies', 'build-dependencies'}:
                for alias, declaration in value.items():
                    package = declaration.get('package', alias) if isinstance(declaration, dict) else alias
                    if package.startswith('fedimint-') and not (path == () and name == 'dependencies' and alias == package == 'fedimint-aleph-bft'):
                        errors.append(f'unapproved Fedimint dependency location/alias: {path + (name, alias)}')
            elif isinstance(value, dict):
                inspect_tables(value, path + (name,))
    inspect_tables(manifest)
    if manifest.get('patch') or manifest.get('replace'):
        errors.append('manifest source patches/replacements need explicit review')
    root = next((p for p in actual if p['name'] == 'minimint-ng' and p.get('source') is None), None)
    if root is None or not any(d.split()[0] == 'fedimint-aleph-bft' for d in root.get('dependencies', [])):
        errors.append('root lock entry does not depend on approved engine')
    return errors


def check(metadata_path=None):
    _, baseline = read_baseline()
    required = closure(baseline)
    actual = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
    errors = manifest_errors(actual)
    # Cargo prunes baseline features not used by this binary (e.g. WASM/Serde).
    # Every actually reachable agreement identity must match the baseline.
    active = closure(actual)
    review_path = ROOT / 'vendor-metadata/reviewed-extra-versions.json'
    reviews = json.loads(review_path.read_text()) if review_path.exists() else []
    reviewed = {identity(p): p for p in reviews}
    for key, package in active.items():
        if key not in required:
            errors.append(f'agreement dependency outside baseline: {key}')
        elif package.get('checksum') != required[key].get('checksum'):
            errors.append(f'checksum differs for {key}')
    names = {p['name'] for p in baseline}
    report = []
    metadata = json.loads(Path(metadata_path).read_text()) if metadata_path else None
    metadata_packages = {(p['name'], p['version'], p.get('source')): p for p in metadata['packages']} if metadata else {}
    metadata_features = {n['id']: n['features'] for n in metadata['resolve']['nodes']} if metadata else {}
    for p in actual:
        if p['name'] == 'minimint-ng':
            continue
        key = identity(p)
        category = 'required-agreement' if key in required else 'shared-other' if p['name'] in names else 'distinct-name'
        report.append({'name': p['name'], 'version': p['version'], 'source': p.get('source'),
                       'checksum': p.get('checksum'), 'overlap': category})
        if metadata:
            details = metadata_packages.get(key)
            if details is None:
                errors.append(f'package missing from supplied Cargo metadata: {key}')
            else:
                kinds = {kind for target in details['targets'] for kind in target['kind']}
                report[-1].update({'build_script': 'custom-build' in kinds,
                                   'procedural_macro': 'proc-macro' in kinds,
                                   'features': metadata_features.get(details['id'], [])})
        if p['name'] in {k[0] for k in required} and key not in required:
            approval = reviewed.get(key)
            # An exception can permit an unrelated library's parallel version,
            # never an upgrade inside the mandatory agreement closure.
            if (key in active or not approval or not approval.get('reason')
                    or approval.get('checksum') != p.get('checksum')):
                errors.append(f'extra version of agreement dependency needs review: {key}')
    print(json.dumps({'baseline_sha256': hashlib.sha256(BASELINE.read_bytes()).hexdigest(),
                      'packages': report, 'errors': errors}, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['seed', 'check'])
    parser.add_argument('--metadata', help='Cargo metadata JSON for features/build-execution inventory; no source inspected')
    args = parser.parse_args()
    seed() if args.action == 'seed' else check(args.metadata)
