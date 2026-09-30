#!/usr/bin/env python3
"""Preserve public survivor evidence after a joined restart acknowledgement.

Only the explicitly listed driver observations and harness public records are
copied. The sole RPC operation retrieves a known confirmed block, read-only.
No driver state, tokens, client databases, credentials, or setup codes are copied.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess

CLI = pathlib.Path('/tmp/minimint-bitcoin-31.1/bitcoin-31.1/bin/bitcoin-cli')
CLI_SHA = '4e3a0fde23ec768a61cdd193602be937b29b6e8f21bcb614af87a2786bf86034'
LOADER = '/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/ld-linux-x86-64.so.2'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preserve(evidence, case, destination, datadir):
    assert 0 <= case < 4
    stop, restart = 2 * case, 2 * case + 1
    marker = json.loads((evidence / f'survivor-case-{case}-public.json').read_text())
    ack = json.loads((evidence / f'guardian-ack-{restart}.json').read_text())
    assert marker['peer'] == case and ack['peer'] == case
    assert ack['id'] == restart and ack['action'] == 'restart' and ack['exit'] is None
    target = destination / f'case{case}'
    target.mkdir(parents=True, exist_ok=False)

    def copy(source, name):
        assert source.is_file() and not source.is_symlink()
        shutil.copyfile(source, target / name)

    def observation(label):
        candidates = list((evidence / 'driver-private').glob('*-' + label + '.stdout'))
        assert len(candidates) == 1, label
        return candidates[0]

    for name in ['peer0-client_config.json', 'artifacts.json', 'federation_id.json']:
        source = evidence / name
        existing = destination / name
        if existing.exists():
            assert existing.read_bytes() == source.read_bytes(), 'mixed fixture federation'
        else:
            shutil.copyfile(source, existing)
    copy(evidence / f'survivor-case-{case}-public.json', 'marker.json')
    copy(evidence / f'guardian-ack-{stop}.json', 'stop-ack.json')
    copy(evidence / f'guardian-ack-{restart}.json', 'restart-ack.json')
    survivor = next(peer for peer in range(4) if peer != case)
    before = f'guardian-control{restart}-before-restart'
    after = f'guardian-control{restart}-after-restart'
    count = ack['completed_count']
    assert type(count) is int and 0 < count <= 1024
    for index in range(count):
        for peer in range(4):
            if peer != case:
                copy(evidence / f'{before}-peer{peer}-signed-session{index}.json',
                     f'before-peer{peer}-signed-session{index}.json')
            copy(evidence / f'{after}-peer{peer}-signed-session{index}.json',
                 f'after-peer{peer}-signed-session{index}.json')
    copy(evidence / f'guardian-control{stop}-before-stop-peer{case}-money.json', 'before-stop-money.json')
    copy(evidence / f'{before}-peer{survivor}-money.json', 'before-restart-money.json')
    for peer in range(4):
        copy(evidence / f'{after}-peer{peer}-money.json', f'after-restart-peer{peer}-money.json')
    for label, suffix in [('withdrawal', 'target'), ('reissue', 'reissue-target')]:
        pointer_path = evidence / f'{before}-peer{survivor}-{suffix}.json'
        pointer = json.loads(pointer_path.read_text())
        copy(pointer_path, label + '-target.json')
        copy(evidence / f'{before}-peer{survivor}-signed-session{pointer["session"]}.json', label + '-history.json')
        copy(evidence / f'guardian-control{restart}-peer{case}-{label}-signature-shares.json', label + '-restored-shares.json')
    for label, observation_label in [('parent', f'survivor-{case}-confirmed-parent'), ('withdrawal', f'survivor-{case}-confirmed-child')]:
        source = observation(observation_label)
        transaction = json.loads(source.read_text())
        copy(source, label + '-decoded.json')
        (target / (label + '.hex')).write_text(transaction['hex'] + '\n')
    copy(observation(f'survivor-{case}-child-entry'), 'withdrawal-mempool.json')
    assert digest(CLI) == CLI_SHA, 'verified Core CLI required'
    block_hash = marker['block_hash']
    assert len(block_hash) == 64 and all(c in '0123456789abcdef' for c in block_hash)
    base = [LOADER, str(CLI), '-datadir=' + str(datadir), '-rpcclienttimeout=10']
    for verbosity, name in [('0', 'confirmed-block.hex'), ('2', 'confirmed-block.json')]:
        result = subprocess.run(base + ['getblock', block_hash, verbosity], capture_output=True, timeout=15)
        assert result.returncode == 0, 'read-only confirmed-block lookup'
        (target / name).write_bytes(result.stdout)
    (target / 'README.md').write_text(
        f'# Monetary survivor case {case}\n\n'
        'Public records retained after the guardian stop/join, fresh reissuance and withdrawal, '
        'Core confirmation, and restart/catch-up acknowledgements. Driver assertion files are '
        'not themselves proof: the dedicated offline test verifies certificates, witness signer '
        'identities, monetary amounts, and restored guardian signing shares. The block RPC capture '
        'is subsequent read-only retrieval; the transaction/mempool observations retain their '
        'original capture times. No tokens, private nonce keys, client databases or credentials '
        'are copied.\n')
    manifest = {'case': case, 'source_evidence_directory': str(evidence),
                'sha256': {p.name: digest(p) for p in sorted(target.iterdir())}}
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    manifest = {'source_evidence_directory': str(evidence),
                'sha256': {str(p.relative_to(destination)): digest(p)
                           for p in sorted(destination.rglob('*'))
                           if p.is_file() and p != destination / 'manifest.json'}}
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Preserved public survivor case', case, 'at', target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=pathlib.Path, required=True)
    parser.add_argument('--case', type=int, choices=range(4), required=True)
    parser.add_argument('--destination', type=pathlib.Path,
                        default=pathlib.Path('tests/fixtures/interop/mixed-monetary-survivors-2026-09-11'))
    parser.add_argument('--core-datadir', type=pathlib.Path,
                        default=pathlib.Path('/tmp/minimint-bitcoin-31.1/regtest-smoke'))
    args = parser.parse_args()
    preserve(args.evidence, args.case, args.destination, args.core_datadir)
