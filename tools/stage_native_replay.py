#!/usr/bin/env python3
"""Stage only native bytes from a prior hosted diagnostic artifact.

The replay is a fresh wheel build from the current Python checkout; the native
inventory must exactly match both the original wheel and its run evidence.
"""

import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from build_native import (NATIVE, inspect_stable_wheel, load_manifest, verify_linux_baseline_wheel,
                          wheel_members, write_manifest)
from posix_firefox161 import validate_candidate


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    slot, directory, evidence, source_run, source_attempt = sys.argv[1:]
    evidence = Path(evidence)
    wheel, = Path(directory).glob('*.whl')
    files, digest = inspect_stable_wheel(wheel, slot)
    index = read(evidence / 'wheel.json')
    assert index['wheel_sha256'] == digest and index['platform'] == slot
    actual = {name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in files.items()}
    assert actual == index['files']
    candidate = read(evidence / 'runtime-manifest.json')
    assert json.loads(wheel_members(wheel, ['runtime-manifest.json'])['runtime-manifest.json']) == candidate
    source_suffix = f'.dev{source_run}+gha.{source_attempt}'
    assert candidate['version'].endswith(source_suffix)
    original = load_manifest()
    entry = candidate['platforms'][slot]
    source_version = candidate['version'].removesuffix(source_suffix)
    measured = 'linux_baseline_candidate' in entry
    # Allow a prior historical policy-generation wheel only for historical replay.
    assert (source_version == original['version'] if measured else source_version in ('0.9.3', original['version']))
    assert entry['status'] == 'ready' and entry['h3_body_abi'] == 1
    assert entry['files'] == {name: information['sha256'] for name, information in actual.items()}
    baseline = original['platforms'][slot]
    assert baseline['status'] == 'build-required' and not baseline['files']
    provenance = read(evidence / 'provenance.json')
    assert provenance['platform'] == slot and provenance['files'] == actual
    validate_candidate(slot, entry, provenance)
    if measured:
        from linux_baseline import audit_record, verify_built_candidate

        verify_linux_baseline_wheel(wheel, slot, entry, provenance)
        assert audit_record(slot, evidence) == read(evidence / 'linux-auditwheel.json')
        with TemporaryDirectory(prefix='ruyi-linux-baseline-replay-') as scratch:
            verified = Path(scratch)
            for name, data in files.items():
                (verified / name).write_bytes(data)
            assert verify_built_candidate(slot, verified, evidence) == (
                entry['linux_baseline_candidate'], provenance['linux_baseline_build'], provenance['linux_elf_preflight'])
    target = NATIVE / slot
    assert target.resolve(strict=True) == target and target.is_dir()
    assert not any((target / name).exists() or (target / name).is_symlink() for name in files)
    for name, data in files.items():
        (target / name).write_bytes(data)
    (target / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    (target / 'SHA256SUMS').write_text(''.join(f'{sha}  {name}\n' for name, sha in entry['files'].items()), encoding='utf-8')
    original['platforms'][slot] = entry
    write_manifest(original)
    print(f'Staged {len(actual)} exact {slot} libraries from {wheel.name} sha256={digest}', flush=True)


if __name__ == '__main__':
    main()
