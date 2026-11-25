#!/usr/bin/env python3
"""Admit a source-built native set from a successful hosted qualification run.

Pass downloaded native-evidence and verified-native-wheel artifacts from that
run, plus the unmodified run/jobs/artifacts JSON from the GitHub Actions API.
This tool never loads the candidate, extracts arbitrary paths, or pushes Git.
"""

import argparse
from hashlib import sha256 as digest
import json
import re
from pathlib import Path

from build_native import (NATIVE, PLATFORM_FILES, ROOT, inspect_stable_wheel,
                          load_manifest, sha256, wheel_members, write_manifest)
from stage_native_candidate import TARGETS


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def promote(args):
    slot, evidence, wheel = args.platform, args.evidence, args.wheel
    run, jobs, artifacts = map(read, (args.run, args.jobs, args.artifacts))
    run_id, attempt = run['id'], run['run_attempt']
    repo_url = 'https://github.com/Facetomyself/ruyihttp/actions/runs/'
    require(run['html_url'] == repo_url + str(run_id), 'Unexpected source repository')
    require(run['path'].split('@', 1)[0] == '.github/workflows/native-arm64-intel.yml', 'Unexpected source workflow')
    matches = [job for job in jobs['jobs'] if job['name'] == slot and job['run_attempt'] == attempt]
    require(len(matches) == 1, 'Missing or ambiguous target job')
    job, = matches
    require(job['run_id'] == run_id and job['head_sha'] == run['head_sha'] and
            job['conclusion'] == 'success' and job['html_url'] == f'{run["html_url"]}/job/{job["id"]}',
            'Target job did not successfully qualify those bytes')
    required_artifact = f'verified-native-wheel-{slot}-{run_id}-{attempt}'
    artifacts = [a for a in artifacts['artifacts'] if a['name'] == required_artifact]
    require(len(artifacts) == 1 and not artifacts[0]['expired'], 'Verified wheel artifact missing or expired')
    artifact, = artifacts
    require(evidence.joinpath('runner.txt').read_text(encoding='utf-8').splitlines()[0] == run['head_sha'],
            'Evidence does not identify the qualifying commit')
    source_id, source_attempt, source_sha = run_id, attempt, run['head_sha']
    if (evidence / 'source-run.txt').is_file():
        source_id, source_attempt = map(int, (evidence / 'source-run.txt').read_text(encoding='utf-8').split())
        source_sha = (evidence / 'source-runner.txt').read_text(encoding='utf-8').splitlines()[0]
        require(source_id > 0 and source_attempt > 0 and re.fullmatch(r'[0-9a-f]{40}', source_sha),
                'Invalid source artifact replay identity')
    provenance = read(evidence / 'provenance.json')
    candidate = read(evidence / 'runtime-manifest.json')
    entry = candidate['platforms'][slot]
    require(provenance['platform'] == slot and entry['status'] == 'ready', 'Unexpected candidate slot')
    require(re.fullmatch(r'\d+\.\d+\.\d+', candidate['version'].split('.dev', 1)[0]) and
            candidate['version'].endswith(f'.dev{run_id}+gha.{attempt}') and
            wheel.name == f'ruyihttp-{candidate["version"]}-py3-none-{entry["wheel_platform_tag"]}.whl',
            'Candidate wheel version or platform does not match the qualifying run')
    actual_files, wheel_digest = inspect_stable_wheel(wheel, slot)
    wheel_index = read(evidence / 'wheel.json')
    require(wheel_digest == wheel_index['wheel_sha256'] and wheel_index['platform'] == slot,
            'Wheel digest differs from the qualifying run')
    require(json.loads(wheel_members(wheel, ['runtime-manifest.json'])['runtime-manifest.json']) == candidate and
            sha256(wheel) == wheel_digest, 'Wheel and evidence manifests differ')
    files = {name: {'size': len(data), 'sha256': digest(data).hexdigest()} for name, data in actual_files.items()}
    require(files == provenance['files'] == wheel_index['files'] and
            {name: info['sha256'] for name, info in files.items()} == entry['files'],
            'Native file inventory differs from the qualifying run')
    if source_id != run_id:
        source_wheel = read(evidence / 'source-wheel.json')
        require(source_wheel['platform'] == slot and source_wheel['files'] == files,
                'Replay differs from original native file inventory')
    require(entry['h3_tls'] == 'nss' and entry['h3_body_abi'] == 1, 'Required H3 capabilities missing')
    expected_patches = ['h3-body-abi-v1.patch']
    if slot.startswith('darwin_'):
        expected_patches.insert(0, 'macos-necko-quic-tls-info.patch')
        expected_patches.append('macos-h3-global-handles.patch')
    require([p['path'] for p in provenance['source_patches']] ==
            [f'native/patches/{name}' for name in expected_patches], 'Unexpected set of applied source patches')
    for patch in provenance['source_patches']:
        require(sha256(ROOT / patch['path']) == patch['sha256'], f'Patch bytes differ: {patch["path"]}')
    for endpoint in ('3.10', '3.14'):
        for name, needle in {'native-transactions': 'H3 binary body ABI: 1', 'full-h3': 'Ran 6 tests',
                             'test_h3_body_abi': 'h3 body binary-v1: bytes=1048579'}.items():
            report = (evidence / endpoint / f'{name}.txt').read_text(encoding='utf-8')
            require(report.endswith('Exit status: 0\n') and needle in report,
                    f'Native qualification witness missing at CPython {endpoint}: {name}')
            if name == 'full-h3':
                require('skipped' not in report and '127.0.0.1' in report and '[::1]' in report,
                        f'IPv4/IPv6 H3 proof missing at CPython {endpoint}')
            if name == 'test_h3_body_abi':
                require(re.search(r'test_native_body_argument_bounds_and_thread_owner[^\n]*\.\.\. ok', report),
                        f'H3 ABI owner-thread proof missing at CPython {endpoint}')
    manifest = load_manifest()
    original = manifest['platforms'][slot]
    require(all(original[key] == entry[key] for key in ('firefox', 'nss', 'nspr', 'neqo', 'h3_version_export')),
            'Unexpected change to baseline runtime expectations')
    target = NATIVE / slot
    require(target.resolve(strict=True) == target and target.is_dir(), 'Unexpected promotion destination')
    for name in PLATFORM_FILES[slot]:
        require(not (target / name).is_symlink(), f'Symlink prevented promotion: {name}')
    provenance['source'] = 'Native source build verified by an installed-wheel runner'
    provenance['native_verification'] = {
        'run': run['html_url'], 'job': job['html_url'], 'ruyihttp_commit': run['head_sha'],
        'wheel_artifact': f'{run["html_url"]}/artifacts/{artifact["id"]}', 'wheel_sha256': wheel_digest,
        'source_build_run': repo_url + str(source_id), 'source_build_attempt': source_attempt,
        'source_build_commit': source_sha,
        'cpython_runtime_endpoints': ['3.10', '3.14'], 'tested_http': ['http/1.1', 'h2', 'h3'], 'h3_body_abi': 1,
    }
    for name, data in actual_files.items():
        (target / name).write_bytes(data)
    (target / 'SHA256SUMS').write_text(''.join(f'{sha}  {name}\n' for name, sha in entry['files'].items()), encoding='utf-8')
    (target / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    manifest['platforms'][slot] = entry
    write_manifest(manifest)
    print(f'Admitted {slot} from {job["html_url"]}: {wheel.name}, SHA-256 {wheel_digest}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=TARGETS)
    for name in ('wheel', 'evidence', 'run', 'jobs', 'artifacts'):
        parser.add_argument(name, type=Path)
    try:
        promote(parser.parse_args())
    except (KeyError, OSError, ValueError) as error:
        parser.error(str(error))
