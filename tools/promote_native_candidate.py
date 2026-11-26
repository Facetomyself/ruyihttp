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
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile

from build_native import (NATIVE, PLATFORM_FILES, inspect_stable_wheel, load_manifest, sha256,
                          verify_linux_baseline_wheel, wheel_members, write_manifest)
from posix_firefox161 import GECKO_H3_SOURCES, H3_PROTOCOL_POLICY, validate_candidate
from stage_native_candidate import TARGETS


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def verify_wire_receipts(report, receipt_path, slot, package_version, entry):
    """Recompute stable fields and repeat proof against the same-slot official reference."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
    try:
        from firefox_wire import (MODES, REFERENCE_DIR, RELEASES, REPEAT_LIMIT, SCHEMA_VERSION,
                                  SLOTS, decode_json, load_reference)
    except ImportError as error:
        raise ValueError('Repeat-aware same-slot Firefox wire gate is required for admission') from error
    reference_path = REFERENCE_DIR / f'{slot}.json'
    reference_sha256 = sha256(reference_path)
    expected = load_reference(REFERENCE_DIR, slot)
    require(sha256(reference_path) == reference_sha256, 'Official reference changed during verification')
    platform, arch, _ = SLOTS[slot]
    version_numbers = {'h1': 11, 'h2': 20, 'h3': 30}
    receipts = receipt_path if isinstance(receipt_path, bytes) else receipt_path.read_bytes()
    lines = receipts.decode('utf-8').splitlines()
    require(lines == [line for line in report.splitlines() if line.startswith('{')],
            'Machine-readable wire receipts differ from the hosted qualification log')
    records = [decode_json(line) for line in lines]
    require(tuple(record['firefox'] for record in records) == RELEASES,
            'Expected one installed-wheel receipt series for each of 159, 160, 161')
    for record in records:
        release = record['firefox']
        require((record['schema_version'], record['source'], record['slot'], record['platform'], record['arch'],
                 record['package_version'], record['native_source'], record['nss'], record['neqo']) ==
                (SCHEMA_VERSION, 'installed-wheel', slot, platform, arch,
                 package_version, entry['firefox'], entry['nss'], entry['neqo']),
                f'Wrong installed-wheel receipt identity: Firefox {release}')
        repeats = record.get('repeats')
        require(isinstance(repeats, list) and len(repeats) < REPEAT_LIMIT and
                all(isinstance(sample, dict) and sample.keys() == {'wire', 'responses'} for sample in repeats),
                f'Missing or malformed wire repeat receipts: Firefox {release}')
        samples = [record, *repeats]
        wires = [sample['wire'] for sample in samples]
        policy = expected[release]
        proof = policy.repeat_proof(wires)
        require(proof['complete'] is True and record.get('repeat_proof') == proof,
                f'Missing or inconsistent fresh TLS permutation evidence: Firefox {release}')
        require(record['differences'] == {} and 'capture_error' not in record and 'repeat_capture_error' not in record and
                not policy.compare_receipt(wires[0], repeats),
                f'Official Firefox wire comparison did not pass: Firefox {release}')
        require(len({tuple(wire[protocol]['port'] for protocol in MODES) for wire in wires}) == len(wires),
                f'Repeated Firefox {release} receipts reuse the same origin set')
        for sample in samples:
            responses = sample['responses']
            require(responses.keys() == MODES.keys() | {'bootstrap'},
                    f'Incomplete Firefox {release} response witnesses')
            for role, response in responses.items():
                protocol = 'h1' if role == 'bootstrap' else role
                wire = sample['wire']['h3']['bootstrap'][0] if role == 'bootstrap' else sample['wire'][role]
                tls = response['tls']
                allowed_alpn = ('', 'http/1.1') if protocol == 'h1' else (protocol,)
                require(wire['mode'] == MODES[protocol] and
                        (response['status'], response['http_version']) == (200, version_numbers[protocol]) and
                        (tls['backend'], tls['nss'], tls['profile'], tls['version']) ==
                        ('NSS', entry['nss'], f'firefox-{release}', 0x0304) and tls['alpn'] in allowed_alpn,
                        f'Wrong Firefox {release} {role} installed-wheel context or TLS witness')
    return reference_sha256, digest(receipts).hexdigest()


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
    def run_artifact(prefix):
        required = f'{prefix}-{slot}-{run_id}-{attempt}'
        selected = [a for a in artifacts['artifacts'] if a['name'] == required]
        require(len(selected) == 1 and not selected[0]['expired'], f'{prefix} artifact missing or expired')
        item, = selected
        require((item['workflow_run']['id'], item['workflow_run']['head_sha']) == (run_id, run['head_sha']),
                f'{prefix} artifact belongs to a different run or commit')
        return item

    artifact = run_artifact('verified-native-wheel')
    evidence_artifact = run_artifact('native-evidence')
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
    manifest = load_manifest()
    version = manifest['version']
    measured = entry.get('linux_baseline_candidate')
    if measured is None and 'linux_baseline' in manifest['platforms'][slot]:
        raise ValueError('Historical source candidates must preserve the admitted Linux baseline')
    tag = measured['candidate_tag'] if measured else entry['wheel_platform_tag']
    require(re.fullmatch(r'\d+\.\d+\.\d+', version) and
            candidate['version'] == f'{version}.dev{run_id}+gha.{attempt}' and
            wheel.name == f'ruyihttp-{candidate["version"]}-py3-none-{tag}.whl',
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
    validate_candidate(slot, entry, provenance)
    source = read(evidence / 'source.json')
    require(source['donor'].split()[0] == provenance['ff_ruyijs_commit'] and
            source['donor_firefox_gitlink'] == provenance['ff_ruyijs_firefox_gitlink'] and
            source['firefox'].split()[0] == provenance['firefox_source_commit'] and
            source['firefox_release_tag'] == provenance['firefox_source_tag'] and
            source['neqo_commit'] == provenance['neqo_source_commit'] and
            source['nss_rs_commit'] == provenance['nss_rs_source_commit'], 'Unmatched source receipt')
    require(source.get('gecko_h3_sources') == GECKO_H3_SOURCES, 'Unmatched Gecko HTTP/3 preference evidence')
    lock = read(evidence / 'standalone-lock.json')
    require(lock['sha256'] == sha256(evidence / 'standalone-Cargo.lock') and
            lock['packages'] == source['mozilla_cargo_lock']['packages'],
            'Standalone vendor lock does not match Firefox sources')
    floor_proof = None
    audit = None
    if slot.startswith('linux_'):
        arch = TARGETS[slot][1]
        if measured:
            from linux_baseline import audit_record, verify_built_candidate
            from verify_linux_floor import (validate_evidence_archive, validate_wheel_archive, verify_floor)

            require(all((args.floor_run, args.floor_jobs, args.floor_artifacts, args.floor_cp310_zip,
                         args.floor_cp314_zip, args.native_evidence_zip, args.native_wheel_zip)),
                    'Linux baseline admission requires hosted modern and independent Bullseye artifact receipts')
            validate_evidence_archive(args.native_evidence_zip, evidence_artifact, evidence)
            validate_wheel_archive(args.native_wheel_zip, artifact, wheel)
            verify_linux_baseline_wheel(wheel, slot, entry, provenance)
            with TemporaryDirectory(prefix='ruyi-linux-promotion-') as scratch:
                native_bytes = Path(scratch)
                for name, data in actual_files.items():
                    (native_bytes / name).write_bytes(data)
                require(verify_built_candidate(slot, native_bytes, evidence) ==
                        (measured, provenance['linux_baseline_build'], provenance['linux_elf_preflight']),
                        'Staged source provenance differs from pinned Bullseye build evidence')
            audit = audit_record(slot, evidence)
            require(audit == read(evidence / 'linux-auditwheel.json') and audit['wheel_sha256'] == wheel_digest,
                    'auditwheel receipt differs from the measured candidate wheel')
            if source_id == run_id:
                floor_wheel = {'filename': wheel.name, 'version': candidate['version'], 'sha256': wheel_digest}
            else:
                source_version = f'{version}.dev{source_id}+gha.{source_attempt}'
                floor_wheel = {'filename': f'ruyihttp-{source_version}-py3-none-{tag}.whl', 'version': source_version,
                               'sha256': source_wheel['wheel_sha256']}
            floor_proof = verify_floor(*map(read, (args.floor_run, args.floor_jobs, args.floor_artifacts)),
                                       (args.floor_cp310_zip, args.floor_cp314_zip), slot,
                                       {'run': source_id, 'attempt': source_attempt}, floor_wheel,
                                       entry, verify_wire_receipts)
        else:
            report = (evidence / 'auditwheel.txt').read_text(encoding='utf-8')
            floor = re.search(r'following platform tag:\s+"manylinux_2_(\d+)_' + arch + r'"', report)
            require(provenance['highest_glibc_dynamic_requirement'] == entry['highest_glibc_dynamic_requirement'] and
                    floor and int(floor[1]) <= 39 and entry['wheel_platform_tag'] == f'manylinux_2_39_{arch}',
                    'Missing Linux candidate policy evidence')
    else:
        require(provenance['macho_minimum_macos'] == entry['macho_minimum_macos'] and
                provenance['minimum_macos'] == entry['minimum_macos'], 'Missing Mach-O deployment evidence')
    reference_hashes = set()
    wire_receipts = {}
    for endpoint in ('3.10', '3.14'):
        markers = {'http1': ['local smoke OK'],
                   'native-transactions': ['H3 binary body ABI: 1', 'h2 200 20', 'h3 200 30',
                                           f'NSS {entry["nss"]} NSPR {entry["nspr"]}'],
                   'firefox-profile-wire': [
                       f'{slot}: explicit 159/160/161 passed H1, H2 and UDP-only H3 against same-slot official Firefox'],
                   'posix-quic-policy': ['PASS: native POSIX QUIC policy',
                                         'v1-only peer without CONNECT: negotiated v1',
                                         'Missing h3_connect preference: id8 absent',
                                         'Shuffled profile keys: explicit receive windows'],
                   'full-h3': ['Ran 6 tests'], 'test_h3_body_abi': ['h3 body binary-v1: bytes=1048579'],
                   'upgrade-0.9.0': ['PASS: in-place 0.9.0 -> ', 'one distribution, native hashes, HTTP before and after']}
        for name, needles in markers.items():
            report = (evidence / endpoint / f'{name}.txt').read_text(encoding='utf-8')
            require(report.endswith('Exit status: 0\n') and all(needle in report for needle in needles),
                    f'Native qualification witness missing at CPython {endpoint}: {name}')
            if name == 'firefox-profile-wire':
                reference_hash, receipt_hash = verify_wire_receipts(
                    report, evidence / endpoint / 'firefox-profile-wire.jsonl', slot, candidate['version'], entry)
                reference_hashes.add(reference_hash)
                wire_receipts[endpoint] = receipt_hash
            if name == 'full-h3':
                require('skipped' not in report and '127.0.0.1' in report and '[::1]' in report,
                        f'IPv4/IPv6 H3 proof missing at CPython {endpoint}')
            if name == 'test_h3_body_abi':
                require(re.search(r'test_native_body_argument_bounds_and_thread_owner[^\n]*\.\.\. ok', report),
                        f'H3 ABI owner-thread proof missing at CPython {endpoint}')
    require(len(reference_hashes) == 1, 'Official reference changed during verification')
    reference_sha256, = reference_hashes
    require(load_manifest() == manifest, 'Local manifest changed during promotion verification')
    if floor_proof is not None:
        require(all(info['reference_sha256'] == reference_sha256 for info in floor_proof['endpoints'].values()),
                'Modern and Bullseye proofs used different official references')
        for record in (entry, provenance):
            record['linux_baseline'] = record.pop('linux_baseline_candidate')
            record['wheel_platform_tag'] = tag
        provenance.update(linux_floor_verification=floor_proof, linux_auditwheel=audit)
        provenance['source'] = 'Native Bullseye source build verified by independent installed-wheel runners'
    else:
        provenance['source'] = 'Native source build verified by an installed-wheel runner'
    provenance['native_verification'] = {
        'run': run['html_url'], 'job': job['html_url'], 'ruyihttp_commit': run['head_sha'],
        'wheel_artifact': f'{run["html_url"]}/artifacts/{artifact["id"]}', 'wheel_sha256': wheel_digest,
        'evidence_artifact': f'{run["html_url"]}/artifacts/{evidence_artifact["id"]}',
        'source_build_run': repo_url + str(source_id), 'source_build_attempt': source_attempt,
        'source_build_commit': source_sha,
        'cpython_runtime_endpoints': ['3.10', '3.14'], 'tested_http': ['http/1.1', 'h2', 'h3'], 'h3_body_abi': 1,
        'in_place_upgrade_from': '0.9.0', 'tested_firefox_profiles': ['159', '160', '161'],
        'h3_protocol_policy': H3_PROTOCOL_POLICY,
        'same_slot_firefox_reference_sha256': reference_sha256,
        'same_slot_firefox_wire_receipt_sha256': wire_receipts,
        'tested_quic_policy_profiles': ['144', '145', '154', '155', '159', '160', '161'],
    }
    validate_candidate(slot, entry, provenance)
    if args.check_only:
        print(f'Accepted proof for {slot} from {job["html_url"]}: {wheel.name}, SHA-256 {wheel_digest}')
        if floor_proof:
            print(f'Independent glibc {floor_proof["glibc"]} proof: {floor_proof["run"]}')
        return
    target = NATIVE / slot
    require(target.resolve(strict=True) == target and target.is_dir(), 'Unexpected promotion destination')
    for name in PLATFORM_FILES[slot]:
        require(not (target / name).is_symlink(), f'Symlink prevented promotion: {name}')
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
    parser.add_argument('--check-only', action='store_true', help='validate the proof without changing the native slot')
    for name in ('wheel', 'evidence', 'run', 'jobs', 'artifacts'):
        parser.add_argument(name, type=Path)
    for name in ('native-evidence-zip', 'native-wheel-zip', 'floor-run', 'floor-jobs', 'floor-artifacts',
                 'floor-cp310-zip', 'floor-cp314-zip'):
        parser.add_argument(f'--{name}', type=Path, help='original hosted receipt (required only for Linux 2.31)')
    try:
        promote(parser.parse_args())
    except (BadZipFile, KeyError, OSError, TypeError, ValueError) as error:
        parser.error(str(error))
