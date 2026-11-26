#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Validate a downloaded run artifact against GitHub metadata before admitting its slot."""

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

from firefox_reference_capture import validate
from firefox_reference_releases import PINS, SLOTS, expect, sha256
from firefox_reference_wire import grease_settings


def admit(slot, run, artifact, jobs, archive, destination):
    ident = run['id']
    attempt = run['run_attempt']
    head = run['head_sha']
    expect(artifact['name'] == f'official-firefox-wire-{slot}-{ident}-{attempt}', 'artifact name does not identify this slot/run')
    expect(artifact['digest'] == f'sha256:{sha256(archive)}', 'GitHub artifact ZIP digest mismatch')
    matching = [job for job in jobs if job['name'].endswith(f'capture / {slot}')]
    expect(len(matching) == 1 and matching[0]['conclusion'] == 'success', 'slot job did not qualify')
    job = matching[0]
    with zipfile.ZipFile(archive) as files:
        members = [info for info in files.infolist() if info.filename == f'{slot}.json']
        expect(len(members) == 1 and members[0].file_size <= 2_000_000, 'archive has no unique, bounded assembled slot')
        raw = files.read(members[0])
    observed = json.loads(raw)
    os_name, arch, _, index = SLOTS[slot]
    expected = {'schema_version': 1, 'slot': slot, 'platform': os_name, 'arch': arch, 'source': 'official-firefox'}
    expect(all(observed.get(key) == value for key, value in expected.items()), 'unexpected capture schema/native slot')
    ci = observed['ci']
    expect(ci['sha'] == head and int(ci['run_id']) == ident and int(ci['run_attempt']) == attempt, 'embedded run identity differs')
    captures = observed['captures']
    expect(set(captures) == PINS.keys(), 'reference is missing a pinned release')
    for release, acq in captures.items():
        expect(acq['version'] == f'{release}.0' and acq['archive_locale'] == 'en-US' and
               acq['sha256'] == PINS[release][index] and acq['source_commit'] == PINS[release][1], 'release pin mismatch')
        expect(2 <= len(acq['samples']) <= 3, 'expected two or three fresh samples')
        ports = set()
        for sample in acq['samples']:
            expect(set(sample) == {'h1', 'h2', 'h3'}, 'capture has missing wire contexts')
            for case, record in sample.items():
                expect(record['process']['native'] == arch, 'process architecture mismatch')
                expect(record['port'] not in ports, 'sample reused a protocol origin')
                ports.add(record['port'])
                validate(case, record, release)
            h3 = sample['h3']
            expect(h3['grease_settings'] == grease_settings(h3['settings']), 'H3 GREASE positions are inconsistent')
            expect(h3['initial']['transport_parameter_ids'] and h3['initial']['udp_payload_bytes'] >= 1200,
                   'missing first QUIC Initial metadata')
    # The repository's JSON files are LF; a Windows runner may have emitted
    # CRLF before LF writing was explicit. Retain the exact raw artifact hash.
    canonical = raw.replace(b'\r\n', b'\n')
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / f'{slot}.json'
    if path.exists():
        expect(path.read_bytes() == canonical, 'different fixture already exists; retain the original before replacing')
    else:
        with path.open('xb') as file:
            file.write(canonical)
    return {'slot': slot, 'run_id': ident, 'run_attempt': attempt, 'run_head_sha': head, 'run_url': run['html_url'],
            'job_id': job['id'], 'job_url': job['html_url'], 'artifact_id': artifact['id'],
            'artifact_digest': artifact['digest'], 'artifact_member_digest': f'sha256:{hashlib.sha256(raw).hexdigest()}',
            'fixture_digest': f'sha256:{hashlib.sha256(canonical).hexdigest()}'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('slot', choices=SLOTS)
    parser.add_argument('run_metadata', type=Path)
    parser.add_argument('jobs_metadata', type=Path)
    parser.add_argument('artifacts_metadata', type=Path)
    parser.add_argument('artifact_id', type=int)
    parser.add_argument('zip', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    run = json.loads(args.run_metadata.read_text(encoding='utf-8'))
    jobs = json.loads(args.jobs_metadata.read_text(encoding='utf-8'))
    artifacts = json.loads(args.artifacts_metadata.read_text(encoding='utf-8'))
    if isinstance(jobs, dict):
        jobs = jobs['jobs']
    if isinstance(artifacts, dict):
        artifacts = artifacts['artifacts']
    matches = [item for item in artifacts if item['id'] == args.artifact_id]
    expect(len(matches) == 1, 'missing artifact ID in run listing')
    print(json.dumps(admit(args.slot, run, matches[0], jobs, args.zip, args.destination), indent=2))


if __name__ == '__main__':
    main()
