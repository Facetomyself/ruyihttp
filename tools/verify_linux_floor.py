#!/usr/bin/env python3
"""Verify independent hosted Bullseye receipts against exact wheel and native bytes."""
from contextlib import contextmanager
import json
from pathlib import PurePosixPath
import re
import stat
from zipfile import ZipFile

from build_native import bound_zip, sha256

RUNS = 'https://github.com/Facetomyself/ruyihttp/actions/runs/'
# Official Python Bullseye OCI manifests pinned by ci/linux_floor/run.sh.
PYTHON_INDEX = 'sha256:65c6bdcca22db1a3468a0262ae05f38a0a718f51e9818cd09c12094aaae28a33'
PYTHON_MANIFEST = {
    'linux_x86_64': 'sha256:4e96d6c7c610e5b2a46ff8a36cc76a159d57a5b865d580eda29d51afdc1a1923',
    'linux_aarch64': 'sha256:7f7a235298401ed56b486968fbb19049fda940005e114ad917e0e60362c93342',
}
ENDPOINTS = ('3.10', '3.14')
REQUIRED_GATES = {
    'installed-identity', 'http1', 'native-h2-h3', 'posix-quic-policy', 'profile-reference',
    'profile-wire', 'h2-preface', 'test_http3_native', 'test_h3_body_abi', 'test_alt_svc_native',
    'proxy-chain', 'h2-eof', 'request-boundaries',
}
OLD = {
    'linux_x86_64': '056729152736a3de16786cf466c290068c257a8e3771206db78314e468188b5b',
    'linux_aarch64': 'e0c7bdd60435f5f88619630428f6aa972b6c30a1d56baaa1ee7326861c5ed946',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def artifact_for(run, catalog, name):
    matches = [item for item in catalog['artifacts'] if item['name'] == name]
    require(len(matches) == 1, f'Missing or ambiguous Actions artifact {name}')
    item, = matches
    workflow_run = item['workflow_run']
    require(not item['expired'] and (workflow_run['id'], workflow_run['head_sha']) == (run['id'], run['head_sha']),
            f'Unexpected source run for Actions artifact {name}')
    return item


@contextmanager
def verified_artifact(path, item):
    expected_size = item['size_in_bytes']
    require(22 <= expected_size <= 256 * 1024**2 and path.is_file() and not path.is_symlink() and
            path.stat().st_size == expected_size and f'sha256:{sha256(path)}' == item['digest'],
            f'Actions artifact ZIP digest differs from hosted API: {item["name"]}')
    with path.open('rb') as stream:
        bound_zip(stream)
        with ZipFile(stream) as archive:
            names = set()
            for row in archive.infolist():
                name = PurePosixPath(row.filename)
                require(not name.is_absolute() and '..' not in name.parts and '\\' not in row.filename and
                        row.orig_filename == name.as_posix() and row.filename not in names and
                        not row.is_dir() and 0 <= row.file_size <= 32 * 1024**2 and
                        stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG) and not row.flag_bits & 1,
                        f'Unsafe or ambiguous Actions artifact ZIP member: {row.filename}')
                names.add(row.filename)
            require(sum(row.file_size for row in archive.infolist()) <= 64 * 1024**2,
                    'Actions evidence ZIP exceeds its uncompressed size budget')
            yield archive
    require(f'sha256:{sha256(path)}' == item['digest'], 'Actions artifact ZIP changed during verification')


def validate_evidence_archive(path, item, directory):
    with verified_artifact(path, item) as archive:
        files = {p.relative_to(directory).as_posix(): p for p in directory.rglob('*') if p.is_file()}
        require(files.keys() == set(archive.namelist()), 'Downloaded native evidence inventory differs from hosted archive')
        require(all(not p.is_symlink() and archive.read(name) == p.read_bytes() for name, p in files.items()),
                'Downloaded native evidence bytes differ from hosted archive')


def validate_wheel_archive(path, item, wheel):
    with verified_artifact(path, item) as archive:
        require(archive.namelist() == [wheel.name] and archive.read(wheel.name) == wheel.read_bytes(),
                'Downloaded native wheel differs from hosted archive')


def verify_floor(run, jobs, artifacts, archives, slot, source, wheel, entry, verify_wire):
    """Bind exact native bytes to two independent same-architecture CPython tests."""
    from linux_baseline import ARCHES, FLOOR

    run_id, attempt, commit = run['id'], run['run_attempt'], run['head_sha']
    workflow = run['path'].split('@', 1)[0]
    require(run['html_url'] == RUNS + str(run_id) and re.fullmatch(r'[0-9a-f]{40}', commit) and
            run['status'] == 'completed' and run_id != source['run'] and
            workflow in ('.github/workflows/linux-minimum.yml', '.github/workflows/ci.yml'),
            'Expected a separate hosted Linux floor workflow run')
    if workflow == '.github/workflows/ci.yml':
        require(run['event'] == 'workflow_dispatch' and run['head_branch'].startswith('transport/masque231-'),
                'The branch-only floor dispatch shim must be a manual candidate run')
    arch = slot.removeprefix('linux_')
    runner = 'ubuntu-24.04-arm' if arch == 'aarch64' else 'ubuntu-24.04'
    docker_platform = f'linux/{ARCHES[slot]}'
    endpoints = {}
    for endpoint, path in zip(ENDPOINTS, archives, strict=True):
        name = f'glibc 2.31 / {slot} / CPython {endpoint}'
        names = {name, f'floor / {name}'}
        matches = [j for j in jobs['jobs'] if j['name'] in names and j['run_attempt'] == attempt]
        require(len(matches) == 1, f'Missing or ambiguous Bullseye job: {name}')
        job, = matches
        require(job['run_id'] == run_id and job['head_sha'] == commit and job['conclusion'] == 'success' and
                runner in job['labels'] and job['html_url'] == f'{run["html_url"]}/job/{job["id"]}',
                f'The hosted Bullseye job did not pass on the expected native runner: {name}')
        item = artifact_for(run, artifacts, f'glibc231-{slot}-cp{endpoint}-{run_id}-{attempt}')
        with verified_artifact(path, item) as archive:
            def data(name):
                return archive.read(f'{endpoint}/{name}')

            summary = json.loads(data('summary.json'))
            image = json.loads(data('image.json'))
            require(summary['container'] == image and image['qualification_commit'] == commit and
                    (image['run_id'], image['attempt'], image['endpoint']) == (str(run_id), str(attempt), endpoint) and
                    (image['producer_run_id'], image['producer_attempt'], image['artifact_kind']) ==
                    (str(source['run']), str(source['attempt']), 'source-native-wheel') and
                    image['index'] == PYTHON_INDEX and image['base_manifest'] == PYTHON_MANIFEST[slot] and
                    image['docker_platform'] == docker_platform and re.fullmatch(r'sha256:[0-9a-f]{64}', image['image_id']),
                    f'Bullseye image or input artifact identity differs at CPython {endpoint}')
            require(summary['slot'] == slot and summary['arch'] == arch and summary['mode'] == 'candidate' and
                    summary['glibc'] == f'glibc {FLOOR}' and summary['network'] == 'loopback-only' and
                    re.fullmatch(re.escape(endpoint) + r'\.\d+', summary['python']) and
                    summary['site_packages'].startswith('/state/venv/') and summary['site_packages'].endswith('/site-packages/ruyihttp') and
                    summary['debian_packages']['libc6'].startswith('2.31-') and
                    summary['system_cxx_ceilings'] == {'GLIBCXX': '3.4.28', 'CXXABI': '1.3.12'},
                    f'Wrong native Bullseye runtime environment at CPython {endpoint}')
            policy = {'kind': 'linux_baseline_candidate', 'manifest_tag': entry['wheel_platform_tag'],
                      **entry['linux_baseline_candidate']}
            require(summary['wheel'] == wheel and summary['native_sha256'] == entry['files'] and
                    summary['native_policy'] == policy and
                    summary['highest_glibc_dynamic_requirement'] == entry['highest_glibc_dynamic_requirement'] and
                    summary['native_loader_paths'].keys() == entry['files'].keys() and
                    summary['native_required_abi_maxima'].keys() == entry['files'].keys(),
                    f'Bullseye runner consumed different wheel or native bytes at CPython {endpoint}')
            require(summary['base_dependencies']['ruyihttp']['sha256'] == wheel['sha256'] and
                    summary['negative_093'] == {'wheel': f'ruyihttp-0.9.3-py3-none-manylinux_2_39_{arch}.whl',
                                                'sha256': OLD[slot], 'commit': 'e8f8b02703239a18a75760d791c15936af632c40',
                                                'pip_rejected': True} and
                    REQUIRED_GATES.issubset(summary['gates']),
                    f'Missing installation, old wheel rejection or runtime sweeps at CPython {endpoint}')
            for file, markers in {
                'installed-identity.txt': ('14 native hashes verified', 'native provenance match'),
                'http1.txt': ('local smoke OK',),
                'native-h2-h3.txt': ('H3 binary body ABI: 1', 'h2 200 20', 'h3 200 30',
                                     f'NSS {entry["nss"]} NSPR {entry["nspr"]}'),
                'posix-quic-policy.txt': ('PASS: native POSIX QUIC policy', 'Missing h3_connect preference: id8 absent'),
                'test_http3_native.txt': ('Ran 6 tests', '127.0.0.1', '[::1]'),
            }.items():
                report = data(file).decode('utf-8')
                require(all(marker in report for marker in markers) and 'skipped' not in report,
                        f'Missing installed-wheel transcript witness at CPython {endpoint}: {file}')
            abi = data('test_h3_body_abi.txt').decode('utf-8')
            require(re.search(r'test_native_body_argument_bounds_and_thread_owner[^\n]*\.\.\. ok', abi),
                    f'Missing Bullseye body-owner ABI proof at CPython {endpoint}')
            reference, wire = verify_wire(data('profile-wire.txt').decode('utf-8'), data('firefox-profile-wire.jsonl'),
                                         slot, wheel['version'], entry)
            masque_status = summary.get('masque_status')
            if masque_status == 'wire-passed':
                require('masque-rfc9298' in summary['gates'] and json.loads(data('masque-wire.json')),
                        f'Missing MASQUE wire receipt at CPython {endpoint}')
        upgrade_name = f'0.9.3 upgrade on modern glibc / {slot} / CPython {endpoint}'
        modern = [j for j in jobs['jobs'] if j['name'] in {upgrade_name, f'floor / {upgrade_name}'} and
                  j['run_attempt'] == attempt]
        require(len(modern) == 1 and modern[0]['run_id'] == run_id and modern[0]['head_sha'] == commit and
                modern[0]['conclusion'] == 'success' and runner in modern[0]['labels'] and
                modern[0]['html_url'] == f'{run["html_url"]}/job/{modern[0]["id"]}',
                f'Missing successful modern v0.9.3 upgrade at CPython {endpoint}')
        upgrade = artifact_for(run, artifacts, f'modern-upgrade-{slot}-cp{endpoint}-{run_id}-{attempt}')
        endpoints[endpoint] = {'job': job['html_url'], 'artifact': f'{run["html_url"]}/artifacts/{item["id"]}',
                               'artifact_digest': item['digest'], 'python': summary['python'],
                               'reference_sha256': reference, 'wire_receipt_sha256': wire, 'masque_status': masque_status,
                               'modern_upgrade_job': modern[0]['html_url'],
                               'modern_upgrade_artifact': f'{run["html_url"]}/artifacts/{upgrade["id"]}'}
    return {'schema': 1, 'slot': slot, 'arch': arch, 'glibc': FLOOR, 'run': run['html_url'],
            'qualification_commit': commit, 'source_run': RUNS + str(source['run']), 'source_attempt': source['attempt'],
            'wheel_sha256': wheel['sha256'], 'wheel_filename': wheel['filename'], 'native_sha256': entry['files'],
            'cpython_runtime_endpoints': list(ENDPOINTS), 'endpoints': endpoints}
