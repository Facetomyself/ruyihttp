#!/usr/bin/env python3
"""Pinned native Bullseye build inputs and separately measured Linux policy."""
import hashlib
import json
from pathlib import Path
import re
import sys


FLOOR = '2.31'
POLICY = 'manylinux_2_31'
ARCHES = {'linux_x86_64': 'amd64', 'linux_aarch64': 'arm64'}
IMAGE_DIGESTS = {
    'linux_x86_64': 'sha256:861d612f2bccf851b081e8c4db098d305c804c909230258a78feb41b9f0e7eb1',
    'linux_aarch64': 'sha256:3ab6b6a9addd2fd03e577c440ef6875692253fe387aa6484f58f169c5377c711',
}
# Official Docker Hub child manifests of buildpack-deps:bullseye (not floating tags).
IMAGE_REPO = 'docker.io/library/buildpack-deps'
DEBIAN_SNAPSHOT = '20261015T000000Z'
PYTHON_VERSION = '3.14.1'
PYTHON_SHA256 = '8dfa08b1959d9d15838a1c2dab77dc8d8ff4a553a1ed046dfacbc8095c6d42fc'
CLANG_VERSION = '1:16.0.6-15~deb11u2'
GCC_VERSION = '10.2.1-6'
RUST_VERSION = '1.95.0'
RUST_SHA256 = {
    'linux_x86_64': '2e0338f18ecbaa4a0f631b9e80e8b26bb6fe77dd5454fba8a70cf96c1e84a1',
    'linux_aarch64': '094c9c36531911c5cc7dd6ab2d3069ab8dcd744d6239b0bda1387b243dfc391e',
}
AUDITWHEEL_VERSION = '6.6.0'


def pins(slot):
    return {
        'BASELINE_IMAGE': f'{IMAGE_REPO}@{IMAGE_DIGESTS[slot]}',
        'BASELINE_ARCH': ARCHES[slot],
        'BASELINE_SNAPSHOT': DEBIAN_SNAPSHOT,
        'BASELINE_PYTHON': PYTHON_VERSION,
        'BASELINE_PYTHON_SHA256': PYTHON_SHA256,
        'BASELINE_CLANG': CLANG_VERSION,
        'BASELINE_GCC': GCC_VERSION,
        'BASELINE_RUST': RUST_VERSION,
        'BASELINE_RUST_SHA256': RUST_SHA256[slot],
        'BASELINE_AUDITWHEEL': AUDITWHEEL_VERSION,
    }


def _read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def _file_hash(path):
    with path.open('rb') as fp:
        return hashlib.file_digest(fp, 'sha256').hexdigest()


def _require(ok, detail):
    if not ok:
        raise ValueError(detail)


def builder_record(slot, evidence):
    pinned = pins(slot)
    arch = slot.removeprefix('linux_')
    image, = _read(evidence / 'builder-image.json')
    repos = image['RepoDigests']
    _require(image['Os'] == 'linux' and image['Architecture'] == ARCHES[slot] and
             any(r in (pinned['BASELINE_IMAGE'], pinned['BASELINE_IMAGE'].removeprefix('docker.io/library/')) for r in repos),
             'Bullseye builder image differs from pinned native OCI child manifest')
    packages = dict(row.split('\t') for row in (evidence / 'builder-dpkg.tsv').read_text().splitlines())
    essential = {}
    for name in ('libc6', 'libc6-dev', 'libstdc++6', 'libgcc-s1', 'gcc-10', 'g++-10',
                 'clang-16', 'libclang-16-dev', 'binutils', 'ninja-build', 'patchelf'):
        essential[name] = packages.get(name) or packages[f'{name}:{ARCHES[slot]}']
    _require(essential['libc6'].startswith('2.31-') and essential['libc6'] == essential['libc6-dev'] and
             all(essential[n] == GCC_VERSION for n in ('libstdc++6','libgcc-s1','gcc-10','g++-10')) and
             essential['clang-16'] == essential['libclang-16-dev'] == CLANG_VERSION and
             essential['ninja-build'] == '1.10.1-1' and essential['patchelf'] == '0.12-1',
             'Bullseye builder toolchain package versions differ from recipe')
    toolchain = (evidence / 'builder-toolchain.txt').read_text().splitlines()
    _require(toolchain[:3] == [f'Linux {arch}', f'glibc {FLOOR}', f'Python {PYTHON_VERSION}'] and
             any('clang version 16.0.6' in line for line in toolchain) and
             f'release: {RUST_VERSION}' in toolchain and f'host: {arch}-unknown-linux-gnu' in toolchain,
             'Unexpected native builder, loader, CPython or Rust toolchain')
    receipts = ['builder-image.json', 'builder-dpkg.tsv', 'builder-toolchain.txt', 'builder-glibc-headers.txt']
    return {'schema': 1, 'slot': slot, 'arch': arch, 'glibc': FLOOR, 'pins': pinned,
            'image_config_id': image['Id'], 'packages': essential,
            'receipts': {name: _file_hash(evidence / name) for name in receipts}}


def audit_record(slot, evidence):
    arch = slot.removeprefix('linux_')
    version = (evidence / 'auditwheel-version.txt').read_text()
    _require(re.search(r'\bauditwheel\s+' + re.escape(AUDITWHEEL_VERSION) + r'\b', version), 'Unexpected auditwheel version')
    audit_report = evidence / 'auditwheel.txt'
    report = audit_report.read_text()
    tag = re.search(r'following platform tag:\s+"(manylinux_2_(\d+)_' + arch + r')"', report)
    proposed = (evidence / 'baseline-build.json').is_file()
    manifest = _read(evidence / 'runtime-manifest.json')
    entry = manifest['platforms'][slot]
    floor = 31 if proposed or entry.get('linux_baseline') else 39
    _require(tag and int(tag[2]) <= floor, f'auditwheel did not establish a {arch} floor at or below glibc 2.{floor}')
    return {'schema': 1, 'slot': slot, 'version': AUDITWHEEL_VERSION,
            'wheel_sha256': _read(evidence / 'wheel.json')['wheel_sha256'],
            'inferred_platform_tag': tag[1], 'auditwheel_sha256': _file_hash(audit_report)}


def candidate_record(slot, elf, build):
    return {'policy': POLICY, 'candidate_tag': f'{POLICY}_{slot.removeprefix("linux_")}',
            'elf_sha256': _hash(elf), 'build_sha256': _hash(build)}


def verify_built_candidate(slot, libraries, evidence):
    from check_linux_candidate import check

    build = _read(evidence / 'baseline-build.json')
    elf = _read(evidence / 'baseline-elf.json')
    _require(build == builder_record(slot, evidence), 'Builder record differs from pinned CI evidence')
    validate_elf(slot, libraries, elf)
    return candidate_record(slot, elf, build), build, elf


def validate_elf(slot, libraries, elf):
    from check_linux_candidate import check

    checked = check(libraries, slot.removeprefix('linux_'), baseline=True)
    recorded = dict(elf)
    providers = recorded.pop('host_provider_definitions')
    _require(checked == recorded and providers, 'ELF receipts differ from actual Linux native bytes')
    required = {}
    for lib in checked['libraries'].values():
        for provider, versions in lib['version_imports'].items():
            if provider in checked['system_dt_needed']:
                required.setdefault(provider, set()).update(versions)
    _require(required.keys() == providers.keys() and
             all(versions <= set(providers[p]['versions']) and re.fullmatch(r'[0-9a-f]{64}', providers[p]['sha256'])
                 for p, versions in required.items()), 'Bullseye providers did not supply all symbol versions')
    return checked


def validate_policy_records(slot, entry, provenance, libraries=None):
    """Return the measured candidate or admitted policy; legacy banks stay 2.39."""
    arch = slot.removeprefix('linux_')
    historical_tag = f'manylinux_2_39_{arch}'
    fields = [field for field in ('linux_baseline_candidate', 'linux_baseline') if field in entry or field in provenance]
    if not fields:
        _require(entry.get('wheel_platform_tag', historical_tag) == historical_tag and
                 provenance.get('wheel_platform_tag', historical_tag) == historical_tag,
                 'Linux compatibility tag changed without a native baseline measurement')
        return None
    _require(len(fields) == 1, 'Linux candidate and admitted policies are exclusive')
    field, = fields
    measured = entry[field]
    elf, build = provenance['linux_elf_preflight'], provenance['linux_baseline_build']
    _require(measured == provenance[field] == candidate_record(slot, elf, build) and
             build['slot'] == slot and build['arch'] == arch and build['glibc'] == FLOOR and build['pins'] == pins(slot) and
             elf['arch'] == arch and elf['schema'] == 2 and elf['allowed_glibc_max'] == FLOOR and
             entry['highest_glibc_dynamic_requirement'] == provenance['highest_glibc_dynamic_requirement'] == elf['highest_glibc_dynamic_requirement'],
             'Linux policy does not match its baseline build and ELF evidence')
    tag = measured['candidate_tag'] if field == 'linux_baseline' else historical_tag
    _require(entry['wheel_platform_tag'] == provenance['wheel_platform_tag'] == tag and
             entry.get('h3_body_abi') == 1 and entry.get('h3_protocol_policy') == 1,
             'Linux measured tag or native HTTP/3 ABI policy differs from its receipt')
    _require({n: v['sha256'] for n, v in elf['libraries'].items()} == entry['files'] ==
             {n: v['sha256'] for n, v in provenance['files'].items()},
             'Linux ELF receipt inventory differs from the runtime manifest')
    if field == 'linux_baseline':
        floor = provenance.get('linux_floor_verification', {})
        _require(floor.get('glibc') == FLOOR and floor.get('slot') == slot and floor.get('arch') == arch and
                 floor.get('cpython_runtime_endpoints') == ['3.10', '3.14'] and floor.get('native_sha256') == entry['files'],
                 'Linux wheel floor requires an independent same-slot Bullseye proof')
    if libraries is not None:
        validate_elf(slot, libraries, elf)
    return measured


def main():
    op, slot, *extra = sys.argv[1:]
    if op == 'record':
        print(json.dumps(builder_record(slot, Path(extra[0])), indent=2))
    elif op == 'audit':
        print(json.dumps(audit_record(slot, Path(extra[0])), indent=2))
    elif op == 'pins':
        for k, value in pins(slot).items():
            print(f'{k}={value}')
    elif op == 'json':
        print(json.dumps(pins(slot), indent=2))
    else:
        raise SystemExit('expected pins or json and a native Linux slot')


if __name__ == '__main__':
    main()
