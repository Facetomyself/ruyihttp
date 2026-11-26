#!/usr/bin/env python3
"""Pinned Firefox 161 POSIX recipe; separate from the tracked runtime manifest."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

DONOR_REPO = 'https://github.com/cutetailbud/ff-ruyijs.git'
DONOR_COMMIT = 'f557fcd437aae5f18f313eb330bd3ef50f5fc7df'
DONOR_FIREFOX = '2887d9de1f69c0e9776413da80e7ba0d1225dd9b'
FIREFOX_REPO = 'https://github.com/mozilla-firefox/firefox.git'
FIREFOX_TAG = 'FIREFOX_161_0_RELEASE'
FIREFOX_COMMIT = '9c70d5d48c866afc2e581d6b7ff6de98a1371d99'
NEQO_COMMIT = 'e302b43503f44e09f4257573dd320621516d1560'
NSS_RUST_COMMIT = 'bb8ed19e82679e613a636f530d15ddc823f1b040'
NSS_TAG = 'NSS_3_133_RTM'
NSS_RUST = '0.16.2'
RUST_VERSION = '1.95.0'
H3_PROTOCOL_POLICY = 1
GECKO_H3_SOURCES = {
    'netwerk/socket/neqo_glue/src/lib.rs': '4b3b029fe2b5f0c0f0007642d1f78df18069b5743a6b7c9e5e60357d17d7f51a',
    'modules/libpref/init/StaticPrefList.yaml': '349056e689a1e211b43710e876f46397b76d6295867a5bceba3770a7e2d3c4ce',
    'netwerk/protocol/http/Http3Session.cpp': '895fa285f1dedcb65d6f754b5d40cfdca48a8e42ee9fcbad866b8dcf15b19b92',
}
VERSIONS = {'firefox': '161.0', 'nss': '3.133', 'nspr': '4.40', 'neqo': '0.34.0'}
NEQO_PACKAGES = ('neqo-common', 'neqo-http3', 'neqo-qpack', 'neqo-transport')
ROOT = Path(__file__).resolve().parents[1]


def need(condition, message):
    if not condition:
        raise ValueError(message)


def runtime_expected(slot):
    mac = slot in {'darwin_arm64', 'darwin_x86_64'}
    need(mac or slot in {'linux_aarch64', 'linux_x86_64'}, f'Unsupported POSIX slot: {slot}')
    export = {'type': 'ascii', 'value': 'neqo-0.34.0/nss-3.133'} if mac else {'type': 'u32', 'value': 32}
    return dict(VERSIONS, h3_version_export=export)


def source_patches(slot):
    runtime_expected(slot)
    if slot.startswith('darwin_'):
        names = ('macos-necko-quic-tls-info.patch', 'h3-body-abi-v1.patch',
                 'macos-h3-global-handles.patch', 'firefox161-macos.patch',
                 'firefox-posix-quic-policy-macos.patch')
    else:
        names = ('h3-body-abi-v1.patch', 'firefox161-linux.patch',
                 'firefox-posix-quic-policy-linux.patch')
    return [f'native/patches/{name}' for name in names]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_candidate(slot, entry, provenance):
    need(all(entry.get(key) == value for key, value in runtime_expected(slot).items()),
         'Unexpected candidate runtime versions or version export')
    need(provenance.get('ff_ruyijs_commit') == DONOR_COMMIT and
         provenance.get('ff_ruyijs_firefox_gitlink') == DONOR_FIREFOX and
         provenance.get('firefox_source_commit') == FIREFOX_COMMIT and
         provenance.get('firefox_source_tag') == FIREFOX_TAG and
         provenance.get('runtime_expected') == VERSIONS and
         provenance.get('neqo_source_commit') == NEQO_COMMIT and
         provenance.get('nss_rs_source_commit') == NSS_RUST_COMMIT,
         'Unexpected Firefox 161 source provenance')
    expected = [{'path': path, 'sha256': digest(ROOT / path)} for path in source_patches(slot)]
    need(provenance.get('source_patches') == expected, 'Unexpected source patch names, order or bytes')
    need(all(type(record.get('h3_protocol_policy')) is int and
             record['h3_protocol_policy'] == H3_PROTOCOL_POLICY for record in (entry, provenance)),
         'Missing or invalid POSIX HTTP/3 policy generation')


def versions_in_lock(path, *, mozilla):
    import tomllib

    doc = tomllib.loads(path.read_text(encoding='utf-8'))
    found = {}
    expected = {name: VERSIONS['neqo'] for name in NEQO_PACKAGES} | {'nss-rs': NSS_RUST}
    for name, version in expected.items():
        candidates = [entry for entry in doc['package'] if entry['name'] == name]
        need(len(candidates) == 1 and candidates[0]['version'] == version,
             f'{path}: expected exactly one {name} {version}')
        source = candidates[0].get('source')
        if mozilla:
            pin = (f'git+https://github.com/mozilla/nss-rs#{NSS_RUST_COMMIT}' if name == 'nss-rs' else
                   f'git+https://github.com/mozilla/neqo?tag=v{version}#{NEQO_COMMIT}')
            need(source == pin, f'{path}: unexpected Mozilla source for {name}')
        else:
            need(source is None, f'{path}: {name} must use the local Firefox vendor overlay')
        found[name] = version
    return {'sha256': digest(path), 'packages': found}


def verify_sources(donor):
    import tomllib

    def git(path, *args):
        return subprocess.check_output(['git', '-C', path, *args], text=True).strip()

    firefox = donor / 'firefox'
    need(git(donor, 'rev-parse', 'HEAD') == DONOR_COMMIT, 'Unexpected donor commit')
    need(git(donor, 'ls-tree', 'HEAD', 'firefox').split() ==
         ['160000', 'commit', DONOR_FIREFOX, 'firefox'], 'Unexpected donor Firefox gitlink')
    need(git(firefox, 'rev-parse', 'HEAD') == FIREFOX_COMMIT, 'Unexpected Firefox release commit')
    files = {
        'browser/config/version.txt': VERSIONS['firefox'],
        'security/nss/TAG-INFO': NSS_TAG,
    }
    for filename, value in files.items():
        need((firefox / filename).read_text().strip() == value, f'Unexpected content in {filename}')
    for filename, define, key in (
        ('security/nss/lib/nss/nss.h', 'NSS_VERSION', 'nss'),
        ('nsprpub/pr/include/prinit.h', 'PR_VERSION', 'nspr'),
    ):
        content = (firefox / filename).read_text()
        need(re.findall(rf'^\s*#\s*define\s+{define}\s+"([^"]+)"', content, re.M) == [VERSIONS[key]],
             f'Unexpected {define} in {filename}')
        files[filename] = VERSIONS[key]
    for name in (*NEQO_PACKAGES, 'nss-rs'):
        filename = f'third_party/rust/{name}/Cargo.toml'
        package = tomllib.loads((firefox / filename).read_text())['package']
        version = NSS_RUST if name == 'nss-rs' else VERSIONS['neqo']
        need(package['name'] == name and package['version'] == version, f'Unexpected package in {filename}')
        files[filename] = version
    gecko_h3 = {name: digest(firefox / name) for name in GECKO_H3_SOURCES}
    need(gecko_h3 == GECKO_H3_SOURCES, 'Unexpected Firefox HTTP/3 policy sources')
    return {
        'donor': git(donor, 'log', '-1', '--format=%H %cI %s'), 'donor_firefox_gitlink': DONOR_FIREFOX,
        'firefox': git(firefox, 'log', '-1', '--format=%H %cI %s'), 'firefox_release_tag': FIREFOX_TAG,
        'source_files': {name: {'version': version, 'sha256': digest(firefox / name)} for name, version in files.items()},
        'mozilla_cargo_lock': versions_in_lock(firefox / 'Cargo.lock', mozilla=True),
        'gecko_h3_sources': gecko_h3,
        'neqo_commit': NEQO_COMMIT, 'nss_rs_commit': NSS_RUST_COMMIT,
    }


if __name__ == '__main__':
    command, *args = sys.argv[1:]
    if command == 'pins' and not args:
        for key in ('DONOR_REPO', 'DONOR_COMMIT', 'DONOR_FIREFOX', 'FIREFOX_REPO', 'FIREFOX_TAG', 'FIREFOX_COMMIT', 'RUST_VERSION'):
            print(f'{key}={globals()[key]}')
    elif command == 'verify-sources' and len(args) == 1:
        print(json.dumps(verify_sources(Path(args[0])), indent=2))
    elif command == 'verify-lock' and len(args) == 1:
        print(json.dumps(versions_in_lock(Path(args[0]), mozilla=False), indent=2))
    elif command == 'patches' and len(args) == 1:
        print('\n'.join(source_patches(args[0])))
    else:
        raise SystemExit('expected pins, verify-sources DONOR, verify-lock LOCKFILE, or patches SLOT')
