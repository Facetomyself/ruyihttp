#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Acquire exact signed Mozilla archives and establish native executable identity."""

import configparser
import ctypes
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from urllib.parse import quote

BASE = 'https://archive.mozilla.org/pub/firefox/releases/'
PRIMARY = '14F26682D0916CDD81E37B6D61B7B526D98F0353'
SIGNER = '827E658608679618CD349F93678E455D76767AA3'
# Manifest, source tag commit, source archive, en-US Linux x64/ARM64, macOS universal, Windows x64.
PINS = {
    '159': (
        '9c402489e6307e4cc1933ca1ebc01f6937f5ce1a9fb4354c2d212ab37eed26e5',
        '9a2dc53c369c7ae5172018b35988e1d2ffeff402',
        '3d98df785894057fce60603e845828e758a5411ad79aaaaff2b8230597f500d9',
        '54536fcd120af484d4c56272a5a1cf4af57b9c713d1a3b1e775da192dd541fcd',
        'de7b16588bf3ab11774f6c1b1461dafde943c1cf0ea93dc15aa5f7bd99aa1191',
        '0772404ae6e068d7cc03cecf4bb06a855f10287a77b624ffa41c6d092a64ea13',
        '8776887b79925abbdd407fcdfe257d8382b54e24be52a6466426b95a804d6790',
    ),
    '160': (
        'cc24dd72af3c4aa3ad300cf9ce0641d8437a746b35db6c0de7549a8fe4077fbf',
        '2887d9de1f69c0e9776413da80e7ba0d1225dd9b',
        '2b23d2bf6716ea16b45c10aa5c275c78a1d7ff50ad53150809ab27424c58fd81',
        'fde774e9757c8878534c05ec210db592bf6a1b244c57941ffb2e364c04f35fcd',
        '0fd9e4fd7ab97f7b1eec42f70e809080679498ebabd78fd692f0b94f9b6bf92f',
        'b270ccc60eb899bd0277bd078d7bd8690f5c4fc3e44b4fa9ee78ed2a3e89f0ca',
        '8732312ee2d7960c6ea830a4e0d3c0ff5fe0b10856dab44e2c432fcdeb63ff63',
    ),
    '161': (
        '803a78b7c8f18d179d40e2b9dec1eeaafc3bb12059c7da61c7aa6b91bdc9f1fd',
        '9c70d5d48c866afc2e581d6b7ff6de98a1371d99',
        'c649de11e4dc6266bc905ce4b33eb8672a1947c2e210ec53dce285cb86296a5a',
        '3e9b1e5132d7b53b1ad968c7300281e90e6a0ef57d0656b1516202d686d25733',
        'b3c2992292efc4a2f7ab6abe2de0ba6e15a482d41813e469c255a2528cacf10a',
        '18f398ada9ba9faa5458dc01c2a68fc7df35517283be2e7a421a0867c5f47f83',
        '8368757b8e39ffe0441b2489e051d0d5ffc016c246ed5634495104da0e66fa83',
    ),
}
SLOTS = {
    'linux_x86_64': ('linux', 'x86_64', 'linux-x86_64/en-US/firefox-{}.tar.xz', 3),
    'linux_aarch64': ('linux', 'aarch64', 'linux-aarch64/en-US/firefox-{}.tar.xz', 4),
    'darwin_arm64': ('darwin', 'arm64', 'mac/en-US/Firefox {}.dmg', 5),
    'darwin_x86_64': ('darwin', 'x86_64', 'mac/en-US/Firefox {}.dmg', 5),
    'win_amd64': ('win32', 'amd64', 'win64/en-US/Firefox Setup {}.exe', 6),
}


def expect(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def output(*command):
    return subprocess.check_output(command, text=True, timeout=30).strip()


def windows_machine(handle):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    fn = api.IsWow64Process2
    fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    fn.restype = ctypes.c_int
    process, native = ctypes.c_ushort(), ctypes.c_ushort()
    if not fn(handle, ctypes.byref(process), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    expect((process.value, native.value) == (0, 0x8664), 'Windows process must be native x64')
    return {'wow_machine': process.value, 'host_machine': native.value}


def host(slot):
    os_name, arch, _, _ = SLOTS[slot]
    expect(sys.platform == os_name and platform.machine().lower() == arch,
           f'expected {os_name}/{arch}, got {sys.platform}/{platform.machine()}')
    fields = {'machine': platform.machine(), 'os_release': platform.release(), 'os_version': platform.version()}
    if os_name == 'darwin':
        cpu = output('/usr/sbin/sysctl', '-n', 'machdep.cpu.brand_string')
        translated = output('/usr/sbin/sysctl', '-in', 'sysctl.proc_translated') or '0'
        expect(translated == '0' and ('Apple' if arch == 'arm64' else 'Intel') in cpu,
               f'non-native Mac host: {cpu}, translated={translated}')
        fields.update(cpu=cpu, rosetta=int(translated), macos=output('/usr/bin/sw_vers', '-productVersion'))
    elif os_name == 'win32':
        api = ctypes.WinDLL('kernel32')
        api.GetCurrentProcess.restype = ctypes.c_void_p
        fields.update(windows_machine(api.GetCurrentProcess()))
    else:
        fields['distribution'] = platform.freedesktop_os_release().get('PRETTY_NAME', '')
    return fields


def download(url, path):
    curl = 'curl.exe' if sys.platform == 'win32' else 'curl'
    subprocess.run([curl, '-q', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                    '--proto-redir', '=https', '--connect-timeout', '20', '--max-time', '150', '--retry', '2',
                    '--output', str(path), url], check=True, timeout=470)


def verify_release(slot, release, work):
    _, _, template, index = SLOTS[slot]
    manifest_hash, commit, source_hash = PINS[release][:3]
    version = f'{release}.0'
    origin = f'{BASE}{version}/'
    relative = template.format(version)
    source = f'source/firefox-{version}.source.tar.xz'
    manifest, signature, key = (work / n for n in ('SHA256SUMS', 'SHA256SUMS.asc', 'KEY'))
    for file in (manifest, signature, key):
        download(origin + file.name, file)
    expect(sha256(manifest) == manifest_hash, f'{version} manifest SHA-256 mismatch')
    home = work / 'gpg'
    home.mkdir(mode=0o700)
    # Git for Windows ships an MSYS-linked GnuPG, whose native home syntax is /d/….
    msys_gpg = sys.platform == 'win32' and any(line.startswith('Home: /') for line in output('gpg', '--version').splitlines())

    def gpg_path(path):
        return output('cygpath', '-u', str(path)) if msys_gpg else str(path)

    gpg = ['gpg', '--no-options', '--batch', '--homedir', gpg_path(home)]
    subprocess.run([*gpg, '--import', gpg_path(key)], check=True, timeout=30)
    status = output(*gpg, '--status-fd', '1', '--verify', gpg_path(signature), gpg_path(manifest))
    valid = [line.split() for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    expect(len(valid) == 1 and (valid[0][2], valid[0][-1]) == (SIGNER, PRIMARY), 'unexpected release signer')
    entries = {}
    for line in manifest.read_text(encoding='utf-8').splitlines():
        digest, artifact = line.split(maxsplit=1)
        if artifact in (relative, source):
            expect(artifact not in entries, f'duplicate release artifact {artifact}')
            entries[artifact] = digest
    digest = PINS[release][index]
    expect(entries == {relative: digest, source: source_hash}, 'signed manifest disagrees with release pins')
    url = origin + quote(relative)
    archive = work / Path(relative).name
    download(url, archive)
    expect(sha256(archive) == digest, f'{relative} archive SHA-256 mismatch')
    return archive, {'sha256': digest, 'url': url, 'manifest_sha256': manifest_hash,
                     'manifest_url': origin + manifest.name, 'signer': SIGNER, 'signing_primary': PRIMARY,
                     'source_tag': f'FIREFOX_{release}_0_RELEASE', 'source_commit': commit,
                     'source_archive': origin + source, 'source_archive_sha256': source_hash}


def extract(archive, work, slot):
    if sys.platform == 'linux':
        with tarfile.open(archive, 'r:xz') as package:
            package.extractall(work, filter='data')
        return work / 'firefox' / 'firefox', work / 'firefox' / 'application.ini'
    if sys.platform == 'darwin':
        mount = work / 'mount'
        mount.mkdir()
        subprocess.run(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', str(mount), str(archive)],
                       check=True, timeout=90)
        try:
            subprocess.run(['/usr/bin/ditto', str(mount / 'Firefox.app'), str(work / 'Firefox.app')],
                           check=True, timeout=90)
        finally:
            subprocess.run(['/usr/bin/hdiutil', 'detach', str(mount)], check=True, timeout=60)
        app = work / 'Firefox.app' / 'Contents'
        return app / 'MacOS' / 'firefox', app / 'Resources' / 'application.ini'
    seven_zip = shutil.which('7z') or str(Path(os.environ['ProgramFiles']) / '7-Zip' / '7z.exe')
    subprocess.run([seven_zip, 'x', str(archive), f'-o{work}', '-y'], check=True,
                   stdout=subprocess.DEVNULL, timeout=120)
    return work / 'core' / 'firefox.exe', work / 'core' / 'application.ini'


def executable_arch(binary, slot):
    arch = SLOTS[slot][1]
    if sys.platform == 'darwin':
        slices = output('/usr/bin/lipo', '-archs', str(binary)).split()
        expect(arch in slices, f'Mach-O lacks {arch}: {slices}')
        return slices
    with binary.open('rb') as file:
        head = file.read(64)
        if sys.platform == 'win32':
            expect(head[:2] == b'MZ', 'Firefox executable is not PE')
            file.seek(struct.unpack_from('<I', head, 60)[0])
            expect(file.read(6) == b'PE\0\0\x64\x86', 'Firefox executable is not AMD64 PE')
        else:
            machine = 62 if arch == 'x86_64' else 183
            expect(head[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', head, 18)[0] == machine,
                   f'Firefox executable is not {arch} ELF')
    return [arch]


def prepare(slot, release, work):
    identity = host(slot)
    work.mkdir(parents=True, exist_ok=False)
    archive, record = verify_release(slot, release, work)
    binary, ini = extract(archive, work, slot)
    slices = executable_arch(binary, slot)
    app = configparser.ConfigParser()
    expect(app.read(ini), 'missing official application.ini')
    version, build = app['App']['Version'], app['App']['BuildID']
    expect(version == f'{release}.0' and len(build) == 14 and build.isdecimal(), f'unexpected Firefox build: {version}/{build}')
    images = {binary.name: sha256(binary)}
    if sys.platform == 'linux' and (image := binary.with_name('firefox-bin')).is_file():
        executable_arch(image, slot)
        images[image.name] = sha256(image)
    record.update(version=version, build_id=build, executable_sha256=images[binary.name], executable_slices=slices,
                  runtime_host=identity, source_stamp=app['App'].get('SourceStamp'), archive_locale='en-US',
                  executable_relative=binary.relative_to(work).as_posix(), packaged_executables=images,
                  acquired_unix=int(time.time()))
    (work / 'release.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record), flush=True)
    archive.unlink()  # This is the just-verified archive under the new, dedicated work directory.
    return record
