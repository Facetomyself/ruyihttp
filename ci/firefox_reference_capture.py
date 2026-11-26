#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Capture exact official Firefox releases from fresh, loopback-only profiles."""

import argparse
import asyncio
import ctypes
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from firefox_reference_releases import PINS, SLOTS, executable_arch, expect, host, prepare, sha256, windows_machine
from firefox_reference_wire import Origin, PATH

PREFS = {
    'app.normandy.enabled': False,
    'app.shield.optoutstudies.enabled': False,
    'app.update.auto': False,
    'app.update.enabled': False,
    'app.update.service.enabled': False,
    'app.update.background.enabled': False,
    'browser.aboutwelcome.enabled': False,
    'browser.discovery.enabled': False,
    'browser.newtabpage.activity-stream.feeds.telemetry': False,
    'browser.newtabpage.activity-stream.telemetry': False,
    'browser.newtabpage.enabled': False,
    'browser.ping-centre.telemetry': False,
    'browser.safebrowsing.downloads.remote.enabled': False,
    'browser.safebrowsing.malware.enabled': False,
    'browser.safebrowsing.phishing.enabled': False,
    'browser.search.update': False,
    'browser.shell.checkDefaultBrowser': False,
    'browser.startup.firstrunSkipsHomepage': True,
    'browser.startup.homepage_override.mstone': 'ignore',
    'datareporting.healthreport.uploadEnabled': False,
    'datareporting.policy.dataSubmissionEnabled': False,
    'extensions.getAddons.cache.enabled': False,
    'extensions.systemAddon.update.enabled': False,
    'extensions.update.enabled': False,
    'extensions.webcompat-reporter.enabled': False,
    'network.captive-portal-service.enabled': False,
    'network.connectivity-service.enabled': False,
    'network.proxy.type': 0,
    'network.trr.mode': 5,
    'security.enterprise_roots.enabled': False,
    'security.certerrors.mitm.auto_enable_enterprise_roots': False,
    'toolkit.telemetry.enabled': False,
    'toolkit.telemetry.unified': False,
}


def certificate(directory):
    """Same leaf shape as smoke_native_target; distinct ephemeral CA per case."""
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'RuyiHttp native test CA')])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    ca_key, server_key = (generate_private_key(SECP256R1()) for _ in range(2))

    def builder(subject, public_key, ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))

    ca = builder(ca_name, ca_key.public_key(), True).sign(ca_key, hashes.SHA256())
    cert = (builder(server_name, server_key.public_key(), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    root, leaf, key = (directory / n for n in ('ca.der', 'leaf.pem', 'key.pem'))
    root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
    leaf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return leaf, key, root


def import_profile_ca(browser, profile, root):
    configured = os.getenv('FIREFOX_REFERENCE_NSS_CERTUTIL')
    if configured:
        subprocess.run([configured, '-N', '--empty-password', '-d', f'sql:{profile}'], check=True, timeout=10)
        subprocess.run([configured, '-A', '-d', f'sql:{profile}', '-n', 'RuyiHttp loopback CA',
                        '-t', 'C,,', '-i', str(root)], check=True, timeout=10)
        return
    env = os.environ.copy()
    if sys.platform == 'linux':
        env['LD_LIBRARY_PATH'] = str(browser.parent)
    elif sys.platform == 'darwin':
        env['DYLD_LIBRARY_PATH'] = str(browser.parent)
    subprocess.run([sys.executable, '-B', __file__, 'nss-import', str(browser), str(profile), str(root)],
                   env=env, check=True, timeout=15)


def nss_import(browser, profile, root):
    """Write only the staged profile's SQL NSS DB, before Firefox opens it."""
    library = {'win32': 'nss3.dll', 'darwin': 'libnss3.dylib', 'linux': 'libnss3.so'}[sys.platform]
    dll_path = os.add_dll_directory(str(browser.parent)) if sys.platform == 'win32' else None
    nss = ctypes.CDLL(str(browser.parent / library))
    pointer, charptr, status = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int

    class Item(ctypes.Structure):
        _fields_ = [('type', status), ('data', ctypes.POINTER(ctypes.c_ubyte)), ('len', ctypes.c_uint)]

    class Trust(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint) for n in ('ssl', 'email', 'object_signing')]

    def bind(name, restype, *argtypes):
        fn = getattr(nss, name)
        fn.restype, fn.argtypes = restype, argtypes
        return fn

    init = bind('NSS_InitReadWrite', status, charptr)
    db = bind('CERT_GetDefaultCertDB', pointer)
    new_cert = bind('CERT_NewTempCertificate', pointer, pointer, ctypes.POINTER(Item), charptr, status, status)
    decode = bind('CERT_DecodeTrustString', status, ctypes.POINTER(Trust), charptr)
    add = bind('PK11_ImportCert', status, pointer, pointer, ctypes.c_ulong, charptr, status)
    change_trust = bind('CERT_ChangeCertTrust', status, pointer, pointer, ctypes.POINTER(Trust))
    destroy = bind('CERT_DestroyCertificate', None, pointer)
    shutdown = bind('NSS_Shutdown', status)
    get_error = bind('PORT_GetError', status)
    internal_slot = bind('PK11_GetInternalKeySlot', pointer)
    needs_init = bind('PK11_NeedUserInit', status, pointer)
    init_pin = bind('PK11_InitPin', status, pointer, charptr, charptr)
    free_slot = bind('PK11_FreeSlot', None, pointer)

    def check(value, operation):
        expect(value == 0, f'NSS {operation} failed: {get_error()}')

    check(init(f'sql:{profile}'.encode('utf-8')), 'init')
    try:
        slot = internal_slot()
        expect(slot, f'NSS internal key slot missing: {get_error()}')
        try:
            if needs_init(slot):
                check(init_pin(slot, None, b''), 'initialize isolated key slot')
            der = root.read_bytes()
            array = (ctypes.c_ubyte * len(der)).from_buffer_copy(der)
            item = Item(0, array, len(der))
            database = db()
            cert = new_cert(database, ctypes.byref(item), None, 0, 1)
            expect(cert, f'NSS decode certificate failed: {get_error()}')
            try:
                trust = Trust()
                check(decode(ctypes.byref(trust), b'C,,'), 'decode trust')
                check(add(slot, cert, 0, b'RuyiHttp loopback CA', 0), 'install local certificate')
                check(change_trust(database, cert, ctypes.byref(trust)), 'trust local CA for TLS')
            finally:
                destroy(cert)
        finally:
            free_slot(slot)
    finally:
        check(shutdown(), 'shutdown')
        if dll_path:
            dll_path.close()


def write_profile(browser, directory, root, case):
    profile = directory / 'profile'
    profile.mkdir()
    settings = dict(PREFS)
    if case == 'h3':
        # Transport eligibility only. Certificate/host validation still uses the
        # isolated profile's NSS trust database with the generated test anchor.
        settings['network.http.http3.disable_when_third_party_roots_found'] = False
    prefs = ''.join(f'user_pref({json.dumps(key)}, {json.dumps(value)});\n' for key, value in sorted(settings.items()))
    (profile / 'user.js').write_text(prefs, encoding='ascii')
    import_profile_ca(browser, profile, root)
    return profile


def launch(browser, arch, profile, url, directory):
    argv = [str(browser), '-headless', '-no-remote', '-new-instance', '-profile', str(profile), url]
    if sys.platform == 'darwin':
        seatbelt = ('(version 1) (allow default) (deny network-outbound '
                    '(require-all (remote ip "*:*" ) (require-not (remote ip "localhost:*"))))')
        argv[:0] = ['/usr/bin/sandbox-exec', '-p', seatbelt, '/usr/bin/arch', '-' + arch]
    if sys.platform == 'win32':
        argv.insert(1, '-wait-for-browser')
    env = dict(os.environ)
    reserved = ('MOZ_', 'XRE_', 'NSS_', 'SSLKEYLOGFILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_')
    env = {k: v for k, v in env.items() if not k.upper().startswith(reserved)}
    (directory / 'home').mkdir()
    env.update(HOME=str(directory / 'home'), MOZ_CRASHREPORTER_DISABLE='1', MOZ_NO_REMOTE='1', MOZ_HEADLESS='1')
    if sys.platform == 'win32':
        for key in ('LOCALAPPDATA', 'APPDATA', 'USERPROFILE'):
            isolated = directory / key.lower()
            isolated.mkdir()
            env[key] = str(isolated)
    with (directory / 'browser.log').open('wb') as log:
        return subprocess.Popen(argv, cwd=directory, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                start_new_session=sys.platform != 'win32')


def log_summary(directory):
    with (directory / 'browser.log').open('rb') as source:
        data = source.read(8192).decode('utf-8', errors='replace')
    # Retain bounded startup diagnostics, redacting filesystem paths and all URL strings.
    selected = []
    for row in data.splitlines():
        if re.search(r'error|failed|denied|sandbox|headless|xpcom|dyld|warn|network|security|certificate', row, re.I):
            row = re.sub(r'(?:[a-z]+://|[A-Za-z]:[\\/]|/)[^\s\])>,;]+', '<omitted>', row)
            selected.append(row[:240])
    return selected[:16]


def darwin_process(pid, browser, arch):
    libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    pidpath = libproc.proc_pidpath
    pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    pidpath.restype = ctypes.c_int
    path = ctypes.create_string_buffer(4096)
    expect(pidpath(pid, path, len(path)) > 0 and Path(os.fsdecode(path.value)).resolve() == browser,
           'macOS did not launch the verified executable')
    pidinfo = libproc.proc_pidinfo
    pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    pidinfo.restype = ctypes.c_int
    result = (ctypes.c_int32 * 2)()
    size = ctypes.sizeof(result)
    expected = 0x0100000C if arch == 'arm64' else 0x01000007
    expect(pidinfo(pid, 19, 0, ctypes.byref(result), size) == size and result[0] == expected,
           'macOS process is not using the expected native Mach-O architecture')
    return {'launch_arch': f'/usr/bin/arch -{arch}', 'cpu_type': result[0], 'cpu_subtype': result[1]}


def stop(process, browser):
    if sys.platform == 'win32':
        env = {**os.environ, 'RUYI_FF_FIXTURE_EXE': str(browser)}
        subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                        'Get-Process -Name firefox -ErrorAction SilentlyContinue | '
                        'Where-Object { $_.Path -ieq $env:RUYI_FF_FIXTURE_EXE } | Stop-Process -Force'],
                       env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if sys.platform != 'win32':
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)


def validate(case, record, release):
    pairs = record['headers']
    headers = {key.lower(): value for key, value in pairs}
    ua = headers.get('user-agent', '')
    expect(len(pairs) == len(headers) and ua.startswith('Mozilla/5.0 ') and ua.endswith(f' Firefox/{release}.0'),
           'wire request has duplicate field names or wrong official release UA')
    authority = f"localhost:{record['port']}"
    if case == 'h1':
        expect(headers.get('host') == authority and headers.get('sec-fetch-mode') == 'navigate', 'wrong H1 navigation')
    else:
        expect((headers.get(':method'), headers.get(':scheme'), headers.get(':authority'), headers.get(':path')) ==
               ('GET', 'https', authority, PATH), f'wrong {case} request target')
        expect(record['settings'], f'missing initial {case} SETTINGS')
        if case == 'h2':
            expect(headers.get('sec-fetch-mode') == 'navigate', 'wrong H2 navigation')
        else:
            expect(record['bootstrap'] and record['quic_version'] and record['transport_parameters'], 'incomplete H3 trace')
            expect((headers.get('sec-fetch-dest'), headers.get('sec-fetch-mode'), headers.get('sec-fetch-site')) ==
                   ('empty', 'cors', 'same-origin'), 'wrong H3 Fetch Metadata context')
            expect(headers.get('referer') == f'https://{authority}/boot' and 'sec-fetch-user' not in headers,
                   'H3 request is not the ordinary fetch from the recorded bootstrap')
    expect(not any(key in headers for key in ('authorization', 'cookie', 'proxy-authorization')), 'unexpected sensitive header')
    record['user_agent'] = ua


async def collect(slot, release, browser, images, case, diagnostic):
    with TemporaryDirectory(prefix='ff-reference-', ignore_cleanup_errors=sys.platform == 'win32') as temp:
        directory = Path(temp)
        leaf, key, root = certificate(directory)
        profile = write_profile(browser, directory, root, case)
        async with Origin(case, leaf, key) as origin:
            process = launch(browser, SLOTS[slot][1], profile, origin.url, directory)
            try:
                arch = SLOTS[slot][1]
                process_record = {'native': arch}
                if sys.platform == 'win32':
                    process_record.update(windows_machine(int(process._handle)))
                try:
                    record = await asyncio.wait_for(origin.result, timeout=23)
                except TimeoutError:
                    diagnostic.update(origin.diagnostics(), browser_returncode=process.poll(), browser_messages=log_summary(directory))
                    raise RuntimeError(f'{case}: no valid request from the official browser in 23 seconds') from None
                validate(case, record, release)
                if sys.platform == 'darwin':
                    process_record.update(darwin_process(process.pid, browser, arch))
                elif sys.platform == 'linux':
                    image = Path(f'/proc/{process.pid}/exe').resolve(strict=True)
                    expect(image.parent == browser.parent and image.name in images and sha256(image) == images[image.name],
                           f'Linux process image differs from verified package ({image.name})')
                    process_record.update(image=image.name, image_sha256=images[image.name])
                record['process'] = process_record
                diagnostic.update(origin.diagnostics())
                return record
            finally:
                stop(process, browser)


def identity(slot, record, work):
    expect(host(slot) == record['runtime_host'], 'capture host differs from the acquisition host')
    browser = (work / record['executable_relative']).resolve(strict=True)
    expect(work in browser.parents and executable_arch(browser, slot) == record['executable_slices'] and
           sha256(browser) == record['executable_sha256'], 'capture executable differs from the original verified binary')
    return browser


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')


def capture(slot, release, work, out, samples):
    out.mkdir(parents=True, exist_ok=True)
    acquisition = json.loads((work / 'release.json').read_text(encoding='utf-8'))
    expect(acquisition['version'] == f'{release}.0' and acquisition['sha256'] == PINS[release][SLOTS[slot][3]],
           'capture release does not match pinned acquisition')
    browser = identity(slot, acquisition, work)
    platform_name, arch, _, _ = SLOTS[slot]
    row = {'schema_version': 1, 'slot': slot, 'platform': platform_name, 'arch': arch, 'source': 'official-firefox',
           'captures': {release: {**acquisition, 'samples': []}}}
    row['ci'] = {k.lower().removeprefix('github_'): os.getenv(k) for k in
                 ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion') if os.getenv(k)}
    diagnostics, partial = [], []
    for attempt in range(samples):
        sample = {}
        for case in ('h1', 'h2', 'h3'):
            diagnostic = {'attempt': attempt, 'case': case}
            diagnostics.append(diagnostic)
            try:
                sample[case] = asyncio.run(collect(slot, release, browser, acquisition['packaged_executables'], case, diagnostic))
                print(f'{slot} Firefox {release}.0 sample {attempt + 1} {case}: {sample[case]["user_agent"]}', flush=True)
            except Exception as exc:
                diagnostic['failure'] = str(exc)
                print(f'{slot} Firefox {release}.0 sample {attempt + 1} {case}: {exc}', flush=True)
        if set(sample) == {'h1', 'h2', 'h3'}:
            row['captures'][release]['samples'].append(sample)
        else:
            partial.append(sample)
    if partial:
        save_json(out / f'{slot}-{release}-partial.json', {**row, 'partial_samples': partial, 'diagnostics': diagnostics})
        raise RuntimeError(f'{slot} Firefox {release}.0: {len(partial)} of {samples} samples incomplete')
    save_json(out / f'{slot}-{release}.json', row)
    save_json(out / f'{slot}-{release}-diagnostics.json', diagnostics)


def merge(slot, out):
    combined = None
    for release in PINS:
        observation = json.loads((out / f'{slot}-{release}.json').read_text(encoding='utf-8'))
        expect(observation['slot'] == slot and set(observation['captures']) == {release}, 'wrong slot/release for merge')
        expect(len(observation['captures'][release]['samples']) >= 2, 'admission needs at least two complete samples')
        if combined is None:
            combined = observation
        else:
            expect(observation['ci'] == combined['ci'], 'capture pieces have distinct run identities')
            combined['captures'].update(observation['captures'])
    save_json(out / f'{slot}.json', combined)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for action in ('prepare', 'capture'):
        cmd = commands.add_parser(action)
        cmd.add_argument('slot', choices=SLOTS)
        cmd.add_argument('release', choices=PINS)
        cmd.add_argument('work', type=Path)
        if action == 'capture':
            cmd.add_argument('out', type=Path)
            cmd.add_argument('--samples', type=int, choices=range(1, 4), default=2)
    cmd = commands.add_parser('merge')
    cmd.add_argument('slot', choices=SLOTS)
    cmd.add_argument('out', type=Path)
    cmd = commands.add_parser('nss-import', help=argparse.SUPPRESS)
    for key in ('browser', 'profile', 'root'):
        cmd.add_argument(key, type=Path)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.slot, args.release, args.work.resolve())
    elif args.command == 'capture':
        capture(args.slot, args.release, args.work.resolve(), args.out.resolve(), args.samples)
    elif args.command == 'merge':
        merge(args.slot, args.out.resolve())
    else:
        nss_import(args.browser, args.profile, args.root)


if __name__ == '__main__':
    main()
