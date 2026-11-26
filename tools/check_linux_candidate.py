#!/usr/bin/env python3
"""Read-only Linux native-set ABI preflight. No library loading or promotion."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess

from build_native import PLATFORM_FILES, sha256

ELF_MACHINE={'x86_64':62,'aarch64':183}
LOADER={'x86_64':'ld-linux-x86-64.so.2','aarch64':'ld-linux-aarch64.so.1'}
SYSTEM={'libc.so.6','libm.so.6','libdl.so.2','libpthread.so.0','librt.so.1','libgcc_s.so.1','libstdc++.so.6'}
GLIBC_MAX=(2,39)
BULLSEYE_LIMITS={'GLIBC':(2,31), 'GLIBCXX':(3,4,28), 'CXXABI':(1,3,12), 'GCC':(7,0,0)}
CORE={f'necko_{group}_{name}' for group,names in {
    'exchange':'open write receive headers read close reusable',
    'socket':'open open_cancellable read write write_some idle peer interrupt close',
    'tls':'open open_profile nss_version nspr_version alpn cipher version resumed set_nonblocking pending error read write write_some close',
}.items() for name in names.split()}
QUIC={'necko_quic_call','necko_quic_set_decoder'}
EXPECTED={'libnecko_core.so':CORE,'libnecko_quic.so':QUIC}


def version_needs(text):
    rows=text.split('Version needs section',1)
    out=set()
    if len(rows)==2:
        for s in re.findall(r'\bName: (GLIBC_[A-Za-z0-9_.]+)\b',rows[1]):
            match=re.fullmatch(r'GLIBC_([0-9]+(?:\.[0-9]+)+)',s)
            if not match:raise ValueError('unsupported glibc version requirement: '+s)
            out.add(tuple(map(int,match[1].split('.'))))
    return out


def function_exports(text):
    names=set()
    for line in text.splitlines():
        f=line.split()
        if len(f)>=8 and re.fullmatch(r'\d+:',f[0]) and f[3]=='FUNC' and f[4] in ('GLOBAL','WEAK') and f[5] in ('DEFAULT','PROTECTED') and f[6]!='UND':
            names.add(f[7].split('@',1)[0])
    return names


def readelf(flag, path):
    return subprocess.check_output(['/usr/bin/readelf','--wide',flag,path],env={**os.environ,'LC_ALL':'C'},text=True,timeout=20)


def needed_versions(text):
    """Return version imports grouped by DT_NEEDED provider, not version definitions."""
    tail = text.partition('Version needs section')[2]
    providers = {}
    provider = None
    for line in tail.splitlines():
        library = re.search(r'\bFile: (\S+)\s+Cnt:', line)
        version = re.search(r'\bName: (\S+)\s+Flags:', line)
        if library:
            provider = library[1]
            if provider in providers:
                raise ValueError(f'duplicate ELF version provider: {provider}')
            providers[provider] = set()
        if version:
            if provider is None or version[1] in providers[provider]:
                raise ValueError(f'corrupt or duplicate ELF version need: {version[1]}')
            providers[provider].add(version[1])
    return providers


def provided_versions(path):
    section = readelf('--version-info', path).partition('Version definition section')[2]
    return set(re.findall(r'\bName: (\S+)', section.partition('Version needs section')[0]))


def baseline_versions(providers, arch, name):
    limits = {k: set() for k in BULLSEYE_LIMITS}
    for provider, versions in providers.items():
        for version in versions:
            family, _, suffix = version.partition('_')
            if family not in limits:
                if provider in SYSTEM or provider == LOADER[arch]:
                    raise ValueError(f'{name}: unsupported system version {provider}:{version}')
                continue  # Bundled NSS/NSPR/provider definitions checked as a closure below.
            if ((family in {'GLIBCXX','CXXABI'} and provider != 'libstdc++.so.6') or
                    (family == 'GCC' and provider != 'libgcc_s.so.1') or
                    (family == 'GLIBC' and provider not in (SYSTEM-{'libstdc++.so.6','libgcc_s.so.1'}) | {LOADER[arch]})):
                raise ValueError(f'{name}: incorrect provider {provider} for {version}')
            permitted_special = {'CXXABI_TM_1'} | ({'CXXABI_FLOAT128'} if arch == 'x86_64' else set())
            if version not in permitted_special:
                if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', suffix):
                    raise ValueError(f'{name}: unsupported {family} requirement {version}')
                numeric = tuple(map(int, suffix.split('.')))
                if numeric > BULLSEYE_LIMITS[family]:
                    cap = '.'.join(map(str, BULLSEYE_LIMITS[family]))
                    raise ValueError(f'{name}: {version} exceeds Bullseye {family}_{cap}')
            limits[family].add(version)
    return {fam: sorted(versions) for fam, versions in limits.items()}


def host_provider(arch, name):
    triple = f'{arch}-linux-gnu'
    for directory in (Path('/lib') / triple, Path('/usr/lib') / triple, Path('/lib64')):
        path = directory / name
        if path.is_file():
            return path.resolve(strict=True)
    raise ValueError(f'Bullseye host provider not found: {name}')


def check(root, arch, *, reference=False, baseline=False, host_providers=False):
    if baseline and reference:
        raise ValueError('historical reference and Bullseye policy are exclusive')
    if host_providers and (not baseline or platform.machine() != arch or os.confstr('CS_GNU_LIBC_VERSION') != 'glibc 2.31'):
        raise ValueError('Bullseye provider checks require the actual native glibc 2.31 builder')
    root=root.resolve(strict=True);files=set(PLATFORM_FILES['linux_x86_64']);allowed=files|SYSTEM|{LOADER[arch]}
    definitions = {}
    system_providers = {}
    unexpected={p.name for p in root.iterdir() if re.search(r'\.so(?:\.|$)', p.name)}-files
    if unexpected:raise ValueError('unexpected libraries: '+', '.join(sorted(unexpected)))
    report={};warnings=[];required=set()
    for name in sorted(files):
        p=root/name
        if p.resolve(strict=True)!=p or not p.is_file() or not 20<=p.stat().st_size<=256*1024**2:
            raise ValueError('expected bounded, unlinked native library: '+name)
        with p.open('rb') as f:
            hdr=f.read(20)
            if hdr[:7]!=b'\x7fELF\x02\x01\x01' or int.from_bytes(hdr[16:18],'little')!=3 or int.from_bytes(hdr[18:20],'little')!=ELF_MACHINE[arch]:
                raise ValueError(f'{name}: expected native {arch} ELF shared object')
            digest=hashlib.sha256(hdr)
            for block in iter(lambda:f.read(1024*1024),b''):digest.update(block)
        if baseline:
            definitions[name] = provided_versions(p)
        guards=readelf('--dynamic',p)
        needs=set(re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]',guards))
        if needs-allowed:raise ValueError(f'{name}: unresolved native dependencies {sorted(needs-allowed)}')
        paths=[piece for entry in re.findall(r'\((?:RUNPATH|RPATH)\)\s+Library \w+: \[([^\]]*)\]',guards) for piece in entry.split(':')]
        if (name in EXPECTED and not set(paths)&{'$ORIGIN','${ORIGIN}'}) or any(x not in ('$ORIGIN','${ORIGIN}') for x in paths):
            issue=f'{name}: loader search path is not limited to the sibling directory'
            if not reference:raise ValueError(issue)
            warnings.append(issue)
        if baseline and (paths != ['$ORIGIN'] or '(RPATH)' in guards or '(RUNPATH)' not in guards):
            raise ValueError(f'{name}: expected exactly one DT_RUNPATH ($ORIGIN)')
        version_info = readelf('--version-info',p)
        versions=version_needs(version_info)
        if versions and max(versions)>GLIBC_MAX:raise ValueError(f'{name}: glibc requirement exceeds 2.39')
        required.update(versions)
        expected=EXPECTED.get(name,set())
        if expected:
            missing=expected-function_exports(readelf('--dyn-syms',p))
            if missing:raise ValueError(f'{name}: missing defined ABI functions {sorted(missing)}')
        report[name]=dict(sha256=digest.hexdigest(),needed=sorted(needs),loader_paths=paths,checked_exports=len(expected))
        if baseline:
            imports = needed_versions(version_info)
            if imports.keys() - needs:
                raise ValueError(f'{name}: version imports without matching DT_NEEDED')
            report[name].update(version_families=baseline_versions(imports, arch, name),
                                version_imports={p: sorted(v) for p, v in sorted(imports.items())})
    highest='.'.join(map(str,max(required))) if required else None
    result = dict(schema=2 if baseline else 1,
                  scope='historical reference analysis' if reference else 'new candidate static ABI preflight',arch=arch,
                  passed=True,runtime_proven=False,highest_glibc_dynamic_requirement=highest,
                  allowed_glibc_max='2.31' if baseline else '2.39',libraries=report,warnings=warnings)
    if baseline:
        if not highest:
            raise ValueError('Bullseye candidate must establish its dynamic glibc requirement')
        for name, item in report.items():
            for provider, versions in item['version_imports'].items():
                if host_providers and provider not in definitions:
                    path = host_provider(arch, provider)
                    definitions[provider] = provided_versions(path)
                    system_providers[provider] = dict(sha256=sha256(path), versions=sorted(definitions[provider]))
                if provider in definitions and set(versions) - definitions[provider]:
                    raise ValueError(f'{name}: {provider} lacks required versions {sorted(set(versions) - definitions[provider])}')
        result['system_dt_needed'] = sorted({p for item in report.values() for p in item['needed']} - files)
        if host_providers:
            result['host_provider_definitions'] = system_providers
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('runtime',type=Path)
    p.add_argument('--arch',choices=tuple(ELF_MACHINE),required=True);p.add_argument('--reference',action='store_true')
    p.add_argument('--baseline', action='store_true', help='require the native Bullseye ABI policy')
    p.add_argument('--host-providers', action='store_true', help='match version imports against the actual native Bullseye runtime')
    a=p.parse_args();print(json.dumps(check(a.runtime,a.arch,reference=a.reference,baseline=a.baseline,
                                           host_providers=a.host_providers),indent=2))
