#!/usr/bin/env python3
"""Read-only Linux native-set ABI preflight. No library loading or promotion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from build_native import PLATFORM_FILES

ELF_MACHINE={'x86_64':62,'aarch64':183}
LOADER={'x86_64':'ld-linux-x86-64.so.2','aarch64':'ld-linux-aarch64.so.1'}
SYSTEM={'libc.so.6','libm.so.6','libdl.so.2','libpthread.so.0','librt.so.1','libgcc_s.so.1','libstdc++.so.6'}
GLIBC_MAX=(2,39)
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


def check(root, arch, *, reference=False):
    root=root.resolve(strict=True);files=set(PLATFORM_FILES['linux_x86_64']);allowed=files|SYSTEM|{LOADER[arch]}
    unexpected={p.name for p in root.iterdir() if p.name.endswith('.so')}-files
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
        guards=readelf('--dynamic',p)
        needs=set(re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]',guards))
        if needs-allowed:raise ValueError(f'{name}: unresolved native dependencies {sorted(needs-allowed)}')
        paths=[piece for entry in re.findall(r'\((?:RUNPATH|RPATH)\)\s+Library \w+: \[([^\]]*)\]',guards) for piece in entry.split(':')]
        if (name in EXPECTED and not set(paths)&{'$ORIGIN','${ORIGIN}'}) or any(x not in ('$ORIGIN','${ORIGIN}') for x in paths):
            issue=f'{name}: loader search path is not limited to the sibling directory'
            if not reference:raise ValueError(issue)
            warnings.append(issue)
        versions=version_needs(readelf('--version-info',p))
        if versions and max(versions)>GLIBC_MAX:raise ValueError(f'{name}: glibc requirement exceeds 2.39')
        required.update(versions)
        expected=EXPECTED.get(name,set())
        if expected:
            missing=expected-function_exports(readelf('--dyn-syms',p))
            if missing:raise ValueError(f'{name}: missing defined ABI functions {sorted(missing)}')
        report[name]=dict(sha256=digest.hexdigest(),needed=sorted(needs),loader_paths=paths,checked_exports=len(expected))
    highest='.'.join(map(str,max(required))) if required else None
    return dict(schema=1,scope='historical reference analysis' if reference else 'new candidate static ABI preflight',arch=arch,
                passed=True,runtime_proven=False,highest_glibc_dynamic_requirement=highest,allowed_glibc_max='2.39',libraries=report,warnings=warnings)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('runtime',type=Path)
    p.add_argument('--arch',choices=tuple(ELF_MACHINE),required=True);p.add_argument('--reference',action='store_true')
    a=p.parse_args();print(json.dumps(check(a.runtime,a.arch,reference=a.reference),indent=2))
