#!/usr/bin/env python3
"""Test one built wheel under the selected native CPython interpreter."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    slot, expected_python, wheel_dir, evidence_dir = sys.argv[1:]
    assert platform.python_implementation() == "CPython"
    assert ".".join(map(str, sys.version_info[:2])) == expected_python, sys.version
    wheel, = Path(wheel_dir).resolve(strict=True).glob("*.whl")
    evidence = Path(evidence_dir).resolve() / expected_python
    evidence.mkdir(parents=True, exist_ok=True)
    print(f"{slot}: Python {sys.version} on {platform.platform()}", flush=True)
    print(f"{wheel.name} sha256={hashlib.sha256(wheel.read_bytes()).hexdigest()}", flush=True)
    env = os.environ.copy()
    for key in ("NECKO_CORE_LIBRARY", "NECKO_QUIC_LIBRARY", "RUYIHTTP_MACHINE", "RUYIHTTP_PLATFORM",
                "NECKO_FIREFOX", "PYTHONPATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
                "DYLD_FALLBACK_LIBRARY_PATH"):
        env.pop(key, None)
    env["RUYIHTTP_TEST_NATIVE_H3"] = "1"
    env["RUYIHTTP_REQUIRE_H3_IPV6"] = "1"
    manifest = json.loads((ROOT / 'ruyihttp/runtime-manifest.json').read_text(encoding='utf-8'))
    if manifest['platforms'][slot].get('h3_body_abi') == 1:
        env['RUYIHTTP_REQUIRE_H3_BODY_ABI'] = '1'
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if sys.platform == "darwin":
        prefix = subprocess.check_output(["brew", "--prefix", "openssl@3"], text=True).strip()
        env["PATH"] = str(Path(prefix) / "bin") + os.pathsep + env["PATH"]
    failed = []

    def run(name, command, required=False):
        print(f"::group::{name} (Python {expected_python})", flush=True)
        with (evidence / f"{name}.txt").open("w", encoding="utf-8") as log:
            proc = subprocess.Popen(command, env=env, cwd=evidence, stderr=subprocess.STDOUT,
                                    stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
            assert proc.stdout is not None
            for line in proc.stdout:
                print(line, end="", flush=True)
                log.write(line)
            status = proc.wait()
            log.write(f"Exit status: {status}\n")
        print(f"Exit status: {status}\n::endgroup::", flush=True)
        if status:
            failed.append(name)
        if required and status:
            raise SystemExit(f"{name} failed: {status}")

    def python(name, *args, **kwargs):
        run(name, [sys.executable, '-X', 'utf8', '-X', 'faulthandler', *map(str, args)], **kwargs)

    python("install", "-m", "pip", "install", f"{wheel}[masque,socks]", "aioquic==1.3.0", "pytest>=8.4.2,<10", required=True)
    python("pip-check", "-m", "pip", "check")
    python("installed-identity", "-I", ROOT / "ci/verify_installed.py", slot, wheel)
    python("upstream-trust-data", "-I", "-m", "unittest", "discover", "-s", ROOT / "tests", "-p", "test_upstream_trust_data.py", "-v")
    python("http1", "-I", ROOT / "ci/smoke_local.py")
    python("native-transactions", "-I", ROOT / "ci/smoke_native_target.py", slot)
    if manifest['platforms'][slot].get('h3_protocol_policy') == 1:
        python('posix-quic-policy', '-I', ROOT / 'ci/smoke_posix_quic_policy.py', slot)
    python('official-reference-identity', '-I', ROOT / 'ci/verify_reference_digests.py', slot, required=True)
    python("firefox-wire-comparator", "-I", "-m", "unittest", "discover", "-s", ROOT / "tests", "-p", "test_firefox_wire_gate.py", "-v")
    python("firefox-profile-wire", "-I", ROOT / "ci/smoke_firefox_profiles.py", slot,
           "--output", evidence / "firefox-profile-wire.jsonl")
    python('h2-official-preface', '-I', ROOT / 'ci/verify_h2_first_flight.py', slot,
           evidence / 'firefox-profile-wire.jsonl', evidence / 'h2-first-flight.json')
    python("full-h3", "-I", "-m", "unittest", "discover", "-s", ROOT / "tests", "-p", "test_http3_native.py", "-v")
    for module in ('test_h3_body_abi.py', 'test_alt_svc_native.py'):
        if (ROOT / 'tests' / module).is_file():
            python(module.removesuffix('.py'), '-I', '-m', 'unittest', 'discover',
                   '-s', ROOT / 'tests', '-p', module, '-v')
        elif module == 'test_h3_body_abi.py' and env.get('RUYIHTTP_REQUIRE_H3_BODY_ABI') == '1':
            print(f'::error::Required native ABI wire tests are missing: {module}', flush=True)
            failed.append(module)
    python("proxy", ROOT / "ci/smoke_proxy_chain.py")
    python('masque-controls', '-I', '-m', 'pytest', '-q', '--import-mode=importlib',
           ROOT / 'tests/test_masque_codec.py', ROOT / 'tests/test_masque_transport.py', ROOT / 'tests/test_masque_routing.py')
    python('masque-rfc9298', '-I', ROOT / 'ci/smoke_masque.py', '--json-output', evidence / 'masque-wire.json')
    if env.get('RUYIHTTP_MASQUE_GO_FIXTURE'):
        python('masque-go-interop', '-I', ROOT / 'ci/smoke_masque_go.py', env['RUYIHTTP_MASQUE_GO_FIXTURE'],
               '--json-output', evidence / 'masque-go.json')
    python("h2-eof", ROOT / "ci/smoke_h2_close.py")
    bash = Path(os.environ['ProgramFiles']) / 'Git/bin/bash.exe' if os.name == 'nt' else 'bash'
    run("request-boundaries", [str(bash), str(ROOT / "ci/verify_request_boundaries.sh")])
    if slot == "win_amd64" or env.get("RUYIHTTP_PREVIOUS_BUILD"):
        python("upgrade-0.9.0", "-I", ROOT / "ci/upgrade_from_090.py", wheel, slot)
    if env.get('RUYIHTTP_FORK_091_BUILD'):
        python('upgrade-fork-0.9.1', '-I', ROOT / 'ci/upgrade_from_090.py', wheel, slot, '--from-fork-091')
    if env.get('RUYIHTTP_RELEASE_092_DIR'):
        env['RUYIHTTP_UPGRADE_WIRE_EVIDENCE'] = str(evidence)
        python('upgrade-release-0.9.2', '-I', ROOT / 'ci/upgrade_from_090.py', wheel, slot, '--from-fork-092')
    if env.get('RUYIHTTP_RELEASE_093_DIR'):
        python('upgrade-release-0.9.3', '-I', ROOT / 'ci/upgrade_from_090.py', wheel, slot, '--from-fork-093')
    if failed:
        raise SystemExit("Failed runtime gates: " + ", ".join(failed))


if __name__ == "__main__":
    main()
