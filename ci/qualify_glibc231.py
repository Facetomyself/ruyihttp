#!/usr/bin/env python3
"""Qualify exactly one Linux wheel under the native Debian 11 runtime floor."""

import argparse
import ast
import ctypes
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen
import venv
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
OLD_COMMIT = "e8f8b02703239a18a75760d791c15936af632c40"
OLD_RELEASE = "https://github.com/Facetomyself/ruyihttp/releases/download/v0.9.3/"
BASE_PINS = {
    "x86_64": (4190558, "056729152736a3de16786cf466c290068c257a8e3771206db78314e468188b5b"),
    "aarch64": (4134064, "e0c7bdd60435f5f88619630428f6aa972b6c30a1d56baaa1ee7326861c5ed946"),
}
CEILINGS = {"GLIBC": (2, 31), "GLIBCXX": (3, 4, 28), "CXXABI": (1, 3, 12)}
PIP = ("-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "--no-cache-dir")
FIXTURES = ("aioquic==1.3.0",)


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_file(path, payload):
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def baseline(arch, directory, fetch=False):
    name = f"ruyihttp-0.9.3-py3-none-manylinux_2_39_{arch}.whl"
    size, digest = BASE_PINS[arch]
    path = directory / name
    if fetch:
        directory.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with urlopen(Request(OLD_RELEASE + name, headers={"User-Agent": "RuyiHttp-floor-qualification"}), timeout=45) as response:
                data = response.read(size + 1)
            require(len(data) == size and hashlib.sha256(data).hexdigest() == digest, "0.9.3 download integrity")
            with path.open("xb") as output:
                output.write(data)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == size and sha(path) == digest,
            "0.9.3 baseline integrity: " + str(path))
    return path


def clean_env():
    result = os.environ.copy()
    for name in list(result):
        if name.startswith(("LD_", "DYLD_", "PIP_", "NECKO_", "RUYIHTTP_")) or name in {
            "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "VIRTUAL_ENV", "http_proxy", "https_proxy",
            "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PYTHONUSERBASE",
        }:
            result.pop(name, None)
    result.update(PIP_CONFIG_FILE=os.devnull, PYTHONUTF8="1", PYTHONUNBUFFERED="1")
    return result


def capture(argv):
    return subprocess.check_output([*map(str, argv)], env=clean_env(), stderr=subprocess.STDOUT, text=True, timeout=45)


def log(evidence, name, argv, *, env=None, expected=0, reject_skip=False):
    target = evidence / (name + ".txt")
    print(f"::group::{name}", flush=True)
    with target.open("w", encoding="utf-8") as output:
        result = subprocess.run([*map(str, argv)], cwd=evidence, env=clean_env() if env is None else env,
                                stdout=output, stderr=subprocess.STDOUT, timeout=240, check=False)
    text = target.read_text(encoding="utf-8", errors="replace")
    print(text, end="", flush=True)
    print(f"Exit status: {result.returncode}\n::endgroup::", flush=True)
    require(result.returncode == expected, f"{name}: expected exit {expected}, got {result.returncode}")
    if reject_skip:
        require(re.search(r"^Ran [1-9][0-9]* tests? in ", text, re.M) and "skipped '" not in text,
                f"{name}: required unittest gate skipped tests or ran zero tests")
    return text


def pip_install(evidence, name, python, *requirements):
    filename = evidence / f"{name}.json"
    log(evidence, name, [python, *PIP, "install", "--index-url", "https://pypi.org/simple", "--only-binary=:all:",
                         "--report", filename, *requirements])
    return filename


def dependencies(path, wheel=None):
    result = {}
    for record in json.loads(path.read_text(encoding="utf-8"))["install"]:
        metadata = record["metadata"]
        download = record["download_info"]
        name = metadata["name"].lower()
        filename = Path(unquote(urlsplit(download["url"]).path)).name
        digest = download["archive_info"]["hashes"]["sha256"]
        require(filename.endswith(".whl") and re.fullmatch(r"[a-f0-9]{64}", digest), f"non-wheel dependency: {name}")
        if name == "ruyihttp":
            require(wheel is not None and filename == wheel.name and digest == sha(wheel), "pip selected wrong wheel bytes")
        result[name] = {"version": metadata["version"], "wheel": filename, "sha256": digest}
    if wheel is not None:
        require("ruyihttp" in result, "pip report omitted the requested wheel")
    return result


def new_venv(path):
    require(not path.exists(), f"expected a clean venv: {path}")
    venv.EnvBuilder(with_pip=True).create(path)
    return path / "bin/python"


def project_requirements():
    # The probe runs before candidate bytes exist, on 3.10 without tomllib.
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8").split("[project]", 1)[1].split("[project.", 1)[0]
    items = ast.literal_eval(re.search(r"^dependencies\s*=\s*(\[.*?^\])", text, re.M | re.S)[1])
    require(isinstance(items, list) and all(isinstance(item, str) for item in items), "invalid project requirements")
    return items


def wheel_info(directory, arch, mode):
    (wheel,) = directory.glob("*.whl")
    require(wheel.is_file() and not wheel.is_symlink(), "expected a plain candidate wheel file")
    tag = f"py3-none-manylinux_2_31_{arch}"
    match = re.fullmatch(rf"ruyihttp-([0-9A-Za-z.+_]+)-{tag}\.whl", wheel.name)
    require(match is not None, f"expected actual {tag} wheel, got {wheel.name}")
    version = match[1]
    require(version == "0.9.4" or (mode == "candidate" and re.fullmatch(r"0\.9\.4\.dev[0-9]+(?:\+[a-z0-9.]+)?", version)),
            f"incorrect {mode} wheel version: {version}")
    with ZipFile(wheel) as archive:
        tags = [line[5:] for line in archive.read(f"ruyihttp-{version}.dist-info/WHEEL").decode().splitlines()
                if line.startswith("Tag: ")]
        require(tags == [tag], f"internal wheel tags differ from filename: {tags}")
        metadata = archive.read(f"ruyihttp-{version}.dist-info/METADATA").decode().splitlines()
        require(f"Version: {version}" in metadata, "wheel metadata version differs from filename")
        extras = {line[16:] for line in metadata if line.startswith("Provides-Extra: ")}
    return wheel, version, extras


def floor_identity(arch, endpoint):
    require(platform.system() == "Linux" and platform.machine() == arch, f"wrong machine: {platform.machine()}")
    require(platform.python_implementation() == "CPython" and f"{sys.version_info.major}.{sys.version_info.minor}" == endpoint,
            f"wrong interpreter: {sys.version}")
    require(not any(key.startswith("LD_") for key in os.environ), "loader environment present before qualification")
    require(not os.environ.get("PYTHONPATH"), "host Python path present before qualification")
    preload = Path("/etc/ld.so.preload")
    require(not preload.exists() or not preload.read_text().strip(), "active /etc/ld.so.preload")
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    require("VERSION_CODENAME=bullseye" in release.splitlines(), release)
    glibc = capture(["getconf", "GNU_LIBC_VERSION"]).strip()
    require(glibc == os.confstr("CS_GNU_LIBC_VERSION") == "glibc 2.31", glibc)
    libc = ctypes.CDLL(None)
    libc.gnu_get_libc_version.restype = ctypes.c_char_p
    require(libc.gnu_get_libc_version() == b"2.31", "runtime glibc differs from getconf")
    packages = capture(["dpkg-query", "-W", "-f=${Package}\t${Version}\n", "libc6", "libgcc-s1", "libstdc++6", "libzstd1"])
    versions = dict(line.split("\t", 1) for line in packages.strip().splitlines())
    require(versions["libc6"].startswith("2.31-") and versions["libstdc++6"].startswith("10."), packages)
    stdcpp = (Path("/usr/lib") / f"{arch}-linux-gnu/libstdc++.so.6").resolve(strict=True)
    ceilings = defined_ceilings(capture(["readelf", "--version-info", "--wide", stdcpp]))
    require(ceilings == {k: v for k, v in CEILINGS.items() if k != "GLIBC"}, f"unexpected Bullseye C++ ceilings: {ceilings}")
    exe = Path(sys.executable).resolve(strict=True)
    python_ldd = capture(["ldd", exe])
    paths = ldd_paths(python_ldd, arch, exe.parent.parent / "lib")
    require(any(path.name.startswith("libc-") for path in paths), python_ldd)
    # ldd's ASLR addresses differ across the online and offline containers.
    python_ldd = re.sub(r"\(0x[0-9a-f]+\)", "(load address elided)", python_ldd)
    result = {"arch": arch, "python": sys.version.split()[0], "python_path": str(exe), "python_ldd": python_ldd,
              "glibc": glibc, "debian_packages": versions, "system_libstdc++": str(stdcpp),
              "system_cxx_ceilings": {k: version_string(v) for k, v in ceilings.items()}, "openssl": ssl.OPENSSL_VERSION}
    if endpoint == "3.14":
        result["python_source"] = (exe.parent.parent / "qualification-source.txt").read_text(encoding="utf-8").strip()
    return result


def version_string(version):
    return ".".join(map(str, version))


def defined_ceilings(readelf):
    definitions = readelf.split("Version definition section", 1)[1].split("Version needs section", 1)[0]
    result = {}
    for family in ("GLIBCXX", "CXXABI"):
        versions = re.findall(rf"\bName: {family}_([0-9]+(?:\.[0-9]+)+)\b", definitions)
        result[family] = max(tuple(map(int, item.split("."))) for item in versions)
    return result


def check_needed_versions(readelf, path):
    if "Version needs section" not in readelf:
        return {}
    requires = re.findall(r"\bName: (\S+)", readelf.split("Version needs section", 1)[1])
    result = {}
    for symbol in requires:
        family, _, version = symbol.partition("_")
        if family in CEILINGS:
            require(re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version), f"{path}: unexpected required ABI {symbol}")
            value = tuple(map(int, version.split(".")))
            require(value <= CEILINGS[family], f"{path}: {symbol} exceeds {family}_{version_string(CEILINGS[family])}")
            result[family] = max(result.get(family, value), value)
    return {family: version_string(version) for family, version in result.items()}


def ldd_paths(text, arch, extra=None):
    paths = []
    system = [(Path(p) / f"{arch}-linux-gnu").resolve() for p in ("/lib", "/usr/lib")]
    loader = (Path("/lib64/ld-linux-x86-64.so.2") if arch == "x86_64" else Path("/lib/ld-linux-aarch64.so.1")).resolve(strict=True)
    require("not found" not in text, text)
    for line in text.splitlines():
        words = line.strip().split()
        if not words or words[0].startswith("linux-vdso"):
            continue
        located = words[2] if len(words) > 2 and words[1] == "=>" else words[0]
        require(located.startswith("/"), f"unexpected ldd output: {line}")
        path = Path(located).resolve(strict=True)
        system_abi = re.match(r"(?:ld-2\.|ld-linux|lib(?:c-|c\.so|stdc\+\+|gcc_s))", path.name)
        require(path == loader or path.parent in system or (not system_abi and extra and path.parent == extra),
                f"unexpected library provider: {path}")
        paths.append(path)
    return paths


def native_tag_record(manifest, arch, mode):
    tag = f"manylinux_2_31_{arch}"
    historical = f"manylinux_2_39_{arch}"
    field = "linux_baseline" if manifest.get("wheel_platform_tag") == tag else "linux_baseline_candidate"
    require(field == "linux_baseline" or (mode == "candidate" and manifest.get("wheel_platform_tag") == historical),
            "release wheel must carry the admitted glibc 2.31 native manifest tag")
    measured = manifest[field]
    require(measured.get("policy") == "manylinux_2_31" and measured.get("candidate_tag") == tag
            and all(re.fullmatch(r"[a-f0-9]{64}", measured.get(key, "")) for key in ("elf_sha256", "build_sha256")),
            "native manifest does not record the pinned low-floor build and ELF policy")
    require(manifest.get("h3_body_abi") == manifest.get("h3_protocol_policy") == 1, "native H3 policies differ from the floor contract")
    return {"kind": field, "manifest_tag": manifest["wheel_platform_tag"], **measured}


def elf_receipt(arch, slot, evidence, wheel, mode):
    source = Path(importlib.util.find_spec("ruyihttp").origin).resolve().parent
    require(source.name == "ruyihttp" and source.parent.name == "site-packages" and source.is_relative_to(Path(sys.prefix).resolve()),
            f"package is not in this venv's site-packages: {source}")
    dist = importlib.metadata.distribution("ruyihttp")
    direct_url = json.loads(dist.read_text("direct_url.json"))
    require(direct_url["archive_info"]["hashes"]["sha256"] == sha(wheel), "installed distribution points to wrong bytes")
    manifest = json.loads((source / "runtime-manifest.json").read_text(encoding="utf-8"))["platforms"][slot]
    native_tag = native_tag_record(manifest, arch, mode)
    libraries = dict(manifest["files"])
    require(len(libraries) == 14 and {p.name for p in source.glob("*.so")} == set(libraries), "wrong native file set")
    maximums = {}
    resolved = {}
    with ZipFile(wheel) as archive, (evidence / "native-elf-loader.txt").open("w", encoding="utf-8") as output:
        for name, digest in sorted(libraries.items()):
            path = source / name
            require(sha(path) == digest == hashlib.sha256(archive.read("ruyihttp/" + name)).hexdigest(), str(path))
            elf = capture(["readelf", "--version-info", "--wide", path])
            ldd = capture(["ldd", path])
            maximums[name] = check_needed_versions(elf, name)
            resolved[name] = [str(p) for p in ldd_paths(ldd, arch, source)]
            output.write(f"{name} sha256={digest}\n{ldd}\n")
            if "Version needs section" in elf:
                output.write("Version needs section" + elf.split("Version needs section", 1)[1] + "\n")
    highest = max(tuple(map(int, v["GLIBC"].split("."))) for v in maximums.values() if "GLIBC" in v)
    require(manifest["highest_glibc_dynamic_requirement"] == version_string(highest), "actual glibc symbol maximum differs from manifest")
    return {"site_packages": str(source), "native_sha256": libraries, "native_required_abi_maxima": maximums,
            "highest_glibc_dynamic_requirement": version_string(highest), "native_loader_paths": resolved, "native_policy": native_tag}


def require_network_offline():
    require(sorted(os.listdir("/sys/class/net")) == ["lo"], "runtime gate must see only the loopback interface")


def suite(evidence, slot, wheel, *, masque=False):
    env = clean_env()
    env.update(RUYIHTTP_TEST_NATIVE_H3="1", RUYIHTTP_REQUIRE_H3_IPV6="1", RUYIHTTP_REQUIRE_H3_BODY_ABI="1",
               RUYIHTTP_TEST_NATIVE_RETRY="1", PYTHON=str(sys.executable))
    results = []

    def python(name, *args, tests=False):
        log(evidence, name, [sys.executable, "-I", "-X", "faulthandler", *args], env=env, reject_skip=tests)
        results.append(name)

    if masque:
        python("masque-rfc9298", ROOT / "ci/smoke_masque.py", "--json-output", evidence / "masque-wire.json")
        return results
    python("installed-identity", ROOT / "ci/verify_installed.py", slot, wheel)
    python("http1", ROOT / "ci/smoke_local.py")
    python("native-h2-h3", ROOT / "ci/smoke_native_target.py", slot)
    python("posix-quic-policy", ROOT / "ci/smoke_posix_quic_policy.py", slot)
    python("profile-reference", ROOT / "ci/verify_reference_digests.py", slot)
    profile_trace = evidence / "firefox-profile-wire.jsonl"
    python("profile-wire", ROOT / "ci/smoke_firefox_profiles.py", slot, "--output", profile_trace)
    python("h2-preface", ROOT / "ci/verify_h2_first_flight.py", slot, profile_trace, evidence / "h2-first-flight.json")
    for module in ("test_http3_native", "test_h3_body_abi", "test_alt_svc_native"):
        python(module, "-m", "unittest", "discover", "-s", ROOT / "tests", "-p", module + ".py", "-v", tests=True)
    python("proxy-chain", ROOT / "ci/smoke_proxy_chain.py")
    python("h2-eof", ROOT / "ci/smoke_h2_close.py")
    log(evidence, "request-boundaries", ["bash", ROOT / "ci/verify_request_boundaries.sh"], env=env)
    results.append("request-boundaries")
    return results


def install(args, identity):
    arch = args.slot.removeprefix("linux_")
    evidence, state = args.evidence, args.state
    old = baseline(arch, args.old)
    python = new_venv(state / "venv")
    supported = log(evidence, "pip-debug", [python, *PIP, "debug", "--verbose"])
    require(f"py3-none-manylinux_2_31_{arch}\n" in supported and f"py3-none-manylinux_2_32_{arch}" not in supported
            and f"py3-none-manylinux_2_39_{arch}" not in supported, "pip tag ceiling differs from actual glibc")
    rejected = log(evidence, "reject-093", [python, *PIP, "install", old], expected=1)
    require("is not a supported wheel on this platform" in rejected and old.name in rejected,
            "pip failed for a reason other than the incompatible v0.9.3 tag")
    present = capture([python, "-I", "-c", "from importlib.util import find_spec; print(find_spec('ruyihttp'))"])
    require(present.strip() == "None", "v0.9.3 was installed, or the environment is contaminated")
    identity["negative_093"] = {"wheel": old.name, "sha256": sha(old), "commit": OLD_COMMIT, "pip_rejected": True}
    if args.mode == "probe":
        base = pip_install(evidence, "base-install", python, *project_requirements())
    else:
        wheel, version, extras = wheel_info(args.wheels, arch, args.mode)
        identity["wheel"] = {"filename": wheel.name, "version": version, "sha256": sha(wheel)}
        base = pip_install(evidence, "base-install", python, wheel)
    identity["base_dependencies"] = dependencies(base, None if args.mode == "probe" else wheel)
    require("cryptography" in identity["base_dependencies"], "clean base install did not resolve cryptography")
    # Fixture packages go into the already-receipted environment; they cannot
    # make the clean base realization pass and have their own resolver report.
    fixture_deps = pip_install(evidence, "fixtures-install", python, "PySocks>=1.5.6,!=1.5.7", *FIXTURES)
    identity["fixture_dependencies"] = dependencies(fixture_deps)
    log(evidence, "pip-check", [python, *PIP, "check"])
    log(evidence, "pip-list", [python, *PIP, "list", "--format=json"])
    masque_fixture = (ROOT / "ci/smoke_masque.py").is_file()
    if args.mode == "release":
        require({"masque", "socks"} <= extras and masque_fixture, "required MASQUE/SOCKS extra or loopback fixture absent")
    if args.mode != "probe" and "masque" in extras:
        require("socks" in extras, "MASQUE floor fixture requires the SOCKS extra")
        identity["masque_status"] = "wire-required" if masque_fixture else "dependency-only-uncombined-source-candidate"
        masque_python = new_venv(state / "masque")
        identity["masque_dependencies"] = dependencies(pip_install(evidence, "masque-install", masque_python, f"{wheel}[masque,socks]"), wheel)
        log(evidence, "masque-pip-check", [masque_python, *PIP, "check"])
    json_file(evidence / "installation.json", identity)


def verify(args, identity):
    require_network_offline()
    arch = args.slot.removeprefix("linux_")
    evidence, state = args.evidence, args.state
    installed = json.loads((evidence / "installation.json").read_text(encoding="utf-8"))
    differing = [key for key, value in identity.items() if installed[key] != value]
    require(not differing, f"installation and runtime environment differ: {differing}")
    installed["container"] = json.loads((evidence / "image.json").read_text(encoding="utf-8"))
    probe = """
import brotli, cryptography, zstandard, aioquic, h2, requests, socks
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
import sys
assert generate_private_key(SECP256R1()).key_size == 256
assert brotli.decompress(brotli.compress(b'test')) == b'test'
assert zstandard.ZstdDecompressor().decompress(zstandard.ZstdCompressor().compress(b'test')) == b'test'
if sys.version_info < (3, 14):
    from backports import zstd
else:
    from compression import zstd
assert zstd.decompress(zstd.compress(b'test')) == b'test'
print('cryptography', cryptography.__version__, 'validated EC, Brotli and Zstandard from installed wheels')
"""
    python = state / "venv/bin/python"
    log(evidence, "dependency-runtime", [python, "-I", "-X", "faulthandler", "-c", probe])
    installed.update(network="loopback-only", mode=args.mode, slot=args.slot)
    if args.mode != "probe":
        wheel, _, _ = wheel_info(args.wheels, arch, args.mode)
        require(installed["wheel"]["sha256"] == sha(wheel), "runtime wheel bytes differ from installation receipt")
        runtime = log(evidence, "runtime-suite", [python, "-I", __file__, "suite", args.slot, args.endpoint,
                                                  args.wheels, args.evidence, args.state, args.old, args.mode])
        require("" != runtime, "no runtime evidence")
        installed.update(json.loads((evidence / "native-runtime.json").read_text(encoding="utf-8")))
        if installed.get("masque_status") == "wire-required":
            log(evidence, "masque-suite", [state / "masque/bin/python", "-I", __file__, "masque", args.slot, args.endpoint,
                                          args.wheels, args.evidence, args.state, args.old, args.mode])
            require((evidence / "masque-wire.json").is_file(), "MASQUE wire receipt is missing")
            installed["masque_status"] = "wire-passed"
            installed["gates"].append("masque-rfc9298")
    json_file(evidence / "summary.json", installed)
    print(json.dumps(installed, sort_keys=True), flush=True)


def upgrade(args):
    arch = args.slot.removeprefix("linux_")
    require(platform.system() == "Linux" and platform.machine() == arch, "wrong modern machine")
    glibc = os.confstr("CS_GNU_LIBC_VERSION")
    require(tuple(map(int, glibc.split()[1].split("."))) >= (2, 39), f"modern upgrade requires glibc >= 2.39, got {glibc}")
    require(platform.python_implementation() == "CPython" and f"{sys.version_info.major}.{sys.version_info.minor}" == args.endpoint,
            f"wrong modern interpreter: {sys.version}")
    old = baseline(arch, args.old, fetch=True)
    wheel, version, _ = wheel_info(args.wheels, arch, args.mode)
    with tempfile.TemporaryDirectory(prefix="ruyihttp-floor-upgrade-") as temp:
        python = new_venv(Path(temp) / "venv")
        old_deps = dependencies(pip_install(args.evidence, "old-install", python, old), old)
        log(args.evidence, "old-version", [python, "-I", "-c", "import ruyihttp; assert ruyihttp.__version__ == '0.9.3'"])
        log(args.evidence, "old-http1", [python, "-I", ROOT / "ci/smoke_local.py"])
        new_deps = dependencies(pip_install(args.evidence, "upgrade-install", python, "--upgrade", wheel), wheel)
        log(args.evidence, "new-version", [python, "-I", "-c", "import importlib.metadata as m, ruyihttp, sys; assert [d.version for d in m.distributions(name='ruyihttp')] == [ruyihttp.__version__] == sys.argv[1:]", version])
        log(args.evidence, "new-identity", [python, "-I", ROOT / "ci/verify_installed.py", args.slot, wheel])
        log(args.evidence, "new-http1", [python, "-I", ROOT / "ci/smoke_local.py"])
        log(args.evidence, "upgrade-pip-check", [python, *PIP, "check"])
        json_file(args.evidence / "summary.json", {"glibc": glibc, "from_commit": OLD_COMMIT, "slot": args.slot,
                   "python": sys.version.split()[0], "baseline": old_deps, "upgraded": new_deps})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase", choices=("fetch-old", "install", "verify", "suite", "masque", "upgrade"))
    p.add_argument("slot", choices=("linux_x86_64", "linux_aarch64"))
    p.add_argument("endpoint", choices=("3.10", "3.14"))
    for name in ("wheels", "evidence", "state", "old"):
        p.add_argument(name, type=lambda s: Path(s).resolve())
    p.add_argument("mode", choices=("release", "candidate", "probe"))
    args = p.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    arch = args.slot.removeprefix("linux_")
    if args.phase == "fetch-old":
        print(baseline(arch, args.old, fetch=True))
    elif args.phase == "upgrade":
        upgrade(args)
    elif args.phase in {"suite", "masque"}:
        require_network_offline()
        wheel, _, _ = wheel_info(args.wheels, arch, args.mode)
        if args.phase == "suite":
            receipt = elf_receipt(arch, args.slot, args.evidence, wheel, args.mode)
            receipt["gates"] = suite(args.evidence, args.slot, wheel)
            json_file(args.evidence / "native-runtime.json", receipt)
        else:
            suite(args.evidence, args.slot, wheel, masque=True)
    else:
        identity = floor_identity(arch, args.endpoint)
        getattr(sys.modules[__name__], args.phase)(args, identity)


if __name__ == "__main__":
    main()
