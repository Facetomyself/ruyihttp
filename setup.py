"""Platform wheel tag. Native files are copied from native/<platform>/."""

import hashlib
import json
import os
import platform
import re
import shutil
import sys
from pathlib import Path

from setuptools import Distribution
from setuptools.command.build_py import build_py
from wheel.bdist_wheel import bdist_wheel

ROOT = Path(__file__).resolve().parent

# The historical Linux default stays 2.39 until exact bytes have a measured
# and admitted lower floor. macOS tags use measured Mach-O deployment targets.
PLATFORMS = {
    "win_amd64": ("py3", "none", "win_amd64"),
    "linux_x86_64": ("py3", "none", "manylinux_2_39_x86_64"),
    "linux_aarch64": ("py3", "none", "manylinux_2_39_aarch64"),
    "darwin_arm64": ("py3", "none", "macosx_26_0_arm64"),
    "darwin_x86_64": ("py3", "none", None),
}
SOURCE_SLOTS = {"linux_aarch64", "darwin_x86_64", "darwin_arm64"}


def source_entry(name):
    data = json.loads((ROOT / "ruyihttp/runtime-manifest.json").read_text(encoding="utf-8"))
    entry = data["platforms"][name]
    if entry.get("status") != "ready" or not entry.get("files"):
        raise SystemExit(f"native runtime missing: native/{name} is build-required")
    return entry


def host_platform():
    override = os.environ.get("RUYIHTTP_PLATFORM")
    if override:
        if override not in PLATFORMS:
            raise SystemExit(f"unsupported RUYIHTTP_PLATFORM: {override}")
        return override
    if os.name == "nt":
        return "win_amd64"
    machine = platform_machine()
    if sys.platform == "darwin":
        if machine == "arm64":
            return "darwin_arm64"
        if machine == "x86_64":
            return "darwin_x86_64"
    if machine == "x86_64":
        return "linux_x86_64"
    if machine in ("aarch64", "arm64"):
        return "linux_aarch64"
    raise SystemExit(f"unsupported host platform: {sys.platform} {machine}")


def platform_machine():
    return os.environ.get("RUYIHTTP_MACHINE") or platform.machine().lower()


def linux_tag(name):
    arch = "aarch64" if name == "linux_aarch64" else "x86_64"
    entry = source_entry(name)
    source = ROOT / 'native' / name
    provenance = json.loads((source / 'provenance.json').read_text(encoding='utf-8'))
    # The build runs outside the package and never imports or loads these DSOs.
    sys.path.insert(0, str(ROOT / 'tools'))
    try:
        from linux_baseline import FLOOR, validate_policy_records
        measured = validate_policy_records(name, entry, provenance, source)
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise SystemExit(f'{name}: {error}') from error
    finally:
        sys.path.pop(0)
    if measured is not None:
        actual = os.confstr('CS_GNU_LIBC_VERSION') if sys.platform == 'linux' else ''
        libc = re.fullmatch(r'glibc (\d+)\.(\d+)', actual or '')
        if platform.machine() != arch or not libc or tuple(map(int, libc.groups())) < (2, 31):
            raise SystemExit(f'{name}: measured Linux wheels require a native glibc {FLOOR}+ build host')
        if os.environ.get('RUYIHTTP_GLIBC', FLOOR) != FLOOR:
            raise SystemExit(f'RUYIHTTP_GLIBC must equal the measured floor {FLOOR}')
        if 'linux_baseline_candidate' in entry:
            manifest = json.loads((ROOT / 'ruyihttp/runtime-manifest.json').read_text(encoding='utf-8'))
            if (os.environ.get('RUYIHTTP_BUILD_BASELINE_CANDIDATE') != '1' or
                    not re.fullmatch(r'\d+\.\d+\.\d+\.dev[1-9]\d*\+gha\.[1-9]\d*', manifest['version'])):
                raise SystemExit(f'{name}: measured but unadmitted baseline requires a stamped diagnostic build')
        return measured['candidate_tag']
    # Historical bytes may keep their original floor or be tagged more narrowly.
    version = os.environ.get('RUYIHTTP_GLIBC', '2.39')
    match = re.fullmatch(r'(\d+)\.(\d+)', version)
    if not match or tuple(map(int, match.groups())) < (2, 39):
        raise SystemExit(f'RUYIHTTP_GLIBC must be major.minor >= 2.39, got {version!r}')
    return f'manylinux_{match[1]}_{match[2]}_{arch}'


PROFILE_DATA = {'firefox-profile.json', 'firefox-root-constraints.json', 'firefox-roots.pem', 'firefox-suffixes.dat'}


def verify_profile_data(directory, manifest):
    files = manifest.get('data', {})
    if set(files) != PROFILE_DATA:
        raise SystemExit('profile/trust data inventory differs from the expected set')
    for name, digest in files.items():
        path = directory / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit(f'profile/trust data hash differs from manifest: {name}')


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


class BundleNative(build_py):
    def run(self):
        super().run()
        self.bundle_native(host_platform())
        destination = Path(self.build_lib) / 'ruyihttp'
        manifest = json.loads((destination / 'runtime-manifest.json').read_text(encoding='utf-8'))
        verify_profile_data(destination, manifest)

    def bundle_native(self, host_name):
        source = ROOT / "native" / host_name
        files = [
            path
            for path in source.glob("*")
            if path.is_file() and path.suffix.lower() in {".dll", ".dylib", ".so"}
        ]
        if not files:
            raise SystemExit(
                f"native runtime missing: {source}. "
                "Windows DLLs are in native/win_amd64. "
                "macOS needs libnecko_core.dylib and libnecko_quic.dylib "
                "in native/darwin_arm64 or native/darwin_x86_64."
            )
        manifest = json.loads((ROOT / 'ruyihttp' / 'runtime-manifest.json').read_text(encoding='utf-8'))
        entry = manifest['platforms'][host_name]
        if entry.get('status') != 'ready':
            raise SystemExit(f"native runtime not ready: {host_name}")
        expected = entry.get('files', {})
        if {path.name for path in files} != set(expected):
            raise SystemExit(f"native inventory differs from manifest: {host_name}")
        for path in files:
            if host_name in SOURCE_SLOTS and path.is_symlink():
                raise SystemExit(f"native candidate is a symlink: {host_name}/{path.name}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected[path.name]:
                raise SystemExit(f"native hash differs from manifest: {host_name}/{path.name}")
        destination = Path(self.build_lib) / "ruyihttp"
        destination.mkdir(parents=True, exist_ok=True)
        for stale in destination.iterdir():
            if stale.is_file() and stale.suffix.lower() in {".dll", ".dylib", ".so"}:
                stale.unlink()
        for path in files:
            shutil.copy2(path, destination / path.name)
        provenance = source / 'provenance.json'
        record = json.loads(provenance.read_text(encoding='utf-8'))
        if record.get('platform') != host_name or {n: v.get('sha256') for n, v in record.get('files', {}).items()} != expected:
            raise SystemExit(f'native provenance differs from manifest: {host_name}')
        # Expose this specific slot's source, patch and verification receipt to
        # wheel-only consumers, too. Repackaging does not create new provenance.
        shutil.copyfile(provenance, destination / 'native-provenance.json')


class PlatformWheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        name = host_platform()
        if name.startswith('linux_'):
            return 'py3', 'none', linux_tag(name)
        if name in SOURCE_SLOTS:
            tag = source_entry(name).get('wheel_platform_tag', '')
            if not re.fullmatch(r'macosx_\d+_\d+_' + name.removeprefix('darwin_'), tag):
                raise SystemExit(f'missing or invalid measured wheel platform tag: {name}')
            return 'py3', 'none', tag
        return PLATFORMS[name]


setup = __import__("setuptools").setup
if __name__ == "__main__":
    setup(
        distclass=BinaryDistribution,
        cmdclass={"build_py": BundleNative, "bdist_wheel": PlatformWheel},
    )
