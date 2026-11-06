"""Platform wheel tag. Native files are copied from native/<platform>/."""

import os
import shutil
import sys
from pathlib import Path

from setuptools import Distribution
from setuptools.command.build_py import build_py
from wheel.bdist_wheel import bdist_wheel

ROOT = Path(__file__).resolve().parent

# win_amd64 matches the published 0.9.0 wheel.
# linux_x86_64 matches the 0.8.1 PyPI wheel tag; 0.9.0 has no Linux wheel.
# darwin_arm64 minos 26.0 was read from the arm64 libnecko_core.dylib
# built on the Mac mini (LC_BUILD_VERSION). darwin_x86_64 has no binary.
PLATFORMS = {
    "win_amd64": ("py3", "none", "win_amd64"),
    "linux_x86_64": ("py3", "none", "manylinux_2_31_x86_64"),
    "darwin_arm64": ("py3", "none", "macosx_26_0_arm64"),
    "darwin_x86_64": ("py3", "none", "macosx_11_0_x86_64"),
}


def host_platform():
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
    raise SystemExit(f"unsupported host platform: {sys.platform} {machine}")


def platform_machine():
    return os.environ.get("RUYIHTTP_MACHINE") or __import__("platform").machine().lower()


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


class BundleNative(build_py):
    def run(self):
        super().run()
        self.bundle_native(host_platform())

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
        destination = Path(self.build_lib) / "ruyihttp"
        destination.mkdir(parents=True, exist_ok=True)
        for path in files:
            shutil.copy2(path, destination / path.name)


class PlatformWheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        return PLATFORMS[host_platform()]


setup = __import__("setuptools").setup
if __name__ == "__main__":
    setup(
        distclass=BinaryDistribution,
        cmdclass={"build_py": BundleNative, "bdist_wheel": PlatformWheel},
    )
