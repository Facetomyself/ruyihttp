# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ruyihttp import _firefox, _http3, _nss, _transport

import setup
WIN_DLL_NAMES = {
    path.name for path in (ROOT / "native" / "win_amd64").glob("*.dll")
}


class _Export:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class _NativeLibrary:
    """Stand-in for the loaded Necko library. configure_library is not mocked."""

    def __init__(self, nss_version):
        self._nss_version = nss_version

    def __getattr__(self, name):
        if not name.startswith("necko_tls_"):
            raise AttributeError(name)
        value = self._nss_version if name == "necko_tls_nss_version" else None
        function = _Export(value)
        setattr(self, name, function)
        return function


@contextmanager
def windows_path(module):
    """Keep pathlib on WindowsPath while os.name is temporarily posix.

    CPython 3.13 selects PosixPath from os.name, and that class cannot be
    constructed after pathlib was imported on Windows.
    """
    saved = module.Path
    module.Path = pathlib.WindowsPath
    try:
        yield
    finally:
        module.Path = saved


@contextmanager
def driven_host(os_name, platform_name, machine):
    saved = (os.name, sys.platform, os.environ.get("RUYIHTTP_MACHINE"))
    os.name = os_name
    sys.platform = platform_name
    os.environ["RUYIHTTP_MACHINE"] = machine
    try:
        yield
    finally:
        os.name = saved[0]
        sys.platform = saved[1]
        if saved[2] is None:
            os.environ.pop("RUYIHTTP_MACHINE", None)
        else:
            os.environ["RUYIHTTP_MACHINE"] = saved[2]


class RuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self._saved_env = {
            key: os.environ.get(key)
            for key in (
                "NECKO_CORE_LIBRARY",
                "NECKO_QUIC_LIBRARY",
                "RUYIHTTP_MACHINE",
            )
        }
        for key in self._saved_env:
            os.environ.pop(key, None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_default_core_names_follow_the_platform(self):
        package = Path(_transport.__file__).resolve().parent
        # 真实宿主可能是 linux/darwin。Windows 名字走 driven_host 时会遇到
        # pathlib 的 WindowsPath 无法在 POSIX 上实例化（Python 限制），
        # 因此首个断言按真实宿主取名字，其余两个平台用 driven_host 覆盖。
        with self.assertRaises(FileNotFoundError) as error:
            _transport._load_library()
        message = str(error.exception)
        host_name = {
            "win_amd64": "necko_core.dll",
            "darwin": "libnecko_core.dylib",
            "linux": "libnecko_core.so",
        }[_firefox.client_platform()]
        self.assertIn(str(package / host_name), message)
        self.assertIn("NECKO_CORE_LIBRARY", message)
        self.assertIn("Session(library_path=...)", message)
        cases = (
            ("posix", "darwin", "arm64", "libnecko_core.dylib"),
            ("posix", "linux", "x86_64", "libnecko_core.so"),
        )
        for os_name, platform_name, machine, filename in cases:
            with self.subTest(filename=filename):
                # Only simulate the loader's OS, not pathlib's real filesystem.
                with patch.object(_transport, 'os', SimpleNamespace(name=os_name, environ=os.environ)), \
                     patch.object(_transport, 'sys', SimpleNamespace(platform=platform_name)):
                    with self.assertRaises(FileNotFoundError) as caught:
                        _transport._load_library()
                caught_message = str(caught.exception)
                self.assertIn(str(package / filename), caught_message)
                self.assertIn("NECKO_CORE_LIBRARY", caught_message)
                self.assertIn("Session(library_path=...)", caught_message)

    def test_environment_selects_missing_core_library(self):
        library = self.root / "external.dll"
        with _env(NECKO_CORE_LIBRARY=str(library)):
            with self.assertRaises(FileNotFoundError) as error:
                _transport._load_library()
        message = str(error.exception)
        self.assertIn(str(library.resolve()), message)
        self.assertIn("NECKO_CORE_LIBRARY", message)
        self.assertIn("Session(library_path=...)", message)

    def test_explicit_path_overrides_environment(self):
        from_env = self.root / "from-env.dll"
        from_arg = self.root / "from-arg.dll"
        with _env(NECKO_CORE_LIBRARY=str(from_env)):
            with self.assertRaises(FileNotFoundError) as error:
                _transport._load_library(from_arg)
        message = str(error.exception)
        self.assertIn(str(from_arg.resolve()), message)
        self.assertNotIn(str(from_env.resolve()), message)

    def test_quic_names_and_environment_override(self):
        # 用真实宿主平台取名字（POSIX 上无法构造 WindowsPath）。
        host_core = {
            "win_amd64": "necko_core.dll",
            "darwin": "libnecko_core.dylib",
            "linux": "libnecko_core.so",
        }[_firefox.client_platform()]
        host_quic = {
            "win_amd64": "necko_quic.dll",
            "darwin": "libnecko_quic.dylib",
            "linux": "libnecko_quic.so",
        }[_firefox.client_platform()]
        core = self.root / "runtime" / host_core
        core.parent.mkdir()
        core.write_bytes(b"")
        # 宿主平台缺 quic 库时，_http3 可能抛 FileNotFoundError（找不到路径）
        # 或 OSError（dlopen 失败），取决于库里是先查还是直接加载。
        with self.assertRaises((FileNotFoundError, OSError)) as error:
            _http3.Connection("example.test", 443, None, core, 1)
        self.assertIn(host_quic, str(error.exception))
        cases = (
            ("posix", "darwin", "arm64", "libnecko_quic.dylib"),
            ("posix", "linux", "x86_64", "libnecko_quic.so"),
        )
        for os_name, platform_name, machine, filename in cases:
            with self.subTest(filename=filename):
                with patch.object(_http3, 'os', SimpleNamespace(name=os_name, environ=os.environ)), \
                     patch.object(_http3, 'sys', SimpleNamespace(platform=platform_name)):
                    # POSIX 上 dlopen 失败的异常类型是 OSError；库里缺文件时才是 FileNotFoundError
                    with self.assertRaises((FileNotFoundError, OSError)) as caught:
                        _http3.Connection("example.test", 443, None, core, 1)
                self.assertIn(filename, str(caught.exception))
        override = self.root / "override-necko-quic"
        with _env(NECKO_QUIC_LIBRARY=str(override)):
            with self.assertRaises((FileNotFoundError, OSError)) as error:
                _http3.Connection("example.test", 443, None, core, 1)
        self.assertIn(str(override), str(error.exception))

    def test_nss_gate_compares_packaged_version(self):
        # 期望版本随宿主平台取 manifest 值（win_amd64=3.131，linux/darwin=3.132），
        # 不能硬编码成 Windows 那一档。
        expected = _nss.expected_nss_version()
        _nss.configure_library(_NativeLibrary(expected))
        wrong = b"3.130" if expected != b"3.130" else b"3.129"
        with self.assertRaisesRegex(
            RuntimeError,
            r"^firefox-159 requires the packaged NSS "
            + expected.decode()
            + r" runtime$",
        ):
            _nss.configure_library(_NativeLibrary(wrong))

    def test_data_path_searches_runtime_layouts(self):
        runtime = self.root / "ext" / "necko_core.dll"
        runtime.parent.mkdir()
        runtime.write_bytes(b"")
        name = "contract-marker.dat"
        layouts = (
            runtime.parent / name,
            runtime.parent / "ruyihttp" / name,
            runtime.parent / "necko" / name,
        )
        for target in layouts:
            with self.subTest(target=target.parent.name):
                for path in layouts:
                    if path.exists():
                        path.unlink()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("marker", encoding="utf-8")
                with _env(NECKO_CORE_LIBRARY=str(runtime)):
                    found = _firefox.data_path(name)
                self.assertEqual(found.resolve(), target.resolve())

    def test_platform_profiles_and_user_agents(self):
        windows = _firefox._user_agent(159, "win_amd64")
        mac = _firefox._user_agent(159, "darwin")
        with driven_host("posix", "linux", "x86_64"):
            linux = _firefox._user_agent(159, "linux")
        self.assertIn("Windows NT 10.0; Win64; x64", windows)
        self.assertIn("Macintosh; Intel Mac OS X 10.15", mac)
        self.assertNotIn("Windows", mac)
        # Linux UA 的架构部分随 RUYIHTTP_MACHINE / 真实机器变化（x86_64 或 aarch64）
        self.assertRegex(linux, r"X11; Linux (x86_64|aarch64)")
        self.assertNotIn("Windows", linux)
        frozen = _firefox._user_agent(112, "darwin")
        self.assertIn("rv:109.0", frozen)
        self.assertIn("Firefox/112.0", frozen)
        with driven_host("posix", "darwin", "arm64"):
            self.assertEqual(_firefox.client_platform(), "darwin")
            self.assertEqual(_firefox.runtime_platform(), "darwin_arm64")
            headers = _firefox.default_headers("navigation", "159")
        self.assertEqual(headers["User-Agent"], mac)
        with driven_host("posix", "linux", "x86_64"):
            self.assertEqual(_firefox.client_platform(), "linux")
            self.assertEqual(_firefox.runtime_platform(), "linux_x86_64")
            self.assertEqual(
                _firefox.default_headers("navigation", "159")["User-Agent"],
                linux,
            )
        built_darwin = _nss.native_profile("159", platform="darwin")
        built_linux = _nss.native_profile("159", platform="linux")
        self.assertEqual(built_darwin.cipher_count, len(_nss.TLS_PROFILES["159"].ciphers))
        self.assertEqual(built_linux.cipher_count, len(_nss.TLS_PROFILES["159"].ciphers))
        self.assertTrue(_firefox.quic_profile("159", platform="darwin"))
        self.assertTrue(_firefox.quic_profile("159", platform="linux"))
        with self.assertRaisesRegex(RuntimeError, "have no profile table"):
            _nss.native_profile("159", platform="other")
        with driven_host("nt", "win32", "amd64"):
            self.assertEqual(_firefox.client_platform(), "win_amd64")
        built = _nss.native_profile("159")
        self.assertEqual(built.cipher_count, len(_nss.TLS_PROFILES["159"].ciphers))

    def test_host_platform_matches_this_host(self):
        if os.name == "nt":
            with _env(RUYIHTTP_MACHINE="arm64"):
                self.assertEqual(setup.host_platform(), "win_amd64")
        else:
            # 非 Windows 宿主：host_platform() 返回 darwin_* / linux_*，
            # 不能固定为 win_amd64。
            self.assertTrue(setup.host_platform().startswith(("darwin", "linux")),
                            f"host_platform()={setup.host_platform()}")
        self.assertEqual(setup.PLATFORMS["win_amd64"], ("py3", "none", "win_amd64"))

    def test_exports_match_documented_abi(self):
        records = json.loads((ROOT / "native" / "win_amd64" / "exports.json").read_text(encoding="utf-8"))
        by_file = {record["file"]: record for record in records}
        for record in records:
            self.assertEqual(record["machine"], "0x8664")
        core = [name for name in by_file["necko_core.dll"]["exports"] if name.startswith("necko_")]
        quic = [name for name in by_file["necko_quic.dll"]["exports"] if name.startswith("necko_quic_")]
        self.assertEqual(len(core), 50)
        self.assertEqual(len(by_file["necko_core.dll"]["exports"]), 50)
        self.assertEqual(quic, by_file["necko_quic.dll"]["exports"])
        self.assertEqual(len(quic), 4)

    def test_darwin_arm64_has_core_and_quic(self):
        slot = ROOT / "native" / "darwin_arm64"
        names = {
            path.name
            for path in slot.rglob("*")
            if path.is_file() and path.suffix.lower() == ".dylib"
        }
        self.assertEqual(
            names,
            {
                "libnecko_core.dylib",
                "libnecko_quic.dylib",
                "libnss3.dylib",
                "libmozglue.dylib",
                "libfreebl3.dylib",
                "libsoftokn3.dylib",
            },
        )
        intel = [
            path.name
            for path in (ROOT / "native" / "darwin_x86_64").rglob("*")
            if path.is_file() and path.suffix.lower() in {".dylib", ".so"}
        ]
        self.assertEqual(intel, [])

    def test_linux_native_layout(self):
        slot = ROOT / "native" / "linux_x86_64"
        names = {
            path.name
            for path in slot.rglob("*")
            if path.is_file() and path.suffix.lower() == ".so"
        }
        self.assertTrue(
            {
                "libnecko_core.so",
                "libnecko_quic.so",
                "libnss3.so",
                "libnspr4.so",
                "libssl3.so",
                "libnssutil3.so",
                "libsoftokn3.so",
                "libfreeblpriv3.so",
                "libsqlite3.so",
                "libnssckbi.so",
                "libnsssysinit.so",
            }.issubset(names)
        )
        self.assertIn("libfreebl3.so", names)

    def test_runtime_manifest_platform_matrix(self):
        manifest = json.loads(
            (ROOT / "ruyihttp" / "runtime-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["default"], "win_amd64")
        self.assertEqual(manifest["platforms"]["win_amd64"]["nss"], "3.131")
        self.assertEqual(manifest["platforms"]["darwin_arm64"]["nss"], "3.132")
        self.assertEqual(manifest["platforms"]["linux_x86_64"]["nss"], "3.132")
        self.assertEqual(
            manifest["platforms"]["darwin_x86_64"]["status"], "build-required"
        )
        self.assertIn("libnecko_quic.dylib", manifest["platforms"]["darwin_arm64"]["files"])
        self.assertIn("libnecko_quic.so", manifest["platforms"]["linux_x86_64"]["files"])

    def test_nss_gate_reads_manifest(self):
        self.assertEqual(_nss.expected_nss_version("win_amd64"), b"3.131")
        self.assertEqual(_nss.expected_nss_version("darwin_arm64"), b"3.132")
        self.assertEqual(_nss.expected_nss_version("linux_x86_64"), b"3.132")
        _nss.configure_library(_NativeLibrary(b"3.132"), expected_nss=b"3.132")
        with self.assertRaisesRegex(
            RuntimeError,
            r"^firefox-159 requires the packaged NSS 3\.132 runtime$",
        ):
            _nss.configure_library(_NativeLibrary(b"3.131"), expected_nss=b"3.132")

    def test_windows_build_copies_native_dlls(self):
        build_lib = self.root / "win-build"
        # 用 RUYIHTTP_PLATFORM 显式指定目标平台，避免依赖宿主 os.name/platform。
        # 这是 setup.py 已支持的官方覆盖方式（docs/build-native.md）。
        with _env(RUYIHTTP_PLATFORM="win_amd64"):
            self.assertEqual(setup.host_platform(), "win_amd64")
            command = _build_py(build_lib)
            command.run()
        packaged = {path.name for path in (build_lib / "ruyihttp").glob("*.dll")}
        self.assertEqual(packaged, WIN_DLL_NAMES)

    def test_darwin_x86_64_missing_native_does_not_package_windows_dlls(self):
        with driven_host("posix", "darwin", "x86_64"):
            selected = setup.host_platform()
        self.assertEqual(selected, "darwin_x86_64")
        build_lib = self.root / selected
        command = _build_py(build_lib)
        with self.assertRaises(SystemExit) as error:
            command.bundle_native(selected)
        message = str(error.exception)
        self.assertIn("native runtime missing", message)
        self.assertIn(str(ROOT / "native" / selected), message)
        packaged = [
            path.name
            for path in build_lib.rglob("*")
            if path.is_file() and path.name in WIN_DLL_NAMES
        ]
        self.assertEqual(packaged, [])

    def test_darwin_arm64_bundle_copies_dylibs_not_windows_dlls(self):
        with driven_host("posix", "darwin", "arm64"):
            selected = setup.host_platform()
        self.assertEqual(selected, "darwin_arm64")
        self.assertEqual(setup.PLATFORMS[selected][2], "macosx_26_0_arm64")
        build_lib = self.root / selected
        command = _build_py(build_lib)
        command.bundle_native(selected)
        packaged = {path.name for path in (build_lib / "ruyihttp").glob("*.dylib")}
        self.assertEqual(
            packaged,
            {
                "libnecko_core.dylib",
                "libnecko_quic.dylib",
                "libnss3.dylib",
                "libmozglue.dylib",
                "libfreebl3.dylib",
                "libsoftokn3.dylib",
            },
        )
        windows = [
            path.name
            for path in build_lib.rglob("*")
            if path.is_file() and path.name in WIN_DLL_NAMES
        ]
        self.assertEqual(windows, [])

    def test_linux_bundle_copies_so_not_windows_dlls(self):
        with driven_host("posix", "linux", "x86_64"):
            selected = setup.host_platform()
        self.assertEqual(selected, "linux_x86_64")
        self.assertEqual(setup.PLATFORMS[selected][2], "manylinux_2_39_x86_64")
        build_lib = self.root / selected
        command = _build_py(build_lib)
        command.bundle_native(selected)
        packaged = {path.name for path in (build_lib / "ruyihttp").glob("*.so")}
        self.assertIn("libnecko_core.so", packaged)
        self.assertIn("libnecko_quic.so", packaged)
        self.assertIn("libnss3.so", packaged)
        windows = [
            path.name
            for path in build_lib.rglob("*")
            if path.is_file() and path.name in WIN_DLL_NAMES
        ]
        self.assertEqual(windows, [])

    def test_bundle_removes_stale_other_platform_native_files(self):
        build_lib = self.root / "stale-build"
        package = build_lib / "ruyihttp"
        package.mkdir(parents=True)
        (package / "libnecko_core.so").write_bytes(b"stale")
        command = _build_py(build_lib)
        command.bundle_native("win_amd64")
        self.assertFalse((package / "libnecko_core.so").exists())
        self.assertTrue((package / "necko_core.dll").exists())

    def test_linux_tag_uses_build_host_glibc(self):
        with _env(RUYIHTTP_GLIBC="2.31"):
            self.assertEqual(setup.linux_tag("linux_x86_64"), "manylinux_2_31_x86_64")
            self.assertEqual(setup.linux_tag("linux_aarch64"), "manylinux_2_31_aarch64")


def _build_py(build_lib):
    from setuptools import Distribution

    dist = Distribution(
        {
            "name": "ruyihttp",
            "version": "0.9.0",
            "packages": ["ruyihttp"],
            "package_dir": {"": str(ROOT)},
            "package_data": {"ruyihttp": ["*.json", "*.pem", "*.dat", "licenses/*"]},
            "cmdclass": {"build_py": setup.BundleNative},
            "script_name": str(ROOT / "setup.py"),
        }
    )
    command = dist.get_command_obj("build_py")
    command.ensure_finalized()
    command.build_lib = str(build_lib)
    command.compile = False
    return command


@contextmanager
def _env(**values):
    saved = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
