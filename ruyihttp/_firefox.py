# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import copy
import ipaddress
import os
import platform as _platform
import re
import sys
from http.cookiejar import DefaultCookiePolicy
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from publicsuffixlist import PublicSuffixList
from requests.cookies import RequestsCookieJar, get_cookie_header
from requests.structures import CaseInsensitiveDict


def data_path(name, directory=None):
    runtime = os.environ.get("NECKO_CORE_LIBRARY")
    if directory is not None or runtime:
        base = (
            Path(directory).expanduser()
            if directory is not None
            else Path(runtime).expanduser().resolve().parent
        )
        for candidate in (base / name, base / "ruyihttp" / name, base / "necko" / name):
            if candidate.is_file():
                return candidate
    local = Path(__file__).with_name(name)
    return local


_suffix_file = data_path("firefox-suffixes.dat")
if _suffix_file.is_file():
    with _suffix_file.open(encoding="utf-8") as _suffix_data:
        _SUFFIXES = PublicSuffixList(_suffix_data)
else:
    _SUFFIXES = PublicSuffixList()
# Compatibility default. Selectable profiles are not tied to build provenance.
DEFAULT_FIREFOX = "159"


def client_platform(os_name=None, platform_name=None):
    """Host class for client fingerprints. Windows measurements stay on win_amd64."""
    os_name = os.name if os_name is None else os_name
    platform_name = sys.platform if platform_name is None else platform_name
    if os_name == "nt":
        return "win_amd64"
    if platform_name == "darwin":
        return "darwin"
    if platform_name.startswith("linux"):
        return "linux"
    return "other"


def _machine(machine=None):
    if machine is None:
        machine = os.environ.get("RUYIHTTP_MACHINE") or _platform.machine()
    return (machine or "").lower()


def runtime_platform(os_name=None, platform_name=None, machine=None):
    """Native runtime directory and manifest key for the current host."""
    name = client_platform(os_name, platform_name)
    machine = _machine(machine)
    if name == "win_amd64":
        return "win_amd64"
    if name == "darwin":
        return "darwin_arm64" if machine in ("arm64", "aarch64") else "darwin_x86_64"
    if name == "linux":
        return "linux_aarch64" if machine in ("aarch64", "arm64") else "linux_x86_64"
    return "other"


def _user_agent(version, platform=None):
    # Firefox 110-119 froze the rv: token at 109 (network.http.useragent.forceRVOnly).
    # The OS token is Firefox's own reduced UA, not a captured ClientHello.
    # macOS stays "Intel Mac OS X 10.15" on Apple Silicon as well.
    platform = client_platform() if platform is None else platform
    if platform.startswith("darwin"):
        platform = "darwin"
    elif platform.startswith("linux"):
        platform = "linux"
    rv = 109 if 110 <= version <= 119 else version
    if platform == "win_amd64":
        system = "Windows NT 10.0; Win64; x64"
    elif platform == "darwin":
        system = "Macintosh; Intel Mac OS X 10.15"
    elif platform == "linux":
        machine = _machine()
        system = "X11; Linux aarch64" if machine in ("aarch64", "arm64") else "X11; Linux x86_64"
    else:
        raise RuntimeError(
            "User-Agent was measured for Windows x64, Macintosh and Linux x86_64. "
            f"Refusing to reuse the Windows token for {platform}."
        )
    return (
        f"Mozilla/5.0 ({system}; rv:{rv}.0) "
        f"Gecko/20100101 Firefox/{version}.0"
    )


PROFILE_PLATFORMS = ("win_amd64", "darwin", "linux")


def require_profile_platform(kind, platform=None):
    platform = client_platform() if platform is None else platform
    if platform in PROFILE_PLATFORMS:
        return platform
    raise RuntimeError(f"{kind} have no profile table for {platform}.")


def quic_profile(version, platform=None):
    require_profile_platform("QUIC profiles", platform)
    return PROFILES[str(version)]["quic"]


def _accept(version):
    if version >= 132:
        return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    if version >= 128:
        return (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
        )
    return (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    )


def _priority(version):
    # RFC 9218 Priority header for (navigation, fetch); absent before 126.
    if version >= 128:
        return ("u=0, i", "u=4")
    if version >= 126:
        return ("u=1", "u=4")
    return None


def _h2_settings(version):
    # SETTINGS in wire order: HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE,
    # MAX_FRAME_SIZE, NO_RFC7540_PRIORITIES.
    settings = [(1, 65536)]
    if version >= 132:
        settings.append((2, 0))
    settings += [(4, 131072), (5, 16384)]
    if version in (128, 132):
        settings.append((9, 1))
    return tuple(settings)


_QUIC_SIGNATURES = (0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806,
                    0x0401, 0x0501, 0x0601, 0x0201)


def _quic(version):
    """QUIC and HTTP/3 behaviour, as necko_quic's Profile. Older releases
    shipped older Neqo, which this reproduces through the build's patches."""
    if version >= 135:
        groups, shares = [0x11EC, 0x1D, 0x17, 0x18, 0x19], 2
    elif version >= 124:
        groups, shares = [0x1D, 0x17, 0x18, 0x19], 1
    else:
        groups, shares = [0x1D, 0x17, 0x18, 0x19, 0x100, 0x101, 0x102, 0x103, 0x104], 0
    signatures = list(_QUIC_SIGNATURES)
    if version == 156:
        # Neqo offered ML-DSA for one release, before security.tls.enable_mldsa.
        signatures[7:7] = [0x0904, 0x0905, 0x0906]
    if version >= 147:
        datagram = 65535
    elif version >= 145:
        datagram = 1500
    elif version >= 114:
        datagram = 1200
    else:
        datagram = 0
    if version >= 139:
        style = 0  # fixed order
    elif version >= 124:
        style = 1  # shuffled
    elif version >= 106:
        style = 2  # shuffled, draft version_information
    else:
        style = 3  # shuffled, no version_information
    return {
        "groups": groups,
        "additional_key_shares": shares,
        "signatures": signatures,
        "compression": [1, 3, 2] if version >= 143 else [],
        "grease_ech": version >= 119,
        "sni_slicing": version >= 137,
        "grease_quic_bit": version < 132,
        "disable_migration": version < 132,
        "max_streams": 100 if version >= 147 else 16,
        "datagram_size": datagram,
        "version2": version >= 155,
        "reliable_stream_reset": version >= 155,
        "tp_style": style,
        "mtu_bonus": 105 if version < 130 else 0,
        "h3_datagram": version >= 145,
    }


def _h3_priority(version):
    # Neqo itself sent a Priority header, right after the pseudo-headers,
    # until 125 stopped it; 126 and later send Firefox's own at the end.
    return ("u=1", "u=4") if version < 125 else None


# Per-version behaviour outside the TLS ClientHello, which is in _tls_profiles.
# Measured from the official builds' HTTP/1.1 and HTTP/2 requests.
PROFILES = {
    str(version): {
        "user_agent": _user_agent(version),
        "accept": _accept(version),
        "accept_language": "en-US,en;q=0.9" if version >= 147 else "en-US,en;q=0.5",
        "accept_encoding": "gzip, deflate, br, zstd" if version >= 126 else "gzip, deflate, br",
        "priority": _priority(version),
        "h2_settings": _h2_settings(version),
        # RFC 7540 dependency tree of idle streams 3-13, sent before requests.
        "h2_priority_tree": version < 132 and version != 128,
        "h3_protocol_error_fallback": version >= 159,
        "quic": _quic(version),
        "h3_priority": _h3_priority(version),
    }
    for version in range(100, 162)
}
FIREFOX_VERSIONS = tuple(PROFILES)
USER_AGENT = PROFILES[DEFAULT_FIREFOX]["user_agent"]


def firefox_version(value):
    """Normalize a Firefox version choice ("160", "161.0", "firefox-161").

    None falls back to the NECKO_FIREFOX environment variable, then
    DEFAULT_FIREFOX.
    """
    version = str(value or os.environ.get("NECKO_FIREFOX") or DEFAULT_FIREFOX)
    version = version.strip().lower()
    version = version.removeprefix("firefox-").removeprefix("firefox").strip()
    version = version.removesuffix(".0")
    if version not in PROFILES:
        raise ValueError(
            f"unsupported Firefox version {value!r}; choose "
            f"{FIREFOX_VERSIONS[0]}-{FIREFOX_VERSIONS[-1]}"
        )
    return version
ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


_IPV4_NUMBER = re.compile(r"(?:[0-9]+|0[xX][0-9a-fA-F]*)")


def _ip_host(host):
    """Canonical IP host, or the full spelling of an ambiguous numeric host."""
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            return host

    # URL IPv4 hosts can have a single final dot and legacy decimal, octal,
    # or hex components. Never reduce an ambiguous numeric host through PSL.
    parts = host.removesuffix(".").split(".")
    if not any(parts) or any(p and not _IPV4_NUMBER.fullmatch(p) for p in parts):
        return None
    if len(parts) > 4 or not all(parts):
        return host

    address = 0
    for index, part in enumerate(parts):
        if part.startswith(("0x", "0X")):
            base, digits = 16, part[2:]
            if not digits:
                return host
        else:
            base, digits = (8 if part.startswith("0") else 10), part
        digits = digits.lstrip("0") or "0"
        if len(digits) > 11:  # Even 32-bit octal fits in 11 digits.
            return host
        try:
            value = int(digits, base)
        except ValueError:
            return host
        bits = 8 if index < len(parts) - 1 else 8 * (5 - len(parts))
        if value >= 1 << bits:
            return host
        address = (address << bits) | value
    return str(ipaddress.IPv4Address(address))


def origin(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    host = _ip_host(host) or host
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    if port and port != (443 if parsed.scheme == "https" else 80):
        host += f":{port}"
    return f"{parsed.scheme}://{host}"


def site(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    # Only DNS names have registrable domains; an IP site's host is the full address.
    return parsed.scheme, _ip_host(host) or _SUFFIXES.privatesuffix(host) or host


def relation(source, target):
    if not source:
        return "none"
    if origin(source) == origin(target):
        return "same-origin"
    return "same-site" if site(source) == site(target) else "cross-site"


def trustworthy(url):
    parsed = urlsplit(url)
    if parsed.scheme == "https" or parsed.hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def default_headers(context, firefox=DEFAULT_FIREFOX):
    version = firefox_version(firefox)
    profile = PROFILES[version]
    return CaseInsensitiveDict([
        ("User-Agent", _user_agent(int(version))),
        ("Accept", profile["accept"] if context == "navigation" else "*/*"),
        ("Accept-Language", profile["accept_language"]),
        ("Accept-Encoding", profile["accept_encoding"]),
        ("Connection", "keep-alive"),
    ])


def apply_headers(
    request, context, document_url, user_activation=True, firefox=DEFAULT_FIREFOX
):
    profile = PROFILES[firefox_version(firefox)]
    headers = request.headers
    if not hasattr(request, "_firefox_explicit"):
        request._firefox_explicit = set(headers)
    explicit = request._firefox_explicit
    if headers.get("Accept-Encoding") == profile["accept_encoding"] and not trustworthy(
        request.url
    ):
        headers["Accept-Encoding"] = "gzip, deflate"
    reference = document_url or headers.get("Referer")
    relationship = relation(reference, request.url)
    computed = {}
    if context == "navigation":
        computed["Upgrade-Insecure-Requests"] = "1"
    if trustworthy(request.url):
        computed.update({
            "Sec-Fetch-Dest": "document" if context == "navigation" else "empty",
            "Sec-Fetch-Mode": "navigate" if context == "navigation" else "cors",
            "Sec-Fetch-Site": relationship,
        })
        if context == "navigation" and user_activation:
            computed["Sec-Fetch-User"] = "?1"
    if profile["priority"]:
        computed["Priority"] = profile["priority"][context != "navigation"]
    if reference:
        secure_downgrade = (
            urlsplit(reference).scheme == "https"
            and urlsplit(request.url).scheme != "https"
        )
        if not secure_downgrade:
            parsed = urlsplit(reference)
            computed["Referer"] = (
                urlunsplit((
                    parsed.scheme,
                    urlsplit(origin(reference)).netloc,
                    parsed.path or "/",
                    parsed.query,
                    "",
                ))
                if relationship == "same-origin"
                else origin(reference) + "/"
            )
        if (
            request.method not in ("GET", "HEAD")
            or context == "fetch"
            and relationship != "same-origin"
        ):
            computed["Origin"] = origin(reference)
    elif request.method not in ("GET", "HEAD"):
        computed["Origin"] = "null"
    for name in (
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
        "Upgrade-Insecure-Requests",
        "Priority",
        "Referer",
        "Origin",
    ):
        if name not in explicit:
            headers.pop(name, None)
            if name in computed:
                headers[name] = computed[name]
    request._firefox_context = context
    request._firefox_document = reference


def wire_headers(headers, http2):
    ordered = CaseInsensitiveDict()
    first = (
        "Host",
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Referer",
        "Origin",
        "Content-Type",
        "Content-Length",
        "Connection",
        "Cookie",
        "Alt-Used",
        "Upgrade-Insecure-Requests",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
        "Priority",
    )
    for name in first:
        if name in headers:
            ordered[name] = headers[name]
    for name, value in headers.items():
        if name not in ordered:
            ordered[name] = value
    if http2:
        ordered["TE"] = "trailers"
    return ordered


class CookiePolicy(DefaultCookiePolicy):
    def __init__(self, context="navigation", document_url=None):
        super().__init__(strict_ns_domain=self.DomainStrictNonDomain)
        self.context = context
        self.document_url = document_url

    def set_ok(self, cookie, request):
        if not super().set_ok(cookie, request):
            return False
        domain = cookie.domain.lstrip(".")
        if cookie.domain_specified and _SUFFIXES.publicsuffix(domain) == domain:
            return False
        if cookie.secure and not trustworthy(request.get_full_url()):
            return False
        if cookie.name.startswith("__Secure-") and not cookie.secure:
            return False
        if cookie.name.startswith("__Host-") and (
            not cookie.secure or cookie.domain_specified or cookie.path != "/"
        ):
            return False
        same_site = self.same_site(cookie)
        return same_site != "none" or cookie.secure

    def return_ok(self, cookie, request):
        if not super().return_ok(cookie, request):
            return False
        if not self.document_url or site(self.document_url) == site(
            request.get_full_url()
        ):
            return True
        same_site = self.same_site(cookie)
        if same_site == "none":
            return cookie.secure
        return (
            same_site != "strict"
            and self.context == "navigation"
            and (
                request.get_method()
                if hasattr(request, "get_method")
                else request._r.method
            )
            in ("GET", "HEAD", "OPTIONS", "TRACE")
        )

    @staticmethod
    def same_site(cookie):
        return str(
            next(
                (
                    value
                    for key, value in cookie._rest.items()
                    if key.lower() == "samesite"
                ),
                "Lax",
            )
        ).lower()


def apply_cookies(request, context, document_url):
    jar = getattr(request, "_cookies", None)
    if jar is not None:
        for cookie in list(jar):
            if not cookie.domain:
                bound = copy.copy(cookie)
                bound.domain = urlsplit(request.url).hostname
                if "." not in bound.domain and ":" not in bound.domain:
                    bound.domain += ".local"
                jar.clear(cookie.domain, cookie.path, cookie.name)
                jar.set_cookie(bound)
        jar.set_policy(CookiePolicy(context, document_url))
        if getattr(request, "_firefox_cookie_header", False):
            request.headers.pop("Cookie", None)
            value = get_cookie_header(jar, request)
            if value:
                request.headers["Cookie"] = value


def cookie_jar(context, document_url):
    return RequestsCookieJar(policy=CookiePolicy(context, document_url))
