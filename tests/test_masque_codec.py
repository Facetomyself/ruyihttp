# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

try:
    import pytest
except ModuleNotFoundError:
    import unittest
    raise unittest.SkipTest('MASQUE codec tests use pytest; wheel qualification installs it')

from ruyihttp._masque_codec import (
    CapsuleDecoder, CapsuleError, connect_headers, parse_proxy, target_path, udp_payload,
)


def test_default_and_restricted_custom_uri_expansion():
    assert target_path("[2001:DB8::42]", 443) == "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
    assert target_path("Bücher.example", 1) == "/.well-known/masque/udp/xn--bcher-kva.example/1/"
    assert target_path("remote.invalid.", 65535, "/udp?h={target_host}&p={target_port}&x=%2B") == (
        "/udp?h=remote.invalid.&p=65535&x=%2B"
    )


@pytest.mark.parametrize("host,port,template", [
    ("127.0.0.1", True, None), ("host.invalid", 0, None), ("host.invalid", 65536, None),
    ("host.invalid", "443", None), ("host.invalid?leak=", 443, None),
    ("fe80::1%eth0", 443, None), ("[badhost]", 443, None),
    ("host.invalid", 443, "https://px.invalid/{target_host}/{target_port}/"),
    ("host.invalid", 443, "//authority/{target_host}/{target_port}/"),
    ("host.invalid", 443, "/udp/{+target_host}/{target_port}/"),
    ("host.invalid", 443, "/udp/{target_host}/{target_port}/{bogus}/"),
    ("host.invalid", 443, "/udp/{target_host}/{target_port}/#frag"),
    ("host.invalid", 443, "/udp/{target_host}/{target_port}/%2"),
    ("host.invalid", 443, "/../udp/{target_host}/{target_port}/"),
    ("host.invalid", 443, "/udp/{target_host}/"),
])
def test_invalid_target_and_template(host, port, template):
    with pytest.raises(ValueError):
        target_path(host, port, template)


def test_proxy_authority_tls_endpoint_and_basic_redaction():
    proxy = parse_proxy("masque://fixture:p%40s%3As@[::1]:8443/")
    assert proxy.host == "::1"
    assert proxy.authority == "[::1]:8443"
    assert proxy.port == 8443
    assert "Basic" not in repr(proxy)
    assert "fixture" not in repr(proxy)
    assert dict(connect_headers(proxy, "/udp")) == {
        b":method": b"CONNECT", b":protocol": b"connect-udp", b":authority": b"[::1]:8443",
        b":scheme": b"https", b":path": b"/udp", b"capsule-protocol": b"?1",
        b"proxy-authorization": b"Basic Zml4dHVyZTpwQHM6cw==",
    }
    proxy = parse_proxy("masque://Bücher.example")
    assert (proxy.host, proxy.port, proxy.authority) == ("xn--bcher-kva.example", 443, "xn--bcher-kva.example")
    assert b"proxy-authorization" not in dict(connect_headers(proxy, "/udp"))


@pytest.mark.parametrize("url", [
    "socks5://host.invalid", "masque:///", "masque://host.invalid:", "masque://host.invalid:0",
    "masque://host.invalid:65536", "masque://host.invalid/path", "masque://host.invalid?",
    "masque://host.invalid#", "masque://[::1]junk:443", "masque://[::1]\\", "masque://[fe80::1%25eth0]",
    "masque://u%3Aname:bad@host.invalid", "masque://u:%0dbad@host.invalid",
    "masque://u:%ZZbad@host.invalid", "masque://u:s@bad@host.invalid", "masque://u:\tbad@host.invalid",
])
def test_proxy_parse_errors_do_not_expose_urls(url):
    with pytest.raises(ValueError) as caught:
        parse_proxy(url)
    assert url not in str(caught.value)
    assert "bad@" not in str(caught.value)


def test_context_zero_decoding_accepts_noncanonical_varints_and_empty_udp():
    assert udp_payload(b"\x00foo", 3) == b"foo"
    assert udp_payload(b"\x40\x00foo", 3) == b"foo"
    assert udp_payload(b"\x00", 0) == b""
    assert udp_payload(b"\x01foo", 3) is None
    assert udp_payload(b"\x81\x00\x00\x00foo", 3) is None
    assert udp_payload(b"\xff", 3) is None
    assert udp_payload(b"\x00foo", 2) is None
    with pytest.raises(CapsuleError):
        udp_payload(b"\x00" + b"a" * 65528, 3)


def test_incremental_decoder_handles_coalesced_and_fragmented_capsules():
    # Unknown (including empty) capsules and unknown contexts are discarded;
    # a legal empty UDP payload is still a datagram.
    stream = b"\x18\x00\x19\x03xyz\x00\x03\x01xx\x00\x01\x00\x00\x05\x40\x00abc"
    for chunk_size in range(1, len(stream) + 1):
        parser = CapsuleDecoder(3)
        result = []
        for i in range(0, len(stream), chunk_size):
            result.extend(parser.feed(stream[i:i + chunk_size]))
        parser.finish()
        assert result == [b"", b"abc"]


def test_huge_unknown_capsule_is_discarded_without_buffering():
    parser = CapsuleDecoder(3)
    assert list(parser.feed(b"\x19\xc0" + b"\x00" * 6 + b"\xff" + b"x" * 200)) == []
    assert len(parser._payload) == 0
    assert len(parser._header) == 0
    assert list(parser.feed(b"x" * 55 + b"\x00\x02\x00y")) == [b"y"]
    parser.finish()


@pytest.mark.parametrize("stream", [b"\x00\x00", b"\x00\x01\x40", b"\x00\x80\x01\x00\x00\x00"])
def test_malformed_datagram_capsules_are_rejected(stream):
    with pytest.raises(CapsuleError):
        list(CapsuleDecoder(100).feed(stream))


@pytest.mark.parametrize("stream", [b"\xff", b"\x00", b"\x00\x02\x00", b"\x01\x02x"])
def test_truncated_capsules_fail_on_clean_fin(stream):
    parser = CapsuleDecoder(8)
    list(parser.feed(stream))
    with pytest.raises(CapsuleError):
        parser.finish()
