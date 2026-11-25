"""Trust material reuse never bypasses hostname, CA rotation or per-client identity."""

import ctypes
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import VerificationError

from ruyihttp import _nss
from ruyihttp._native_buffer import read_bytes
from ruyihttp._trust import TrustCache


def certs(label):
    now = datetime.now(timezone.utc)
    key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])

    def builder(subject, public, ca):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                False,
            )
            .add_extension(
                x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False),
                True,
            )
        )

    root = builder(issuer, key.public_key(), True).sign(key, hashes.SHA256())
    leaf = (
        builder(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ok.example")]),
            leaf_key.public_key(),
            False,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("ok.example")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, hashes.SHA256())
    )
    return root, leaf, leaf_key


class TrustTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.d = Path(tmp.name)
        self.cache = TrustCache(2, 16384)
        swap = patch.object(_nss, "TRUST_MATERIALS", self.cache)
        swap.start()
        self.addCleanup(swap.stop)
        self.a, self.leaf, self.key = certs("one")
        self.b, self.leaf_b, _ = certs("two")
        self.pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
        self.wire = _nss._certificate_bytes(self.leaf)
        self.roots = self.d / "roots.pem"
        self.roots.write_bytes(self.pem(self.a))

    def test_hot_store_reused_but_verifier_is_per_peer(self):
        with patch.object(
            x509, "load_pem_x509_certificates", wraps=x509.load_pem_x509_certificates
        ) as load:
            a, b = [_nss.Context(self.roots, None) for _ in range(2)]
            self.assertIs(a.store, b.store)
            self.assertEqual(a.identity, b.identity)
            self.assertEqual(load.call_count, 1)
        b.verify("ok.example", self.wire)
        with self.assertRaises(VerificationError):
            b.verify("wrong.example", self.wire)
        with self.assertRaises(VerificationError):
            b.verify("ok.example", _nss._certificate_bytes(self.leaf_b))

    def test_rotation_detected_even_if_stat_size_and_mtime_match(self):
        size = max(map(len, (self.pem(self.a), self.pem(self.b)))) + 8
        self.roots.write_bytes(self.pem(self.a).ljust(size, b"\n"))
        a = _nss.Context(self.roots, None)
        stamp = self.roots.stat()
        self.roots.write_bytes(self.pem(self.b).ljust(size, b"\n"))
        os.utime(self.roots, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        b = _nss.Context(self.roots, None)
        self.assertIsNot(a.store, b.store)
        self.assertNotEqual(a.identity, b.identity)
        b.verify("ok.example", _nss._certificate_bytes(self.leaf_b))
        with self.assertRaises(VerificationError):
            b.verify("ok.example", self.wire)
        self.roots.unlink()
        with self.assertRaises(OSError):
            _nss.Context(self.roots, None)

    def test_constraints_are_read_only_and_rotate_resumption_partition(self):
        roots = self.d / "firefox-roots.pem"
        roots.write_bytes(self.pem(self.a))
        side = self.d / "firefox-root-constraints.json"
        side.write_text("{}")
        first = _nss.Context(True, None, self.d)
        first.verify("ok.example", self.wire)
        custom = _nss.Context(roots, None)
        self.assertIsNot(custom.store, first.store)
        fingerprint = hashlib.sha256(
            self.a.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        side.write_text(json.dumps({fingerprint: "210101000000Z"}))
        second = _nss.Context(True, None, self.d)
        self.assertNotEqual(first.identity, second.identity)
        with self.assertRaises(TypeError):
            second.constraints["bad"] = "change"
        with self.assertRaises(ssl.SSLCertVerificationError):
            second.verify("ok.example", self.wire)
        custom.verify("ok.example", self.wire)
        side.write_text("{bad")
        with self.assertRaises(ValueError):
            _nss.Context(True, None, self.d)

    def test_bad_constraints_never_replace_or_fall_back_to_good_snapshot(self):
        f = self.d / "constraints.json"
        digest = "ab" * 32
        for data in [
            b"[]",
            b'{"bad":"210101000000Z"}',
            json.dumps({digest: "211901000000Z"}).encode(),
            (
                '{"%s":"210101000000Z","%s":"220101000000Z"}' % (digest, digest.upper())
            ).encode(),
        ]:
            with self.subTest(data=data):
                f.write_bytes(b"{}")
                good = self.cache.load(self.roots, f)
                f.write_bytes(data)
                with self.assertRaises(ValueError):
                    self.cache.load(self.roots, f)
                f.write_bytes(b"{}")
                self.assertIs(self.cache.load(self.roots, f), good)

    def test_directory_membership_and_bounded_entries(self):
        ca_dir = self.d / "cas"
        ca_dir.mkdir()
        path = ca_dir / "1"
        path.write_bytes(self.pem(self.a))
        a = _nss.Context(ca_dir, None)
        (ca_dir / "2").write_bytes(self.pem(self.b))
        b = _nss.Context(ca_dir, None)
        self.assertIsNot(a.store, b.store)
        b.verify("ok.example", self.wire)
        path.unlink()
        c = _nss.Context(ca_dir, None)
        with self.assertRaises(VerificationError):
            c.verify("ok.example", self.wire)
        self.assertLessEqual(len(self.cache._items), 2)
        self.assertLessEqual(self.cache._bytes, 16384)
        tiny = TrustCache(8, 8)
        self.assertIsNot(tiny.load(self.roots).store, tiny.load(self.roots).store)
        self.assertEqual(len(tiny._items), 0)

    def test_unverified_and_client_identity_are_not_cached(self):
        with patch.object(
            self.cache,
            "load",
            side_effect=AssertionError("looked up unverified context"),
        ):
            self.assertIsNone(_nss.Context(False, None).store)
        cert = self.d / "client.pem"
        cert.write_bytes(self.pem(self.leaf))
        key = self.d / "client.key"
        key.write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        ordinary = _nss.Context(self.roots, None)
        a, b = [_nss.Context(self.roots, (cert, key)) for _ in range(2)]
        self.assertIs(ordinary.store, a.store)
        self.assertNotEqual(a.identity, ordinary.identity)
        self.assertEqual(a.identity, b.identity)
        a.key = b""
        self.assertTrue(b.key)
        self.assertFalse(ordinary.key)
        self.assertEqual(len(self.cache._items), 1)
        key.write_bytes(b"broken")
        with self.assertRaises(ValueError):
            _nss.Context(self.roots, (cert, key))

    def test_concurrent_readers_share_only_the_material(self):
        with ThreadPoolExecutor(4) as pool:
            result = list(pool.map(lambda _: _nss.Context(self.roots, None), range(12)))
        self.assertEqual(len({id(x.store) for x in result}), 1)
        self.assertEqual(len({id(x) for x in result}), len(result))
        self.cache._after_fork()
        self.assertFalse(self.cache._items)
        self.assertEqual(self.cache._bytes, 0)


class BufferTests(unittest.TestCase):
    def test_exact_partial_empty_and_owned_result(self):
        b = (ctypes.c_uint8 * 4)(0, 255, 128, 0)
        self.assertEqual(read_bytes(b, 0), b"")
        self.assertEqual(read_bytes(b, 3), b"\0\xff\x80")
        data = read_bytes(b, 4)
        b[0] = 42
        self.assertEqual(data, b"\0\xff\x80\0")
        for n in [-1, 5]:
            with self.assertRaises(OSError):
                read_bytes(b, n)
