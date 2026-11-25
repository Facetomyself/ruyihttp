# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Bounded cache of parsed CA materials; never caches leaf verification or client keys."""

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from types import MappingProxyType

from cryptography import x509
from cryptography.x509.verification import Store


@dataclass(frozen=True)
class TrustMaterial:
    store: Store
    constraints: MappingProxyType
    identity: bytes
    source_bytes: int


def _parse_constraints(data):
    def checked_pairs(pairs):
        result = {}
        for key, cutoff in pairs:
            if not (
                re.fullmatch(r"[0-9a-fA-F]{64}", key)
                and isinstance(cutoff, str)
                and re.fullmatch(r"[0-9]{12}Z", cutoff)
            ):
                raise ValueError("invalid root fingerprint or cutoff")
            key = key.lower()
            if key in result:
                raise ValueError("duplicate root constraint")
            datetime.strptime(cutoff, "%y%m%d%H%M%SZ")
            result[key] = cutoff
        return result

    constraints = json.loads(data, object_pairs_hook=checked_pairs)
    if not isinstance(constraints, dict):
        raise ValueError("invalid root constraints mapping")
    return MappingProxyType(constraints)


class TrustCache:
    def __init__(self, capacity=8, byte_limit=4 * 1024 * 1024):
        if capacity < 0 or byte_limit < 0:
            raise ValueError("negative trust cache budget")
        self._items = OrderedDict()
        self._bytes = 0
        self._capacity = capacity
        self._byte_limit = byte_limit
        self._lock = threading.Lock()

    def load(self, path: Path, constraints_path: Path | None = None) -> TrustMaterial:
        # Hash precisely the bytes we will parse. Timestamps (or a directory's
        # mtime) alone can miss in-place edits and equal-sized CA rotations.
        # Inputs and leaf chains are never retained as cache keys.
        path = path.resolve(strict=True)
        sources = sorted(path.iterdir()) if path.is_dir() else (path,)
        chunks = []
        fingerprint = hashlib.sha256(b"ruyihttp:trust:v1")

        def update(data):
            fingerprint.update(len(data).to_bytes(8, "big"))
            fingerprint.update(data)

        update(os.fsencode(path))
        update(b"custom" if constraints_path is None else b"packaged")
        for file in sources:
            if file.is_file():
                data = file.read_bytes()
                if b"-----BEGIN CERTIFICATE-----" in data:
                    chunks.append(data)
                    update(data)
        constraints_data = (
            b"{}" if constraints_path is None else constraints_path.read_bytes()
        )
        update(constraints_data)
        key = fingerprint.digest()
        with self._lock:
            existing = self._items.get(key)
            if existing is not None:
                self._items.move_to_end(key)
                return existing

        # Disk I/O, X.509 parsing and store construction run outside the cache
        # lock. Two concurrent first handshakes may parse once each; only one
        # material is kept. Malformed/missing inputs never reuse an old result.
        constraints = _parse_constraints(constraints_data)
        roots = [
            root for data in chunks for root in x509.load_pem_x509_certificates(data)
        ]
        material = TrustMaterial(
            Store(roots),
            constraints,
            key,
            sum(map(len, chunks)) + len(constraints_data),
        )
        if not self._capacity or material.source_bytes > self._byte_limit:
            return material
        with self._lock:
            existing = self._items.get(key)
            if existing is not None:
                self._items.move_to_end(key)
                return existing
            while self._items and (
                len(self._items) >= self._capacity
                or self._bytes + material.source_bytes > self._byte_limit
            ):
                _, stale = self._items.popitem(last=False)
                self._bytes -= stale.source_bytes
            self._items[key] = material
            self._bytes += material.source_bytes
        return material

    def _after_fork(self):
        # No thread that held this lock in the parent exists in the child.
        self._lock = threading.Lock()
        self._items = OrderedDict()
        self._bytes = 0


TRUST_MATERIALS = TrustCache()
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=TRUST_MATERIALS._after_fork)
