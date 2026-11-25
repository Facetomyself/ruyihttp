# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


def read_bytes(buffer, used):
    """Detach bytes from one native byte buffer, without a temporary list of ints."""
    if not 0 <= used <= len(buffer):
        raise OSError(f"native read returned {used} bytes for capacity {len(buffer)}")
    if not used:
        return b""
    return memoryview(buffer).cast("B")[:used].tobytes()
