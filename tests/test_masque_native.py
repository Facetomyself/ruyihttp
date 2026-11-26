# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Check the fixture independently, with opt-in installed native qualification.

Install aioquic==1.3.0, then use unittest discovery. Set
RUYIHTTP_TEST_NATIVE_H3=1 to run the public-API wire scenarios, or run
ci/smoke_masque.py directly for an installed-wheel JSON receipt.
"""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


CI_SMOKE = Path(__file__).resolve().parents[1] / "ci" / "smoke_masque.py"


def _load_smoke():
    spec = importlib.util.spec_from_file_location("masque_ci_wire", CI_SMOKE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MasqueWireTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        if importlib.util.find_spec("aioquic") is None:
            if os.environ.get("RUYIHTTP_TEST_NATIVE_H3") == "1":
                self.fail("native wire tests require aioquic==1.3.0")
            self.skipTest("fixture tests require aioquic==1.3.0")
        self.smoke = _load_smoke()
        work = tempfile.TemporaryDirectory(prefix="ruyi-masque-fixture-")
        self.addCleanup(work.cleanup)
        self.origin, self.relay = self.smoke.certs(Path(work.name))

    async def test_fixture_blocks_other_targets_and_udp_peers(self):
        receipt = await self.smoke.fixture_self_test(self.origin, self.relay)
        self.assertEqual(receipt["verdict"], "passed")
        self.assertEqual([event["status"] for event in receipt["outer"]["connects"]], [403, 200])
        self.assertEqual(receipt["datagrams"]["rx_quarter_stream_ids"], [1])
        self.assertEqual(len(receipt["origin"]["rejected_udp"]), 1)
        self.assertEqual(len(receipt["origin"]["tcp_contacts"]), 1)
        self.assertEqual(receipt["origin"]["peer_sockets"], [receipt["sockets"]["relay_egress"]])

    @unittest.skipUnless(os.environ.get("RUYIHTTP_TEST_NATIVE_H3") == "1", "requires installed native runtime")
    async def test_installed_native_masque_wire(self):
        # Native Requests calls and the independent peers run concurrently;
        # disabling debug fairness/timing diagnostics matches the wheel smoke.
        import asyncio
        asyncio.get_running_loop().set_debug(False)
        receipt = {"cases": []}
        await self.smoke.qualify(receipt, self.origin, self.relay, self.smoke.MODES)
        self.assertEqual([c["name"] for c in receipt["cases"]], list(self.smoke.MODES))
        self.assertTrue(all(c["verdict"] == "passed" for c in receipt["cases"]))
