# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""suit.audit.v1 conformance against the shared vectors.

The same vectors file is copied into the Drupal module's tests, where an
independent PHP implementation must reproduce every value.
"""

import json
import unittest
from pathlib import Path

from suitlinux.audit_v1 import (GENESIS, ProfileError, _encode_string, canonicalize, event_hash,
                                strict_loads, verify_chain)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "suit-audit-v1.json").read_text(encoding="utf-8"))


class TestVectors(unittest.TestCase):

    def test_rfc8785_string_example(self):
        ex = VECTORS["rfc8785_string_example"]
        self.assertEqual(ex["canonical"], _encode_string(ex["value"]))

    def test_valid_vectors(self):
        for v in VECTORS["valid"]:
            with self.subTest(v["name"]):
                self.assertEqual(v["canonical"].encode("utf-8"), canonicalize(v["event"]))
                self.assertEqual(v["hash"], event_hash(v["event"], bytes.fromhex(v["previous"])).hex())

    def test_chain_vectors(self):
        self.assertEqual(GENESIS.hex(), VECTORS["chain"][0]["previous"])
        ok, problems = verify_chain([(e["event"], e["hash"]) for e in VECTORS["chain"]])
        self.assertTrue(ok, problems)

    def test_altered_event_breaks_chain(self):
        entries = [(dict(e["event"]), e["hash"]) for e in VECTORS["chain"]]
        entries[1][0]["actor"] = 9999
        ok, problems = verify_chain(entries)
        self.assertFalse(ok)
        self.assertIn("entry 2", problems[0])

    def test_invalid_vectors_are_refused(self):
        for v in VECTORS["invalid"]:
            with self.subTest(v["name"]):
                with self.assertRaises(ProfileError):
                    canonicalize(strict_loads(v["json"]))

    def test_previous_must_be_raw_32_bytes(self):
        v = VECTORS["valid"][0]
        with self.assertRaises(ProfileError):
            event_hash(v["event"], v["previous"].encode())


if __name__ == "__main__":
    unittest.main()
