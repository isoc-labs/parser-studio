"""Pairs separated by "&" are not "completely parsed" as one field (independent audit 2026-11-22, G-11).

Same rule as src/grammar/ampersandPairGuard20261123.test.ts: inside one token a key behind "&" is a pair,
unless the value before it opened a URL query with "?".
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview
from source_kv import decode_source_kv


class AmpersandPairUnread(unittest.TestCase):
    def test_pairs_behind_an_ampersand_are_not_completely_parsed(self):
        found = decode_source_kv("a=1&b=2&c=3")
        self.assertIn("KV_DELIMITED_PAIR_UNREAD", found.issues)
        self.assertNotEqual("SOURCE_PARSED", preview("a=1&b=2&c=3")["status"])

    def test_a_url_query_stays_one_value(self):
        for raw, expected in (
            ("url=/a?x=1&y=2", {"url": "/a?x=1&y=2"}),
            ("src=10.0.0.1 note=a&b=c status=200", {"src": "10.0.0.1", "note": "a&b=c", "status": "200"}),
        ):
            with self.subTest(raw=raw):
                found = decode_source_kv(raw)
                self.assertNotIn("KV_DELIMITED_PAIR_UNREAD", found.issues)
                self.assertEqual(expected, found.fields)


if __name__ == "__main__":
    unittest.main()
