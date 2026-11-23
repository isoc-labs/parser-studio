"""The Python preview declines a comma key=value list as the browser and Ruby grammars do (audit 2026-11-22, G-10).

TS/RB decline a list of more than 100 pairs (TOO_MANY_PAIRS) and a list with a repeated key (DUPLICATE_KEY); the
Python comma_kv frame reported both SOURCE_PARSED. The raw line is kept either way; no field may look parsed in one
runtime and declined in the others.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview


class CommaKvLimits(unittest.TestCase):
    def test_more_than_one_hundred_pairs_is_not_parsed(self):
        raw = ",".join(f"k{i}=v{i}" for i in range(101))
        self.assertNotEqual("SOURCE_PARSED", preview(raw)["status"])

    def test_a_repeated_key_is_not_parsed(self):
        raw = ",".join(f"k{i}=v{i}" for i in range(100)) + ",k0=x"
        self.assertNotEqual("SOURCE_PARSED", preview(raw)["status"])
        self.assertNotEqual("SOURCE_PARSED", preview("a=1,b=2,c=3,d=4,e=5,a=6")["status"])

    def test_one_hundred_distinct_pairs_stay_parsed(self):
        raw = ",".join(f"k{i}=v{i}" for i in range(100))
        self.assertEqual("SOURCE_PARSED", preview(raw)["status"])


if __name__ == "__main__":
    unittest.main()
