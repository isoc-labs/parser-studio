"""Python and the browser agree on a long comma key=value line (audit 2026-11-22 G-10, re-audit A2).

The audit compared the Python comma frame with the browser's key=value grammar (kvBody.ts, 100 pairs). The
Python comma_kv / delimited_kv frames are the counterpart of the Generic Structural comma_kv / delimited_kv
modes of src/genericStructural.ts, which have no pair limit; the generated Ruby is derived from that grammar.
A line of 101 comma pairs is parsed by both, every value kept.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview


class CommaKvParity(unittest.TestCase):
    def test_a_long_comma_list_is_parsed_with_every_value(self):
        raw = ",".join(f"k{i}=v{i}" for i in range(101))
        result = preview(raw)
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual(f"v{100}", result["fields"]["generic"]["fields"]["k100"])


if __name__ == "__main__":
    unittest.main()
