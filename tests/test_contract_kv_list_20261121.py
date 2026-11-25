"""The Multi-Pass key=value scanner reads a delimited list of pairs (Issue #315, Phase 3 P1).

A body whose pairs are separated by ONE list delimiter (, ; |) is read as its pairs, exactly as the browser
grammar reads it (src/grammar/kvList.test.ts holds the same values). Every expectation is the value the sender
wrote, stated by hand. Anything that is not one delimited list is read by the white space grammar as before.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview
from source_kv import decode_source_kv

THREE = {"src": "10.0.0.1", "dst": "10.0.0.2", "action": "allow"}
PAIRS = ["src=10.0.0.1", "dst=10.0.0.2", "action=allow"]


class DelimitedKeyValueList(unittest.TestCase):
    def test_every_pair_of_a_delimited_body_is_a_field(self):
        for separator in (",", ";", "|", ", ", ";\t", "|  "):
            with self.subTest(separator=repr(separator)):
                raw = separator.join(PAIRS)
                found = decode_source_kv(raw)
                self.assertEqual((THREE, []), (found.fields, found.issues))
                self.assertEqual(["src", "dst", "action"], [span[0] for span in found.spans])
                self.assertEqual(["10.0.0.1", "10.0.0.2", "allow"], [raw[span[1]:span[2]] for span in found.spans])
                self.assertEqual(len(raw), sum(end - start for start, end in found.covered))

    def test_quoted_values_and_other_characters(self):
        # A quoted value is the text between its quotes: nothing is decoded (contract KV_LIST_DQ).
        found = decode_source_kv('msg="a, b=c",user=\'x y\',esc="a\\=b",unc="\\\\srv\\share",path=C:\\Temp,note=a\u2028b')
        self.assertEqual([], found.issues)
        self.assertEqual({"msg": "a, b=c", "user": "x y", "esc": "a\\=b", "unc": "\\\\srv\\share", "path": "C:\\Temp", "note": "a\u2028b"}, found.fields)
        # A value that would need its own quote is not a list; the white space grammar finds one pair and stops.
        self.assertNotEqual([], decode_source_kv('q="say \\"hi\\"",user="bob"').issues)

    def test_a_body_that_is_not_one_delimited_list_is_read_as_before(self):
        unread = ["KV_DELIMITED_PAIR_UNREAD"]
        for raw, expected, issues in (
            ("list=a,b,c", {"list": "a,b,c"}, []),
            ("a=1 b=2\tc=3", {"a": "1", "b": "2", "c": "3"}, []),
            # Pairs separated by white space: a delimiter inside one of their values is value data
            # (independent audit 2026-11-22, G-05).
            ("a=1 b=2,c=3", {"a": "1", "b": "2,c=3"}, []),
            ("dn=CN=John,OU=Users,DC=corp srcip=10.1.1.1", {"dn": "CN=John,OU=Users,DC=corp", "srcip": "10.1.1.1"}, []),
            # Not one list (a value that holds "=", two delimiters, an empty last item) and nothing but one
            # token: the white space grammar reads it as before, and the pair it left inside the value keeps
            # the event from being reported as completely parsed. One token cannot say whether a
            # distinguished name or a query string is one value or a list (G-01).
            ("dn=CN=John,OU=Users,DC=corp", {"dn": "CN=John,OU=Users,DC=corp"}, unread),
            ("url=http://x/?a=1,b=2", {"url": "http://x/?a=1,b=2"}, unread),
            ("a=1,b=2;c=3", {"a": "1,b=2;c=3"}, unread),
            ("a=1,b=2,", {"a": "1,b=2,"}, unread),
        ):
            with self.subTest(raw=raw):
                found = decode_source_kv(raw)
                self.assertEqual((expected, issues), (found.fields, found.issues))

    def test_a_repeated_key_in_a_list_is_never_completely_parsed(self):
        found = decode_source_kv("a=1,b=2,a=3")
        self.assertEqual({"a": ["1", "3"], "b": "2"}, found.fields)
        self.assertIn("DUPLICATE_SOURCE_FIELD", found.issues)

    def test_preview_reads_a_delimited_message_behind_a_syslog_header(self):
        result = preview("<134>Nov 13 10:00:00 fw01 src=10.0.0.1,dst=10.0.0.2,action=allow")
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual(THREE, result["fields"]["body"])
        self.assertEqual([], result["residuals"])

    def test_preview_reads_a_bare_delimited_line(self):
        result = preview("src=10.0.0.1,dst=10.0.0.2,action=allow")
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual(THREE, result["fields"])
        self.assertEqual([], result["residuals"])


if __name__ == "__main__":
    unittest.main()
