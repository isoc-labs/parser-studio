"""A key=value pair behind a list delimiter is never "completely parsed" (Issue #315, Phase 3 P1).

The key=value grammar separates pairs at SP and TAB only, so "src=10.0.0.1,dst=10.0.0.2" is one pair whose value
is the rest of the line. The browser grades such an event PARTIAL (src/grammar/delimitedPairGuard.test.ts); the
Multi-Pass preview keeps every field it read and reports the same event as not completely parsed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview
from source_kv import decode_source_kv


class DelimitedPairUnread(unittest.TestCase):
    def test_a_pair_behind_a_list_delimiter_is_not_completely_parsed(self):
        for raw in (
            # (A body that is one delimited list - "src=10.0.0.1,dst=10.0.0.2,action=allow" - is read as its
            # pairs by the list grammar: tests/test_contract_kv_list_20261121.py.)
            "src=10.0.0.1, dst=10.0.0.2 action=allow",
            "src=10.0.0.1,dst=10.0.0.2;action=allow",
            "src=10.0.0.1,dst=10.0.0.2,",
            # Independent audit 2026-11-22, G-01 and G-02: a first value that holds "=", a key the grammar
            # cannot read.
            "url=/login?user=bob,src=10.0.0.1,dst=10.0.0.2,action=allow",
            "token=YWJjZA==,user=bob,src=10.0.0.1",
            "src=10.0.0.1,\uc0ac\uc6a9\uc790=bob,dst=10.0.0.2",
            "cookie=a=1; next=2",
        ):
            with self.subTest(raw=raw):
                found = decode_source_kv(raw)
                self.assertIn("KV_DELIMITED_PAIR_UNREAD", found.issues)
                self.assertEqual(1, found.issues.count("KV_DELIMITED_PAIR_UNREAD"))
                self.assertNotEqual("SOURCE_PARSED", preview(raw)["status"])

    def test_the_fields_that_were_read_are_kept(self):
        found = decode_source_kv("src=10.0.0.1, dst=10.0.0.2;action=allow")
        self.assertEqual({"src": "10.0.0.1,", "dst": "10.0.0.2;action=allow"}, found.fields)

    def test_a_value_that_is_one_value_stays_completely_parsed(self):
        for raw, expected in (
            ("dn=CN=John,OU=Users,DC=corp srcip=10.1.1.1", {"dn": "CN=John,OU=Users,DC=corp", "srcip": "10.1.1.1"}),
            ("url=http://x/?a=1,b=2 action=allow", {"url": "http://x/?a=1,b=2", "action": "allow"}),
            ("list=a,b,c ports=1;2|3 last=1,", {"list": "a,b,c", "ports": "1;2|3", "last": "1,"}),
            ("srcip=10.1.1.1 dstip=10.2.2.2 action=deny", {"srcip": "10.1.1.1", "dstip": "10.2.2.2", "action": "deny"}),
            # Independent audit 2026-11-22, G-05: pairs separated by white space; a delimiter inside a value
            # is value data.
            ("src=10.0.0.1 content_type=text/html;charset=utf-8 status=200",
             {"src": "10.0.0.1", "content_type": "text/html;charset=utf-8", "status": "200"}),
            ("src=10.0.0.1 url=/app/login;jsessionid=AB12 status=200",
             {"src": "10.0.0.1", "url": "/app/login;jsessionid=AB12", "status": "200"}),
            ("dev=sda1 opts=rw,uid=1000,gid=1000 action=mount", {"dev": "sda1", "opts": "rw,uid=1000,gid=1000", "action": "mount"}),
            ("a=1 b=2;c=3", {"a": "1", "b": "2;c=3"}),
            ('msg="mounted" opts=rw,uid=1000', {"msg": "mounted", "opts": "rw,uid=1000"}),
            ("actioL=vEF:2.0|n=denydeny srcip=10.9.9.9", {"actioL": "vEF:2.0|n=denydeny", "srcip": "10.9.9.9"}),
        ):
            with self.subTest(raw=raw):
                found = decode_source_kv(raw)
                self.assertEqual((expected, []), (found.fields, found.issues))
                self.assertEqual("SOURCE_PARSED", preview(raw)["status"])


if __name__ == "__main__":
    unittest.main()
