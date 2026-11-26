"""Independent oracle for an actual mixed ASA browser download."""
import json
import sys
from pathlib import Path

# The same immutable source lines used in the real browser journey.
# Values below are authored from the documented direction and ACL layout.
from importlib import import_module
downloaded_ruby = import_module("assisted-regex-native-gate").downloaded_ruby

TITLE = "bounded compiler candidate remains usable beside unsupported events"
CASES = [
    '<166>Nov 26 2026 09:12:01 fw01 : %ASA-6-302013: Built outbound TCP connection 7345 for outside:203.0.113.10/443 (203.0.113.10/443) to inside:10.1.1.5/52044 (198.51.100.7/61012)',
    '<166>Nov 26 2026 09:12:09 fw01 : %ASA-6-302014: Teardown TCP connection 7345 for outside:203.0.113.10/443 to inside:10.1.1.5/52044 duration 0:00:08 bytes 4521 TCP FINs',
    '<164>Nov 26 2026 09:12:15 fw01 : %ASA-4-106023: Deny tcp src outside:192.0.2.9/40222 dst inside:10.1.1.20/22 by access-group "OUTSIDE_IN" [0x0, 0x0]',
    '<166>Nov 26 2026 09:12:20 fw01 : %ASA-6-113005: AAA user authentication Rejected : reason = Invalid password : server = 10.1.1.9 : user = alice',
]
EXPECTED = {
    0: {"srcip": "10.1.1.5", "srcport": 52044, "dstip": "203.0.113.10", "dstport": 443},
    2: {"srcip": "192.0.2.9", "srcport": 40222, "dstip": "10.1.1.20", "dstport": 22},
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def prepare(root, path):
    ruby = downloaded_ruby(root, TITLE)
    doc = json.loads(path.read_text())
    doc["cases"].extend({"id": f"mixed-asa-{i}", "ruby": ruby, "raw": raw} for i, raw in enumerate(CASES))
    path.write_text(json.dumps(doc, ensure_ascii=False))
    print("MIXED_ASA_NATIVE_PREPARED cases=4")

def compare(path):
    doc = json.loads(path.read_text())
    require(doc["ruby"] == "2.4.9", "MIXED_ASA_RUBY_VERSION")
    for i, raw in enumerate(CASES):
        calls = doc["results"][f"mixed-asa-{i}"]["calls"]
        require(len(calls) == 1, f"MIXED_ASA_EVENT_COUNT {i}")
        record = calls[0][1]
        if i in EXPECTED:
            require(all(record.get(k) == v for k, v in EXPECTED[i].items()), f"MIXED_ASA_ENDPOINT_MISMATCH {i}")
            require("parser_err_msg" not in record, f"MIXED_ASA_PARSE_ERROR {i}")
            source = record.get("parserstudio_source", {}).get("asa", {})
            require(isinstance(source, dict) and source.get("source_raw") == raw, f"MIXED_ASA_SOURCE_MISMATCH {i}")
            fields = source
            if i == 0:
                require(str(fields.get("mapped_src_ip")) == "198.51.100.7" and str(fields.get("mapped_src_port")) == "61012", "MIXED_ASA_NAT_MISMATCH")
            else:
                require(fields.get("access_group") == "OUTSIDE_IN", "MIXED_ASA_ACL_MISMATCH")
        else:
            require(record.get("parser_raw_msg") == raw and record.get("parser_err_stage") == "extraction" and bool(record.get("parser_err_msg")), f"MIXED_ASA_FALLBACK_MISMATCH {i}")
    print("MIXED_ASA_NATIVE_ORACLE_PASS ruby=2.4.9 cases=4")

if __name__ == "__main__":
    try:
        if sys.argv[1] == "prepare":
            prepare(Path(sys.argv[2]), Path(sys.argv[3]))
        elif sys.argv[1] == "compare":
            compare(Path(sys.argv[2]))
        else:
            raise ValueError("expected prepare or compare")
    except (ValueError, KeyError, OSError) as exc:
        sys.exit(str(exc))
