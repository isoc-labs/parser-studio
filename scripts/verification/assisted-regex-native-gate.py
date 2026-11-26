"""Independent synthetic source/value oracle for the real Assisted download.
The expectations are authored from the source log layout, not preview output.
This is a fragment-runtime check, not a live sensor or Fluentd ingestion check.
"""
import hashlib
import json
import sys
from pathlib import Path

TITLE = "independent ChatGPT Assisted journey exports a statically accepted Regex with real backend"
# Raw fixture values: explicit source IP, URL, and non-placeholder user.
CASES = [
    ("1763859723.123    245 192.0.2.51 TCP_MISS/200 5120 GET http://www.example.test/index.html - HIER_DIRECT/198.51.100.10 text/html", "192.0.2.51", "http://www.example.test/index.html", None),
    ("1763859724.456     12 192.0.2.52 TCP_DENIED/403 3900 CONNECT blocked.example.test:443 alice HIER_NONE/- text/html", "192.0.2.52", "blocked.example.test:443", "alice"),
    ("1763859725.789     77 192.0.2.53 TCP_HIT/200 777 GET http://cdn.example.test/a.js - HIER_NONE/- application/javascript", "192.0.2.53", "http://cdn.example.test/a.js", None),
    ("1763859726.012      9 192.0.2.54 TCP_DENIED/407 3900 GET http://intranet.example.test/ 김민수 HIER_NONE/- text/html", "192.0.2.54", "http://intranet.example.test/", "김민수"),
    ("1763859727.345   1500 2001:db8::10 TCP_TUNNEL/200 88213 CONNECT mail.example.test:443 bob HIER_DIRECT/203.0.113.25 -", "2001:db8::10", "mail.example.test:443", "bob"),
    ("1763859728.678      3 192.0.2.55 NONE_NONE/400 4012 POST http://upload.example.test/form carol HIER_NONE/- text/html", "192.0.2.55", "http://upload.example.test/form", "carol"),
]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def downloaded_ruby(root, title, name="customized_demo_firewall"):
    matches = []
    for index in root.rglob("index-*.jsonl"):
        for line in index.read_text().splitlines():
            entry = json.loads(line)
            if entry.get("test", "").endswith(title) and entry.get("name") == name and entry.get("synthetic") is None:
                artifact = (index.parent / entry["file"]).resolve()
                require(artifact.is_relative_to(index.parent.resolve()), "ASSISTED_ARTIFACT_OUTSIDE_INDEX")
                raw = artifact.read_bytes()
                require(len(raw) == entry["bytes"] and hashlib.sha256(raw).hexdigest() == entry["sha256"], "ASSISTED_ARTIFACT_HASH_MISMATCH")
                matches.append(raw.decode("utf-8"))
    require(len(matches) == 1, f"ASSISTED_REAL_DOWNLOAD_COUNT {len(matches)}")
    return matches[0]

def prepare(root, path):
    ruby = downloaded_ruby(root, TITLE)
    doc = json.loads(path.read_text())
    doc["cases"].extend({"id": f"assisted-regex-{i}", "ruby": ruby, "raw": row[0]} for i, row in enumerate(CASES))
    path.write_text(json.dumps(doc, ensure_ascii=False))
    print("ASSISTED_NATIVE_PREPARED cases=6")

def compare(path):
    doc = json.loads(path.read_text())
    require(doc["ruby"] == "2.4.9", "ASSISTED_RUBY_VERSION")
    for i, (_, ip, url, user) in enumerate(CASES):
        calls = doc["results"][f"assisted-regex-{i}"]["calls"]
        require(len(calls) == 1, f"ASSISTED_EVENT_COUNT {i}")
        record = calls[0][1]
        require(record.get("srcip") == ip and record.get("url") == url, f"ASSISTED_SOURCE_VALUE_MISMATCH {i}")
        require("parser_err_msg" not in record, f"ASSISTED_PARSE_ERROR {i}")
        if user is not None:
            # The recipe leaves user unmapped; verify preservation in its vendor output.
            require(any(isinstance(v, dict) and v.get("user") == user for v in record.values()), f"ASSISTED_USER_VALUE_MISMATCH {i}")
    print("ASSISTED_NATIVE_ORACLE_PASS ruby=2.4.9 cases=6")

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
