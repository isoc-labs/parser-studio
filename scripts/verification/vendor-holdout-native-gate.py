"""Independent vendor-grammar holdout audit, actual browser downloads only."""
import datetime
import hashlib
import json
import pathlib
import sys
from importlib import import_module

downloaded_ruby = import_module("assisted-regex-native-gate").downloaded_ruby
ROOT = pathlib.Path("tests/fixtures/vendor-holdout-20261116")
REGISTRY = pathlib.Path("contracts/vendor-holdout-disposition.v1.json")
TITLE = "holdout actual parser download "

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def fixtures():
    registry = json.loads(REGISTRY.read_text())
    require(set(registry) == {p.name for p in ROOT.iterdir() if p.is_dir()}, "HOLDOUT_INVENTORY_MISMATCH")
    for id, disposition in sorted(registry.items()):
        p = ROOT / id
        meta = json.loads((p / "meta.json").read_text())
        raw = (p / "raw.log").read_bytes()
        require(hashlib.sha256(raw).hexdigest() == meta["raw_sha256"], "HOLDOUT_SOURCE_SHA " + id)
        lines = raw.decode().rstrip("\n").split("\n")
        require(len(lines) == meta["events"] == len(meta["oracle"]), "HOLDOUT_SOURCE_COUNT " + id)
        if disposition == "AUTO_DOWNLOAD":
            yield id, lines, meta["oracle"]

def prepare(root, path):
    doc = json.loads(path.read_text())
    for id, lines, _ in fixtures():
        ruby = downloaded_ruby(root, TITLE + id)
        doc["cases"].extend({"id": f"holdout-{id}:{i}", "ruby": ruby, "raw": line} for i, line in enumerate(lines))
    path.write_text(json.dumps(doc, ensure_ascii=False))
    print("HOLDOUT_NATIVE_PREPARED")

def leaves(record, prefix=()):
    if isinstance(record, dict):
        for k, v in record.items():
            if k not in {"source_raw", "message_raw", "parser_raw_msg", "syslog_structured_data"}:
                yield from leaves(v, (*prefix, k))
    elif isinstance(record, list):
        for i, v in enumerate(record):
            yield from leaves(v, (*prefix, str(i)))
    else:
        yield prefix, record

# Independently identified source field / documented mapping aliases. The
# complete source fixture remains immutable; no raw-text substring matching.
ALIASES = {
    "h_panos_threat_url": {"user": ("srcuser",), "url": ("misc",), "act": ("action",), "nat": ("natsrc",)},
    "h_sophos_xg_fw": {"device_name": ("hostname",), "protocol": ("proto_name",)},
    "h_srx_sd_close_deny": {"policy-name": ("rule.name",)},
}
# Default deny (owner decision 2026-11-28): hostname is not a listed field. The Syslog header host of these
# samples is kept under its own name in the vendor fields, and the value must still be there.
FALLBACK = {
    "h_checkpoint_logexporter": {"srcport": "s_port", "dstport": "service"},
    "h_fortigate_mixed": {"username": "user", "action": "action"},
    "h_panos_threat_url": {"hostname": "hostname"},
    "h_panos_traffic": {"hostname": "hostname"},
    "h_srx_sd_close_deny": {"hostname": "syslog_hostname"},
    "h_suricata_rfc5424": {"hostname": "syslog_hostname"},
    "h_sonicwall_fw": {"username": "usr", "action": "fw_action"},
    "h_sophos_xg_fw": {"username": "user_name"},
    "h_stormshield_filter": {"srcport": "srcport", "dstport": "dstport", "username": "user"},
}

def equal_source(a, b):
    # Text source and documented numeric representation may differ in type;
    # never allow substring matches or rounding of integers/decimal strings.
    if isinstance(a, bool) or isinstance(b, bool) or a is None or b is None:
        return type(a) is type(b) and a == b
    return str(a) == str(b)

def field_present(values, names, value):
    return any(any(path[-1:] == (name,) or ".".join(path[-2:]) == name for name in names)
               and equal_source(actual, value) for path, actual in values)

def check_record(id, i, expected, calls):
    label = f"{id}:{i}"
    require(len(calls) == 1 and isinstance(calls[0][1], dict), "HOLDOUT_EVENT_COUNT " + label)
    r = calls[0][1]
    require("parser_err_msg" not in r, "HOLDOUT_PARSE_ERROR " + label)
    values = list(leaves(r))
    canonical = 0
    missing = []
    for k, v in expected["canon"].items():
        if k in r:
            require(type(r[k]) is type(v) and r[k] == v, f"HOLDOUT_CANONICAL_WRONG {label} {k}")
            canonical += 1
        else:
            missing.append(k)
            if id == "h_sonicwall_fw" and k in {"srcip", "dstip", "srcport", "dstport"}:
                # The original exact composite address:port:interface is
                # itself a separately required fixture field below.
                source = "src" if k.startswith("src") else "dst"
                composite = expected["values"][source]
                ip, port, _interface = composite.rsplit(":", 2)
                require((ip if k.endswith("ip") else int(port)) == v, "HOLDOUT_COMPOSITE_ORACLE " + label)
                require(field_present(values, (source,), composite), "HOLDOUT_COMPOSITE_LOST " + label)
            else:
                source = FALLBACK.get(id, {}).get(k)
                require(source is not None and field_present(values, (source,), v),
                        f"HOLDOUT_UNMAPPED_VALUE_LOST {label} {k}")
    for k, v in expected["forbid"]:
        require(k not in r or not equal_source(r[k], v), f"HOLDOUT_FORBIDDEN {label} {k}")
    for k, v in expected["values"].items():
        if id == "h_cloudtrail_line" and k == "eventTime":
            millis = int(datetime.datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp() * 1000)
            require(type(r.get("timestamp")) is int and r["timestamp"] == millis or field_present(values, (k,), v),
                    f"HOLDOUT_TIMESTAMP {label}")
            continue
        names = (k,) + ALIASES.get(id, {}).get(k, ())
        require(field_present(values, names, v), f"HOLDOUT_SOURCE_VALUE_LOST {label} {k}")
    return canonical, missing

def compare(path):
    doc = json.loads(path.read_text())
    require(doc["ruby"] == "2.4.9", "HOLDOUT_RUBY_VERSION")
    events = canon = total = 0
    for id, lines, expected in fixtures():
        for i, oracle in enumerate(expected):
            n, missing = check_record(id, i, oracle, doc["results"][f"holdout-{id}:{i}"]["calls"])
            events += 1
            canon += n
            total += len(oracle["canon"])
            if missing:
                print("HOLDOUT_MAPPING_REVIEW", id, i, ",".join(missing))
    print(f"HOLDOUT_NATIVE_ORACLE_PASS events={events} canonical_mapped={canon}/{total}; unmapped values preserved; no target claim")

if __name__ == "__main__":
    try:
        if sys.argv[1] == "prepare":
            prepare(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
        elif sys.argv[1] == "compare":
            compare(pathlib.Path(sys.argv[2]))
        else:
            raise ValueError("expected prepare or compare")
    except (ValueError, KeyError, OSError) as exc:
        sys.exit(str(exc))

