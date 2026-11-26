"""Independent expectations for actual downloaded parsers after mapping review.

The raw examples are synthetic. Manual override tests deliberately change one
event's mapping: this proves scope and preservation, not correctness of the
operator's chosen semantic role. No expected value is derived from emitted Ruby.
"""
import json
import sys
from pathlib import Path
from importlib import import_module

downloaded_ruby = import_module("assisted-regex-native-gate").downloaded_ruby

def case(raw, required, absent=()):
    return {"raw": raw, "required": required, "absent": list(absent)}

def vendor(**fields):
    return {"Demo Local Draft/" + name: value for name, value in fields.items()}

def endpoint(src, dst, sport, dport, action):
    return {"srcip": src, "dstip": dst, "srcport": sport, "dstport": dport, "action": action}

PAN = '<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy'
CEF = 'CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow'

SCENARIOS = {
    "assisted-unmapped": {
        "title": "ChatGPT Assisted refuses wrong replies and keeps the column a reply leaves unmapped (Q3-1)",
        "cases": [
            case(action + "," + value, {"custom/action": action, **vendor(src_ip=value)}, ["srcip"])
            for action, value in [
                ("allow", "198.51.100.10"), ("deny", "203.0.113.4"),
                ("allow", "192.0.2.10"), ("deny", "192.0.2.11"),
                ("allow", "2001:db8::7"), ("deny", "김민수-host"),
            ]
        ],
    },
    "manual-event": {
        "title": "the field matches of one event type are added, changed and removed by hand; the parser follows",
        "cases": [
            case('<134>Nov 25 09:10:01 gw-a fwd: srcip=10.44.7.21 dstip=198.51.100.77 srcport=51522 dstport=8443 action=permit',
                 {**endpoint("10.44.7.21", "198.51.100.77", 51522, 8443, "permit"),
                  "parserstudio_event_family": "rfc3164_kv"}, ["Demo Local Draft/sensor_bytes"]),
            case('{"ts":"2026-11-25T09:10:04Z","sensor":"brisa-3","src_ip":"10.9.8.7","dst_ip":"203.0.113.40","bytes":1820}',
                 {"srcip":"203.0.113.40", **vendor(src_ip="10.9.8.7",sensor="brisa-3",sensor_bytes="1820"),
                  "parserstudio_event_family":"json"}, ["dstip","Demo Local Draft/bytes"]),
            case('CEF:0|Tavora|Sentinel|4.2|1007|Policy hit|6|src=10.3.3.3 dst=203.0.113.9 spt=40112 dpt=22 act=blocked',
                 {**endpoint("10.3.3.3","203.0.113.9",40112,22,"blocked"),
                  "parserstudio_event_family":"cef"}, ["Demo Local Draft/sensor_bytes"]),
            case('{"ts":"2026-11-25T09:11:00Z","sensor":"brisa-4","src_ip":"2001:db8::7","dst_ip":"2001:db8::40","bytes":7}',
                 {"srcip":"2001:db8::40", **vendor(src_ip="2001:db8::7",sensor="brisa-4",sensor_bytes="7"),
                  "parserstudio_event_family":"json"}, ["dstip","Demo Local Draft/bytes"]),
            case('CEF:0|Tavora|Sentinel|4.2|1008|Policy miss|3|src=10.3.3.4 dst=203.0.113.10 spt=40113 dpt=443 act=allowed',
                 {**endpoint("10.3.3.4","203.0.113.10",40113,443,"allowed"),
                  "parserstudio_event_family":"cef"}, ["Demo Local Draft/sensor_bytes"]),
        ],
    },
    "jsonata-event": {
        "title": "ChatGPT JSONata mapping changes one event type of a multi-type parser and the generated parser",
        "cases": [
            case(raw, {**endpoint(ip,"8.8.8.8",51514,443,"allow"), "proto_name":"tcp",
                       **vendor(natsrc="203.0.113.10",natsport="62001",serial="012345678901"),
                       "parserstudio_source/generic/source_raw":raw,
                       "parserstudio_event_family":"panos_traffic_csv"}, ["event_name"])
            for raw,ip in [(PAN,"10.10.20.15"),(PAN.replace("10.10.20.15","10.10.20.16"),"10.10.20.16")]
        ] + [
            case(raw, {**endpoint(ip,"10.0.0.8",51234,443,"allow"),"event_name":"Login",
                       "parserstudio_source/generic/source_raw":raw,
                       "parserstudio_event_family":"structured_family_cef"}, ["Demo Local Draft/cef_name"])
            for raw,ip in [(CEF,"10.0.0.7"),(CEF.replace("10.0.0.7","10.0.0.9"),"10.0.0.9")]
        ],
    },
}

MISSING = object()

def get(record, path):
    for key in path.split("/"):
        if not isinstance(record, dict) or key not in record:
            return MISSING
        record = record[key]
    return record

def require(condition, message):
    if not condition:
        raise ValueError(message)

def prepare(root, path):
    doc = json.loads(path.read_text())
    for scenario, spec in SCENARIOS.items():
        ruby = downloaded_ruby(root, spec["title"])
        doc["cases"].extend({"id": f"mapping-{scenario}-{i}", "ruby": ruby, "raw": c["raw"]}
                            for i,c in enumerate(spec["cases"]))
    path.write_text(json.dumps(doc, ensure_ascii=False))
    print("MAPPING_NATIVE_PREPARED scenarios=3 cases=15")

def compare(path):
    doc = json.loads(path.read_text())
    require(doc["ruby"] == "2.4.9", "MAPPING_NATIVE_RUBY_VERSION")
    for scenario, spec in SCENARIOS.items():
        for i,c in enumerate(spec["cases"]):
            name=f"mapping-{scenario}-{i}"
            calls=doc["results"][name]["calls"]
            require(len(calls)==1, f"MAPPING_NATIVE_EVENT_COUNT {name}")
            record=calls[0][1]
            require(isinstance(record,dict) and "parser_err_msg" not in record, f"MAPPING_NATIVE_PARSE_ERROR {name}")
            for field,expected in c["required"].items():
                actual=get(record,field)
                require(type(actual) is type(expected) and actual==expected, f"MAPPING_NATIVE_VALUE {name} {field}")
            for field in c["absent"]:
                require(get(record,field) is MISSING, f"MAPPING_NATIVE_UNAPPROVED_FIELD {name} {field}")
    print("MAPPING_NATIVE_ORACLE_PASS ruby=2.4.9 scenarios=3 cases=15")

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
