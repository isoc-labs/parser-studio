#!/usr/bin/env python3
"""Does the running Multi-Pass engine execute the code of this checkout?

    live_engine_check.py --source <checkout> --url <base url> --origin <origin>

A health endpoint that answers 200 and installed files whose hashes match say nothing about the code a long-running
process holds in memory (independent audit AUD-01 of 2026-11-25: the files were replaced, the process kept running
the previous engine). This check computes, with the engine code of <checkout>, the exact response bytes for a fixed
set of synthetic events and compares them with what the running service answers over HTTP. Any difference is a
failure. It reads nothing but the checkout and sends only the synthetic events below.

Exit status 0: every answer is byte-identical. 1: a difference or an unreachable service. 2: usage.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Synthetic events of every source family the engine reads, with the shapes on which two engine versions have
# differed before. They are probes of the running process, not parsing rules.
PROBES: tuple[tuple[str, str, str], ...] = (
    ('cef', 'preview', 'CEF:0|Acme|Gateway|7.4.5|13|forward accept|3|src=10.1.1.1 dst=203.0.113.9 spt=51000 dpt=443 act=accept'),
    ('syslog_cef_colon_space', 'preview', '<189>Nov 25 10:00:00 gw60 CEF: 0|Acme|Gateway|v7.4.5|00013|forward accept|3|deviceExternalId=gw60 src=10.1.1.1 spt=51000 dst=203.0.113.9 dpt=443 act=accept'),
    ('pri_only_cef', 'preview', '<134>CEF:0|Acme|GW|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow'),
    ('comma_kv', 'preview', 'srcip=10.0.0.1,dstip=10.0.0.2,action=deny'),
    ('semicolon_kv', 'preview', 'srcip=10.0.0.1;dstip=10.0.0.2;action=deny'),
    ('json', 'preview', '{"ts":"2026-11-25T09:10:04Z","src_ip":"10.9.8.7","dst_ip":"203.0.113.40","bytes":1820}'),
    ('json_nested', 'preview', '{"event":{"type":"alert","severity":3},"net":{"src":{"ip":"10.9.8.7","port":51000},"dst":{"ip":"203.0.113.40","port":443}}}'),
    ('json_member_names', 'preview', '{"__proto__":"alpha","constructor":"beta","prototype":"gamma","src_ip":"10.0.0.1"}'),
    ('cef_claim_only', 'preview', '<134>Nov 25 10:00:00 gw01 app: CEF:0|only|three|fields'),
    ('syslog_text_prefix_kv', 'preview', '<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected signature=1000123 src=192.0.2.40 dst=198.51.100.5 action=block'),
    ('rfc5424_structured_data', 'preview', '<134>1 2026-10-19T09:15:22.123Z fw01 application 12 audit [meta@12345 action="deny" src="192.0.2.10"] firewall denied'),
    ('batch_read_and_unread', 'preview-batch', '<134>Nov 25 09:10:01 gw-a fwd: srcip=10.44.7.21 dstip=198.51.100.77 srcport=51522 dstport=8443 action=permit\n<134>Nov 25 09:10:02 gw-a fwd: connection table is full, dropping new flows'),
)


def expected_bytes(source: Path, endpoint: str, raw: str) -> bytes:
    """The response body the engine of `source` writes for this request (same serialization as its HTTP handler)."""
    engine = str(source / 'runtime' / 'multipass')
    if engine not in sys.path:
        sys.path.insert(0, engine)
    import multipass_preview_api as api  # the engine of the checkout, not an installed copy
    if Path(api.__file__).resolve().parent != Path(engine).resolve():
        raise SystemExit('ENGINE_CHECK_FAIL the engine module was not loaded from ' + engine)
    result = api.preview_batch(raw) if endpoint == 'preview-batch' else api.preview(raw)
    return json.dumps(result, ensure_ascii=True, separators=(',', ':')).encode()


def live_bytes(url: str, origin: str, endpoint: str, raw: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url.rstrip('/') + '/api/v1/multipass/' + endpoint,
                                     data=json.dumps({'raw': raw}).encode(),
                                     headers={'Content-Type': 'application/json', 'Origin': origin}, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--url', required=True)
    parser.add_argument('--origin', required=True)
    args = parser.parse_args()
    if not (args.source / 'runtime' / 'multipass' / 'multipass_preview_api.py').is_file():
        print('ENGINE_CHECK_FAIL no engine in ' + str(args.source))
        return 2
    different = []
    for name, endpoint, raw in PROBES:
        want = expected_bytes(args.source, endpoint, raw)
        try:
            status, got = live_bytes(args.url, args.origin, endpoint, raw)
        except (OSError, ValueError) as error:
            print('ENGINE_CHECK_FAIL %s: %s is not reachable (%s)' % (name, args.url, error))
            return 1
        same = status == 200 and got == want
        print('%s %s http=%s live=%s checkout=%s' % ('same     ' if same else 'DIFFERENT', name, status,
              hashlib.sha256(got).hexdigest()[:16], hashlib.sha256(want).hexdigest()[:16]))
        if not same:
            different.append(name)
    if different:
        print('ENGINE_CHECK_FAIL %d of %d answers differ from the engine of the checkout: %s'
              % (len(different), len(PROBES), ', '.join(different)))
        return 1
    print('ENGINE_CHECK_OK %d of %d answers are byte-identical to the engine of the checkout' % (len(PROBES), len(PROBES)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
