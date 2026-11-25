import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';

// Golden case mixed_envelope_cef_kv (final audit corpus): an RFC 5424 CEF line and an RFC 3164 key=value line.
// Each family is mapped on its own, but the vendor names of another family (generic.kv.srcip is kept as the
// vendor field "srcip") were treated as taken destinations, so the CEF family lost srcip, dstip, srcport and
// dstport. SYNTHETIC lines.
const CEF='<165>1 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dst=198.51.100.4 spt=40000 dpt=443 act=deny';
const KV='<134>Oct 12 01:02:05 fw01 date=2026-10-12 time=01:02:05 srcip=10.5.5.6 srcport=2001 dstip=203.0.113.21 dstport=80 action=deny policyid=9';

describe('per-family mapping ignores the vendor names of another family',()=>{
  it('maps the network tuple of both families',()=>{
    const source=[CEF,KV].join('\n');
    const draft=buildAutomaticGenericStructuralDraft(source,createDraft())!.draft;
    const tuple=preview(source,draft).events.map(event=>{
      const out=event.normalized as Record<string,unknown>;
      return [out.srcip,out.dstip,out.srcport,out.dstport];
    });
    expect(tuple).toEqual([['192.0.2.11','198.51.100.4',40000,443],['10.5.5.6','203.0.113.21',2001,80]]);
  });
});
