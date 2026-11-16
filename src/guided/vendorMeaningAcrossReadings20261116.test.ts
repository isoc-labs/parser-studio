import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {fortiGateFalseFriend} from './normalizationCandidates';
import type {BackendCapabilities} from './backendCapabilities';

// What a vendor record means does not depend on which reading produced its fields. The same FortiGate line is read at
// the root by the KV format and under generic.kv.* behind a PRI; a Suricata alert is read at the root as JSON and
// under body.* inside an RFC 5424 message. The guards that keep a vendor field away from a Stellar field of another
// meaning looked at the root only and were silent for the second reading of each.
const cap={authoring:{extractionFormats:['json','kv','csv','syslog_rfc3164','syslog_rfc5424','cef','leef'],
  rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
function official(sample:string):Record<string,string>{
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(sample,'single-line');
  const native=prepareAutoParserDraft(sample,draft,preview(sample,draft),ledger,assessEnvelopeCompilation(ledger,cap));
  const made=native.ok?native.draft:buildAutomaticGenericStructuralDraft(sample,draft)?.draft;
  expect(made).toBeDefined();
  return Object.fromEntries(made!.mappings.filter(mapping=>made!.guided!.groups[mapping.id]!=='vendor_fields')
    .map(mapping=>[mapping.source.split('.').at(-1)!,mapping.target]));
}
const webfilter=(n:number)=>'date=2026-11-16 time=10:15:0'+n+' devname="FGT60F-HQ" devid="FGT60FTK20001234" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" policyid=5 user="mlee" srcip=10.1.10.3'+n+' srcport=5021'+n+' srcintf="internal" dstip=198.51.100.80 dstport=80 dstintf="wan1" proto=6 service="HTTP" hostname="bad'+n+'.example.net" action="blocked" url="http://bad.example.net/dl/a.exe" direction="outgoing"';
const KV=[webfilter(1),webfilter(2)].join('\n');
const KV_BEHIND_PRI=['<188>'+webfilter(1),'<188>'+webfilter(2)].join('\n');
const alert=(n:number)=>JSON.stringify({timestamp:'2026-11-16T10:15:0'+n+'.251547+0900',event_type:'alert',src_ip:'203.0.113.7'+n,src_port:40022,
  dest_ip:'10.1.10.9',dest_port:22,proto:'TCP',alert:{action:'allowed',gid:1,signature_id:2010935,rev:3,signature:'ET SCAN',category:'Potentially Bad Traffic',severity:2}});
const EVE=[alert(1),alert(2)].join('\n');
const EVE_IN_RFC5424=[1,2].map(n=>'<134>1 2026-11-16T01:15:0'+n+'Z ids01 suricata 1234 - - '+alert(n)).join('\n');

describe('vendor meaning is the same for every reading of one record',()=>{
  it('FortiGate: the requested web host and the session direction stay vendor fields, at the root and behind a PRI',()=>{
    const root=official(KV),wrapped=official(KV_BEHIND_PRI);
    for(const mapping of [root,wrapped]){
      expect(mapping.hostname).toBeUndefined();
      expect(mapping.direction).toBeUndefined();
      expect(mapping).toMatchObject({srcip:'srcip',dstip:'dstip',srcport:'srcport',dstport:'dstport',action:'action',url:'url'});
    }
    expect(wrapped).toEqual(root);
  });
  it('FortiGate: one rule answers for both containers',()=>{
    const record={logid:'0316013056',type:'utm',vd:'root',hostname:'bad.example.net'};
    expect(fortiGateFalseFriend('hostname',[record])).toBe(true);
    expect(fortiGateFalseFriend('generic.kv.hostname',[{generic:{kv:record}}])).toBe(true);
    expect(fortiGateFalseFriend('body.hostname',[{body:record}])).toBe(true);
    // Not a FortiGate record: no logid beside the field.
    expect(fortiGateFalseFriend('generic.kv.hostname',[{generic:{kv:{hostname:'web01',type:'x'}}}])).toBe(false);
    expect(fortiGateFalseFriend('generic.kv.srcip',[{generic:{kv:record}}])).toBe(false);
  });
  it('Suricata: the 1-4 alert priority is not the Stellar severity, as JSON and inside an RFC 5424 message',()=>{
    const root=official(EVE),wrapped=official(EVE_IN_RFC5424);
    expect(root.severity).toBeUndefined();
    expect(wrapped.severity).toBeUndefined();
    expect(root).toMatchObject({src_ip:'srcip',dest_ip:'dstip',src_port:'srcport',dest_port:'dstport'});
    expect(wrapped).toMatchObject({src_ip:'srcip',dest_ip:'dstip',src_port:'srcport',dest_port:'dstport'});
  });
  it('Imperva Cloud WAF: spt beside cpt is the server port and is not mapped to the source port',()=>{
    const line=(n:number)=>'CEF:0|Incapsula|SIEMintegration|1|1|Illegal Resource Access|3| fileId=341234116000251817'+n+' sourceServiceName=site.example.com siteid=1509732 src=203.0.113.7'+n+' cn1=200 in=54 requestMethod=GET app=HTTPS act=REQ_BLOCKED_SECURITY cpt=4002'+n+' spt=443 sip=10.1.10.9';
    const bare=official([line(1),line(2)].join('\n'));
    const wrapped=official([1,2].map(n=>'<134>Nov 16 10:15:0'+n+' waf01 '+line(n)).join('\n'));
    for(const mapping of [bare,wrapped]){
      expect(mapping.spt).toBeUndefined();
      expect(mapping.src).toBe('srcip');
      expect(Object.values(mapping)).not.toContain('srcport');
    }
    // Without cpt the CEF dictionary stands: spt is the source port.
    const standard=official(['CEF:0|Vendor|Product|1.0|100|Name|5|src=10.1.1.5 dst=203.0.113.9 spt=51000 dpt=443 proto=6',
      'CEF:0|Vendor|Product|1.0|100|Name|5|src=10.1.1.6 dst=203.0.113.9 spt=51001 dpt=443 proto=6'].join('\n'));
    expect(standard).toMatchObject({spt:'srcport',dpt:'dstport',src:'srcip',dst:'dstip'});
  });
});
