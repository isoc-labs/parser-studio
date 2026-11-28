import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import type {FieldType} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import {STELLAR_METADATA_CATALOG,findStellarMetadataField} from './stellarMetadataCatalog';
import policy from '../../runtime/multipass/semantic-policy.v1.json';
import backendPolicy from '../../backend/semantic-policy.v1.json';

// Owner decision 2026-11-28: automatic mapping is default deny. An official field is proposed from a name only
// when the shared policy lists it with the dictionary definition and a basis, and only from a source that stands
// for the record itself. A matching name, alias, type or range is not a reason by itself.
const approved=Object.keys(policy.autoApprovedTargets);
const proposals=(format:string|undefined,rows:Record<string,unknown>[])=>suggestNormalizationCandidatesFromSuite(
  {events:rows.map(fields=>({fields,...(format?{effectiveFormat:format}:{})}))} as unknown as SuiteResult,[])
  .map(candidate=>[candidate.source,candidate.target,candidate.confidence]);
// Values of the documented type; for a listed field, values its own protections accept.
const SAMPLES:Readonly<Record<string,readonly unknown[]>>={
  action:['allow','deny','block'],proto_name:['tcp','udp','tcp'],proto:[6,17,6],
  url:['https://a.example/x','https://b.example/y','/z'],
};
const BY_TYPE:Readonly<Record<FieldType,readonly unknown[]>>={
  string:['alpha','beta','gamma'],integer:[12,23,34],number:[12.5,23.5,34.5],boolean:[true,false,true],
  ip:['10.1.2.3','10.1.2.4','10.1.2.5'],port:[443,8080,53],
  timestamp:['2026-11-27T10:00:00Z','2026-11-27T10:00:01Z','2026-11-27T10:00:02Z'],
};

describe('default-deny automatic mapping, 2026-11-28',()=>{
  it('proposes a same-named, type-fitting source for the listed fields and for no other field of the dictionary',()=>{
    const mappable=STELLAR_METADATA_CATALOG.filter(entry=>entry.mappable&&entry.mappingType);
    expect(mappable.length).toBeGreaterThan(200);
    const proposed:string[]=[];
    for(const entry of mappable){
      const values=SAMPLES[entry.name]??BY_TYPE[entry.mappingType!];
      const found=proposals('json',values.map(value=>({[entry.name]:value})));
      if(approved.includes(entry.name))expect(found,entry.name).toEqual([[entry.name,entry.name,'HIGH']]);
      else expect(found,entry.name).toEqual([]);
      if(found.length)proposed.push(entry.name);
    }
    expect(proposed.sort()).toEqual([...approved].sort());
  });
  it('does not take a name inside an object of the record for a field of the record',()=>{
    const nested:Record<string,unknown>[][]=[
      [{xlate:{srcip:'203.0.113.7'},n:1},{xlate:{srcip:'203.0.113.8'},n:2}],           // a translated address
      [{peer:{dstip:'10.0.0.1'},n:1},{peer:{dstip:'10.0.0.2'},n:2}],
      [{file:{timestamp:'2020-01-01T00:00:00Z'},n:1},{file:{timestamp:'2020-01-02T00:00:00Z'},n:2}], // a file time
      [{target:{username:'alice'},n:1},{target:{username:'bob'},n:2}],
      [{referrer:{url:'https://a.example/x'},n:1},{referrer:{url:'https://b.example/y'},n:2}],
      [{tunnel:{srcport:4500,proto:17},n:1},{tunnel:{srcport:4501,proto:17},n:2}],
      [{previous:{action:'allow'},n:1},{previous:{action:'deny'},n:2}],
      [{answers:{src_ip:'10.0.0.1'},n:1},{answers:{src_ip:'10.0.0.2'},n:2}],             // an alias as a leaf
      [{'flow.sport':40000,'flow.dport':443,'flow.proto':'tcp'},{'flow.sport':40001,'flow.dport':443,'flow.proto':'tcp'}],
    ];
    for(const rows of nested)for(const format of ['json','kv','generic_structural','syslog_rfc5424',undefined])
      expect(proposals(format,rows),JSON.stringify([format,rows[0]])).toEqual([]);
  });
  it('still takes a root-level name, a whole path the policy lists, and a name in the container of the reader',()=>{
    expect(proposals('json',[{srcip:'10.0.0.1'},{srcip:'10.0.0.2'}])).toEqual([['srcip','srcip','HIGH']]);
    expect(proposals('json',[{source:{ip:'10.0.0.1'}},{source:{ip:'10.0.0.2'}}])).toEqual([['source.ip','srcip','HIGH']]);
    expect(proposals('json',[{'id.orig_h':'10.0.0.1',proto:'tcp'},{'id.orig_h':'10.0.0.2',proto:'tcp'}]))
      .toContainEqual(['id.orig_h','srcip','HIGH']);
    expect(proposals('generic_structural',[{generic:{mode:'space_kv',kv:{srcip:'10.0.0.1'}}},
      {generic:{mode:'space_kv',kv:{srcip:'10.0.0.2'}}}])).toEqual([['generic.kv.srcip','srcip','HIGH']]);
    expect(proposals('syslog_rfc5424',[{body:{src_ip:'10.0.0.1'}},{body:{src_ip:'10.0.0.2'}}]))
      .toEqual([['body.src_ip','srcip','HIGH']]);
    // The same container is an object of the log when another reader produced the event.
    expect(proposals('json',[{generic:{kv:{srcip:'10.0.0.1'}}},{generic:{kv:{srcip:'10.0.0.2'}}}])).toEqual([]);
  });
  it('keeps every listed field tied to its dictionary definition and a stated basis',()=>{
    for(const [name,entry] of Object.entries(policy.autoApprovedTargets)){
      const field=findStellarMetadataField(name);
      expect(field?.mappable,name).toBe(true);
      expect(field?.descriptions,name).toContain(entry.definition);
      expect(entry.basis.length,name).toBeGreaterThan(80);
    }
    for(const [name,entry] of Object.entries(policy.autoApprovalDeclined)){
      expect(findStellarMetadataField(name)?.descriptions,name).toContain(entry.definition);
      expect(entry.reason.length,name).toBeGreaterThan(20);
      expect(approved,name).not.toContain(name);
    }
  });
  it('lets no table of the policy lead to a field the policy does not list',()=>{
    const targets=new Set([...Object.values(policy.normalizationAliases),...Object.values(policy.advisoryOnlyAliases),
      ...Object.values(policy.explicitPortSourceAliases),...Object.keys(policy.advisoryTargetTypes)]);
    expect([...targets].filter(target=>!approved.includes(target))).toEqual([]);
    expect(backendPolicy).toEqual(policy);
    // No listed source name is a translated (NAT) endpoint: the browser proposals rely on this.
    const translated=new Set<string>(policy.excludedPortSourceSegments);
    const names=[...Object.keys(policy.normalizationAliases),...Object.keys(policy.advisoryOnlyAliases),
      ...policy.advisoryNameOnlySources,...Object.keys(policy.explicitPortSourceAliases),...approved];
    expect(names.filter(name=>name.split('.').some(segment=>segment.replace(/([a-z0-9])([A-Z])/gu,'$1_$2').toLowerCase()
      .split(/[-_]+/u).some(token=>translated.has(token))))).toEqual([]);
    // body.<name> is the record's pair only for a reader that wrote the body: no whole path of the policy says so.
    expect(names.filter(name=>/^(?:body|generic|fields|kv)\./u.test(name))).toEqual([]);
  });
});
