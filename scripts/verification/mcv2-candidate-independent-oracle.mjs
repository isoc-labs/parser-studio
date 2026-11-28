/** Independent contract oracle; receives a compiled, in-memory mutant on stdin. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const mod=await import('data:text/javascript;base64,'+readFileSync(0,'utf8').trim());
// The reader that produced an event (its effective format) decides which containers hold the pairs of the record.
const READER=new WeakMap();
const readBy=(format,fields)=>{READER.set(fields,format);return fields;};
const bodyOf=kv=>readBy('syslog_rfc3164',{body:kv});
const suggest=(events,existing=[],groups={},options={})=>
  mod.suggestNormalizationCandidatesFromSuite({events:events.map(fields=>
    ({fields,...(READER.has(fields)?{effectiveFormat:READER.get(fields)}:{})}))},
    existing,groups,options);
const row=(fields,source,existing=[])=>suggest([fields],existing).find(c=>c.source===source);
const high=(fields,source,target,type)=>{
  const r=row(fields,source);
  assert.equal(r?.source,source,'source identity '+source);
  assert.equal(r?.target,target,'official destination '+source);
  assert.equal(r?.type,type,'Stellar type '+source);
  assert.equal(r?.confidence,'HIGH','high-confidence '+source);
  assert.equal(r?.safeForBulk,true,'safe bulk '+source);
  assert.equal(r?.catalogVerified,true,'catalog evidence '+source);
  assert.equal(r?.observed,1,'observed '+source);
  assert.equal(r?.compatibleObserved,1,'compatible '+source);
  assert.equal(r?.total,1,'total '+source);
};
const review=(fields,source,target)=>{
  const r=row(fields,source);
  assert.equal(r?.target,target,'review target '+source);
  assert.equal(r?.confidence,'REVIEW','review required '+source);
  assert.equal(r?.safeForBulk,false,'no auto-approve '+source);
};
const absent=(fields,source)=>
  assert.equal(row(fields,source),undefined,'forbidden inference '+source);
high({src_ip:'192.0.2.1'},'src_ip','srcip','ip');
high({src_ip:'2001:db8::1'},'src_ip','srcip','ip');
high({sourceIPAddress:'192.0.2.5'},'sourceIPAddress','srcip','ip');
high({httpRequest:{clientIp:'192.0.2.6'}},'httpRequest.clientIp','srcip','ip');
high({'source-port':594,proto:1},'source-port','srcport','integer');
high({'destination-port':'10400'},'destination-port','dstport','integer');
high({destination_port:65535},'destination_port','dstport','integer');
high({spt:443,protocol:'tcp'},'spt','srcport','integer');
high({event_time:'2026-10-16T12:30:00Z'},'event_time','timestamp','timestamp');
// severity, fidelity and threat_score are 0-100 scores where higher means more. A source field of the same name may
// use another scale (Syslog 0-7 with 0 the most severe, IDS 1-4, CEF 0-10, 0-20, 0-255), run the other way or count
// something else, and no value inside the range shows which. The name is never evidence (owner principle of
// 2026-11-28: no automatic approval without a specification, a verified field definition or the user's approval).
for(const value of [0,2,6,10,11,15,55,80,100,'high'])absent({severity:value},'severity');
absent({asa:{severity:'6'}},'asa.severity');
absent({fidelity:7},'fidelity');absent({fidelity:87},'fidelity');
absent({threat_score:80},'threat_score');absent({threat_score:250},'threat_score');
assert.equal(suggest([{severity:5},{severity:60}]).find(r=>r.source==='severity'),undefined,
  'a larger value elsewhere in the sample is not evidence of the scale either');
assert.equal(suggest([{severity:5},{severity:'-'}]).find(r=>r.source==='severity'),undefined,
  'a placeholder value does not show the scale');
assert.notEqual(row({severity:true},'severity')?.confidence,'HIGH','a non-numeric severity is never approved');
// A translated (NAT) address is not the original endpoint, like a translated port.
absent({nat:{srcip:'203.0.113.7'}},'nat.srcip');
absent({snat_dst_ip:'203.0.113.8'},'snat_dst_ip');
// Default deny (owner decision 2026-11-28). A name is evidence only where it stands for the record: a member of an
// object of the record names that object, whatever the object is called (no list of translated names decides it).
absent({national:{src_ip:'192.0.2.9'}},'national.src_ip');
absent({xlate:{srcip:'203.0.113.7'}},'xlate.srcip');
absent({mapped:{dstip:'203.0.113.7'}},'mapped.dstip');
absent({file:{timestamp:'2020-01-01T00:00:00Z'}},'file.timestamp');
absent({referrer:{url:'https://a.example/x'}},'referrer.url');
absent({previous:{action:'allow'}},'previous.action');
absent({target:{username:'alice'}},'target.username');
// An official field is proposed only when the shared policy lists it. Each of these was approved from its name.
absent({duration_ms:1200},'duration_ms');
absent({session_duration_ms:1200},'session_duration_ms');
absent({policyid:7},'policyid');
absent({appid:41},'appid');
absent({file_size:1024},'file_size');
absent({file_path:'/tmp/a.exe'},'file_path');
absent({localIP:'10.30.5.23'},'localIP');
absent({hostip:'10.30.5.23'},'hostip');
absent({processName:'powershell.exe'},'processName');
absent({commandLine:'powershell.exe -NoProfile'},'commandLine');
absent({parentProcess:'WINWORD.EXE'},'parentProcess');
absent({sha256:'6f5902ac237024bdd0c176cb93063dc46f5902ac237024bdd0c176cb93063dc4'},'sha256');
absent({event_id:4625},'event_id');
absent({computer_name:'WS-01'},'computer_name');
absent({host:{name:'ecs-01'}},'host.name');
absent({process:{name:'agent.exe'}},'process.name');
// The listed fields that have no check of the value beyond its type.
high({username:'alice'},'username','username','string');
high({srcmac:'02:00:00:00:00:01'},'srcmac','srcmac','string');
high({vlan:120},'vlan','vlan','integer');
review({vlan:'guest'},'vlan','vlan');
high({timestamp:'2026-11-27T10:00:00Z'},'timestamp','timestamp','timestamp');
high({proto:6},'proto','proto','integer');
high({protocol:'tcp'},'protocol','proto_name','string');
high({action:'block'},'action','action','string');
// hostname is not a listed field: a name does not say which host is meant (see the host block below).
absent({hostname:'sensor1'},'hostname');
review({src_ip:'invalid-ip'},'src_ip','srcip');
review({'source-port':65536},'source-port','srcport');
review({'source-port':-1},'source-port','srcport');
review({spt:443,protocol:'icmp'},'spt','srcport');
review({spt:443,protocol:'undocumented'},'spt','srcport');
review({spt:443,proto:6,protocol:'icmp'},'spt','srcport');
review({destination_port:'invalid'},'destination_port','dstport');
review({protocol:'HTTPS'},'protocol','proto_name');
review({proto:256},'proto','proto');
review({proto:-1},'proto','proto');
review({event_time:'2026-10-16T12:30:00'},'event_time','timestamp');
absent({severity:101},'severity');
review({src_ip:''},'src_ip','srcip');
review({src_ip:'N/A'},'src_ip','srcip');
absent({post_nat:{'source-port':443}},'post_nat.source-port');
absent({nat_source:{'source-port':443}},'nat_source.source-port');
absent({translated_source:{'source-port':443}},'translated_source.source-port');
absent({event_type:'alert'},'event_type');
absent({duration:2000},'duration');
// Stellar direction is the direction of a maltrace event; a vendor direction field is not that (2026-11-23).
absent({direction:'client-to-server'},'direction');
absent({generic:{fields:{direction:'server-to-client',src:'10.0.0.1'}}},'generic.fields.direction');
absent({action:'admin-login'},'action');
absent({syslog:{severity:4}},'syslog.severity');
absent({unknown_vendor_field:42},'unknown_vendor_field');
absent({type:'TRAFFIC',logid:'0001',vd:'root'},'type');
absent({eventtype:'traffic',logid:'0001',vd:'root',type:'traffic'},'eventtype');
absent({direction:'inbound',logid:'0001',vd:'root',type:'traffic'},'direction');
absent({type:'traffic'},'type');
// The Windows-agent type is not a listed field, with or without the fields of a Windows event beside it.
absent({type:4,provider_guid:'abc'},'type');
absent({event_type:'alert',alert:{signature_id:1,severity:2}},'alert.severity');
// Generic Structural space_kv: an unquoted value runs to the next key, so a
// destination port followed by free text is stored whole under kv and as
// whitespace-separated pieces under atoms. A port/IP cannot contain whitespace,
// hence ONLY the first piece of a port/IP key is a valid official source.
const spaced=(key,pieces)=>readBy('generic_structural',{generic:{mode:'space_kv',
  kv:{[key]:pieces.join(' ')},
  atoms:Object.fromEntries(pieces.map((p,i)=>[key+'_'+String(i+1).padStart(3,'0'),p]))}});
// The same atom in an event another reader produced is a member of an object of the log.
absent({generic:{mode:'space_kv',kv:{dport:'53 x'},atoms:{dport_001:'53',dport_002:'x'}}},'generic.atoms.dport_001');
high(spaced('dport',['53','pattern:','allow','all']),'generic.atoms.dport_001','dstport','integer');
high(spaced('sport',['55719','extra']),'generic.atoms.sport_001','srcport','integer');
high(spaced('src',['192.0.2.7','trailing']),'generic.atoms.src_001','srcip','ip');
high(spaced('dst',['198.51.100.7','trailing']),'generic.atoms.dst_001','dstip','ip');
review(spaced('dport',['abc','def']),'generic.atoms.dport_001','dstport');
review(spaced('dport',['65536','x']),'generic.atoms.dport_001','dstport');
review(spaced('dport',['53','pattern:','allow','all']),'generic.kv.dport','dstport');
// The protocol that qualifies a port atom is recorded on the KV carrier, not on the atom.
const withProtocol=(event,protocol)=>readBy('generic_structural',{generic:{...event.generic,kv:{...event.generic.kv,protocol}}});
review(withProtocol(spaced('dport',['53','trailing']),'icmp'),'generic.atoms.dport_001','dstport');
review(withProtocol(spaced('dport',['53','trailing']),'icmp reply'),'generic.atoms.dport_001','dstport');
high(withProtocol(spaced('dport',['53','trailing']),'tcp'),'generic.atoms.dport_001','dstport','integer');
absent(spaced('dport',['x','53']),'generic.atoms.dport_002');
absent(spaced('dport',['53','80']),'generic.atoms.dport_002');
absent(spaced('severity',['3','of','5']),'generic.atoms.severity_001');
absent(spaced('action',['allow','now']),'generic.atoms.action_001');
absent(spaced('hostname',['fw01','edge']),'generic.atoms.hostname_001');
absent(spaced('time',['2026-01-01','10:00:00']),'generic.atoms.time_001');
absent(spaced('post_nat_sport',['443','x']),'generic.atoms.post_nat_sport_001');
absent(spaced('unknown_vendor',['53','x']),'generic.atoms.unknown_vendor_001');
{
  // The two carriers of one key do not compete: only the atom can be approved.
  const both=suggest([spaced('dport',['53','pattern:','allow','all'])]);
  assert.deepEqual(both.filter(r=>r.confidence==='HIGH').map(r=>r.source),
    ['generic.atoms.dport_001'],'only the first atom is auto-approved');
  const kv=both.find(r=>r.source==='generic.kv.dport');
  assert.equal(kv?.safeForBulk,false,'whole-text kv value is never auto-approved');
}
const noMapping=[{id:'owner',source:'custom',target:'srcip',type:'ip'}];
assert.equal(suggest([{src_ip:'192.0.2.1'}],noMapping).length,0,'occupied target');
const current={id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'string',
  authoring:{version:1,origin:'AUTO'}};
const generated=row({src_ip:'192.0.2.1'},'src_ip',[current]);
assert.equal(generated?.safeForBulk,true,'trusted generated mapping');
assert.equal(generated?.replacesMappingId,'auto-1','source identity provenance');
assert.equal(generated?.currentTarget,'custom.src_ip','destination provenance');
for(const origin of ['USER_EDITED','APPROVED']){
  const owned=row({src_ip:'192.0.2.1'},'src_ip',
    [{...current,authoring:{version:1,origin}}]);
  assert.equal(owned?.safeForBulk,false,'manual edit protected '+origin);
}
assert.equal(row({src_ip:'192.0.2.1'},'src_ip',
  [{id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'string'}])?.safeForBulk,
  false,'legacy unmarked provenance');
assert.equal(suggest([{src_ip:'192.0.2.1'}],
  [{id:'auto-1',source:'src_ip',target:'srcip',type:'ip',
    authoring:{version:1,origin:'AUTO'}}],{'auto-1':'top_fields'}).length,
  0,'identical official mapping and group');
assert.equal(row({src_ip:'192.0.2.1'},'src_ip',
  [{id:'r2',source:'other',target:'srcip.extra',type:'string'}]),undefined,
  'nested target collision');
const sparse=suggest([{src_ip:'192.0.2.1'},{dst_ip:'198.51.100.1'}]);
assert.deepEqual(sparse.map(r=>r.source).sort(),['dst_ip','src_ip']);
assert.ok(sparse.every(r=>r.confidence==='REVIEW'&&!r.safeForBulk&&
  r.observed===1&&r.total===2),'heterogeneous family scope');
const mixed=suggest([{src_ip:'192.0.2.1'},{src_ip:'invalid-ip'}]);
assert.equal(mixed[0]?.compatibleObserved,1,'mixed type evidence');
assert.equal(mixed[0]?.confidence,'REVIEW','invalid event');
const competing=suggest([{source_ip:'192.0.2.1',src_ip:'198.51.100.1'}]);
assert.equal(competing.length,2,'both ambiguous sources retained');
assert.ok(competing.every(r=>r.confidence==='REVIEW'&&!r.safeForBulk));
assert.equal(suggest([{source_ip:'192.0.2.1',src_ip:'198.51.100.1'}],
  [],{},{skipAmbiguousTargets:true}).length,0,'ambiguous skip');
assert.deepEqual(suggest([{src_ip:'192.0.2.1',srcport:443}]).map(r=>r.source),
  ['src_ip','srcport'],'single-event insertion order');
const reversed=[{dst_ip:'192.0.2.1',src_ip:'198.51.100.1'},
  {src_ip:'198.51.100.2',dst_ip:'192.0.2.2'}];
assert.deepEqual(suggest(reversed),suggest([...reversed].reverse()),
  'multi-event deterministic');
assert.deepEqual(mod.suggestNormalizationCandidatesFromSuite(undefined,[]),[],
  'missing suite');
assert.deepEqual(suggest([]),[],'empty suite');
const scan=mod.normalizationCandidateScanStatus({events:[{fields:{
  unknown:1,src_ip:'192.0.2.1',dst_port:443}}]});
assert.equal(scan.eligiblePaths,2,'eligible paths');
assert.equal(scan.exceeded,false,'within budget');
assert.deepEqual(scan.paths,['src_ip','dst_port'],'stable order');
const many=Object.fromEntries(Array.from({length:1025},(_,i)=>
  ['node'+i,{src_ip:'192.0.2.1'}]));
const over=mod.normalizationCandidateScanStatus({events:[{fields:many}]});
assert.equal(over.sourceScanTruncated,true,'single-event over 1024 paths flagged');
assert.equal(over.exceeded,true,'large event fails closed');
assert.deepEqual(over.paths,[],'no truncated auto-approve');
assert.deepEqual(suggest([many]),[],'no partial official suggestions');
const exactly1024=Object.fromEntries(Array.from({length:1024},(_,i)=>
  ['node'+i,{src_ip:'192.0.2.1'}]));
const within=mod.normalizationCandidateScanStatus({events:[{fields:exactly1024}]});
assert.equal(within.sourceScanTruncated,false,'exact scan bound is allowed');
assert.equal(within.eligiblePaths,1024,'last scanned path not lost');
const late={src_ip:'192.0.2.1',
  ...Object.fromEntries(Array.from({length:99},(_,i)=>['vendor_'+i,i])),
  source_ip:'198.51.100.1'};
const complete=suggest([late]);
assert.equal(complete.length,2,'late official alias must not be missed');
assert.ok(complete.every(r=>r.target==='srcip'&&r.confidence==='REVIEW'&&
  !r.safeForBulk),'no auto-approval of early alias with late competitor');
const distributed=Array.from({length:21},(_,i)=>Object.fromEntries(
  Array.from({length:50},(_,j)=>['product_'+(i*50+j),{srcip:'192.0.2.1'}])));
const multi=mod.normalizationCandidateScanStatus({
  events:distributed.map(fields=>({fields}))});
assert.equal(multi.eligiblePaths,1050,'cross-event eligible census');
assert.equal(multi.exceeded,true,'aggregate budget fails closed');
assert.equal(multi.sourceScanTruncated,false,'per-event not truncated');
assert.equal(mod.MAX_OFFICIAL_CANDIDATE_SCAN,1024,'bounded scan');
assert.equal(mod.valueFitsMappingType('integer',443),true);
assert.equal(mod.valueFitsMappingType('integer','not-an-integer'),false);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer',65535),true);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer',65536),false);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer',null),true);
// Additional independently stated decision and explanation contracts.
absent({vendor:{url:'https://example.com/a'}},'vendor.url');
high({rule:{name:'policy-1'}},'rule.name','rule.name','string');
absent({flow:{spt:443,protocol:'icmp'}},'flow.spt');
absent({flow:{spt:443,protocol:'tcp'}},'flow.spt');
// Protocol evidence in the container that holds the port: the body of a Syslog record is such a container.
review(bodyOf({sport:443,dport:80,protocol:'icmp'}),'body.sport','srcport');
high(bodyOf({sport:443,dport:80,protocol:'tcp'}),'body.sport','srcport','integer');
review({action:'N/A'},'action','action');
absent({hostname:'fg',logid:'001',vd:'root',type:'traffic'},'hostname');
absent({hostname:'fg',vd:'root',type:'traffic'},'hostname');
// icmp_type is not a listed field: its value means something only in an ICMP event.
absent({'icmp-type':8,'protocol-id':6},'icmp-type');
absent({'icmp-type':8,'protocol-id':1},'icmp-type');
assert.equal(suggest([{'icmp-type':8,'protocol-id':1},{'protocol-id':6}]).find(r=>r.source==='icmp-type'),undefined,
  'an ICMP type is not proposed in a sparse sample either');
absent({event_type:'alert',alert:{signature_id:99,severity:2}},'alert.severity');
// A Suricata priority is not the 0-100 score inside an alert or outside one, whatever its value.
absent({event_type:'alert',alert:{signature_id:99,severity:75}},'alert.severity');
absent({event_type:'flow',alert:{signature_id:99,severity:2}},'alert.severity');
absent({event_type:'flow',alert:{signature_id:99,severity:75}},'alert.severity');
const policyCandidate=row({'policy-name':'policy-1'},'policy-name');
assert.equal(policyCandidate?.target,'rule.name','policy-name official alias');
assert.equal(row({'policy-name':'policy-1'},'policy-name',
  [{id:'taken',source:'other',target:'rule',type:'string'}]),undefined,
  'parent destination overlap');
const descriptions=[
  [row({'source-port':594},'source-port'),'explicitly names a port'],
  [row({src_ip:'192.0.2.1'},'src_ip'),'Reviewed source alias'],
  [row({srcip:'192.0.2.1'},'srcip'),'Source name matches'],
  [row({spt:443,protocol:'icmp'},'spt'),'abbreviated port field'],
  [suggest([{src_ip:'192.0.2.1'},{dst_ip:'192.0.2.2'}])[0],
    'missing from some events'],
  [row({src_ip:''},'src_ip'),'no informative values'],
  [row({src_ip:'invalid-ip'},'src_ip'),'incompatible'],
  [suggest([{source_ip:'192.0.2.1',src_ip:'192.0.2.2'}])[0],
    'multiple source fields'],
];
for(const [candidate,part] of descriptions)
  assert.ok(candidate?.explanation.includes(part),
    'independent UI reason: '+part);
assert.equal(row({srcip:'192.0.2.1'},'srcip')?.method,
  'EXACT_DICTIONARY_NAME','exact catalog identity');
assert.equal(row({src_ip:'192.0.2.1'},'src_ip')?.method,
  'DOCUMENTED_ALIAS','documented alias identity');
assert.equal(multi.paths.length,0,'aggregate-overflow candidates unavailable');
assert.equal(mod.valueFitsMappingType('integer','N/A'),true);
assert.equal(mod.valueFitsMappingType('ip',null),true);
// A blank-only string is a missing value for the run time, so it fits every type; NBSP is a value.
assert.equal(mod.valueFitsMappingType('ip','  '),true);
assert.equal(mod.valueFitsMappingType('integer','\t \r\n'),true);
assert.equal(mod.valueFitsMappingType('ip',undefined),true);
assert.equal(mod.valueFitsMappingType('ip','\u00a0'),false);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer',' '),true);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer','\u00a0'),false);
// Per-container protocol evidence must not disappear when root fields differ.
review(bodyOf({sport:443,dport:80,'protocol-id':1}),'body.sport','srcport');
// Audit G-13: protocol evidence written in other common ways; a protocol object's non-protocol member is not
// evidence; another object of the record is another family; a bare transport= (FortiGate) is a port.
review({spt:8,'protocol.name':'icmp'},'spt','srcport');
review({spt:8,'flow.l4.proto':'icmp'},'spt','srcport');
review({spt:8,ip_protocol:'icmp'},'spt','srcport');
review({spt:8,l4_proto:'icmp'},'spt','srcport');
review({spt:8,network:{transport:'icmp'}},'spt','srcport');
review({spt:8,protocol:{name:'icmp',flags:'SYN'}},'spt','srcport');
review({spt:8,protocol:{meta:{name:'icmp'}}},'spt','srcport');
high({spt:443,protocol:{name:'tcp',number:6,flags:'SYN'}},'spt','srcport','integer');
high({spt:443,protocol:{name:'tcp',state:'ESTABLISHED',direction:'in'}},'spt','srcport','integer');
high({spt:443,proto:6,network:{transport:'tcp'}},'spt','srcport','integer');
high({spt:443,proto:6,other:{protocol:'icmp'}},'spt','srcport','integer');
high({spt:443,proto:6,transport:8080},'spt','srcport','integer');
high({spt:443,proto:6,network:{bytes:10}},'spt','srcport','integer');
// A literal key written with a protocol-named prefix: only the sibling's own name is read ('proto.' is how the
// source is written), and a list of transport names is transport evidence.
// Default deny: a literal key written with a prefix names an attribute of what the prefix names and is not proposed.
absent({'proto.sport':443,'proto.dport':8443,'proto.note':'x'},'proto.sport');
high({spt:443,protocol:['tcp','udp']},'spt','srcport','integer');
review({spt:443,protocol:['tcp','icmp']},'spt','srcport');
// A non-transport protocol at the root of the record keeps a port of a nested object in review.
review(readBy('syslog_rfc3164',{body:{sport:443,dport:80},protocol:'icmp'}),'body.sport','srcport');
// Re-audit A1: ECS network.protocol is the application protocol, not the IP protocol.
high({spt:443,network:{transport:'tcp',protocol:'http'}},'spt','srcport','integer');
high({spt:443,'network.transport':'udp','network.protocol':'dns'},'spt','srcport','integer');
review({spt:8,network:{transport:'icmp',protocol:'http'}},'spt','srcport');
review(bodyOf({sport:443,dport:80,proto:1}),'body.sport','srcport');
review(bodyOf({sport:443,dport:80,proto_name:'icmp'}),'body.sport','srcport');
high(bodyOf({sport:443,dport:80,'protocol-id':6}),'body.sport','srcport','integer');
absent({post_nat:{'destination-port':443}},'post_nat.destination-port');
absent({translated_source:{'destination-port':443}},'translated_source.destination-port');
absent({icmp_type:'8','protocol-id':6},'icmp_type');
// The Junos structured-data reader writes icmp_type beside protocol_id: zero-filled on TCP/UDP, a type on ICMP.
absent(readBy('generic_structural',{junos_sd:{icmp_type:'0',protocol_id:'6'}}),'junos_sd.icmp_type');
absent(readBy('generic_structural',{junos_sd:{icmp_type:'8',protocol_id:'1'}}),'junos_sd.icmp_type');
high(readBy('generic_structural',{junos_sd:{source_address:'10.0.0.1',protocol_id:'6'}}),'junos_sd.source_address','srcip','ip');
// A sample of several record families: an endpoint field that carries the official name itself is approved
// although one family lacks it; an alias, or an official name of another kind, stays a review proposal.
const families=suggest([{srcip:'192.0.2.1',srcport:51544,dstport:443,proto:6,md5:'69630e4574ec6798239b091cda43dca0'},
  {note:'system record'}]);
for(const name of ['srcip','srcport','dstport','proto']){
  const found=families.find(r=>r.source===name);
  assert.equal(found?.target,name,'sparse official-name endpoint '+name);
  assert.equal(found?.confidence,'HIGH','sparse official-name endpoint approved '+name);
  assert.equal(found?.safeForBulk,true,'sparse official-name endpoint bulk '+name);
}
assert.equal(families.find(r=>r.source==='md5'),undefined,'an official name the policy does not list is not proposed');
// A listed field that is not an endpoint or URL field keeps the full-coverage rule.
for(const [name,value] of [['username','alice'],['action','deny'],['vlan',120],['timestamp','2026-11-27T10:00:00Z']]){
  const sparse=suggest([{srcip:'192.0.2.1',[name]:value},{note:'system record'}]).find(r=>r.source===name);
  assert.equal(sparse?.target,name,'sparse listed name is proposed '+name);
  assert.equal(sparse?.confidence,'REVIEW','sparse listed name stays a review proposal '+name);
  assert.equal(sparse?.safeForBulk,false,'sparse listed name is not approved '+name);
}
// A source called proto: documented protocol names are the name field, numbers the number field.
const target=(events,source)=>suggest(events).filter(r=>r.source===source).map(r=>r.target+':'+r.confidence);
assert.deepEqual(target([{proto:'tcp'},{proto:'UDP'}],'proto'),['proto_name:HIGH'],'protocol names');
assert.deepEqual(target([{proto:'tcp'},{proto:'-'}],'proto'),['proto_name:HIGH'],'a placeholder beside a name does not make the field a number');
assert.deepEqual(target([{proto:6},{proto:'17'}],'proto'),['proto:HIGH'],'protocol numbers');
assert.deepEqual(target([{proto:'tcp'},{proto:6}],'proto'),['proto:REVIEW'],'names and numbers mixed');
assert.deepEqual(target([{proto:'https'}],'proto'),['proto:REVIEW'],'an application label is neither');
// Independent audit of 2026-11-21 (F3-F6, F9): sparse approval needs TCP or UDP named by the record for a port,
// a record-level source, a URL-shaped url, and never applies to an explicit port label or a Zeek id.*_p alias
// without a transport protocol.
const rv=(events,source)=>suggest(events).filter(r=>r.source===source).map(r=>r.confidence);
assert.deepEqual(rv([{srcport:51234,ipproto:6},{srcport:8,ipproto:1},{note:'x'}],'srcport'),['REVIEW'],'ICMP family, ipproto');
assert.deepEqual(rv([{srcport:8},{note:'x'}],'srcport'),['REVIEW'],'sparse port, no protocol');
assert.deepEqual(rv([{srcport:51234,l4proto:'tcp'},{note:'x'}],'srcport'),['HIGH'],'sparse port, l4proto=tcp');
assert.deepEqual(rv([{srcport:51234,proto:6,transport:51234},{note:'x'}],'srcport'),['HIGH'],'FortiGate transport is a translated port, not a protocol');
assert.deepEqual(rv([{xlate:{srcip:'203.0.113.5'}},{note:'x'}],'xlate.srcip'),[],'nested endpoint');
assert.deepEqual(rv([{xlate:{srcip:'203.0.113.5'}},{xlate:{srcip:'203.0.113.6'}}],'xlate.srcip'),[],'nested endpoint that every event carries');
assert.deepEqual(rv([{generic:{kv:{srcip:'203.0.113.5'}}},{note:'x'}],'generic.kv.srcip'),[],'a container of an unknown reading is not the record level');
// Re-audit of 2026-11-21 (N2-N4).
assert.deepEqual(rv([{proto:6,fields:{srcip:'203.0.113.5',srcport:40002}},{note:'x'}],'fields.srcip'),[],'JSON object called fields');
assert.deepEqual(rv([{proto:6,fields:{srcip:'203.0.113.5',srcport:40002}},{note:'x'}],'fields.srcport'),[],'a port of a nested object is not proposed');
assert.deepEqual(rv([{srcport:51234,dstport:443,service:'HTTPS'},{srcport:8,dstport:0,service:'PING'},{srcport:'-',dstport:'-',service:'-'}],'srcport'),['REVIEW'],'a placeholder is not coverage');
assert.deepEqual(rv([{SrcPort:51234,Protocol:'TCP'},{SrcPort:8,Protocol:'ICMP'}],'SrcPort'),['REVIEW'],'protocol field name in another case');
assert.deepEqual(rv([{SrcPort:51234,Protocol:'TCP'},{SrcPort:443,Protocol:'udp'}],'SrcPort'),['HIGH'],'TCP and UDP named in another case');
assert.deepEqual(rv([{srcport:51234,proto:6},{srcport:8},{note:'x'}],'srcport'),['REVIEW'],'evidence of one event does not serve another');
// The record level follows from the reading of the events that carry the source.
const read=(format,events,source)=>mod.suggestNormalizationCandidatesFromSuite(
  {events:events.map(fields=>({fields,effectiveFormat:format}))},[]).filter(r=>r.source===source).map(r=>r.confidence);
const inKv={generic:{kv:{srcip:'203.0.113.5',srcport:40002,proto:6}}},inBody={body:{srcip:'203.0.113.5',srcport:40002,proto:6}};
const other={generic:{kv:{note:'x'}},body:{note:'x'}};
assert.deepEqual(read('generic_structural',[inKv,other],'generic.kv.srcip'),['HIGH'],'generic reader container');
// A normalized Generic Structural event keeps the source record under parserstudio_source: the same container
// one level down is still the container of the reader.
assert.deepEqual(read('generic_structural',[{parserstudio_source:inKv},{parserstudio_source:other}],
  'parserstudio_source.generic.kv.srcip'),['HIGH'],'generic reader container in the source copy');
// The single-event helper judges a container by the reader it is told; told none, a container is not one.
assert.deepEqual(mod.suggestNormalizationCandidates(inKv,[],'generic_structural')
  .filter(r=>r.source==='generic.kv.srcip').map(r=>r.confidence),['HIGH'],'single event, reader named');
assert.deepEqual(mod.suggestNormalizationCandidates(inKv,[])
  .filter(r=>r.source==='generic.kv.srcip').map(r=>r.confidence),[],'single event, no reader named');
assert.deepEqual(read('generic_structural',[inKv,other],'generic.kv.srcport'),['HIGH'],'port with TCP in its own container');
assert.deepEqual(read('json',[inKv,other],'generic.kv.srcip'),[],'the same path in a JSON log');
assert.deepEqual(read('json',[inKv,inKv],'generic.kv.srcip'),[],'the same path in a JSON log, in every event');
assert.deepEqual(read('syslog_rfc3164',[inBody,other],'body.srcip'),['HIGH'],'RFC 3164 body');
assert.deepEqual(read('syslog_rfc5424',[inBody,other],'body.srcip'),['HIGH'],'RFC 5424 body');
// A mixed event is read by the grammar of its family (the router's reading family), never by the name 'mixed'.
const mixedRead=(families,events,source)=>mod.suggestNormalizationCandidatesFromSuite(
  {events:events.map((fields,index)=>({fields,effectiveFormat:'mixed',readingFamily:families[index]}))},[])
  .filter(r=>r.source===source).map(r=>r.confidence);
assert.deepEqual(mixedRead(['rfc5424_kv','rfc5424_kv'],[inBody,other],'body.srcip'),['HIGH'],'RFC 5424 body of a mixed reading');
assert.deepEqual(mixedRead(['rfc3164_kv','rfc3164_kv'],[inBody,other],'body.srcip'),['HIGH'],'RFC 3164 body of a mixed reading');
assert.deepEqual(mixedRead(['json','json'],[inBody,other],'body.srcip'),[],'a JSON object called body in a mixed reading');
assert.deepEqual(read('mixed',[inBody,other],'body.srcip'),[],'a mixed event without its reading family');
// CEF/LEEF extension keys the specification defines (src, dst, spt, dpt; LEEF srcPort, dstPort) are read like
// a source named as its official field, inside a CEF or LEEF record only.
const cefRecord={cef_version:'0',src:'192.0.2.1',dst:'198.51.100.2',spt:'40000',dpt:'443',proto:'TCP'};
const cefOther={cef_version:'0',suser:'admin'};
assert.deepEqual(read('cef',[cefRecord,cefOther],'dst'),['HIGH'],'CEF dst in some records');
assert.deepEqual(read('cef',[cefRecord,cefOther],'dpt'),['HIGH'],'CEF dpt beside proto=TCP in some records');
assert.deepEqual(read('cef',[cefRecord,{...cefRecord,dst:'198.51.100.3'},cefOther],'dst'),['HIGH'],'CEF dst in two records of three');
assert.deepEqual(read('cef',[cefRecord,{suser:'admin'}],'dst'),['HIGH'],'a record without the key needs no CEF version');
// The Syslog and Generic Structural readers report the grammar of the body (bodyKind); the mixed router its family.
const readBody=(format,kinds,events,source)=>mod.suggestNormalizationCandidatesFromSuite(
  {events:events.map((fields,index)=>({fields,effectiveFormat:format,bodyKind:kinds[index]}))},[])
  .filter(r=>r.source===source).map(r=>r.confidence);
assert.deepEqual(readBody('syslog_rfc5424',['cef','cef'],[{body:cefRecord},{body:cefOther}],'body.dst'),['HIGH'],'CEF dst in a Syslog body');
assert.deepEqual(readBody('syslog_rfc3164',['cef',undefined],[{body:cefRecord},{body:{note:'x'}}],'body.dst'),['HIGH'],'CEF dst in an RFC 3164 body');
assert.deepEqual(readBody('generic_structural',['cef','cef'],[{body:cefRecord},{body:cefOther}],'body.dst'),['HIGH'],'CEF dst in a Generic Structural body');
assert.deepEqual(readBody('syslog_rfc5424',['leef','leef'],[{body:{leef_version:'2.0',src:'192.0.2.1',dstPort:'443',proto:'6'}},{body:{leef_version:'2.0',usrName:'a'}}],'body.dstPort'),['HIGH'],'LEEF dstPort in a Syslog body');
// F2 (independent audit 2026-11-23): a JSON or key=value body is not CEF, whatever its keys are called.
assert.deepEqual(readBody('syslog_rfc5424',['json','json'],[{body:cefRecord},{body:cefOther}],'body.dst'),['REVIEW'],'cef_version in a JSON Syslog body');
assert.deepEqual(readBody('syslog_rfc5424',['kv','kv'],[{body:cefRecord},{body:cefOther}],'body.dst'),['REVIEW'],'cef_version in a key=value Syslog body');
assert.deepEqual(readBody('syslog_rfc5424',[undefined,undefined],[{body:cefRecord},{body:cefOther}],'body.dst'),['REVIEW'],'a Syslog body of no reported grammar');
assert.deepEqual(readBody('syslog_rfc5424',['leef','leef'],[{body:cefRecord},{body:cefOther}],'body.dst'),['REVIEW'],'a CEF version in a LEEF body');
assert.deepEqual(readBody('json',['cef','cef'],[cefRecord,cefOther],'dst'),['REVIEW'],'a JSON reading never has a CEF body');
assert.deepEqual(readBody('cef',['json','json'],[cefRecord,cefOther],'dst'),['HIGH'],'the CEF reading itself');
assert.deepEqual(mixedRead(['rfc5424_cef','rfc5424_cef'],[{body:cefRecord},{body:cefOther}],'body.dst'),['HIGH'],'a CEF family of a mixed reading');
assert.deepEqual(mixedRead(['rfc3164_leef','rfc3164_leef'],[{body:{leef_version:'2.0',src:'192.0.2.1',dstPort:'443',proto:'6'}},{body:{leef_version:'2.0',usrName:'a'}}],'body.dstPort'),['HIGH'],'a LEEF family of a mixed reading');
assert.deepEqual(mixedRead(['cef','cef'],[cefRecord,cefOther],'dst'),['HIGH'],'the CEF family of a mixed reading');
assert.deepEqual(mixedRead(['rfc5424_json','rfc5424_json'],[{body:cefRecord},{body:cefOther}],'body.dst'),['REVIEW'],'a JSON family of a mixed reading');
assert.deepEqual(mixedRead(['rfc5424_kv','rfc5424_kv'],[{body:cefRecord},{body:cefOther}],'body.dst'),['REVIEW'],'a key=value family of a mixed reading');
assert.deepEqual(mixedRead(['xcef','xcef'],[cefRecord,cefOther],'dst'),['REVIEW'],'a family name that only ends in cef');
assert.deepEqual(read('leef',[{leef_version:'2.0',src:'192.0.2.1',dstPort:'443',proto:'6'},{leef_version:'2.0',usrName:'a'}],'dstPort'),['HIGH'],'LEEF dstPort');
assert.deepEqual(read('kv',[cefRecord,cefOther],'dst'),['REVIEW'],'the same names in a key=value log');
const {cef_version:_v,...bareCef}=cefRecord;
assert.deepEqual(readBody('syslog_rfc5424',['cef','cef'],[{cef_version:'0',body:bareCef},{body:cefOther}],'body.dst'),['REVIEW'],'the version beside the body is not the version of the body');
assert.deepEqual(read('cef',[bareCef,cefOther],'dst'),['REVIEW'],'no CEF version in the record of the key');
assert.deepEqual(read('cef',[bareCef,cefRecord,cefOther],'dst'),['REVIEW'],'one record of the key without CEF version');
assert.deepEqual(read('cef',[{...cefRecord,dst:'db01.example.com'},cefOther],'dst'),['REVIEW'],'a CEF dst that is not an address');
// The WatchGuard Traffic Monitor layout defines its port positions; an ICMP message has none.
const wgTcp={generic:{mode:'watchguard_traffic_monitor'},watchguard:{src_ip:'10.0.1.2',dst_ip:'100.100.100.11',protocol:'tcp',src_port:'42017',dst_port:'80',kv:{msg_id:'3000-0176'}}};
const wgIcmp={generic:{mode:'watchguard_traffic_monitor'},watchguard:{src_ip:'10.0.1.131',dst_ip:'10.0.1.1',protocol:'icmp',kv:{msg_id:'3000-0148',type:'8'}}};
assert.deepEqual(read('generic_structural',[wgTcp,wgIcmp],'watchguard.src_port'),['HIGH'],'WatchGuard source port position');
assert.deepEqual(read('generic_structural',[wgTcp,wgIcmp],'watchguard.src_ip'),['HIGH'],'WatchGuard source address position');
assert.deepEqual(read('generic_structural',[{...wgTcp,generic:{mode:'space_kv'}},{...wgIcmp,generic:{mode:'space_kv'}}],'watchguard.src_port'),['REVIEW'],'the same name in another reading');
const wgKv={generic:{mode:'watchguard_traffic_monitor'},watchguard:{protocol:'tcp',kv:{src_port:'42017',protocol:'tcp'}}};
assert.deepEqual(read('generic_structural',[wgKv,wgIcmp],'watchguard.kv.src_port'),['REVIEW'],'a detail pair is not the layout position');
assert.deepEqual(mod.suggestNormalizationCandidatesFromSuite({events:[inBody,other].map(fields=>
  ({fields,effectiveFormat:'json',readingFamily:'rfc5424_kv'}))},[]).filter(r=>r.source==='body.srcip').map(r=>r.confidence),
  [],'a reading family is read only for a mixed event');
assert.deepEqual(read('json',[inBody,other],'body.srcip'),[],'a JSON object called body');
assert.deepEqual(read('kv',[inBody,other],'body.srcip'),[],'no container in a key=value reading');
assert.deepEqual(read('syslog_rfc3164',[inKv,other],'generic.kv.srcip'),[],'generic container under a Syslog reading');
assert.deepEqual(read('generic_structural',[{xlate:{fields:{srcip:'203.0.113.5'}}},other],'xlate.fields.srcip'),[],'not a reader container');
// The other containers the readers write the record into.
assert.deepEqual(read('generic_structural',[{asa:{src_ip:'10.0.0.1'}}],'asa.src_ip'),['HIGH'],'ASA reader node');
assert.deepEqual(read('generic_structural',[{juniper:{'source-address':'10.0.0.1'}}],'juniper.source-address'),['HIGH'],'Juniper reader node');
assert.deepEqual(read('generic_structural',[{body:{leef_extension:{src:'10.0.0.1'}}}],'body.leef_extension.src'),['HIGH'],'LEEF extension of the implicit-tab reading');
assert.deepEqual(read('generic_structural',[{syslog:{timestamp:'2026-11-27T10:00:00Z'}}],'syslog.timestamp'),['HIGH'],'Syslog header of Generic Structural');
assert.deepEqual(read('syslog_rfc5424',[{syslog_sd:{element_1:{params:{'source-address':'10.0.0.1'}}}}],'syslog_sd.element_1.params.source-address'),['HIGH'],'SD-PARAM of an RFC 5424 element');
for(const format of ['json','kv','cef','syslog_rfc3164'])for(const [fields,path] of [[{asa:{src_ip:'10.0.0.1'}},'asa.src_ip'],
  [{juniper:{'source-address':'10.0.0.1'}},'juniper.source-address'],[{syslog:{timestamp:'2026-11-27T10:00:00Z'}},'syslog.timestamp'],
  [{syslog_sd:{element_1:{params:{'source-address':'10.0.0.1'}}}},'syslog_sd.element_1.params.source-address']])
  assert.deepEqual(read(format,[fields],path),[],'the same path under another reading: '+format+' '+path);
// hostname is not a listed field (default deny, owner decision 2026-11-28): a name does not say which host is meant,
// and the 7.0 dictionary defines the field for one source only ("The host name (Linux Audit)."). The earlier rules
// told a requested host from a device host by the values of the record (audits F-05, F-06, G-04, G-08); none of
// their samples is proposed now, whichever host it holds.
for(const sample of [
  {method:'GET',host:'example.com',uri:'/index.html',status_code:200},
  {host:'shop.example.com',request:'GET /cart HTTP/1.1',status:200},
  {host:'fw01',msg:'link up'},{host:'fw01',url:'/admin',action:'login'},
  {host:'fw01',referer:'https://portal.example.com/start',action:'allow'},
  {host:'srv01',action:'delete',user:'bob'},
  {client:'10.0.0.5',host:'example.com',url:'http://example.com/a',status:200}])absent(sample,'host');
absent({http:{hostname:'example.com',http_method:'GET',protocol:'HTTP/1.1'}},'http.hostname');
absent({agent:{hostname:'collector-7'},message:'started'},'agent.hostname');
absent({'http.host':'example.com','http.uri':'/index.html'},'http.host');
absent({client_ip:'192.0.2.70',action:'deny',host_name:'edge-01'},'host_name');
absent({device_name:'ise-01',username:'alice'},'device_name');
absent({deviceName:'vision-01'},'deviceName');
// The host of a Syslog header is not proposed either, in any reading.
assert.deepEqual(read('syslog_rfc3164',[{syslog_hostname:'web01',body:{method:'GET',host:'example.com',uri:'/'}}],'syslog_hostname'),[],'Syslog header host');
assert.deepEqual(read('syslog_rfc3164',[{syslog_hostname:'web01',body:{method:'GET',host:'example.com',uri:'/'}}],'body.host'),[],'host of the request beside a Syslog header');
assert.deepEqual(read('generic_structural',[{syslog:{hostname:'web01'},generic:{kv:{host:'fw01',action:'allow'}}}],'syslog.hostname'),[],'Syslog header host of Generic Structural');
assert.deepEqual(read('generic_structural',[{syslog:{hostname:'web01'},generic:{kv:{host:'fw01',action:'allow'}}}],'generic.kv.host'),[],'host pair of Generic Structural');
assert.deepEqual(read('generic_structural',[{parserstudio_source:{syslog:{host:'bigip-waf01',time:'00:14:27'}}}],'parserstudio_source.syslog.host'),[],'Syslog header host in the source copy');
// A literal dotted key in the body of a Syslog record is two levels below the record and is not proposed.
assert.deepEqual(read('syslog_rfc3164',[{body:{'flow.sport':8,'flow.dport':0,'flow.proto':'icmp'}}],'body.flow.sport'),[],'literal dotted key in a Syslog body');
assert.deepEqual(read('syslog_rfc3164',[{body:{'flow.sport':51234,'flow.dport':443,'flow.proto':'tcp'}}],'body.flow.sport'),[],'literal dotted key in a Syslog body, TCP');
// The header object of the WatchGuard reading holds the HOSTNAME of the Syslog header: not proposed.
const wg=kv=>({watchguard_header:{hostname:'WatchGuard-Firebox',app_tag:'firewall[10]'},watchguard:{kv}});
const wgSample=[wg({msg_id:'3000-0148'}),wg({msg_id:'1AFF-0024',op:'GET',host:'www.example.com',arg:'/index.html'})];
assert.deepEqual(read('generic_structural',wgSample,'watchguard_header.hostname'),[],'Syslog header host of the WatchGuard reading');
assert.deepEqual(read('generic_structural',wgSample,'watchguard.kv.host'),[],'requested host beside the header host of the WatchGuard reading');
// A protocol field without a value says nothing. One that holds an object or a list says what its scalar members
// say, and an unknown protocol beside the port is evidence, never silence (independent audit 2026-11-21, F-04).
assert.deepEqual(rv([{srcport:51234,dstport:443,proto:6,protocol:null}],'srcport'),['HIGH'],'null protocol field');
assert.deepEqual(rv([{srcport:51234,dstport:443,proto:6,protocol:{name:'x'}}],'srcport'),['REVIEW'],'object protocol field of an unknown protocol');
assert.deepEqual(rv([{srcport:51234,dstport:443,proto:6,protocol:{name:'tcp'}}],'srcport'),['HIGH'],'object protocol field that names TCP');
assert.deepEqual(rv([{sport:8,dport:0,protocol:{name:'icmp',number:1}}],'sport'),['REVIEW'],'object protocol field that names ICMP');
assert.deepEqual(rv([{'flow.sport':8,'flow.dport':0,'flow.proto':'icmp'}],'flow.sport'),[],'a literal dotted key written with a prefix is not proposed');
assert.deepEqual(rv([{'flow.sport':51234,'flow.dport':443,'flow.proto':'tcp'}],'flow.sport'),[],'a literal dotted key written with a prefix is not proposed, TCP');
// Zeek conn.log: the port is a literal dotted key, the protocol a plain key of the same record.
assert.deepEqual(rv([{'id.orig_h':'192.168.1.10','id.orig_p':51234,'id.resp_h':'8.8.8.8','id.resp_p':53,proto:'udp'}],'id.orig_p'),['HIGH'],'Zeek port alias beside proto');
assert.deepEqual(rv([{'id.orig_h':'192.168.1.10','id.orig_p':8,'id.resp_h':'8.8.8.8','id.resp_p':0,proto:'icmp'}],'id.orig_p'),['REVIEW'],'Zeek port alias beside an ICMP proto');
// A null member of a structured protocol field says nothing, as a null field does.
assert.deepEqual(rv([{sport:51234,dport:443,protocol:{name:'tcp',alias:null}}],'sport'),['HIGH'],'null member of an object protocol field');
assert.deepEqual(rv([{url:'category-db-2026.11'},{note:'x'}],'url'),['REVIEW'],'url that is not a URL');
assert.deepEqual(rv([{url:'/index.html'},{url:'https://example.com/a'},{note:'x'}],'url'),['HIGH'],'URL-shaped url');
assert.deepEqual(rv([{'source-port':'12','destination-port':'2048','protocol-id':'1'},{note:'x'}],'source-port'),['REVIEW'],'sparse explicit label');
assert.deepEqual(rv([{'id.orig_h':'192.168.1.10','id.orig_p':8,'id.resp_h':'8.8.8.8','id.resp_p':0}],'id.orig_p'),['REVIEW'],'Zeek port alias without proto');
assert.deepEqual(rv([{'id.orig_h':'192.168.1.10','id.orig_p':51234,'id.resp_h':'8.8.8.8','id.resp_p':443,proto:'tcp'}],'id.orig_p'),['HIGH'],'Zeek port alias beside tcp');
const sparseBadPort=suggest([{srcport:70000},{note:'system record'}]);
assert.equal(sparseBadPort.find(r=>r.source==='srcport')?.confidence,'REVIEW','sparse endpoint with an invalid value');
const mismatch={id:'auto-1',source:'src_ip',target:'srcip',type:'string',
  authoring:{version:1,origin:'AUTO'}};
const mismatchCandidate=row({src_ip:'192.0.2.1'},'src_ip',[mismatch]);
assert.equal(mismatchCandidate?.target,'srcip','incorrect type needs review');
assert.equal(mismatchCandidate?.replacesMappingId,'auto-1');
const wrongGroup=suggest([{src_ip:'192.0.2.1'}],
  [{...mismatch,type:'ip'}],{'auto-1':'vendor_fields'});
assert.equal(wrongGroup.length,1,'incorrect group needs review');
const scoped=suggest([{src_ip:'192.0.2.1'}],
  [{...mismatch,type:'ip',when:{sourcePath:'event',operator:'in',values:['login']}}],
  {'auto-1':'top_fields'});
assert.equal(scoped.length,1,'scoped rules do not suppress global official mapping');
// One vendor record has one meaning in every reading (2026-11-16). The KV and JSON formats hold a record at the
// root; Generic Structural holds it under generic.kv, a Syslog-wrapped body under body. The evidence that names the
// record is beside the field or in a container around it, never in an unrelated sibling.
const fortiWeb={hostname:'bad.example.net',direction:'outgoing',logid:'0316013056',vd:'root',type:'utm'};
absent({generic:{kv:fortiWeb}},'generic.kv.hostname');
absent({generic:{kv:fortiWeb}},'generic.kv.direction');
absent({body:fortiWeb},'body.hostname');
// A FortiGate record without vd is named by its source interface.
absent({generic:{kv:{hostname:'bad.example.net',logid:'0316013056',srcintf:'internal',type:'utm'}}},'generic.kv.hostname');
absent({hostname:'bad.example.net',logid:'0316013056',srcintf:'internal',type:'utm'},'hostname');
absent({body:{logid:'0316013056',vd:'root',type:'utm',request:{hostname:'bad.example.net'}}},'body.request.hostname');
// generic.kv is the record itself under the reading that produces it, and only under that reading.
assert.deepEqual(read('generic_structural',[{generic:{kv:{hostname:'sensor1',vd:'root',type:'utm'}}}],'generic.kv.hostname'),[],'host in the reader container of its reading');
assert.deepEqual(read('json',[{generic:{kv:{hostname:'sensor1',vd:'root',type:'utm'}}}],'generic.kv.hostname'),[],'host in an object of a JSON log');
absent({hostname:'sensor1',other:{logid:'0316013056',vd:'root',type:'utm'}},'hostname');
assert.equal(mod.fortiGateFalseFriend('generic.kv.hostname',[{generic:{kv:fortiWeb}}]),true);
assert.equal(mod.fortiGateFalseFriend('hostname',[fortiWeb]),true);
assert.equal(mod.fortiGateFalseFriend('generic.kv.srcip',[{generic:{kv:{...fortiWeb,srcip:'192.0.2.1'}}}]),false);
assert.equal(mod.fortiGateFalseFriend('generic.kv.hostname',[{generic:{kv:{hostname:'sensor1',type:'utm'}}}]),false);
absent({body:{event_type:'alert',alert:{signature_id:99,severity:2}}},'body.alert.severity');
absent({body:{event_type:'alert',alert:{signature_id:99,severity:75}}},'body.alert.severity');
absent({body:{event_type:'flow',alert:{signature_id:99,severity:75}}},'body.alert.severity');
// The evidence of a record is in one container: pieces at different levels do not make a FortiGate record, and
// a key of the same name deeper inside does not hide the alert that contains it.
absent({type:'alert',agent:{logid:'0316013056',vd:'root',hostname:'sensor1'}},'agent.hostname');
absent({event_type:'alert',alert:{signature_id:99,severity:75,event_type:'x'}},'alert.severity');
// Imperva Cloud WAF writes the client port as cpt and uses spt for the server port: spt beside cpt is not the
// source port. Without cpt the CEF dictionary stands (asserted above: spt with protocol tcp is srcport).
absent({spt:443,cpt:40022,protocol:'tcp'},'spt');
absent(bodyOf({spt:443,cpt:40022,protocol:'tcp'}),'body.spt');
high(bodyOf({spt:443,protocol:'tcp'}),'body.spt','srcport','integer');
high({spt:443,protocol:'tcp',other:{cpt:40022}},'spt','srcport','integer');
high(readBy('syslog_rfc3164',{body:{spt:443,protocol:'tcp'},cpt:40022}),'body.spt','srcport','integer');
// A JSON object called body is an object of the log: its member is not the record's port.
absent({body:{spt:443,protocol:'tcp'}},'body.spt');
absent(readBy('json',{body:{spt:443,protocol:'tcp'}}),'body.spt');
// `sport` is the source port beside a destination port, and the server port in records that name their endpoints
// client and server (cip sip cport sport; W3C c-ip s-ip s-port). It is approved only when the same record has a
// destination port; otherwise it is offered for review. Other source-port names are not affected.
review({cip:'10.2.2.5',sip:'192.0.2.20',cport:51000,sport:443},'sport','srcport');
review({'c-ip':'10.2.2.5',sport:443},'sport','srcport');
review({client_ip_address:'10.2.2.1',server_ip_address:'192.0.2.20',sport:443},'sport','srcport');
review({client_hostname:'pc-1',server_hostname:'web-1',sport:443},'sport','srcport');
review({remote_ip:'10.2.2.1',local_ip:'192.0.2.20',sport:443},'sport','srcport');
review({category:'web',count:3,sport:52000},'sport','srcport');
review(bodyOf({cport:51000,sport:443}),'body.sport','srcport');
review(readBy('syslog_rfc3164',{meta:{dport:443},body:{sport:52000}}),'body.sport','srcport');
high({sip:'10.3.3.5',dip:'192.0.2.30',sport:52000,dport:443},'sport','srcport','integer');
high({cip:'10.2.2.5',sport:52000,dport:443},'sport','srcport','integer');
high({cip:'10.2.2.5',sport:52000,dst_port:443},'sport','srcport','integer');
high({sport:52000,dstport:443},'sport','srcport','integer');
high(bodyOf({sport:52000,dport:443}),'body.sport','srcport','integer');
high({cip:'10.2.2.5',src_port:52000},'src_port','srcport','integer');
high({cport:51000,source_port:52000},'source_port','srcport','integer');
assert.deepEqual(suggest([{sport:52000,dport:443},{sport:443}]).filter(c=>c.source==='sport').map(c=>c.confidence),['REVIEW'],
  'one record without a destination port beside sport');
console.log('INDEPENDENT_ORACLE_PASS');
