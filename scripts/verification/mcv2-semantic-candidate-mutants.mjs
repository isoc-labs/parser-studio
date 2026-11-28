/** Independent source-level fault probes for official Stellar mapping
 * candidates. Every mutant is a real source change; the independent oracle
 * includes positive/negative semantic examples and manual provenance.
 * Synthetic values only. This is a selected policy-gate mutation inventory,
 * not an exhaustive AST mutation score of the complete candidate provider.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as esbuild from 'esbuild';
const path='src/guided/normalizationCandidates.ts';
const source=readFileSync(path,'utf8');
async function load(text){
  const result=await esbuild.build({entryPoints:[path],bundle:true,platform:'node',
    format:'esm',write:false,logLevel:'silent',plugins:[{
      name:'semantic-candidate-mutant',setup(build){
        build.onLoad({filter:/normalizationCandidates\.ts$/},()=>({contents:text,loader:'ts'}));
      },
    }]});
  return import('data:text/javascript;base64,'+
    Buffer.from(result.outputFiles[0].text).toString('base64'));
}
const examples=[
  ['src_ip','srcip',{src_ip:'192.0.2.9'},true],
  ['src_ip','srcip',{src_ip:'invalid-ip'},false],
  ['source-port','srcport',{'source-port':594,proto:1},true],
  ['destination-port','dstport',{'destination-port':10400},true],
  ['source-port','srcport',{'source-port':65536},false],
  ['action','action',{action:'block'},true],
  ['proto','proto',{proto:256},false],
  ['proto','proto',{proto:6},true],
  ['username','username',{username:'alice'},true],
];
const forbidden=[
  ['post_nat.source-port',{post_nat:{'source-port':4411}}],
  ['nat_source.source-port',{nat_source:{'source-port':4411}}],
  ['translated_source.source-port',{translated_source:{'source-port':4411}}],
  ['event_type',{event_type:'alert'}],
  ['duration',{duration:2000}],
  ['action',{action:'admin-login'}],
  ['syslog.severity',{syslog:{severity:4}}],
  // Default deny (owner decision 2026-11-28): a field the shared policy does not list is not proposed from its name.
  ['duration_ms',{duration_ms:2000}],
  ['hostname',{hostname:'sensor1'}],
  ['host',{host:'fw01',msg:'link up'}],
  ['severity',{severity:75}],
  ['policyid',{policyid:7}],
  ['file_size',{file_size:1024}],
  ['icmp_type',{icmp_type:'8','protocol-id':1}],
  // ... and a member of an object of the record is not a field of the record, whatever the object is called.
  ['xlate.srcip',{xlate:{srcip:'203.0.113.5'}}],
  ['file.timestamp',{file:{timestamp:'2020-01-01T00:00:00Z'}}],
  ['alert.action',{alert:{action:'allowed'}}],
  ['generic.kv.srcip',{generic:{kv:{srcip:'203.0.113.5'}}}],
];
function runSuite(mod,events,existing=[],options={}){
  return mod.suggestNormalizationCandidatesFromSuite({events:events.map(fields=>({fields}))},
    existing,{},options);
}
function oracle(mod){
  for(const [source,target,fields,high] of examples){
    const row=runSuite(mod,[fields]).find(c=>c.source===source);
    assert.equal(row?.target,target,'independent target '+source);
    assert.equal(row?.confidence,high?'HIGH':'REVIEW','confidence '+source+' '+high);
    assert.equal(row?.safeForBulk,high,'bulk permission '+source);
    assert.equal(row?.catalogVerified,true,'Stellar catalog gate '+source);
  }
  for(const [source,fields] of forbidden)
    assert.equal(runSuite(mod,[fields]).some(c=>c.source===source),false,
      'vendor false friend '+source);
  const alias=runSuite(mod,[{src_ip:'192.0.2.1',source_ip:'198.51.100.1'}]);
  const competition=alias.filter(c=>c.target==='srcip');
  assert.equal(competition.length,2,'both ambiguous aliases retained');
  assert.equal(competition.every(c=>c.confidence==='REVIEW'&&!c.safeForBulk),true,
    'neither ambiguous alias may be bulk-applied');
  assert.equal(runSuite(mod,[{src_ip:'192.0.2.1',source_ip:'198.51.100.1'}],[],
    {skipAmbiguousTargets:true}).some(c=>c.target==='srcip'),false,
    'explicit skip should exclude ambiguous official target');
  const sparse=runSuite(mod,[{src_ip:'192.0.2.1'},{dst_ip:'198.51.100.1'}]);
  assert.equal(sparse.filter(c=>['srcip','dstip'].includes(c.target))
    .every(c=>c.confidence==='REVIEW'&&!c.safeForBulk),true,
    'sparse event family must not bulk-approve');
  const abbreviation=runSuite(mod,[{sport:443,protocol:'icmp'}])
    .find(c=>c.source==='sport');
  assert.equal(abbreviation?.safeForBulk,false,'nontransport abbreviated port');
  const manual={id:'auto-1',source:'src_ip',target:'custom.srcip',type:'string',
    authoring:{version:1,origin:'USER_EDITED'}};
  const edited=runSuite(mod,[{src_ip:'192.0.2.1'}],[manual])[0];
  assert.equal(edited?.safeForBulk,false,'explicit user edit protected');
  assert.equal(edited?.replacesMappingId,'auto-1');
  assert.equal(runSuite(mod,[{src_ip:'192.0.2.1'}],[
    {id:'custom',source:'old',target:'srcip',type:'ip'}]).some(c=>c.target==='srcip'),
    false,'occupied destination cannot get a competing candidate');
  // Mixed record families: an endpoint field that carries the official name itself is approved although one
  // family lacks it; an official name of another kind is not.
  const families=runSuite(mod,[{srcport:51544,proto:6,md5:'69630e4574ec6798239b091cda43dca0'},{note:'system record'}]);
  // Found by the independent audit of 2026-11-21: none of these may be approved.
  const icmpFamily=runSuite(mod,[{srcport:51234,dstport:443,ipproto:6},{srcport:8,dstport:0,ipproto:1},{note:'system record'}]);
  assert.equal(icmpFamily.filter(c=>['srcport','dstport'].includes(c.target)).every(c=>!c.safeForBulk),true,
    'sparse port beside an ICMP record that names its protocol ipproto');
  const noProtocol=runSuite(mod,[{srcport:8,dstport:0},{note:'system record'}]);
  assert.equal(noProtocol.filter(c=>['srcport','dstport'].includes(c.target)).every(c=>!c.safeForBulk),true,
    'sparse port without any protocol in the record');
  const nested=runSuite(mod,[{xlate:{srcip:'203.0.113.5',srcport:40002},proto:6},{note:'system record'}]);
  assert.equal(nested.filter(c=>['srcip','srcport'].includes(c.target)).every(c=>!c.safeForBulk),true,
    'sparse endpoint inside a nested object');
  assert.equal(families.find(c=>c.source==='srcport')?.safeForBulk,true,'sparse official-name endpoint field');
  assert.equal(families.some(c=>c.source==='md5'),false,'an official name the policy does not list');
  assert.equal(runSuite(mod,[{url:'category-db-2026.11'},{note:'system record'}]).find(c=>c.source==='url')?.safeForBulk,false,
    'a sparse field called url whose value is not a URL');
  assert.equal(runSuite(mod,[{url:'https://example.com/a'},{note:'system record'}]).find(c=>c.source==='url')?.safeForBulk,true,
    'a sparse field called url that holds a URL');
  // A listed field that is not an endpoint or URL field keeps the full-coverage rule: sparse, it is a review proposal.
  const sparseUser=runSuite(mod,[{srcport:51544,proto:6,username:'alice'},{note:'system record'}]).find(c=>c.source==='username');
  assert.equal(sparseUser?.target,'username','sparse listed name is still proposed');
  assert.equal(sparseUser?.safeForBulk,false,'sparse listed name of another kind is not approved');
  // The container of the reader holds the pairs of the record: the body of a Syslog reading, the key=value node
  // of Generic Structural. Protocol evidence is read in that container.
  const read=(format,...events)=>mod.suggestNormalizationCandidatesFromSuite(
    {events:events.map(fields=>({fields,effectiveFormat:format}))},[]);
  assert.equal(read('syslog_rfc3164',{body:{src_ip:'192.0.2.9'}}).find(c=>c.source==='body.src_ip')?.safeForBulk,true,
    'a name in the body of a Syslog reading');
  assert.equal(read('generic_structural',{generic:{kv:{srcip:'192.0.2.9'}}}).find(c=>c.source==='generic.kv.srcip')?.safeForBulk,true,
    'a name in the key=value node of Generic Structural');
  assert.equal(read('json',{body:{src_ip:'192.0.2.9'}}).length,0,'the same path in a JSON log is an object of the log');
  assert.equal(read('syslog_rfc3164',{body:{sport:51234,dport:443,protocol:'tcp'}},{body:{sport:8,dport:0,protocol:'icmp'}})
    .find(c=>c.source==='body.sport')?.confidence,'REVIEW','ICMP named in the body that holds the port');
  assert.deepEqual(runSuite(mod,[]),[],'empty data has no candidates');
}
const variants=[
  ['allow vendor false friend',
    'if(incompatibleVendorMeaning(source,target,events))return null;',
    'if(false)return null;'],
  ['pretend no type-compatible observations',
    'const compatibleObserved=informativeValues.filter(result=>',
    'const compatibleObserved=informativeValues.filter(result=>false&&'],
  ['propose an official field the policy does not list',
    'if(!target||!AUTO_APPROVED_TARGETS.has(target))return null;',
    'if(!target)return null;'],
  ['take a member of an object of the record for a field of the record',
    'if(!wholePathListed&&!recordLevelSource(recordPathOf(source),carrierFormats))return null;',
    ''],
  ['take any container for the container of the reader',
    "return formats.length>0&&formats.every(format=>RECORD_CONTAINERS[format??'']?.test(source)===true);",
    'return true;'],
  ['take no container for the container of the reader',
    "return formats.length>0&&formats.every(format=>RECORD_CONTAINERS[format??'']?.test(source)===true);",
    'return false;'],
  ['look for the protocol of a port at the root of the event only',
    'const containers=new Map<Record<string,unknown>,string>([[holder.container,holder.written]]);',
    "const containers=new Map<Record<string,unknown>,string>([[fields,source.slice(0,source.lastIndexOf('.')+1).toLowerCase()]]);"],
  ['ignore a non-transport protocol beside the port',
    'informative>0&&!nonTransportPort&&!lacksTransportEvidence;',
    'informative>0&&!lacksTransportEvidence;'],
  ['ignore complete event evidence',
    'compatibleObserved===informative&&(values.length===events.length||namedAsTarget)&&',
    'compatibleObserved===informative&&'],
  ['approve every sparse source',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeValues(target,informativeValues);',
    'const namedAsTarget=true;'],
  ['approve a sparse source for any official name',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeValues(target,informativeValues);',
    'const namedAsTarget=(leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeValues(target,informativeValues);'],
  ['approve a sparse alias of an endpoint field',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeValues(target,informativeValues);',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&sparseSafeValues(target,informativeValues);'],
  ['approve a sparse port without TCP or UDP named by the record',
    'informative>0&&!nonTransportPort&&!lacksTransportEvidence;',
    'informative>0&&!nonTransportPort;'],
  ['approve a sparse url of any shape',
    "return target!=='url'||values.every(result=>result.found&&typeof result.value==='string'&&\n    URL_SHAPED.test(result.value.trim()));",
    'return true;'],
  ['never approve a sparse official-name endpoint field',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeValues(target,informativeValues);',
    'const namedAsTarget=false;'],
  ['ignore abnormal port protocol',
    'const nonTransportPort=!explicitPort&&(target===\'srcport\'||target===\'dstport\')&&',
    'const nonTransportPort=false&&(target===\'srcport\'||target===\'dstport\')&&'],
  ['ignore existing destination collisions',
    'if(existing.some(rule=>rule.id!==current?.id&&overlaps(rule.target,target)))return null;',
    'if(false)return null;'],
  ['allow manual owner edits to auto-promote',
    'safeForBulk:high&&(!current||replaceIsGenerated),',
    'safeForBulk:high,'],
  ['declare every candidate high confidence',
    "confidence:high?'HIGH':'REVIEW',method,",
    "confidence:'HIGH',method,"],
  ['never flag competing aliases',
    '.filter(([,candidates])=>candidates.filter(candidate=>candidate.compatibleObserved>0).length>1)',
    '.filter(([,candidates])=>false)'],
  ['bulk-approve competing aliases',
    "?{...candidate,confidence:'REVIEW' as const,safeForBulk:false,",
    "?{...candidate,confidence:'HIGH' as const,safeForBulk:true,"],
  ['ignore suppression of ambiguous targets',
    '?reviewed.filter(candidate=>!ambiguousTargets.has(candidate.target)):reviewed;',
    '?reviewed:reviewed;'],
];
oracle(await load(source));
let killed=0;
for(const [label,anchor,replace] of variants){
  assert.equal(source.split(anchor).length,2,'mutation anchor changed: '+label);
  const mod=await load(source.replace(anchor,replace));
  let detected=false;
  try{oracle(mod);}catch(error){
    if(error instanceof assert.AssertionError)detected=true;
    else throw error;
  }
  assert.equal(detected,true,'SEMANTIC_MUTANT_SURVIVED '+label);
  killed++;
}
console.log('MCV2_SEMANTIC_CANDIDATE_MUTATION_PASS killed='+killed+'/'+variants.length+
  ' selected source mutations; not comprehensive AST coverage');
