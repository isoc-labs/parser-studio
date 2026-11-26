import {readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {validateBrowserShardReport} from './browser-shard-report.mjs';

// This is the owner-facing recertification subset of the real-backend catalogue.
// Other intentionally scoped or historical suites have their own CI dispositions.
const requiredByFile={
  'tests/chatgpt-event-profile-scope-20261123.spec.ts':['ChatGPT Assisted improves one event type of a multi-type parser and generates one parser'],
  'tests/first-time-complete-auto-journey-20261023.spec.ts':['a first-time desktop user saves logs, generates actual files, and restores the source'],
  'tests/chatgpt-h2-residuals-20261125.spec.ts':[
    'Auto Parser applies a lossless ChatGPT recovery across multi-token residual regions and refuses lossy ones (H-2)',
    'independent ChatGPT Assisted journey exports a statically accepted Regex with real backend',
  ],
  'tests/readable-events-gate-20261125.spec.ts':[
    'an RFC 5424 line with VERSION 2 is not offered as read completely; the parser is created for the VERSION 1 event',
    'a Syslog line whose free text needs a rule is left out; the parser is created for the key=value events',
    'a sample that cannot go on and has no readable event still says so',
    'bounded compiler candidate remains usable beside unsupported events',
  ],
  'tests/recertification-layout-20261126.spec.ts':[1024,1280,1440,1920].map(w=>'responsive recovery and mapping workspace '+w),
  'tests/map-fields-event-type-manual-20261125.spec.ts':[
    'the field matches of one event type are added, changed and removed by hand; the parser follows',
  ],
  'tests/map-fields-event-types-20261125.spec.ts':[
    'Map Fields shows the field matches of every event type of a multi-type parser',
  ],
  'tests/chatgpt-jsonata-event-profile-20261123.spec.ts':[
    'ChatGPT JSONata mapping changes one event type of a multi-type parser and the generated parser',
  ],
  'tests/chatgpt-q31-unmapped-20261124.spec.ts':[
    'ChatGPT Assisted refuses wrong replies and keeps the column a reply leaves unmapped (Q3-1)',
  ],
  'tests/chatgpt-key-outside-region-20261125.spec.ts':[
    'ChatGPT Assisted reads a pipe-separated key=value log: the prompt names what failed, lossy replies are refused, the lossless reply is applied',
  ],
  'tests/d2-pri-cef-journey-20261125.spec.ts':[
    'D-2: RFC 5424 messages that only claim CEF are not completely parsed, so nothing is generated from them alone',
    'D-2: with a plain message in the sample, the parser keeps such messages whole with their envelope',
    'a bare PRI before CEF (<189>CEF:0| and <189>CEF: 0|) is read as CEF with the PRI',
  ],
  'tests/g5-reserved-names-journey-20261125.spec.ts':[
    'G-5: key=value fields named __proto__, constructor and prototype are parsed and kept',
    'G-5: JSON members named __proto__ and constructor, and a dotted key, are parsed and kept',
  ],
};
export const REQUIRED_JOURNEYS=Object.entries(requiredByFile).flatMap(([file,titles])=>titles.map(title=>({file,title})));
const key=(item)=>JSON.stringify([item.file,item.title]);
const required=new Set(REQUIRED_JOURNEYS.map(key));
const CONTRACT='parser-studio.required-browser-journeys.v2';
const catalogue=JSON.parse(readFileSync(new URL('../../contracts/browser-catalogue.v1.json',import.meta.url),'utf8'));
if(catalogue.contract!=='parser-studio.browser-catalogue.v1'||!Array.isArray(catalogue.cases))
  throw new Error('BROWSER_CATALOGUE_INVALID');
export const BROWSER_CATALOGUE=catalogue.cases;
const fullCatalogue=new Map(BROWSER_CATALOGUE.map(c=>[key(c),c]));
if(fullCatalogue.size!==BROWSER_CATALOGUE.length||
  BROWSER_CATALOGUE.some(c=>!['REQUIRED','RETIRED_TARGET_UI','HISTORICAL_PUBLIC_ONLY'].includes(c.disposition)||
    (c.disposition!=='REQUIRED'&&!(typeof c.reason==='string'&&c.reason.length>0)))||
  REQUIRED_JOURNEYS.some(c=>fullCatalogue.get(key(c))?.disposition!=='REQUIRED'))
  throw new Error('BROWSER_CATALOGUE_INVALID');
const SHARDS=6;
function require(condition,message){if(!condition)throw new Error(message);}
function validHead(head){return typeof head==='string'&&/^[a-f0-9]{40}$/.test(head);}
function validShard(shard){return Number.isInteger(shard)&&shard>=1&&shard<=SHARDS;}

export function receiptFromReport(raw,sourceHead,shard){
  validateBrowserShardReport(raw);
  require(validHead(sourceHead)&&validShard(shard),'REQUIRED_BROWSER_RECEIPT_IDENTITY');
  const report=JSON.parse(raw);
  require(Array.isArray(report.suites)&&report.suites.length>0,'REQUIRED_BROWSER_REPORT_SUITES');
  const seen=new Set(),cases=[],allCases=[];
  let passed=0,skipped=0;
  function walk(suite){
    require(suite&&Array.isArray(suite.specs),'REQUIRED_BROWSER_REPORT_SPEC_SHAPE');
    for(const spec of suite.specs){
      const id=key(spec);
      const declared=fullCatalogue.get(id);
      require(declared,'BROWSER_CATALOGUE_UNKNOWN '+id);
      require(!seen.has(id),'REQUIRED_BROWSER_DUPLICATE '+id);
      const tests=spec.tests;
      require(spec.ok===true&&Array.isArray(tests)&&tests.length===1,'REQUIRED_BROWSER_NOT_PASSED '+id);
      const t=tests[0];
      require(t.projectName==='chromium'&&Array.isArray(t.results),'REQUIRED_BROWSER_NOT_PASSED '+id);
      const expectedSkip=declared.disposition!=='REQUIRED';
      if(expectedSkip){
        require(t.expectedStatus==='skipped'&&t.status==='skipped'&&
          (t.results.length===0||(t.results.length===1&&t.results[0].status==='skipped'&&t.results[0].retry===0)),
          'BROWSER_CATALOGUE_EXCLUDED_NOT_SKIPPED '+id);
        skipped++;
      }else{
        require(t.expectedStatus==='passed'&&t.status==='expected'&&
          t.results.length===1&&t.results[0].status==='passed'&&t.results[0].retry===0,
          'REQUIRED_BROWSER_NOT_PASSED '+id);
        passed++;
      }
      seen.add(id);
      allCases.push({file:spec.file,title:spec.title,outcome:expectedSkip?'SKIPPED':'PASSED'});
      if(required.has(id))cases.push({file:spec.file,title:spec.title});
    }
    if(suite.suites!==undefined){require(Array.isArray(suite.suites),'REQUIRED_BROWSER_REPORT_SUITE_SHAPE');suite.suites.forEach(walk);}
  }
  report.suites.forEach(walk);
  require(report.stats.expected===passed&&report.stats.skipped===skipped,"BROWSER_CATALOGUE_REPORT_COUNT");
  return {contract:CONTRACT,sourceHead,shard,cases,allCases};
}

export function verifyReceipts(receipts,sourceHead){
  require(validHead(sourceHead),'REQUIRED_BROWSER_EXPECTED_HEAD');
  require(receipts.length===SHARDS,'REQUIRED_BROWSER_SHARD_COUNT '+receipts.length);
  const shards=new Set(),seen=new Set(),fullSeen=new Set();
  let passed=0,skipped=0;
  for(const r of receipts){
    require(r&&r.contract===CONTRACT&&r.sourceHead===sourceHead&&validShard(r.shard)&&Array.isArray(r.cases)&&Array.isArray(r.allCases),
      'REQUIRED_BROWSER_RECEIPT_MISMATCH');
    require(!shards.has(r.shard),'REQUIRED_BROWSER_DUPLICATE_SHARD '+r.shard);shards.add(r.shard);
    const thisShard=new Set();
    for(const c of r.allCases){
      const id=key(c),declared=fullCatalogue.get(id);
      require(declared,'BROWSER_CATALOGUE_UNKNOWN '+id);
      require(!fullSeen.has(id),'BROWSER_CATALOGUE_DUPLICATE '+id);
      const expected=declared.disposition==='REQUIRED'?'PASSED':'SKIPPED';
      require(c.outcome===expected,'BROWSER_CATALOGUE_WRONG_OUTCOME '+id);
      fullSeen.add(id);thisShard.add(id);
      if(c.outcome==='PASSED')passed++;else skipped++;
    }
    for(const c of r.cases){
      const id=key(c);
      require(required.has(id)&&thisShard.has(id),'REQUIRED_BROWSER_UNKNOWN '+id);
      require(!seen.has(id),'REQUIRED_BROWSER_DUPLICATE '+id);seen.add(id);
    }
  }
  const missing=REQUIRED_JOURNEYS.filter(c=>!seen.has(key(c)));
  require(missing.length===0,'REQUIRED_BROWSER_MISSING '+missing.map(key).join('; '));
  const missingAll=BROWSER_CATALOGUE.filter(c=>!fullSeen.has(key(c)));
  require(missingAll.length===0,"BROWSER_CATALOGUE_MISSING "+missingAll.map(key).join("; "));
  return {shards:shards.size,journeys:seen.size,catalogue:fullSeen.size,passed,skipped};
}

function readReceipts(root){
  return readdirSync(root,{recursive:true,withFileTypes:true})
    .filter(e=>e.isFile()&&e.name==='browser-required-journeys.json')
    .map(e=>JSON.parse(readFileSync(join(e.parentPath,e.name),'utf8')));
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    const [mode,input,outOrHead,head,shard]=process.argv.slice(2);
    if(mode==='prepare'&&input&&outOrHead&&head&&shard){
      const receipt=receiptFromReport(readFileSync(input,'utf8'),head,Number(shard));
      writeFileSync(outOrHead,JSON.stringify(receipt)+'\n');
      console.log('REQUIRED_BROWSER_SHARD_RECEIPT',receipt.shard,receipt.cases.length);
    }else if(mode==='compare'&&input&&outOrHead){
      console.log('REQUIRED_BROWSER_CENSUS_PASS',verifyReceipts(readReceipts(input),outOrHead));
    }else throw new Error('usage: prepare <report> <receipt> <head> <shard> | compare <downloads> <head>');
  }catch(error){console.error(error instanceof Error?error.message:error);process.exitCode=1;}
}
