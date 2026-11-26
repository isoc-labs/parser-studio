import test from 'node:test';
import assert from 'node:assert/strict';
import {REQUIRED_JOURNEYS,BROWSER_CATALOGUE,receiptFromReport,verifyReceipts} from './browser-required-journeys.mjs';
const HEAD='a'.repeat(40);
const pass={projectName:'chromium',expectedStatus:'passed',status:'expected',results:[{status:'passed',retry:0}]};
const report=(items)=>JSON.stringify({stats:{expected:items.filter(c=>!c.disposition||c.disposition==='REQUIRED').length,
  skipped:items.filter(c=>c.disposition&&c.disposition!=='REQUIRED').length,unexpected:0,flaky:0},errors:[],
  suites:[{specs:items.map(c=>({...c,ok:true,tests:[c.disposition&&c.disposition!=='REQUIRED'
    ?{projectName:'chromium',expectedStatus:'skipped',status:'skipped',results:[]}:structuredClone(pass)]}))}]});
const all=()=>Array.from({length:6},(_,i)=>receiptFromReport(report(BROWSER_CATALOGUE.filter((_,j)=>j%6===i)),HEAD,i+1));
test('every mandatory browser journey is seen exactly once on the exact head',()=>{
  assert.deepEqual(verifyReceipts(all(),HEAD),{shards:6,journeys:REQUIRED_JOURNEYS.length,catalogue:BROWSER_CATALOGUE.length,passed:BROWSER_CATALOGUE.length-13,skipped:13});
  assert.equal(REQUIRED_JOURNEYS.length,22);
});
test('skipping a required case cannot hide behind other successful tests',()=>{
  const r=JSON.parse(report([REQUIRED_JOURNEYS[0]]));
  r.stats.skipped=1;
  const t=r.suites[0].specs[0].tests[0];
  t.expectedStatus='skipped';t.status='skipped';t.results=[{status:'skipped',retry:0}];
  assert.throws(()=>receiptFromReport(JSON.stringify(r),HEAD,1),/NOT_PASSED/);
});
test('an expected failure, retry, wrong project or zero results are not a successful journey',()=>{
  for(const mutation of [
    t=>{t.expectedStatus='failed';t.results[0].status='failed';},
    t=>{t.results[0].retry=1;},
    t=>{t.projectName='firefox';},
    t=>{t.results=[];},
  ]){
    const r=JSON.parse(report([REQUIRED_JOURNEYS[0]]));
    mutation(r.suites[0].specs[0].tests[0]);
    assert.throws(()=>receiptFromReport(JSON.stringify(r),HEAD,1),/NOT_PASSED/);
  }
});
test('an omitted, renamed or undiscovered required case fails the aggregate census',()=>{
  const r=all();r.find(x=>x.cases.length).cases.shift();
  assert.throws(()=>verifyReceipts(r,HEAD),/MISSING/);
});
test('missing, stale and duplicate shard receipts fail closed',()=>{
  const r=all();assert.throws(()=>verifyReceipts(r.slice(1),HEAD),/SHARD_COUNT/);
  r[0].sourceHead='b'.repeat(40);assert.throws(()=>verifyReceipts(r,HEAD),/RECEIPT_MISMATCH/);
  const s=all();s[0].shard=s[1].shard;assert.throws(()=>verifyReceipts(s,HEAD),/DUPLICATE_SHARD/);
});
test('a duplicate journey cannot substitute for a missing one',()=>{
  const r=all();r[0].allCases.push(r[0].allCases[0]);assert.throws(()=>verifyReceipts(r,HEAD),/DUPLICATE/);
  assert.throws(()=>receiptFromReport(report([REQUIRED_JOURNEYS[0],REQUIRED_JOURNEYS[0]]),HEAD,1),/DUPLICATE/);
});

test('the complete catalogue rejects an omitted non-critical journey',()=>{
  const r=all();
  const requiredKeys=new Set(REQUIRED_JOURNEYS.map(c=>JSON.stringify([c.file,c.title])));
  const row=r.find(x=>x.allCases.some(c=>!requiredKeys.has(JSON.stringify([c.file,c.title]))));
  row.allCases.splice(row.allCases.findIndex(c=>!requiredKeys.has(JSON.stringify([c.file,c.title]))),1);
  assert.throws(()=>verifyReceipts(r,HEAD),/BROWSER_CATALOGUE_MISSING/);
});
test('a previously non-critical test cannot silently skip',()=>{
  const c=BROWSER_CATALOGUE.find(c=>c.disposition==='REQUIRED'&&!REQUIRED_JOURNEYS.some(r=>r.file===c.file&&r.title===c.title));
  const r=JSON.parse(report([c]));
  r.stats.expected=0;r.stats.skipped=1;
  const t=r.suites[0].specs[0].tests[0];t.expectedStatus='skipped';t.status='skipped';t.results=[];
  assert.throws(()=>receiptFromReport(JSON.stringify(r),HEAD,1),/NOT_PASSED|SHARD/);
});
test('catalogue forbids unreviewed tests or count mismatch',()=>{
  assert.throws(()=>receiptFromReport(report([{file:'tests/unknown.spec.ts',title:'not reviewed'}]),HEAD,1),/UNKNOWN/);
  const r=JSON.parse(report([REQUIRED_JOURNEYS[0]]));r.stats.expected++;
  assert.throws(()=>receiptFromReport(JSON.stringify(r),HEAD,1),/REPORT_COUNT/);
});
