import test from 'node:test';
import assert from 'node:assert/strict';
import {REQUIRED_JOURNEYS,receiptFromReport,verifyReceipts} from './browser-required-journeys.mjs';
const HEAD='a'.repeat(40);
const pass={projectName:'chromium',expectedStatus:'passed',status:'expected',results:[{status:'passed',retry:0}]};
const report=(items)=>JSON.stringify({stats:{expected:1,unexpected:0,flaky:0},errors:[],
  suites:[{specs:items.map(c=>({...c,ok:true,tests:[structuredClone(pass)]}))}]});
const all=()=>Array.from({length:6},(_,i)=>receiptFromReport(report(REQUIRED_JOURNEYS.filter((_,j)=>j%6===i)),HEAD,i+1));
test('every mandatory browser journey is seen exactly once on the exact head',()=>{
  assert.deepEqual(verifyReceipts(all(),HEAD),{shards:6,journeys:REQUIRED_JOURNEYS.length});
  assert.equal(REQUIRED_JOURNEYS.length,20);
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
  const r=all();r[0].cases.shift();
  assert.throws(()=>verifyReceipts(r,HEAD),/MISSING/);
});
test('missing, stale and duplicate shard receipts fail closed',()=>{
  const r=all();assert.throws(()=>verifyReceipts(r.slice(1),HEAD),/SHARD_COUNT/);
  r[0].sourceHead='b'.repeat(40);assert.throws(()=>verifyReceipts(r,HEAD),/RECEIPT_MISMATCH/);
  const s=all();s[0].shard=s[1].shard;assert.throws(()=>verifyReceipts(s,HEAD),/DUPLICATE_SHARD/);
});
test('a duplicate journey cannot substitute for a missing one',()=>{
  const r=all();r[1].cases[0]=r[0].cases[0];assert.throws(()=>verifyReceipts(r,HEAD),/DUPLICATE/);
  assert.throws(()=>receiptFromReport(report([REQUIRED_JOURNEYS[0],REQUIRED_JOURNEYS[0]]),HEAD,1),/DUPLICATE/);
});
