// The browser golden spec and the Ruby 2.4.9 aggregate gate must read the SAME corpus
// file list. A corpus file that only one of them knew about would either be skipped
// silently or make the gate reject its own bundles, so the list lives in one registry
// and this test keeps the registry and the directory identical.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '../..');
const registry = JSON.parse(readFileSync(resolve(root, 'evals/golden-corpus/corpus-files.v1.json'), 'utf8')) as {
  contract: string; files: string[];
};

test('registry names every vendor-documented corpus file and nothing else', () => {
  assert.equal(registry.contract, 'parserstudio.golden-corpus.registry.v1');
  const onDisk = readdirSync(resolve(root, 'evals/golden-corpus'))
    .filter(name => /^vendor-documented-.*\.json$/.test(name))
    .map(name => 'evals/golden-corpus/' + name);
  const listed = registry.files.filter(file => file.startsWith('evals/golden-corpus/'));
  assert.deepEqual([...listed].sort(), onDisk.sort());
  for (const file of registry.files) assert.ok(readFileSync(resolve(root, file), 'utf8').length > 0, file);
});

test('every registered case is publisher documented, uniquely identified and hash-consistent', async () => {
  const { createHash } = await import('node:crypto');
  const ids = new Set<string>();
  let documented = 0;
  for (const file of registry.files) {
    const cases = (JSON.parse(readFileSync(resolve(root, file), 'utf8')) as {
      cases: { id: string; sampleClass: string; rawSample: string; originalSha256?: string;
        provenanceUrl?: string; desiredFields: string; goldenSourceValues: unknown[] }[];
    }).cases;
    for (const item of cases) {
      assert.ok(!ids.has(item.id), 'duplicate case id ' + item.id);
      ids.add(item.id);
      if (!item.sampleClass.startsWith('VENDOR_DOCUMENTED')) continue;
      documented += 1;
      assert.ok(item.goldenSourceValues.length > 0, item.id + ' has no documented values');
      assert.ok(item.desiredFields.trim().length > 0, item.id + ' names no required fields');
      if (item.originalSha256 !== undefined) {
        assert.equal(createHash('sha256').update(item.rawSample).digest('hex'), item.originalSha256, item.id);
      }
    }
  }
  assert.ok(documented >= 14, 'expected at least the 14 documented cases, saw ' + documented);
});

test('every documented case has a separately authored endpoint disposition', () => {
  const endpoints = JSON.parse(readFileSync(resolve(root, 'evals/golden-corpus/stellar70-endpoint-goldens.v1.json'), 'utf8')) as {
    contract:string; cases:Record<string,Record<string,string|number>>;
  };
  assert.equal(endpoints.contract, 'parserstudio.stellar70-endpoint-goldens.v1');
  const all = registry.files.flatMap(file => (JSON.parse(readFileSync(resolve(root,file),'utf8')) as {
    cases:{id:string;sampleClass:string;rawSample:string}[]
  }).cases).filter(c=>c.sampleClass.startsWith('VENDOR_DOCUMENTED'));
  assert.deepEqual(Object.keys(endpoints.cases).sort(),all.map(c=>c.id).sort());
  for(const c of all){
    for(const [key,value] of Object.entries(endpoints.cases[c.id]!)){
      assert.ok(['srcip','dstip','srcport','dstport'].includes(key));
      assert.ok(c.rawSample.includes(String(value)),c.id+' '+key);
      if(key.endsWith('port'))assert.ok(Number.isInteger(value));
      else assert.equal(typeof value,'string');
    }
  }
  assert.deepEqual(Object.keys(endpoints.cases).filter(id=>!Object.keys(endpoints.cases[id]!).length),['fortinet-008']);
});

test('independent non-endpoint semantic entries cover every registered case and cite literal values', () => {
  const file=resolve(root,'evals/golden-corpus/stellar70-semantic-goldens.v1.json');
  const semantic=JSON.parse(readFileSync(file,'utf8')) as {
    contract:string; cases:Record<string,{source:string;target:string;value:string|number}[]>;
  };
  assert.equal(semantic.contract,'parserstudio.stellar70-semantic-goldens.v1');
  const all=registry.files.flatMap(file=>(JSON.parse(readFileSync(resolve(root,file),'utf8')) as {
    cases:{id:string;sampleClass:string;rawSample:string}[]
  }).cases).filter(c=>c.sampleClass.startsWith('VENDOR_DOCUMENTED'));
  assert.deepEqual(Object.keys(semantic.cases).sort(),all.map(c=>c.id).sort());
  const integerTargets=new Set(['proto','appid','vlan','file_size']);
  const stringTargets=new Set(['proto_name','fw_policy_id','srcmac','username','action','file_path']);
  let count=0;
  for(const c of all)for(const entry of semantic.cases[c.id]!){
    assert.ok(entry.source);
    assert.ok(c.rawSample.includes(String(entry.value)),c.id+' '+entry.source);
    assert.ok(integerTargets.has(entry.target)?Number.isInteger(entry.value):
      stringTargets.has(entry.target)&&typeof entry.value==='string',entry.target);
    count++;
  }
  assert.equal(count,20);
});
