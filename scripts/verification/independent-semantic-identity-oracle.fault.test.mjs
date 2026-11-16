// Fault injection for the independently authored semantic identity oracle
// (independent-semantic-identity-oracle.ts): the gate is only worth running if it reports a wrong mapping.
// A private copy of what the oracle reads is made inside the repository (so package resolution is unchanged);
// the unmodified copy must pass and every injected fault must make the oracle fail.
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const REPO = resolve('.');
// The browser and the backend each read their own copy of the policy (kept identical by the build check).
const POLICIES = ['runtime/multipass/semantic-policy.v1.json', 'backend/semantic-policy.v1.json'];
const swap = (text, left, right) => text.split(left).join('\u0000').split(right).join(left).split('\u0000').join(right);
const FAULTS = [
  ['source and destination address swapped in the semantic policy', text => swap(text, '"srcip"', '"dstip"')],
  ['source and destination port swapped in the semantic policy', text => swap(text, '"srcport"', '"dstport"')],
];

function runCopy(mutate) {
  const root = mkdtempSync(join(REPO, '.oracle-mutant-'));
  try {
    for (const path of ['src', 'backend/src', 'backend/semantic-policy.v1.json', 'runtime/multipass', 'contracts/semantic-identity-independent-goldens.v1.json',
      'scripts/verification/independent-semantic-identity-oracle.ts'])
      cpSync(join(REPO, path), join(root, path), { recursive: true });
    symlinkSync(join(REPO, 'backend/node_modules'), join(root, 'backend/node_modules'), 'dir');
    if (mutate) {
      for (const policy of POLICIES) {
        const before = readFileSync(join(root, policy), 'utf8');
        const after = mutate(before);
        assert.notEqual(after, before, 'the fault does not apply to ' + policy + ' any more');
        writeFileSync(join(root, policy), after);
      }
    }
    return spawnSync(process.execPath, [join(REPO, 'backend/node_modules/tsx/dist/cli.mjs'), 'scripts/verification/independent-semantic-identity-oracle.ts'],
      { cwd: root, encoding: 'utf8', timeout: 120000 });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('the unmodified copy passes (the harness itself is valid)', () => {
  const run = runCopy(null);
  assert.equal(run.status, 0, run.stderr.slice(0, 600));
  assert.match(run.stdout, /INDEPENDENT_SEMANTIC_ORACLE_PASS/);
});

for (const [name, mutate] of FAULTS) {
  test('injected fault is reported: ' + name, () => {
    const run = runCopy(mutate);
    assert.notEqual(run.status, 0, 'the oracle passed with the fault injected');
    assert.doesNotMatch(run.stdout, /INDEPENDENT_SEMANTIC_ORACLE_PASS/);
  });
}
