// Writes or verifies contracts/ruby-template-set.v1.json (see backend/test/template-set.ts).
//   node backend/node_modules/tsx/dist/cli.mjs scripts/verification/ruby-template-set.ts --write | --verify
// --write records what the current templates and compiler produce. It does not approve anything: the digest
// it prints is a request for an owner review (backend/test/template-set-approval.test.ts holds the approval).
import {readFileSync, writeFileSync} from 'node:fs';
import {currentTemplateSet, serializeManifest, TEMPLATE_SET_MANIFEST_PATH} from '../../backend/test/template-set.js';

const mode = process.argv[2];
const {manifest} = currentTemplateSet();
const text = serializeManifest(manifest);
const summary = `templates=${Object.keys(manifest.templates).length} variants=${Object.keys(manifest.artifacts).length} sha256=${manifest.templateSetSha256}`;
if (mode === '--write') {
  writeFileSync(TEMPLATE_SET_MANIFEST_PATH, text);
  process.stdout.write(`RUBY_TEMPLATE_SET_WRITE ${summary}\n`);
} else if (mode === '--verify') {
  let committed = '';
  try { committed = readFileSync(TEMPLATE_SET_MANIFEST_PATH, 'utf8'); } catch { /* reported below */ }
  if (committed !== text) {
    process.stdout.write(`RUBY_TEMPLATE_SET_STALE ${summary}\nThe templates or the compiler changed: run with --write and request an owner review of the new digest.\n`);
    process.exit(1);
  }
  process.stdout.write(`RUBY_TEMPLATE_SET_IN_SYNC ${summary}\n`);
} else {
  process.stderr.write('usage: ruby-template-set.ts --write | --verify\n');
  process.exit(2);
}
