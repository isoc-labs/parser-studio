// The compiler reads its Ruby templates from disk at start-up. The tests run the TypeScript sources, where every
// file of backend/templates is at hand; the product runs dist/, where only what the build script copies exists.
// When the grammar became generated (W4) the build still copied the two deleted templates and none of the new
// ones: `npm run build` failed and no gate that runs the sources could see it. These checks tie the three lists
// (what the compiler reads, what the build ships, what CI and the lineage receipt name) to the directory.
import assert from 'node:assert/strict';
import {existsSync, readdirSync, readFileSync} from 'node:fs';
import test from 'node:test';

const root=new URL('../../',import.meta.url);
const read=(path:string):string=>readFileSync(new URL(path,root),'utf8');
const templates=readdirSync(new URL('backend/templates/',root)).filter(name=>name.endsWith('.rb.tpl')).sort();

test('every template the compiler reads exists',()=>{
  const wanted=Array.from(read('backend/src/compiler.ts').matchAll(/new URL\(['"]\.\.\/templates\/([A-Za-z0-9._-]+)['"]/g),match=>match[1]!).sort();
  assert.ok(wanted.length>=5,'template reads were not found in compiler.ts');
  for(const name of wanted)assert.ok(templates.includes(name),name+' is read by the compiler and is not in backend/templates');
  assert.deepEqual(wanted,templates,'a file in backend/templates is not read by the compiler, or the reverse');
});

test('the build ships every template to dist',()=>{
  const build=(JSON.parse(read('backend/package.json')) as {scripts:{build:string}}).scripts.build;
  const copy=/cp ((?:templates\/[A-Za-z0-9.*_-]+ )+)dist\/templates\//.exec(build);
  assert.ok(copy,'the build script does not copy templates to dist/templates');
  const sources=copy[1]!.trim().split(' ');
  if(sources.includes('templates/*.rb.tpl'))return;
  for(const name of templates)assert.ok(sources.includes('templates/'+name),name+' is not copied to dist/templates by the build script');
  for(const source of sources)assert.ok(existsSync(new URL('backend/'+source,root)),source+' is copied by the build script and does not exist');
});

test('CI and the lineage receipt name only templates that exist, and the receipt names all of them',()=>{
  for(const path of ['.github/workflows/quality.yml','scripts/verification/executable-artifact-lineage.ts','backend/package.json']){
    const named=Array.from(read(path).matchAll(/(?:backend\/)?templates\/([A-Za-z0-9._-]+\.rb\.tpl)/g),match=>match[1]!);
    for(const name of named)assert.ok(templates.includes(name),path+' names '+name+', which is not in backend/templates');
  }
  const lineage=read('scripts/verification/executable-artifact-lineage.ts');
  for(const name of templates)assert.ok(lineage.includes("'backend/templates/"+name+"'"),name+' is missing from the lineage receipt');
});
