// Independent re-audit of 2026-11-15 (PR #311, commit 3b9e3f5), generated Ruby. The same hand-authored goldens
// as src/reauditGenericDifferences20261115.test.ts: lines that the generated Ruby declined although its own
// recognizer admits them (UTC offset without colon, Z, fraction of a second), and lines it parsed although they
// are not JSON (comment, unknown escape, two high surrogates) or carry an offset minute of 60.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {compilePair} from '../src/index.js';
import {sampleProject} from './fixture.js';

interface GenericCase{id:string;raw:string;expect:{fields?:Record<string,unknown>;reject?:boolean}}
const REAUDIT=[
  'generic-envelope-iso-space-basic-offset','generic-envelope-iso-space-zulu','generic-envelope-rfc3339-loose-basic-offset',
  'generic-envelope-bsd-fraction-of-second','generic-envelope-rfc5424-basic-offset-asa','generic-iso-pri-offset-minute-60-declined',
  'generic-json-nesting-depth-9-declined','generic-json-lone-surrogate-escape-declined','generic-json-two-high-surrogates-declined',
  'generic-json-unknown-escape-declined','generic-json-comment-declined',
  'generic-positional-csv-quote-inside-unquoted-field-declined','generic-positional-csv-quoted-field-with-comma-and-quote',
];
const cases=(JSON.parse(readFileSync(new URL('../../contracts/semantic-goldens.v1.json',import.meta.url),'utf8')) as
  {genericCases:GenericCase[]}).genericCases.filter(item=>REAUDIT.includes(item.id));
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function fragment(extraction:Record<string,unknown>):string{
  const p:any=sampleProject();
  p.receiver.port=6801;p.extraction=extraction;
  p.normalization.topFields={};p.normalization.nsFields={};
  p.normalization.vendorFields={'generic.mode':{normalized_name:'reaudit_mode',data_type:'string'}};
  p.classification.rules=[];
  return compilePair(p).files.find(file=>!file.name.endsWith('.conf'))!.content;
}
function native(source:string,method:string,lines:string[]):string[]{
  const code=["require 'json'","require 'base64'","require 'time'","require 'date'","require 'ipaddr'","require 'csv'","require 'zlib'",
    'input=JSON.parse(STDIN.read)','klass=Class.new',"klass.class_eval(input.fetch('fragment'))",'parser=klass.new',"parser.parse('x'){}",
    "m=input.fetch('method').to_sym",
    "out=input.fetch('lines').map{|line| begin; 'OK '+JSON.generate(parser.send(m,line)); rescue ArgumentError, CSV::MalformedCSVError, JSON::ParserError => e; 'DECLINED '+e.message; end}",
    'STDOUT.write(JSON.generate(out))'].join('\n');
  const run=spawnSync('ruby',['-e',code],{input:JSON.stringify({fragment:source,method,lines}),encoding:'utf8',timeout:20000,maxBuffer:64*1024*1024});
  assert.equal(run.status,0,run.stderr||String(run.error));
  return JSON.parse(run.stdout) as string[];
}
const at=(tree:unknown,path:string):unknown=>path.split('.').reduce<unknown>((node,key)=>
  node!==null&&typeof node==='object'?(node as Record<string,unknown>)[key]:undefined,tree);

test('every listed golden exists',()=>{assert.deepEqual(cases.map(item=>item.id).sort(),[...REAUDIT].sort());});

test('Generic Structural: the generated Ruby reads the re-audit lines as the goldens say',{skip:!rubyAvailable},()=>{
  for(const extraction of [{format:'generic_structural'},{format:'generic_structural',genericStructuralFamilyGrammar:'dedicated'}]){
    const results=native(fragment(extraction),'parserstudio_generic_structural',cases.map(item=>item.raw));
    cases.forEach((item,index)=>{
      const result=results[index]!;
      if(item.expect.reject){assert.match(result,/^DECLINED /,item.id+' -> '+result.slice(0,160));return;}
      assert.match(result,/^OK \{/,item.id+' -> '+result.slice(0,160));
      const tree=JSON.parse(result.slice(3)) as unknown;
      for(const [path,value] of Object.entries(item.expect.fields!))assert.deepEqual(at(tree,path),value,item.id+' '+path);
    });
  }
});

test('JSON format: text outside RFC 8259 is declined, not repaired by the json library',{skip:!rubyAvailable},()=>{
  const B='\\';
  const lines=['{"a":1,"b":"x"}','{"s":"'+B+'ud83d'+B+'ude00 '+B+'u00e9 '+B+'n '+B+'/ '+B+'" '+B+B+'"}',
    '{"a":1 /* c */}','{"a":1} // c','{"a":"'+B+'x41"}','{"a":"'+B+'q"}','{"a":"'+B+'ud83d'+B+'ud83d"}','{"a":"'+B+'ud83d"}','{"a":"'+B+'ude00"}','{"'+B+'ud83d":1}'];
  const results=native(fragment({format:'json'}),'parserstudio_json_object',lines);
  assert.match(results[0]!,/^OK /);
  assert.equal(results[1],'OK '+JSON.stringify({s:'\u{1F600} é \n / " \\'}));
  for(let index=2;index<lines.length;index+=1)assert.match(results[index]!,/^DECLINED /,lines[index]+' -> '+results[index]!.slice(0,120));
});

// Format-level browser/Ruby fuzz of 2026-11-15: CSV.parse_line of Ruby 2.4.9 decides quoting by counting
// quotation marks and returned the field "a" (with quotation marks) for ""a"". The RFC 4180 text rule in front of
// the library declines such a row; rows that conform are split exactly as before.
test('CSV format: a row outside RFC 4180 is declined before the library sees it',{skip:!rubyAvailable},()=>{
  const source=fragment({format:'csv',csvDelimiter:',',csvColumns:['c1','c2','c3']});
  const lines=['aaa,bbb,ccc','"a""a", "b,b" ,ccc',' aaa ,bbb\f,ccc','""aaa"",bbb,ccc','"aaa"x,bbb,ccc','a"a,bbb,ccc','   '];
  const results=native(source,'parserstudio_extract',lines);
  assert.equal(results[0],'OK '+JSON.stringify({c1:'aaa',c2:'bbb',c3:'ccc'}));
  assert.equal(results[1],'OK '+JSON.stringify({c1:'a"a',c2:'b,b',c3:'ccc'}));
  assert.equal(results[2],'OK '+JSON.stringify({c1:'aaa',c2:'bbb\f',c3:'ccc'}));
  for(let index=3;index<lines.length;index+=1)assert.match(results[index]!,/^DECLINED /,JSON.stringify(lines[index])+' -> '+results[index]!.slice(0,120));
});

// CI run on 9c28109: the same test gave c2 = "bbb" on the newer host Ruby and "bbb\f" on Ruby 2.4.9, because
// the artifact passed strip: true to the CSV library where that option exists. The compiled parser must not
// depend on the interpreter: it strips field edges itself and never hands a strip option to the library.
test('CSV format: the compiled parser strips field edges itself, on every Ruby',()=>{
  const source=fragment({format:'csv',csvDelimiter:',',csvColumns:['c1','c2','c3']});
  assert.match(source,/input=strip_edges \? parserstudio_csv_strip_field_edges\(text,separator\) : text/);
  assert.doesNotMatch(source,/^[^#\n]*strip: *(?:true|strip_edges)/m);
  assert.doesNotMatch(source,/CSV::DEFAULT_OPTIONS/);
});

test('Generic Structural positional CSV: the same RFC 4180 rule',{skip:!rubyAvailable},()=>{
  const head='<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,';
  const results=native(fragment({format:'generic_structural'}),'parserstudio_generic_structural',[head+'"a,b"',head+'""a""',head+'"""a"""']);
  assert.match(results[0]!,/^OK \{/);
  assert.match(results[1]!,/^DECLINED /,results[1]!.slice(0,160));
  assert.match(results[2]!,/^OK \{/);
  assert.equal((JSON.parse(results[2]!.slice(3)) as {generic:{columns:Record<string,string>}}).generic.columns.column_11,'"a"');
});
