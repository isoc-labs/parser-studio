import assert from 'node:assert/strict';
import {rubyE} from './ruby-argv.js';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {diagnosticsOf} from './failure-record.js';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function project(){
  const p=sampleProject();
  p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[];
  // Order matters: one good field before the failing cast, one after it.
  p.normalization.topFields={
    username:{normalized_name:'username',data_type:'string'},
    value:{normalized_name:'dstport',data_type:'integer'},
    hostname:{normalized_name:'host_name',data_type:'string'},
  };
  return p;
}

function run(p:ReturnType<typeof project>,line:string):Record<string,unknown>{
  const code=compilePair(p).files.find(file=>!file.name.endsWith('.conf'))!.content;
  const program=[
    "require 'json'","require 'base64'","require 'csv'","require 'time'","require 'ipaddr'",
    'klass = Class.new',
    "klass.class_eval(Base64.strict_decode64('"+Buffer.from(code).toString('base64')+"'))",
    'parser = klass.new',
    'parser.parse(STDIN.read){|_time,record| puts JSON.generate(record)}',
  ].join('\n');
  const result=spawnSync('ruby',rubyE(program),{encoding:'utf8',input:line,timeout:15000,maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout) as Record<string,unknown>;
}

test('a failing field cast keeps the other successfully extracted fields next to the diagnostics',
  {skip:!rubyAvailable},()=>{
    const line=JSON.stringify({username:'alice',value:65536,hostname:'fw01'});
    const out=run(project(),line);
    assert.equal(out.parser_err_msg,'MappedFieldError');
    assert.equal(out.parser_err_stage,'normalization');
    assert.equal(out.parser_err_field,'value');
    assert.equal(out.stellar_log_index,'syslog');
    assert.equal(out.username,'alice');
    assert.equal(out.host_name,'fw01');
    assert.ok(!('dstport' in out),'the field that failed is not emitted');
    assert.equal(out.parser_raw_msg,line,'the original text is kept whole');
    assert.ok(!JSON.stringify(diagnosticsOf(out)).includes('65536'),'no other field echoes the invalid value');
  });

test('diagnostic keys always win over extracted fields and only parser_raw_msg holds the raw log text',
  {skip:!rubyAvailable},()=>{
    const line=JSON.stringify({username:'alice',value:65536,hostname:'fw01',unmapped:'DO_NOT_ECHO_PRIVATE'});
    const out=run(project(),line);
    assert.equal(out.parser_err_stage,'normalization');
    assert.equal(out.parser_raw_msg,line,'the original text is kept whole');
    assert.ok(!JSON.stringify(diagnosticsOf(out)).includes('DO_NOT_ECHO_PRIVATE'),'unmapped source data stays out of every other field');
    assert.ok(!JSON.stringify(diagnosticsOf(out)).includes(line),'no other field repeats the raw line');
  });

test('an extraction failure emits the diagnostics and the original text only',
  {skip:!rubyAvailable},()=>{
    const line='this is not json DO_NOT_ECHO_PRIVATE';
    const out=run(project(),line);
    assert.equal(out.parser_err_stage,'extraction');
    assert.equal(out.parser_raw_msg,line);
    assert.deepEqual(Object.keys(out).sort(),['parser_err_msg','parser_err_stage','parser_raw_msg','stellar_log_index']);
  });

test('a clean event is unchanged',
  {skip:!rubyAvailable},()=>{
    const out=run(project(),JSON.stringify({username:'alice',value:443,hostname:'fw01'}));
    assert.ok(!('parser_err_msg' in out));
    assert.ok(!('parser_raw_msg' in out),'a parsed event carries no raw copy');
    assert.equal(out.dstport,443);
    assert.equal(out.username,'alice');
  });

test('a mapped parser_raw_msg never replaces the original text of a failed event',
  {skip:!rubyAvailable},()=>{
    const p=project();
    p.normalization.topFields={
      username:{normalized_name:'parser_raw_msg',data_type:'string'},
      value:{normalized_name:'dstport',data_type:'integer'},
    };
    const line=JSON.stringify({username:'alice',value:65536});
    const out=run(p,line);
    assert.equal(out.parser_err_stage,'normalization');
    assert.equal(out.parser_raw_msg,line);
  });
