// Owner decision of 2026-11-22: an event the generated parser cannot read is never lost. Its failure record
// carries the original text in parser_raw_msg - the field of the Stellar Cyber 7.0 dictionary for "the raw,
// unparsed message. In the case of a parsing error, the entire error log", which the installed reference
// parsers write as well. Until then the record named the error only and copied no text, so the event survived
// only if the receiver kept it.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {compilerVariants} from './compiler-variants.js';
import {rubyE} from './ruby-argv.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

const records=(variantId:string,lines:string[]):Array<Array<Record<string,unknown>|null>>=>{
  const variant=compilerVariants().find(item=>item.id===variantId)!;
  const ruby=compilePair(variant.project).files.find(file=>!file.name.endsWith('.conf'))!.content;
  const script=[
    "require 'json'","require 'base64'","require 'time'","require 'date'","require 'ipaddr'","require 'zlib'",
    "klass = Class.new","klass.class_eval(Base64.strict_decode64('"+Buffer.from(ruby,'utf8').toString('base64')+"').force_encoding('UTF-8'))",
    "parser = klass.new",
    "lines = JSON.parse(Base64.strict_decode64('"+Buffer.from(JSON.stringify(lines),'utf8').toString('base64')+"').force_encoding('UTF-8'))",
    "out = lines.map { |line| events = []; parser.parse(line) { |_time, record| events << record }; events }",
    "STDOUT.write(Base64.strict_encode64(JSON.generate(out)))",
  ].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});
  assert.equal(result.status,0,(result.stderr||String(result.error)).slice(0,600));
  return JSON.parse(Buffer.from(result.stdout,'base64').toString('utf8')) as Array<Array<Record<string,unknown>|null>>;
};

test('the failure record of an event that was not read keeps the original text in parser_raw_msg',{skip:!rubyAvailable},()=>{
  for(const [variantId,line] of [
    ['format:kv','srcip="unterminated'],
    ['format:kv','srcip=10.0.0.9 msg="열린 따옴표 é action=accept'],
    ['format:json','not json at all'],
    ['format:json','{"a":1,"a":2}'],
    ['format:cef','CEF:0|only|three'],
    ['format:leef','LEEF:9.9|x'],
  ] as const){
    const events=records(variantId,[line])[0]!;
    assert.equal(events.length,1,variantId+' emits one record');
    assert.equal(typeof events[0]!.parser_err_msg,'string',variantId);
    assert.equal(events[0]!.parser_raw_msg,line,variantId+' keeps the original text');
  }
});

test('every line yields one record, and only the failure record carries parser_raw_msg',{skip:!rubyAvailable},()=>{
  const lines=['{"srcip":"10.0.0.1","action":"allow"}','{broken','{"srcip":"10.0.0.2","action":"deny"}'];
  const out=records('format:json',lines);
  assert.deepEqual(out.map(events=>events.length),[1,1,1]);
  assert.equal(out[1]![0]!.parser_raw_msg,'{broken');
  for(const index of [0,2]){
    assert.equal('parser_err_msg' in out[index]![0]!,false,'event '+(index+1)+' is parsed');
    assert.equal('parser_raw_msg' in out[index]![0]!,false,'a parsed event carries no copy of the raw text here');
  }
});
