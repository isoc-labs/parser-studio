// The record of a declined event names the class of its error in parser_err_msg, and that name is data an operator
// filters on. Text that is not JSON at all has always been reported there as JSON::ParserError; every other decline
// of the extraction is an ArgumentError. Since the grammar of an artifact is generated from the browser grammar, a
// decline is a reading that is not FULL, so the name is decided where the reading is handed over. Found by comparing
// the error records of artifacts downloaded from main with this branch on abnormal lines (2026-11-15).
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {compilerVariants} from './compiler-variants.js';
import {rubyE} from './ruby-argv.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

const diagnostics=(variantId:string,lines:string[]):Array<Array<Record<string,unknown>|null>>=>{
  const variant=compilerVariants().find(item=>item.id===variantId)!;
  const ruby=compilePair(variant.project).files.find(file=>!file.name.endsWith('.conf'))!.content;
  const script=[
    "require 'json'","require 'base64'","require 'time'","require 'date'","require 'ipaddr'","require 'zlib'",
    "klass = Class.new","klass.class_eval(Base64.strict_decode64('"+Buffer.from(ruby,'utf8').toString('base64')+"').force_encoding('UTF-8'))",
    "parser = klass.new",
    "lines = JSON.parse(Base64.strict_decode64('"+Buffer.from(JSON.stringify(lines),'utf8').toString('base64')+"').force_encoding('UTF-8'))",
    "out = lines.map { |line| events = []; parser.parse(line) { |_time, record| events << (record && record.reject { |key, _| key == 'source_raw' }) }; events }",
    "STDOUT.write(Base64.strict_encode64(JSON.generate(out)))",
  ].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});
  assert.equal(result.status,0,(result.stderr||String(result.error)).slice(0,600));
  return JSON.parse(Buffer.from(result.stdout,'base64').toString('utf8')) as Array<Array<Record<string,unknown>|null>>;
};

test('text that is not JSON is reported as JSON::ParserError, every other declined JSON event as ArgumentError',{skip:!rubyAvailable},()=>{
  const lines=['{invalid','{"action":"deny"} trailing','not json at all','[1,2]','"text"','{"a":1,"a":2}','{"a":12345678901234567890}'];
  const names=diagnostics('format:json',lines).map(events=>events.map(record=>record?String(record.parser_err_msg)+'/'+String(record.parser_err_stage):'nil').join(','));
  assert.deepEqual(names,[
    'JSON::ParserError/extraction','JSON::ParserError/extraction','JSON::ParserError/extraction',
    'ArgumentError/extraction','ArgumentError/extraction','ArgumentError/extraction','ArgumentError/extraction',
  ]);
});

test('a declined event of another format is an ArgumentError',{skip:!rubyAvailable},()=>{
  for(const [variantId,line] of [['format:cef','CEF:0|only|three'],['format:leef','LEEF:9.9|x'],['format:kv','srcip="unterminated']] as const){
    const events=diagnostics(variantId,[line])[0]!;
    assert.equal(events.length,1,variantId);
    assert.equal(events[0]!.parser_err_msg,'ArgumentError',variantId);
    assert.equal(events[0]!.parser_err_stage,'extraction',variantId);
  }
});
