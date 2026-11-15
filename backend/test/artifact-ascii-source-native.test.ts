// The generated parser is loaded by Fluentd on the sensor with whatever source encoding the process has; with
// LANG=C that is US-ASCII, and a regular expression literal that holds a character beyond ASCII is then a
// syntax error: the plugin does not load at all. Every non-ASCII character of the Ruby is therefore written as an
// escape. Found by the CI job that starts a real Fluentd 1.7.4 on Ruby 2.4.9 (2026-11-15): the hand-written
// grammar runtime held the Unicode white space of String#trim as literal characters.
import assert from 'node:assert/strict';
import {readdirSync, readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {compilerVariants} from './compiler-variants.js';
import {rubyE} from './ruby-argv.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const nonAscii=(text:string):string|null=>{
  const at=text.search(/[^\x00-\x7f]/);
  return at<0?null:'line '+text.slice(0,at).split('\n').length;
};

test('every Ruby template is ASCII source',()=>{
  const directory=new URL('../templates/',import.meta.url);
  for(const name of readdirSync(directory))
    assert.equal(nonAscii(readFileSync(new URL(name,directory),'utf8')),null,name+' holds a character beyond ASCII');
});

test('the Ruby of every compiler variant is ASCII source',()=>{
  for(const variant of compilerVariants()){
    const ruby=compilePair(variant.project).files.find(file=>!file.name.endsWith('.conf'))!.content;
    assert.equal(nonAscii(ruby),null,variant.id+' holds a character beyond ASCII');
  }
});

test('an artifact loaded as US-ASCII source parses events with text beyond ASCII',{skip:!rubyAvailable},()=>{
  const variant=compilerVariants().find(item=>item.id==='format:kv')!;
  variant.project.normalization.vendorFields={user:{normalized_name:'user_name',data_type:'string'}};
  const ruby=compilePair(variant.project).files.find(file=>!file.name.endsWith('.conf'))!.content;
  const lines=['srcip=10.1.1.1 user=김철수 note= x y action=deny','srcip=10.1.1.2 user=kim\u{1f600} action=accept',' 　'];
  const script=[
    "require 'json'","require 'base64'","require 'time'","require 'date'","require 'ipaddr'","require 'zlib'",
    // The fragment and the lines arrive as Base64 so that this script itself stays ASCII.
    "source = Base64.strict_decode64('"+Buffer.from(ruby,'utf8').toString('base64')+"').force_encoding('US-ASCII')",
    "klass = Class.new","klass.class_eval(source)","parser = klass.new",
    "lines = JSON.parse(Base64.strict_decode64('"+Buffer.from(JSON.stringify(lines),'utf8').toString('base64')+"').force_encoding('UTF-8'))",
    "out = lines.map { |line| events = []; parser.parse(line.dup.force_encoding('ASCII-8BIT')) { |_time, record| events << record }; events }",
    "STDOUT.write(Base64.strict_encode64(JSON.generate(out)))",
  ].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});
  assert.equal(result.status,0,(result.stderr||String(result.error)).slice(0,600));
  const events=JSON.parse(Buffer.from(result.stdout,'base64').toString('utf8')) as Array<Array<Record<string,unknown>|null>>;
  assert.equal(JSON.stringify(events[0]).includes('parser_err'),false,JSON.stringify(events[0]).slice(0,300));
  assert.ok(JSON.stringify(events[0]).includes('김철수'),JSON.stringify(events[0]).slice(0,300));
  assert.equal(JSON.stringify(events[1]).includes('parser_err'),false,JSON.stringify(events[1]).slice(0,300));
  // A line of Unicode blanks is no event, as in the browser (String#trim).
  assert.equal(events[2]!.filter(record=>record&&!('parser_err_msg' in record)).length,0);
});
