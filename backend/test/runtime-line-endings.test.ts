// Line endings at run time. The browser preview reads CRLF as a line terminator and declines an event that
// holds a bare carriage return, in every format. The generated Ruby is held to the same reading of the same
// bytes: a frame cut at LF from a CRLF-terminated stream ends in CR, which is part of the terminator; any other
// CR declines the event, in JSON as well; LF inside an event exists only in the blank-line framing of its format.
import assert from 'node:assert/strict';
import {rubyE} from './ruby-argv.js';
import {spawnSync} from 'node:child_process';
import {resolvedTemplate} from './template-fixture.js';
import test from 'node:test';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function run(extraction:Record<string,unknown>,framing:string,raw:string):string{
  const script=[
    "require 'json'","require 'base64'","require 'ipaddr'","require 'time'","require 'date'","require 'zlib'",
    resolvedTemplate('ruby-fragment.rb.tpl'),
    "@parser_rule_set={'receiver'=>{'messageLengthLimit'=>65536,'tcpFraming'=>"+JSON.stringify(framing)+"},'extraction'=>JSON.parse("+JSON.stringify(JSON.stringify(extraction))+")}",
    "begin; record=parserstudio_extract("+JSON.stringify(raw)+"); STDOUT.write('OK '+JSON.generate(record)); rescue ArgumentError => e; STDOUT.write('REJECTED '+e.message); end",
  ].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:8000,maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return result.stdout;
}

const FORMATS:Array<[string,Record<string,unknown>,string,string]>=[
  ['kv',{format:'kv'},'srcip=10.1.1.1 action=deny','{"srcip":"10.1.1.1","action":"deny"}'],
  ['json',{format:'json'},'{"user":"kim","port":443}','{"user":"kim","port":443}'],
  ['csv',{format:'csv',csvDelimiter:',',csvColumns:['a','b']},'one,two','{"a":"one","b":"two"}'],
  ['cef',{format:'cef'},'CEF:0|a|b|c|d|e|5|src=10.0.0.1 msg=two words','"msg":"two words"}'],
  ['leef',{format:'leef'},'LEEF:1.0|a|b|c|d|src=10.0.0.1\tmsg=two words','"msg":"two words"}'],
  ['rfc3164 kv',{format:'syslog_rfc3164',syslogBodyFormat:'kv'},'<134>Nov 14 09:30:00 fw01 srcip=10.1.1.1 action=deny','"body":{"srcip":"10.1.1.1","action":"deny"}}'],
  ['rfc5424 raw',{format:'syslog_rfc5424',syslogBodyFormat:'raw'},'<165>1 2026-11-14T09:30:00Z host app - ID47 - a message','"message":"a message"}'],
  ['generic',{format:'generic_structural'},'<13>srcip=10.1.1.1 dstip=10.2.2.2 dstport=443 proto=tcp action=accept','"action":"accept"'],
];

test('a frame of a CRLF-terminated stream is the event without its terminator, in every format',{skip:!rubyAvailable},()=>{
  for(const [name,extraction,raw,held] of FORMATS){
    const plain=run(extraction,'line',raw);
    assert.match(plain,/^OK /,name+' -> '+plain.slice(0,160));
    assert.ok(plain.includes(held),name+': '+plain.slice(0,300));
    assert.equal(run(extraction,'line',raw+'\r'),plain,name+' with the CR of a CRLF terminator');
  }
});

test('a bare carriage return declines the event in every format, JSON included',{skip:!rubyAvailable},()=>{
  for(const [name,extraction,raw] of FORMATS){
    const middle=Math.floor(raw.length/2);
    for(const text of ['\r'+raw,raw.slice(0,middle)+'\r'+raw.slice(middle),raw+'\r\r',raw+' \r '])
      assert.match(run(extraction,'line',text),/^REJECTED /,name+' '+JSON.stringify(text).slice(0,80));
  }
  // CR is JSON white space, so the JSON reader alone would accept these.
  for(const text of ['{"user":"kim",\r"port":443}','\r{"user":"kim","port":443}'])
    assert.match(run({format:'json'},'line',text),/^REJECTED A bare carriage return/,JSON.stringify(text));
});

test('LF inside an event exists only in the blank-line framing of its format',{skip:!rubyAvailable},()=>{
  const multiline='{"user":"kim",\n"port":443}';
  assert.match(run({format:'json'},'line',multiline),/^REJECTED Multiline unframed event/);
  assert.match(run({format:'json'},'blank_line_java',multiline),/^REJECTED Multiline unframed event/);
  assert.equal(run({format:'json'},'blank_line_json',multiline),'OK {"user":"kim","port":443}');
  // CRLF inside a blank-line framed event is a line break, as in the browser.
  assert.equal(run({format:'json'},'blank_line_json','{"user":"kim",\r\n"port":443}'),'OK {"user":"kim","port":443}');
  assert.match(run({format:'json'},'blank_line_json','{"user":"kim",\r"port":443}'),/^REJECTED A bare carriage return/);
  for(const [name,extraction,raw] of FORMATS.filter(([name])=>name!=='json'))
    for(const framing of ['line','blank_line_json'])
      assert.match(run(extraction,framing,raw+'\n'+raw),/^REJECTED /,name+' '+framing);
});
