// RFC 5424 structured data with characters beyond the BMP, on Ruby 2.4.9. The grammar is written in UTF-16 code
// units; the structured-data scanner used to measure its 1024-byte limit by cutting a prefix of the text at
// every unit, which in the generated Ruby cut inside a character and declined every event that carries an
// emoji in an SD-PARAM value (found by the browser/Ruby differential, 2026-11-15).
import assert from 'node:assert/strict';
import {rubyE} from './ruby-argv.js';
import {spawnSync} from 'node:child_process';
import {resolvedTemplate} from './template-fixture.js';
import test from 'node:test';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const HEAD='<165>1 2026-11-14T09:30:00Z host app - ID47 ';

function run(raws:string[]):string[]{
  const script=[
    "require 'json'","require 'base64'","require 'ipaddr'","require 'time'","require 'date'","require 'zlib'",
    resolvedTemplate('ruby-fragment.rb.tpl'),
    "@parser_rule_set={'receiver'=>{'messageLengthLimit'=>65536,'tcpFraming'=>'line'},'extraction'=>{'format'=>'syslog_rfc5424','syslogBodyFormat'=>'raw'}}",
    "out=JSON.parse(Base64.strict_decode64('"+Buffer.from(JSON.stringify(raws)).toString('base64')+"')).map do |raw|",
    "  begin; 'OK '+JSON.generate(parserstudio_extract(raw)); rescue ArgumentError => e; 'REJECTED '+e.message; end",
    "end",
    "STDOUT.write(JSON.generate(out))",
  ].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:15000,maxBuffer:4*1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout) as string[];
}
const params=(out:string):Record<string,string>=>
  (JSON.parse(out.slice(3)) as {syslog_sd:{element_1:{params:Record<string,string>}}}).syslog_sd.element_1.params;

test('an SD-PARAM value with characters beyond the BMP is read whole',{skip:!rubyAvailable},()=>{
  const [emoji,escaped,several,message]=run([
    HEAD+'[meta@32473 user="kim \u{1f600}" site="한국"] login ok',
    HEAD+'[meta@32473 note="a \\" \u{1f600} \\] \\\\ z"] m',
    HEAD+'[a@1 x="\u{1f600}\u{1f601}\u{1f602}"][b@2 y="\u{10000}"] m',
    HEAD+'- \u{1f600} message with \u{1f601}',
  ]) as [string,string,string,string];
  assert.deepEqual(params(emoji),{user:'kim \u{1f600}',site:'한국'});
  assert.match(emoji,/"message":"login ok"/);
  assert.deepEqual(params(escaped),{note:'a " \u{1f600} ] \\ z'});
  assert.deepEqual(params(several),{x:'\u{1f600}\u{1f601}\u{1f602}'});
  assert.match(several,/"element_2":\{"sd_id":"b@2","params":\{"y":"\u{10000}"\}\}/u);
  assert.match(message,/^OK .*"message":"\u{1f600} message with \u{1f601}"/u);
});

test('the 1024-byte limit of the structured data counts UTF-8 bytes, with or without such characters',{skip:!rubyAvailable},()=>{
  const sd=(filler:string)=>'[meta@32473 a="'+filler+'"]';
  const overhead=Buffer.byteLength(sd(''),'utf8');
  const ascii=(bytes:number)=>sd('x'.repeat(bytes-overhead));
  // 250 emoji are 1000 bytes; the rest is ASCII.
  const astral=(bytes:number)=>sd('\u{1f600}'.repeat(250)+'x'.repeat(bytes-overhead-1000));
  for(const build of [ascii,astral]){
    assert.equal(Buffer.byteLength(build(1024),'utf8'),1024);
    const [atLimit,overLimit]=run([HEAD+build(1024)+' m',HEAD+build(1025)+' m']) as [string,string];
    assert.match(atLimit,/^OK /,atLimit.slice(0,120));
    assert.match(overLimit,/^REJECTED /,overLimit.slice(0,120));
  }
});
