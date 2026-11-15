// Run-time Parsing Success Contract of the generated Ruby for CSV, JSON, CEF and LEEF (W7): an event is handed
// over only when its fields spell the text of the event (src/grammar/lossGuard.ts, executed in Ruby as its
// translation). Shown on Ruby 2.4.9 in both directions: valid events of every route are parsed with their
// values unchanged, and an extraction that dropped, cut or invented a field becomes a rejection, never an event.
import assert from 'node:assert/strict';
import {rubyE} from './ruby-argv.js';
import {spawnSync} from 'node:child_process';
import {resolvedTemplate} from './template-fixture.js';
import test from 'node:test';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const CEF='CEF:0|Fortinet|FortiGate-60F|7.2.5|0000000013|traffic \\| forward|5|src=10.1.100.11 dst=172.16.200.55 spt=54190 msg=Detected a \\=threat\\= at C:\\\\dir request=https://example.test/?a=1&b=2 act=accept';
const LEEF1='LEEF:1.0|IBM|QRadar|7.5|Logon|src=10.0.0.1\tdst=10.0.0.2\tmsg=two words = here\tusrName=kim';
const LEEF2='LEEF:2.0|Vendor|Product|2.0|event|^|src=10.0.0.1^dst=10.0.0.2^msg=two words^url=http://x.test/?a=1';
const JSON_EVENT='{"timestamp":"2026-11-14T09:30:00Z","user":"kim \\u00e9\\ud83d\\ude00","port":443,"ratio":-1.5e2,"ok":true,"none":null,"tags":["a","b",{"deep":"value"}],"nested":{"name":"\\"quoted\\" \\/ path"}}';
const H5424='<165>1 2026-11-14T09:30:00Z host app - ID47 - ';
const H3164='<134>Nov 14 09:30:00 fw01 ';
const columns=(count:number)=>Array.from({length:count},(_item,index)=>'c'+(index+1));
// [route, extraction, event, a value the parsed event must hold unchanged]
const ROUTES:Array<[string,Record<string,unknown>,string,string]>=[
  ['csv comma',{format:'csv',csvDelimiter:',',csvColumns:columns(5)},'1,2026/10/16 15:44:21,"TRAFFIC, end", allow ,"say ""hi"""','"c5":"say \\"hi\\""'],
  ['csv semicolon',{format:'csv',csvDelimiter:';',csvColumns:columns(3)},'alpha;"b;c";gamma delta','"c2":"b;c"'],
  ['csv tab',{format:'csv',csvDelimiter:'\t',csvColumns:columns(3)},' padded \tsecond value\t"q\tq"','"c1":" padded "'],
  ['json',{format:'json'},JSON_EVENT,'"nested":{"name":"\\"quoted\\" / path"}'],
  ['cef',{format:'cef'},CEF,'"msg":"Detected a =threat= at C:\\\\dir"'],
  ['leef 1.0',{format:'leef'},LEEF1,'"msg":"two words = here"'],
  ['leef 2.0',{format:'leef'},LEEF2,'"url":"http://x.test/?a=1"'],
  ['rfc5424 json',{format:'syslog_rfc5424',syslogBodyFormat:'json'},H5424+JSON_EVENT,'"port":443'],
  ['rfc3164 cef',{format:'syslog_rfc3164',syslogBodyFormat:'cef'},H3164+CEF,'"act":"accept"'],
  ['rfc5424 leef',{format:'syslog_rfc5424',syslogBodyFormat:'leef'},H5424+LEEF2,'"msg":"two words"'],
  ['rfc3164 leef',{format:'syslog_rfc3164',syslogBodyFormat:'leef'},H3164+LEEF1,'"usrName":"kim"'],
  ['mixed json',{format:'mixed',mixedFormats:['json','kv','cef']},JSON_EVENT,'"ratio":-150'],
  ['mixed cef',{format:'mixed',mixedFormats:['json','kv','cef']},CEF,'"spt":"54190"'],
  ['mixed csv',{format:'mixed',mixedFormats:['kv','csv'],csvDelimiter:',',csvColumns:columns(3)},'alpha,"b,c",gamma','"c2":"b,c"'],
  ['mixed rfc5424_leef',{format:'mixed',mixedFormats:['rfc5424_leef','json']},H5424+LEEF2,'"dst":"10.0.0.2"'],
];
// The faults replace the generated extraction entry (psg_extract_event): the result it returns is the
// product's own, with one field of the event body dropped, cut by one character or invented.
const damaged=(change:string):string=>[
  'alias psg_extract_event_real psg_extract_event',
  'def psg_extract_event(raw, settings)',
  '  out = psg_extract_event_real(raw, settings)',
  "  return out unless out['errors'].empty?",
  "  target = out['fields']['body'].is_a?(Hash) ? out['fields']['body'] : out['fields']",
  "  key = target.keys.reverse.find { |name| target[name].is_a?(String) && target[name].length > 1 && !name.start_with?('cef_', 'leef_', 'syslog_') }",
  '  '+change,
  '  out',
  'end',
].join('\n');
const FAULTS:Record<string,string>={
  'field dropped':damaged('target.delete(key)'),
  'value cut':damaged('target[key] = target[key][0, target[key].length - 1]'),
  'field invented':damaged("target['zz_invented'] = 'x'"),
};

function run(extraction:Record<string,unknown>,fault:string,raw:string):string{
  const script=[
    "require 'json'","require 'base64'","require 'ipaddr'","require 'time'","require 'date'","require 'zlib'",
    resolvedTemplate('ruby-fragment.rb.tpl'),fault,
    "@parser_rule_set={'receiver'=>{'messageLengthLimit'=>65536},'extraction'=>JSON.parse("+JSON.stringify(JSON.stringify(extraction))+")}",
    "begin; record=parserstudio_extract("+JSON.stringify(raw)+"); STDOUT.write('OK '+JSON.generate(record)); rescue ArgumentError => e; STDOUT.write('REJECTED '+e.message); end",
  ].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:8000,maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return result.stdout;
}

test('the loss accounting of every dialect is part of the generated grammar',()=>{
  const body=resolvedTemplate('ruby-fragment.rb.tpl');
  for(const method of ['psg_csv_row_unaccounted','psg_json_text_unaccounted','psg_cef_event_unaccounted','psg_leef_event_unaccounted','psg_unaccounted_text'])
    assert.match(body,new RegExp('^def '+method+'\\(','m'),method);
});

test('valid CSV, JSON, CEF and LEEF events are parsed on every route with their values unchanged',{skip:!rubyAvailable},()=>{
  for(const [route,extraction,raw,held] of ROUTES){
    const out=run(extraction,'',raw);
    assert.match(out,/^OK /,route+' -> '+out.slice(0,200));
    assert.ok(out.includes(held),route+' does not hold '+held+': '+out.slice(0,400));
  }
});

test('an extraction that dropped, cut or invented a field is rejected on every route, and the reason holds no event text',{skip:!rubyAvailable},()=>{
  for(const [route,extraction,raw] of ROUTES)for(const [fault,code] of Object.entries(FAULTS)){
    const out=run(extraction,code,raw);
    assert.match(out,/^REJECTED .*(CSV|JSON|CEF|LEEF)/,route+' / '+fault+' -> '+out.slice(0,200));
    assert.doesNotMatch(out,/10\.0\.0|172\.16|kim|alpha|gamma|TRAFFIC|two words|example\.test/,route+' / '+fault+' quotes the event: '+out.slice(0,200));
  }
});
