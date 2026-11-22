/**
 * Per-event independence of the Auto Parser's reading (Phase 3, P2).
 *
 * Every event of a multi-event sample gets its own verdict (FULL, PARTIAL, or declined: UNKNOWN / ERROR), and
 * the verdict and the fields of an event do not depend on which other events stand in the sample or in which
 * order: the success of one event never hides the failure of another, and a damaged event never spoils a good
 * one. The property is checked for the native reading of the browser (format "auto") against the reading of
 * the same event alone.
 *
 * The samples marked SYNTHETIC are written after documented formats; they are not vendor originals.
 */
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';

const KV1='<134>Nov 21 10:00:00 fw1 traffic: srcip=10.0.0.1 dstip=10.0.0.2 srcport=51234 dstport=443 proto=6 action=accept';
const KV2='<134>Nov 21 10:00:01 fw1 traffic: srcip=10.0.0.3 dstip=10.0.0.4 srcport=51235 dstport=53 proto=17 action=deny';
const KV_NO_PRI='Nov 21 10:00:03 fw1 traffic: srcip=10.0.0.7 dstip=10.0.0.8 srcport=51237 dstport=22 proto=6 action=accept';
const KV_LIST='<134>Nov 21 10:00:05 fw1 src=10.0.0.1,dst=10.0.0.2,action=allow';
const KV_LOST_PAIR='<134>Nov 21 10:00:06 fw1 url=/login?user=bob,src=10.0.0.1,dst=10.0.0.2';
const JSON1='{"ts":"2026-11-21T10:00:01Z","src_ip":"10.0.0.5","dest_ip":"10.0.0.9","src_port":51000,"dest_port":443,"action":"allow"}';
const CEF1='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const RFC5424='<165>1 2026-11-21T10:00:07Z host1 app 1234 ID47 [meta@32473 seq="1"] user=bob action=login';
const UNCLOSED_QUOTE='<134>Nov 21 10:00:04 fw1 traffic: srcip=10.0.0.9 dstip=10.0.0.10 msg="unterminated action=accept';
const FREE_TEXT='kernel panic - not syncing: fatal exception in interrupt';
const BROKEN_JSON='{"ts":"2026-11-21T10:00:08Z","src_ip":"10.0.0.5",';
// SYNTHETIC, PAN-OS field order without a Syslog PRI.
const PAN_TRAFFIC='Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const PAN_SYSTEM='Oct 15 00:05:00 PA-FW01 1,2026/10/15 00:05:00,012345678901,SYSTEM,general,0,2026/10/15 00:05:00,,general,,0,0,general,informational,"User admin logged in via Web from 10.1.1.5 using https",12345,0x0,0,0,0,0,,PA-FW01';

const EXPECTED:readonly (readonly [name:string,line:string,status:string])[]=[
  ['RFC 3164 key=value',KV1,'FULL'],
  ['RFC 3164 key=value, second record',KV2,'FULL'],
  ['RFC 3164 comma list',KV_LIST,'FULL'],
  ['RFC 3164 with a pair the grammar did not read',KV_LOST_PAIR,'PARTIAL'],
  ['JSON',JSON1,'FULL'],
  ['CEF',CEF1,'FULL'],
  ['RFC 5424 with structured data',RFC5424,'FULL'],
  ['unclosed quote',UNCLOSED_QUOTE,'UNKNOWN'],
  ['free text',FREE_TEXT,'UNKNOWN'],
  ['truncated JSON',BROKEN_JSON,'UNKNOWN'],
];

type Reading={status:string;format:string;fields:string};
function read(lines:readonly string[]):Reading[]{
  return preview(lines.join('\n'),{...createDraft(),format:'auto'}).events.map(event=>({
    status:event.parseStatus as string,format:String(event.effectiveFormat),fields:JSON.stringify(event.fields)}));
}
function permutations<T>(items:readonly T[]):T[][]{
  if(items.length<=1)return [[...items]];
  return items.flatMap((item,index)=>permutations([...items.slice(0,index),...items.slice(index+1)]).map(rest=>[item,...rest]));
}

describe('every event gets its own verdict',()=>{
  it.each(EXPECTED)('%s alone',(_name,line,status)=>{
    const alone=read([line]);
    expect(alone).toHaveLength(1);
    expect(alone[0]!.status).toBe(status);
  });

  it('a declined event keeps no field, a partly read event keeps the fields it read',()=>{
    expect(read([UNCLOSED_QUOTE])[0]!.fields).toBe('{}');
    expect(read([FREE_TEXT])[0]!.fields).toBe('{}');
    expect(JSON.parse(read([KV_LOST_PAIR])[0]!.fields).body).toEqual({url:'/login?user=bob,src=10.0.0.1,dst=10.0.0.2'});
  });
});

describe('the verdict and the fields of an event do not depend on the other events of the sample',()=>{
  const GROUPS:readonly (readonly [name:string,lines:readonly string[]])[]=[
    ['different log types',[KV1,JSON1,CEF1,RFC5424]],
    ['good and damaged events',[KV1,UNCLOSED_QUOTE,KV2,FREE_TEXT]],
    ['a list, a lost pair and a truncated record',[KV_LIST,KV_LOST_PAIR,BROKEN_JSON,JSON1]],
    ['Syslog with and without a PRI',[KV1,KV_NO_PRI,KV2]],
    ['PAN-OS record types without a PRI',[PAN_TRAFFIC,PAN_SYSTEM,KV1]],
  ];
  it.each(GROUPS)('%s, in every order',(_name,lines)=>{
    const alone=new Map(lines.map(line=>[line,read([line])[0]!]));
    for(const order of permutations(lines)){
      const together=read(order);
      expect(together).toHaveLength(order.length);
      order.forEach((line,index)=>expect(together[index],'event '+(index+1)+' of '+order.length).toEqual(alone.get(line)));
    }
  });

  it('counts each verdict once: one damaged event among three good ones',()=>{
    const suite=preview([KV1,KV2,UNCLOSED_QUOTE,JSON1].join('\n'),{...createDraft(),format:'auto'});
    expect(suite.events.map(event=>event.parseStatus)).toEqual(['FULL','FULL','UNKNOWN','FULL']);
    expect(suite.counts).toMatchObject({total:4,extracted:3,failures:1});
  });
});
