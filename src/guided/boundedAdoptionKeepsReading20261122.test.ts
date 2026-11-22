/**
 * Adoption of the bounded compiler's reading is decided on the READING, not on what the first scan called
 * the line (independent audit 2026-11-21 of 714d272..7a255a6: F-01, F-02, F-08).
 *
 * F-01  A delimited record whose cells the reading merges is not adopted. One double quote in a cell made the
 *       first scan call the line "suspected CSV, not read" and the rule for CSV lines was switched off: three
 *       cells ended up in the official url and the event was FULL.
 * F-02  An event the first scan read natively and completely is not replaced by a reading that holds less:
 *       beside a PRI-less PAN-OS record, a Syslog key=value line became one message field, or its header
 *       became five positional vendor fields, and the sample was adopted as completely parsed.
 * F-08  A reading that keeps the cells of the record and names them from the record itself is adopted whether
 *       the values are quoted or not.
 */
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {buildSourceReviewedBoundedDraft,headerlessCsvEvents,nativelyReadEvents,
  type GenericStructuralSourceReview} from './genericStructuralAutoDraft';

// The witness the Auto Parser gets from the preview service: every line a completely parsed source record.
function parsedWitness(source:string):GenericStructuralSourceReview{
  const encoder=new TextEncoder();let offset=0;
  const events=source.split('\n').map(line=>{
    const startByte=offset,endByte=offset+encoder.encode(line).byteLength;
    offset=endByte+1;
    return {startByte,endByte,preview:{status:'SOURCE_PARSED' as const,issues:[]}};
  });
  return {raw:source,events};
}
// Exactly what AutoParser.tsx does with the first scan of the sample.
function adopt(source:string){
  const report=analyzeLogEnvelopes(source,'single-line');
  return buildSourceReviewedBoundedDraft(source,createDraft(),parsedWitness(source),
    headerlessCsvEvents(report.events),nativelyReadEvents(report.events));
}
const modes=(source:string)=>adopt(source)?.suite.events.map(event=>(event.fields.generic as {mode:string}).mode)??null;

const PAN='Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';

describe('F-01: a reading that merges the cells of a delimited record is not adopted',()=>{
  it.each([
    ['a quoted value in one cell',
      '2026-11-21 10:00:00,web01,request user="bob" src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok\n'+
      '2026-11-21 10:00:01,web01,request user="amy" src=10.0.0.6 method=POST status=403 url=/admin,10.0.0.9,8443,denied'],
    ['a quoted first word',
      '2026-11-21 10:00:00,web01,"request" user=bob src=10.0.0.5 dst=10.0.0.9 method=GET status=200 url=/index.html,10.0.0.9,8443,ok'],
    ['semicolon cells',
      '2026-11-21 10:00:00;web01;request user="bob" src=10.0.0.5 method=GET status=200 url=/index.html;10.0.0.9;8443;ok'],
    ['the same record behind a PRI',
      '<14>2026-11-21 10:00:00,web01,request user=bob src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok'],
  ])('%s',(_name,source)=>{
    expect(adopt(source)).toBeNull();
  });

  it('flags a suspected delimited record whether or not the strict CSV lexer could read it',()=>{
    const flags=(source:string)=>headerlessCsvEvents(analyzeLogEnvelopes(source,'single-line').events);
    expect(flags('2026-11-21 10:00:00,web01,request user="bob" src=10.0.0.5 url=/index.html,10.0.0.9,8443,ok')).toEqual([true]);
    expect(flags('2026-11-21 10:00:00,web01,request user=bob src=10.0.0.5 url=/index.html,10.0.0.9,8443,ok')).toEqual([true]);
    expect(flags('<134>Nov 21 10:00:01 fw1 system: logdesc=login user=bob srcip=10.0.0.7 action=accept')).toEqual([false]);
  });
});

describe('a delimiter inside a quoted value is not evidence of merged cells',()=>{
  // E2E T9: the public Junos RT_FLOW sample was adopted before the rule and must stay adopted.
  const SD='<14>1 2019-11-14T09:37:51.184+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.40 source-address="10.0.0.1" source-port="594" destination-address="67.43.156.13" destination-port="10400" application-category="Web,Media,Other" policy-name="vpn_trust;permit;all"]';
  it('adopts an RFC 5424 record whose STRUCTURED-DATA values hold commas and semicolons',()=>{
    const none=[false];
    const adopted=buildSourceReviewedBoundedDraft(SD,createDraft(),parsedWitness(SD),none,none);
    expect(adopted).not.toBeNull();
    expect(adopted!.suite.events[0]!.parseStatus).toBe('FULL');
  });
});

describe('F-08: a reading that keeps the cells and names them from the record is adopted',()=>{
  const QUOTED='Oct 15 00:14:28 bigip-waf01 ASM: unit_hostname="bigip-waf01",management_ip_address="10.1.1.10",request_status="blocked",violations="SQL-Injection,Cross Site Scripting",ip_client="203.0.113.211",route_domain="0",method="POST",protocol="HTTPS",dest_port="443",dest_ip="10.20.1.25",uri="/api/login?a=1,b=2"';
  const UNQUOTED='Oct 15 00:14:27 bigip-waf01 ASM: unit_hostname=bigip-waf01,management_ip_address=10.1.1.10,request_status=blocked,ip_client=203.0.113.210,route_domain=0,method=POST,protocol=HTTPS,dest_port=443,dest_ip=10.20.1.25,uri=/api/login';

  it('keeps a delimiter inside a quoted value in its value',()=>{
    const adopted=adopt(QUOTED);
    expect(adopted).not.toBeNull();
    const fields=(adopted!.suite.events[0]!.fields.generic as {mode:string;fields:Record<string,string>});
    expect(fields.mode).toBe('delimited_kv');
    expect(fields.fields.violations).toBe('SQL-Injection,Cross Site Scripting');
    expect(fields.fields.uri).toBe('/api/login?a=1,b=2');
    expect(adopted!.suite.events[0]!.parseStatus).toBe('FULL');
  });

  it('adopts the quoted and the unquoted line of one family together',()=>{
    expect(modes(UNQUOTED+'\n'+QUOTED.replace(',violations="SQL-Injection,Cross Site Scripting"','').replace('?a=1,b=2',''))).toEqual(['delimited_kv','delimited_kv']);
  });
});

describe('F-02: a natively and completely read event is not replaced by a reading that holds less',()=>{
  it('names the events the first scan read natively',()=>{
    const report=analyzeLogEnvelopes(PAN+'\n<134>Nov 21 10:00:01 fw1 system: logdesc=login user=bob srcip=10.0.0.7 action=accept\nfree text nobody reads','single-line');
    expect(nativelyReadEvents(report.events)).toEqual([false,true,false]);
  });

  it.each([
    ['its pairs would become one message field','<134>Nov 21 10:00:01 fw1 system: logdesc=login user=bob srcip=10.0.0.7 action=accept'],
    ['its Syslog header would become positional vendor fields','<134>Nov 21 10:00:00 fw1 traffic: srcip=10.0.0.1 dstip=10.0.0.2 srcport=51234 dstport=443 proto=6 action=accept'],
    ['text beyond ASCII','<134>Nov 21 10:00:00 fw1 traffic: srcip=10.0.0.1 dstip=10.0.0.2 msg="접속 허용 é" user=홍길동'],
  ])('a Syslog key=value line beside a PRI-less PAN-OS record: %s',(_name,line)=>{
    expect(adopt(PAN+'\n'+line)).toBeNull();
    expect(adopt(line+'\n'+PAN)).toBeNull();
  });

  it('still adopts the PRI-less PAN-OS record alone, with its columns named',()=>{
    expect(modes(PAN)).toEqual(['panos_traffic_csv']);
    expect(modes(PAN+'\n'+PAN.replace('10.10.20.15','10.10.20.16'))).toEqual(['panos_traffic_csv','panos_traffic_csv']);
  });
});

// Independent audit of 2026-11-22, G-03: the rule knew cells separated by a comma or a semicolon, and three or
// more of them. The same record with pipes, or with two cells before the first white space, was still adopted
// with three cells in the official url.
describe('G-03: pipe cells and two header cells are the cells of a delimited record as well',()=>{
  it.each([
    ['pipe cells',
      '2026-11-21 10:00:00|web01|request user="bob" src=10.0.0.5 method=GET status=200 url=/index.html|10.0.0.9|8443|ok'],
    ['pipe cells behind a PRI',
      '<14>2026-11-21 10:00:00|web01|request user="bob" src=10.0.0.5 method=GET status=200 url=/index.html|10.0.0.9|8443|ok'],
    ['two header cells behind a PRI',
      '<14>2026-11-21 10:00:00,web01 user=bob src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok'],
    ['two header cells without a PRI',
      '2026-11-21 10:00:00,web01 user=bob src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok'],
  ])('%s',(_name,source)=>{
    expect(adopt(source)).toBeNull();
  });

  it.each([
    '<14>2026-11-21 10:00:00,123 user=bob src=10.0.0.5 method=GET status=200 url=/index.html',
    '<14>2026-11-21 10:00:00,123+09:00 user=bob src=10.0.0.5 method=GET status=200 url=/index.html',
    '<14>2026-11-21 10:00:00,123Z user=bob src=10.0.0.5 method=GET status=200 url=/index.html',
  ])('does not take the decimal fraction of a time for a second cell: %s',source=>{
    expect(modes(source)).toEqual(['space_kv']);
  });
});
