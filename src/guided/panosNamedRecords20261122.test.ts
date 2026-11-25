import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {extractGenericStructural} from '../genericStructural';
import {classifyGenericStructural} from '../grammar/genericParseStatus';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {buildSourceReviewedBoundedDraft,headerlessCsvEvents,nativelyReadEvents,
  type GenericStructuralSourceReview} from './genericStructuralAutoDraft';

// PAN-OS THREAT and SYSTEM records are named from the documented field order of the PAN-OS syslog field
// descriptions, like TRAFFIC. SYNTHETIC lines written after that order (not vendor originals).
const TRAFFIC='Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const THREAT='Oct 15 00:03:25 PA-FW01 1,2026/10/15 00:03:25,012345678901,THREAT,url,2561,2026/10/15 00:03:25,10.10.20.15,203.0.113.50,203.0.113.10,203.0.113.50,allow-web,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:25,123457,1,51520,80,62002,80,0x408000,tcp,alert,"example.com/index.html",(9999),computer-and-internet-info,informational,client-to-server,987654322,0x0,10.0.0.0-10.255.255.255,United States,0,text/html';
const SYSTEM='Oct 15 00:05:00 PA-FW01 1,2026/10/15 00:05:00,012345678901,SYSTEM,general,0,2026/10/15 00:05:00,,general,,0,0,general,informational,"User admin logged in via Web from 10.1.1.5 using https",12345,0x0,0,0,0,0,,PA-FW01';
type Generic={mode:string;fields?:Record<string,string>;columns?:Record<string,string>};
const generic=(raw:string)=>extractGenericStructural(raw,undefined,'dedicated').fields.generic as Generic;
const cells=(raw:string)=>raw.slice(raw.indexOf(' 1,')+1);
function witness(source:string):GenericStructuralSourceReview{
  const encoder=new TextEncoder();let offset=0;
  return {raw:source,events:source.split('\n').map(line=>{
    const startByte=offset,endByte=offset+encoder.encode(line).byteLength;offset=endByte+1;
    return {startByte,endByte,preview:{status:'SOURCE_PARSED' as const,issues:[]}};
  })};
}
function adopted(source:string){
  const report=analyzeLogEnvelopes(source,'single-line');
  return buildSourceReviewedBoundedDraft(source,createDraft(),witness(source),
    headerlessCsvEvents(report.events),nativelyReadEvents(report.events));
}

describe('PAN-OS THREAT and SYSTEM records get their documented column names',()=>{
  for(const [name,line] of [['with a PRI','<14>'+THREAT],['without a PRI',THREAT]] as const){
    it('THREAT '+name,()=>{
      const read=generic(line);
      expect(read.mode).toBe('panos_threat_csv');
      expect(read.fields).toMatchObject({type:'THREAT',subtype:'url',src:'10.10.20.15',dst:'203.0.113.50',
        natsrc:'203.0.113.10',sport:'51520',dport:'80',natsport:'62002',protocol:'tcp',action:'alert',
        misc:'example.com/index.html',threatid:'(9999)',severity:'informational',direction:'client-to-server',
        contenttype:'text/html',column_40:'0'});
    });
  }
  it('SYSTEM with a PRI',()=>{
    const read=generic('<14>'+SYSTEM);
    expect(read.mode).toBe('panos_system_csv');
    expect(read.fields).toMatchObject({type:'SYSTEM',subtype:'general',vsys:'',eventid:'general',module:'general',
      severity:'informational',opaque:'User admin logged in via Web from 10.1.1.5 using https',seqno:'12345',
      device_name:'PA-FW01',column_10:'0',column_11:'0'});
  });
  it('every cell is kept in order, and a cell after the documented prefix keeps its position as its name',()=>{
    const extra=Array.from({length:20},(_,index)=>'x'+String(42+index));
    const long='<14>'+THREAT+','+extra.join(',');
    const read=generic(long);
    expect(read.mode).toBe('panos_threat_csv');
    expect(Object.keys(read.fields!).length).toBe(62);
    expect(read.fields!.pcap_id).toBe('x42');
    expect(read.fields!.device_name).toBe('x59');
    expect(read.fields!.column_60).toBe('x60');
    expect(read.fields!.column_61).toBe('x61');
    expect(classifyGenericStructural(long,extractGenericStructural(long,undefined,'dedicated')).status).toBe('FULL');
  });
  it('a damaged reading of a named THREAT record is PARTIAL',()=>{
    const raw='<14>'+THREAT;
    const extraction=extractGenericStructural(raw,undefined,'dedicated');
    delete (extraction.fields.generic as Generic).fields!.misc;
    expect(classifyGenericStructural(raw,extraction).status).toBe('PARTIAL');
  });
  it('a record that breaks a documented invariant keeps positional names',()=>{
    for(const raw of [
      '<14>'+THREAT.replace(',informational,',',loud,'),          // severity outside the documented values
      '<14>'+THREAT.replace(',51520,',',70000,'),                 // source port out of range
      '<14>'+SYSTEM.replace(',informational,',',6,'),
    ]){
      expect(generic(raw).mode,raw).not.toMatch(/^panos_(?:threat|system)_csv$/u);
    }
  });
  it('TRAFFIC keeps its own table',()=>{
    expect(generic('<14>'+TRAFFIC).mode).toBe('panos_traffic_csv');
    expect(generic('<14>'+TRAFFIC).fields!.misc).toBeUndefined();
  });
  it('the cells of every named record are the cells of the line',()=>{
    for(const line of [TRAFFIC,THREAT,SYSTEM]){
      const read=generic('<14>'+line);
      expect(Object.values(read.fields!).length).toBe(cells(line).split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/u).length);
    }
  });
});

describe('a sample that mixes PAN-OS record types is adopted with named columns',()=>{
  for(const [name,lines] of [
    ['TRAFFIC + THREAT + SYSTEM without a PRI',[TRAFFIC,THREAT,SYSTEM]],
    ['SYSTEM + THREAT + TRAFFIC with a PRI',['<14>'+SYSTEM,'<14>'+THREAT,'<14>'+TRAFFIC]],
  ] as const){
    it(name,()=>{
      const result=adopted(lines.join('\n'));
      expect(result).not.toBeNull();
      const modes=result!.suite.events.map(event=>(event.fields.generic as Generic).mode);
      expect(modes).toEqual(lines.map(line=>line.includes(',THREAT,')?'panos_threat_csv':
        line.includes(',SYSTEM,')?'panos_system_csv':'panos_traffic_csv'));
      expect(result!.suite.events.every(event=>event.parseStatus==='FULL')).toBe(true);
    });
  }
});
