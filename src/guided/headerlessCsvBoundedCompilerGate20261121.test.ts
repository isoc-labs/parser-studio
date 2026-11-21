import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {buildSourceReviewedGenericStructuralDraft,buildSourceReviewedNamedPositionalDraft,
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
const PAN='Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,7000000001,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,tcp-fin,0,0,0,0,,PA-FW01,from-policy';

describe('a headerless positional CSV sample and the bounded compiler (independent audit 2026-11-21, F1 and F2)',()=>{
  it('adopts a PAN-OS TRAFFIC record without a PRI: its columns are named from the record layout',()=>{
    const adopted=buildSourceReviewedNamedPositionalDraft(PAN,createDraft(),parsedWitness(PAN));
    expect(adopted).not.toBeNull();
    expect(adopted!.suite.events.map(event=>(event.fields.generic as {mode:string}).mode)).toEqual(['panos_traffic_csv']);
    expect(adopted!.draft.mappings.find(mapping=>mapping.source==='generic.fields.src')?.target).toBe('srcip');
  });

  // The compiler can read each of these lines, but only by moving the cell boundaries of the CSV reading.
  const MISREAD:Record<string,string>={
    'first cell starts like a BSD timestamp (the Syslog host would take the next cells)':
      'Nov 21 10:00:00 2026,fw1,Web Filter,allow,10.0.0.1,10.0.0.2,51234,443,tcp,eth0,eth1,100,200,ok,x,y\n'+
      'Nov 21 10:00:01 2026,fw1,Web Filter,deny,10.0.0.3,10.0.0.4,51235,80,tcp,eth0,eth1,60,0,blocked,x,y',
    'host followed by a comma':
      'Nov 21 10:00:00 fw1,allow,web browsing,10.0.0.1,10.0.0.2,51234,443,tcp,eth0,eth1,100,200,ok,x,y,z',
    'one cell holds key=value pairs (the last value would take the following cells)':
      '2026-11-21 10:00:00,web01,request user=bob src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok\n'+
      '2026-11-21 10:00:01,web01,request user=amy src=10.0.0.6 method=POST status=403 url=/admin,10.0.0.9,8443,denied',
    'a PAN-OS THREAT record without a PRI (no verified column names)':
      'Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,THREAT,url,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,80,45001,80,0x400000,tcp,alert,"example.com/a",(9999),any,informational,client-to-server',
  };
  for(const [name,source] of Object.entries(MISREAD)){
    it('keeps the CSV column review: '+name,()=>{
      expect(buildSourceReviewedNamedPositionalDraft(source,createDraft(),parsedWitness(source))).toBeNull();
    });
  }

  it('the general route used for unsupported events is unchanged by the stricter headerless route',()=>{
    const wrapped='<14>'+PAN;
    expect(buildSourceReviewedGenericStructuralDraft(wrapped,createDraft(),parsedWitness(wrapped))).not.toBeNull();
  });
});
