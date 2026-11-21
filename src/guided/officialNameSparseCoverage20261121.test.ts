import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

function suite(...fields:Record<string,unknown>[]):SuiteResult{
  return {events:fields.map(value=>({fields:value}))} as unknown as SuiteResult;
}
function candidate(target:string,...fields:Record<string,unknown>[]){
  const found=suggestNormalizationCandidatesFromSuite(suite(...fields),[]).filter(item=>item.target===target);
  expect(found.length,'candidates for '+target).toBeLessThanOrEqual(1);
  return found[0];
}
const traffic={srcip:'10.1.10.25',dstip:'142.250.196.14',srcport:51544,dstport:443,proto:6,action:'accept'};
const web={srcip:'10.1.10.31',dstip:'198.51.100.80',srcport:50211,dstport:80,proto:6,url:'http://bad.example.net/a'};
const system={srcip:'10.1.10.2',dstip:'10.1.10.1',logdesc:'Admin login successful'};

describe('a source named as its official Stellar field in a sample of several record families',()=>{
  it('is approved although some record families do not carry it',()=>{
    for(const target of ['srcport','dstport','url','proto'])
      expect(candidate(target,traffic,web,system),target).toMatchObject({source:target,confidence:'HIGH',safeForBulk:true});
    expect(candidate('url',traffic,web,system)).toMatchObject({observed:1,total:3});
  });

  it('is approved inside a container as well (generic.kv.dstport)',()=>{
    const wrap=(kv:Record<string,unknown>)=>({generic:{kv}});
    expect(candidate('dstport',wrap(traffic),wrap(web),wrap(system)))
      .toMatchObject({source:'generic.kv.dstport',confidence:'HIGH',safeForBulk:true});
  });

  it('stays a review proposal when one of its values does not fit the field',()=>{
    expect(candidate('dstport',traffic,{...web,dstport:'http'},system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('dstport',traffic,{...web,dstport:70000},system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  });

  it('never approves a port beside a protocol that is not TCP or UDP',()=>{
    const icmp={srcip:'10.1.10.9',dstip:'10.1.10.1',srcport:8,dstport:0,proto:1};
    expect(candidate('srcport',traffic,icmp,system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('dstport',traffic,icmp,system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  });

  it('never approves a translated port whatever its coverage',()=>{
    expect(candidate('srcport',{nat:{srcport:40000},proto:6},system)).toBeUndefined();
  });

  it('keeps a reviewed abbreviation a review proposal when a record family lacks it',()=>{
    const abbreviated={src:'10.1.10.25',dst:'142.250.196.14',dpt:443,spt:51544,proto:6};
    for(const target of ['srcip','dstip','srcport','dstport'])
      expect(candidate(target,abbreviated,{logdesc:'Admin login successful'}),target)
        .toMatchObject({confidence:'REVIEW',safeForBulk:false});
    // Present in every event, the same abbreviations are approved as before.
    for(const target of ['srcip','dstip','srcport','dstport'])
      expect(candidate(target,abbreviated,{...abbreviated,src:'10.1.10.26'}),target).toMatchObject({confidence:'HIGH'});
  });
});

describe('Zeek conn.log endpoint columns',()=>{
  const conn=(overrides:Record<string,unknown>={})=>({ts:1731719701.123456,uid:'CHhAvVGS1DHFjwGM9',
    'id.orig_h':'10.1.10.25','id.orig_p':51544,'id.resp_h':'142.250.196.14','id.resp_p':443,proto:'tcp',
    service:'ssl',conn_state:'SF',...overrides});

  it('maps originator and responder to source and destination',()=>{
    const events=[conn(),conn({'id.orig_h':'203.0.113.77','id.orig_p':40022,'id.resp_h':'10.1.10.9','id.resp_p':22,proto:'udp'})];
    expect(candidate('srcip',...events)).toMatchObject({source:'id.orig_h',confidence:'HIGH'});
    expect(candidate('dstip',...events)).toMatchObject({source:'id.resp_h',confidence:'HIGH'});
    expect(candidate('srcport',...events)).toMatchObject({source:'id.orig_p',confidence:'HIGH'});
    expect(candidate('dstport',...events)).toMatchObject({source:'id.resp_p',confidence:'HIGH'});
  });

  it('does not take the ICMP type and code columns for ports',()=>{
    const events=[conn(),conn({proto:'icmp','id.orig_p':8,'id.resp_p':0})];
    expect(candidate('srcport',...events)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('dstport',...events)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('srcip',...events)).toMatchObject({confidence:'HIGH'});
  });
});

describe('a source field called proto',()=>{
  it('is the protocol name when it holds documented protocol names',()=>{
    expect(candidate('proto_name',{proto:'tcp'},{proto:'UDP'})).toMatchObject({source:'proto',confidence:'HIGH'});
    expect(candidate('proto',{proto:'tcp'},{proto:'UDP'})).toBeUndefined();
  });
  it('is the protocol number when it holds numbers',()=>{
    expect(candidate('proto',{proto:6},{proto:'17'})).toMatchObject({source:'proto',confidence:'HIGH'});
    expect(candidate('proto_name',{proto:6},{proto:'17'})).toBeUndefined();
  });
  it('is neither when it holds an application label or a mix',()=>{
    expect(candidate('proto',{proto:'https'},{proto:'ssh'})).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('proto_name',{proto:'https'},{proto:'ssh'})).toBeUndefined();
    expect(candidate('proto',{proto:'tcp'},{proto:6})).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  });
});

describe('official names whose meaning differs between vendors keep the full-coverage rule',()=>{
  it('does not approve a sparse severity, type-like or hash field by its name alone',()=>{
    const alarm={srcip:'10.0.1.2',dstip:'81.2.69.192',severity:4,md5:'69630e4574ec6798239b091cda43dca0',path:'/eicar.com.txt'};
    const flow={srcip:'10.0.1.3',dstip:'81.2.69.193'};
    for(const target of ['severity','md5','path']){
      const found=candidate(target,alarm,flow);
      if(found)expect(found,target).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    }
  });
});

describe('Junos structured data read with underscore names',()=>{
  const flow=(overrides:Record<string,unknown>={})=>({junos_sd:{source_address:'10.0.0.1',source_port:'37233',
    destination_address:'67.43.156.13',destination_port:'161',protocol_id:'17',icmp_type:'0',...overrides}});
  it('maps the addresses and the protocol number like the hyphenated spelling',()=>{
    const events=[flow(),flow({source_address:'10.0.0.2',protocol_id:'6'})];
    expect(candidate('srcip',...events)).toMatchObject({source:'junos_sd.source_address',confidence:'HIGH'});
    expect(candidate('dstip',...events)).toMatchObject({source:'junos_sd.destination_address',confidence:'HIGH'});
    expect(candidate('proto',...events)).toMatchObject({source:'junos_sd.protocol_id',confidence:'HIGH'});
  });
  it('does not take a zero-filled icmp_type of a TCP or UDP session for an ICMP type',()=>{
    expect(candidate('icmp_type',flow(),flow({protocol_id:'6'}))).toBeUndefined();
    // On ICMP sessions the same field is the ICMP type.
    expect(candidate('icmp_type',flow({protocol_id:'1',icmp_type:'8'}),flow({protocol_id:'1',icmp_type:'0'})))
      .toMatchObject({source:'junos_sd.icmp_type',confidence:'HIGH'});
  });
});
