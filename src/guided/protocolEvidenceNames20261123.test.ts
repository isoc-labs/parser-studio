import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

// Independent audit 2026-11-22, G-13. An ICMP record whose protocol is written as "protocol.name", "flow.l4.proto"
// or "ip_protocol" must not let its pseudo-ports become official Layer 4 ports (a wrong srcport/dstport mapping),
// and a TCP protocol object with a member that is not the protocol (flags) still says TCP.
function port(...fields:Record<string,unknown>[]){
  const read={events:fields.map(value=>({fields:value,effectiveFormat:'json'}))} as unknown as SuiteResult;
  return suggestNormalizationCandidatesFromSuite(read,[]).filter(item=>item.target==='srcport')[0];
}
const tcp={src_ip:'10.0.0.1',dst_ip:'10.0.0.2',sport:51234,dport:443,protocol:'tcp'};

describe('protocol evidence written in other common ways (G-13)',()=>{
  it.each([
    ['a literal dotted key protocol.name',{'protocol.name':'icmp'}],
    ['a dotted key flow.l4.proto',{'flow.l4.proto':'icmp'}],
    ['ip_protocol',{ip_protocol:'icmp'}],
    ['ECS network.transport',{network:{transport:'icmp'}}],
  ])('an ICMP record with %s keeps the ports in review',(_name,evidence)=>{
    const icmp={src_ip:'10.0.0.3',dst_ip:'8.8.8.8',sport:8,dport:0,...evidence};
    expect(port(tcp,icmp)).toMatchObject({source:'sport',confidence:'REVIEW'});
  });
  it('a TCP protocol object with a flags member still says TCP',()=>{
    const flagged={src_ip:'10.0.0.1',dst_ip:'10.0.0.2',sport:51235,dport:443,protocol:{name:'tcp',number:6,flags:'SYN'}};
    expect(port(flagged,flagged)).toMatchObject({source:'sport',confidence:'HIGH'});
  });
  // Re-audit A1: ECS network.protocol is the application protocol (http, dns, tls), not the IP protocol.
  it.each([
    ['nested',{network:{transport:'tcp',protocol:'http'}}],
    ['flat keys',{'network.transport':'tcp','network.protocol':'http'}],
    ['udp dns',{network:{transport:'udp',protocol:'dns'}}],
  ])('an ECS record with an application protocol keeps its TCP/UDP ports approved (%s)',(_name,network)=>{
    const ecs={source:{ip:'10.0.0.1',port:51234},destination:{ip:'10.0.0.2',port:443},...network};
    const read={events:[{fields:ecs,effectiveFormat:'json'}]} as unknown as SuiteResult;
    const found=suggestNormalizationCandidatesFromSuite(read,[]).filter(item=>item.target==='srcport'||item.target==='dstport');
    expect(found.map(item=>[item.source,item.confidence])).toEqual([['source.port','HIGH'],['destination.port','HIGH']]);
  });
});
