import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import type {SuiteResult} from '../model';
import {createDraft} from '../model';
import {extractFields} from '../parser';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

const root=resolve('tests/fixtures/docs-practice-20261104');
const fields=(file:string)=>{
  const d=createDraft();
  d.format=file.startsWith('01-')?'syslog_rfc5424':'kv';
  d.syslogBodyFormat='raw';
  return readFileSync(resolve(root,file),'utf8').trimEnd().split('\n').map(log=>{
    const format=file.startsWith('01-')?'syslog_rfc5424':'kv';
    const result=extractFields(log,format,d);
    expect(result.errors).toEqual([]);
    // The reader that produced the event decides which containers hold the pairs of the record.
    return {fields:result.fields,effectiveFormat:format};
  });
};
const suggestions=(file:string)=>suggestNormalizationCandidatesFromSuite(
  {events:fields(file)} as unknown as SuiteResult,[]);
const bySource=(file:string,source:string)=>
  suggestions(file).find(x=>x.source===source);

describe('exact published parser.xdr.ooo practice corpus - Stellar 7.0 semantic oracles',()=>{
  it('does not treat FortiOS seconds and vendor classifications as Stellar names',()=>{
    for(const file of ['04-fortigate-traffic.log','04-fortigate-threat.log',
      '05-relay-original.log','05-relay-holdout-original.log']){
      // policyid: default deny, 2026-11-28 - the policy does not list fw_policy_id (a name does not say that
      // the policy is a firewall policy).
      for(const source of ['type','duration','eventtype','direction','hostname','policyid']){
        expect(bySource(file,source),file+' '+source).toBeUndefined();
      }
      expect(bySource(file,'srcip')).toMatchObject({target:'srcip',confidence:'HIGH'});
      expect(bySource(file,'dstip')).toMatchObject({target:'dstip',confidence:'HIGH'});
      expect(bySource(file,'proto')).toMatchObject({target:'proto',type:'integer',confidence:'HIGH'});
    }
  });

  it('does not turn the UDP session zero-filled icmp-type into a real ICMP event',()=>{
    const result=suggestions('01-juniper-srx.log');
    for(const [source,target] of [
      ['source-address','srcip'],['destination-address','dstip'],
      ['protocol-id','proto'],['policy-name','rule.name'],
    ]){
      expect(result).toEqual(expect.arrayContaining([expect.objectContaining({
        source:'syslog_sd.element_1.params.'+source,target,confidence:'HIGH',
        safeForBulk:true,
      })]));
    }
    expect(result.some(x=>x.source.endsWith('icmp-type'))).toBe(false);
    expect(result.some(x=>x.source.endsWith('nat-source-address'))).toBe(false);
  });

  it('preserves EDR event family, unqualified duration and host name while normalizing its source IP',()=>{
    const result=suggestNormalizationCandidatesFromSuite(
      {events:[{fields:{eventType:'DetectionSummaryEvent',hostname:'EDR01',
        duration:1500,src_ip:'192.0.2.10'}}]} as unknown as SuiteResult,[]);
    expect(result.find(x=>x.source==='eventType')).toBeUndefined();
    expect(result.find(x=>x.source==='duration')).toBeUndefined();
    // Default deny, 2026-11-28: the policy does not list hostname.
    expect(result.find(x=>x.source==='hostname')).toBeUndefined();
    expect(result.find(x=>x.source==='src_ip')).toMatchObject({target:'srcip',confidence:'HIGH'});
  });
});