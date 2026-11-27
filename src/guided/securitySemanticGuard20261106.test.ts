import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import {STELLAR_METADATA_CATALOG} from './stellarMetadataCatalog';
import policy from '../../runtime/multipass/semantic-policy.v1.json';

const candidates=(...fields:Record<string,unknown>[])=>suggestNormalizationCandidatesFromSuite(
  {events:fields.map(value=>({fields:value}))} as unknown as SuiteResult,[],
);
const official=(...fields:Record<string,unknown>[])=>candidates(...fields)
  .filter(candidate=>candidate.confidence==='HIGH'&&candidate.safeForBulk)
  .map(candidate=>[candidate.source,candidate.target]);

describe('cross-vendor Stellar 7.0 semantic false-friend oracle, 2026-11-06',()=>{
  it('preserves Fortinet traffic session-close as vendor action without losing valid L4 fields',()=>{
    const fields={logid:'0000000013',type:'traffic',vd:'vdom1',proto:'6',
      srcip:'10.1.100.11',srcport:'58012',dstip:'23.59.154.35',dstport:'80',
      action:'close',utmaction:'allow',policyid:1,duration:116};
    const mapped=official(fields);
    expect(mapped).not.toContainEqual(['action','action']);
    for(const pair of [['srcip','srcip'],['dstip','dstip'],['srcport','srcport'],
      ['dstport','dstport'],['proto','proto'],['policyid','fw_policy_id']]){
      expect(mapped).toContainEqual(pair);
    }
  });
  it('keeps admin-login and VPN-negotiation actions vendor scoped, but accepts blocking actions',()=>{
    for(const action of ['login','negotiate','close','Detection','user.session.start']){
      expect(official({action,srcip:'192.0.2.1'})).not.toContainEqual(['action','action']);
    }
    for(const action of ['allow','allowed','block','blocked','deny','denied','drop','dropped',
      'accept','permitted','reject','quarantine']){
      expect(official({action})).toContainEqual(['action','action']);
    }
  });
  it('does not relabel AWS identity type or WatchGuard ICMP type as a Windows-agent field',()=>{
    expect(official({userIdentity:{type:'IAMUser',userName:'John'},
      eventTime:'2014-07-16T15:49:27Z',sourceIPAddress:'192.0.2.110'}))
      .not.toContainEqual(['userIdentity.type','type']);
    expect(official({parserstudio_source:{generic:{kv:{type:'8',duration:'0'}}}}))
      .not.toContainEqual(['parserstudio_source.generic.kv.type','type']);
    expect(official({type:'event',subtype:'system',action:'login'}))
      .not.toContainEqual(['type','type']);
  });
  it('does not call Suricata or Okta event families Stellar ML event_type',()=>{
    expect(official({event_type:'alert',src_ip:'192.0.2.10'}))
      .not.toContainEqual(['event_type','event_type']);
    expect(official({eventType:'user.session.start',client:{ipAddress:'192.0.2.44'}}))
      .not.toContainEqual(['eventType','event_type']);
  });
  it('does not silently treat vendor duration as milliseconds, but supports explicit ms units',()=>{
    expect(official({parserstudio_source:{generic:{kv:{duration:'14'}}}}))
      .not.toContainEqual(['parserstudio_source.generic.kv.duration','duration']);
    expect(official({duration:116})).not.toContainEqual(['duration','duration']);
    expect(official({duration_ms:14000})).toContainEqual(['duration_ms','duration']);
  });
  it('does not relabel Suricata IDS signature severity into Stellar security severity',()=>{
    const src={event_type:'alert',src_ip:'192.0.2.10',
      alert:{action:'allowed',signature_id:2018358,severity:2}};
    expect(official(src)).not.toContainEqual(['alert.severity','severity']);
    expect(official(src)).toContainEqual(['src_ip','srcip']);
    expect(official(src)).toContainEqual(['alert.action','action']);
  });
  // The 7.0 dictionary defines severity, fidelity and threat_score on a 0-100 scale where a higher value means more.
  // Syslog levels (0-7, 0 the most severe), IDS priorities (1-4) and CEF or CVSS scores (0-10) all lie inside that
  // range, so a matching name and a value in range do not show which scale a source uses.
  it('accepts a 0-100 score field only when the sample itself shows that scale',()=>{
    // The level digit of a Cisco ASA/FTD tag such as %ASA-6-302013, under the name the ASA reader gives it.
    const levels=[{asa:{severity:'6',src_ip:'10.0.0.1'}},{asa:{severity:'4',src_ip:'10.0.0.2'}}];
    expect(official(...levels)).not.toContainEqual(['asa.severity','severity']);
    expect(official(...levels)).toContainEqual(['asa.src_ip','srcip']);
    // No vendor or reader is named by the rule: the same values under any path, and every 0-100 target.
    expect(official({severity:3},{severity:7})).not.toContainEqual(['severity','severity']);
    expect(official({event:{severity:10}})).not.toContainEqual(['event.severity','severity']);
    expect(official({syslog:{severity:5}})).not.toContainEqual(['syslog.severity','severity']);
    expect(official({fidelity:3,threat_score:4})).toEqual([]);
    // A sample that shows the 0-100 scale keeps the direct official mapping.
    expect(official({severity:25},{severity:60})).toContainEqual(['severity','severity']);
    expect(official({severity:5},{severity:60})).toContainEqual(['severity','severity']);
    expect(official({fidelity:90,threat_score:80})).toEqual([['fidelity','fidelity'],['threat_score','threat_score']]);
  });
  it('does not offer the unproven score field as a recommendation; a qualitative severity is still shown for review',()=>{
    expect(candidates({asa:{severity:'6'}}).map(candidate=>candidate.source)).not.toContain('asa.severity');
    expect(candidates({severity:'high'},{severity:'low'}).map(candidate=>[candidate.source,candidate.confidence]))
      .toEqual([['severity','REVIEW']]);
  });
  it('names every catalog field that the 7.0 dictionary documents on the 0-100 scale',()=>{
    const documented=STELLAR_METADATA_CATALOG.filter(entry=>entry.mappable&&
      entry.descriptions.some(text=>text.includes('0–100'))).map(entry=>entry.name).sort();
    expect([...policy.scoreScaleEvidence.targets].sort()).toEqual(documented);
    expect(documented).toEqual(['fidelity','severity','threat_score']);
  });
  // A translated (NAT) address is not the original endpoint of the session. The exclusion that already keeps
  // translated ports out of srcport/dstport holds for the whole network tuple.
  it('never takes a translated address for the original endpoint',()=>{
    expect(official({nat:{srcip:'203.0.113.7'},dstip:'198.51.100.2'})).toEqual([['dstip','dstip']]);
    expect(official({snat_src_ip:'203.0.113.7'},{snat_src_ip:'203.0.113.8'})).toEqual([]);
    const both={srcip:'10.0.0.1',translated:{srcip:'203.0.113.7'},dstip:'198.51.100.2',postNat:{dstip:'192.0.2.9'}};
    expect(official(both)).toEqual([['srcip','srcip'],['dstip','dstip']]);
    // Names that merely contain the letters are not translated addresses.
    expect(official({national:{src_ip:'10.0.0.1'}})).toContainEqual(['national.src_ip','srcip']);
  });
});
