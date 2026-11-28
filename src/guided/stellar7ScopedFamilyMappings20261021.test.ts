import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planReviewedEventFamilyDraft} from './reviewedEventFamilyDraft';
import {proposeStellar7FamilyMappings,applyStellar7FamilyMapping} from './stellar7ScopedFamilyMappings';
import {toBackendProject} from './backendAdapter';
import {inspectReviewedEventValues} from './reviewedEventValueEvidence';

const threatHash='a'.repeat(64);
const raw=[
  {event_type:'threat',src_ip:'192.0.2.11',action:'deny',sha256:threatHash,request_status:403},
  {event_type:'threat',src_ip:'192.0.2.12',action:'block',sha256:threatHash,request_status:404},
  {event_type:'user',username:'김민수',login_result:'failure',host:{ip:'198.51.100.5'}},
  {event_type:'user',username:'山田',login_result:'success',host:{ip:'198.51.100.6'}},
  {event_type:'asset',host:{name:'asset-01'},process:{name:'agent.exe'},rule:{name:'inventory-a'}},
  {event_type:'asset',host:{name:'asset-02'},process:{name:'agent2.exe'},rule:{name:'inventory-b'}},
].map(record=>JSON.stringify(record)).join('\n');
const base=()=>({...createDraft(),format:'json' as const,mappings:[]});

describe('fixed Stellar 7.0 evidence is scoped to explicitly reviewed event-family routes',()=>{
  it('suggests only type-compatible, whole-family mappings without leaking synthetic field values',()=>{
    const draft=base(),suite=preview(raw,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    expect(plan.ok).toBe(true);
    if(!plan.ok)return;
    const candidates=proposeStellar7FamilyMappings(suite,plan.candidate);
    expect(candidates).toContainEqual(expect.objectContaining({
      family:'threat',source:'src_ip',target:'srcip',confidence:'HIGH',
      total:2,observed:2,group:'top_fields',catalogRelease:'7.0.xs',
    }));
    expect(candidates).toContainEqual(expect.objectContaining({
      family:'user',source:'username',target:'username',confidence:'HIGH',
    }));
    expect(candidates).toContainEqual(expect.objectContaining({
      family:'asset',source:'rule.name',target:'rule.name',
      group:'ns_fields',confidence:'HIGH',
    }));
    expect(candidates.some(candidate=>candidate.source==='request_status')).toBe(false);
    // Default deny, 2026-11-28: a name the policy does not list is not proposed inside a family either.
    expect(candidates.filter(candidate=>['sha256','login_result','host.ip','host.name','process.name']
      .includes(candidate.source))).toEqual([]);
    expect(JSON.stringify(candidates)).not.toContain('김민수');
    expect(JSON.stringify(candidates)).not.toContain('192.0.2.11');
    expect(draft.eventProfiles).toBeUndefined();
  });

  it('applies only reviewed high-confidence per-family destinations, preserving conditional isolation and source',()=>{
    const draft=base(),suite=preview(raw,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const original=structuredClone(plan.candidate),originalRaw=suite.events.map(e=>e.raw);
    let reviewed=plan.candidate;
    const proposals=proposeStellar7FamilyMappings(suite,reviewed);
    const allow=[
      ['threat','src_ip'],['threat','action'],
      ['user','username'],
      ['asset','rule.name'],
    ];
    for(const [family,source] of allow){
      const suggestion=proposals.find(item=>item.family===family&&item.source===source);
      if(!suggestion)throw Error('Missing reviewed 7.0 suggestion '+family+':'+source);
      expect(suggestion.confidence).toBe('HIGH');
      const applied=applyStellar7FamilyMapping(reviewed,suggestion,suite);
      expect(applied.ok).toBe(true);
      if(applied.ok)reviewed=applied.draft;
    }
    expect(toBackendProject(reviewed).ok).toBe(true);
    expect(inspectReviewedEventValues(suite,reviewed)).toMatchObject({ok:true});
    const compiled=toBackendProject(reviewed);
    if(!compiled.ok)throw Error(JSON.stringify(compiled.issues));
    const vars=compiled.project.normalization.eventProfiles?.variants??[];
    expect(vars.find(v=>v.name==='threat')?.topFields.src_ip)
      .toMatchObject({normalized_name:'srcip',data_type:'ip'});
    expect(vars.find(v=>v.name==='asset')?.nsFields['rule.name'])
      .toMatchObject({normalized_name:'rule.name',data_type:'string'});
    const result=preview(raw,reviewed);
    const goldens=[
      {srcip:'192.0.2.11',action:'deny'},
      {srcip:'192.0.2.12',action:'block'},
      {username:'김민수'},
      {username:'山田'},
      {rule:{name:'inventory-a'}},
      {rule:{name:'inventory-b'}},
    ];
    // The fields the policy does not list keep their values in the output of their event.
    const kept=[threatHash,threatHash,'198.51.100.5','198.51.100.6','asset-01','agent2.exe'];
    for(const [i,value] of kept.entries())expect(JSON.stringify(result.events[i]?.normalized)).toContain(value);
    let matchedOfficialFields=0;
    for(const [i,expected] of goldens.entries()){
      expect(result.events[i]?.normalized).toMatchObject(expected);
      for(const [target,expectedValue] of Object.entries(expected)){
        expect(result.events[i]?.normalized[target]).toEqual(expectedValue);
        matchedOfficialFields++;
      }
    }
    // Six manually-authored synthetic event goldens, 8 exact value matches (16 before default deny, when the
    // hash, the login result, the host and the process were written from their names).
    // This is fixture coverage, not independent manufacturer accuracy.
    expect(matchedOfficialFields).toBe(8);
    expect(result.events.map(e=>e.raw)).toEqual(originalRaw);
    expect(plan.candidate).toEqual(original);
    expect(reviewed.eventProfiles?.unknown).toBe('reject');
  });

  it('never upgrades ambiguous, incomplete or invalid evidence within a single family',()=>{
    const records=[
      {event_type:'threat',src_ip:'192.0.2.7',source_ip:'192.0.2.8',sha256:'a'.repeat(32)},
      {event_type:'threat',src_ip:'192.0.2.9',source_ip:'192.0.2.10'},
      {event_type:'user',username:'alice',action:'login'},
      {event_type:'user',username:'bob',action:'logout'},
    ];
    const draft=base(),suite=preview(records.map(record=>JSON.stringify(record)).join('\n'),draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const candidates=proposeStellar7FamilyMappings(suite,plan.candidate);
    for(const source of ['src_ip','source_ip']){
      const ambiguous=candidates.find(c=>c.family==='threat'&&c.source===source);
      expect(ambiguous).toMatchObject({confidence:'REVIEW',safeForBulk:false});
      expect(applyStellar7FamilyMapping(plan.candidate,ambiguous!,suite)).toMatchObject({ok:false});
    }
    // Not a listed field: not proposed at all (it was a review proposal).
    expect(candidates.find(c=>c.family==='threat'&&c.source==='sha256')).toBeUndefined();
    expect(candidates.some(c=>c.family==='threat'&&c.confidence==='HIGH'&&c.target==='srcip')).toBe(false);
    expect(candidates.find(c=>c.family==='user'&&c.source==='username')).toMatchObject({confidence:'HIGH'});
  });

  it('refuses stale/forged evidence and never overwrites a manually reviewed mapping',()=>{
    const draft=base(),suite=preview(raw,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const candidate=proposeStellar7FamilyMappings(suite,plan.candidate)
      .find(item=>item.family==='threat'&&item.source==='src_ip');
    if(!candidate)throw Error('Missing initial 7.0 source-backed candidate');
    expect(candidate).toMatchObject({confidence:'HIGH',safeForBulk:true});
    expect(applyStellar7FamilyMapping(plan.candidate,candidate,undefined))
      .toMatchObject({ok:false});
    expect(applyStellar7FamilyMapping(plan.candidate,{
      ...candidate,target:'dstip',
    },suite)).toMatchObject({ok:false});
    const changed=preview(raw.replace('192.0.2.11','invalid-ip'),draft);
    expect(applyStellar7FamilyMapping(plan.candidate,candidate,changed))
      .toMatchObject({ok:false});
    const manual=structuredClone(plan.candidate);
    const threat=manual.eventProfiles!.variants.find(item=>item.name==='threat')!;
    const selected=threat.mappings.find(item=>item.source==='src_ip')!;
    selected.target='custom.manual_author_choice';
    expect(proposeStellar7FamilyMappings(suite,manual).some(item=>
      item.family==='threat'&&item.source==='src_ip')).toBe(false);
    expect(applyStellar7FamilyMapping(manual,candidate,suite))
      .toMatchObject({ok:false});
    expect(selected.target).toBe('custom.manual_author_choice');
  });

});
