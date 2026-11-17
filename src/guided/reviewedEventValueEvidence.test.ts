import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planReviewedEventFamilyDraft} from './reviewedEventFamilyDraft';
import {inspectReviewedEventValues} from './reviewedEventValueEvidence';

const source=[
  '{"event_type":"threat","confidence":"high","action":"deny"}',
  '{"event_type":"user","username":"김민수","action":"login"}',
].join('\n');

describe('reviewed event-family typed sample evidence',()=>{
  const candidate=()=>{
    const draft={...createDraft(),format:'json' as const};
    const planned=planReviewedEventFamilyDraft(preview(source,draft),draft,'event_type');
    if(!planned.ok)throw Error(planned.reason);
    return {draft:planned.candidate,suite:preview(source,draft)};
  };
  it('rejects incompatible user-selected type before a downloadable DRAFT is approved',()=>{
    const {draft,suite}=candidate();
    const profile=draft.eventProfiles!.variants.find(x=>x.name==='threat')!;
    const field=profile.mappings.find(x=>x.source==='confidence')!;
    field.type='integer';
    const evidence=inspectReviewedEventValues(suite,draft);
    expect(evidence.ok).toBe(false);
    if(!evidence.ok){
      expect(evidence.reason).toContain('confidence');
      expect(evidence.reason).toContain('integer');
      expect(evidence.reason).not.toContain('high');
    }
    field.type='string';
    expect(inspectReviewedEventValues(suite,draft)).toEqual({ok:true,skipped:0});
  });
  it('retains optional and ignored values without fabricating normalized fields',()=>{
    const draft={...createDraft(),format:'json' as const};
    const sample=[
      '{"event_type":"threat","confidence":"","action":"deny"}',
      '{"event_type":"threat","action":"allow"}',
      '{"event_type":"user","username":"山田","action":"login"}',
    ].join('\n');
    const suite=preview(sample,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    expect(plan.ok).toBe(true);
    if(!plan.ok)return;
    const evidence=inspectReviewedEventValues(suite,plan.candidate);
    expect(evidence.ok).toBe(true);
    if(evidence.ok)expect(evidence.skipped).toBeGreaterThan(0);
    expect(suite.events.map(x=>x.raw)).toEqual(sample.split('\n'));
  });
  it('never accepts a missing family discriminator or partially parsed event',()=>{
    const {draft,suite}=candidate();
    suite.events[1]!.fields={action:'login'};
    expect(inspectReviewedEventValues(suite,draft).ok).toBe(false);
  });
  it('skips a blank-only typed value as the run time does',()=>{
    // Audit of 2026-11-17 (F2): the run time skips a blank-only value; this review still stopped at it.
    const draft={...createDraft(),format:'json' as const};
    const sample=[
      '{"event_type":"threat","srcip":"203.0.113.9","action":"deny"}',
      '{"event_type":"threat","srcip":" ","action":"allow"}',
      '{"event_type":"user","username":"alice","action":"login"}',
    ].join('\n');
    const suite=preview(sample,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    expect(plan.ok).toBe(true);
    if(!plan.ok)return;
    const mapping=plan.candidate.eventProfiles!.variants.find(x=>x.name==='threat')!.mappings.find(x=>x.source==='srcip')!;
    // The user maps the field to the official srcip, typed ip.
    mapping.target='srcip';mapping.type='ip';plan.candidate.guided!.groups[mapping.id]='top_fields';
    const evidence=inspectReviewedEventValues(suite,plan.candidate);
    expect(evidence.ok?'':evidence.reason).toBe('');
    if(evidence.ok)expect(evidence.skipped).toBeGreaterThan(0);
  });
});
