import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { preview } from '../parser';
import { defaultGuidedOptions } from './contract';
import { suggestClassification } from './classify';

describe('explainable local classification suggestions', () => {
  it('routes preview extracted event fields with transparent first-match priority', () => {
    const draft = createDraft();
    const events = preview('{"action":"allow"}\naction=deny\n{"action":"other"}', draft).events;
    const options = defaultGuidedOptions();
    expect(suggestClassification(events[0], options)).toMatchObject({ index: 'Session', rule: 1, status: 'matched' });
    expect(suggestClassification(events[1], options)).toMatchObject({ index: 'Threat', rule: 0, status: 'matched' });
    expect(suggestClassification(events[2], options)).toMatchObject({ index: 'Syslog', rule: null, status: 'fallback' });
  });

  it('never assigns a green classification when extracting a log has failed', () => {
    const events = preview('not recognizable', createDraft()).events;
    expect(suggestClassification(events[0], defaultGuidedOptions())).toMatchObject({ index: null, status: 'unresolved' });
  });

  it('supports nested JSON own-key path conditions but does not inspect object prototypes', () => {
    const draft = createDraft();
    const event = preview('{"session":{"outcome":"deny"}}', draft).events[0];
    const options = defaultGuidedOptions();
    options.classification.rules = [{ id: 'nested', sourceField: 'session.outcome', equals: 'deny', index: 'Threat' }];
    expect(suggestClassification(event, options).index).toBe('Threat');
    options.classification.rules = [{ id: 'proto', sourceField: 'constructor', equals: '[object Object]', index: 'Threat' }];
    expect(suggestClassification(event, options).status).toBe('fallback');
  });

  it('matches an exact dotted KV source field before attempting nested JSON traversal', () => {
    const draft=createDraft();
    draft.format='kv';
    const event=preview('event.action=deny src_ip=198.51.100.10', draft).events[0];
    expect(event.fields['event.action']).toBe('deny');
    const options=defaultGuidedOptions();
    options.classification.rules = [
      {id:'flat-dot',sourceField:'event.action',equals:'deny',index:'Threat'},
    ];
    expect(suggestClassification(event,options)).toMatchObject({
      index:'Threat',rule:0,status:'matched',
    });
  });

  it('has case-sensitive exact conditions, never claiming native routing success', () => {
    const event = preview('{"action":"DENY"}', createDraft()).events[0];
    const result = suggestClassification(event, defaultGuidedOptions());
    expect(result.status).toBe('fallback');
    expect(result.reason).toContain('default event');
  });

  // Independent audit of 2026-11-15: the generated parser classifies on the manufacturer field when the
  // source is mapped only there (backendAdapter: "a vendor-only source may classify using Vendor.field"); the
  // browser hint fell back to the default category for the same project and event.
  it('classifies on a field that is mapped only to the manufacturer namespace, as the generated parser does', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.vendor = 'Acme';
    draft.mappings = [{ id: 'm1', source: 'action', target: 'act', type: 'string' }];
    const options = defaultGuidedOptions();
    options.groups = { m1: 'vendor_fields' };
    options.classification.rules = [{ id: 'r1', sourceField: 'action', equals: 'deny', index: 'Threat' }];
    const [deny, allow] = preview('{"action":"deny"}\n{"action":"allow"}', draft).events;
    expect((deny!.normalized.Acme as Record<string, unknown>).act).toBe('deny');
    expect(suggestClassification(deny!, options, draft)).toMatchObject({ index: 'Threat', rule: 0, status: 'matched' });
    expect(suggestClassification(allow!, options, draft)).toMatchObject({ status: 'fallback' });
    // Two manufacturer destinations of one source decide nothing (the export reports the rule as ambiguous).
    draft.mappings.push({ id: 'm2', source: 'action', target: 'act2', type: 'string' });
    options.groups = { m1: 'vendor_fields', m2: 'vendor_fields' };
    expect(suggestClassification(preview('{"action":"deny"}', draft).events[0]!, options, draft)).toMatchObject({ status: 'fallback' });
  });

  // Independent re-audit of 2026-11-15: the generated parser classifies an event only after extraction, mapping
  // and enrichment have succeeded; an event with a mapped-field error is a diagnostic record there, in no
  // category. The browser hint said "Condition Matched" for the same event.
  it('does not classify an event whose mapped field has an error, as the generated parser does not', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings = [
      { id: 'm1', source: 'dpt', target: 'dstport', type: 'port' },
      { id: 'm2', source: 'act', target: 'action', type: 'string' },
    ];
    const options = defaultGuidedOptions();
    options.groups = { m1: 'top_fields', m2: 'top_fields' };
    options.classification.rules = [{ id: 'r1', sourceField: 'act', equals: 'deny', index: 'Threat' }];
    draft.guided = options;
    const [good, bad] = preview('{"dpt":443,"act":"deny"}\n{"dpt":70000,"act":"deny"}', draft).events;
    expect(suggestClassification(good!, options, draft)).toMatchObject({ index: 'Threat', rule: 0, status: 'matched' });
    expect(bad!.diagnostics.some(issue => issue.severity === 'error' && issue.code === 'TYPE_ERROR')).toBe(true);
    expect(suggestClassification(bad!, options, draft)).toMatchObject({ index: null, rule: null, status: 'unresolved' });
  });

  // The export refuses a classification path it cannot address (CLASSIFICATION_FIELD_PATH_UNSUPPORTED); the hint
  // must not promise a category that no generated parser will assign.
  it('does not match on a manufacturer field whose path the export refuses', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.vendor = 'Acme Corp';
    draft.mappings = [{ id: 'm1', source: 'action', target: 'act', type: 'string' }];
    const options = defaultGuidedOptions();
    options.groups = { m1: 'vendor_fields' };
    options.classification.rules = [{ id: 'r1', sourceField: 'action', equals: 'deny', index: 'Threat' }];
    const event = preview('{"action":"deny"}', draft).events[0]!;
    expect(suggestClassification(event, options, draft)).toMatchObject({ status: 'fallback' });
  });
});
