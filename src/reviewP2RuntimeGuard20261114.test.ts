/**
 * PR #311 review, two P2 findings on the Parsing Success Contract (W7), browser side.
 *  1. The header-misread check must apply to what the RFC 3164 grammar read as the host name, not to any
 *     field that happens to be called syslog_hostname (JSON, key=value, CSV, regex results).
 *  2. RFC 5424 STRUCTURED-DATA is not key=value text: an SD-PARAM is stored under its own (encoded) name
 *     and must not be demanded as a key=value field. Pair accounting is for the MSG.
 * The generated Ruby is held to the same cases in backend/test/runtime-field-loss-guard.test.ts.
 */
import { describe, expect, it } from 'vitest';
import { preview } from './parser';
import { createDraft, type ParserDraft } from './model';
import { classifyStructuredParse, independentKeyValuePairs } from './grammar/parseStatus';
import { extractStructuredFamily } from './structuredFamilies';

const draft = (patch: Partial<ParserDraft>): ParserDraft => ({ ...createDraft(), ...patch });
const SD_EVENTS = [
  '<165>1 2026-11-14T09:30:00Z host app - ID47 [meta a.b="x"] srcip=10.1.1.1 action=deny',
  '<165>1 2026-11-14T09:30:00Z host app - ID47 [origin ip="192.0.2.1"][meta note="k=v \\] z" seq="1"] srcip=10.1.1.1 dstip=10.2.2.2 action=deny',
];

describe('PR #311 review: header check only for RFC 3164 results', () => {
  it.each([
    ['json', '{"syslog_hostname":"host=a","message":"ok"}', { format: 'json' }],
    ['json, TAG-like value', '{"syslog_hostname":"kernel:","message":"ok"}', { format: 'json' }],
    ['key=value', 'syslog_hostname="host=a" action=deny', { format: 'kv' }],
  ] as Array<[string, string, Partial<ParserDraft>]>)('%s: a field named syslog_hostname is data', (_name, raw, patch) => {
    const event = preview(raw, draft(patch)).events[0]!;
    expect(event.parseStatus).toBe('FULL');
    expect(event.diagnostics.map(item => item.code)).not.toContain('HEADER_MISREAD_NOT_FULL');
  });

  it('a hand-made result with that field name is not judged as a Syslog header', () => {
    expect(classifyStructuredParse('{"syslog_hostname":"host=a"}', { fields: { syslog_hostname: 'host=a' }, errors: [] }, 'other').status).toBe('FULL');
  });

  it('what the RFC 3164 grammar read as host name is still checked', () => {
    const raw = '<134>Nov 14 09:30:00 fw01 srcip=10.1.1.1 action=deny';
    const real = extractStructuredFamily(raw, 'syslog_rfc3164', 'kv');
    expect(classifyStructuredParse(raw, real, 'kv').status).toBe('FULL');
    // The same extraction with the host name replaced by a TAG, as a faulty grammar would return it.
    (real.fields as Record<string, unknown>).syslog_hostname = 'kernel:';
    const verdict = classifyStructuredParse(raw, real, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.reasons.join(' ')).toContain('taken as the host name');
  });
});

describe('PR #311 review: RFC 5424 structured data is not key=value text', () => {
  it.each(SD_EVENTS)('%s', raw => {
    expect(independentKeyValuePairs(raw).map(pair => pair.key)).toEqual(raw.includes('dstip') ? ['srcip', 'dstip', 'action'] : ['srcip', 'action']);
    const event = preview(raw, draft({ format: 'syslog_rfc5424', syslogBodyFormat: 'kv' })).events[0]!;
    expect(event.parseStatus).toBe('FULL');
    expect(event.diagnostics.filter(item => item.severity === 'error')).toEqual([]);
  });

  it('a pair lost from the MSG behind structured data is still PARTIAL', () => {
    const raw = SD_EVENTS[0]!;
    const real = extractStructuredFamily(raw, 'syslog_rfc5424', 'kv');
    delete ((real.fields as Record<string, Record<string, unknown>>).body as Record<string, unknown>).srcip;
    const verdict = classifyStructuredParse(raw, real, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['srcip']);
  });

  it('text that is not structured data keeps full accounting (NILVALUE, and a malformed element)', () => {
    expect(independentKeyValuePairs('<165>1 2026-11-14T09:30:00Z host app - ID47 - a=1 b=2').map(pair => pair.key)).toEqual(['a', 'b']);
    expect(independentKeyValuePairs('<165>1 2026-11-14T09:30:00Z host app - ID47 [meta x="1" a=1 b=2').map(pair => pair.key)).toEqual(['x', 'a', 'b']);
  });
});
