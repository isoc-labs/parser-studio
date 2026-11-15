import { describe, expect, it } from 'vitest';
import goldens from '../../contracts/semantic-goldens.v1.json';
import { extractGenericStructural } from '../genericStructural';
import { classifyGenericStructural } from './genericParseStatus';

// Parsing Success Contract of Generic Structural for the modes whose body is JSON, CEF, LEEF or positional CSV:
// the verdict is FULL only when the body fields spell the body text (src/grammar/lossGuard.ts).

const GOLDENS = goldens as unknown as { genericCases: Array<{ id: string; raw: string }> };
const golden = (prefix: string) => GOLDENS.genericCases.find(item => item.raw.startsWith(prefix))!.raw;
const CEF = 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=80 act=blocked proto=tcp';
const LEEF = 'LEEF:2.0|Acme Corp|Gateway|1|event|0x09|first=one\tsecond=two words\tthird=three';
const ISO = '<13>2026-10-16 03:11:07 +0200 edge ';

type Fields = Record<string, any>;
const read = (raw: string, damage?: (fields: Fields) => void, route: 'dedicated' | 'legacy' = 'dedicated') => {
  const extraction = extractGenericStructural(raw, undefined, route === 'dedicated' ? 'dedicated' : undefined);
  expect(extraction.errors, raw).toEqual([]);
  damage?.(extraction.fields);
  return { ...classifyGenericStructural(raw, extraction), fields: extraction.fields as Fields };
};

const CASES: Array<[string, string, (fields: Fields) => void]> = [
  ['structured_family_cef', CEF, fields => { delete fields.body.dpt; }],
  ['structured_family_leef', LEEF, fields => { fields.body.second = 'two'; }],
  ['syslog_envelope_cef', ISO + CEF, fields => { fields.body.act = 'block'; }],
  ['syslog_envelope_leef', ISO + LEEF, fields => { delete fields.body.third; }],
  ['syslog_envelope_json', ISO + '{"srcip":"10.5.5.6","port":443,"tags":["a","b"]}', fields => { fields.body.tags = ['a']; }],
  ['prefixed_json', 'app-1 {"user":"kim","port":443}', fields => { fields.body.port = 44; }],
  ['body', '<13>1 2026-10-16T03:11:07Z host {"user":"kim","port":443}', fields => { fields.body.extra = 1; }],
  ['rfc3164_positional_csv', '<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,"rule ""A"", east"', fields => { fields.generic.columns.column_11 = 'rule'; }],
  ['panos_traffic_csv', golden('<14>Dec 10 00:00:00 hostname 1,'), fields => { delete fields.generic.fields.rule; }],
];

describe('Generic Structural: the body fields spell the body text', () => {
  it.each(CASES)('%s: a complete reading is FULL', (mode, raw) => {
    const verdict = read(raw);
    expect(verdict.mode).toBe(mode);
    expect(verdict.status, verdict.reasons.join('; ')).toBe('FULL');
  });
  it.each(CASES)('%s: a reading that lost, changed or invented body data is PARTIAL', (_mode, raw, damage) => {
    const verdict = read(raw, damage);
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.reasons.join(' ')).not.toMatch(/10\.0\.0\.1|kim|two words|threatmanager/);
  });
  it('keeps every Generic Structural golden at its verdict', () => {
    for (const item of GOLDENS.genericCases as Array<{ id: string; raw: string; familyGrammar?: 'dedicated'; expect: { status: string } }>) {
      const extraction = extractGenericStructural(item.raw, undefined, item.familyGrammar);
      if (extraction.errors.length) continue;
      if (item.expect.status === 'FULL') expect(classifyGenericStructural(item.raw, extraction).status, item.id).toBe('FULL');
    }
  });
});

describe('Generic Structural: a CEF or LEEF event inside a Syslog envelope is read by its own grammar', () => {
  // Five pairs at token boundaries used to send the line to the generic space-separated key=value route: the
  // CEF header and the first pair ended up in prefix tokens, and the same vendor's events were mapped from
  // two different trees depending on how many pairs a line carried.
  const few = ISO + 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2';
  const many = ISO + CEF;
  it('reads the event with the CEF grammar however many pairs it carries', () => {
    for (const raw of [few, many, '<134>Nov 14 09:30:00 fw01 ' + CEF]) {
      const verdict = read(raw);
      expect(verdict.mode, raw).toBe('syslog_envelope_cef');
      expect(verdict.status).toBe('FULL');
      expect(verdict.fields.body).toMatchObject({ cef_name: 'worm successfully stopped', src: '10.0.0.1', dst: '2.1.2.2' });
    }
  });
  it('declines an enveloped line that claims CEF or LEEF and is not one', () => {
    for (const raw of [ISO + 'CEF:1|a|b|c|d|e|5|a=1 b=2 c=3 d=4 e=5 f=6', ISO + 'LEEF:3.0|a|b|c|d|a=1 b=2 c=3 d=4 e=5 f=6']) {
      const extraction = extractGenericStructural(raw, undefined, 'dedicated');
      expect(extraction.errors.join(' '), raw).toMatch(/claims to be (CEF|LEEF)/);
    }
  });
  it('keeps the output of a project without the marker and reports it as PARTIAL (owner policy D-2)', () => {
    const verdict = read(many, undefined, 'legacy');
    expect(verdict.mode).toBe('space_kv');
    expect(verdict.fields.generic.kv).toMatchObject({ dst: '2.1.2.2', proto: 'tcp' });
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.reasons.join(' ')).toMatch(/claims to be CEF/);
  });
});
