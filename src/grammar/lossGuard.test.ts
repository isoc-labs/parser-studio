import { describe, expect, it } from 'vitest';
import { generateCefLeefCases } from './cefLeefModel';
import { generateCsvCases } from './csvModel';
import { generateJsonCases } from './jsonModel';
import { cefEventUnaccounted, csvRowUnaccounted, jsonTextUnaccounted, leefEventUnaccounted } from './lossGuard';
import { gradeExtraction, readEvent } from './readEvent';
import { extractEvent, tokenizeCsvRow, type ExtractionSettings } from './extractEvent';

// Parsing Success Contract for CSV, JSON, CEF and LEEF. Two things are shown for every format:
//  - a complete parse of valid data is FULL (the accounting never rejects normal data), on hand-written
//    vendor-style events and on the model-generated cases of the semantic oracle;
//  - a result that lost, truncated or invented data is reported, with a reason that carries no event text.

const full = (raw: string, settings: ExtractionSettings) => {
  const reading = readEvent(raw, settings);
  expect(reading.status, raw + ' -> ' + reading.reasons.join('; ')).toBe('FULL');
  return reading.fields;
};

describe('CSV: the cells written back spell the row', () => {
  const settings = (columns: number, csvDelimiter = ','): ExtractionSettings =>
    ({ format: 'csv', csvDelimiter, csvColumns: Array.from({ length: columns }, (_item, index) => 'c' + (index + 1)) });
  it('accepts every way a valid row writes its cells', () => {
    full('1,alice,10.0.0.1', settings(3));
    full(' 1 , alice ,\t10.0.0.1 ', settings(3));
    full('"a,b","say ""hi""",,"" , last', settings(5));
    full('a;;"x;y"', settings(3, ';'));
    full(' a \tb c\t"q\tq"', settings(3, '\t'));
    full('\ud55c\uae00,\u{1f600} emoji,"\u{1f600},\u00e9"', settings(3));
  });
  it('accepts the model-generated rows', () => {
    let parsed = 0;
    for (const item of generateCsvCases(400, 20261115)) {
      const cells = tokenizeCsvRow(item.raw, item.delimiter);
      if (!cells) continue;
      parsed += 1;
      expect(csvRowUnaccounted(item.raw, item.delimiter, cells), JSON.stringify(item.raw)).toBeNull();
    }
    expect(parsed).toBeGreaterThan(100);
  });
  it('reports a dropped, truncated, altered or invented cell', () => {
    const raw = 'alpha, "b,c" ,gamma';
    expect(csvRowUnaccounted(raw, ',', ['alpha', 'b,c', 'gamma'])).toBeNull();
    expect(csvRowUnaccounted(raw, ',', ['alpha', 'b,c'])).toMatch(/after the last CSV cell/);
    expect(csvRowUnaccounted(raw, ',', ['alpha', 'b', 'gamma'])).toMatch(/CSV cell 2/);
    expect(csvRowUnaccounted(raw, ',', ['alph', 'b,c', 'gamma'])).toMatch(/no delimiter after CSV cell 1/);
    expect(csvRowUnaccounted(raw, ',', ['alpha', 'b,c', 'gamma', 'extra'])).toMatch(/no delimiter after CSV cell 3/);
    expect(csvRowUnaccounted(raw, ',', ['alpha', null, 'gamma'])).toMatch(/no delimiter after CSV cell 2/);
  });
});

describe('JSON: the names and values of the text are those of the fields', () => {
  it('accepts valid JSON whatever its spelling', () => {
    full('{"a":1,"b":"x","c":[true,false,null],"d":{"e":-1.5e2,"f":"\\u00e9\\ud83d\\ude00\\n\\"q\\" \\/"}}', { format: 'json' });
    full(' {\n  "10" : 1.0 , "2":"two", "nested":{"2":[{"k":""}]} }\n', { format: 'json' });
    full('{"\ud55c\uae00":"\u{1f600}","n":0,"neg":-0,"big":9007199254740991,"small":1e-7}', { format: 'json' });
    full('<165>1 2026-11-14T09:30:00Z host app - ID47 - {"user":"kim","ok":true,"n":[1,2,3]}', { format: 'syslog_rfc5424', syslogBodyFormat: 'json' });
  });
  it('accepts the model-generated documents', () => {
    let parsed = 0;
    for (const item of generateJsonCases(300, 20261115)) {
      const extraction = extractEvent(item.raw, { format: 'json' });
      if (extraction.errors.length) continue;
      parsed += 1;
      expect(jsonTextUnaccounted(item.raw, extraction.fields), JSON.stringify(item.raw).slice(0, 200)).toBeNull();
    }
    expect(parsed).toBeGreaterThan(100);
  });
  it('reports a lost member, a changed value and an invented member, without quoting the event', () => {
    const raw = '{"user":"kim","port":443,"tags":["a","b"],"ok":true}';
    expect(jsonTextUnaccounted(raw, { user: 'kim', port: 443, tags: ['a', 'b'], ok: true })).toBeNull();
    const lost = jsonTextUnaccounted(raw, { user: 'kim', port: 443, tags: ['a'], ok: true });
    expect(lost).toMatch(/missing from the extracted fields/);
    expect(lost).not.toMatch(/kim|443/);
    expect(jsonTextUnaccounted(raw, { user: 'kim', port: 44, tags: ['a', 'b'], ok: true })).not.toBeNull();
    expect(jsonTextUnaccounted(raw, { user: 'kim', port: 443, tags: ['a', 'b'], ok: true, extra: 1 })).toMatch(/not in the JSON text/);
    expect(jsonTextUnaccounted(raw, { user: 'kim', port: 443, tags: ['a', 'b'], ok: false })).not.toBeNull();
  });
});

describe('CEF and LEEF: the extension is accounted for', () => {
  const CEF = 'CEF:0|Security|threatmanager|1.0|100|worm \\| stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 msg=Detected a \\=threat\\= at C:\\\\dir\\nline two request=http://x/?a=1&b=2 cs1="quoted text" end';
  const LEEF1 = 'LEEF:1.0|Vendor|Product|1.0|event|src=10.0.0.1\tdst=10.0.0.2\tmsg=a b=c \\ d\tusrName=kim';
  const LEEF2 = 'LEEF:2.0|Vendor|Product|2.0|event|^|src=10.0.0.1^dst=10.0.0.2^msg=two words^url=http://x/?a=1';
  it('accepts valid events, standalone and inside Syslog', () => {
    full(CEF, { format: 'cef' });
    full('CEF:0|a|b|c|d|e|5|', { format: 'cef' });
    full(LEEF1, { format: 'leef' });
    full(LEEF2, { format: 'leef' });
    full('<134>Nov 14 09:30:00 fw01 ' + CEF, { format: 'syslog_rfc3164', syslogBodyFormat: 'cef' });
    full('<165>1 2026-11-14T09:30:00Z host app - ID47 - ' + LEEF2, { format: 'syslog_rfc5424', syslogBodyFormat: 'leef' });
  });
  it('accepts the model-generated events', () => {
    let parsed = 0;
    for (const item of generateCefLeefCases(400, 20261115)) {
      const reading = readEvent(item.raw, { format: item.family });
      if (reading.errors.length) continue;
      parsed += 1;
      expect(reading.status, JSON.stringify(item.raw).slice(0, 240) + ' -> ' + reading.reasons.join('; ')).toBe('FULL');
    }
    expect(parsed).toBeGreaterThan(100);
  });
  it('reports a lost, truncated, altered or invented field', () => {
    const cef = extractEvent(CEF, { format: 'cef' }).fields;
    expect(cefEventUnaccounted(CEF, cef)).toBeNull();
    const { spt: _spt, ...withoutPort } = cef;
    expect(cefEventUnaccounted(CEF, withoutPort)).toMatch(/missing from the extracted fields/);
    expect(cefEventUnaccounted(CEF, { ...cef, src: '10.0.0' })).toMatch(/ends before/);
    expect(cefEventUnaccounted(CEF, { ...cef, msg: 'Detected' })).toMatch(/not part of any extracted field/);
    expect(cefEventUnaccounted(CEF, { ...cef, dst: '2.1.2.3' })).toMatch(/not the text of its key=value pair/);
    expect(cefEventUnaccounted(CEF, { ...cef, cef_name: 'worm' })).toMatch(/CEF header/);
    expect(cefEventUnaccounted(CEF, { ...cef, extra: 'x' })).toMatch(/not in the CEF extension/);
    const leef = { ...extractEvent(LEEF2, { format: 'leef' }).fields };
    expect(leefEventUnaccounted(LEEF2, leef)).toBeNull();
    const { dst: _dst, ...withoutDst } = leef;
    expect(leefEventUnaccounted(LEEF2, withoutDst)).toMatch(/missing from the extracted fields/);
    expect(leefEventUnaccounted(LEEF2, { ...leef, msg: 'two' })).toMatch(/ends before/);
    expect(leefEventUnaccounted(LEEF2, { ...leef, src: '10.0.0.9' })).toMatch(/not the text of its attribute/);
    expect(leefEventUnaccounted(LEEF2, { ...leef, leef_vendor: 'Other' })).toMatch(/LEEF header/);
    expect(leefEventUnaccounted(LEEF2, { ...leef, extra: 'x' })).toMatch(/not in the LEEF extension/);
    // The delimiter is the declared one: a value that holds the default TAB is one value.
    const tabbed = 'LEEF:2.0|Vendor|Product|2.0|event|0x5e|a=1\tb=2^c=3';
    expect(full(tabbed, { format: 'leef' })).toMatchObject({ a: '1\tb=2', c: '3' });
    expect(leefEventUnaccounted(tabbed, { ...extractEvent(tabbed, { format: 'leef' }).fields, a: '1', b: '2' })).not.toBeNull();
  });
});

describe('the verdict on an extraction that lost data is PARTIAL', () => {
  // The extraction is the product's own; one field is then removed or cut, as a faulty extractor would.
  const lossy = (raw: string, settings: ExtractionSettings, damage: (fields: Record<string, unknown>) => void) => {
    const extraction = extractEvent(raw, settings);
    expect(gradeExtraction(raw, settings, extraction).status).toBe('FULL');
    damage(extraction.fields);
    return gradeExtraction(raw, settings, extraction);
  };
  it('for every format, standalone and as the body of a Syslog event', () => {
    const body = (fields: Record<string, unknown>) => fields.body as Record<string, unknown>;
    const verdicts = [
      lossy('1,alice,10.0.0.1', { format: 'csv', csvColumns: ['id', 'user', 'ip'] }, fields => { fields.user = 'ali'; }),
      lossy('{"user":"kim","port":443}', { format: 'json' }, fields => { delete fields.port; }),
      lossy('CEF:0|a|b|c|d|e|5|src=10.0.0.1 msg=two words', { format: 'cef' }, fields => { fields.msg = 'two'; }),
      lossy('LEEF:1.0|a|b|c|d|src=10.0.0.1\tmsg=two words', { format: 'leef' }, fields => { delete fields.src; }),
      lossy('<165>1 2026-11-14T09:30:00Z host app - ID47 - {"user":"kim","port":443}', { format: 'syslog_rfc5424', syslogBodyFormat: 'json' }, fields => { delete body(fields).port; }),
      lossy('<134>Nov 14 09:30:00 fw01 CEF:0|a|b|c|d|e|5|src=10.0.0.1 msg=two words', { format: 'syslog_rfc3164', syslogBodyFormat: 'cef' }, fields => { body(fields).msg = 'two'; }),
      lossy('<165>1 2026-11-14T09:30:00Z host app - ID47 - LEEF:2.0|a|b|c|d|^|src=10.0.0.1^msg=x', { format: 'syslog_rfc5424', syslogBodyFormat: 'leef' }, fields => { delete body(fields).msg; }),
      lossy('{"user":"kim","port":443}', { format: 'mixed', mixedFormats: ['json', 'kv'] }, fields => { fields.port = 44; }),
      lossy('a,"b,c"', { format: 'mixed', mixedFormats: ['kv', 'csv'], csvColumns: ['one', 'two'] }, fields => { fields.two = 'b'; }),
      lossy('1,alice,10.0.0.1', { format: 'csv', csvColumns: ['id', 'user', 'ip'] }, fields => { fields.invented = 'x'; }),
    ];
    for (const verdict of verdicts) {
      expect(verdict.status).toBe('PARTIAL');
      expect(verdict.reasons).toHaveLength(1);
      expect(verdict.reasons[0]).not.toMatch(/kim|alice|10\.0\.0\.1|two words/);
    }
  });
});
