/**
 * Independent re-audit of 2026-11-15 (PR #311, commit 3b9e3f5): eight classes of lines that the browser and the
 * generated Ruby read differently inside Generic Structural. The lines and what they mean are the Semantic
 * Oracle's hand-authored goldens (contracts/semantic-goldens.v1.json); this file holds the browser to them, and
 * backend/test/reaudit-generic-differences-20261115.test.ts holds the generated Ruby to the same entries.
 */
import { describe, expect, it } from 'vitest';
import goldens from '../contracts/semantic-goldens.v1.json';
import { extractGenericStructural } from './genericStructural';
import { lookupFieldValue } from './fieldPaths';
import { preview, tokenizeCSV } from './parser';
import { createDraft } from './model';

interface GenericCase { id: string; raw: string; provenance: string; expect: { fields?: Record<string, unknown>; reject?: boolean } }
const REAUDIT = [
  'generic-envelope-iso-space-basic-offset', 'generic-envelope-iso-space-zulu', 'generic-envelope-rfc3339-loose-basic-offset',
  'generic-envelope-bsd-fraction-of-second', 'generic-envelope-rfc5424-basic-offset-asa', 'generic-iso-pri-offset-minute-60-declined',
  'generic-json-nesting-depth-9-declined', 'generic-json-lone-surrogate-escape-declined', 'generic-json-two-high-surrogates-declined',
  'generic-json-unknown-escape-declined', 'generic-json-comment-declined',
  'generic-positional-csv-quote-inside-unquoted-field-declined', 'generic-positional-csv-quoted-field-with-comma-and-quote',
];
const cases = (goldens.genericCases as GenericCase[]).filter(item => REAUDIT.includes(item.id));

describe('re-audit 2026-11-15: Generic Structural lines the two engines read differently', () => {
  it('every listed golden exists', () => { expect(cases.map(item => item.id).sort()).toEqual([...REAUDIT].sort()); });

  it.each(cases.filter(item => item.expect.reject))('$id is declined, and the preview does not call it parsed', item => {
    const result = extractGenericStructural(item.raw);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.fields).toEqual({});
    const event = preview(item.raw, { ...createDraft(), format: 'generic_structural' }).events[0]!;
    expect(event.parseStatus).not.toBe('FULL');
    expect(event.parseStatus).not.toBe('PARTIAL');
  });

  it.each(cases.filter(item => item.expect.fields))('$id is parsed with the meant values', item => {
    const result = extractGenericStructural(item.raw);
    expect(result.errors).toEqual([]);
    for (const [path, value] of Object.entries(item.expect.fields!))
      expect(lookupFieldValue(result.fields, path), path).toEqual({ found: true, value });
  });

  it('a quoted CSV field keeps its comma and its quotation mark; nothing is dropped from an unquoted one', () => {
    const head = '<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,';
    const column = (tail: string) => lookupFieldValue(extractGenericStructural(head + tail).fields, 'generic.columns.column_11');
    expect(column('"a,b"')).toEqual({ found: true, value: 'a,b' });
    expect(column('""')).toEqual({ found: true, value: '' });
    for (const tail of ['a"b', 'a""b', '"a"b', ' "a"', '"a" ', '"a', 'a"'])
      expect(extractGenericStructural(head + tail).errors.length, tail).toBeGreaterThan(0);
  });

  it('JSON at eight nested levels is read; a paired surrogate escape is one character', () => {
    expect(lookupFieldValue(extractGenericStructural('EXAMPLE: {"a":[[[[[[[1]]]]]]]}').fields, 'generic.mode')).toEqual({ found: true, value: 'prefixed_json' });
    expect(lookupFieldValue(extractGenericStructural('EXAMPLE: {"c":"\\ud83d\\ude00"}').fields, 'body.c')).toEqual({ found: true, value: '\u{1F600}' });
  });
});

describe('format-level browser/Ruby fuzz 2026-11-15: CSV rows and empty events', () => {
  it('a quotation mark around the content of a quoted field, not doubled, is not a row', () => {
    expect(tokenizeCSV('""aaa"",bbb,ccc', ',')).toBeNull();
    expect(tokenizeCSV('"a""a",bbb,ccc', ',')).toEqual(['a"a', 'bbb', 'ccc']);
  });

  it('only SP and TAB are stripped at the edge of an unquoted field; form feed, vertical tab and NBSP are data', () => {
    expect(tokenizeCSV(' aaa\t,bbb\f,\vccc,\u00a0d ', ',')).toEqual(['aaa', 'bbb\f', '\vccc', '\u00a0d']);
    expect(tokenizeCSV('aaa\t;bbb\f', ';')).toEqual(['aaa', 'bbb\f']);
  });

  it('a row that is empty or only spaces is no row; a row of empty fields is', () => {
    expect(tokenizeCSV('   ', ',')).toBeNull();
    expect(tokenizeCSV('', ',')).toBeNull();
    expect(tokenizeCSV(',', ',')).toEqual([null, null]);
    expect(tokenizeCSV('""', ',')).toEqual(['']);
    expect(tokenizeCSV('   ', '\t')).toEqual(['   ']);
  });

  it('an empty JSON object is not a parsed event', () => {
    expect(preview('{}', { ...createDraft(), format: 'json' }).events[0]!.parseStatus).toBe('UNKNOWN');
  });
});
