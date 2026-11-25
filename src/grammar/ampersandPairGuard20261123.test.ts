/**
 * Loss guard for pairs separated by "&" (independent audit 2026-11-22, G-11).
 *
 * "a=1&b=2&c=3" was reported FULL with one field: "&" was not a list delimiter, so the independent reader saw
 * one pair whose value is the rest of the line. A pair behind "&" is now seen inside one token - unless the
 * value before it opened a URL query with "?", where "&" separates query parameters of one value
 * ("url=/a?x=1&y=2" stays one value).
 */
import { describe, expect, it } from 'vitest';
import { classifyStructuredParse, independentKeyValuePairs } from './parseStatus';

const written = (raw: string) => independentKeyValuePairs(raw).map(pair => [pair.key, pair.rawValue]);

describe('pairs separated by "&"', () => {
  it('sees every pair of a line whose pairs are separated by "&" alone', () => {
    expect(written('a=1&b=2&c=3')).toEqual([['a', '1'], ['b', '2'], ['c', '3']]);
  });
  it('grades a one-field reading of such a line PARTIAL, not FULL', () => {
    const verdict = classifyStructuredParse('a=1&b=2&c=3', { fields: { a: '1&b=2&c=3' }, errors: [] }, 'kv');
    expect(verdict.status).toBe('PARTIAL');
  });
  it('keeps a URL query as one value', () => {
    expect(written('url=/a?x=1&y=2')).toEqual([['url', '/a?x=1&y=2']]);
    expect(written('src=10.0.0.1 url=/a?x=1&y=2 status=200')).toEqual([['src', '10.0.0.1'], ['url', '/a?x=1&y=2'], ['status', '200']]);
  });
  it('keeps "&" inside a value of a white-space separated line as value data', () => {
    expect(written('src=10.0.0.1 note=a&b=c status=200')).toEqual([['src', '10.0.0.1'], ['note', 'a&b=c'], ['status', '200']]);
  });
});
