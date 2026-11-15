/**
 * Parsing Success Contract.
 *
 *   FULL     every verifiable field and the event boundary are correct
 *   PARTIAL  some field or span was not recovered; the original text is kept
 *   UNKNOWN  the structure cannot be trusted, so nothing is auto-parsed
 *   ERROR    an execution failure or a contract violation
 *
 * A parser result alone cannot prove FULL: a grammar that swallows a field into
 * the wrong place still "succeeds". This module therefore re-reads the ORIGINAL
 * line with a deliberately separate, much simpler tokenizer and refuses FULL
 * when a key=value pair that is visible in the raw text is not present, with the
 * same value, in the extracted fields. FULL does not require a Stellar mapping
 * for every vendor field; it is about extraction, not mapping.
 */
export type ParseStatus = 'FULL' | 'PARTIAL' | 'UNKNOWN' | 'ERROR';

import { getTag, matchAt } from './primitives';

export interface StructuredOutcome { fields: Record<string, unknown>; errors: string[] }
export interface RawPair { key: string; value: string; rawValue: string }
export interface ParseVerdict { status: ParseStatus; lostPairs: RawPair[]; reasons: string[] }

// Sticky: tried exactly where a token starts, without cutting a window out of the text.
const KEY_AT_TOKEN_START = /[A-Za-z_][A-Za-z0-9_.-]{0,95}=/uy;

/**
 * RFC 5424 section 6: after "<PRI>VERSION" come five header fields, each separated by exactly one SP and
 * each defined by its position alone. A HOSTNAME written "a=b" is a host name, not a pair, so pair
 * accounting starts after the sixth token. An RFC 3164 header gets no such exemption: its HOSTNAME is
 * optional, which is exactly how a first key=value pair was once lost into it (F-1).
 */
function positionalHeaderEnd(raw: string): number {
  if (!/^<[0-9]{1,3}>[0-9]{1,3} /u.test(raw)) return 0;
  let index = 0;
  for (let token = 0; token < 6; token += 1) {
    const space = raw.indexOf(' ', index);
    if (space < 0) return raw.length;
    index = space + 1;
  }
  return structuredDataEnd(raw, index);
}

/**
 * RFC 5424 section 6.3: STRUCTURED-DATA follows the header, as NILVALUE or as SD-ELEMENTs. An SD-PARAM is
 * written NAME="value" but it is not a key=value pair of the MSG: the extractor stores it under its
 * SD-ELEMENT (and encodes a name that is not a plain identifier), so pair accounting starts after it
 * (PR #311 review). Text that is not well-formed STRUCTURED-DATA is not skipped: the index is returned
 * unchanged and every pair in it is accounted for.
 */
function structuredDataEnd(raw: string, start: number): number {
  const after = (index: number) => (index === raw.length ? index : raw[index] === ' ' ? index + 1 : -1);
  if (raw[start] === '-') { const end = after(start + 1); return end < 0 ? start : end; }
  let index = start;
  while (raw[index] === '[') {
    let cursor = index + 1;
    let quoted = false;
    for (; cursor < raw.length; cursor += 1) {
      const ch = raw[cursor];
      if (quoted && ch === '\\') { cursor += 1; continue; }
      if (ch === '"') { quoted = !quoted; continue; }
      if (ch === ']' && !quoted) break;
    }
    if (cursor >= raw.length) return start;
    index = cursor + 1;
  }
  if (index === start) return start;
  const end = after(index);
  return end < 0 ? start : end;
}

/**
 * Independent evidence: key=value pairs that start a whitespace-separated token
 * of the raw line. Values in double or single quotes are consumed whole, so a
 * '=' inside a quoted value is never reported as a pair of its own. This is intentionally not the
 * product KV parser.
 */
export function independentKeyValuePairs(raw: string): RawPair[] {
  const pairs: RawPair[] = [];
  const length = raw.length;
  // Tokens are separated by ASCII white space (SP, TAB, LF, VT, FF, CR): the key=value grammar never puts one
  // of these into an unquoted value and allows them after the last pair (contract KV_BARE, KV_TRAILING), so a
  // form feed at the end of the line is not part of the last value.
  const gap = (ch: string | undefined): boolean => ch === ' ' || ch === '\t' || ch === '\n' || ch === '\v' || ch === '\f' || ch === '\r';
  let index = positionalHeaderEnd(raw);
  while (index < length) {
    while (index < length && gap(raw[index])) index += 1;
    const start = index;
    const key = matchAt(KEY_AT_TOKEN_START, raw, index);
    if (key) {
      index += key[0].length;
      const quote = raw[index];
      if (quote === '"' || quote === "'") {
        let cursor = index + 1;
        let value = '';
        let closed = false;
        while (cursor < length) {
          if (raw[cursor] === '\\' && cursor + 1 < length) { value += raw[cursor + 1]; cursor += 2; continue; }
          if (raw[cursor] === quote) { closed = true; break; }
          value += raw[cursor]; cursor += 1;
        }
        if (closed) {
          pairs.push({ key: key[0].slice(0, -1), value, rawValue: raw.slice(index + 1, cursor) });
          index = cursor + 1;
          continue;
        }
      }
      let end = index;
      // An unquoted value ends at white space. No backslash rule here: this reader must not share the
      // grammar's idea of an escape (a backslash that carried the next SP made the grammar swallow the
      // following pair, and a reader with the same rule could not see it).
      while (end < length && !gap(raw[end])) end += 1;
      const value = raw.slice(index, end);
      pairs.push({ key: key[0].slice(0, -1), value, rawValue: value });
      index = end;
      continue;
    }
    while (index < length && !gap(raw[index])) index += 1;
    if (index === start) index += 1;
  }
  return pairs;
}

function collectLeaves(value: unknown, key: string, out: Map<string, string[]>): void {
  // The values of a list belong to the field that holds the list.
  if (Array.isArray(value)) { for (const child of value) collectLeaves(child, key, out); return; }
  if (value !== null && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) collectLeaves(child, childKey, out);
    return;
  }
  if (value === undefined || value === null) return;
  const list = out.get(key);
  if (list) list.push(String(value)); else out.set(key, [String(value)]);
}

/**
 * Classifies one structured extraction against the raw line it came from.
 * `outcome` is the extractor result, or `{ thrown }` when the extractor raised.
 * Pair accounting is defined for key=value bodies; for other body formats only
 * the UNKNOWN/ERROR distinctions are decided here and the Semantic Golden
 * Oracle carries the field-level proof.
 */
export function classifyStructuredParse(
  raw: string,
  outcome: StructuredOutcome | { thrown: unknown },
  bodyFormat: string,
): ParseVerdict {
  if ('thrown' in outcome) return { status: 'ERROR', lostPairs: [], reasons: ['extractor raised: ' + String(outcome.thrown)] };
  if (outcome.errors.length > 0) return { status: 'UNKNOWN', lostPairs: [], reasons: outcome.errors.slice(0, 4) };
  if (Object.keys(outcome.fields).length === 0) return { status: 'UNKNOWN', lostPairs: [], reasons: ['no field was extracted'] };
  // A TAG ("kernel:") or a pair ("srcip=10.1.1.1") read as the RFC 3164 host name is a misread header, whatever
  // the grammar matched. Only a result of the RFC 3164 header grammar is judged (it carries the mark below): a
  // JSON or key=value field called syslog_hostname is data, and an RFC 5424 HOSTNAME is positional.
  const host = getTag(outcome, 'rfc3164Header') === true ? outcome.fields.syslog_hostname : undefined;
  const headerReasons = typeof host === 'string' && (host.includes('=') || host.endsWith(':'))
    ? ['a TAG or a key=value pair was taken as the host name'] : [];
  if (bodyFormat !== 'kv') return { status: headerReasons.length ? 'PARTIAL' : 'FULL', lostPairs: [], reasons: headerReasons };
  // The pairs of the raw line are looked up where the key=value parser put them: in the body of a Syslog
  // result, or in the result itself when the whole event is key=value. Header fields and RFC 5424 structured
  // data are not searched, so an SD-PARAM with the name and value of a lost pair cannot stand in for it.
  const body = outcome.fields.body;
  const scope = body !== null && typeof body === 'object' && !Array.isArray(body) ? body : outcome.fields;
  const leaves = new Map<string, string[]>();
  collectLeaves(scope, '', leaves);
  // Every pair of the raw line needs a value of its own in the result: a field written twice and present
  // once is a lost occurrence (owner policy D-1), so a matched value is consumed.
  const taken = new Map<string, Set<number>>();
  const lostPairs = independentKeyValuePairs(raw).filter(pair => {
    // Which backslashes a grammar decodes is the grammar's business; presence of the value is what is
    // accounted here, so both sides are compared with backslashes removed.
    const written = pair.rawValue.split('\\').join('');
    const values = leaves.get(pair.key) ?? [];
    const consumed = taken.get(pair.key) ?? new Set<number>();
    const at = values.findIndex((value, index) => !consumed.has(index) &&
      (value === pair.value || value === pair.rawValue || value.split('\\').join('') === written));
    if (at < 0) return true;
    consumed.add(at);
    taken.set(pair.key, consumed);
    return false;
  });
  if (lostPairs.length > 0 || headerReasons.length > 0) {
    return {
      status: 'PARTIAL',
      lostPairs,
      reasons: [...headerReasons, ...lostPairs.slice(0, 4).map(pair => `raw pair ${pair.key}= is not present with its value in the extracted fields`)],
    };
  }
  return { status: 'FULL', lostPairs: [], reasons: [] };
}
