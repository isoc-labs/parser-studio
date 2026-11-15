// Probes of the TypeScript -> Ruby translation (scripts/grammar/ts2rb).
//
// Each function exercises one group of ECMAScript operations the shared grammar may use. The module is
// translated to Ruby by the same generator as the grammar, and scripts/verification/translation-conformance.ts
// runs both on the same inputs: a difference is a defect of the emitter or of a psg_* primitive, found here
// instead of inside a grammar route. The functions return JSON values only.
import { getTag, isWellFormed, matchAt, matchEnd, namedGroups, setTag } from '../../src/grammar/primitives';

const STICKY_WORD = /[A-Za-z]+/uy;
const NAMED = /^(?<head>[a-z]+)(?:-(?<tail>[0-9]+))?/u;
const LIMITS = { low: 2, high: 5, names: ['a', 'b'], nested: { flag: true } } as const;
const KNOWN = new Set(['a', 'bb', '']);

export function probeString(s: string, t: string, a: number, b: number): unknown[] {
  return [
    s.length, s.slice(a), s.slice(a, b), s.slice(-a), s.slice(a, -b), s.substring(a, b), s.substring(b, a),
    s.indexOf(t), s.indexOf(t, a), s.lastIndexOf(t), s.includes(t), s.startsWith(t), s.startsWith(t, a), s.endsWith(t),
    s.split(t === '' ? ',' : t), s.split(','), s.split(' '), s.split(',', 2),
    String(s.charCodeAt(a)), s.codePointAt(a), s[a], s.charAt(a), s.padStart(b, '0'), s.padStart(b),
    s.trim(), s.trimStart(), s.trimEnd(), s.replace(',', ';'), s.replaceAll(',', ';'), s.replace('a', t), s.repeat(2),
    [...s].length, s + t, `${s}:${a}`, s === t, s !== t, isWellFormed(s), new TextEncoder().encode(s).length, KNOWN.has(s),
  ];
}

export function probeScan(s: string): unknown[] {
  // The loops the grammar's hand scanners are made of: by code unit, by character, with continue and break.
  let units = '';
  let quoted = false;
  let count = 0;
  for (let index = 0; index < s.length; index += 1) {
    const unit = s[index]!;
    if (unit === '"') { quoted = !quoted; continue; }
    if (unit === ';' && !quoted) break;
    units += unit === ' ' && !quoted ? '_' : unit;
    count++;
  }
  const characters: string[] = [];
  for (const character of s) {
    if (character === ' ') continue;
    characters.push(character);
    if (characters.length >= 6) break;
  }
  let cursor = 0;
  const tokens: string[] = [];
  while (cursor < s.length) {
    const next = s.indexOf(',', cursor);
    const end = next < 0 ? s.length : next;
    tokens.push(s.slice(cursor, end));
    cursor = end + 1;
  }
  return [units, count, characters, tokens, cursor];
}

export function probeRegex(s: string): unknown[] {
  const word = /[A-Za-z_]+/u.exec(s);
  const named = NAMED.exec(s);
  // An offset the grammar would produce: just after a first match, never inside a character.
  const sticky = matchAt(STICKY_WORD, s, word ? matchEnd(word) - 1 : 0);
  const numbers: unknown[] = [];
  for (const match of s.matchAll(/[0-9]+/gu)) numbers.push([match[0], match.index]);
  return [
    /^a.c$/u.test(s), /^.*$/u.test(s), /^.*$/su.test(s), /\s/u.test(s), /\S+/u.exec(s)?.[0], /\d+/u.exec(s)?.index, /\w+$/u.test(s),
    /\bab\b/u.test(s), /^[^,]{2,4}?,/u.exec(s)?.[0], /^(?:ab){2}?/u.test(s), /[\[\]&#/-]/u.test(s), /^[a-c&]+$/u.test(s),
    /^[^ \t\n\r\f\v]{1,3}$/u.test(s), /^.{1,3}$/u.test(s), /[é\u{1f600}]/u.test(s), /^(a|b)\1$/u.test(s), /a$/u.test(s), /^$/u.test(s),
    word?.index, word?.[0], word ? matchEnd(word) : null, named ? namedGroups(named) : null, named?.groups!.tail, named?.[1],
    sticky ? [sticky[0], sticky.index, matchEnd(sticky)] : null, matchAt(STICKY_WORD, s, 0)?.[0],
    s.split(/,\s*/u), s.split(/(;)/u), s.replace(/[0-9]+/u, 'N'), s.replace(/[0-9]+/gu, 'N'),
    s.replace(/([a-z])([0-9])/gu, (_whole, letter, digit) => digit + letter), s.replace(/[A-Z]/gu, upper => upper + upper), numbers,
    s.match(/^(\w)(\w)?/u)?.slice(1), /^(?<x>x)?y/u.exec(s)?.groups!.x,
  ];
}

export function probeNumber(s: string, a: number, b: number): unknown[] {
  const n = Number(s);
  return [
    String(n), Number.isInteger(n), Number.isFinite(n), Number.isSafeInteger(n), Number.isNaN(n), n > 5, n <= 5, n === 0,
    String(parseInt(s, 10)), String(parseInt(s, 16)), String(a + b), a - b, a * b, String(a % 3), String(-a % 3), String(a % b),
    String(Math.floor(a / 3)), String(a / 2), String(a / b), Math.max(a, b), Math.min(a, b), `${a / 4}`, a.toString(16), String(n + 1), s + a, a + s,
    String(n * 1000000), String(n / 1000000), String(0.1 + 0.2), String(1e21), String(1e-7), String(123456789012345680000), String(a / 3),
  ];
}

export function probeValue(v: unknown): unknown[] {
  const out: unknown[] = [!v, typeof v, v === null, v === undefined, v == null, Array.isArray(v), v ?? 'default', String(typeof v === 'object' ? 'object' : v)];
  if (typeof v === 'string') out.push(v.length, v ? 'non-empty' : 'empty');
  if (typeof v === 'number') out.push(v + 1, v ? 'non-zero' : 'zero', Number.isInteger(v));
  if (v !== null && typeof v === 'object') out.push(Object.keys(v), Object.entries(v), Object.values(v).length);
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const record = v as Record<string, unknown>;
    out.push(Object.prototype.hasOwnProperty.call(record, 'a'), 'a' in record, record.a === null, record.a === undefined, record.a == null, record.a ?? 'd', !record.a);
  }
  return out;
}

function counter(start: number, step = 2, label?: string): string {
  return (label ?? 'n') + (start + step);
}

export function probeCollections(items: string[], record: Record<string, unknown>): unknown[] {
  const copy = [...items, 'tail'];
  const popped = copy.pop();
  copy.push('x', 'y');
  const merged: Record<string, unknown> = { first: 1, ...record, last: items.length };
  const assigned = Object.assign({}, record, { extra: true });
  const seen = new Set<string>();
  const index = new Map<string, number>();
  let total = 0;
  for (const [position, item] of items.map((item, position): [number, string] => [position, item])) {
    if (seen.has(item)) continue;
    seen.add(item);
    index.set(item, position);
    total += position;
  }
  const lengths = items.map(item => item.length);
  const tagged = setTag({ value: 1 }, 'kind', 'kv');
  const [head, second] = items;
  let caught = 'none';
  try { JSON.parse(items[0] ?? ''); } catch { caught = 'invalid'; }
  const add = (x: number, y: number): number => x + y;
  let post = 0;
  const before = post++;
  return [
    copy, popped, copy.length, items.slice(1), items.slice(-2), items.slice(1, 2), items.indexOf('b'), items.includes('b'), items.join('|'), items.join(),
    items.filter(item => item !== ''), items.some(item => item === 'b'), items.every(item => item.length < 3), items.find(item => item.length > 1),
    items.findIndex(item => item.length > 1), lengths.reduce((sum, value) => sum + value, 0), items.concat(['z']), items.map((item, position) => item + position),
    merged, Object.keys(merged), assigned, seen.size, index.get('b'), index.has('zz'), total, getTag(tagged, 'kind'), getTag(tagged, 'none'), getTag({ ...tagged }, 'kind'),
    head, second, caught, add(2, 3), before, post, counter(1), counter(1, 5), counter(1, undefined, 'k'), LIMITS.high, LIMITS.names.includes(items[0] ?? ''), LIMITS.nested.flag,
    items[items.length - 1], items[-1], items[99], record.missing, { empty: null, absent: undefined, zero: 0, text: '' }, items.length ? 'some' : 'none', [1, 2, 3].map(value => String(value)),
  ];
}
