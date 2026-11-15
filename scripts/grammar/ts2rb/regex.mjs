// Shared-grammar regular expression dialect: ECMAScript `u`-mode patterns translated to Ruby (Onigmo).
//
// The browser executes the pattern as written. The generated Ruby executes the translation produced here. A
// construct whose meaning differs between the two engines is either rewritten to an equivalent Ruby form or
// refused, so a pattern that reaches the generated parser means the same thing in both engines:
//   ^ $            -> \A \z (ECMAScript without the m flag anchors at the input, Ruby at a line)
//   .              -> every code point except LF, CR, U+2028, U+2029 (Ruby's dot excludes LF only)
//   \d \w \s \b    -> explicit ASCII / ECMAScript white space sets (Ruby's are encoding dependent)
//   a{n}?          -> a{n} (Ruby reads {n}? as an optional group, ECMAScript as a lazy exact count)
//   [ & inside a class are escaped (Ruby reads them as a nested set / an intersection)
// Refused: the i, m and v flags, \B, \D \W \S inside a class, \c, octal and identity escapes of letters,
// \p{..}, lone surrogates, an empty class, and a pattern that mixes named and unnamed capture groups (Ruby
// stops numbering unnamed groups as soon as one group is named).

export const ECMASCRIPT_WHITE_SPACE = '\\t\\n\\x0b\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff';
const WORD = 'A-Za-z0-9_';
const WORD_BOUNDARY = `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`;

export class RegexDialectError extends Error {}

// Deliberate mistranslations, for the fault injection of the gates only (TRANSLATION_FAULTS in index.mjs).
const NO_FAULTS = new Set();

export function toRubyRegexp(source, flags, faults = NO_FAULTS) {
  const where = `/${source}/${flags}`;
  for (const flag of flags) if (!'dgsuy'.includes(flag)) throw new RegexDialectError(`flag ${flag} is outside the shared dialect: ${where}`);
  if (!flags.includes('u')) throw new RegexDialectError(`the u flag is required (code point semantics in both engines): ${where}`);
  const dotAll = flags.includes('s');
  const length = source.length;
  let cursor = 0, named = 0, unnamed = 0, backreference = false;
  const names = [];
  const fail = message => { throw new RegexDialectError(`${message} at offset ${cursor}: ${where}`); };

  const literal = (codePoint, inClass) => {
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) fail('a lone surrogate cannot be written in Ruby');
    if (codePoint > 0x10ffff) fail('code point out of range');
    const char = String.fromCodePoint(codePoint);
    if (/[A-Za-z0-9_]/.test(char)) return char;
    if (codePoint < 0x20 || codePoint === 0x7f) return '\\x' + codePoint.toString(16).padStart(2, '0');
    if (codePoint > 0x7f) return '\\u{' + codePoint.toString(16) + '}';
    if (inClass) return '\\^-[]&/#'.includes(char) ? (char === '&' ? '\\x26' : '\\' + char) : char;
    return '\\^$.|?*+()[]{}/#'.includes(char) ? '\\' + char : char;
  };

  // Returns {text, single}: single is true when the escape denotes exactly one code point (a range endpoint).
  const escape = inClass => {
    const char = source[cursor + 1];
    cursor += 2;
    const one = text => ({ text, single: true });
    const many = text => ({ text, single: false });
    switch (char) {
      case 'd': return many(inClass ? '0-9' : '[0-9]');
      case 'w': return many(inClass ? WORD : `[${WORD}]`);
      case 's': if (faults.has('regex-ruby-space')) return many('\\s'); return many(inClass ? ECMASCRIPT_WHITE_SPACE : `[${ECMASCRIPT_WHITE_SPACE}]`);
      case 'D': if (inClass) fail('\\D inside a class'); return many('[^0-9]');
      case 'W': if (inClass) fail('\\W inside a class'); return many(`[^${WORD}]`);
      case 'S': if (inClass) fail('\\S inside a class'); return many(`[^${ECMASCRIPT_WHITE_SPACE}]`);
      case 'b': return inClass ? one('\\x08') : many(WORD_BOUNDARY);
      case 'n': return one('\\n');
      case 'r': return one('\\r');
      case 't': return one('\\t');
      case 'f': return one('\\f');
      case 'v': return one('\\x0b');
      case '0': if (/[0-9]/.test(source[cursor] ?? '')) fail('octal escape'); return one('\\x00');
      case 'x': {
        const digits = source.slice(cursor, cursor + 2);
        if (!/^[0-9A-Fa-f]{2}$/.test(digits)) fail('\\x escape');
        cursor += 2;
        return one(literal(parseInt(digits, 16), inClass));
      }
      case 'u': {
        if (source[cursor] === '{') {
          const end = source.indexOf('}', cursor);
          if (end < 0 || !/^[0-9A-Fa-f]{1,6}$/.test(source.slice(cursor + 1, end))) fail('\\u{} escape');
          const codePoint = parseInt(source.slice(cursor + 1, end), 16);
          cursor = end + 1;
          return one(literal(codePoint, inClass));
        }
        const digits = source.slice(cursor, cursor + 4);
        if (!/^[0-9A-Fa-f]{4}$/.test(digits)) fail('\\u escape');
        cursor += 4;
        let codePoint = parseInt(digits, 16);
        const low = /^\\u([dD][c-fC-F][0-9A-Fa-f]{2})/.exec(source.slice(cursor));
        if (codePoint >= 0xd800 && codePoint <= 0xdbff && low) {
          cursor += 6;
          codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (parseInt(low[1], 16) - 0xdc00);
        }
        return one(literal(codePoint, inClass));
      }
      case 'k': {
        const name = /^<([A-Za-z_][A-Za-z0-9_]*)>/.exec(source.slice(cursor));
        if (!name || inClass) fail('\\k escape');
        cursor += name[0].length;
        backreference = true;
        return many(`\\k<${name[1]}>`);
      }
      default:
        if (char !== undefined && /[1-9]/.test(char)) {
          if (inClass) fail('back reference inside a class');
          let digits = char;
          while (/[0-9]/.test(source[cursor] ?? '')) digits += source[cursor++];
          backreference = true;
          return many(`(?:\\${digits})`);
        }
        if (char !== undefined && '^$\\.*+?()[]{}|/-'.includes(char)) return one(literal(char.codePointAt(0), inClass));
        return fail(`escape \\${char} is outside the shared dialect`);
    }
  };

  const characterClass = () => {
    cursor += 1;
    let negated = false;
    if (source[cursor] === '^') { negated = true; cursor += 1; }
    if (source[cursor] === ']') {
      if (!negated) fail('empty class');
      cursor += 1;
      return '(?m:.)';
    }
    let body = '';
    let previousSingle = false;
    while (cursor < length && source[cursor] !== ']') {
      const char = source[cursor];
      if (char === '\\') {
        const item = escape(true);
        body += item.text;
        previousSingle = item.single;
        continue;
      }
      if (char === '-') {
        const rangeOperator = previousSingle && source[cursor + 1] !== ']' && source[cursor + 1] !== undefined;
        body += rangeOperator ? '-' : '\\-';
        cursor += 1;
        // After a range operator the next item is the upper endpoint; it cannot start another range.
        if (rangeOperator) {
          if (source[cursor] === '\\') { const item = escape(true); if (!item.single) fail('class range endpoint'); body += item.text; }
          else { const codePoint = source.codePointAt(cursor); cursor += codePoint > 0xffff ? 2 : 1; body += literal(codePoint, true); }
        }
        previousSingle = false;
        continue;
      }
      const codePoint = source.codePointAt(cursor);
      cursor += codePoint > 0xffff ? 2 : 1;
      body += literal(codePoint, true);
      previousSingle = true;
    }
    if (cursor >= length) fail('unterminated class');
    cursor += 1;
    return `[${negated ? '^' : ''}${body}]`;
  };

  let out = '';
  while (cursor < length) {
    const char = source[cursor];
    if (char === '\\') { out += escape(false).text; continue; }
    if (char === '[') { out += characterClass(); continue; }
    if (char === '(') {
      const rest = source.slice(cursor, cursor + 4);
      if (rest.startsWith('(?:') || rest.startsWith('(?=') || rest.startsWith('(?!')) { out += rest.slice(0, 3); cursor += 3; }
      else if (rest.startsWith('(?<=') || rest.startsWith('(?<!')) { out += rest; cursor += 4; }
      else if (rest.startsWith('(?<')) {
        const end = source.indexOf('>', cursor);
        const name = source.slice(cursor + 3, end);
        if (end < 0 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) fail('group name');
        names.push(name);
        named += 1;
        out += `(?<${name}>`;
        cursor = end + 1;
      } else if (rest.startsWith('(?')) fail('group syntax');
      else { unnamed += 1; out += '('; cursor += 1; }
      continue;
    }
    if (char === ')' || char === '|' || char === '*' || char === '+' || char === '?') { out += char; cursor += 1; continue; }
    if (char === '{') {
      const quantifier = /^\{([0-9]+)(,([0-9]*))?\}/.exec(source.slice(cursor));
      if (!quantifier) fail('brace');
      out += quantifier[0];
      cursor += quantifier[0].length;
      // Ruby: a{n}? is (?:a{n})?. ECMAScript: lazy, which for an exact count is the count itself.
      if (quantifier[2] === undefined && source[cursor] === '?') cursor += 1;
      continue;
    }
    if (char === '^') { out += faults.has('regex-line-anchors') ? '^' : '\\A'; cursor += 1; continue; }
    if (char === '$') { out += faults.has('regex-line-anchors') ? '$' : '\\z'; cursor += 1; continue; }
    if (char === '.') { out += dotAll ? '(?m:.)' : faults.has('regex-ruby-dot') ? '.' : '[^\\n\\r\\u2028\\u2029]'; cursor += 1; continue; }
    if (char === ']' || char === '}') fail(`unescaped ${char}`);
    const codePoint = source.codePointAt(cursor);
    cursor += codePoint > 0xffff ? 2 : 1;
    out += literal(codePoint, false);
  }
  if (named && unnamed) throw new RegexDialectError(`named and unnamed capture groups are mixed: ${where}`);
  if (named && backreference && /\(\?:\\[0-9]/.test(out)) throw new RegexDialectError(`numbered back reference with named groups: ${where}`);
  const sticky = flags.includes('y');
  return { body: sticky && !faults.has('regex-sticky-unanchored') ? `\\G(?:${out})` : out, names, global: flags.includes('g'), sticky };
}

export function rubyRegexpLiteral(source, flags) {
  return `/${toRubyRegexp(source, flags).body}/`;
}
