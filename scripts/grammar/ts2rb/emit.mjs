// TypeScript (restricted grammar subset) -> Ruby 2.4 emitter.
//
// The grammar is written once, in TypeScript, and executed as written by the browser. This emitter derives
// the Ruby that the generated parser executes. It is type directed (the TypeScript checker decides whether
// `.length`, `.slice`, `[i]` act on a string, an array, a match or a record) and fail closed: a construct
// without a defined translation is reported and the generation fails, it is never guessed.
//
// Value model in Ruby: string -> String (UTF-8, addressed in UTF-16 code units by the psg_* primitives),
// number -> Integer/Float, boolean -> true/false, undefined -> nil, null -> :psg_null (always, so the two
// stay distinct exactly as in ECMAScript), array -> Array, record -> Hash with String keys, RegExp match ->
// MatchData, Set/Map -> Hash, function value -> lambda / Method.
import { toRubyRegexp } from './regex.mjs';

const RESERVED = new Set(('alias and begin break case class def defined do else elsif end ensure false for if in module next ' +
  'nil not or redo rescue retry return self super then true undef unless until when while yield loop lambda proc raise ' +
  'method format p puts print binding test').split(' '));

export function rubyString(value) {
  if (/^[\x20-\x7e]*$/.test(value)) return "'" + value.replace(/[\\']/g, m => '\\' + m) + "'";
  let out = '"';
  for (const char of value) {
    const codePoint = char.codePointAt(0);
    if (char === '"' || char === '\\' || char === '#') out += '\\' + char;
    else if (codePoint >= 0x20 && codePoint < 0x7f) out += char;
    else if (codePoint >= 0xd800 && codePoint <= 0xdfff) throw new Error('a lone surrogate cannot be written in Ruby');
    else out += '\\u{' + codePoint.toString(16) + '}';
  }
  return out + '"';
}

export function rubyNumber(value) {
  if (Number.isNaN(value)) return 'Float::NAN';
  if (!Number.isFinite(value)) return value > 0 ? 'Float::INFINITY' : '-Float::INFINITY';
  if (Number.isInteger(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER) return String(value);
  return String(value).includes('e') || String(value).includes('.') ? String(value).replace(/^(-?\d+)e/, '$1.0e') : String(value) + '.0';
}

export function rubyValue(value, faults) {
  if (value === null || value === undefined) return 'nil';
  if (typeof value === 'string') return rubyString(value);
  if (typeof value === 'number') return rubyNumber(value);
  if (typeof value === 'boolean') return String(value);
  if (value instanceof RegExp) return `/${toRubyRegexp(value.source, value.flags, faults).body}/`;
  if (Array.isArray(value)) return '[' + value.map(item => rubyValue(item, faults)).join(', ') + ']';
  if (value instanceof Set) return '{' + [...value].map(item => `${rubyValue(item, faults)} => true`).join(', ') + '}';
  if (value instanceof Map) return '{' + [...value].map(([k, v]) => `${rubyValue(k, faults)} => ${rubyValue(v, faults)}`).join(', ') + '}';
  if (typeof value === 'object') return '{' + Object.entries(value).map(([k, v]) => `${rubyString(k)} => ${rubyValue(v, faults)}`).join(', ') + '}';
  throw new Error(`a ${typeof value} cannot be a grammar constant`);
}

export function createEmitter(ctx) {
  const { ts, checker } = ctx;
  const K = ts.SyntaxKind;
  const faults = ctx.faults ?? new Set();
  let state = null;

  const fail = (node, message) => { ctx.fail(node, message); return 'PSG_UNSUPPORTED'; };
  const skip = node => {
    while (node && (ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node) || ts.isAsExpression(node) ||
      ts.isSatisfiesExpression(node) || ts.isTypeAssertionExpression(node))) node = node.expression;
    return node;
  };
  const resolve = node => {
    let symbol = checker.getSymbolAtLocation(node);
    if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    return symbol;
  };

  // ---- types -------------------------------------------------------------------------------------------
  const kindsOfType = type => {
    const out = new Set();
    const visit = t => {
      if (t.isUnion()) { t.types.forEach(visit); return; }
      const f = t.flags, F = ts.TypeFlags;
      if (f & F.StringLike) out.add('str');
      else if (f & (F.NumberLike | F.BigIntLike)) out.add('num');
      else if (f & F.BooleanLike) out.add('bool');
      else if (f & F.Null) out.add('null');
      else if (f & (F.Undefined | F.Void)) out.add('undef');
      else if (f & (F.Any | F.Unknown)) out.add('any');
      else if (f & F.Never) { /* no value */ }
      else if (f & F.ESSymbolLike) out.add('sym');
      else if (f & (F.TypeParameter | F.IndexedAccess | F.Conditional | F.Substitution | F.Index)) {
        const constraint = checker.getBaseConstraintOfType(t);
        if (constraint && constraint !== t) visit(constraint); else out.add('any');
      } else if (t.isIntersection()) {
        const inner = new Set();
        t.types.forEach(part => kindsOfType(part).forEach(kind => inner.add(kind)));
        out.add(inner.has('arr') ? 'arr' : inner.has('match') ? 'match' : inner.has('str') ? 'str' : 'hash');
      } else if (f & F.Object) {
        const name = String(t.symbol?.escapedName ?? '');
        if (checker.isArrayType(t) || checker.isTupleType(t) || name === 'Uint8Array' || /Iterator$/.test(name)) out.add('arr');
        else if (name === 'RegExpExecArray' || name === 'RegExpMatchArray') out.add('match');
        else if (name === 'RegExp') out.add('re');
        else if (name === 'Set' || name === 'ReadonlySet') out.add('set');
        else if (name === 'Map' || name === 'ReadonlyMap') out.add('map');
        else if (t.getCallSignatures().length) out.add('fn');
        else out.add('hash');
      } else out.add('any');
    };
    visit(type);
    return out;
  };
  const kinds = node => kindsOfType(checker.getTypeAtLocation(node));
  const core = k => new Set([...k].filter(kind => kind !== 'null' && kind !== 'undef'));
  const only = (k, ...allowed) => { const c = core(k); return c.size > 0 && [...c].every(kind => allowed.includes(kind)); };
  const nullish = k => k.has('null') || k.has('undef');

  // ---- names -------------------------------------------------------------------------------------------
  const localName = symbol => {
    if (!symbol) return 'PSG_UNRESOLVED';
    let name = state.names.get(symbol);
    if (name) return name;
    let base = String(symbol.escapedName);
    if (RESERVED.has(base) || !/^[a-z_][A-Za-z0-9_]*$/.test(base) || base.startsWith('psg_')) base = 'v_' + base.replace(/[^A-Za-z0-9_]/g, '_');
    name = base;
    for (let index = 2; state.used.has(name); index += 1) name = `${base}_${index}`;
    state.used.add(name);
    state.names.set(symbol, name);
    return name;
  };
  const temp = () => `psg_t${++state.temps}`;

  // ---- constants ---------------------------------------------------------------------------------------
  const isPrimitive = value => value === null || value === undefined || ['string', 'number', 'boolean'].includes(typeof value);
  const fold = node => {
    node = skip(node);
    if (ts.isStringLiteralLike(node)) return { value: node.text };
    if (ts.isNumericLiteral(node)) return { value: Number(node.text) };
    if (ts.isIdentifier(node)) {
      const g = ctx.global(resolve(node));
      return g && g.kind === 'const' ? { value: g.value, global: g } : null;
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const base = fold(node.expression);
      if (!base) return null;
      const key = ts.isPropertyAccessExpression(node) ? { value: node.name.text } : fold(node.argumentExpression);
      if (!key || !isPrimitive(key.value)) return null;
      const value = base.value;
      if (value instanceof RegExp) return key.value === 'source' ? { value: value.source } : key.value === 'flags' ? { value: value.flags } : null;
      if (typeof value === 'string' || Array.isArray(value)) {
        if (key.value === 'length') return { value: value.length };
        return Array.isArray(value) && Number.isInteger(key.value) && key.value >= 0 && key.value < value.length ? { value: value[key.value] } : null;
      }
      if (value && typeof value === 'object' && !(value instanceof Set) && !(value instanceof Map) &&
        Object.prototype.hasOwnProperty.call(value, key.value)) return { value: value[key.value] };
    }
    return null;
  };
  const regexCode = (node, source, flags, anyFlags) => {
    try {
      const translated = toRubyRegexp(source, flags, faults);
      if (!anyFlags && (translated.sticky || translated.global))
        return { code: fail(node, 'a sticky or global RegExp is only usable through matchAt / replace / replaceAll / matchAll / split'), meta: translated };
      return { code: `/${translated.body}/`, meta: translated };
    } catch (error) {
      return { code: fail(node, error.message), meta: { global: false, sticky: false, names: [] } };
    }
  };
  // A RegExp known at generation time: a literal or a module constant.
  const regexOf = (node, anyFlags) => {
    const inner = skip(node);
    if (inner.kind === K.RegularExpressionLiteral) {
      const end = inner.text.lastIndexOf('/');
      return regexCode(inner, inner.text.slice(1, end), inner.text.slice(end + 1), anyFlags);
    }
    const folded = fold(inner);
    return folded && folded.value instanceof RegExp ? regexCode(inner, folded.value.source, folded.value.flags, anyFlags) : null;
  };
  const constant = (node, folded) => {
    const value = folded.value;
    if (isPrimitive(value)) return rubyValue(value);
    if (value instanceof RegExp) return regexCode(node, value.source, value.flags, false).code;
    return null;
  };

  // ---- expressions -------------------------------------------------------------------------------------
  const isNullishLiteral = node => {
    node = skip(node);
    return node.kind === K.NullKeyword || (ts.isIdentifier(node) && node.text === 'undefined' && ctx.isLib(resolve(node))) || node.kind === K.VoidExpression;
  };
  const truthy = (k, code) => {
    const c = core(k);
    // null is the :psg_null value, which Ruby would take for true.
    if (faults.has('truthiness-ruby')) return code;
    if (!k.has('null') && [...c].every(kind => ['bool', 'hash', 'arr', 'match', 're', 'set', 'map', 'fn'].includes(kind))) return code;
    return `psg_t(${code})`;
  };
  // x === null, x === undefined, x == null.
  const nullTest = (code, nullLiteral, loose) => (loose ? `psg_null?(${code})` : nullLiteral ? `${code}.equal?(:psg_null)` : `${code}.nil?`);
  const cond = node => {
    const inner = skip(node);
    if (ts.isPrefixUnaryExpression(inner) && inner.operator === K.ExclamationToken) return `!${cond(inner.operand)}`;
    if (ts.isBinaryExpression(inner) && (inner.operatorToken.kind === K.AmpersandAmpersandToken || inner.operatorToken.kind === K.BarBarToken))
      return `(${cond(inner.left)} ${inner.operatorToken.kind === K.BarBarToken ? '||' : '&&'} ${cond(inner.right)})`;
    return truthy(kinds(inner), expr(inner));
  };
  const str = node => (only(kinds(node), 'str') && !nullish(kinds(node)) ? expr(node) : `psg_str(${expr(node)})`);

  const ident = node => {
    const symbol = resolve(node);
    if (symbol && ctx.isLib(symbol)) {
      if (node.text === 'undefined') return 'nil';
      if (node.text === 'NaN') return 'Float::NAN';
      if (node.text === 'Infinity') return 'Float::INFINITY';
      return fail(node, `global ${node.text} has no translation`);
    }
    const g = symbol && ctx.global(symbol);
    if (g) {
      if (g.kind === 'const') return constant(node, { value: g.value }) ?? ctx.useConst(g);
      return `method(:${g.ruby})`;
    }
    return localName(symbol);
  };

  const groupName = node => {
    // match.groups.NAME / match.groups!.NAME / match?.groups!.NAME / match.groups['NAME']
    const holder = skip(node.expression);
    if (!ts.isPropertyAccessExpression(holder) || holder.name.text !== 'groups' || !only(kinds(holder.expression), 'match')) return null;
    const key = ts.isPropertyAccessExpression(node) ? rubyString(node.name.text) : expr(node.argumentExpression);
    return `psg_group(${expr(holder.expression)}, ${key})`;
  };
  const isEncodeCall = node => {
    const inner = skip(node);
    return ts.isCallExpression(inner) && ts.isPropertyAccessExpression(inner.expression) && inner.expression.name.text === 'encode' &&
      ts.isNewExpression(skip(inner.expression.expression)) && skip(inner.expression.expression).expression.getText() === 'TextEncoder' ? inner : null;
  };

  const propAccess = node => {
    const group = groupName(node);
    if (group) return group;
    const folded = fold(node);
    if (folded) { const code = constant(node, folded); if (code !== null) return code; }
    const name = node.name.text;
    const encode = isEncodeCall(node.expression);
    if (encode && (name === 'length' || name === 'byteLength')) return `${expr(encode.arguments[0])}.bytesize`;
    const k = kinds(node.expression);
    const optional = !!node.questionDotToken;
    const t = optional ? temp() : null;
    const receiver = optional ? t : expr(node.expression);
    const done = code => (optional ? `(psg_null?(${t} = ${expr(node.expression)}) ? nil : ${code})` : code);
    if (only(k, 'match')) {
      if (name === 'index') return done(`psg_match_index(${receiver})`);
      if (name === 'length') return done(`${receiver}.size`);
      return fail(node, `match.${name}`);
    }
    if ((name === 'length' || name === 'byteLength') && only(k, 'arr')) return done(`${receiver}.length`);
    if (name === 'length' && only(k, 'str', 'arr')) return done(faults.has('length-in-characters') ? `${receiver}.length` : `psg_len(${receiver})`);
    if (name === 'size' && only(k, 'set', 'map')) return done(`${receiver}.length`);
    if (only(k, 'hash')) return done(`${receiver}[${rubyString(name)}]`);
    return fail(node, `property .${name} on ${[...k].join('|')}`);
  };

  const elemAccess = node => {
    const group = groupName(node);
    if (group) return group;
    const folded = fold(node);
    if (folded) { const code = constant(node, folded); if (code !== null) return code; }
    const k = kinds(node.expression);
    const receiver = expr(node.expression);
    const index = skip(node.argumentExpression);
    const ik = kinds(index);
    if (only(k, 'match')) return node.questionDotToken ? `psg_at(${receiver}, ${expr(index)})` : `${receiver}[${expr(index)}]`;
    if (only(ik, 'num')) {
      if (only(k, 'arr') && ts.isNumericLiteral(index) && !node.questionDotToken) return `${receiver}[${index.text}]`;
      if (only(k, 'arr', 'str', 'any')) return `psg_at(${receiver}, ${expr(index)})`;
    }
    if (only(ik, 'str') && only(k, 'hash', 'any')) return node.questionDotToken ? `psg_get(${receiver}, ${expr(index)})` : `${receiver}[${expr(index)}]`;
    return fail(node, `element access [${[...ik].join('|')}] on ${[...k].join('|')}`);
  };

  const lvalue = node => {
    const target = skip(node);
    if (ts.isIdentifier(target)) {
      const symbol = resolve(target);
      if (ctx.global(symbol)) return fail(target, 'assignment to a module level binding');
      return localName(symbol);
    }
    if (ts.isPropertyAccessExpression(target) && only(kinds(target.expression), 'hash'))
      return `${expr(target.expression)}[${rubyString(target.name.text)}]`;
    if (ts.isElementAccessExpression(target)) {
      const k = kinds(target.expression), ik = kinds(target.argumentExpression);
      if ((only(k, 'hash', 'any') && only(ik, 'str')) || (only(k, 'arr') && only(ik, 'num')))
        return `${expr(target.expression)}[${expr(target.argumentExpression)}]`;
    }
    return fail(node, 'assignment target');
  };

  const template = node => {
    const parts = [];
    if (node.head.text) parts.push(rubyString(node.head.text));
    for (const span of node.templateSpans) {
      parts.push(str(span.expression));
      if (span.literal.text) parts.push(rubyString(span.literal.text));
    }
    return parts.length === 1 ? parts[0] : `(${parts.join(' + ')})`;
  };

  const propertyKey = name => {
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return rubyString(name.text);
    if (ts.isNumericLiteral(name)) return rubyString(String(Number(name.text)));
    if (ts.isComputedPropertyName(name)) return str(name.expression);
    return fail(name, 'property name');
  };
  const objLit = node => {
    const segments = [];
    let current = null;
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) {
        current = null;
        const k = kinds(property.expression);
        if (!only(k, 'hash') && core(k).size) fail(property, `spread of ${[...k].join('|')}`);
        segments.push({ spread: nullish(k) || !core(k).size ? `psg_spread(${expr(property.expression)})` : expr(property.expression) });
        continue;
      }
      if (!current) { current = { pairs: [] }; segments.push(current); }
      if (ts.isPropertyAssignment(property)) {
        if (ts.isIdentifier(property.name) && property.name.text === '__proto__') fail(property, '__proto__ in an object literal');
        current.pairs.push(`${propertyKey(property.name)} => ${expr(property.initializer)}`);
      } else if (ts.isShorthandPropertyAssignment(property)) {
        const symbol = checker.getShorthandAssignmentValueSymbol(property);
        const g = symbol && ctx.global(symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol);
        const value = g ? (g.kind === 'const' ? (isPrimitive(g.value) ? rubyValue(g.value) : ctx.useConst(g)) : `method(:${g.ruby})`) : localName(symbol);
        current.pairs.push(`${rubyString(property.name.text)} => ${value}`);
      } else fail(property, 'object literal member');
    }
    if (!segments.length) return '{}';
    let code = segments[0].pairs ? `{${segments[0].pairs.join(', ')}}` : `{}.merge!(${segments[0].spread})`;
    for (const segment of segments.slice(1)) code += segment.pairs ? `.merge!({${segment.pairs.join(', ')}})` : `.merge!(${segment.spread})`;
    return code;
  };
  const arrLit = node => '[' + node.elements.map(element => {
    if (ts.isSpreadElement(element)) {
      const k = kinds(element.expression);
      if (only(k, 'str')) return `*${expr(element.expression)}.chars`;
      if (only(k, 'arr')) return `*${expr(element.expression)}`;
      if (only(k, 'match')) return `*${expr(element.expression)}.to_a`;
      if (only(k, 'set')) return `*${expr(element.expression)}.keys`;
      return fail(element, `spread of ${[...k].join('|')}`);
    }
    if (element.kind === K.OmittedExpression) return 'nil';
    return expr(element);
  }).join(', ') + ']';

  const typeofTest = (operand, literal, negate) => {
    const value = expr(operand);
    const test = {
      string: `${value}.is_a?(String)`, number: `${value}.is_a?(Numeric)`, boolean: `(${value} == true || ${value} == false)`,
      undefined: `${value}.nil?`, object: `(psg_typeof(${value}) == 'object')`, function: `${value}.respond_to?(:call)`,
    }[literal];
    if (!test) return fail(operand, `typeof compared with ${literal}`);
    return negate ? `!${test}` : test;
  };

  const binary = node => {
    const op = node.operatorToken.kind;
    const L = node.left, R = node.right;
    const assign = { [K.PlusEqualsToken]: '+', [K.MinusEqualsToken]: '-', [K.AsteriskEqualsToken]: '*' }[op];
    if (op === K.EqualsToken) {
      if (ts.isArrayLiteralExpression(skip(L)) || ts.isObjectLiteralExpression(skip(L))) return fail(node, 'destructuring assignment');
      const target = skip(L);
      if (ts.isPropertyAccessExpression(target) && target.name.text === 'length' && only(kinds(target.expression), 'arr') && skip(R).getText() === '0')
        return `${expr(target.expression)}.clear`;
      return `(${lvalue(L)} = ${expr(R)})`;
    }
    if (assign) {
      const lk = kinds(L), rk = kinds(R);
      if (assign === '+' && only(lk, 'str') && !nullish(lk)) return `(${lvalue(L)} += ${str(R)})`;
      if (only(lk, 'num') && only(rk, 'num') && !nullish(lk) && !nullish(rk)) return `(${lvalue(L)} ${assign}= ${expr(R)})`;
      return fail(node, `compound assignment on ${[...lk].join('|')} and ${[...rk].join('|')}`);
    }
    if (op === K.QuestionQuestionEqualsToken) { const target = lvalue(L); return `(psg_null?(${target}) ? (${target} = ${expr(R)}) : ${target})`; }
    if (op === K.AmpersandAmpersandToken || op === K.BarBarToken) {
      const lk = kinds(L), rk = kinds(R);
      if (only(lk, 'bool') && !nullish(lk) && only(rk, 'bool') && !nullish(rk)) return `(${cond(L)} ${op === K.BarBarToken ? '||' : '&&'} ${cond(R)})`;
      const t = temp();
      const test = truthy(lk, `(${t} = ${expr(L)})`);
      return op === K.BarBarToken ? `(${test} ? ${t} : ${expr(R)})` : `(${test} ? ${expr(R)} : ${t})`;
    }
    if (op === K.QuestionQuestionToken) { const t = temp(); return `(psg_null?(${t} = ${expr(L)}) ? ${expr(R)} : ${t})`; }
    const equality = op === K.EqualsEqualsEqualsToken || op === K.EqualsEqualsToken, inequality = op === K.ExclamationEqualsEqualsToken || op === K.ExclamationEqualsToken;
    if (equality || inequality) {
      const loose = op === K.EqualsEqualsToken || op === K.ExclamationEqualsToken;
      const nullSide = isNullishLiteral(L) ? R : isNullishLiteral(R) ? L : null;
      if (nullSide) {
        const literal = skip(nullSide === R ? L : R);
        const test = nullTest(expr(nullSide), literal.kind === K.NullKeyword, loose);
        return inequality ? `!${test}` : test;
      }
      if (loose) return fail(node, 'loose equality of two values');
      const typeofSide = ts.isTypeOfExpression(skip(L)) ? [skip(L), R] : ts.isTypeOfExpression(skip(R)) ? [skip(R), L] : null;
      if (typeofSide && ts.isStringLiteralLike(skip(typeofSide[1]))) return typeofTest(typeofSide[0].expression, skip(typeofSide[1]).text, inequality);
      const lk = kinds(L), rk = kinds(R);
      const objectLike = k => [...core(k)].some(kind => ['hash', 'arr', 'set', 'map', 'match', 're', 'fn'].includes(kind));
      if (objectLike(lk) && objectLike(rk)) return `${inequality ? '!' : ''}${expr(L)}.equal?(${expr(R)})`;
      return `(${expr(L)} ${inequality ? '!=' : '=='} ${expr(R)})`;
    }
    const comparison = { [K.LessThanToken]: '<', [K.GreaterThanToken]: '>', [K.LessThanEqualsToken]: '<=', [K.GreaterThanEqualsToken]: '>=' }[op];
    if (comparison) {
      const lk = kinds(L), rk = kinds(R);
      const same = (only(lk, 'num') && only(rk, 'num')) || (only(lk, 'str') && only(rk, 'str'));
      if (!same || nullish(lk) || nullish(rk)) return fail(node, `comparison of ${[...lk].join('|')} with ${[...rk].join('|')}`);
      return `(${expr(L)} ${comparison} ${expr(R)})`;
    }
    if (op === K.PlusToken) {
      const lk = kinds(L), rk = kinds(R);
      if (only(lk, 'num') && only(rk, 'num') && !nullish(lk) && !nullish(rk)) return `(${expr(L)} + ${expr(R)})`;
      if ((only(lk, 'str') && !nullish(lk)) || (only(rk, 'str') && !nullish(rk))) return `(${str(L)} + ${str(R)})`;
      return `psg_add(${expr(L)}, ${expr(R)})`;
    }
    if (op === K.MinusToken || op === K.AsteriskToken) {
      const lk = kinds(L), rk = kinds(R);
      if (!only(lk, 'num') || !only(rk, 'num') || nullish(lk) || nullish(rk)) return fail(node, 'arithmetic on a non number');
      // A product can leave the range in which Ruby integers and ECMAScript numbers agree.
      return op === K.MinusToken ? `(${expr(L)} - ${expr(R)})` : `psg_mul(${expr(L)}, ${expr(R)})`;
    }
    if (op === K.SlashToken) return `psg_div(${expr(L)}, ${expr(R)})`;
    if (op === K.PercentToken) return `psg_mod(${expr(L)}, ${expr(R)})`;
    if (op === K.InKeyword) return `${expr(R)}.key?(${str(L)})`;
    return fail(node, `operator ${K[op]}`);
  };

  const callback = node => {
    const inner = skip(node);
    return ts.isArrowFunction(inner) || ts.isFunctionExpression(inner) ? lambda(inner) : expr(inner);
  };
  const args = (node, regexArgs) => node.arguments.map(argument => {
    if (ts.isSpreadElement(argument)) return fail(argument, 'spread argument');
    const regex = regexArgs ? regexOf(argument, true) : null;
    return regex ? regex.code : expr(argument);
  }).join(', ');

  const stringMethod = (node, name, receiver, A) => {
    const a = index => expr(A[index]);
    switch (name) {
      case 'slice': case 'substring': return `psg_${name}(${[receiver, ...A.map(expr)].join(', ')})`;
      case 'includes': return `${receiver}.include?(${a(0)})`;
      case 'startsWith': return A.length === 1 ? `${receiver}.start_with?(${a(0)})` : `psg_starts_with(${receiver}, ${a(0)}, ${a(1)})`;
      case 'endsWith': return A.length === 1 ? `${receiver}.end_with?(${a(0)})` : fail(node, 'endsWith with a position');
      case 'indexOf': return `psg_index(${[receiver, ...A.map(expr)].join(', ')})`;
      case 'lastIndexOf': return A.length === 1 ? `psg_rindex(${receiver}, ${a(0)})` : fail(node, 'lastIndexOf with a position');
      case 'split': {
        const regex = regexOf(A[0], true);
        if (faults.has('split-ruby')) return `${receiver}.split(${regex ? regex.code : a(0)})`;
        return `psg_split(${[receiver, regex ? regex.code : a(0), ...A.slice(1).map(expr)].join(', ')})`;
      }
      case 'replace': case 'replaceAll': {
        const regex = regexOf(A[0], true);
        if (!regex && !only(kinds(A[0]), 'str')) return fail(node, 'replace with a pattern that is not known at generation time');
        const all = regex ? regex.meta.global : name === 'replaceAll';
        if (regex && name === 'replaceAll' && !regex.meta.global) return fail(node, 'replaceAll with a non global RegExp');
        if (ts.isStringLiteralLike(skip(A[1])) && skip(A[1]).text.includes('$')) return fail(node, 'replacement text with $');
        return `psg_replace(${receiver}, ${regex ? regex.code : a(0)}, ${all}, ${callback(A[1])})`;
      }
      case 'match': {
        const regex = regexOf(A[0], true);
        if (regex && (regex.meta.global || regex.meta.sticky)) return fail(node, 'match with a global or sticky RegExp');
        return `(${regex ? regex.code : a(0)}.match(${receiver}) || :psg_null)`;
      }
      case 'matchAll': { const regex = regexOf(A[0], true); return regex ? `psg_match_all(${receiver}, ${regex.code})` : fail(node, 'matchAll pattern'); }
      case 'charCodeAt': return `psg_char_code_at(${receiver}, ${A.length ? a(0) : '0'})`;
      case 'codePointAt': return `psg_code_point_at(${receiver}, ${A.length ? a(0) : '0'})`;
      case 'charAt': return `(psg_at(${receiver}, ${a(0)}) || '')`;
      case 'padStart': return `psg_pad_start(${[receiver, ...A.map(expr)].join(', ')})`;
      case 'trim': return `psg_trim(${receiver}, 3)`;
      case 'trimStart': return `psg_trim(${receiver}, 1)`;
      case 'trimEnd': return `psg_trim(${receiver}, 2)`;
      case 'toLowerCase': return `psg_lower(${receiver})`;
      case 'toUpperCase': return `psg_upper(${receiver})`;
      case 'repeat': return `(${receiver} * ${a(0)})`;
      case 'toString': return receiver;
      default: return fail(node, `String#${name}`);
    }
  };
  const arrayMethod = (node, name, receiver, A) => {
    const a = index => expr(A[index]);
    switch (name) {
      case 'push': return ts.isExpressionStatement(node.parent) ? `${receiver}.push(${A.map(expr).join(', ')})` : `${receiver}.push(${A.map(expr).join(', ')}).length`;
      case 'pop': return `${receiver}.pop`;
      case 'shift': return `${receiver}.shift`;
      case 'unshift': return ts.isExpressionStatement(node.parent) ? `${receiver}.unshift(${A.map(expr).join(', ')})` : fail(node, 'value of unshift');
      case 'slice': return `psg_slice(${[receiver, ...A.map(expr)].join(', ')})`;
      case 'includes': return `${receiver}.include?(${a(0)})`;
      case 'indexOf': return `psg_index(${receiver}, ${a(0)})`;
      case 'join': return `psg_join(${receiver}, ${A.length ? a(0) : "','"})`;
      case 'concat': return `(${receiver} + ${a(0)})`;
      case 'reverse': return `${receiver}.reverse!`;
      case 'map': case 'filter': case 'some': case 'every': case 'forEach': case 'find': case 'findIndex': case 'flatMap':
        return `psg_${name.replace(/[A-Z]/g, m => '_' + m.toLowerCase())}(${receiver}, ${callback(A[0])})`;
      case 'reduce': return A.length === 2 ? `psg_reduce(${receiver}, ${callback(A[0])}, ${a(1)})` : fail(node, 'reduce without an initial value');
      case 'toString': return `psg_join(${receiver}, ',')`;
      default: return fail(node, `Array#${name}`);
    }
  };

  const staticCall = (node, owner, name, A) => {
    const a = index => expr(A[index]);
    switch (`${owner}.${name}`) {
      case 'Array.isArray': return `${a(0)}.is_a?(Array)`;
      case 'Array.from': {
        const k = kinds(A[0]);
        const encode = isEncodeCall(A[0]);
        const base = encode ? `${expr(encode.arguments[0])}.bytes` : only(k, 'str') ? `${a(0)}.chars` : only(k, 'set') ? `${a(0)}.keys` : only(k, 'arr', 'match') ? `${a(0)}.to_a` : fail(node, 'Array.from source');
        return A.length > 1 ? `psg_map(${base}, ${callback(A[1])})` : base;
      }
      case 'Number.isInteger': return `psg_integer?(${a(0)})`;
      case 'Number.isFinite': return `psg_finite?(${a(0)})`;
      case 'Number.isSafeInteger': return `psg_safe_integer?(${a(0)})`;
      case 'Number.isNaN': return `psg_nan?(${a(0)})`;
      case 'Math.max': return `[${A.map(expr).join(', ')}].max`;
      case 'Math.min': return `[${A.map(expr).join(', ')}].min`;
      case 'Math.floor': {
        const inner = skip(A[0]);
        if (ts.isBinaryExpression(inner) && inner.operatorToken.kind === K.SlashToken) return `psg_floor_div(${expr(inner.left)}, ${expr(inner.right)})`;
        return `psg_floor(${a(0)})`;
      }
      case 'Math.abs': return `${a(0)}.abs`;
      // Of a record these are the Hash methods; of anything else (an array has index keys) the primitive decides.
      case 'Object.keys': return only(kinds(A[0]), 'hash') ? `${a(0)}.keys` : `psg_keys(${a(0)})`;
      case 'Object.values': return only(kinds(A[0]), 'hash') ? `${a(0)}.values` : `psg_values(${a(0)})`;
      case 'Object.entries': return only(kinds(A[0]), 'hash') ? `${a(0)}.to_a` : `psg_entries(${a(0)})`;
      case 'Object.assign': return `psg_assign(${A.map(expr).join(', ')})`;
      case 'Object.create': return skip(A[0]).kind === K.NullKeyword && A.length === 1 ? '{}' : fail(node, 'Object.create with a prototype');
      case 'Object.fromEntries': return `${a(0)}.to_h`;
      case 'JSON.parse': return A.length === 1 ? `psg_json_parse(${a(0)})` : fail(node, 'JSON.parse with a reviver');
      case 'String.fromCharCode': case 'String.fromCodePoint': return A.length === 1 ? `psg_from_code_point(${a(0)})` : fail(node, `${name} with several code points`);
      default: return fail(node, `${owner}.${name}`);
    }
  };

  const call = node => {
    const callee = skip(node.expression);
    const A = node.arguments;
    if (ts.isIdentifier(callee)) {
      const symbol = resolve(callee);
      if (symbol && ctx.isLib(symbol)) {
        switch (callee.text) {
          case 'Number': if (faults.has('number-to-i') && only(kinds(A[0]), 'str')) return `${expr(A[0])}.to_i`;
            return only(kinds(A[0]), 'num') && !nullish(kinds(A[0])) ? expr(A[0]) : `psg_num(${expr(A[0])})`;
          case 'String': return str(A[0]);
          case 'Boolean': return `(${cond(A[0])} ? true : false)`;
          case 'parseInt': return A.length === 2 ? `psg_parse_int(${expr(A[0])}, ${expr(A[1])})` : fail(node, 'parseInt without a radix');
          default: return fail(node, `global function ${callee.text}`);
        }
      }
      const g = symbol && ctx.global(symbol);
      if (g && g.kind === 'const') return fail(node, 'call of a constant');
      if (g) return `${g.ruby}(${args(node, g.kind === 'extern')})`;
      return `${localName(symbol)}.call(${args(node, false)})`;
    }
    if (!ts.isPropertyAccessExpression(callee)) return fail(node, 'call target');
    const name = callee.name.text;
    const owner = skip(callee.expression);
    if (name === 'call' && callee.expression.getText().replace(/\s+/g, '') === 'Object.prototype.hasOwnProperty')
      return `${expr(A[0])}.key?(${str(A[1])})`;
    if (ts.isIdentifier(owner) && ctx.isLib(resolve(owner)) && ['Array', 'Number', 'Math', 'Object', 'JSON', 'String'].includes(owner.text))
      return staticCall(node, owner.text, name, A);
    if (name === 'encode' && isEncodeCall(node)) return `${expr(A[0])}.bytes`;
    const k = kinds(callee.expression);
    const optional = !!callee.questionDotToken;
    const t = optional ? temp() : null;
    const receiver = optional ? t : expr(callee.expression);
    let code;
    if (only(k, 're')) {
      const regex = regexOf(callee.expression, false);
      const pattern = regex ? regex.code : receiver;
      if (name === 'test') code = `${pattern}.match?(${expr(A[0])})`;
      else if (name === 'exec') code = `(${pattern}.match(${expr(A[0])}) || :psg_null)`;
      else code = fail(node, `RegExp#${name}`);
    } else if (only(k, 'str')) code = stringMethod(node, name, receiver, A);
    else if (only(k, 'arr')) code = arrayMethod(node, name, receiver, A);
    else if (only(k, 'match')) code = arrayMethod(node, name, `${receiver}.to_a`, A);
    else if (only(k, 'str', 'arr') && ['slice', 'includes', 'indexOf'].includes(name))
      code = name === 'includes' ? `${receiver}.include?(${expr(A[0])})` : `psg_${name === 'slice' ? 'slice' : 'index'}(${[receiver, ...A.map(expr)].join(', ')})`;
    else if (only(k, 'set')) {
      if (name === 'has') code = `${receiver}.key?(${expr(A[0])})`;
      else if (name === 'add' && ts.isExpressionStatement(node.parent)) code = `${receiver}[${expr(A[0])}] = true`;
      else if (name === 'delete' && ts.isExpressionStatement(node.parent)) code = `${receiver}.delete(${expr(A[0])})`;
      else code = fail(node, `Set#${name}`);
    } else if (only(k, 'map')) {
      if (name === 'has') code = `${receiver}.key?(${expr(A[0])})`;
      else if (name === 'get') code = `${receiver}[${expr(A[0])}]`;
      else if (name === 'set' && ts.isExpressionStatement(node.parent)) code = `${receiver}[${expr(A[0])}] = ${expr(A[1])}`;
      else if (name === 'delete' && ts.isExpressionStatement(node.parent)) code = `${receiver}.delete(${expr(A[0])})`;
      else code = fail(node, `Map#${name}`);
    } else if (only(k, 'num') && name === 'toString') code = A.length ? `${receiver}.to_s(${expr(A[0])})` : `psg_str(${receiver})`;
    else code = fail(node, `method .${name} on ${[...k].join('|')}`);
    return optional ? `(psg_null?(${t} = ${expr(callee.expression)}) ? nil : ${code})` : code;
  };

  const newExpr = node => {
    const name = node.expression.getText();
    const A = node.arguments ?? [];
    if (name === 'Set') return A.length ? `psg_set(${expr(A[0])})` : '{}';
    if (name === 'Map') return A.length ? `${expr(A[0])}.to_h` : '{}';
    if (name === 'RegExp') return fail(node, 'new RegExp inside a function: build the expression at module level');
    return fail(node, `new ${name}`);
  };

  const expr = node => {
    switch (node.kind) {
      case K.ParenthesizedExpression: case K.NonNullExpression: case K.AsExpression: case K.SatisfiesExpression: case K.TypeAssertionExpression:
        return expr(node.expression);
      case K.StringLiteral: case K.NoSubstitutionTemplateLiteral: return rubyString(node.text);
      case K.NumericLiteral: return rubyNumber(Number(node.text));
      case K.TrueKeyword: return 'true';
      case K.FalseKeyword: return 'false';
      case K.NullKeyword: return faults.has('null-is-nil') ? 'nil' : ':psg_null';
      case K.RegularExpressionLiteral: return regexOf(node, false).code;
      case K.Identifier: return ident(node);
      case K.TemplateExpression: return template(node);
      case K.PropertyAccessExpression: return propAccess(node);
      case K.ElementAccessExpression: return elemAccess(node);
      case K.CallExpression: return call(node);
      case K.NewExpression: return newExpr(node);
      case K.BinaryExpression: return binary(node);
      case K.ConditionalExpression: return `(${cond(node.condition)} ? ${expr(node.whenTrue)} : ${expr(node.whenFalse)})`;
      case K.ObjectLiteralExpression: return objLit(node);
      case K.ArrayLiteralExpression: return arrLit(node);
      case K.ArrowFunction: case K.FunctionExpression: return lambda(node);
      case K.TypeOfExpression: return `psg_typeof(${expr(node.expression)})`;
      case K.VoidExpression: return 'nil';
      case K.PrefixUnaryExpression:
        if (node.operator === K.ExclamationToken) return `!${cond(node.operand)}`;
        if (node.operator === K.MinusToken) return `(-${expr(node.operand)})`;
        if (node.operator === K.PlusToken) return `psg_num(${expr(node.operand)})`;
        if (node.operator === K.PlusPlusToken) return `(${lvalue(node.operand)} += 1)`;
        if (node.operator === K.MinusMinusToken) return `(${lvalue(node.operand)} -= 1)`;
        return fail(node, 'prefix operator');
      case K.PostfixUnaryExpression:
        return node.operator === K.PlusPlusToken ? `((${lvalue(node.operand)} += 1) - 1)` : `((${lvalue(node.operand)} -= 1) + 1)`;
      default: return fail(node, `expression ${K[node.kind]}`);
    }
  };

  // ---- functions and statements ------------------------------------------------------------------------
  const bindingNames = (name, found) => {
    if (ts.isIdentifier(name)) found.push(name);
    else for (const element of name.elements) if (!ts.isOmittedExpression(element)) bindingNames(element.name, found);
  };
  const declaredIn = fn => {
    const variables = [], functions = [];
    const walk = node => {
      if (node !== fn && ts.isFunctionLike(node)) { if (ts.isFunctionDeclaration(node) && node.name) functions.push(node); return; }
      if (ts.isVariableDeclaration(node) && !(ts.isVariableDeclarationList(node.parent) && ts.isForOfStatement(node.parent.parent))) bindingNames(node.name, variables);
      ts.forEachChild(node, walk);
    };
    if (fn.body) walk(fn.body);
    return { variables, functions };
  };
  const parameter = (node, pre) => {
    if (node.dotDotDotToken) return fail(node, 'rest parameter');
    if (ts.isIdentifier(node.name)) return localName(resolve(node.name));
    if (ts.isArrayBindingPattern(node.name) && node.name.elements.every(element => !ts.isOmittedExpression(element) && ts.isIdentifier(element.name) && !element.initializer && !element.dotDotDotToken))
      return `(${node.name.elements.map(element => localName(resolve(element.name))).join(', ')})`;
    if (ts.isObjectBindingPattern(node.name) && node.name.elements.every(element => ts.isIdentifier(element.name) && !element.initializer && !element.dotDotDotToken)) {
      const t = temp();
      for (const element of node.name.elements)
        pre.push(`${localName(resolve(element.name))} = ${t}[${rubyString((element.propertyName ?? element.name).text)}]`);
      return t;
    }
    return fail(node, 'parameter pattern');
  };
  const functionBody = (fn, out, indent, pre) => {
    const { variables, functions } = declaredIn(fn);
    const names = [...variables.map(id => localName(resolve(id))), ...functions.map(decl => localName(resolve(decl.name)))];
    if (names.length) out.push(`${indent}${names.join(' = ')} = nil`);
    for (const line of pre) out.push(indent + line);
    for (const decl of functions) out.push(`${indent}${localName(resolve(decl.name))} = ${lambda(decl)}`);
    if (ts.isBlock(fn.body)) {
      block(fn.body.statements, out, indent);
      const last = fn.body.statements[fn.body.statements.length - 1];
      if (!last || !ts.isReturnStatement(last)) out.push(`${indent}nil`);
    } else out.push(`${indent}${expr(fn.body)}`);
  };
  const lambda = fn => {
    if (fn.asteriskToken || fn.modifiers?.some(modifier => modifier.kind === K.AsyncKeyword)) return fail(fn, 'generator or async function');
    const pre = [];
    const parameters = fn.parameters.map(node => { if (node.initializer) fail(node, 'default value in a function value'); return parameter(node, pre); });
    const out = [];
    functionBody(fn, out, '  ', pre);
    const head = parameters.length ? `lambda { |${parameters.join(', ')}|` : 'lambda {';
    return out.length === 1 ? `${head} ${out[0].trim()} }` : `${head}\n${out.join('\n')}\n}`;
  };

  const containsContinue = body => {
    let found = false;
    const walk = node => {
      if (found || ts.isFunctionLike(node) || ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) return;
      if (ts.isContinueStatement(node)) { found = true; return; }
      ts.forEachChild(node, walk);
    };
    ts.forEachChild(body, walk);
    return found || ts.isContinueStatement(body);
  };
  const statementExpression = node => {
    const inner = skip(node);
    if (ts.isPostfixUnaryExpression(inner) || (ts.isPrefixUnaryExpression(inner) && (inner.operator === K.PlusPlusToken || inner.operator === K.MinusMinusToken)))
      return `${lvalue(inner.operand)} ${inner.operator === K.PlusPlusToken ? '+' : '-'}= 1`;
    const code = expr(inner);
    return ts.isBinaryExpression(inner) && code.startsWith('(') && code.endsWith(')') ? code.slice(1, -1) : code;
  };
  const variable = (declaration, line) => {
    const name = declaration.name;
    if (ts.isIdentifier(name)) { line(`${localName(resolve(name))} = ${declaration.initializer ? expr(declaration.initializer) : 'nil'}`); return; }
    const simple = name.elements.every(element => ts.isOmittedExpression(element) || (ts.isIdentifier(element.name) && !element.initializer && !element.dotDotDotToken));
    if (!simple || !declaration.initializer) { fail(declaration, 'binding pattern'); return; }
    if (ts.isArrayBindingPattern(name)) {
      const k = kinds(declaration.initializer);
      const source = only(k, 'match') ? `${expr(declaration.initializer)}.to_a` : expr(declaration.initializer);
      line(`${name.elements.map(element => (ts.isOmittedExpression(element) ? '_' : localName(resolve(element.name)))).join(', ')}, _ = ${source}`);
      return;
    }
    const t = temp();
    line(`${t} = ${expr(declaration.initializer)}`);
    for (const element of name.elements) line(`${localName(resolve(element.name))} = ${t}[${rubyString((element.propertyName ?? element.name).text)}]`);
  };
  const body = (node, out, indent) => { if (ts.isBlock(node)) block(node.statements, out, indent); else statement(node, out, indent); };
  const block = (statements, out, indent) => { for (const node of statements) statement(node, out, indent); };

  const statement = (node, out, indent) => {
    const line = text => out.push(indent + text);
    const inner = indent + '  ';
    switch (node.kind) {
      case K.VariableStatement: for (const declaration of node.declarationList.declarations) variable(declaration, line); return;
      case K.ExpressionStatement: line(statementExpression(node.expression)); return;
      case K.ReturnStatement: line(node.expression ? `return ${expr(node.expression)}` : 'return nil'); return;
      case K.IfStatement: {
        line(`if ${cond(node.expression)}`);
        body(node.thenStatement, out, inner);
        let rest = node.elseStatement;
        while (rest && ts.isIfStatement(rest)) { line(`elsif ${cond(rest.expression)}`); body(rest.thenStatement, out, inner); rest = rest.elseStatement; }
        if (rest) { line('else'); body(rest, out, inner); }
        line('end');
        return;
      }
      case K.Block: block(node.statements, out, indent); return;
      case K.WhileStatement: line(`while ${cond(node.expression)}`); body(node.statement, out, inner); line('end'); return;
      case K.ForStatement: {
        if (node.initializer) {
          if (ts.isVariableDeclarationList(node.initializer)) for (const declaration of node.initializer.declarations) variable(declaration, line);
          else line(statementExpression(node.initializer));
        }
        const test = node.condition ? cond(node.condition) : 'true';
        const step = node.incrementor ? statementExpression(node.incrementor) : null;
        if (step && containsContinue(node.statement)) {
          const first = temp();
          line(`${first} = true`);
          line('while true');
          out.push(`${inner}if ${first} then ${first} = false else ${step} end`);
          out.push(`${inner}break unless ${test}`);
          body(node.statement, out, inner);
          line('end');
        } else {
          line(`while ${test}`);
          body(node.statement, out, inner);
          if (step) out.push(inner + step);
          line('end');
        }
        return;
      }
      case K.ForOfStatement: {
        if (!ts.isVariableDeclarationList(node.initializer) || node.awaitModifier) { fail(node, 'for-of binding'); return; }
        const name = node.initializer.declarations[0].name;
        const k = kinds(node.expression);
        const found = [];
        bindingNames(name, found);
        const names = found.map(id => localName(resolve(id)));
        const source = expr(node.expression);
        let head;
        if (ts.isIdentifier(name)) {
          head = only(k, 'str') ? `${source}.each_char do |${names[0]}|` : only(k, 'arr') ? `${source}.each do |${names[0]}|` :
            only(k, 'match') ? `${source}.to_a.each do |${names[0]}|` : only(k, 'set') ? `${source}.keys.each do |${names[0]}|` : null;
        } else if (ts.isArrayBindingPattern(name) && names.length === name.elements.length) {
          head = only(k, 'arr') ? `${source}.each do |(${names.join(', ')})|` : only(k, 'map') ? `${source}.to_a.each do |(${names.join(', ')})|` : null;
        }
        if (!head) { fail(node, `for-of over ${[...k].join('|')}`); return; }
        line(head);
        body(node.statement, out, inner);
        line('end');
        return;
      }
      case K.BreakStatement: if (node.label) fail(node, 'labelled break'); line('break'); return;
      case K.ContinueStatement: if (node.label) fail(node, 'labelled continue'); line('next'); return;
      case K.TryStatement: {
        if (!node.catchClause || node.finallyBlock) { fail(node, 'try without catch, or with finally'); return; }
        line('begin');
        block(node.tryBlock.statements, out, inner);
        const variableName = node.catchClause.variableDeclaration;
        line(variableName ? `rescue StandardError => ${localName(resolve(variableName.name))}` : 'rescue StandardError');
        block(node.catchClause.block.statements, out, inner);
        line('end');
        return;
      }
      case K.ThrowStatement: {
        const thrown = skip(node.expression);
        if (ts.isNewExpression(thrown) && /Error$/.test(thrown.expression.getText()) && thrown.arguments?.length === 1) line(`raise ArgumentError, ${str(thrown.arguments[0])}`);
        else fail(node, 'throw of a non Error');
        return;
      }
      case K.FunctionDeclaration: return; // hoisted by functionBody
      case K.EmptyStatement: return;
      default: fail(node, `statement ${K[node.kind]}`);
    }
  };

  // A module level function (declaration or `const name = (...) => ...`) as a Ruby method.
  const emitFunction = (fn, rubyName) => {
    state = { names: new Map(), used: new Set(), temps: 0 };
    const pre = [];
    const defaults = [];
    const parameters = fn.parameters.map(node => {
      const text = parameter(node, pre);
      if (node.initializer) defaults.push(`${text} = ${expr(node.initializer)} if ${text}.nil?`);
      const optional = node.questionToken || node.initializer || (ts.isIdentifier(node.name) && kinds(node.name).has('undef'));
      return optional ? `${text} = nil` : text;
    });
    const out = [];
    functionBody(fn, out, '  ', [...defaults, ...pre]);
    return [`def ${rubyName}(${parameters.join(', ')})`, ...out, 'end'].join('\n');
  };

  return { emitFunction };
}
