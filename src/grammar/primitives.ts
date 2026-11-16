/**
 * Primitives of the shared grammar.
 *
 * The grammar modules (structured families, Generic Structural and what they reach) are written once, here in
 * TypeScript. The browser executes them as written; the Ruby of the generated parser is derived from them by
 * scripts/grammar/ts2rb. The functions of this module are the exception: each has a hand written Ruby
 * counterpart of the same name (psg_<snake_case>, backend/templates/grammar-runtime.rb.tpl), because it
 * stands for something the two runtimes do differently. The primitive conformance test runs both sides on
 * the same inputs.
 */

/** Match of a sticky (y) expression that starts exactly at `position`, or null. */
export function matchAt(expression: RegExp, text: string, position: number): RegExpExecArray | null {
  expression.lastIndex = position;
  return expression.exec(text);
}

/** Offset just after a match, in UTF-16 code units like every string offset of the grammar. */
export function matchEnd(match: RegExpExecArray): number {
  return match.index + match[0].length;
}

/** Named groups of a match by name; a group that took no part in the match is undefined. */
export function namedGroups(match: RegExpMatchArray): Record<string, string | undefined> {
  return { ...match.groups };
}

const TAGS = new WeakMap<object, Record<string, string | boolean>>();

/** Attach a note to a result object. The note is not a field: it is neither enumerated nor copied. */
export function setTag<T extends object>(target: T, name: string, value: string | boolean): T {
  const tags = TAGS.get(target) ?? {};
  tags[name] = value;
  TAGS.set(target, tags);
  return target;
}

export function getTag(target: object, name: string): string | boolean | undefined {
  return TAGS.get(target)?.[name];
}

/** False when the text holds an unpaired UTF-16 surrogate (which Ruby's UTF-8 strings cannot hold at all). */
export function isWellFormed(text: string): boolean {
  return new TextDecoder('utf-8', { ignoreBOM: true }).decode(new TextEncoder().encode(text)) === text;
}
