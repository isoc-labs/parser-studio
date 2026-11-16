/**
 * Parsing Success Contract for Generic Structural results (W7, owner policy D-2).
 *
 *   FULL     every key=value pair of the original line is an extracted field, or is inside a text field the
 *            mode keeps (a message, a prefix); and the line was read by the grammar it claims
 *   PARTIAL  a pair is in no field at all, or a line that claims to be CEF/LEEF was read as generic
 *            key=value (its header is not parsed): the original text is kept, the result is not complete
 *   UNKNOWN  the bounded grammar declined the line; nothing is parsed
 *   ERROR    the extractor raised
 *
 * The verdict is the same for every mode because it is decided from the original line and the result, not
 * from the mode's own grammar. The copies of the original text that every mode carries for provenance
 * (source_raw and message_raw of the nodes the grammar builds) are not counted as fields; a field of the event
 * with one of those names is.
 */
import { independentKeyValuePairs, type ParseVerdict, type RawPair, type StructuredOutcome } from './parseStatus';
import { GENERIC_FAMILY_MODES, envelopedFamilyClaim, structuredFamilyClaim } from '../genericStructural';
import { cefEventUnaccounted, jsonTextUnaccounted, leefEventUnaccounted, positionalCsvUnaccounted } from './lossGuard';
import { getTag } from './primitives';

const PROVENANCE_COPIES: readonly string[] = ['source_raw', 'message_raw'];
// The nodes the grammar itself builds and puts its copies of the original text into. A field of the event that
// happens to be called source_raw or message_raw (generic.kv.source_raw, a CEF extension key under body) is data.
const GRAMMAR_OWNED_NODES: readonly string[] = ['generic', 'watchguard_message', 'session_envelope', 'asa', 'juniper', 'watchguard'];

function collect(value: unknown, key: string, out: Array<[string, string]>): void {
  if (Array.isArray(value)) { for (const child of value) collect(child, key, out); return; }
  if (value !== null && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) collect(child, childKey, out);
    return;
  }
  if (value !== undefined && value !== null) out.push([key, String(value)]);
}

/** Every leaf of the result with its own key, without the provenance copies of the grammar-owned nodes. */
function collectFields(fields: Record<string, unknown>, out: Array<[string, string]>): void {
  for (const [name, node] of Object.entries(fields)) {
    if (!GRAMMAR_OWNED_NODES.includes(name) || node === null || typeof node !== 'object' || Array.isArray(node)) { collect(node, name, out); continue; }
    for (const [childKey, child] of Object.entries(node as Record<string, unknown>))
      if (!PROVENANCE_COPIES.includes(childKey)) collect(child, childKey, out);
  }
}

const withoutBackslashes = (text: string) => text.split('\\').join('');

/** A pair is accounted for when a field of that name holds its value, or a kept text field holds the pair as written. */
function accounted(pair: RawPair, leaves: Array<[string, string]>): boolean {
  const written = withoutBackslashes(pair.rawValue);
  return leaves.some(([key, value]) => (key === pair.key && (
    value === pair.value || value === pair.rawValue || withoutBackslashes(value) === written ||
    // A mode whose values run to the next key keeps the token and what follows it.
    value.startsWith(pair.value + ' ') || withoutBackslashes(value).startsWith(written + ' '))) ||
    (value.includes(pair.key + '=') && value.includes(pair.rawValue)));
}

/**
 * JSON, CEF, LEEF and positional CSV bodies: what of the body text the body fields do not account for
 * (src/grammar/lossGuard.ts). The extractor marks such a result with the dialect and the text it read.
 */
function bodyUnaccounted(fields: Record<string, unknown>): string | null {
  const kind = getTag(fields, 'bodyKind');
  const text = getTag(fields, 'bodyText');
  if (typeof kind !== 'string' || typeof text !== 'string') return null;
  if (kind === 'positional_csv') {
    const generic = fields.generic as { columns?: unknown; fields?: unknown } | undefined;
    const cells = generic?.columns ?? generic?.fields;
    if (cells === null || typeof cells !== 'object' || Array.isArray(cells)) return 'the CSV cells of the event body are not where the extractor reports them';
    return positionalCsvUnaccounted(text, Object.values(cells as Record<string, unknown>));
  }
  const body = fields.body;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return 'the fields of the event body are not where the extractor reports them';
  const record = body as Record<string, unknown>;
  if (kind === 'json') return jsonTextUnaccounted(text, record);
  return kind === 'cef' ? cefEventUnaccounted(text, record) : leefEventUnaccounted(text, record);
}

export function classifyGenericStructural(raw: string, outcome: StructuredOutcome | { thrown: unknown }): ParseVerdict & { mode?: string } {
  if ('thrown' in outcome) return { status: 'ERROR', lostPairs: [], reasons: ['extractor raised: ' + String(outcome.thrown)] };
  if (outcome.errors.length > 0) return { status: 'UNKNOWN', lostPairs: [], reasons: outcome.errors.slice(0, 4) };
  if (Object.keys(outcome.fields).length === 0) return { status: 'UNKNOWN', lostPairs: [], reasons: ['no field was extracted'] };
  const generic = outcome.fields.generic as { mode?: unknown } | undefined;
  const mode = typeof generic?.mode === 'string' ? generic.mode : Object.keys(outcome.fields).filter(key => key !== 'syslog').join('+');
  const reasons: string[] = [];
  const claim = structuredFamilyClaim(raw) ?? envelopedFamilyClaim(raw);
  if (claim && !GENERIC_FAMILY_MODES.includes(mode))
    reasons.push('the line claims to be ' + claim + ' but was read as generic key=value (legacy compatibility route): its ' + claim + ' header is not parsed');
  const leaves: Array<[string, string]> = [];
  collectFields(outcome.fields, leaves);
  const lostPairs = independentKeyValuePairs(raw).filter(pair => !accounted(pair, leaves));
  for (const pair of lostPairs.slice(0, 4)) reasons.push('raw pair ' + pair.key + '= is not present with its value in the extracted fields');
  const unaccounted = bodyUnaccounted(outcome.fields);
  if (unaccounted !== null) reasons.push(unaccounted);
  return { status: reasons.length > 0 ? 'PARTIAL' : 'FULL', lostPairs, reasons, mode };
}
