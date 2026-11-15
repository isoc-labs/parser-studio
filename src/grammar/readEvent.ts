/**
 * Reading one event: extraction and the Parsing Success Contract together.
 *
 * readEvent is what the generated Ruby parser executes for every event (as its translation,
 * scripts/grammar/ts2rb) and what the browser preview grades an event with. A result is a parsed event only
 * when its status is FULL; "the extractor returned no error" is never enough (src/grammar/parseStatus.ts).
 */
import { bodyKindOf, type StructuredExtraction } from '../structuredFamilies';
import { inspectDeclaredForwarders, type ForwarderHop } from '../guided/declaredForwarder';
import { extractEvent, type ExtractionSettings } from './extractEvent';
import { classifyGenericStructural } from './genericParseStatus';
import { classifyStructuredParse, type ParseVerdict } from './parseStatus';

export interface EventReading {
  fields: Record<string, unknown>;
  errors: string[];
  status: 'FULL' | 'PARTIAL' | 'UNKNOWN' | 'ERROR';
  reasons: string[];
  /** Keys of key=value pairs that are visible in the event text and missing from the fields. */
  lostKeys: string[];
  /** The relay envelopes that were removed, outermost first. */
  forwarderHops: ForwarderHop[];
}

/** The verdict on an extraction the caller already holds. */
export function gradeExtraction(raw: string, settings: ExtractionSettings, extraction: StructuredExtraction): ParseVerdict {
  if (settings.format === 'generic_structural') return classifyGenericStructural(raw, extraction);
  // A key=value body is known from the settings (format kv, or Syslog with body kv) or from what the extractor
  // says it parsed (an `auto` body that resolved to key=value, the key=value branches of a mixed allowlist).
  const keyValueBody = settings.format === 'kv' || bodyKindOf(extraction) === 'kv' ||
    ((settings.format === 'syslog_rfc3164' || settings.format === 'syslog_rfc5424') && settings.syslogBodyFormat === 'kv');
  return classifyStructuredParse(raw, extraction, keyValueBody ? 'kv' : 'other');
}

export function readEvent(raw: string, settings: ExtractionSettings): EventReading {
  // Only a declared relay host and a complete Syslog envelope qualify for removal; anything else about a
  // relayed event that cannot be replayed exactly declines it.
  const relay = inspectDeclaredForwarders(raw, settings.forwarder);
  if (relay.status === 'ABSTAIN_UNSAFE') {
    const reason = 'The forwarded log cannot be safely unwrapped: ' + relay.reason;
    return { fields: {}, errors: [reason], status: 'UNKNOWN', reasons: [reason], lostKeys: [], forwarderHops: [] };
  }
  const source = relay.status === 'UNWRAPPED' ? relay.payload : raw;
  const extraction = extractEvent(source, settings);
  const verdict = gradeExtraction(source, settings, extraction);
  return {
    fields: extraction.fields, errors: extraction.errors, status: verdict.status, reasons: verdict.reasons,
    lostKeys: verdict.lostPairs.map(pair => pair.key), forwarderHops: relay.hops,
  };
}
