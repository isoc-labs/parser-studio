# Phase 3 P2: per-event independent parsing - baseline at b03f72a (2026-11-22)

Scope: what the product does today with a multi-event sample whose events differ in type or quality. This is a
measurement and a set of characterization tests. No product code was changed for P2 in this step.

## Method

- Browser reading: `preview(sample, {format: 'auto'})`, the first scan `analyzeLogEnvelopes`, and the adoption
  step `buildSourceReviewedBoundedDraft`, called the way `AutoParser.tsx` calls them.
- Source witness: the real Multi-Pass preview (`runtime/multipass`, `preview_batch`), not a permissive stand-in.
- Journey gate: the condition of `AutoParser.tsx` for the beginner journey (`beginnerResolved`): every event
  `SOURCE_PARSED` by the witness and `RECOGNIZED` by the first scan, or an adopted bounded draft whose suite is
  complete.
- Samples: SYNTHETIC, written after documented formats (RFC 3164 key=value, JSON, CEF, PAN-OS CSV without a
  PRI). They are not vendor originals.
- Scripts: `ps-takeover-scratch/p2/p2.py`, `p2.mts` on dev-atlas (not in the repository).

## Result per sample

| Sample | Events | Native verdicts (browser) | Witness | Journey |
|---|---|---|---|---|
| one family x3 (control) | 3 | FULL, FULL, FULL | all SOURCE_PARSED | goes on |
| Syslog key=value + JSON + CEF | 3 | FULL (syslog_rfc3164), FULL (json), FULL (cef) | all SOURCE_PARSED | goes on |
| the same, reversed | 3 | same verdict per event | same | goes on |
| key=value + JSON + key=value | 3 | FULL, FULL, FULL | all SOURCE_PARSED | goes on |
| three good + one with an unclosed quote | 4 | FULL, FULL, UNKNOWN, FULL | third PARTIAL (KV_QUOTE_UNCLOSED) | blocked |
| three good + one free-text line | 4 | FULL, UNKNOWN, FULL, FULL | second RAW_ONLY | blocked |
| RFC 3164 with PRI + the same record without PRI | 3 | FULL, UNKNOWN, FULL | all SOURCE_PARSED (the PRI-less line as BSD_SYSLOG+KV) | blocked |
| PAN-OS TRAFFIC + THREAT + SYSTEM, no PRI | 3 | UNKNOWN x3 natively (positional CSV without names) | all SOURCE_PARSED; only TRAFFIC has a column table | not adopted by the bounded compiler; left to the CSV column review, whose columns differ per record type |

## What holds

- Every event has its own verdict, and it is the verdict the event gets alone. Checked for five groups of
  events in every order (`src/guided/perEventIndependence20261122.test.ts`, 17 tests): different log types, good
  and damaged events, a delimited list beside a line with an unread pair and a truncated JSON record, Syslog
  with and without a PRI, PAN-OS record types beside a Syslog line. Fields are compared as well as verdicts.
- A declined event keeps no field; a partly read event keeps what was read and is PARTIAL.
- The counts of the suite count each verdict once (3 extracted, 1 failure for one damaged event among three).

## What does not hold yet (open work, in priority order)

1. One declined event blocks the whole beginner journey. The verdicts are per event, but a parser can only be
   generated when every event was read. Whether a sample with declined events may go on - and what the
   generated parser then does with such an event at run time - is a product decision that has not been made.
   Nothing is hidden today: the declined event is shown and the journey stops.
2. An RFC 3164 record without a PRI is not read by the browser grammar (and therefore not by the generated
   Ruby), while the Python preview reads it. Alone, such a sample is adopted through the bounded compiler; in a
   sample that also holds natively read events it is not. This is an executor mismatch in the shared grammar.
3. PAN-OS THREAT and SYSTEM have no column table; only TRAFFIC is named. A sample that mixes the record types
   is not adopted.
4. The verdict name DECLINED does not exist in the product; the equivalents are UNKNOWN (no field extracted)
   and ERROR (the extractor raised).
5. Browser versus generated Ruby per event: measured by the Chromium journeys for the single-family and
   mixed-type samples of the Phase 3 set (see the E2E evidence, tag recorded in the handoff); not yet measured
   for samples whose journey is blocked, because no parser is generated for them.
