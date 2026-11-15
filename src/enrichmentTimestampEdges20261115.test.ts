// Independent audit of 2026-11-15 (A4): an enrichment constant for `timestamp` written with white space around
// it was a field error for every event in the browser preview, while the generated parser (which reads the text
// with the typed-value reader, edges set aside) emitted and classified every event.
import { describe, expect, it } from 'vitest';
import { canonicalOfficialScalarValid } from '../backend/src/canonical-value-contract';
import { meetsStellar7ValueConstraints } from './stellar7ValueConstraints';

describe('an official timestamp text with ASCII white space at its edges', () => {
  it.each([' 2024-05-01T10:00:00Z ', '2024-05-01T10:00:00Z', '\t2024-05-01T10:00:00+09:00\n'])('is valid like in the generated parser: %j', (text) => {
    expect(canonicalOfficialScalarValid('timestamp', text)).toBe(true);
    expect(meetsStellar7ValueConstraints('timestamp', text, text)).toBe(true);
  });
  it.each(['2024-05-01 10:00:00', ' ', ' 2024-05-01T10:00:00Z', '2024-02-30T10:00:00Z'])('still refuses %j', (value) => {
    expect(canonicalOfficialScalarValid('timestamp', value)).toBe(false);
  });
});
