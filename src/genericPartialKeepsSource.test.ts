import { describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { preview } from './parser';

// Generic Structural hands over an event that is only PARTIAL (owner policy D-2). What its fields do not hold
// exists nowhere else than in the copy of the original line, so "omit the source copy" never applies to it.
const LEGACY_CEF = 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=80 act=blocked proto=tcp';
const COMPLETE = '<134>date=2023-02-23 time=22:49:29 devname=FMG-VM log_id=0001010018 type=event user=alice status=success';

const source = (raw: string, omitSourceRaw: boolean) => {
  const event = preview(raw, { ...createDraft(), format: 'generic_structural', ...(omitSourceRaw ? { omitSourceRaw: true as const } : {}) }).events[0]!;
  const generic = (event.normalized.parserstudio_source as { generic: Record<string, unknown> }).generic;
  return { status: event.parseStatus, generic };
};

describe('Generic Structural: a PARTIAL event never loses its original text', () => {
  it('keeps the copy of the original line of a PARTIAL event although the project omits source copies', () => {
    const partial = source(LEGACY_CEF, true);
    expect(partial.status).toBe('PARTIAL');
    expect(partial.generic.source_raw).toBe(LEGACY_CEF);
  });
  it('omits the copy of a FULL event as configured, and keeps it by default', () => {
    const full = source(COMPLETE, true);
    expect(full.status).toBe('FULL');
    expect(full.generic).not.toHaveProperty('source_raw');
    expect(source(COMPLETE, false).generic.source_raw).toBe(COMPLETE);
  });
  it('reads a manufacturer field named like a source copy as data: the event is FULL and the field is kept', () => {
    // Only the copies the grammar itself adds (generic.source_raw, generic.message_raw) are provenance.
    for (const name of ['source_raw', 'message_raw']) {
      const raw = '<134>date=2023-02-23 time=22:49:29 devname=FMG-VM user=alice ' + name + '=vendor-value status=success';
      const read = source(raw, true);
      expect(read.status, name).toBe('FULL');
      expect((read.generic.kv as Record<string, unknown>)[name]).toBe('vendor-value');
      expect(read.generic).not.toHaveProperty('source_raw');
    }
  });
});
