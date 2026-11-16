import { describe, expect, it } from 'vitest';
import { readEvent } from './readEvent';

// Independent reverse audit, 2026-11-15: `path=C:\Windows\Temp\ user=bob` was read as one value
// `C:\Windows\Temp\ user=bob` and reported FULL without the user field.
describe('key=value: an unquoted value ends at white space, also after a backslash', () => {
  const kv = (raw: string) => readEvent(raw, { format: 'kv' });
  it('keeps the pair that follows a value ending in a backslash', () => {
    const reading = kv('path=C:\\Windows\\Temp\\ user=bob src=10.0.0.5 action=deny');
    expect(reading.status, reading.reasons.join('; ')).toBe('FULL');
    expect(reading.fields).toEqual({ path: 'C:\\Windows\\Temp\\', user: 'bob', src: '10.0.0.5', action: 'deny' });
  });
  it('reads a value that ends the event in a backslash, and a TAB after a backslash', () => {
    expect(kv('user=bob path=C:\\Temp\\').fields).toEqual({ user: 'bob', path: 'C:\\Temp\\' });
    expect(kv('path=C:\\Temp\\\tuser=bob').fields).toEqual({ path: 'C:\\Temp\\', user: 'bob' });
  });
  it('reads the same body inside a Syslog envelope', () => {
    const reading = readEvent('<134>Nov 15 01:02:03 fw01 app: path=C:\\Temp\\ user=bob action=deny', { format: 'syslog_rfc3164', syslogBodyFormat: 'kv' });
    expect(reading.status).toBe('FULL');
    expect(reading.fields.body).toEqual({ path: 'C:\\Temp\\', user: 'bob', action: 'deny' });
  });
  it('does not read text after a backslash and a space as part of the value', () => {
    // "a\ b" is no longer one value: b is text outside any pair, and the event is declined, not guessed.
    expect(kv('msg=a\\ b action=deny').status).not.toBe('FULL');
  });
  it('leaves the other backslash forms as they were', () => {
    expect(kv('path=C:\\Windows\\System32 a=1').fields).toEqual({ path: 'C:\\Windows\\System32', a: '1' });
    expect(kv('msg="say \\"hi\\" now" a=1').fields).toEqual({ msg: 'say "hi" now', a: '1' });
  });
});
