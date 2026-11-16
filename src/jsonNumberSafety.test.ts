import {describe,expect,it} from 'vitest';
import {createDraft} from './model';
import {extractFields,preview} from './parser';
import {hasUnsafeJsonNumbers} from './jsonNumberSafety';

// A JSON number in decimal or exponent spelling is read as a double. It is read when the double stands for exactly
// the number that was written, and declined otherwise. The earlier rule counted digits (more than 15 declined), so
// every Zeek JSON record - `"ts":1731719701.123456`, sixteen digits printed from a double - was declined.
describe('a JSON number is read when a double stands for exactly what was written',()=>{
  it.each([
    ['epoch seconds with microseconds (Zeek ts)','1731719701.123456'],
    ['seventeen digits printed from a double','1731719701.1234567'],
    ['the classic sum','0.30000000000000004'],
    ['the next double after one','1.0000000000000002'],
    ['fifteen digits','123456789012345.6'],
    ['trailing zeros','100.000000000000000'],
    ['an exponent spelling of an integer','1e2'],
    ['negative zero','-0.0'],
    ['a small number','1.5e-7'],
  ])('reads %s: %s',(_name,number)=>{
    expect(hasUnsafeJsonNumbers('{"n":'+number+'}')).toBe(false);
  });
  it.each([
    ['more digits than a double identifies','0.1234567890123456789'],
    ['the exact expansion of the double nearest 0.1','0.1000000000000000055511151231257827'],
    ['one digit too many after seventeen','1731719701.12345678'],
    ['an integer above 2^53 in decimal spelling','9007199254740993.0'],
    ['an integer above 2^53 in exponent spelling','9.007199254740993e15'],
    ['an integer above 2^53','9007199254740993'],
    ['overflow','1e309'],
    ['underflow to zero','1e-400'],
    ['below the smallest step of a double','4.9e-324'],
  ])('declines %s: %s',(_name,number)=>{
    expect(hasUnsafeJsonNumbers('{"n":'+number+'}')).toBe(true);
  });
  it('emits the number that was written',()=>{
    const draft=createDraft();draft.format='json';
    const raw='{"ts":1731719701.123456,"uid":"CHhAvVGS1DHFjwGM9","id.orig_h":"10.1.10.25","duration":35.2}';
    const extracted=extractFields(raw,'json',draft);
    expect(extracted.errors).toEqual([]);
    expect(extracted.fields.ts).toBe(1731719701.123456);
    expect(JSON.stringify(extracted.fields.ts)).toBe('1731719701.123456');
    expect(preview(raw,draft).counts.failures).toBe(0);
  });
  it('still declines the event when one number is not exact, inside a Syslog message too',()=>{
    const draft=createDraft();draft.format='json';
    expect(extractFields('{"ts":1731719701.123456,"x":0.1234567890123456789}','json',draft).errors.join(' ')).toMatch(/precision/);
    const wrapped=createDraft();wrapped.format='syslog_rfc5424';wrapped.syslogBodyFormat='json';
    expect(extractFields('<14>1 2026-11-03T11:11:11Z fw app - ID - {"ts":1731719701.123456}','syslog_rfc5424',wrapped).errors).toEqual([]);
    expect(extractFields('<14>1 2026-11-03T11:11:11Z fw app - ID - {"ts":1731719701.12345678}','syslog_rfc5424',wrapped).errors.join(' ')).toMatch(/precision/);
  });
  it('does not read digits inside a string as a number',()=>{
    expect(hasUnsafeJsonNumbers('{"s":"0.1234567890123456789 and 9007199254740993"}')).toBe(false);
  });
});
