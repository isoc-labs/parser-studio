import {describe,expect,it} from 'vitest';
import {portableRegexIssue} from '../backend/src/portable-regex';
import {validatePreviewRegexPattern} from './regexSafety';
import {extractPortableRegexFields} from './portableRegexExtraction';

const bad=[
  String.raw`^(?<field>\A\d+)$`,
  String.raw`^(?<field>\d+\z)$`,
  String.raw`^(?<field>\h+)$`,
  String.raw`^(?<field>[\h]+)$`,
  String.raw`^(?<field>[[:digit:]]+)$`,
  String.raw`^(?<field>.*.*.*.*.*.*)b$`,
  String.raw`^(?<field>[ab]*[ab]*[ab]*[ab]*[ab]*)c$`,
  String.raw`^(?<field>a{0,128}a{0,128}a{0,128}a{0,128})b$`,
  String.raw`^(?<field>.*a.*a.*a.*a.*a.*)z$`,
  // An optional part that can be empty and holds a capture: unset in ECMAScript, the empty string in Ruby.
  String.raw`-(?<sep>={0,2})?(?<rest>x+)`,
  String.raw`(?:(?<a>x?))?z`,
  String.raw`(?:w|(?<a>x?))?z`,
  String.raw`^(?<a>\d*)?$`,
];
const good=[
  String.raw`^action=(?<action>\w+)$`,
  String.raw`(?<field>tcp|udp)$`,
  String.raw`(?<field>[^\x22\x27\\]+)`,
  String.raw`^(?<month>\d{2})-(?<day>\d{2})\s+(?<name>\w+)$`,
  String.raw`^(?<field>\d+\s+)$`,
  String.raw`(?:q(?<a>x?))?z`,
  String.raw`(?: user=(?<user>\S*))?$`,
  String.raw`-(?<sep>=?)(?<rest>x+)`,
];

describe('single portable regex policy — browser',()=>{
  it.each(bad)('rejects an invalid dialect or ambiguous repetition: %s',pattern=>{
    expect(portableRegexIssue(pattern)).not.toBeNull();
    expect(validatePreviewRegexPattern(pattern)).toMatch(/unsupported|expensive/i);
  });
  it.each(good)('preserves supported common grammar: %s',pattern=>{
    expect(portableRegexIssue(pattern)).toBeNull();
    expect(validatePreviewRegexPattern(pattern)).toBeNull();
  });
});

describe('the end anchor in the browser preview',()=>{
  // V8 tries a match between the two halves of an astral character, and there a negative look-ahead for
  // "any character" holds: an expression that may be empty before `$` matched in the middle of the first
  // emoji of the event and captured nothing, while Ruby matched at the end of the event (three-way Regex
  // comparison of 2026-11-15, Ruby 2.4.9 and 3.2.11 agreeing with each other).
  it.each([
    [String.raw`(?<f0><*$)`,"'　]s[\u{1F600}<",{f0:'<'}],
    [String.raw`(?<tail>[a-z]*)$`,'id=7 \u{1F600} deny',{tail:'deny'}],
    [String.raw`(?<f0>=*$)`,'(Z~s\u{1F600}s',{f0:''}],
    [String.raw`(?<a>\d+) (?<b>\w*)$`,'\u{1F512} 42 ok',{a:'42',b:'ok'}],
  ])('reads %s at the end of %j',(pattern,raw,fields)=>{
    expect(validatePreviewRegexPattern(pattern)).toBeNull();
    expect(extractPortableRegexFields(raw,pattern)).toEqual({fields,errors:[]});
  });
});
