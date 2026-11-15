import assert from 'node:assert/strict';
import test from 'node:test';
import {portableRegexIssue} from '../src/portable-regex.js';
import {validateBoundedRegexPattern,validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';

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
 // A lazy modifier after an exact count: ECMAScript reads X{n}? as exactly n, Ruby 2.4 (Onigmo) as an optional
 // group of n. The same pattern declined ' disk full' in the browser and parsed it on Ruby with the capture absent
 // (independent audit, 2026-11-15).
 String.raw`^(?<sev>[A-Z]{4}?) (?<msg>.{1,60})$`,
 String.raw`^(?<code>\d{3}?)-(?<rest>.{0,40})$`,
 String.raw`^(?<a>a{2,2}?)b$`,
];
const good=[
 String.raw`^action=(?<action>\w+)$`,
 String.raw`(?<field>tcp|udp)$`,
 String.raw`(?<field>[^\x22\x27\\]+)`,
 String.raw`^(?<month>\d{2})-(?<day>\d{2})\s+(?<name>\w+)$`,
 String.raw`^(?<field>\d+\s+)$`,
 // A lazy range is the same in both engines.
 String.raw`^(?<a>a{2,3}?)b$`,
 String.raw`^(?<sev>[A-Z]{4}) (?<msg>.{1,60})$`,
];
for(const expression of bad)test('backend fails closed on portable regex: '+expression,()=>{
 assert.notEqual(portableRegexIssue(expression),null);
 assert.equal(validateBoundedRegexPattern(expression),'regex_unsafe_construct');
 const p=sampleProject();p.extraction={format:'regex',pattern:expression};p.classification.rules=[];
 const verdict=validateProject(p);
 assert.equal(verdict.ok,false);
 assert.ok(verdict.issues.some(i=>i.code==='regex_unsafe_construct'));
});
for(const expression of good)test('backend admits safe portable syntax: '+expression,()=>{
 assert.equal(portableRegexIssue(expression),null);
 assert.equal(validateBoundedRegexPattern(expression),null);
 const p=sampleProject();p.extraction={format:'regex',pattern:expression};p.classification.rules=[];
 assert.equal(validateProject(p).ok,true);
 assert.equal(compilePair(p).files.length,2);
});
