// The grammar runtime of a generated parser reads a text by UTF-16 offsets, as the browser does, while a Ruby
// string is UTF-8. These tests hold what the delta audit of 2026-11-16 found missing: an offset is converted
// without walking the text (F1), the kept unit arrays are bounded by size (F2), and the primitives changed for
// speed still mean what they meant for arguments the generated grammar does not pass today (F3). The fourth
// test holds what the profile taken while fixing F1 showed: a scan built the units of its text for every match.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {rubyE} from './ruby-argv.js';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';

function parserSource(extraction: Record<string, unknown>): string {
  const project = sampleProject() as unknown as {extraction: unknown};
  project.extraction = extraction;
  return compilePair(project as never).files.find(file => !file.name.endsWith('.conf'))!.content;
}

function ruby(source: string, body: string[], input: Record<string, unknown>): any {
  const script = ["require 'json'", "require 'base64'", "require 'time'", "require 'date'", "require 'ipaddr'", "require 'zlib'",
    'input = JSON.parse(STDIN.read)', 'klass = Class.new', "klass.class_eval(input.fetch('source'), 'generated_runtime_cost', 1)", 'parser = klass.new',
    "texts = input.fetch('texts', []).map { |text| Base64.strict_decode64(text).force_encoding('UTF-8') }",
    "settings = parser.instance_variable_get(:@parser_rule_set)['extraction']", ...body].join('\n');
  const texts = ((input.texts as string[] | undefined) ?? []).map(text => Buffer.from(text, 'utf8').toString('base64'));
  const run = spawnSync('ruby', rubyE(script), {input: JSON.stringify({...input, source, texts}), encoding: 'utf8', maxBuffer: 1 << 28, timeout: 300000});
  assert.equal(run.status, 0, (run.stderr || String(run.error)).slice(0, 600));
  return JSON.parse(run.stdout);
}

const CSV = {format: 'csv', csvColumns: ['c1', 'c2', 'c3', 'c4'], csvDelimiter: ','};
const KV = {format: 'kv'};

test('a quoted CSV cell with doubled quotes costs in proportion to its length, also beside a character beyond the BMP', () => {
  // A quoted cell is read in pieces between its doubled quotes. Four times the pieces is four times the work;
  // when every piece cost a walk from the start of the text it was sixteen times.
  const row = (lead: string, marks: number) => '"' + lead + 'ab""'.repeat(marks) + '",b,c,d';
  const shapes: Array<[string, string]> = [['beyond the BMP', '\u{1F600}'], ['BMP', 'é'], ['ASCII', 'x']];
  const texts = shapes.flatMap(([, lead]) => [row(lead, 1500), row(lead, 6000)]);
  const out = ruby(parserSource(CSV), [
    'timed = texts.map do |text|',
    '  best = nil; status = nil',
    '  3.times do',
    '    line = text.dup',
    '    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)',
    "    status = parser.send(:psg_read_event, parser.send(:psg_text, line), settings)['status']",
    '    spent = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started',
    '    best = spent if best.nil? || spent < best',
    '  end',
    '  [status, best]',
    'end',
    'STDOUT.write(JSON.generate(timed))'], {texts}) as Array<[string, number]>;
  shapes.forEach(([label], index) => {
    const small = out[index * 2]!;
    const large = out[index * 2 + 1]!;
    assert.equal(small[0], 'FULL', label);
    assert.equal(large[0], 'FULL', label);
    const growth = large[1] / small[1];
    assert.ok(growth < 9, `${label}: four times the row took ${growth.toFixed(1)} times as long (${(small[1] * 1000).toFixed(0)} ms, ${(large[1] * 1000).toFixed(0)} ms)`);
  });
});

test('the kept UTF-16 unit arrays stay within their size budget across large events with text beyond ASCII', () => {
  const texts = Array.from({length: 90}, (_unused, index) => Array.from({length: 20}, (_u, pair) => `k${pair + 1}=${index}` + (index % 2 ? '\u{1F600}' : 'é').repeat(400)).join(' '));
  const out = ruby(parserSource(KV), [
    "peak = 0; statuses = texts.map do |text|",
    "  status = parser.send(:psg_read_event, parser.send(:psg_text, text), settings)['status']",
    '  units = parser.instance_variable_get(:@psg_unit_cache)',
    '  total = units.nil? ? 0 : units.each_value.map(&:length).inject(0, :+)',
    '  peak = total if total > peak',
    '  status',
    'end',
    'units = parser.instance_variable_get(:@psg_unit_cache); offsets = parser.instance_variable_get(:@psg_offset_cache)',
    "STDOUT.write(JSON.generate({'statuses' => statuses.uniq, 'peak' => peak, 'entries' => units.length, 'offsetEntries' => offsets.nil? ? 0 : offsets.length, 'strangers' => offsets.nil? ? 0 : offsets.keys.count { |text| !units.key?(text) }}))"], {texts});
  assert.deepEqual(out.statuses, ['FULL']);
  assert.ok(out.peak > 0, 'the events must go through the unit arrays for this test to mean anything');
  assert.ok(out.peak <= 131072, `kept units at the highest point: ${out.peak}`);
  assert.ok(out.entries <= 64, `kept texts: ${out.entries}`);
  assert.equal(out.strangers, 0, 'an offset table is kept only for a text whose units are kept');
});

test('a scan over a text beyond ASCII builds the UTF-16 units of that text once, not once for every match', () => {
  // MatchData#string is a new copy for every match of a text that is not frozen. The end of a match was asked
  // of that copy, so its units were built again for every pair of the body.
  const text = '<134>May  1 10:00:01 fw01 ' + Array.from({length: 100}, (_unused, pair) => `k${pair + 1}=` + '\u00e9'.repeat(50)).join(' ');
  const out = ruby(parserSource({format: 'syslog_rfc3164', syslogBodyFormat: 'kv'}), [
    'built = 0',
    'parser.define_singleton_method(:psg_units) do |value|',
    '  kept = instance_variable_get(:@psg_unit_cache)',
    '  built += value.length if kept.nil? || !kept.key?(value)',
    '  super(value)',
    'end',
    "status = parser.send(:psg_read_event, parser.send(:psg_text, texts[0]), settings)['status']",
    "STDOUT.write(JSON.generate({'status' => status, 'built' => built, 'length' => texts[0].length}))"], {texts: [text]});
  assert.equal(out.status, 'FULL');
  assert.ok(out.built >= out.length, 'the event must go through the unit arrays for this test to mean anything');
  assert.ok(out.built <= 8 * out.length, `units built for one event of ${out.length} characters: ${out.built}`);
});

test('offset primitives agree with the browser at every offset of a text with characters beyond the BMP', () => {
  const texts = ['a\u{1F600}b\u{10348}c', '\u{1F600}\u{1F600}', 'é\u{1F600}=한 x', 'x'.repeat(40) + '\u{1F600}' + 'é'.repeat(40) + '\u{1F600}y'];
  const whole = (text: string, at: number) => at <= 0 || at >= text.length || !(text.charCodeAt(at) >= 0xdc00 && text.charCodeAt(at) <= 0xdfff);
  const cases: Array<{text: number; from: number; to: number; expected: string}> = [];
  texts.forEach((text, index) => {
    for (let from = 0; from <= text.length; from++) for (let to = from; to <= text.length; to++)
      if (whole(text, from) && whole(text, to)) cases.push({text: index, from, to, expected: text.slice(from, to)});
  });
  const out = ruby(parserSource(KV), [
    "wrong = input.fetch('cases').reject do |item|",
    "  text = texts[item['text']]",
    "  parser.send(:psg_slice, text, item['from'], item['to']) == item['expected'] && parser.send(:psg_substring, text, item['to'], item['from']) == item['expected'] &&",
    "    parser.send(:psg_char_to_unit, text, parser.send(:psg_unit_to_char, text, item['from'])) == item['from']",
    'end',
    "inside = begin; parser.send(:psg_slice, texts[0], 0, 2); rescue ArgumentError => error; error.message; end",
    "STDOUT.write(JSON.generate({'wrong' => wrong.first(5), 'count' => wrong.length, 'inside' => inside}))"], {texts, cases});
  assert.ok(cases.length > 3000, String(cases.length));
  assert.deepEqual(out.wrong, []);
  assert.equal(out.count, 0);
  // The browser would cut the character in two; a UTF-8 string cannot hold half of it, so the event is declined.
  assert.equal(out.inside, 'String offset inside a surrogate pair');
});

test('psg_group and the list primitives keep their meaning for a name that is not a string and for a list without items', () => {
  const out = ruby(parserSource(KV), [
    "match = /(?<a>x)(?<b>y)?/.match('x')",
    'attempt = lambda { |&block| begin; block.call; rescue Exception => error; error.class.name; end }',
    "STDOUT.write(JSON.generate({",
    "  'named' => parser.send(:psg_group, match, 'a'), 'unmatched' => parser.send(:psg_group, match, 'b'), 'unknown' => parser.send(:psg_group, match, 'zz'),",
    "  'index' => parser.send(:psg_group, match, 0), 'symbol' => parser.send(:psg_group, match, :a), 'nil' => parser.send(:psg_group, match, nil),",
    "  'noMatch' => parser.send(:psg_group, :psg_null, 'a'), 'notAMatch' => attempt.call { parser.send(:psg_group, 'x', 'a') },",
    "  'map' => parser.send(:psg_map, [], nil), 'flatMap' => parser.send(:psg_flat_map, [], nil), 'filter' => parser.send(:psg_filter, [], nil),",
    "  'some' => parser.send(:psg_some, [], nil), 'every' => parser.send(:psg_every, [], nil), 'find' => parser.send(:psg_find, [], nil),",
    "  'findIndex' => parser.send(:psg_find_index, [], nil), 'forEach' => parser.send(:psg_for_each, [], nil),",
    "  'withItems' => attempt.call { parser.send(:psg_map, [1], nil) },",
    "  'mapIndex' => parser.send(:psg_map, [5, 6], lambda { |item, index| item + index }), 'mapItem' => parser.send(:psg_map, [5, 6], lambda { |item| item * 2 })",
    '}))'], {});
  assert.deepEqual(out, {
    named: 'x', unmatched: null, unknown: null, index: null, symbol: null, nil: null, noMatch: null, notAMatch: 'NoMethodError',
    map: [], flatMap: [], filter: [], some: false, every: true, find: null, findIndex: -1, forEach: null,
    withItems: 'NoMethodError', mapIndex: [5, 7], mapItem: [10, 12],
  });
});
