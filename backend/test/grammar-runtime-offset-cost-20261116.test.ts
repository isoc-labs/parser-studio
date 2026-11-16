// The grammar runtime of a generated parser reads a text by UTF-16 offsets, as the browser does, while a Ruby
// string is UTF-8. These tests hold what the two audits of 2026-11-16 found: an offset is converted without
// walking the text and a short piece far into a text is not read by walking to it (F1), the kept unit arrays
// are bounded and small texts do not push out the text an event is read through (F2, G2), a scan builds the
// units of its text once, and the primitives changed for speed mean what they meant for arguments the
// generated grammar does not pass today (F3, G4). Nothing here measures time: every assertion counts work
// (objects allocated, unit arrays built, texts kept), so a slow machine cannot fail it (G1).
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
  const script = ["require 'json'", "require 'base64'", "require 'time'", "require 'date'", "require 'ipaddr'", "require 'zlib'", "require 'stringio'",
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
// Counts, per text, how often its unit array is built: `built` holds the length of every text built.
const COUNT_BUILDS = [
  'built = []',
  'parser.define_singleton_method(:psg_units) do |value|',
  '  kept = instance_variable_defined?(:@psg_unit_cache) ? instance_variable_get(:@psg_unit_cache) : nil',
  '  built << value.length if kept.nil? || !kept.key?(value)',
  '  super(value)',
  'end'];

test('an offset of a text with a character beyond the BMP is converted without walking the text', () => {
  // Converting counted the units before the offset: an array or a scan per call. With the offset tables a
  // conversion allocates nothing, wherever the offset is. A CSV row read through such conversions is FULL.
  const text = '\u{1F600}' + '\u00e9'.repeat(6000);
  const row = '"\u{1F600}' + 'ab""'.repeat(3000) + '",b,c,d';
  const out = ruby(parserSource(CSV), [
    'text = texts[0]',
    'allocated = lambda do |&work|',
    '  work.call(0)',
    '  GC.disable; before = GC.stat(:total_allocated_objects)',
    '  2000.times { |i| work.call(i) }',
    '  after = GC.stat(:total_allocated_objects); GC.enable',
    '  after - before',
    'end',
    'idle = allocated.call { |i| parser.send(:psg_int, 3000 + i) }',
    'to_char = allocated.call { |i| parser.send(:psg_unit_to_char, text, 3000 + i) }',
    'to_unit = allocated.call { |i| parser.send(:psg_char_to_unit, text, 3000 + i) }',
    "status = parser.send(:psg_read_event, parser.send(:psg_text, texts[1]), settings)['status']",
    "STDOUT.write(JSON.generate({'idle' => idle, 'toChar' => to_char, 'toUnit' => to_unit, 'status' => status,",
    "  'char' => parser.send(:psg_unit_to_char, text, 4002), 'unit' => parser.send(:psg_char_to_unit, text, 4001), 'plain' => parser.send(:psg_plain?, text)}))"], {texts: [text, row]});
  assert.equal(out.plain, false);
  assert.equal(out.char, 4001);
  assert.equal(out.unit, 4002);
  // Counting again costs at least one object per call (2,000 here); an idle loop of the same shape allocates
  // none or a handful, depending on the Ruby.
  assert.ok(out.idle < 200, `an idle loop allocated ${out.idle} objects`);
  assert.ok(out.toChar < 200, `objects allocated by 2,000 conversions of a code unit offset: ${out.toChar} (an idle loop: ${out.idle})`);
  assert.ok(out.toUnit < 200, `objects allocated by 2,000 conversions of a character offset: ${out.toUnit} (an idle loop: ${out.idle})`);
  assert.equal(out.status, 'FULL');
});

test('a short piece far into a text beyond ASCII is put together from the units, not read by walking the text', () => {
  // String#[] of a UTF-8 text walks from the start of the text. The texts of this test refuse to be read
  // that way; a piece of up to 32 units behind unit 2,048 must not ask.
  const texts = ['\u00e9'.repeat(5000), '\u{1F600}' + 'a\u00e9'.repeat(2500)];
  const out = ruby(parserSource(KV), [
    'pieces = texts.map do |text|',
    '  parser.send(:psg_len, text)',
    "  text.define_singleton_method(:[]) { |*_at| raise IndexError, 'the text was read by walking' }",
    '  far = begin; [parser.send(:psg_slice, text, 4000, 4008), parser.send(:psg_slice, text, 2048, 2080), parser.send(:psg_substring, text, 4900, 4899)]; rescue IndexError => error; error.message; end',
    '  long = begin; parser.send(:psg_slice, text, 4000, 4033); rescue IndexError => error; error.message; end',
    '  [far, long]',
    'end',
    'STDOUT.write(JSON.generate(pieces))'], {texts}) as Array<[string[] | string, string]>;
  texts.forEach((text, index) => {
    assert.deepEqual(out[index]![0], [text.slice(4000, 4008), text.slice(2048, 2080), text.substring(4900, 4899)]);
    // The other path is the one that walks; a piece of 33 units takes it. This holds the test itself: if the
    // refusal did not work, the assertion above would prove nothing.
    assert.equal(out[index]![1], 'the text was read by walking');
  });
});

test('the kept unit arrays are bounded, and small texts never push out the text an event is read through', () => {
  const out = ruby(parserSource(KV), [
    ...COUNT_BUILDS,
    'units = lambda { parser.instance_variable_get(:@psg_unit_cache) }',
    'offsets = lambda { parser.instance_variable_get(:@psg_offset_cache) || {} }',
    // one long text, read while 500 small texts come and go
    "long = \"\\u00e9\" * 5000",
    'parser.send(:psg_len, long)',
    "500.times { |i| parser.send(:psg_len, \"v#{i}\\u00e9\"); parser.send(:psg_at, long, i) }",
    'long_builds = built.count(5000)',
    'after_small = units.call.length',
    // eight long texts read in turn stay; a ninth pushes out the oldest of them only
    "eight = Array.new(8) { |i| \"\\u{1F600}#{i}\" + \"\\u00e9\" * (1100 + i) }",
    'built.clear',
    '3.times { eight.each { |text| parser.send(:psg_unit_to_char, text, 900) } }',
    'eight_builds = built.length',
    "ninth = \"\\u{1F600}9\" + \"\\u00e9\" * 1200",
    'parser.send(:psg_unit_to_char, ninth, 900)',
    'kept_long = units.call.keys.select { |text| units.call[text].length >= 1024 }',
    'first_kept = units.call.key?(eight[0]); second_kept = units.call.key?(eight[1])',
    // a stream of large texts beyond the BMP and of small ones
    "peak_entries = 0; 60.times { |i| parser.send(:psg_unit_to_char, \"\\u{1F600}\" * (30000 + i), 5000); 9.times { |j| parser.send(:psg_len, \"s#{i}-#{j}\\u00e9\") }; peak_entries = [peak_entries, units.call.length].max }",
    "STDOUT.write(JSON.generate({'longBuilds' => long_builds, 'afterSmall' => after_small, 'eightBuilds' => eight_builds, 'keptLong' => kept_long.length,",
    "  'firstKept' => first_kept, 'secondKept' => second_kept, 'peakEntries' => peak_entries, 'entries' => units.call.length,",
    "  'longNow' => units.call.values.count { |array| array.length >= 1024 }, 'shortNow' => units.call.values.count { |array| array.length < 1024 },",
    "  'tables' => offsets.call.length, 'strangers' => offsets.call.keys.count { |text| !units.call.key?(text) }}))"], {});
  assert.equal(out.longBuilds, 1, 'the long text is built once while 500 small texts pass');
  assert.equal(out.afterSmall, 65, '64 small texts and the long one are kept');
  assert.equal(out.eightBuilds, 8, 'eight long texts read in turn are built once each');
  assert.equal(out.keptLong, 8);
  assert.equal(out.firstKept, false, 'the ninth long text pushes out the oldest long one');
  assert.equal(out.secondKept, true);
  assert.ok(out.peakEntries <= 72, `kept texts at the highest point: ${out.peakEntries}`);
  assert.equal(out.longNow, 8);
  assert.equal(out.shortNow, 64);
  assert.ok(out.tables <= 8 + 64);
  assert.equal(out.strangers, 0, 'an offset table is kept only for a text whose units are kept');
});

test('events with text beyond ASCII build the units of each text once: per match of a scan, and per value of a long event', () => {
  // MatchData#string is a new copy for every match of a text that is not frozen. The end of a match was asked
  // of that copy, so its units were built again for every pair of the body. And a LEEF event with thousands of
  // small values lost its own text from the kept list every 64 values.
  const scan = '<134>May  1 10:00:01 fw01 ' + Array.from({length: 100}, (_unused, pair) => `k${pair + 1}=` + '\u00e9'.repeat(50)).join(' ');
  const many = 'LEEF:1.0|Vendor|Product|1.0|100|' + Array.from({length: 1500}, (_unused, pair) => `k${pair}=\u00e9${pair}`).join('\t');
  const run = (extraction: Record<string, unknown>, text: string) => ruby(parserSource(extraction), [
    ...COUNT_BUILDS,
    'warnings = StringIO.new; stderr = $stderr; verbose = $VERBOSE; $stderr = warnings; $VERBOSE = true',
    "status = parser.send(:psg_read_event, parser.send(:psg_text, texts[0]), settings)['status']",
    "plain_end = parser.send(:psg_match_end, /\\u00e9+/.match(\"a\\u00e9\\u00e9b\")); plain_index = parser.send(:psg_match_index, /\\u00e9+/.match(\"\\u{1F600}a\\u00e9\\u00e9b\"))",
    '$stderr = stderr; $VERBOSE = verbose',
    "STDOUT.write(JSON.generate({'status' => status, 'built' => built.inject(0, :+), 'length' => texts[0].length, 'plainEnd' => plain_end, 'plainIndex' => plain_index,",
    "  'warnings' => warnings.string.lines.grep(/@psg_/)}))"], {texts: [text]});
  for (const [label, out] of [['RFC 3164 + key=value', run({format: 'syslog_rfc3164', syslogBodyFormat: 'kv'}, scan)], ['LEEF with 1,500 small values', run({format: 'leef'}, many)]] as const) {
    assert.equal(out.status, 'FULL', label);
    assert.ok(out.built >= out.length, `${label}: the event must go through the unit arrays for this test to mean anything`);
    assert.ok(out.built <= 4 * out.length, `${label}: units built for one event of ${out.length} characters: ${out.built}`);
    assert.equal(out.plainEnd, 3);
    assert.equal(out.plainIndex, 3);
    assert.deepEqual(out.warnings, [], 'no warning about a state variable of the runtime under $VERBOSE');
  }
});

test('offset primitives agree with the browser at every offset of a text with characters beyond the BMP', () => {
  const texts = ['a\u{1F600}b\u{10348}c', '\u{1F600}\u{1F600}', 'é\u{1F600}=한 x', 'x'.repeat(40) + '\u{1F600}' + 'é'.repeat(40) + '\u{1F600}y'];
  const whole = (text: string, at: number) => at <= 0 || at >= text.length || !(text.charCodeAt(at) >= 0xdc00 && text.charCodeAt(at) <= 0xdfff);
  const cases: Array<{text: number; from: number; to: number; expected: string}> = [];
  texts.forEach((text, index) => {
    for (let from = 0; from <= text.length; from++) for (let to = from; to <= text.length; to++)
      if (whole(text, from) && whole(text, to)) cases.push({text: index, from, to, expected: text.slice(from, to)});
  });
  // pieces of 0 to 40 units around unit 2,048 of a longer text: both ways of cutting a piece, and their border
  const longer = Array.from({length: 450}, (_unused, index) => `k${index}\u00e9\u{1F600}`).join('');
  texts.push(longer);
  for (let from = 2030; from <= 2070; from++) for (let size = 0; size <= 40; size++)
    if (whole(longer, from) && whole(longer, from + size)) cases.push({text: texts.length - 1, from, to: from + size, expected: longer.slice(from, from + size)});
  const out = ruby(parserSource(KV), [
    "wrong = input.fetch('cases').reject do |item|",
    "  text = texts[item['text']]",
    "  parser.send(:psg_slice, text, item['from'], item['to']) == item['expected'] && parser.send(:psg_substring, text, item['to'], item['from']) == item['expected'] &&",
    "    parser.send(:psg_char_to_unit, text, parser.send(:psg_unit_to_char, text, item['from'])) == item['from']",
    'end',
    "inside = begin; parser.send(:psg_slice, texts[0], 0, 2); rescue ArgumentError => error; error.message; end",
    "STDOUT.write(JSON.generate({'wrong' => wrong.first(5), 'count' => wrong.length, 'inside' => inside}))"], {texts, cases});
  assert.ok(cases.length > 4500, String(cases.length));
  assert.ok(longer.length > 2200);
  assert.deepEqual(out.wrong, []);
  assert.equal(out.count, 0);
  // The browser would cut the character in two; a UTF-8 string cannot hold half of it, so the event is declined.
  assert.equal(out.inside, 'String offset inside a surrogate pair');
});

test('psg_group and the list primitives keep their meaning for a name that is not a string, a list without items and a list that is not an array', () => {
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
    "  'range' => parser.send(:psg_map, (1..3), lambda { |item, index| item * 10 + index }), 'emptyRange' => parser.send(:psg_filter, (1...1), nil),",
    "  'enumerator' => parser.send(:psg_some, [4, 5].each, lambda { |item| item == 5 }), 'emptyEnumerator' => parser.send(:psg_every, [].each, nil),",
    "  'mapIndex' => parser.send(:psg_map, [5, 6], lambda { |item, index| item + index }), 'mapItem' => parser.send(:psg_map, [5, 6], lambda { |item| item * 2 })",
    '}))'], {});
  assert.deepEqual(out, {
    named: 'x', unmatched: null, unknown: null, index: null, symbol: null, nil: null, noMatch: null, notAMatch: 'NoMethodError',
    map: [], flatMap: [], filter: [], some: false, every: true, find: null, findIndex: -1, forEach: null,
    withItems: 'NoMethodError', range: [10, 21, 32], emptyRange: [], enumerator: true, emptyEnumerator: true, mapIndex: [5, 7], mapItem: [10, 12],
  });
});
