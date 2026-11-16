// Translation conformance: the probes of translation-probes.ts executed as TypeScript and as the Ruby the
// generator derives from them (Ruby 2.4.9 with the grammar runtime), on the same inputs.
//
//   node backend/node_modules/tsx/dist/cli.mjs scripts/verification/translation-conformance.ts
//
// A difference fails the run. One class of input has no Ruby counterpart and is counted separately: an
// operation that cuts a string between the two UTF-16 units of one character yields an unpaired surrogate in
// the browser; a Ruby string cannot hold one, so the generated parser declines the event there
// (ArgumentError "String offset inside a surrogate pair") or keeps the character whole (value[index]).
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import * as probes from './translation-probes';
import { generatedWith, runtimeWith, RUNTIME_FAULTS, TRANSLATION_FAULT_IDS } from './translation-faults';

const ROOT = new URL('../../', import.meta.url);
const STRINGS = ['', 'a', 'ab', 'abc', 'abab', 'aa', 'bb', 'xy', 'y', 'a,b', 'a, b;c', ' a b ', 'x1y2', 'ab-12', 'Hello World', 'a"b c";d e', ',', ',,', 'a,',
  'é', 'aé,b', '한글 a=1', '\u{1f600}', 'a\u{1f600}b', '\u{1f600}\u{1f600},\u{1f600}', 'ab\u{1f600}', ' a ', '\t a\n', 'a\r\nb', '12', '007', '-5', '+7',
  '1.5', '1e3', '1E-3', '0x1f', '0b11', '9007199254740993', '12345678901234567890', '1.', '.5', '5e', 'Infinity', '-Infinity', 'a&c', '[x]#/-', 'A1b2C3', 'x;y', 'ab ab', ' ', 'ff', 'zz9'];
const NEEDLES = ['', ',', 'a', 'b', '\u{1f600}', ' ', 'ab'];
const OFFSETS = [0, 1, 2, 3, -1, 7];
const VALUES: unknown[] = [null, true, false, 0, 1, -1, 1.5, '', 'a', '0', [], [1], [null], ['a', 'b'], {}, { a: null }, { a: 1 }, { a: '' }, { a: 0 }, { b: 2 }, { a: { b: [1, null] } }, 'null'];
const LISTS: string[][] = [[], ['a'], ['a', 'b'], ['a', 'b', 'a', 'bb', ''], ['{"x":1}', 'b'], ['{', 'b', 'ccc'], ['\u{1f600}', 'b']];
const RECORDS: Array<Record<string, unknown>> = [{}, { first: 2 }, { z: null, last: 'x', a: [1] }, { missing: 0 }];

const calls: Array<[string, ...unknown[]]> = [];
for (const s of STRINGS) {
  calls.push(['probeScan', s], ['probeRegex', s]);
  for (const t of NEEDLES) for (const a of OFFSETS) for (const b of [0, 1, 3, -2]) calls.push(['probeString', s, t, a, b]);
  for (const a of [-7, -1, 0, 1, 2, 9]) for (const b of [-2, 0, 3]) calls.push(['probeNumber', s, a, b]);
}
// A text long enough for both ways the runtime cuts a piece out of a text beyond ASCII (a short piece behind
// unit 2,048 is put together from the units, any other is read out of the text); offsets on character borders.
const LONG = 'k\u00e9\u{1f600}'.repeat(700);
for (const t of ['', '\u{1f600}']) for (const a of [2048, 2052]) for (const b of [2056, 2060, 2076, 2084]) calls.push(['probeString', LONG, t, a, b]);
for (const v of VALUES) calls.push(['probeValue', v]);
for (const items of LISTS) for (const record of RECORDS) calls.push(['probeCollections', items, record]);

const rubyNames: Record<string, string> = { probeString: 'psg_probe_string', probeScan: 'psg_probe_scan', probeRegex: 'psg_probe_regex', probeNumber: 'psg_probe_number', probeValue: 'psg_probe_value', probeCollections: 'psg_probe_collections' };
const payload = Buffer.from(JSON.stringify(calls.map(([name, ...args]) => [rubyNames[name], ...args])), 'utf8').toString('base64');
const HARNESS = `
def conformance_plain(value)
  case value
  when Hash then value.each_with_object({}) { |(key, item), out| out[key] = conformance_plain(item) }
  when Array then value.map { |item| conformance_plain(item) }
  when Float then value.finite? ? value : nil
  else value
  end
end
JSON.parse(Base64.decode64('${payload}').force_encoding('UTF-8')).each do |call|
  begin
    arguments = call[1..-1].map { |argument| psg_json_import(argument) }
    puts 'OK ' + JSON.generate([conformance_plain(psg_export(send(call[0], *arguments)))])
  rescue ArgumentError => e
    puts 'DECLINED ' + e.message
  rescue StandardError, ScriptError => e
    puts "RAISED #{e.class}: #{e.message[0, 160]}"
  end
end
`;
const canon = (value: unknown): string => JSON.stringify(value, (_key, item) =>
  item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))) : item);
// JSON.stringify writes an unpaired surrogate as a \\udXXX escape and a paired one as the character itself.
const unpaired = (json: string): boolean => /\\ud[89a-f][0-9a-f]{2}/.test(json);

interface Outcome { compared: number; unrepresentable: number; problems: string[] }
/** Runs every probe call on the given runtime and generated probes; a Ruby that does not even load is one problem. */
function conformance(runtime: string, generatedProbes: string): Outcome {
  const script = "require 'json'\nrequire 'base64'\n" + runtime + '\n' + generatedProbes + HARNESS;
  const run = spawnSync('ruby', [], { input: script, encoding: 'utf8', maxBuffer: 1 << 29 });
  if (run.status !== 0) return { compared: 0, unrepresentable: 0, problems: ['the Ruby program failed: ' + (run.stderr ?? '').slice(0, 300)] };
  const lines = run.stdout.split('\n').filter(line => line !== '');
  if (lines.length !== calls.length) return { compared: 0, unrepresentable: 0, problems: [`Ruby answered ${lines.length} of ${calls.length} calls`] };
  let compared = 0, unrepresentable = 0;
  const problems: string[] = [];
  calls.forEach(([name, ...args], index) => {
    const ruby = lines[index]!;
    let browser: unknown;
    try { browser = (probes as unknown as Record<string, (...input: unknown[]) => unknown>)[name]!(...args); }
    catch (error) { problems.push(`${name}(${JSON.stringify(args)}) threw in TypeScript: ${String(error).slice(0, 120)}`); return; }
    const expected = canon(JSON.parse(JSON.stringify([browser])));
    if (unpaired(JSON.stringify([browser]))) {
      unrepresentable += 1;
      if (ruby.startsWith('RAISED')) problems.push(`${name}(${JSON.stringify(args)}): ${ruby}`);
      return;
    }
    if (!ruby.startsWith('OK ')) { problems.push(`${name}(${JSON.stringify(args)}): Ruby ${ruby.slice(0, 200)}; TypeScript ${expected.slice(0, 200)}`); return; }
    const actual = canon(JSON.parse(ruby.slice(3)));
    compared += 1;
    if (actual === expected) return;
    const left = JSON.parse(expected)[0] as unknown[], right = JSON.parse(actual)[0] as unknown[];
    const at = left.findIndex((item, position) => canon(item) !== canon(right[position]));
    problems.push(`${name}(${JSON.stringify(args)}) result ${at}: TypeScript ${canon(left[at]).slice(0, 160)} Ruby ${canon(right[at]).slice(0, 160)}`);
  });
  return { compared, unrepresentable, problems };
}

const PROBES = 'scripts/verification/translation-probes.generated.rb';
const runtime = readFileSync(new URL('backend/templates/grammar-runtime.rb.tpl', ROOT), 'utf8');
const { compared, unrepresentable, problems } = conformance(runtime, readFileSync(new URL(PROBES, ROOT), 'utf8'));
for (const problem of problems.slice(0, 60)) console.error('TRANSLATION_DIFFERENCE ' + problem);
console.log(`TRANSLATION_CONFORMANCE calls=${calls.length} compared=${compared} unrepresentable=${unrepresentable} differences=${problems.length} ${problems.length ? 'FAIL' : 'PASS'}`);
if (problems.length) process.exit(1);

// Fault injection: every deliberate defect of the generator or of a primitive must be noticed by the probes.
const undetected: string[] = [];
for (const id of TRANSLATION_FAULT_IDS) {
  const runtimeFault = RUNTIME_FAULTS.some(fault => fault.id === id);
  const outcome = runtimeFault
    ? conformance(runtimeWith(id), readFileSync(new URL(PROBES, ROOT), 'utf8'))
    : conformance(runtime, (await generatedWith(id.slice('translation-'.length))).get(PROBES)!);
  if (outcome.problems.length === 0) undetected.push(id);
  else console.log(`TRANSLATION_FAULT_DETECTED ${id} differences=${outcome.problems.length}`);
}
for (const id of undetected) console.error('TRANSLATION_FAULT_NOT_DETECTED ' + id);
console.log(`TRANSLATION_FAULT_INJECTION detected=${TRANSLATION_FAULT_IDS.length - undetected.length}/${TRANSLATION_FAULT_IDS.length} ${undetected.length ? 'FAIL' : 'PASS'}`);
process.exit(undetected.length ? 1 : 0);
