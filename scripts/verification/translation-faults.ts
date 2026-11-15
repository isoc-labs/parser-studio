// Fault injection for the translation layer (scripts/grammar/ts2rb and the grammar runtime).
//
// The Ruby grammar of a generated parser is not written by hand, so a hand-edited Ruby line is no longer a
// realistic defect. What can go wrong is the translation: the generator emitting Ruby that means something
// else than the TypeScript, or a psg_* primitive that does not behave like the ECMAScript operation it stands
// for. Each fault below is one such defect. Every gate that compares the browser with the generated Ruby
// injects them and must notice each one; a gate that lets one pass proves nothing about the translation.
import { readFileSync } from 'node:fs';
// @ts-expect-error -- the generator is a plain ES module
import { createGenerator, TRANSLATION_FAULTS } from '../grammar/ts2rb/generate.mjs';

const ROOT = new URL('../../', import.meta.url);
const RUNTIME_PATH = 'backend/templates/grammar-runtime.rb.tpl';

/** Defects of a hand written primitive: the text is replaced in the grammar runtime (it must occur once). */
export const RUNTIME_FAULTS: ReadonlyArray<{ id: string; find: string; replace: string }> = [
  { id: 'runtime-undefined-exported-as-null', find: 'record[key] = psg_export(item) unless item.nil? }', replace: 'record[key] = psg_export(item) }' },
  { id: 'runtime-json-null-is-absent', find: '  when nil then :psg_null\n  when Hash then value.each_with_object({}) { |(key, item), record| record[key] = psg_json_import(item) }', replace: '  when nil then nil\n  when Hash then value.each_with_object({}) { |(key, item), record| record[key] = psg_json_import(item) }' },
  { id: 'runtime-unit-offset-read-as-character-offset', find: '  char = chars[unit]\n', replace: '  char = unit\n' },
  { id: 'runtime-character-offset-read-as-unit-offset', find: '        starts << index\n', replace: '        starts << starts.length\n' },
  { id: 'runtime-short-piece-cut-by-character-offset', find: '    return units[from, to - from].join\n', replace: '    return value[from, to - from]\n' },
  { id: 'runtime-length-in-characters', find: '  value.ascii_only? ? value.length : psg_units(value).length', replace: '  value.length' },
  { id: 'runtime-large-number-not-an-integer', find: '  value.is_a?(Integer) || (value.is_a?(Float) && value.finite? && value == value.floor)', replace: '  value.is_a?(Integer)' },
  { id: 'runtime-split-drops-trailing-fields', find: "      text.empty? ? [''] : text.split(separator, -1)", replace: "      text.empty? ? [''] : text.split(separator)" },
  { id: 'runtime-zero-is-true', find: "  !(value.nil? || value == false || value == '' || value == 0 || value.equal?(:psg_null) ||", replace: "  !(value.nil? || value == false || value == '' || value.equal?(:psg_null) ||" },
  { id: 'runtime-empty-string-is-true', find: "  !(value.nil? || value == false || value == '' || value == 0 || value.equal?(:psg_null) ||", replace: "  !(value.nil? || value == false || value == 0 || value.equal?(:psg_null) ||" },
];

export const TRANSLATION_FAULT_IDS: readonly string[] = [...(TRANSLATION_FAULTS as string[]).map(id => 'translation-' + id), ...RUNTIME_FAULTS.map(fault => fault.id)];

type Generated = Array<{ files: Array<{ output: string; text: string }>; problems: string[] }>;
let generator: Promise<{ generate(faults?: string[]): Promise<Generated> }> | undefined;
const cache = new Map<string, Promise<Map<string, string>>>();

/** Generated file texts (by repository path) with one translation fault, or without any for ''. */
export function generatedWith(fault: string): Promise<Map<string, string>> {
  let made = cache.get(fault);
  if (!made) {
    generator ??= createGenerator();
    made = generator.then(async instance => {
      const out = new Map<string, string>();
      for (const result of await instance.generate(fault ? [fault] : [])) {
        if (result.problems.length) throw new Error(`TRANSLATION_FAULT_GENERATION_FAILED ${fault}: ${result.problems[0]}`);
        for (const file of result.files) out.set(file.output, file.text);
      }
      return out;
    });
    cache.set(fault, made);
  }
  return made;
}

const replaceOnce = (text: string, find: string, replace: string, what: string): string => {
  if (text.split(find).length !== 2) throw new Error(`TRANSLATION_FAULT_NOT_APPLICABLE ${what}: target text must occur exactly once`);
  return text.replace(find, () => replace);
};

/** The grammar runtime with one runtime fault. */
export function runtimeWith(id: string): string {
  const fault = RUNTIME_FAULTS.find(candidate => candidate.id === id);
  if (!fault) throw new Error(`unknown runtime fault ${id}`);
  return replaceOnce(readFileSync(new URL(RUNTIME_PATH, ROOT), 'utf8'), fault.find, fault.replace, id);
}

/** A compiled parser (Ruby text) with one fault of TRANSLATION_FAULT_IDS injected into its grammar. */
export async function faultyArtifact(artifact: string, id: string): Promise<string> {
  if (!TRANSLATION_FAULT_IDS.includes(id)) throw new Error(`unknown translation fault ${id}`);
  if (!id.startsWith('translation-')) {
    const fault = RUNTIME_FAULTS.find(candidate => candidate.id === id)!;
    return replaceOnce(artifact, fault.find, fault.replace, id);
  }
  const [good, bad] = await Promise.all([generatedWith(''), generatedWith(id.slice('translation-'.length))]);
  let out = artifact;
  let changed = false;
  for (const path of ['backend/templates/grammar-core.generated.rb.tpl', 'backend/templates/grammar-generic.generated.rb.tpl']) {
    const before = good.get(path)!.replace(/\n*$/, ''), after = bad.get(path)!.replace(/\n*$/, '');
    if (!out.includes(before)) continue;
    if (before !== after) changed = true;
    out = out.replace(before, () => after);
  }
  if (!changed) throw new Error(`TRANSLATION_FAULT_NOT_APPLICABLE ${id}: the generated grammar of this artifact is unchanged by the fault`);
  return out;
}

/** All faulty grammars generated up front, so that a fault can be injected synchronously. */
export async function prepareFaultInjector(): Promise<(artifact: string, id: string) => string> {
  // The grammar an artifact carries is the committed generated text.
  const good = new Map(['backend/templates/grammar-core.generated.rb.tpl', 'backend/templates/grammar-generic.generated.rb.tpl']
    .map(path => [path, readFileSync(new URL(path, ROOT), 'utf8')] as [string, string]));
  const bad = new Map<string, Map<string, string>>();
  for (const id of TRANSLATION_FAULT_IDS) if (id.startsWith('translation-')) bad.set(id, await generatedWith(id.slice('translation-'.length)));
  const paths = ['backend/templates/grammar-core.generated.rb.tpl', 'backend/templates/grammar-generic.generated.rb.tpl'];
  return (artifact, id) => {
    if (!TRANSLATION_FAULT_IDS.includes(id)) throw new Error(`unknown translation fault ${id}`);
    const runtime = RUNTIME_FAULTS.find(candidate => candidate.id === id);
    if (runtime) return replaceOnce(artifact, runtime.find, runtime.replace, id);
    let out = artifact;
    let changed = false;
    for (const path of paths) {
      const before = good.get(path)!.replace(/\n*$/, ''), after = bad.get(id)!.get(path)!.replace(/\n*$/, '');
      if (!out.includes(before)) continue;
      if (before !== after) changed = true;
      out = out.replace(before, () => after);
    }
    if (!changed) throw new Error(`TRANSLATION_FAULT_NOT_APPLICABLE ${id}: the generated grammar of this artifact is unchanged by the fault`);
    return out;
  };
}
