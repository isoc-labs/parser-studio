#!/usr/bin/env node
// Generates the Ruby grammar of the generated parser from the TypeScript grammar the browser executes.
//
//   node scripts/grammar/ts2rb/generate.mjs --write     regenerate the files listed in targets.mjs
//   node scripts/grammar/ts2rb/generate.mjs --verify    fail when a generated file differs from its source (CI)
//   node scripts/grammar/ts2rb/generate.mjs --notes     also print the review notes of the emitter
//
// Module constants (expression tables, limits) are not re-derived: the modules are executed and the values
// they hold are written out, so a constant in Ruby is the value the browser uses.
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createEmitter, rubyValue } from './emit.mjs';
import { EXTERNS, PRIMITIVE_MODULE, TARGETS } from './targets.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
// The repository root has TypeScript where the web tooling is installed; a job with only the backend tooling
// (the Ruby 2.4.9 target job) uses the backend's.
const ts = (() => {
  const backend = () => createRequire(path.join(ROOT, 'backend/package.json'))('typescript');
  if (process.env.PARSER_STUDIO_TS2RB_TYPESCRIPT === 'backend') return backend();
  try { return createRequire(import.meta.url)('typescript'); }
  catch { return backend(); }
})();
const rel = file => path.relative(ROOT, file).split(path.sep).join('/');
const snake = name => name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toLowerCase();

function loadProgram(files) {
  const configPath = path.join(ROOT, 'tsconfig.json');
  const parsed = ts.getParsedCommandLineOfConfigFile(configPath, {}, {
    ...ts.sys, onUnRecoverableConfigFileDiagnostic: diagnostic => { throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n')); },
  });
  return ts.createProgram({ rootNames: files.map(file => path.join(ROOT, file)), options: { ...parsed.options, noEmit: true } });
}

// Transpile the program's modules next to each other and execute them, to read the module level constants.
async function loadConstants(program) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ts2rb-'));
  const sources = program.getSourceFiles().filter(file => !file.isDeclarationFile && !file.fileName.includes('/node_modules/'));
  const mirror = file => path.join(directory, rel(file).replace(/\.\.\//g, '__/') + '.mjs');
  const resolveSpecifier = (from, specifier) => {
    const base = path.resolve(path.dirname(from), specifier);
    for (const candidate of [base, base + '.ts', base + '.tsx', path.join(base, 'index.ts')])
      if (existsSync(candidate) && !candidate.endsWith('/')) {
        if (/\.tsx?$/.test(candidate)) return candidate;
      }
    return null;
  };
  for (const source of sources) {
    const names = source.statements.filter(ts.isVariableStatement).flatMap(statement => statement.declarationList.declarations)
      .filter(declaration => ts.isIdentifier(declaration.name)).map(declaration => declaration.name.text);
    let code = ts.transpileModule(`${source.text}\nexport const __ts2rb = {${names.join(',')}};\n`, {
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX }, fileName: source.fileName,
    }).outputText;
    code = code.replace(/(\bfrom\s*|\bimport\s*)(['"])(\.{1,2}\/[^'"]+)\2/g, (whole, head, quote, specifier) => {
      const target = resolveSpecifier(source.fileName, specifier);
      if (!target) return whole;
      let relative = path.relative(path.dirname(mirror(source.fileName)), mirror(target)).split(path.sep).join('/');
      if (!relative.startsWith('.')) relative = './' + relative;
      return `${head}${quote}${relative}${quote}`;
    });
    mkdirSync(path.dirname(mirror(source.fileName)), { recursive: true });
    writeFileSync(mirror(source.fileName), code);
  }
  const values = new Map();
  const failures = new Map();
  for (const source of sources) {
    try { values.set(source.fileName, (await import(pathToFileURL(mirror(source.fileName)).href)).__ts2rb); }
    catch (error) { failures.set(source.fileName, error); }
  }
  rmSync(directory, { recursive: true, force: true });
  return { values, failures };
}

async function generate(target, program, constants, faults) {
  const checker = program.getTypeChecker();
  const problems = [], notes = [];
  const position = node => {
    const source = node.getSourceFile();
    const { line, character } = source.getLineAndCharacterOfPosition(node.getStart());
    return `${rel(source.fileName)}:${line + 1}:${character + 1}`;
  };
  const globals = new Map();
  const taken = new Set();
  const queue = [];
  let current = null; // the function being emitted: what it references is recorded for the bundle split
  const unique = base => { let name = base; for (let i = 2; taken.has(name); i += 1) name = `${base}_${i}`; taken.add(name); return name; };
  const skip = node => { while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) node = node.expression; return node; };

  const ctx = {
    ts, checker, faults,
    fail: (node, message) => problems.push(`${position(node)}: ${message}`),
    note: (node, message) => notes.push(`${position(node)}: ${message}`),
    isLib: symbol => !symbol || !symbol.declarations?.length || symbol.declarations.every(declaration => declaration.getSourceFile().isDeclarationFile),
    useConst: entry => { entry.used = true; return entry.ruby; },
    global: symbol => {
      const entry = ctx.resolveGlobal(symbol);
      if (entry && current) current.refs.add(entry);
      return entry;
    },
    resolveGlobal: symbol => {
      if (!symbol) return null;
      if (globals.has(symbol)) return globals.get(symbol);
      const declaration = symbol.valueDeclaration ?? symbol.declarations?.[0];
      let entry = null;
      if (declaration && !declaration.getSourceFile().isDeclarationFile) {
        const file = rel(declaration.getSourceFile().fileName);
        const name = String(symbol.escapedName);
        const fn = node => {
          const extern = EXTERNS[`${file}#${name}`] ?? (file === PRIMITIVE_MODULE ? `psg_${snake(name)}` : null);
          if (extern) return { kind: 'extern', ruby: extern };
          const made = { kind: 'fn', ruby: unique(`psg_${snake(name)}`), node, origin: `${file}: ${name}`, refs: new Set() };
          queue.push(made);
          return made;
        };
        if (ts.isFunctionDeclaration(declaration) && ts.isSourceFile(declaration.parent)) entry = fn(declaration);
        else if (ts.isVariableDeclaration(declaration) && ts.isVariableStatement(declaration.parent.parent) && ts.isSourceFile(declaration.parent.parent.parent)) {
          const initializer = declaration.initializer && skip(declaration.initializer);
          if (initializer && (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer))) entry = fn(initializer);
          else {
            const module = constants.values.get(declaration.getSourceFile().fileName);
            if (!module) problems.push(`${position(declaration)}: the module could not be executed to read ${name}: ${constants.failures.get(declaration.getSourceFile().fileName)?.message}`);
            if (!(declaration.parent.flags & ts.NodeFlags.Const)) problems.push(`${position(declaration)}: module level ${name} is not const`);
            entry = { kind: 'const', value: module?.[name], ruby: unique(`psg_k_${snake(name)}`), origin: `${file}: ${name}`, used: false };
          }
        }
      }
      globals.set(symbol, entry);
      return entry;
    },
  };
  const emitter = createEmitter(ctx);
  const entryOf = ([file, name]) => {
    const source = program.getSourceFile(path.join(ROOT, file));
    const symbol = source && checker.getExportsOfModule(checker.getSymbolAtLocation(source)).find(candidate => candidate.escapedName === name);
    if (!symbol) { problems.push(`${file}: entry ${name} is not exported`); return null; }
    const entry = ctx.resolveGlobal(symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol);
    if (!entry || entry.kind !== 'fn') { problems.push(`${file}: entry ${name} is not a function`); return null; }
    return entry;
  };
  const roots = target.entries.map(entryOf).filter(Boolean);
  const splitRoots = new Set((target.split?.roots ?? []).map(entryOf).filter(Boolean));
  const items = [];
  while (queue.length) {
    const entry = queue.shift();
    current = entry;
    try { items.push({ entry, name: entry.ruby, text: `# ${entry.origin}\n${emitter.emitFunction(entry.node, entry.ruby)}` }); }
    catch (error) { problems.push(`${entry.origin}: ${error.stack}`); }
    current = null;
  }
  for (const entry of globals.values()) {
    if (!entry || entry.kind !== 'const' || !entry.used) continue;
    try { items.push({ entry, name: entry.ruby, table: true, text: `# ${entry.origin}\ndef ${entry.ruby}\n  @${entry.ruby} ||= ${rubyValue(entry.value, faults)}\nend` }); }
    catch (error) { problems.push(`${entry.origin}: ${error.message}`); }
  }
  // What the main bundle needs is everything its entries reach without passing through a split root; the rest
  // (reached only through a split root) goes to the second bundle, emitted only for the projects that use it.
  const core = new Set();
  const stack = roots.filter(entry => !splitRoots.has(entry));
  while (stack.length) {
    const entry = stack.pop();
    if (core.has(entry) || splitRoots.has(entry)) continue;
    core.add(entry);
    for (const reference of entry.refs ?? []) stack.push(reference);
  }
  const byName = (a, b) => (a.table === b.table ? (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) : a.table ? -1 : 1);
  const bundle = (title, selected) => [
    '# GENERATED FILE - DO NOT EDIT.',
    `# ${title}`,
    `# Source: ${target.entries.map(([file, name]) => `${file} (${name})`).join(', ')} and the functions they reach.`,
    '# Regenerate with: node scripts/grammar/ts2rb/generate.mjs --write',
    '# CI runs the generator with --verify, so a hand edit of this file fails the gate.',
    '',
    ...selected.sort(byName).map(item => item.text + '\n'),
  ].join('\n');
  const count = selected => ({ methods: selected.filter(item => !item.table).length, tables: selected.filter(item => item.table).length });
  const main = target.split ? items.filter(item => core.has(item.entry)) : items;
  const files = [{ output: target.output, text: bundle(target.title, main), ...count(main) }];
  if (target.split) {
    const rest = items.filter(item => !core.has(item.entry));
    files.push({ output: target.split.output, text: bundle(target.split.title, rest), ...count(rest) });
  }
  return { files, problems, notes };
}

/**
 * Deliberate mistranslations. A gate that compares the browser with the generated Ruby must notice each of
 * them (scripts/verification): they are the proof that a real defect of the translation would not pass.
 */
export const TRANSLATION_FAULTS = ['regex-sticky-unanchored', 'regex-line-anchors', 'regex-ruby-dot', 'regex-ruby-space',
  'truthiness-ruby', 'null-is-nil', 'length-in-characters', 'split-ruby', 'number-to-i'];

/** The generator as a library: generate(faults) returns [{ output, text }] for every target. */
export async function createGenerator() {
  const program = loadProgram([...new Set(TARGETS.flatMap(target => target.entries.map(([file]) => file)))]);
  const constants = await loadConstants(program);
  return {
    async generate(faults = []) {
      for (const fault of faults) if (!TRANSLATION_FAULTS.includes(fault)) throw new Error(`unknown translation fault ${fault}`);
      const results = [];
      for (const target of TARGETS) results.push({ target, ...(await generate(target, program, constants, new Set(faults))) });
      return results;
    },
  };
}

async function main() {
const mode = process.argv.includes('--write') ? 'write' : process.argv.includes('--verify') ? 'verify' : 'check';
const outIndex = process.argv.indexOf('--out');
let failed = false;
for (const result of await (await createGenerator()).generate()) {
  const target = result.target;
  if (process.argv.includes('--notes')) for (const note of result.notes) console.log(`NOTE ${note}`);
  if (result.problems.length) {
    failed = true;
    for (const problem of [...new Set(result.problems)]) console.error(`TS2RB ${problem}`);
    console.error(`TS2RB ${target.output}: ${new Set(result.problems).size} construct(s) outside the shared grammar subset`);
    if (outIndex < 0) continue;
  }
  for (const file of result.files) {
    const output = outIndex >= 0 ? path.join(process.argv[outIndex + 1], path.basename(file.output)) : path.join(ROOT, file.output);
    if (mode === 'verify') {
      const currentText = existsSync(output) ? readFileSync(output, 'utf8') : '';
      if (currentText !== file.text) { failed = true; console.error(`TS2RB ${file.output} is out of date; run node scripts/grammar/ts2rb/generate.mjs --write`); }
      else console.log(`TS2RB_VERIFY ${file.output} methods=${file.methods} tables=${file.tables} in sync`);
    } else if (mode === 'write' || outIndex >= 0) {
      writeFileSync(output, file.text);
      console.log(`TS2RB_WRITE ${rel(output)} methods=${file.methods} tables=${file.tables} notes=${result.notes.length}`);
    } else console.log(`TS2RB_CHECK ${file.output} methods=${file.methods} tables=${file.tables} notes=${result.notes.length}`);
  }
}
process.exit(failed ? 1 : 0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
