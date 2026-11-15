// The Ruby template set: everything that decides the Ruby and CONF text of a generated parser.
//
// The reviewed-template hash of the disposable POC path (pocTemplateSha256 in src/stellar-legacy-plan.ts)
// covers the one artifact that is uploaded there, compiled from a JSON sample project. A change to a template
// part or a compiler-owned helper that this artifact does not contain (the Generic Structural grammar, the
// Regex helper, the source-copy helper, a CONF variant) leaves that hash unchanged. The template set closes the
// gap: it records every template file and the artifact of every compiler variant, and one digest over all of it.
import {createHash} from 'node:crypto';
import {readdirSync, readFileSync} from 'node:fs';
import {inflateSync} from 'node:zlib';
import {compilePair} from '../src/compiler.js';
import {compilerVariants} from './compiler-variants.js';

export interface TemplateSetManifest {
  schema: 'parser-studio/ruby-template-set/v1';
  purpose: string;
  hashRule: string[];
  /** SHA-256 of every file in backend/templates, by file name. */
  templates: Record<string, string>;
  /** SHA-256 of the Unicode case-fold table as the Ruby inflates it (independent of the zlib build). */
  unicodeCaseMapSha256: string;
  /** SHA-256 of the normalized Ruby and of the CONF of every compiler variant (backend/test/compiler-variants.ts). */
  artifacts: Record<string, { ruby: string; conf: string }>;
  /** SHA-256 over templates, unicodeCaseMapSha256 and artifacts in canonical JSON: the value an owner approves. */
  templateSetSha256: string;
}

const TEMPLATES = new URL('../templates/', import.meta.url);
const sha256 = (text: string | Buffer): string => createHash('sha256').update(text).digest('hex');
const BASE64_LITERAL = /Base64\.strict_decode64\('([A-Za-z0-9+/=]{8,})'\)/g;
const CASE_MAP = /@parserstudio_case_map = JSON\.parse\(Zlib::Inflate\.inflate\(Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)\)\)/;

/**
 * The Ruby of an artifact without the two literals that are not template text: the project IR (first Base64
 * literal) and the deflated case-fold table, whose bytes depend on the zlib build of the Node runtime. The
 * table is returned inflated, so its content is still part of the set.
 */
export function normalizedRuby(text: string): { text: string; caseMap: string } {
  const table = CASE_MAP.exec(text);
  if (!table) throw new Error('TEMPLATE_SET_SHAPE: the case-fold table literal is missing');
  const caseMap = inflateSync(Buffer.from(table[1]!, 'base64')).toString('utf8');
  const withoutTable = text.replace(table[1]!, '__PARSERSTUDIO_UNICODE_CASE_B64__');
  const literals = Array.from(withoutTable.matchAll(BASE64_LITERAL));
  if (literals.length !== 1) throw new Error('TEMPLATE_SET_SHAPE: expected exactly one project literal, found ' + literals.length);
  return { text: withoutTable.replace(literals[0]![1]!, '__PARSER_PROJECT_B64__'), caseMap };
}

const canonical = (value: unknown): string => JSON.stringify(value, (_key, item) =>
  item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
    : item);

/** The digest an owner approves, over the three parts of a manifest. */
export function templateSetDigest(parts: Pick<TemplateSetManifest, 'templates' | 'unicodeCaseMapSha256' | 'artifacts'>): string {
  return sha256(canonical({ templates: parts.templates, unicodeCaseMapSha256: parts.unicodeCaseMapSha256, artifacts: parts.artifacts }));
}

export interface TemplateSet { manifest: TemplateSetManifest; ruby: Record<string, string> }

/** The manifest of the current templates and compiler, with the normalized Ruby of every variant. */
export function currentTemplateSet(): TemplateSet {
  const templates: Record<string, string> = {};
  for (const name of readdirSync(TEMPLATES).sort()) templates[name] = sha256(readFileSync(new URL(name, TEMPLATES)));
  const artifacts: Record<string, { ruby: string; conf: string }> = {};
  const ruby: Record<string, string> = {};
  const tables = new Set<string>();
  for (const variant of compilerVariants()) {
    if (artifacts[variant.id]) throw new Error('TEMPLATE_SET_SHAPE: duplicate compiler variant ' + variant.id);
    const files = compilePair(variant.project).files;
    const conf = files.find(file => file.name.endsWith('.conf'));
    const fragment = files.find(file => !file.name.endsWith('.conf'));
    if (!conf || !fragment || files.length !== 2) throw new Error('TEMPLATE_SET_SHAPE: ' + variant.id + ' is not one CONF and one Ruby file');
    const normalized = normalizedRuby(fragment.content);
    tables.add(normalized.caseMap);
    ruby[variant.id] = normalized.text;
    artifacts[variant.id] = { ruby: sha256(normalized.text), conf: sha256(conf.content) };
  }
  if (tables.size !== 1) throw new Error('TEMPLATE_SET_SHAPE: the variants do not share one case-fold table');
  const parts = { templates, unicodeCaseMapSha256: sha256([...tables][0]!), artifacts };
  return {
    ruby,
    manifest: {
      schema: 'parser-studio/ruby-template-set/v1',
      purpose: 'Detects a change to any Ruby template file, compiler-owned Ruby helper, CONF generator or the Unicode case-fold table. ' +
        'templateSetSha256 is the value an owner approves; it is recorded in backend/test/template-set-approval.test.ts and nowhere else.',
      hashRule: [
        'templates: SHA-256 of the bytes of every file in backend/templates',
        'artifacts.<variant>.ruby: SHA-256 of the UTF-8 Ruby of the variant with the project IR literal replaced by __PARSER_PROJECT_B64__ and the deflated case-fold literal replaced by __PARSERSTUDIO_UNICODE_CASE_B64__',
        'artifacts.<variant>.conf: SHA-256 of the UTF-8 CONF of the variant',
        'unicodeCaseMapSha256: SHA-256 of the inflated case-fold table (JSON text)',
        'templateSetSha256: SHA-256 of the canonical JSON (object keys sorted, no white space) of {artifacts, templates, unicodeCaseMapSha256}',
      ],
      ...parts,
      templateSetSha256: templateSetDigest(parts),
    },
  };
}

export const TEMPLATE_SET_MANIFEST_PATH = new URL('../../contracts/ruby-template-set.v1.json', import.meta.url);
export const serializeManifest = (manifest: TemplateSetManifest): string => JSON.stringify(manifest, null, 2) + '\n';
