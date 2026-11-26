import {createPortableRegex,parsePortableRegexAst,portableRegexIssue,
  portableRegexBytes,PORTABLE_REGEX_MAX_BYTES,hasRepeatedChoice} from '../backend/src/portable-regex';
/**
 * Conservative preview-only regular-expression linter. The separate Web Worker
 * still enforces an execution timeout, and this check is NOT a proof that all
 * accepted JS regexes have linear complexity or match native Ruby/Fluentd.
 */
/** Adjacent unbounded captures can overlap with polynomial backtracking
 * despite having no nested groups or identical literal atoms. Conservatively
 * require an explicit separator between consecutive quantified captures. */
function hasAdjacentQuantifiedCaptures(pattern:string):boolean{
  const capture=/\(\?<([A-Za-z_][A-Za-z0-9_]*)>((?:\\.|[^()])*)\)/g;
  let previousEnd=-1,previousQuantified=false;
  for(const match of pattern.matchAll(capture)){
    const body=match[2]!;
    const quantified=/(?:\+|\*|\{\d+(?:,\d*)?\})$/.test(body);
    if(previousEnd===match.index&&previousQuantified&&quantified)return true;
    previousEnd=match.index!+match[0].length;
    previousQuantified=quantified;
  }
  return false;
}

export function validatePreviewRegexPattern(pattern: string): string | null {
  if (!pattern.trim()) return 'Enter a named-group regular expression';
  if (portableRegexBytes(pattern)>PORTABLE_REGEX_MAX_BYTES) return 'Regex exceeds 256 UTF-8 bytes';
  if(/[\x00-\x1f\x7f]/.test(pattern))return 'Regex contains unsupported control characters';
  if (!pattern.includes('(?<')) return 'Add at least one (?<field>...) named capture';

  const unsupported = 'Regex uses an unsupported or potentially expensive construct';
  if(portableRegexIssue(pattern))return unsupported;
  const ast=parsePortableRegexAst(pattern);
  if(!ast.ok)return unsupported;
  if(!ast.captureNames.length)return 'Add at least one (?<field>...) named capture';
  try{createPortableRegex(pattern);}catch{return unsupported;}

  // Backreferences and lookbehind enable nonlocal matching/ambiguous nesting.
  if (/\\[1-9]|\\k<|\(\?<[=!]/.test(pattern)) return unsupported;

  // These forms can yield exponential backtracking even with short input:
  // repeated groups containing quantifiers, optional terms or alternatives.
  if (/\((?:[^()]|\\.)*[+*?](?:[^()]|\\.)*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern)) {
    return unsupported;
  }
  if (/\((?:\?:)?[^()]*\|[^()]*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern)) {
    return unsupported;
  }
  if (hasRepeatedChoice(ast.ast)) return unsupported;
  if (hasAdjacentQuantifiedCaptures(pattern)) return unsupported;

  // Adjacent repetitions of the identical literal character are ambiguous.
  if (/([A-Za-z0-9])(?:[*+])\1(?:[*+])/.test(pattern)) return unsupported;

  // Prohibit very large unrolled repetition budgets, even without nested
  // quantifiers; the user can rewrite these as smaller typed expressions.
  for (const match of pattern.matchAll(/\{(\d{1,8})(?:,(\d{0,8}))?\}/g)) {
    const low = Number(match[1]);
    const high = match[2] === undefined || match[2] === '' ? low : Number(match[2]);
    if (low > 128 || high > 128) return unsupported;
  }
  return null;
}
