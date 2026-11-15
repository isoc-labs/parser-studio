// What the Ruby grammar is generated from.
//
// PRIMITIVE_MODULE: functions of this module are not translated; each has a hand written Ruby counterpart of
// the same name (psg_<snake_case>) in backend/templates/grammar-runtime.rb.tpl, checked by the primitive
// conformance test. EXTERNS: other functions that stay hand written on the Ruby side.
export const PRIMITIVE_MODULE = 'src/grammar/primitives.ts';

export const EXTERNS = {
  'src/portableRegexExtraction.ts#extractPortableRegexFields': 'psg_x_portable_regex_fields',
};

export const TARGETS = [
  {
    output: 'backend/templates/grammar-core.generated.rb.tpl',
    title: 'Parser Studio grammar: every format of the generated parser, generated from the grammar the browser executes.',
    entries: [
      ['src/grammar/readEvent.ts', 'readEvent'],
      ['src/grammar/extractEvent.ts', 'extractEvent'],
      ['src/grammar/extractEvent.ts', 'tokenizeCsvRow'],
    ],
    // Generic Structural is by far the largest part and only a generic_structural project executes it.
    split: {
      output: 'backend/templates/grammar-generic.generated.rb.tpl',
      title: 'Parser Studio grammar: the Generic Structural routes (emitted for generic_structural projects only).',
      roots: [
        ['src/genericStructural.ts', 'extractGenericStructural'],
        ['src/grammar/genericParseStatus.ts', 'classifyGenericStructural'],
      ],
    },
  },
  {
    output: 'scripts/verification/translation-probes.generated.rb',
    title: 'Probes of the translation itself (scripts/verification/translation-conformance.ts).',
    entries: ['probeString', 'probeScan', 'probeRegex', 'probeNumber', 'probeValue', 'probeCollections']
      .map(name => ['scripts/verification/translation-probes.ts', name]),
  },
];
