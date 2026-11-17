# LF-0 baseline census — 2026-11-17

This is an isolated experiment checkout at baseline `1b14cf0d70602788ac0cd73521eee696a45c0e51`.
The figures below describe repository behavior and the checked test corpus; they are not vendor-wide accuracy claims.

## Independent status dimensions

| Dimension | Existing evidence | Meaning |
|---|---|---|
| Original event retained | `SuiteResult.events` retains each framed event's `raw` string; raw-source copy is separately controlled by `omitSourceRaw` for Generic Structural output. | Source retention does not establish extraction completeness. |
| Structured extraction | `readEvent` grades FULL/PARTIAL/UNKNOWN/ERROR; the Generic Structural guard independently reconstructs JSON/CEF/LEEF/CSV body accounting. | FULL is an extraction verdict, not a mapping or native target verdict. |
| Mapping/output | `createCanonicalMappingPlan` tracks safe-path mapping decisions; generated normalized fields are checked separately by sample validation. | Source raw copies and merely extracted leaves are not mapped output. |

## Baseline corpus evidence

Before changing code, the focused baseline passed **53 tests across 5 files**:
`src/fieldPaths.test.ts`, `src/grammar/genericLossGuard.test.ts`,
`src/grammar/lossGuard.test.ts`, `src/guided/canonicalMappingPlan.test.ts`, and
`src/guided/NormalizationMappingReview.test.tsx`.
The generic structural corpus includes CEF, LEEF, JSON, positional CSV, and
syslog-enveloped variants. Mutating/removing or changing extracted body values
is classified PARTIAL; complete cases are FULL. This is deterministic repository
fixture evidence only.

The source path contract is bounded to depth 8 and 100 authoring leaf paths.
Literal dotted keys that collide with nested interpretations are rejected;
nulls, arrays, unsafe key segments, excess depth, and paths beyond the 100-path
authoring bound are not selectable as mapping paths. They remain in parsed
`fields`/raw samples, while `countUnaddressableSourceValues` reports the
non-addressable values. A 120-scalar adversarial object yields 100 selectable
paths and 20 unaddressable values.

## Confirmed accounting defect and correction

The baseline `countUnaddressableSourceValues` counted every array as one value,
regardless of its members. An independently asserted three-value array
(`['IOC-A', {indicator:'IOC-B'}, null]`) reproduced **1** where **3** values
were present. This did not prove extraction loss or false FULL: the values
remained in the JSON field tree and loss guard. It was a source-coverage
accounting undercount, not a reason to modify parser classification.

The corrected census counts scalar/null leaves recursively inside unaddressable
arrays and nested objects, while treating empty arrays/objects as one retained
unaddressable value. The focused rerun passed **54 tests across the same 5
files**. The UI's unmappable count for `actor@realm` plus a two-member evidence
array is now 3, distinct from its safe-path count.

## Boundaries not established

- This checkout does not contain the owner's real sample logs/parsers as an
  ingestable acceptance corpus; no synthetic data is described as real vendor
  evidence.
- The baseline did not establish exact raw-byte preservation through every
  parser/export path, or a family-wide FULL/PARTIAL/UNKNOWN census for every
  fixture. UTF-8/log-boundary regressions must be run as part of later
  qualification.
- 1,024-path candidate reconnaissance is a separate bounded scan; this report
  does not claim reviewability of source trees beyond current UI support.
- Browser output presence, Ruby runtime behavior, Stellar 7.0 import/indexing,
  and Ruby 2.4.9 are not qualified by these unit tests.
