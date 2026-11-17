# Three template changes after the accuracy work of 2026-11-16: they need new approved hashes

The first two repairs were found by the accuracy work recorded in `20261116-accuracy-after-311.md`, the third by
the independent audit of this change. None could be part of that work: each changes text of the generated Ruby,
and with it the template-set hash (the first two also the reviewed POC template hash). The approval constants are **not** changed by this change. Until the owner approves the new values, the
approval tests fail by design and the change is not merged.

## 1. JSON numbers: read when a double stands for exactly what was written

`hasUnsafeJsonNumbers` (src/jsonNumberSafety.ts, generated into the Ruby grammar, mirrored by the Python preview)
declined every number in decimal or exponent spelling with more than 15 significant digits. The reason given in
its comment was right - the browser and the Ruby must not emit another number than the one written - but the
digit count is not that property. `"ts":1731719701.123456` has sixteen digits and is exactly what a double prints:
it is the `ts` of every Zeek JSON record, and of any epoch time written from a double. Such an event was declined
on the Add Logs step and, in a generated parser, became a diagnostic record.

The rule is now the property itself: a decimal or exponent spelling is read when the double it parses to, printed
in its shortest form, gives the same decimal number. `decimalIdentity` reduces a spelling to its digits without
leading and trailing zeros and the power of ten of the last digit, so `1731719701.123456`, `1.731719701123456e9`
and `1731719701.1234560` are one number.

| Number | Before | Now | Why |
|---|---|---|---|
| `1731719701.123456` | declined | read | the double prints as this text |
| `1731719701.1234567`, `0.30000000000000004` | declined | read | 17 digits, printed from a double |
| `0.1234567890123456789` | declined | declined | the nearest double prints as 0.12345678901234568 |
| `1731719701.12345678` | declined | declined | the nearest double prints as 1731719701.1234567 |
| `4.9e-324` | read as 5e-324 | declined | below the smallest step of a double |
| integers beyond 2^53 in any spelling | declined | declined | unchanged |

Verification of the rule itself:

- 31,168 spellings (random decimals of 1 to 21 digits with and without exponents, shortest forms of random
  doubles, epoch times with 0 to 9 fractional digits, the edge values): browser and generated Ruby on 2.4.9 and
  on 3.2.11 give the same verdict for every one; the Python rule was compared on the 29,942 decimal and exponent
  spellings (0 differences). For an integer spelling beyond 2^53 the Python preview reads the integer exactly
  while browser and Ruby decline it, on main as well; the Add Logs step needs both readings, so such an event is
  not adopted.
- The verdict equals exact decimal arithmetic (Python `Decimal`, used by none of the three) for every spelling;
  7,838 of the 18,787 accepted decimals have more than 15 digits and were declined before.
- Goldens `json-decimal-printed-from-a-double` (read, value checked) and `json-decimal-one-digit-beyond-a-double`
  (declined); TS mutants `ts-json-inexact-decimal-read` and `ts-json-decimal-declined-by-digit-count`, both killed;
  ten new number seeds in the format differential.

Changes `src/jsonNumberSafety.ts` and the generated `grammar-core.generated.rb.tpl`; the Python preview follows.

## 2. A mapped value of nothing but white space is a missing value

The mapping loop skips a source value that is absent or one of the strings `""`, `N/A`, `-`
(`canonicalIgnoreSourceValue`, `parserstudio_apply_field_maps`). A string of blanks only (`user=" "`) was not on
that list, reached the typed conversion, was rejected there as "Missing value", and its event took the field-error
path: `parser_err_msg` in the generated Ruby, a failed event in the browser preview. An independent audit found
it (P2-4) after the automatic draft stopped dropping a field that is empty in one event.

A string of nothing but ASCII white space - the six characters space, tab, LF, CR, FF and VT that the typed
conversion already trims; NUL, NBSP and the other Unicode spaces stay values - is now skipped like the empty string, in the browser and in the Ruby operators. The check of the Map Fields
step (`valueFitsMappingType`, `valueFitsNormalizationTarget`) asks the same contract, so the sample is not
stopped there either; that part changes no template.

| Mapped value | Before | Now |
|---|---|---|
| absent, `""`, `N/A`, `-` | skipped | skipped |
| `" "`, tab, CR LF only | field error for the event | skipped; the other mappings of the event apply |
| NBSP (U+00A0) only | a value | a value (not ASCII white space) |
| `" 192.0.2.1 "` as a string | kept with its blanks | kept with its blanks |

Verification: four cases in the operator matrix (`contracts/operator-conformance.v1.json`: string, ip, integer,
NBSP), each run ordinary and as an event family in the browser and in native Ruby; with either half reverted alone
the matrix fails. The audit's sample (`user="bob"` / `user=" "`, key=value and JSON) normalizes 2 of 2 and
has no finding on Map Fields (red with the check reverted).

What follows from the skip, each equal to the behaviour for `""`: a blank official `timestamp`, `srcip` or
`dstport` gives an ordinary record without that field (it was an error record); a blank discriminator of a `when`
condition also leaves out the fields conditioned on it; an enrichment that reads a field whose source was blank
fails the event at the enrichment stage. The value itself is not written; formats with a source copy (Generic
Structural) keep it there.

The review of ChatGPT proposals and the review of event types ask the same rule: a proposal whose every sample
value is blank is blocked like one whose every value is empty, and a blank-only typed value does not stop the
event-type review. The automatic draft calls a value blank by the same six characters, so a field whose samples
are all NBSP is mapped.

In Chromium, for `user="bob"` / `user=" "` / `user="eve"`:

| Tree | Journey | Downloaded parser under Ruby 2.4.9 |
|---|---|---|
| main before the accuracy work (949c474) | completes | 3 events, no `user` in any of them |
| main with the accuracy work | stops on Map Fields: "a sample value does not fit the selected value type" | - |
| this change | completes | 3 events, 0 error records, `user` bob and eve, none for the blank one |

Changes `backend/src/canonical-operator-contract.ts` and `backend/templates/canonical-operators.rb.tpl`.

## 3. A JSON message of a Syslog envelope is read as JSON or declined, never as free text

Found by the independent audit of this change; on main as well. Behind an RFC 3164 header, a message that
claims to be a JSON object and that the JSON body contract does not read - a number that cannot be kept exactly,
a repeated member name, the bounded depth, or text that is not JSON after all - fell through to the tagged-message
profile:

```
<134>Nov 16 10:15:04 fw01 app: {"k":"a","n":9007199254740993,"m":{"x":2.5},"t":"x"}
```

Browser and generated Ruby emitted the header and the raw message as a complete event: none of `k`, `n`, `m.x`,
`t`, no `parser_err_msg`, verdict FULL. RFC 5424 + JSON and prefix + JSON already declined the same event.

| Parser | Before | Now |
|---|---|---|
| new (dedicated grammar, as for the CEF/LEEF claims of owner policy D-2) | tagged message, FULL | declined with the reason |
| existing project (no dedicated grammar) | tagged message, FULL | tagged message, PARTIAL: the members are not parsed |
| a message that claims an object and is not JSON (`{"k":"a",}`) | tagged message, FULL | as the first two rows |
| a message the contract accepts | read member by member | the same |
| text that does not make the claim (`{not json} started job 7`, `{"k":"a"} trailing words`) | tagged message | the same |

The claim is lexical - an opening brace, a member name in quotes with its colon, a closing brace at the end of
the message - so that the browser and the generated Ruby cannot disagree about it (the first version asked each
JSON library whether the text parses; the differential showed the two differ on an escape that names no
character).

Not covered: a key=value body with a tab inside a quoted value takes the same fallback to a tagged message (on
main as well); a key=value "claim" has no syntax that would tell it from free text.

Changes `src/genericStructural.ts` (`envelopedJsonDeclined`), `src/grammar/genericParseStatus.ts` and the
generated `grammar-generic.generated.rb.tpl`. Goldens for both routes, two TypeScript mutants, three seeds of the
browser/Ruby differential.

## Hashes

Recalculated independently of the project code from the artifacts the compiler emits (Ruby text with the project
literal replaced; digest over the template files and the 102 artifacts), equal to the manifest written by
`scripts/verification/ruby-template-set.ts`. The independent auditor recalculated the first three rows with his
own code. Computed under Node 24; CI pins Node 22 (the digest depends on the zlib of Node; main's approved values
come out the same under both).

| State | Reviewed POC template SHA-256 | Template-set SHA-256 |
|---|---|---|
| approved today (main) | `a829026d948b8a492db534ddf50e9009a8686f6a3a642abccaecb7f332bed246` | `3bd3172b620f0c09f87d5b8d9df548b2c187048b451a0cde7cf95cf287421936` |
| change 1 alone (`0dda714`) | `be0005935032cc9fe2e4dadfeda01c6dd94f824cbdaacd576b71fcffe30750ce` | `7919a4437d83f99aaac18ec6443da1e7531dd50d9654e3e7b16fd7ae13e614e5` |
| changes 1 and 2 (`6449387`) | `4efddd8b5446799c0173788a8ef913fa393162cf18c1e1463e7e3e2e338bbfb8` | `c74c2d82d28447efafc5035327810d0ca3a461f5ab20cb3fdf0baa04d8cdec2d` |
| changes 1, 2 and 3 (head) | `4efddd8b5446799c0173788a8ef913fa393162cf18c1e1463e7e3e2e338bbfb8` | `49dd3680c8dea6f0b12fef9bf95c5f1ff3fd0cfde5628bf684990311fc8be411` |

The POC template reads JSON and does not hold the Generic Structural grammar, so change 3 leaves its hash as it
is. The changes are separate commits, so each state can be approved.

## Verification of the head (all three changes)

- TypeScript build; vitest 236 files, 2,042 tests; Python suite 191 tests; grammar generators in sync;
  candidate mutation gate 92.31% with the 8 reviewed equivalents.
- Translation conformance; semantic oracle in the browser, in native Ruby 2.4.9 (Generic Structural goldens 48 of
  48) and in Python, with its mutants (the two new TypeScript mutants are killed).
- Browser/Ruby differential: formats 44,948 cases, 0 differences, 15 of 15 injected faults detected; Generic
  Structural 23,486 cases from 109 seeds and 27,000 random cases, 0 differences.
- Operator matrix: 115 compiled pairs, 230 native records, equal to the independent truth.
- Backend suite: 759 of 775; the failures are the 12 tests that compare against the approved hashes and 4 that need Drain3 or
  a Ruby runner the development host does not have.
- Real Chromium journey with the downloaded Ruby under 2.4.9, 92 samples and five probes, all three changes:
  the Zeek sample is downloaded with `ts` written as `1731719701.123456`; 24 holdouts: 14 downloaded, 78 correct
  Stellar meanings, 0 mapped to a forbidden field, 0 lost; the 68 earlier samples give exactly the result of main
  (43 downloaded, 99 events, 0 error records, 2,425 values each text of its own line).

| Probe | main (c5f1a1b, Development Preview) | this change |
|---|---|---|
| `user="bob"` / `user=" "` / `user="eve"` | stops on Map Fields | downloaded; 3 events, 0 error records, `user` bob and eve |
| BSD syslog + JSON, one event with the integer 9007199254740993 | downloaded; that event is written as a tagged message with the JSON text as `message`, no member, no error | stops on Add Logs and names the number |
| the same with safe numbers | downloaded, read member by member | the same |

## Independent audit

An independent auditor examined 6449387 (changes 1 and 2) with his own generators: **0 P1 and 0 P2 introduced**.

- Change 1: 85,573 spellings; the browser verdict equals exact arithmetic (39,278 read, 45,863 declined); the
  generated Ruby on 2.4.9 and 3.2.11 equals the browser; none of the 39,278 read numbers is emitted as another
  number; 0 regressions against main, 1,174 numbers main emitted as another number are now declined.
- Change 2: 1,607 one-event lines through 17 scenarios; browser preview and Ruby 2.4.9 agree record for record;
  660 events that failed on main now pass, only for the six ASCII blanks.
- All six hashes of the first three rows recalculated with his own code.

| Finding | Disposition |
|---|---|
| M1 (class P2, on main) BSD syslog + JSON with a declined number is emitted as a complete tagged message | Fixed: change 3 |
| F1 (P3) the review of ChatGPT proposals kept its own list of ignored values | Fixed |
| F2 (P3) the review of event types stopped a blank-only typed value | Fixed |
| F3 (P3) "browser = Ruby = Python for 31,168 spellings" was not measured for integer spellings | Statement corrected (section 1); the Python reading of integers beyond 2^53 is on main and is not changed |
| F4 (P3) wording of the title and of the blank test | Corrected |
| F5 (P3) mutations no test killed: capital exponent mark, leading zeros, the 17-digit form, NUL in the operator matrix | Tests added |
| F6 (P3) consequences of the skip not stated | Stated in section 2 |
| F7 (P3) Python preview failed on an exponent of more than 4,300 digits | Fixed |
| M3 (P3, on main) the automatic draft called a value blank by Unicode `trim()` | Fixed for the automatic draft; `sampleUnionSchema.ts` still uses `trim()` |

Not verified: a real Stellar Cyber 7.0 sensor, loader, import or indexing; production.
