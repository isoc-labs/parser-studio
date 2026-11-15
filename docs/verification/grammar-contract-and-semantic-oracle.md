# Grammar Contract and Semantic Oracle

Status: introduced 2026-11-13 (Issue #249). This document is the working
standard for adding or changing a parsing grammar or a field mapping.

## Why defects kept recurring (measured on main `bed8db3`)

| Root cause | Evidence in the code |
|---|---|
| The same header grammar is hand-written in three languages | 148 literal copies of five Syslog header tokens: 69 in TypeScript, 60 in Ruby templates, 19 in Python (`contracts/grammar-duplication-baseline.v1.json`). `[!-~]{1,255}` (HOSTNAME) alone occurs 26 times in 8 files |
| Differential tests pass when both executors are wrong in the same way | F-1: `<134>Nov 13 10:00:00 srcip=10.1.1.1 ...` gives `syslog_hostname="srcip=10.1.1.1"` in `src/structuredFamilies.ts` and in `backend/templates/ruby-fragment.rb.tpl`; the generated Ruby then drops `srcip` and classifies the event as `syslog` instead of `session`. Browser and Ruby agree, so parity is green |
| "Parsed" is declared by the parser that parsed | No stage re-reads the raw line; a field swallowed into the wrong place is still a success |
| Policy is decided per consumer | F-2: `src/rfc5424Subset.ts` parses only VERSION 1, `src/syslogEnvelope.ts` and the Generic Structural Ruby helper accept `[1-9]\d{0,2}` |
| Regular-expression dialects differ silently | F-3 (found by the new property generator): `.` excludes U+2028 in ECMAScript but not in Ruby, so the browser rejects a line that the generated Ruby parses |
| The corpus follows the defects already found | Hand-picked samples; no generator that varies host, PRI, tag, order, Unicode or boundaries with an independent expectation |
| Target runtime differs from the developer runtime | Ruby 2.4.9 gates exist (#299, #301) but covered compiler variants, not grammar semantics |

## Architecture

```
contracts/syslog-header-grammar.v1.json        one declarative grammar (tokens, rules, alternatives, semantic limits)
        |  scripts/grammar/generate-grammar.mjs  (portable-subset validator, --verify in CI)
        +--> src/grammar/syslogHeaderGrammar.generated.ts   ECMAScript dialect  -> src/grammar/syslogHeader.ts
        +--> backend/src/syslog-header-grammar.generated.ts  Ruby dialect        -> injected into the Ruby templates by the compiler
        +--> Python dialect                                  -> Multi-Pass (roadmap)

contracts/semantic-goldens.v1.json             hand-authored expectations (raw text + RFC citation)
src/grammar/syslogHeaderModel.ts               model-rendered property cases, expectation computed from the model
src/grammar/parseStatus.ts                     FULL / PARTIAL / UNKNOWN / ERROR decided against the raw line
scripts/verification/semantic-oracle.ts        both executors versus the expectations + fault injection
scripts/verification/grammar-duplication-ratchet.mjs   hand-written copies may only decrease
```

### A. Single source of truth
A token pattern may use only the regular-expression subset that means the same
in ECMAScript, Ruby 2.4 and Python. The generator rejects `.`, `\d`, `\w`, `\s`,
anchors, back-references, capture groups inside tokens and lazy or possessive
quantifiers. Captures belong to rules and are read by name, so a consumer cannot
shift a group index. Semantic limits (`priMax`, calendar, supported RFC 5424
versions) are contract data.

### B. Semantic correctness oracle
Executors are compared with expectations, not with each other. A golden states
the source fields (browser extraction), the emitted event under a fixed mapping
profile (generated Ruby on Ruby 2.4.9), fields that must be absent, and the
status. The oracle refuses a golden whose expected source value is not literal
raw text.

### C. Parsing success contract
`classifyStructuredParse` re-reads the raw line with a separate, simpler
tokenizer. A key=value pair that is visible in the raw text but missing from
the extracted fields makes FULL impossible (PARTIAL). Extraction errors are
UNKNOWN, a raising extractor is ERROR. FULL does not require a Stellar mapping
for every vendor field.

Wired into the product (W7, first slice): `processEvent` in `src/parser.ts`
classifies every previewed event and puts the verdict on
`EventResult.parseStatus`. For a key=value body (format `kv`, or RFC 3164 /
RFC 5424 with body `kv`) a PARTIAL verdict adds the error diagnostic
`FIELD_LOSS_NOT_FULL`, so the event status is `fail`, `counts.failures` rises
and every existing gate that refuses failed samples refuses it. The RFC 5424
header fields are positional and are not counted as pairs (a HOSTNAME written
`a=b` is a host name); RFC 3164 gets no such exemption because its HOSTNAME is
optional. `src/parseStatusGate.test.ts` injects an F-1 style loss into the
extractor and requires `fail`. On the 3,897 audit lines no correctly parsed
line is classified PARTIAL (281 key=value parses, all FULL).

`auto` bodies and the key=value branches of a `mixed` allowlist are covered as
well: the extractor records which body dialect it actually parsed
(`bodyKindOf` in `src/structuredFamilies.ts`, kept beside the result so its
shape does not change) and the pipeline applies pair accounting whenever that
is key=value. The draft-based condition stays in place, so losing the record
cannot switch the check off.

Generated Ruby at run time (W7). A line that never appeared as a sample is
checked by the artifact itself: `parserstudio_extract` ends with
`parserstudio_assert_no_field_loss(text, result)` in both templates. For a
key=value body the original text is read again by a separate control flow
(every white-space separated token is visited, with no header and no pair
order; the key and quoted-value tokens are the contract's) and a pair that is
missing, has another value, or occurs more often in the text than in the
result raises, so the event becomes an error record instead of a parsed event
that lacks a field. A TAG (`kernel:`) or a pair read as the RFC 3164 host name
is refused the same way (RFC 5424 HOSTNAME is positional and exempt). The
browser applies the same two rules (`src/grammar/parseStatus.ts`,
`HEADER_MISREAD_NOT_FULL`). Proof: the native oracle injects three grammar
faults that lose a pair silently and prints, per fault,
`RUNTIME_FIELD_LOSS_GUARD ... wrong_events_without_guard=N
wrong_events_with_guard=0`; `backend/test/runtime-field-loss-guard.test.ts`
injects pair loss, value truncation and a skipped first pair on six routes in
both templates.

Not covered by the run-time check: CSV, JSON, CEF and LEEF bodies (the oracle
holds those), and Generic Structural, whose verdict is described below.

### D. Property-based and metamorphic cases
Every variant has its own expectation: base, double spaces, reversed pairs,
HOSTNAME omitted, PRI omitted (FULL for the tagless form, NEVER_WRONG for the
tagged form), TAB as separator (UNKNOWN), PRI and day out of range (UNKNOWN),
U+2028 inside a value (FULL). Values cover IPv4 and port boundaries, 64-bit
counters, UTF-8, quoted values that contain `=` and URLs that contain `=`.

### E. Generated artifact contract
The native oracle compiles real projects with `compilePair`, executes the
Fragment on Ruby 2.4.9 and checks event count, mapped values, types,
classification and absence. It also proves that the contract's Ruby regular
expressions capture exactly what its ECMAScript expressions capture.

### Fault injection
The gate must show that it can detect a new defect. Faults are injected into a
private copy of `src/` (TypeScript) and into the generated Fragment (Ruby); every
fault must be reported and the unmutated copy must reproduce the product result.
A `knownDefect` case is a strict expected failure: it must fail on the listed
engines and the gate fails when it starts to pass.

## Migration status

The Ruby rows of this table describe the state before W4 was completed. Since 2026-11-15 the Ruby grammar is
generated from the TypeScript grammar (see "One grammar: executed in the browser, translated for Ruby"); the
templates named below with a hand-written grammar no longer exist.

| Consumer | State |
|---|---|
| `src/structuredFamilies.ts` (RFC 3164 extraction and detection), `src/rfc5424Subset.ts`, `src/guided/autoParserEnvelope.ts` (tagless front door) | contract (`src/grammar/syslogHeader.ts`) |
| `backend/templates/ruby-fragment.rb.tpl`, `ruby-forwarder-family.rb.tpl` (`parserstudio_syslog_rfc3164`, `parserstudio_syslog_rfc5424`) | contract, injected by `injectHeaderGrammar` in `backend/src/compiler.ts`; a template with an unresolved `__PS_GRAMMAR_*__` placeholder does not compile |
| `src/genericStructural.ts`, `src/syslogEnvelope.ts`, `backend/templates/generic-structural-helper.rb.tpl`, `runtime/multipass/generic_structural_poc.py` (W4) | header tokens from the contract: PRI, BSD month, printable-ASCII host token, TAG, RFC 5424 VERSION (`T.*` in TypeScript, compiled once per expression; `__PS_GRAMMAR_TOKEN_*__` and `__PS_GRAMMAR_RFC5424_VERSION_PATTERN__` in Ruby; `TOKENS` in Python). 93 literal copies removed |
| the bodies of the Generic Structural sub-profiles, the other `runtime/multipass/*.py` files, a few UI helpers | hand-written; 49 token copies left in the ratchet (142 before W4) |

Resolved: F-1 (field loss when HOSTNAME is omitted), F-2 (one RFC 5424 VERSION
policy, including `detectStructuredFamily`), F-3 (U+2028 inside a value, on the
structured path and in the message of the generic envelope), F-4 (RFC 5424
TIMESTAMP with an impossible day: the browser rejected it, Ruby `Time.iso8601`
rolled it over), F-5 (a TAG such as `kernel:` read as HOSTNAME when HOSTNAME is
omitted). F-4 and F-5 were found by the independent audit of 2026-11-13. The
corresponding goldens and property variants are ordinary must-pass cases; the
faults `contract-hostname-any-printable` and `contract-hostname-trailing-colon`
re-introduce F-1 and F-5 in the contract and must be reported by both
executors. The native oracle runs every case through both Ruby templates
(`ruby-fragment` and `ruby-forwarder-family`).

Known differences that remain (evidence: independent audit, 2026-11-13):

- Python Multi-Pass: `security_envelope.py` (BSD envelope) and the RFC 5424
  VERSION / PRI checks of `structured_source.py`, `security_pairs.py` and
  `generic_structural_poc.py` read the generated
  `syslog_header_grammar_generated.py`; F-1 and F-5 are gone there and the
  oracle has a `python` engine. The other Multi-Pass header expressions are
  still hand-written (ratchet).
- Auto Parser front door, tagged path: still a hand-written header expression
  (W4). Its key=value validation now uses the contract parser.
- Generic envelope and Generic Structural extractor, browser versus Ruby 2.4.9
  (W4): the 34 differing audit lines are resolved (host token delimited by
  ASCII white space, exactly one SP removed before an RFC 5424 MSG, BOM kept,
  `.` spelled out in the BSD message profiles). On the audit's 3,897 lines the
  envelope is identical on all of them and the extractor has no one-sided
  accept and no field difference (707 parsed identically, 3,190 rejected by
  both). The grammar of the Generic Structural sub-profiles is still
  hand-written in TypeScript and Ruby; what is shared is the VERSION gate, the
  goldens (`genericCases`) and the faults.
- The oracle covers the structured RFC 3164 / RFC 5424 path with a key=value
  body, the forwarder-family template and Generic Structural goldens. JSON,
  CEF, LEEF and raw bodies and the mixed router are not in it yet (W6).
- The duplication ratchet counts exact literal copies; a re-spelled copy is not
  counted.

## Key=value body grammar (W3)

`fragments.kv_pair` in the contract is the one definition of a strict key=value
pair: `KEY="..."`, `KEY='...'` or `KEY=bare`, matched at a position (sticky in
ECMAScript, `\G` in Ruby, `pattern.match(text, pos)` in Python). SP and TAB
separate pairs; every other character, NBSP and U+2028 included, is value data.
The pair limit, the forbidden keys and the characters that are decoded after a
backslash are contract semantics.

Consumers: `src/grammar/kvBody.ts` (used by `strictKeyValues` and by the Auto
Parser front door, which previously had its own token expression with a
different white-space notion), and `parserstudio_key_values` /
`parserstudio_unescape` in both Ruby templates. `src/grammar/kvBodyModel.ts`
renders bodies from meant values (quotes of both kinds, escaped quotes,
Windows paths, escaped `=`, U+2028, NBSP, UTF-8, adjacency after a quote,
100/101 pairs, duplicate and forbidden keys, unterminated quotes) and the
oracle runs them through both executors and both Ruby templates.

The Python Multi-Pass source scanner (`runtime/multipass/source_kv.py`) reads
the same fragment, escape set, forbidden keys and pair limit from the generated
Python module. Before, it was a hand-written scanner that split pairs with
`str.isspace()` (so NBSP and U+2028 ended a value, defect F-8) and decoded a
different escape set (`\=` kept, `\ ` decoded). The oracle's `python` engine
sends the goldens and the model-rendered bodies through
`multipass_preview_api.preview`, the entry point the Analyze step calls.

Information separators (issue #214): U+001C..U+001F are never value data and
never a pair separator. `KV_BARE` excludes them, so the strict path of the
browser and of the generated Ruby now declines such a line the same way
Generic Structural and the Python preview already did (defect F-7). The
portable regex subset gained `\xHH` for ASCII code points for this purpose.

Owner policy D-1 (decided 2026-11-14): a field written more than once in one
event is never resolved by keeping one of its values.

| Engine | Behaviour |
| --- | --- |
| Python source preview | keeps the original key and every value in wire order; issue `DUPLICATE_SOURCE_FIELD`, status never `SOURCE_PARSED` |
| Browser extractor | declines the event; the message names the repeated field (`duplicateFieldMessage`) |
| Generated Ruby | declines the event (error record, no parsed event) |

It applies to key=value bodies (bare and under RFC 3164 / RFC 5424), CEF and
LEEF 1.0 / 2.0. The Analyze step names the repeated fields in plain words and
does not offer parser files while a field is repeated. The oracle enforces it
with hand-written goldens and model-rendered cases that carry
`expect.repeated` (every meant value, in order) and with fault injection in all
three engines (`ownerPolicies.D-1` in `contracts/semantic-goldens.v1.json`
lists them).

`parse_quoted_kv` in `runtime/multipass/engine.py` keeps its own pair expression; it has no caller (see below).

## CEF and LEEF (W6)

Covered by the oracle in all three engines: hand-written goldens taken from the
ArcSight CEF and IBM LEEF format guides (`familyCases`) and bodies rendered from
meant values (`src/grammar/cefLeefModel.ts`: header escapes, extension escapes,
multi-word values, Windows and UNC paths, U+2028, UTF-8, LEEF 1.0 and 2.0
separators, missing header fields, truncated escapes, an undefined LEEF
version). Faults are injected into the browser extractor, the generated Ruby
and the Python preview.

Defects this found:

- F-9: a CEF or LEEF line with U+2028 in a value was rejected by the browser
  only (`.` in two head expressions). Fixed with dotAll.
- F-11: the header splitter also decoded backslash escapes in the extension,
  and the extension grammar decoded them again - identically in the browser and
  the generated Ruby, so every differential test passed. A Windows path
  `filePath=C:\\Users\\new` came out as `C:\Users` LF `ew`, and the CEF
  guide's own example `act=blocked a \\ dst=1.1.1.1` lost `dst`. LEEF values,
  which have no escapes at all, lost one backslash of a UNC path. Fixed in
  `splitEscaped` and `parserstudio_split_escaped`: the text after the last
  header delimiter is kept exactly as written. The Python preview was already
  correct.
- F-10: the Python preview reported a malformed CEF/LEEF line as parsed through
  its permissive generic fallback. Fixed with `fragments.structured_family_claim`.

Owner policy D-2 (decided 2026-11-14): inside Generic Structural a line that
claims to be CEF or LEEF (`fragments.structured_family_claim`) is, for every
newly created parser, read by the CEF/LEEF grammar or declined. The marker is
`extraction.genericStructuralFamilyGrammar: "dedicated"` (draft, project
schema, validator, capability `genericStructuralDedicatedFamilies`); it is set
when Generic Structural is selected, built automatically or taken from an AI
recipe, and kept as stored on import. The result is
`{body: <CEF/LEEF fields>, generic: {mode: structured_family_cef |
structured_family_leef, source_raw}}`. A project without the marker keeps its
V15 output (legacy compatibility route: the three existing tests still pass
unchanged); its verdict for such a line is PARTIAL with the warning
`GENERIC_STRUCTURAL_NOT_FULL`, never FULL. A backend that does not advertise
the capability is refused before download (`BACKEND_PROFILE_UNSUPPORTED`).
Enforced by `ownerPolicies.D-2`: `genericCases` with `familyGrammar` and
`expect.status` run against the browser extractor and verdict and against two
compiled Ruby artifacts (with and without the marker) on Ruby 2.4.9; faults
`ts-generic-dedicated-gate-removed`, `ts-generic-claim-verdict-full`,
`rb-generic-dedicated-gate-removed`, `py-generic-family-claim-gate-removed`;
`src/ownerPolicyD2GenericFamilies20261114.test.ts` and
`backend/test/owner-policy-d2-generic-families.test.ts` read the same goldens.

Contract values (revision 5): the CEF extension key token (`CEF_KEY`), the
LEEF attribute key token (`LEEF_KEY`), `cefSupportedVersions`,
`leefSupportedVersions`, `cefMaxExtensionFields`, `cefExtensionEscapes` and the
forbidden keys are read from the contract by the browser extractor, by both
Ruby templates (`__PS_GRAMMAR_TOKEN_CEF_KEY__`, `__PS_GRAMMAR_CEF_*__`,
`__PS_GRAMMAR_LEEF_VERSIONS__`, `__PS_GRAMMAR_FORBIDDEN_KEYS__`) and by the
Python CEF passes. Defect F-13: the Python preview parsed `CEF:1|` while the
browser and Ruby implement CEF version 0 only; all three now read
`cefSupportedVersions`.

The Python LEEF pass (`decode_cef_or_leef` in `structured_source.py`) reads
`leefSupportedVersions`, `LEEF_KEY` and the forbidden keys as well; its own
bounded key expression used to reject an attribute key longer than 128
characters that the browser and Ruby accept.

Control flow (contract revision 6). The CEF extension and the LEEF delimiter
are contract fragments (`cef_pair`, `leef_delimiter`, `leef_attribute`; tokens
`CEF_WS`, `CEF_WS_RUN`, `CEF_NOT_WS`, `CEF_ESCAPE`, `CEF_PLAIN`,
`LEEF_DELIMITER_LITERAL`, `LEEF_HEX_DIGITS`; semantics
`leefDelimiterFieldVersions`, `leefHeaderFields`, `leefDefaultDelimiter`,
`leefDelimiterExtraCodePoints`). The five hand-written CEF extension scanners
are gone (one fragment plus a short loop per engine) and the five copies of
the LEEF delimiter rule, which had three different behaviours, are one. All
three engines now agree: a LEEF hex delimiter is `0x` or `x` plus one to four
hex digits, a white-space delimiter is refused, an empty attribute or a
trailing delimiter is refused, trailing white space of a CEF line is grammar.
`ruby-forwarder-family.rb.tpl` is generated from `ruby-fragment.rb.tpl` plus
an overlay (`scripts/grammar/generate-forwarder-template.mjs`; `--verify` in
CI), which removed 723 duplicated lines. Scanning is linear (200,000 spaces:
milliseconds in JavaScript, Ruby 2.4.9 and Python).

## Generic Structural: browser versus generated Ruby (differential, 2026-11-14)

W4 replaced token literals only, so its acceptance test is that nothing changes: 58,430 lines (every string
of the repository's fixtures and tests plus PRI, VERSION, month, host and key mutations of the 655 lines that
parse) were run through `extractGenericStructural` / `parseSyslogEnvelope` and through the compiled Ruby on
Ruby 2.4.9, in five configurations (legacy, dedicated, three profiles), before and after. The SHA-256 of the
complete output is identical on both sides (browser `56b91485...`, Ruby `e30c8ba3...`).

The same run compares the two engines with each other, which no earlier check did on mutated lines. On the
legacy configuration it found 33 lines parsed only by the browser, 24 parsed only by the generated Ruby and
33 parsed by both with a different field tree. Causes and state:

| Cause | Lines | State |
|---|---|---|
| Positional CSV route: 150 columns in Ruby, 100 in the browser; a PAN-OS row longer than 100 columns got a tree without `syslog.variant` / `generic.profile` from Ruby | 31 | fixed in Ruby (100, and the PAN-OS check of the browser) |
| `Time.new` rolls 30 February over to 2 March, so the Ruby envelope calendar accepted an impossible date; the positional route had no PAN-OS check at all | 23 | fixed in Ruby (calendar by arithmetic, as in the browser) |
| JSON body inside Generic Structural with an integer beyond 2^53: the browser parsed and rounded it, Ruby declined | 19 | fixed in the browser (`parseJsonBody`, one function for the three JSON routes) |
| `.` after PRI stops at U+2028 in JavaScript: another route, another tree | 2 | fixed in the browser (`[^\n]`) |
| An SD-NAME that is not valid (non-ASCII, longer than 32 characters, DEL in the SD-ID): the browser's envelope accepts it, Ruby declines | 14 | open |
| IP token: lexical rule in the browser, `IPAddr.new` in Ruby (`[::1]` is an address only in Ruby; `12:34:56` only in the browser) | 1 | open |

After the fixes: 6,123 lines parsed identically, 15 one-sided, 0 tree differences. Goldens
`generic-envelope-json-integer-beyond-2-53`, `generic-panos-receive-time-30-february`,
`generic-pri-space-kv-u2028`, `generic-panos-traffic-more-than-100-columns` and faults
`ts-generic-json-unsafe-integer-accepted`, `ts-generic-pri-space-kv-stops-at-u2028`,
`rb-generic-calendar-rollover`, `rb-generic-positional-150-columns` keep them.

Unicode white space and separators (second run, 26,000 variants with U+2028, U+2029, NBSP, U+0085, U+3000,
U+FEFF and edge white space): 1,244 lines parsed with a different tree, 258 only in the browser, 194 only in
Ruby. Classified by cause and closed on 2026-11-15:

| Cause | Lines | Decision |
|---|---|---|
| JavaScript `\s` / `\S` also match Unicode white space; Ruby's are ASCII | most of the tree differences in `space_kv`, `comma_kv`, `delimited_kv` | supported input: NBSP, U+2028 and the like are value data (contract KV_GAP). The browser spells the ASCII class out everywhere |
| JavaScript `trim()` removes Unicode white space; Ruby `strip` does not | value edges | browser trims ASCII white space only (`ASCII_EDGE_SPACE`); the CEF extension slot likewise |
| `.` stops at U+2028 / U+2029 in JavaScript | lines parsed by Ruby only (WatchGuard, bracket PID, session envelope) | every expression carries the dotAll flag |
| a line feed or NUL inside the event | positional CSV, key=value | unsupported input: declined by both engines up front (one event is one line) |
| impossible calendar values (30 February, hour 24, second 60): `Time.iso8601` and `Date.parse` roll them over, each differently | timestamps of nine Ruby and five browser routes | unsupported input: one arithmetic timestamp rule in both engines (`parserstudio_generic_iso_timestamp!`, `isoTimestampOk`) |
| SD-NAME validity (browser envelope accepted any bracketed text) | 14 + 46 | unsupported input: the envelope uses the strict STRUCTURED-DATA scanner of the RFC 5424 format, as Ruby does |
| IP token (browser lexical, Ruby `IPAddr.new`); WatchGuard envelope counted IPv4 only in Ruby | found by the gate itself | one lexical rule in both engines; IPv6 addresses count on every WatchGuard route |

Result on the same corpora: 58,430 lines - 0 one-sided, 0 tree differences; 26,000 Unicode variants - 0 and 0
after the CEF extension fix. No line that both engines parsed before is declined now except the 14 with an
invalid SD-NAME.

Independent re-audit (2026-11-15, commit `3b9e3f5`). A reviewer that had not seen the work ran its own
pseudo-random stream against both engines (a special token inserted, a character deleted or replaced, words
moved between seed lines): 378 differences in 84,000 cases, while the gate of that commit reported none. Eight
causes, all closed:

| Cause | Before | Decision |
|---|---|---|
| UTC offset `Z` or `+hhmm` after a space-separated date (`iso_space`, `slash_date`): validated in Ruby with `Time.new`, which on 2.4.9 takes only `+HH:MM` | browser parsed, Ruby declined | supported input (both recognizers write `[+-]HH:?MM`): the offset is checked as text, `parserstudio_generic_zone_valid` = `validZone` |
| fraction of a second after a BSD clock time: `Integer("07.915")` in Ruby | browser parsed, Ruby declined | supported input (both recognizers admit the fraction): the clock is matched as text |
| offset without colon in an RFC 5424 or loose RFC 3339 envelope timestamp: second, narrower check in Ruby | browser parsed, Ruby declined | supported input: the envelope sites pass `basic_offset`, like the browser's `validIsoTimestamp` |
| offset minute 60 and above on the ISO-PRI routes: `Time.iso8601` does not bound it | Ruby parsed, browser declined | unsupported input: declined by both (same text rule) |
| JSON below 8 nested levels, lone surrogate escape: the browser's Generic Structural JSON reader did not apply the JSON source contract | browser parsed, Ruby declined | unsupported input: `parseJsonBody` applies `jsonSourceValueValid`, as the JSON format does |
| JSON that is not RFC 8259 (`/* */` and `//` comments, unknown escapes such as `\x41`, two high surrogates): the json library of Ruby 2.4.9 accepts and alters it (`10.5.5.\x416` became `10.5.5.x416`) | Ruby parsed with a changed value, browser declined | unsupported input: `parserstudio_json_strict_text?` checks the RFC 8259 token rules before `JSON.parse`, for the JSON format and every JSON body |
| quotation mark inside an unquoted CSV field (`TRA""FFIC`): the browser dropped the marks and reported a complete parse | browser parsed with characters removed, Ruby declined | unsupported input: `positionalCsvValues` is RFC 4180 strict, like `CSV.parse_line(liberal_parsing: false)` |
| astral characters: the gate excluded every line that held one (a string comparison that also matched surrogate pairs) | not compared | compared; only an unpaired surrogate, which has no UTF-8 form, is left out |

After the fixes the reviewer's generator reports 0 differences on its seeds 101 to 103 (84,000 cases) and on
further seeds (see the PR). Goldens: `generic-envelope-iso-space-basic-offset`, `generic-envelope-iso-space-zulu`,
`generic-envelope-rfc3339-loose-basic-offset`, `generic-envelope-bsd-fraction-of-second`,
`generic-envelope-rfc5424-basic-offset-asa`, `generic-iso-pri-offset-minute-60-declined`,
`generic-json-nesting-depth-9-declined`, `generic-json-lone-surrogate-escape-declined`,
`generic-json-two-high-surrogates-declined`, `generic-json-unknown-escape-declined`, `generic-json-comment-declined`,
`generic-positional-csv-quote-inside-unquoted-field-declined`,
`generic-positional-csv-quoted-field-with-comma-and-quote`, and for the JSON format `json-unknown-escape`,
`json-comment`, `json-two-high-surrogates`, `json-lone-low-surrogate`.

Every other format (2026-11-15, after the re-audit). The same kind of stream was then pointed at the formats
that are not Generic Structural: key=value, JSON, CEF, LEEF, CSV (comma, semicolon, TAB) and RFC 3164 / RFC 5424
with each body, 17 configurations. The rule compared: the browser preview calls an event completely parsed
(FULL) exactly when the generated Ruby returns a record, and then the two field trees are equal; PARTIAL and
UNKNOWN in the browser are a record the generated Ruby declines. Found and closed:

| Cause | Before | Decision |
|---|---|---|
| `CSV.parse_line` of Ruby 2.4.9 decides quoting by counting quotation marks: `""a""` is the field `"a"` | Ruby parsed, browser declined (CSV format and the Generic Structural CSV routes) | unsupported input: `parserstudio_csv_rfc4180?` checks the row as text first; the library only splits a conforming row |
| form feed or vertical tab at the edge of an unquoted CSV field: the browser trimmed all ASCII white space, the generated parser strips SP and TAB | different value | supported input, the value is kept: the browser strips SP and TAB only |
| a CSV row that is empty or only spaces: one empty field in the browser, "No CSV event parsed" in Ruby | browser parsed (one-column layout) | unsupported input: no row in both |
| an empty JSON object: UNKNOWN in the browser (no field was extracted), an event without fields from Ruby | Ruby parsed | unsupported input: `parserstudio_extract` raises `No field was extracted` |
| form feed or vertical tab after the last key=value pair: the grammar allows it (KV_TRAILING), the run-time field-loss check split tokens at SP and TAB only and read it into the last value | a complete event PARTIAL in the browser and rejected by Ruby | supported input: the check splits tokens at ASCII white space in both engines |

Goldens: `csv-quotation-marks-around-content-not-doubled`, `csv-form-feed-at-field-edge-is-data`,
`csv-row-of-spaces-only`, `json-empty-object`, `rfc3164-kv-trailing-form-feed`. The Python preview declined a
JSON comment and an unknown escape already; it kept an unpaired surrogate (`json-two-high-surrogates`,
`json-lone-low-surrogate`) and now declines it (`JSON_UNPAIRED_SURROGATE`).

Second independent re-audit (2026-11-15, commit `d249d79`). The same reviewer confirmed that the findings of
the first pass are closed, found no valid input that the new strict rules decline (51 RFC 8259 documents, 46
RFC 4180 rows, 50 key=value bodies under 8 headers, 2,665 timestamps) and measured the two new Ruby expressions
as linear up to 1 MB. It then found what the gate did not look at:

| Cause | Before | Decision |
|---|---|---|
| mixed format: the browser tried every body parser on the message of a Syslog envelope, the generated Ruby tests the exact prefix of the message | a message that starts with SP or TAB: FULL in the browser, declined by Ruby | the browser's router mirrors `parserstudio_mixed`: exact prefixes, nothing trimmed (the design the browser already states for lines without an envelope) |
| mixed format: the browser asked for PRI in front of a BSD timestamp, Ruby (and the RFC 3164 format in both engines) does not | `Nov 14 09:30:00 fw01 a=1 b=2`: a record from Ruby, UNKNOWN in the browser | the browser opens an RFC 3164 envelope with or without PRI |
| a blank message: no event in the browser (blank lines separate samples), a TAB-separated row of empty fields from Ruby | Ruby parsed | `parserstudio_extract` declines a blank message (`Blank event`; the white-space set of the browser's `String#trim`) |
| the gate ran neither the mixed router, nor Regex, nor the forwarder-family template, and called itself "every format" | not compared | 8 configurations added; the step is named for what it runs |
| a fault in the 100/400 leap-year rule was not reported (no 1900 / 2100 dates in the variants) | undetected | century dates added; three faults |

A Regex pattern without a static cost proof is FULL in the preview and declines every event on Ruby 2.4.9. That
is by design and cannot reach a user: such a project is refused at export (`TARGET_RUNTIME_REGEX_UNSUPPORTED`,
`backend/src/target-runtime-export.ts`, `src/guided/backendCapabilities.ts`). The gate compares only patterns
that carry the proof and fails when one of its patterns does not.

Declined by both engines, by the grammar as it stands (not differences; listed because a reader may expect them
to parse): a key=value pair with an empty value followed by another pair (`a= b=2`), JSON that starts with a
byte-order mark, an RFC 3164 line with a TAG and no PRI, seven to nine fraction digits in a short RFC 5424
timestamp.

CI gate. `scripts/verification/semantic-oracle.ts differential` runs in the required job
`native-isolated-synthetic` on Ruby 2.4.9, in two stages. The same decision and the same field tree are required
for every case.

Generic Structural, both routes (legacy and dedicated):

- enumerated variants of 58 seed lines (`contracts/generic-differential-seeds.v1.json`) and the Generic
  Structural goldens: PRI, VERSION, month, host, key and address mutations, Unicode separators, control
  characters, impossible dates, century years, time zones and fractions of a second, JSON escapes, comments and
  nesting, CSV quoting, and the 8192-byte bound: 21,052 cases;
- the reviewer's pseudo-random stream, fixed seeds 101, 102 and 103, 3,000 lines each: 18,000 cases;
- eighteen injected faults (seven in the browser extractor, eleven in the compiled Ruby), each of which must be
  reported (`ts-diff-*`, `rb-diff-*` in `semantic-oracle.ts`).

The other formats, 25 configurations: key=value, JSON, CEF, LEEF, CSV with comma, semicolon and TAB, RFC 3164
and RFC 5424 with each of five bodies, four mixed allowlists, two Regex patterns with a cost proof, two
declared-forwarder layouts (the forwarder-family template):

- their golden and seed lines and 1,500 stream lines each (fixed seed 401): 38,499 cases. FULL in the browser
  if and only if a record from the generated Ruby, with equal field trees. Every configuration must have at
  least one case on each side of that decision;
- the CSV row tokenizer against `parserstudio_csv_parse_line` for comma, semicolon and TAB: every string of up
  to six symbols over a letter, the quotation mark, the separator and SP, and 3,000 stream rows per separator
  over a wider alphabet: 25,380 rows;
- twelve injected faults (`ts-format-*`, `rb-format-*`).

The Ruby side runs in batches (6,000 cases a process; a fault runs batch by batch until it is reported), because
the CI interpreter is a container with 512 MB and one CPU. Run against the product code of `3b9e3f5`, the
Generic Structural stage fails with 208 enumerated and 80 stream differences. The differential says the engines
agree; the hand-authored goldens say what is right.

Third independent pass (2026-11-15, commit `7cc4d8e`, limited to that change): no difference in the mixed router
over 43 allowlists (79,500 lines); the blank rule agrees with the browser's `String#trim` on 25 characters, for
UTF-8 and binary-tagged text; injected faults in the mixed router and in the forwarder hop limit fail the gate.
One gap: the gate's blank rows were ASCII only, so removing NBSP from the Ruby blank rule passed. Rows of NBSP
and other Unicode blanks and the fault `rb-format-blank-event-ascii-only` were added. The browser's mixed router
also got Ruby's "at least two CSV columns" condition (unreachable: such a project is refused at compile time).

What it is not. It is a sample, not a proof: a class of lines that neither the enumerated variants nor the
streams produce is not compared. The first two independent passes each found such a class. Not compared at all: the
Python preview, `java_stacktrace`, the `genericStructuralProfile` variants, a Regex body inside Syslog, and LF
or CR inside an event (framing; declined before extraction).

The independently authored semantic identity oracle (`independent-semantic-identity-oracle.ts`) now runs before
the template-hash gate, with its own fault injection
(`independent-semantic-identity-oracle.fault.test.mjs`: an unmodified copy must pass, a swapped policy must fail).

## Run-time guard: PR #311 review (2026-11-15)

- The host-name check applies only to a result of the RFC 3164 header grammar (a mark on the result, not the
  field name): a JSON, key=value, CSV or regex field called `syslog_hostname` is data.
- RFC 5424 STRUCTURED-DATA is not key=value text: pair accounting starts after well-formed STRUCTURED-DATA,
  so an SD-PARAM (stored under an encoded name) is not demanded as a body field. Goldens
  `rfc5424-sd-dotted-param-kv`, `rfc5424-sd-two-elements-pair-text-in-value-kv`; fault
  `rb-guard-structured-data-counted-as-pairs`.
- Re-audit of 2026-11-15: the pairs of the MSG are looked up in the key=value body (or in the record itself
  when the whole event is key=value), not in the whole record. Before, an SD-PARAM with the name and value of a
  pair that the body parser had lost stood in for it and the loss went through. Golden
  `rfc5424-sd-param-repeats-first-msg-pair-kv`: with the fault `rfc5424-body-skips-first-pair` the guarded
  Fragment must not emit it (`wrong_events_with_guard=0`).
- Tokens of the check are separated by ASCII white space (SP, TAB, LF, VT, FF, CR), as the key=value grammar
  never puts one of these into an unquoted value and allows them after the last pair. Golden
  `rfc3164-kv-trailing-form-feed`.
- An event from which no field was extracted is rejected before the check (`No field was extracted`).

## RFC 5424 model (W8)

`src/grammar/rfc5424Model.ts` renders RFC 5424 lines with a key=value MSG from
a model of the header fields (RFC 3339 timestamps with fractions and offsets,
a leap day, NILVALUE fields, one SD-ELEMENT) and of the meant pairs, and states
what the RFC does not allow: two SP between header fields, STRUCTURED-DATA
missing, PRI above 191, a day that is not on the calendar, plus the VERSION
policy. The browser, both Ruby templates on Ruby 2.4.9 and the Python preview
meet every expectation without a change.

## JSON model (W8)

`src/grammar/jsonModel.ts` renders a JSON object event from meant values in
spellings RFC 8259 defines as equal (compact, insignificant white space, every
non-ASCII character and `/` escaped, members reversed) and lists texts the RFC
does not allow (trailing comma, single-quoted or bare names, truncation, text
after the object, a leading-zero number, NaN). A repeated member name is
declined by product policy. The browser, the generated Ruby and the Python
preview meet every expectation without a change.

One difference is pinned, not changed: an integer beyond 2^53. The browser and
the generated Ruby decline the event (review safety); the Python preview keeps
it and reports exactly the digits written. The oracle allows a decline and
requires exact digits from whoever parses it, so a rounding engine fails.

## Parse status and Generic Structural (wired)

The strict pair accounting of `classifyStructuredParse` would report correct
Generic Structural parses as PARTIAL (message profiles keep the message as one
text field, SD-PARAMs sit under their SD-ELEMENT, `space_kv` gives the last
pair the rest of the line). `classifyGenericStructural`
(`src/grammar/genericParseStatus.ts`) therefore decides from the original line
and the result, the same way for every mode: a raw pair is accounted for when
a field of that name holds its value or a kept text field holds the pair as
written; the provenance copies `source_raw` and `message_raw` are not fields.
FULL needs every pair accounted for and the line read by the grammar it
claims; otherwise PARTIAL, reported as the warning
`GENERIC_STRUCTURAL_NOT_FULL` (a warning, not a failure, so an existing
project keeps working). A declined line is UNKNOWN. `processEvent` uses this
verdict for format `generic_structural`.

`parse_event` / `parse_quoted_kv` in `runtime/multipass/engine.py` have no
caller in the repository (preview API, tests, scripts), so that legacy
key=value path is not on any product path.

## CSV (W6)

RFC 4180 goldens (`csvCases`) and rows rendered from meant values
(`src/grammar/csvModel.ts`: comma, semicolon and TAB; enclosed fields, doubled
quotes, the delimiter inside a field, U+2028, UTF-8, empty fields; unterminated
quotes, a quote inside a bare field, text after a closing quote, one field
missing or extra). The browser tokenizer and the generated Ruby
(`CSV.parse_line` on Ruby 2.4.9) meet every expectation. The Python preview
reads comma rows only and detects the format by itself; it is held to "a row
offered as CSV carries exactly the meant values, a malformed row is never
offered". Defect F-12: the Python preview offered a row with a double quote
inside a bare field, which RFC 4180 forbids and the other two reject.

The product does not combine a declared forwarder with CSV, so there is no
forwarder-family variant for it.

## RFC 5424 VERSION policy (owner decision, 2026-11-13)

Only VERSION 1 is supported. A line with any other VERSION is never parsed,
labelled or shown as RFC 5424 and never FULL; the original line is kept and the
reason is reported as unsupported. The list lives in
`semantics.rfc5424SupportedVersions`; TypeScript, the Ruby export and the
Python Multi-Pass entry points all read it. Goldens cover 1, 2, 12, 999, 0, 01
and 1000; the Python engine probes five entry points per VERSION; the fault
`contract-version-2-supported` must be reported.

`fragments.rfc5424_version_head` (`<PRI>VERSION SP` followed by NILVALUE or the
start of an RFC 3339 date) is how every entry point recognizes a line that
claims to be RFC 5424. The Generic Structural extractors use it as a gate
before any other grammar: such a line used to succeed in the browser and in
Ruby as space-separated key=value with the header kept as opaque prefix tokens,
and in Python a three-digit VERSION slipped past a two-digit header expression
and came back as SOURCE_PARSED (found by the VERSION probe).

## One grammar: executed in the browser, translated for Ruby (W4, 2026-11-15)

Until this change the grammar existed twice: TypeScript for the browser preview and hand-written Ruby in the
templates. The differential gate compared the two on generated lines, which finds a difference only where a
line happens to hit it. The second implementation is now gone.

```
src/grammar/readEvent.ts        readEvent(raw, settings): extraction + forwarder unwrap + Parsing Success Contract
src/grammar/extractEvent.ts     extractEvent(raw, settings): every format, the mixed router, the CSV tokenizer
        |   the browser executes these modules as written
        |   scripts/grammar/ts2rb/generate.mjs  (--write | --verify in CI)
        +--> backend/templates/grammar-core.generated.rb.tpl      every artifact
        +--> backend/templates/grammar-generic.generated.rb.tpl   Generic Structural artifacts only
backend/templates/grammar-runtime.rb.tpl     hand-written: the value model of the translation (psg_* primitives)
backend/templates/ruby-fragment.rb.tpl       hand-written: 74 lines of Fluentd glue around psg_read_event
```

What is still hand-written Ruby: the runtime primitives, the glue, the canonical operators (normalization and
mapping, `canonical-operators.rb.tpl`) and the Regex helper, because a Regex extraction runs the user's pattern
on the regular expression engine of each runtime. `generic-structural-helper.rb.tpl`,
`ruby-forwarder-family.rb.tpl` and their generator are deleted.

### The translator

`scripts/grammar/ts2rb` is type-directed and fail-closed: it reads the TypeScript program with the compiler API,
translates the functions reachable from the entry points and refuses any construct it has no rule for (the
build fails; nothing is emitted "approximately"). The rules that carry the semantics:

| TypeScript | Ruby 2.4 |
|---|---|
| string, addressed in UTF-16 code units | UTF-8 String addressed through `psg_len`, `psg_at`, `psg_slice` (code-unit offsets; an offset inside a surrogate pair raises and the event is declined) |
| number | Integer below 2^53, otherwise the nearest Float, as the double it is in ECMAScript |
| `undefined` / `null` | `nil` / `:psg_null` (never the same value; a JSON `null` is `:psg_null` until the result is exported) |
| truthiness | `psg_t` wherever the type admits `''`, `0`, `null` or `undefined` |
| regular expression (every one carries the `u` flag) | `^ $` become `\A \z`, `.` and `\d \w \s \b` are spelled out, sticky becomes `\G`; flags `i`, `m`, `v` and a mixed named/unnamed group are refused |
| module constants | executed and serialized, so a table is the value the browser has |

### How the translation is verified

1. `generate.mjs --verify`: the committed Ruby is exactly what the current TypeScript translates to.
2. Translation conformance (`scripts/verification/translation-conformance.ts`, Ruby 2.4.9 job): probe functions
   that exercise every translation rule are translated by the same generator and run in both runtimes on the
   same inputs; a difference fails the gate.
3. Translation faults (`scripts/verification/translation-faults.ts`): each fault is a wrong translation rule or a
   wrong runtime primitive (Ruby truthiness, `nil` for `null`, length in characters, Ruby `split`, `to_i`,
   unanchored sticky, line anchors, Ruby `.` and `\s`, and seven runtime faults). Every fault must be reported
   by the conformance gate; the faults that change what an artifact returns must also be reported by the native
   oracle and by the differential gate.
4. The semantic oracle, the native oracle and the browser/Ruby differential are unchanged in purpose: they now
   check the translation end to end instead of comparing two implementations.

A sample-based differential is therefore no longer the argument for "browser and Ruby agree". The argument is:
one source, a translator whose every rule is probed, and faults that show the probes can fail.

### Rules

- Grammar is changed in TypeScript only, then `node scripts/grammar/ts2rb/generate.mjs --write`.
- A construct the translator refuses is rewritten in the supported subset or gets a translation rule together
  with a conformance probe and a fault. It is never worked around in the template.
- The grammar reads text by code unit and by sticky match; it does not cut windows out of the text.

## Loss accounting for CSV, JSON, CEF, LEEF and Generic Structural (W7, 2026-11-15)

The Parsing Success Contract used to account for key=value pairs only. For the other dialects "the extractor
returned no error" was the whole argument, which is not an argument: a tokenizer that drops a cell or cuts a
value also returns no error. `src/grammar/lossGuard.ts` closes this. After a successful extraction it reads the
original text of the event a second time, with code that shares no expression, splitter or decoder with the
extractor, and asks whether the fields spell that text, all of it and nothing else:

| Dialect | Accounting |
|---|---|
| CSV | reconstruction: the cells, written back as RFC 4180 writes them (quoted or not, SP and TAB beside a cell with `,` and `;`), spell the row; the fields are exactly the declared columns |
| JSON | token count: the member names, strings, numbers and literals of the text, read by a scanner of its own, are exactly those of the fields |
| CEF | reconstruction: the header fields spell the header; the extension is, from first to last character, `key=value` pairs in which every key is a field and every value, with the contract escapes read on the way, is that field |
| LEEF | reconstruction: the same for the header; the extension is attributes joined by the event's own delimiter |
| Generic Structural | the same four accountings for the modes whose body is JSON, CEF, LEEF or positional CSV (`classifyGenericStructural`); key=value modes keep their pair accounting |

A result that fails the accounting is PARTIAL. `gradeExtraction` (`src/grammar/readEvent.ts`) applies it for
every route: the format alone, the body of an RFC 3164 or RFC 5424 event, and the families of the mixed router.
The generated Ruby executes the same functions (they are translated like the rest of the grammar) and hands an
event over only when the reading is FULL, so the guard is a run-time guard on the sensor, not a test. The
reasons never contain event text.

Generic Structural hands over a PARTIAL event (owner policy D-2). What such an event does not hold in a field
exists only in the copy of the original line, so `omitSourceRaw` applies to FULL events only; the verdict
travels with the event (`readingStatus` tag) and `parserstudio_normalize` decides per event.

Verified in both directions (Ruby 2.4.9: `backend/test/runtime-loss-accounting.test.ts`,
`issue219221-native-parity.test.ts`; browser: `src/grammar/lossGuard.test.ts`,
`genericLossGuard.test.ts`, `src/genericPartialKeepsSource.test.ts`):

- no false rejection: hand-written vendor-style events of every route, the model-generated CSV, JSON, CEF and
  LEEF cases, every golden, and the lines of the format differential compared with the tree before this change
  (no verdict changed on 15,961 + 13,461 lines);
- no silent loss: an extraction with one field dropped, cut by one character or invented is rejected on every
  route, in the browser and in the generated Ruby.

Found while wiring it (each with a regression test):

- Generic Structural called a manufacturer field named `source_raw` or `message_raw` a lost pair (false
  PARTIAL). Only the copies in the nodes the grammar builds are provenance.
- A CEF or LEEF event behind a Syslog header was read by the CEF grammar with up to four pairs and by the
  generic space-separated key=value route with five or more (header and first pair in prefix tokens, verdict
  FULL). The claim of an enveloped message is now honoured like the claim of a bare line: read by the family
  grammar or declined on the dedicated route; unchanged output and verdict PARTIAL on the legacy route.

## What the gates reach since 2026-11-15 (work order item 3)

| Was outside the gates | Now |
|---|---|
| Regex body inside Syslog | format differential configurations `syslog_rfc3164+regex`, `syslog_rfc5424+regex` |
| Java stack trace, multi-line JSON | configurations `java_stacktrace`, `json-blank-line` (LF LF framing, events with LF) |
| Generic Structural profiles | the three profiles on a stream of their own (`GENERIC_DIFFERENTIAL_PROFILE`) |
| LF, CR, CRLF | line-ending stage (`LINE_ENDING_DIFFERENTIAL`): streams are cut into frames as the receiver cuts them, and the events of the browser preview of the stream must be the events the generated Ruby returns for the frames |
| JSON numbers around 2^53 | seeds for integers, decimals and exponent spellings at the limits of a double, in every JSON route |
| Python preview | three-way comparison in `semantic-oracle.ts python` (`PYTHON_THREE_WAY`): a line the preview reports as completely parsed is read by the browser, in that format, to the same fields |

Found this way and fixed at the cause:

- RFC 5424: the structured-data scanner measured its 1024-byte limit by cutting a prefix of the text at every
  code unit. In the generated Ruby that cut inside a character and declined every event with a character
  beyond the BMP in an SD-PARAM value. The size is now counted as the scan advances.
- Line endings: the generated Ruby declined every CRLF-terminated line in the non-JSON formats (the frame ends
  in CR) while the browser parsed it, and accepted a bare CR or an unframed LF inside JSON that the browser
  declines. One rule now, in both: CRLF is a line terminator, a bare CR declines the event, LF belongs to an
  event only in the blank-line framing of its format.
- Python preview: it decoded `\n`, `\t`, `\=` and `\"` in CEF and LEEF header fields (the header has two
  escapes, the pipe and the backslash), and it reported a JSON decimal with more digits than a double holds, or
  an integer beyond 2^53 in exponent spelling, as parsed with the rounded value.

Known limit, not a parser matter: blank-line framing splits a stream at LF LF. A CRLF stream has no LF LF
(`\r\n\r\n`), so the receiver never cuts it, whereas the browser preview normalizes CRLF first. Multi-line
sources must send LF line endings.

## Template set approval (work order item 4)

The reviewed-template hash (`pocTemplateSha256`, `KNOWN_TEMPLATES`) covers one artifact, compiled from a JSON
sample project. A change to the Generic Structural grammar, the Regex helper, the source-copy helper or a CONF
variant does not move it. `contracts/ruby-template-set.v1.json` records what decides the text of every
generated parser: the SHA-256 of every file in `backend/templates`, the normalized Ruby and the CONF of every
compiler variant (`backend/test/compiler-variants.ts`), the case-fold table as inflated, and one digest over
all of it (`templateSetSha256`). `backend/test/template-set-approval.test.ts` recomputes the manifest, fails
when the committed file is stale, and holds the digest to `APPROVED_TEMPLATE_SET_SHA256`, which only an owner
review sets. The existing constants are unchanged and still gate the disposable POC upload.

```
node backend/node_modules/tsx/dist/cli.mjs scripts/verification/ruby-template-set.ts --write | --verify
```

## Rules for adding or changing a grammar or a mapping

1. Change the contract and regenerate. Do not write a header pattern in a
   consumer; the ratchet fails on a new literal copy.
2. Add goldens authored from the specification or the publisher document, with
   provenance, including a negative and a boundary case.
3. Extend the model generator with the new variant and its own expectation.
4. Add one fault per new rule or semantic limit to the oracle mutants.
5. `semantic-oracle.ts ts` and `semantic-oracle.ts native` (Ruby 2.4.9) must pass.
6. Browser journey and downloaded-artifact native execution stay mandatory
   (existing Chromium and golden-vendor gates).
7. A template change needs a new owner-reviewed template hash; never edit
   `KNOWN_TEMPLATES` without that approval.

## Commands

```
node scripts/grammar/generate-grammar.mjs --write | --verify
node scripts/grammar/ts2rb/generate.mjs --write | --verify
node backend/node_modules/tsx/dist/cli.mjs scripts/verification/translation-conformance.ts
node --test scripts/grammar/generate-grammar.test.mjs
node scripts/verification/grammar-duplication-ratchet.mjs [--write]
node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts ts
PARSER_STUDIO_EXPECT_RUBY=2.4.9 node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts native
node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts python
PARSER_STUDIO_EXPECT_RUBY=2.4.9 node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts differential
node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts mutants
```

## Scope

This verifies Parser Studio output. It is not a Stellar Cyber import, Syslog
reception or indexing result.
