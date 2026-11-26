# System recertification — 2026-11-26

Baseline: `isoc-labs/parser-studio@14dcacddff48365001bfca2653c4466037d023b0`.
Execution: CHATGPT_CHAT implementer, Claude independent review (owner coordinates).
No production or release changes authorized by this work packet.

## ACTIVE work packet

- W0: inventory and requirement traceability, with explicit supersession.
- W1: shared Regex safety prerequisite; do not remove UI denial until safety tests pass.
- NEXT_CHAT_START: read this file and the W0–W11 roadmap, verify actual branch/HEAD,
  then continue the earliest unfinished work and any independent safe work.
- Baseline CI 10/10 is historical; current recertification is OPEN.
- Do not treat a PASS at one layer as proof of a complete user journey.

## Audit findings and traceability seeds (not exhaustive)

| ID | Requirement | Evidence / code | Status | Work |
|---|---|---|---|---|
| R01 | Two paths, equal supported export ability | 14_TWO_PATH_PRODUCT_V2; ChatGPTAssist unconditional Regex denial | DEFECT | W2/W3 |
| R02 | Safe native execution | F08/F14/F16; ruby24-regex-cost false acceptance; validate.ts separate refusal | DEFECT (analyzer); exposure unverified | W1 |
| R03 | Single capability decision | target-runtime-profiles vs executable-capability-matrix; backendClient discards verdict | DEFECT | W2 |
| R04 | Preserve supported events in mixed input | owner 2026-11-22; readableEvents AND of scanner/browser/server; deployed ASA 1+3 blocked | DEFECT | W4 |
| R05 | Correct source/destination semantics | F09/F10; Cisco 302013 outbound official samples vs security_asa and golden corpus | DEFECT | W5/W6 |
| R06 | Accurate error classification | F15/F23; ChatGPTAssist catch collapses distinct failures | DEFECT | W2/W3 |
| R07 | Responsive UI | F10/F11; normalization grid and warning flex; 1920px measured escape 212px | DEFECT | W7 |
| R08 | Evidence-backed completion | F08/F14/F23; Snort spec asserts old deny, successful Assisted Regex spec env-gated | DEFECT | W8/W9/W10 |
| R09 | Common grammar | 45 recorded duplicate tokens; semantic impact not exhaustively established | PARTIAL | W0/W2/W10 |
| R10 | Dictionary 7.0, original unmapped names, Auto/AI/manual | owner decisions; mapping UI and policy | UNVERIFIED | W6 |
| R11 | UDP 6801 / exact custom port, vendor identity, multi-type | owner decisions; F03A/F14 | UNVERIFIED | W10 |
| R12 | Real Stellar DP/sensor import | target profile targetImportVerified false; separate authorized lab | UNVERIFIED | W11 |

Evidence basis: ChatGPT source audit and Claude independent report dated 2026-11-26
(21 pages); report retained by owner. Claude's isolated local evidence is under
`/root/audit-20261126/`. Do not commit private logs or local screenshots.
Full requirement census, full-text document disposition, whole-corpus oracle
review and new end-to-end receipts remain open.

## Completion

Only VERIFIED / PARTIAL / DEFECT / LIMITATION / UNVERIFIED are permitted.
LIMITATION requires evidence and considered alternatives. Native synthetic
qualification is not proprietary target validation. Each work item requires
red/green evidence and exact candidate SHA; independent review and approved
deployment remain separate gates.

## W1 checkpoint — shared AST and native cost corpus

- RED: new 11-pattern nested-choice classification test failed on the first
  counterexample at the baseline (accepted, zero ambiguous loops).
- GREEN: shared AST rejection used by cost classifier, Browser preview and
  backend schema. The old independent nested-quantifier scans were removed;
  other existing safety checks retained. A conservative rejection is not a
  universal proof of runtime safety.
- Focused backend classifier/portable/export suites: 30/30 before the
  additional boundary regression; export suite then 7/7 (including the new
  direct validate/generate/compiler negative test). Browser regex suites 47/47.
- Local Ruby 2.4.9p362 chroot runner: accepted cost corpus 50 probes, existing
  generated-artifact checks 28/28; CI's sealed Ruby 2.4/3.2 gate now consumes
  the same accepted fixture corpus. Existing ASA oracle is NOT recertified.
- Backend typecheck PASS; full web typecheck attempt timed out at the remote
  command deadline, no PASS claimed. Full CI and independent verification open.
- Frontend legacy blanket denial remains until W2/W3 changes and required
  positive/negative shipping journey tests are verified.

## W2/W3 checkpoint

- Shared backend export verdict and reason codes implemented in 53f721d.
- Real Chromium Assisted positive and negative journeys passed (2/2).
- f1576ff adds independent source-value verification of the actual browser
  download to the existing native CI gate. Local Ruby 2.4.9: 6/6 events
  passed; deliberately wrong source IP correctly rejected.
- Full CI and complete export-journey census remain open.

## W4 checkpoint

- RED: actual Chromium mixed ASA structured connection plus unsupported
  free text had no readable-event continuation offer.
- GREEN: exact source-frame correspondence, the existing bounded adoption
  contract and one jointly validated candidate now allow the supported subset.
  The original sample is retained for restoration. No scanner or native
  safety guard was removed; generic whole-message capture alone is not
  considered additional structured coverage.
- Actual Chromium: new journey through download and original sample restore
  PASS; previous mixed-event and unsupported-event journeys 5/5 PASS.
  Focused unit regression 29/29 PASS.
- Remaining: broader combinations, source accounting in actual native
  execution including excluded events, and independent semantic direction
  oracle (W5/W10). This is not certification of ASA source/destination.

## W4/W5 checkpoint — ASA direction, exact source spans and mixed execution

- Independent reference: Cisco ASA syslog 302013 description and configuration
  example (https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html
  and https://www.cisco.com/c/en/us/support/docs/ip/network-address-translation-nat/118996-config-asa-00.html).
  Outbound connection initiator is the second endpoint in the documented
  foreign/local layout; real and mapped address/port pairs must follow it.
- RED: corrected hand-authored Browser oracle failed with both endpoints
  and NAT values reversed. The published-text corpus also used the wrong
  initiator. Corrected corpus and direction-specific regex mapping profiles.
- Shared TypeScript -> generated Ruby grammar reorders the complete tuple;
  Python changes corresponding semantic names without changing byte offsets.
  Python now also recognizes the existing bounded ACL access-group grammar.
  Explicit deny labels are unchanged; teardown without established initiator
  remains partial. No guessed source/destination from positional teardown.
- Browser unit regression 82/82; Python independent direction/span checks
  4/4 (including TCP/UDP and inbound/outbound subcases); Ruby 2.4.9 offline
  28/28 and 50/50 cost probes. Backend build passed.
- Actual isolated Chromium, four mixed ASA records: two readable events,
  download, restore original sample. Actual downloaded fragment executed in
  Ruby 2.4.9; 4/4 events accounted, exact normalized source/destination
  sockets for connection and ACL denial, NAT and ACL values preserved,
  two unsupported records retained byte-for-byte as parser_raw_msg.
- Full semantic oracle invocation hit the 30-second remote command deadline
  during mutation testing. Do not report it as completed.
- Regenerated template-set digest:
  6384710b9af630de6a4ceee86a344e12f7ecb9fddef1a72e7f284fcbec93f00f.
  Existing owner approval remains unchanged; new digest requires owner
  review before merge. Do not change approval constants.
- Remaining W5: independent truth audit across the rest of the corpus;
  W6 mapping audit, W7 layout and W8-W11 remain open. No actual Stellar
  sensor import or indexed event has been verified.

## W7 responsive recovery and mapping

- RED: real Chromium at 1920px showed the recovery explanation and action
  competing in one horizontal flex row instead of sequential presentation.
- GREEN: recovery warnings now stack content and actions; mapping uses
  available container width, not viewport width. Fields, metadata, actions,
  identity cards and long values have bounded grid tracks and local wrapping.
- Real Chromium recovery, field review, mapping and create-parser navigation
  at 1024, 1280, 1440 and 1920px: 4/4 PASS, with overlap and containment
  assertions. Language and multilingual/Unicode regression: 15/15 PASS.
- Scope: these four tested desktop layouts; independent visual review and
  other UI journeys remain open.

## W9/W10 mixed-download oracle

- The existing aggregate download gate now requires the actual mixed ASA
  browser artifact in addition to the Assisted Regex artifact. Both are
  checked against the download index and SHA-256 before executing Ruby.
- Local real Chromium downloads: 2/2 journeys; Ruby 2.4.9 source-value
  oracles: Assisted 6/6 and mixed ASA 4/4, including exact raw fallback,
  extraction error stage, normalized endpoint sockets and vendor NAT/ACL.
- Three mutated output records (reversed source IP, missing original log,
  wrong error stage) were all rejected by the independent mixed oracle.
- Full CI aggregate result and the remaining vendor corpus remain open.

## W5/W6/W8/W9 — independent endpoint destinations and CI repair

- Exact-head CI 934ef43 (run 45731859334) exposed two missed test changes:
  the layout spec imported stock Playwright rather than the download sink;
  common-security-logs retained reversed ASA outbound expectations. Fixed
  both, retained the CI guard, and verified actual Chromium 2/2.
- The documented vendor gate previously followed the browser mapping rows
  alone. Reversing both the mapping and emitted value could pass. Added a
  separate hand-authored Stellar 7.0 endpoint oracle for all 14 registered
  documented cases, 42 exact canonical IP/port fields (strict value/type).
  The Fortinet VPN remote/local pair has no direct endpoint expectation in
  this oracle; existing source preservation remains mandatory. No expectations
  are generated from the implementation or downloaded artifact.
- Real Chromium produced all 14 bundles. The first four-test invocation
  reached the remote deadline after three bundles were recorded; the
  subsequent 11 journeys completed successfully. Every recorded Ruby was
  then executed in the digest-verified Ruby 2.4.9 chroot and compared by the
  aggregate gate: 14/14 PASS, 42/42 canonical endpoint checks PASS.
- Registry/comparison tests 25/25, aggregate gate tests 15/15 (including
  a jointly reversed mapping and output), independent identity oracle 26
  cases PASS, backend typecheck PASS, download-sink guard PASS (183 files).
- This is an independent endpoint sub-oracle, not full semantic mapping
  certification for every field, nor target import/indexing evidence.

## W8/W9 — mandatory journey execution receipts

- Existing shard success validated aggregate stats but permitted silent skips
  in the owner-critical subset. Added a separate 20-journey exact file/title
  registry covering Assisted and inline recovery, mixed readable events,
  manual and JSONata mappings, source preservation, CEF and responsive UI.
- Each shard emits a compact exact-HEAD receipt only for one successful
  Chromium execution of each listed case it encounters. The required release
  eligibility job checks all six receipts, every required case exactly once,
  no skipped/expected-failed/retried cases, and no stale or duplicate shard.
  Existing separately scoped and legacy test dispositions are unchanged.
- Six unit tests passed including omission, skip, expected failure, wrong
  project, retry, stale HEAD and duplicate controls. Actual real-backend
  JSONata mapping journey passed and its real JSON reporter produced the
  expected receipt (1/1). Full six-shard aggregate CI remains pending.

## W6/W8/W9/W10 — mapping paths and stricter comparison

- CI run 45733561899 on 236e7c9: all six Chromium shards, native isolated
  synthetic, and Ruby 2.4.9 / Fluentd 1.7.4 UDP jobs succeeded. Web-quality
  failed because the new receipt step duplicated the expected source-HEAD
  declaration checked by the executable contract guard. The release job now
  shares one job-level exact-HEAD variable; both checks assert the checkout
  identity. Guard and six receipt tests passed. No policy guard was disabled.
- Real Chromium: Q3-1 partially mapped CSV, manual event-specific mapping,
  and scoped ChatGPT JSONata mapping each passed. Their three actual recorded
  downloads were checked by SHA and executed in the local Ruby 2.4.9 chroot:
  15/15 independent events passed, including IPv6, Unicode, original unmapped
  leaf name/value, unchanged event types and PAN-OS NAT/serial preservation.
  The manual case deliberately changes a role by operator choice; this proves
  faithful execution and isolation, not semantic endorsement of that choice.
- The same mapping oracle is mandatory in the aggregate downloaded-Ruby gate.
  Its four unit tests cover missing values/events, unapproved mappings,
  cross-event leakage, incorrect type, duplicate callbacks and wrong Ruby.
- Golden comparator now requires exactly one callback including null callback
  accounting, and allows timestamp instant equivalence only for an official
  timestamp mapping, not a vendor string. Invalid clock and offset rollovers
  are refused. Comparator suite 25/25 PASS; actual prior vendor downloads
  14/14 PASS under the stricter comparison. This is not a new browser run.
- Latest CI aggregate, further non-endpoint semantic audit, exact requirement
  traceability, independent review and actual proprietary target remain open.

## W0 — core functional requirement traceability

- Read the product vision, UI specification, functional requirements,
  architecture and two-path product scope. The original Workbench/Wizard
  navigation, bilingual readiness wording, docs-only deployment statement
  and historical P0 COMPLETE snapshots cannot govern present acceptance.
  Added explicit precedence/historical notices to the existing documents;
  the two-method scope and owner decisions are unchanged.
- docs/verification/20261126-requirement-traceability.json accounts for all
  27 F-series requirements, with implementation references, relevant
  evidence/test references, scope disposition and remaining gaps. It is
  not a new specification or a certificate. No requirement marked VERIFIED.
  Automated coverage and reference existence check passed (27/27).
- Full individual disposition of the baseline 148-file inventory and
  independent proof of each active requirement are still open.

## W5/W6/W10 — expanded independent semantic destination truth

- Added 20 explicit non-endpoint expectations across the same 14 registered
  publisher cases: L4 protocol numbers/names, dispositions, application ID,
  firewall policy, MAC, username, VLAN and file fields. A common loader
  combines these with the 42 endpoint expectations for browser and Native
  gates. Source values were read from the corpus, with types from the
  Stellar 7.0 catalog; no runtime-derived expectations.
- Registry checks 4/4, focused gate tests 3/3, backend typecheck PASS.
  The actual existing 14 vendor downloads pass all 62 independent
  destination values/types. Mutation of numeric proto into a string fails.
- Local aggregate gate on previously captured actual downloads passed:
  14 vendor + 6 Assisted Regex + 4 mixed ASA + 15 mapping events = 39.
  Ruby version 2.4.9; this reuses prior evidence, not a newly executed
  exact-HEAD six-shard browser run or proprietary target verification.
- Remaining: current full CI, original corpus beyond these 14 registered
  examples, complete independent semantic truth across all fields,
  document-by-document disposition, and independent final acceptance.

## W0/W3 — consolidated specification and package paths

- Integrated the exact existing specification PR #6 head 9d572f6 into this
  candidate, not main; resolved three overlapping historical notices in
  favor of its current scope. No second competing normative document.
- All 148 original document/contract bytes matched baseline SHA-256 and
  18,559 lines were screened; 110 historical, 21 supporting, 3 active
  specification documents, 14 executable/oracle assets. Historical evidence
  is not current proof. The expanded canonical manifest covers all 137
  current Markdown specifications/evidence and repository authority files.
  Original 27 legacy dispositions and 12 current PS trace anchors are checked.
  This is an authority census and full-text screening, not semantic
  certification of all 18,559 lines or every historical golden expectation.
- Actual Assisted, conditional Assisted, inline recovery, and normal Auto
  downloads: four Chromium journeys PASS; all four ZIPs expanded to exact
  verified Ruby/CONF pairs, eight total pairs, zero integrity failures.
  One shared package component now consumes the verified pair in all three
  surfaces. Mandatory browser census increased to 22.
- Focused component/package 17/17, multilingual policy 15/15, web typecheck
  PASS, prior exact-head native and six browser jobs PASS. Prior web-quality
  failed solely on owner template approval, not bypassed. Latest exact-head
  CI and independent semantic/native coverage remain separate.

## W8 — full Chromium catalogue census

- Registered all 523 unique discovered file/title pairs. Required 510; only
  six retired target-UI cases and seven historical fixed-public-URL cases
  have explicit non-required dispositions. All six exact-source shards enable
  scoped authoring and must reconcile every case to its declared outcome.
- Scoped authoring suite: 66 passed; two concurrent-output trace-file
  teardown failures rerun with isolated output directories, both passed.
  No application assertion failed in those two cases.
- Receipt gate negative tests 9/9 and real-report receipt preparation passed.
- Shared package surface retains missing-capability and corrupt-SHA refusal
  with a visible alert and existing loose pair; real browser fault tests 2/2.
- Full exact-HEAD CI remains required; catalogue disposition does not imply
  independent vendor semantic verification.
