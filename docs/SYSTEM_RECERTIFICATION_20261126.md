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
