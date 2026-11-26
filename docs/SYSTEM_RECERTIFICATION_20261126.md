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
