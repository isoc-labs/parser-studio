# Default deny for automatic field mapping (2026-11-28)

Change record and evidence for an independent audit. Written by the executor that made the change; **this is
not an independent audit**. Tree: PR #8 (`fix/root-cause-closure-20261127`), on top of `efca5f0`.

Owner decision (2026-11-28): automatic mapping is default deny. The 24 fields whose aliases had been reviewed
are the candidates for the first list; each needs a stated reason; a matching name, alias, type or range is not
a reason; the list is not to be widened to keep the mapping rate; no vendor rule, no new engine.

## 1. The rule

An official Stellar 7.0 field is proposed automatically only when both hold.

| | Condition | Where |
|---|---|---|
| A | The target is listed in `autoApprovedTargets` of the shared policy (`runtime/multipass/semantic-policy.v1.json`, identical copy `backend/semantic-policy.v1.json`). Each entry quotes the 7.0 dictionary definition and states the basis. | TypeScript: the `AUTO_APPROVED_TARGETS` check in `normalizationCandidates.ts` · Python: `FIELDS` is filtered by `_AUTO_APPROVED_TARGETS` |
| B | The source stands for the record itself: a whole path the dictionary or the alias table lists, a key the format specification defines (CEF, LEEF, WatchGuard layout), or a name in the container the reader of that event writes the pairs of the record into (`RECORD_CONTAINERS`, chosen by the effective format, never by the text of the path). | TypeScript: `recordLevelSource` · Python: `_record_name` |

Everything else is not proposed at all (not "review"): the field keeps its own name and value as a vendor field.
The existing protections still apply to a listed field: type and range, translated (NAT) endpoints, transport
evidence for ports, closed vocabularies (`securityDispositions`, `officialProtocolNames`), the `sport`/`spt`
server-port readings, one source per target.

Condition B was not in the request. It was added because a list of targets alone left the defect class open: on
`efca5f0`, `xlate.srcip → srcip`, `file.timestamp → timestamp`, `referrer.url → url`, `previous.action → action`
and `target.username → username` were HIGH, and the Python preview mapped `event.destination-port → dstport`
and a JSON `body.srcip → srcip`. A leaf of an object of the record names that object.

## 2. The 24 candidates

The 7.0 dictionary has 245 mappable fields. 13 are listed. The full definition and basis of each entry is in the
policy file; the table gives the reason in short.

| Field | Outcome | Reason in short |
|---|---|---|
| srcip, dstip | listed | One role in every format (CEF src/dst, LEEF, ECS source/destination, Zeek orig/resp). Value must be an IP. NAT never. |
| srcport, dstport | listed | Same role definitions (CEF spt/dpt, ECS, Zeek). Integer 0–65535, TCP/UDP evidence, no translated port. |
| proto | listed | One registry (IANA protocol numbers). Integer 0–255. |
| proto_name | listed | Closed list in the definition; only values of `officialProtocolNames`. |
| url | listed | CEF request / LEEF url; no qualifier left open. A sparse field must be URL-shaped. |
| action | listed | CEF act; every value must be one of `securityDispositions`. |
| timestamp | listed | Any time the record states for its event; only ISO 8601 with an explicit zone. Two qualifying fields are not chosen between. |
| username | listed | Definition has no qualifier. |
| srcmac, vlan | listed | No alias: only a source of that very name; vlan integer only. |
| rule.name | listed | ECS rule.name; alias `policy-name` (the security policy a session matched). |
| appid | **declined** | Identifier space of the Stellar DPI engine. |
| command | **declined** | Also holds protocol verbs (FTP, SMTP, SQL). |
| duration | **declined** | Milliseconds by definition; a name states neither unit nor what was timed. |
| file_path | **declined** | The definition is the directory; a source path normally includes the file name. |
| file_size | **declined** | Unit not stated by a name. |
| fw_policy_id | **declined** | `policyid` names a policy of any product. |
| hostip, hostname | **declined** | Which host is not stated (sender, requested host, DHCP client, DNS name). Three earlier defects. |
| icmp_type | **declined** | Meaning depends on the event; the earlier check knew one product's protocol field. |
| parent_proc_name | **declined** | Name, path or pid. |
| process_name | **declined** | Definition is specific to the agent sensor and a network connection. |

Six fields that were already restricted are recorded in `autoApprovalDeclined` with the same kind of reason:
severity, fidelity, threat_score, event_type, direction, type. The remaining mappable fields (for example
`sha256`, `process.name`, `host.ip`, `user.name`) were proposed from an equal name before; they are no longer
proposed and were not reviewed one by one.

## 3. Code removed

The special cases that existed to hold back single fields are gone, because the fields are not proposed:
`reviewOnlyScoreTargets`, the host-name heuristics (HTTP request host, Syslog header host, relay), the
`event_type` / `direction` / `type` / `duration` / score / PAN-OS type / `icmp_type` branches, the Windows-agent
evidence, the FortiGate false-friend call in the candidate engine, 55 aliases (130 → 75) and every `body.*`
whole-path alias. Two branches that no input reaches after the change were deleted instead of kept (a NAT
segment check; a root-level test inside `recordLevelSource`). `normalizationCandidates.ts`: 650 → about 530
lines. No new module, engine or vendor rule.

## 4. One policy, three paths

| Path | Role | How the policy reaches it | Evidence |
|---|---|---|---|
| TypeScript candidate engine | Decides the mappings of the draft, and through the draft the generated Ruby | Imports the policy JSON | `src/guided/defaultDenyMapping20261128.test.ts` (5 tests), cross-engine corpus |
| Python Multi-Pass preview | Display of a preview per event | Loads the same JSON | `tests/test_semantic_conformance_corpus.py`, `tests/test_mapping_correctness_v2.py` |
| Backend compiler / generated Ruby | Compiles the mappings of the draft; has no policy logic of its own | Receives the draft | `tests/default-deny-mapping-20261128.spec.ts` runs the downloaded Ruby on Ruby 2.4.9; `backend/test/golden-ruby-gate.test.ts`, golden corpus `notOfficial` |

- `contracts/conformance-cases.v1.json` has two new sections that both engines must satisfy: `defaultDeny` (33
  cases) and `memberOfObject` (7 records, only `dstip` may be mapped).
- The exhaustive unit test goes through the whole catalogue: a same-named, type-fitting source is proposed if
  and only if the field is listed. Another test requires that no table of the policy leads to an unlisted field,
  that no listed name contains a translated segment, and that both policy files are equal.
- Known differences, unchanged by this work: the Python preview approves a subset (9 of the 13 targets: not
  timestamp, srcmac, vlan, rule.name; CEF aliases and explicit port labels only; identity at the root and in a
  Syslog body only). It never approves what TypeScript denies. Python previews one event at a time, TypeScript
  decides over the whole sample.

## 5. When automatic mapping declines

1. The ChatGPT JSONata mapping assistant may propose any mappable field. A proposal for a target the local
   engine does not approve as HIGH is `CHECK FIRST`, is not pre-selected and needs two confirmations by the
   user; a translated endpoint over an existing endpoint is `BLOCKED`. Unchanged code; covered end to end by
   the second test of `tests/default-deny-mapping-20261128.spec.ts`. ChatGPT itself was not called (the reply
   is a fixture).
2. Manual mapping: the user types a Stellar field for a vendor row (same test).
3. A field left unmapped keeps its original name and value in the vendor fields; the test compares the values
   of the downloaded Ruby output with the sample. A nested field is kept under its leaf name, as before.

## 6. Cost

Vendor holdout corpus (`tests/fixtures/vendor-holdout-20261116`), official mappings applied automatically:
76 → 65. Lost: hostname ×7, service_id, fw_policy_id, event_id, alert.action. Semantic goldens: 20 → 12
official rows; 8 rows moved to `notOfficial` (they must stay vendor fields and keep their value).

## 7. Expectations that were changed

Every change follows from the owner decision; each carries a comment with the date. Three kinds.

**a. Expectations that asserted an approval the policy no longer gives** (the assertion now says "not
proposed" or "vendor field"; none was deleted to pass):

| File | Change |
|---|---|
| `officialNameSparseCoverage20261121.test.ts` | 42 → 31 tests. Three describe blocks on which host name is the right one became one: a host field is never proposed. icmp_type and literal dotted-key cases: not proposed. |
| `securitySemanticGuard20261106`, `normalizationCandidates`, `docsPracticeSemanticMapping20261104`, `juniperSdNormalization20261104`, `canonicalMappingPlan`, `independentAuditFindings20261123`, `issue232SemanticMapping`, `mcv2CandidateSemanticOracle`, `serverPortReading20261125`, `stellar7NestedDictionary20261021`, `stellar7EventFamilyPanel20261021` (unit) | hostname, fw_policy_id, duration, nested dictionary names, members of objects: official → not proposed. |
| `vendorHoldout20261116.test.ts` | Official counts: panos_threat_url 5→4, panos_traffic 12→10, srx 13→11, suricata 10→8. |
| `genericStructuralAutoDraft.test.ts` | 6 → 5 official, hostname kept as vendor field. |
| `stellar7ScopedFamilyMappings20261021.test.ts` | 16 → 8 matched official values; the other values must still be in the output. |
| `evals/golden-corpus/stellar70-semantic-goldens.v1.json` | 8 rows to `notOfficial`: fw_policy_id ×3, appid, file_size, file_path, alert.action, userIdentity.userName. |
| `contracts/semantic-identity-independent-goldens.v1.json` | `national.source-port → srcport` expected HIGH; now no target. Nested-SD cases name their reader. |
| `scripts/verification/mcv2-candidate-independent-oracle.mjs` | Host block replaced; members of objects absent; reader containers stated by format. |
| `scripts/verification/mcv2-canonical-mutants.mjs` | The ancestor-collision case used `host.ip` as its nested official field; it uses `rule.name`. |
| `scripts/verification/vendor-holdout-native-gate.py` | The gate accepts a documented value that is not official only where it names the vendor field that keeps it. The Syslog header host of four samples is declared that way (`hostname`, `syslog_hostname`). Official values in the downloaded Ruby output: 102 → 95 of 126; every value is still in the output. |
| Browser: `common-security-logs` (EDR), `docs-fortigate-multiple-types`, `docs-practice-full-authoring`, `issue232-semantic-auto-parser` (8 → 7), `stellar7-normalization-safety` (2), `stellar7-event-family-reviewed-browser`, `stellar7-reviewed-family-mapping` | hostname, hostip, process, command, policyid, sha256, nested names: official → vendor row; listed fields used where a positive case was needed. |

**b. Checks that were too weak and were made stricter**

| File | Before | After |
|---|---|---|
| `tests/normalizationAcceptance.ts` | Compared the text of the destination input; a vendor row named `severity` or `hostname` passed as official. | Reads the official rows; the official set must equal the listed targets of the scenario. |
| `tests/common-security-logs.spec.ts` (EDR) | Same weak comparison. | Official rows exactly `timestamp`, `userName → username`; every other source one vendor row under its own name. |
| `backend/src/golden-event-comparison.ts` | Only checked official rows. | A declined destination written as official, or its value lost, fails (`DECLINED_DESTINATION_WRITTEN`, `DECLINED_VALUE_LOST`). |
| `tests/normalization-security-edge.spec.ts` (wrapped LEEF) | Five targets checked. | The whole set is compared, so the scenario names `timestamp` too (the RFC 5424 header time, official before as well). |

**c. A gate that rewarded the old behaviour**

`scripts/verification/executable-contract-gate.mjs` required at least 90 aliases. Replaced by: every listed
field carries its definition and a stated basis, no field is both listed and declined, and every table of the
policy leads to a listed field only.

Earlier goldens that asserted `file_path` and `appid` as official contradicted the dictionary definition they
were mapped to. This is the same pattern as the earlier defects (an expected value written from the
implementer's assumption).

## 8. Fault injection

Each fault was applied to an isolated copy of the final tree. The non-browser checks were run on every copy:
tsc, the 2,634 unit tests, the Python policy tests, the gates of the local battery and the backend tests.
Browser journeys were run where those did not detect the fault and for the faults that change only the generated
Ruby; for these three the backend tests that execute Ruby were also run with Ruby 2.4.9. Counts are tests that
fail because of the fault; failures caused by machine load (time-outs) were not counted.

| ID | Class | Injected fault | Non-browser | Browser | Detected |
|---|---|---|---|---|---|
| A1 | wrong source / destination | ASA "Built outbound": the initiator is no longer taken for the source (both engines, Ruby regenerated). The defect of 2026-10-18 to 11-26 | unit 2, semantic oracle (TS), Python 1, template-set gate, backend 2 | not run | yes |
| A2 | wrong source / destination | Policy edit: alias `src → dstip`, `dst → srcip` | unit 35, independent candidate oracle. The policy consistency gate passes | not run | yes |
| B1 | NAT / original endpoint | TypeScript: the record-level rule removed (`xlate.srcip → srcip` again) | unit 38, identity oracle, cross-consumer gate, candidate-mutant gate, independent oracle, requirement trace (and tsc: unused code) | not run | yes |
| B2 | NAT / original endpoint | Python preview takes a member of an object for a field of the record | Python 3 | not run | yes |
| B3 | NAT / original endpoint | Policy edit: `nat_src_ip`, `xlate.srcip` listed as source aliases | unit 5, candidate-mutant gate, independent oracle | not run | yes |
| C1 | score / unit | TypeScript: the list is not consulted (severity, duration, hostname proposed again) | unit 50, candidate-mutant gate, independent oracle, requirement trace (and tsc: unused code) | not run | yes |
| C2 | score / unit | Policy edit: severity and duration listed, each with a plausible written basis | unit 22, candidate-mutant gate, independent oracle. The policy consistency gate passes | not run | yes |
| C3 | score / unit | Python preview proposes hostname and severity | Python 1, requirement trace | not run | yes |
| C5 | score / unit (new case) | Policy edit: `sha256`, a field outside the 24 reviewed ones, listed with a plausible basis | unit 5 (the exhaustive test, the test that requires a cross-engine corpus case for every listed field, three tests that expect sha256 to stay a vendor field), independent oracle. The policy consistency gate, the Python tests and the candidate-mutant gate pass | not run | yes |
| U1 | control removed while typing | D-1 again: the final-step identity card is mounted only while a placeholder is shown | none | 1 lifecycle journey (5 run) | yes, browser only |
| U2 | control removed while typing | Same class, new place: the Version input is remounted when its value becomes empty or non-empty | none | 31 journeys fail with `EDITING_CONTROL_LOST` in the 7 specs that type a version. The 5 journeys tried first (lifecycle, default deny) passed | yes, browser only, and only in journeys that type into that control |
| S4 | old result reused | Assisted: the pasted reply and its checks survive a change of the logs | unit 1 | not run | yes |
| S5 | old result reused | Auto: created files and their evidence are no longer bound to the input (both protections removed) | none (2,634 unit tests pass) | 1 journey of 56 run: the files are still shown after the input changed | yes, browser only, one journey |
| L1 | original field / value lost | Browser preview drops unmapped original fields | unit 50 | not run | yes |
| L2 | original field / value lost | A key=value pair the reader lost is reported FULL (Ruby regenerated) | unit 15, template-set gate | not run | yes |
| L3 | original field / value lost; Ruby differs from screen | The generated Ruby drops every vendor field; the screen is unchanged | unit none; backend with Ruby 25 | default-deny 2, golden vendor 14 | yes |
| R1 | Ruby differs from screen | The generated Ruby writes srcip and dstip swapped; the screen is unchanged | unit none; backend with Ruby 1 | default-deny 2, golden vendor 4 | yes |
| R2 | Ruby differs from screen | The generated Ruby writes hostname, severity and policyid as official fields; the screen is unchanged | none, also with Ruby | default-deny 2, golden vendor 3 (`DECLINED_DESTINATION_WRITTEN`, the new check) | yes, browser only |

What the results say:

- Every fault of the seven required classes is detected by checks that CI runs.
- Four faults are seen only by browser journeys (U1, U2, S5, R2). L3 and R1 are seen by browser journeys and by
  the backend tests that execute Ruby, not by unit tests. For U2 and S5 the barrier is narrow: U2 is caught only
  by journeys that type into the changed control, S5 by one journey.
- A policy edit with a plausible written basis passes the policy consistency gate (A2, C2, C5). Such edits are
  caught because tests state the expected result for those fields, and because a listed field without a case in
  the cross-engine corpus fails a test. An edit that changes the policy and those expectations together passes
  every gate; that is a decision to be reviewed, not something a gate can judge.

## 9. Verification on the final tree (local)

| Check | Result |
|---|---|
| `tsc -b`, `npm run build`, backend `check` and build | pass |
| Unit tests (vitest) | 2,634 of 2,634 |
| Python (`unittest discover`) | 276 tests. In the full run 2 failed, neither because of the change: `test_nginx_public_no_login_https_and_post_origin_gate` needs the preview host and fails before the change too; `test_apply_installs_every_part_and_restarts_what_changed` did not get its sandbox port while the machine was busy and passes when its file is run alone |
| Backend tests | 804 tests. 2 fail: the Drain3 tests (the library is not installed on the work server; they fail before the change too). The tests that execute Ruby were run with Ruby 2.4.9; two local set-ups were needed, and every such test passes in the one that provides what it calls |
| Gates of the repository | specification contract, executable contract, download sink (with its test), reachability, grammar and ts2rb verify, duplication ratchet, template set (unchanged), semantic oracle TS, identity oracle (with its fault test), mapping hints, MCV2 Python, mutation sensitivity, canonical AST score, allocation AST score, selected candidate mutants 22 of 22, bounded candidate AST 90.00 %: pass |
| Semantic oracle Python | pass |
| Downloaded-artifact gates on the files of the browser run, Ruby 2.4.9 | artifact contract, golden vendor 14 cases, Assisted 6, mixed ASA 4, mapping 15, vendor holdout 27 events: pass. The structure gate that needs the container images was not run here |
| With Ruby 2.4.9 | semantic oracle native and differential, vendor native parity, canonical cross-engine, operator conformance, translation conformance, native evidence: pass. Grammar conformance stops at `syslog_rfc3164-regex-body` in the same way before the change (local Ruby set-up) |
| Browser (Chromium, 554 journeys, real key presses) | 539 pass, 13 skipped as before, 2 fail: `novice-declared-schema` cannot write `/tmp/*.png` on the work server, as before the change. 7 journeys timed out in the full run, which shared the machine with the injection runs; their 7 specs were run again and passed (22 of 22) |

Two CI gates that the local battery did not contain failed on their first run here, both because they named a
field that is no longer proposed: `mcv2-canonical-ast-score.mjs` (its oracle used `host.ip` as the nested official
field of one case) and the vendor holdout gate on downloaded Ruby (it had no declared vendor field for the header
host). Both are in section 7. The CI workflow was then read step by step and every step that can run on the work
server was run; the steps that need the container images (variant matrix, Fluentd UDP, isolated runner) were
not.

CI on the exact head is recorded in PR #8.

## 10. Limits

- The 13 reasons are the executor's reading of the 7.0 dictionary and of the public format specifications
  (CEF, LEEF, ECS, Zeek, IANA). They were not confirmed by Stellar Cyber. An independent auditor should read
  `autoApprovedTargets` entry by entry.
- A listed field can still be wrong for a vendor that uses a standard name with another meaning; the list
  lowers that risk to 13 fields with stated reasons, it does not remove it.
- Python approves a subset and previews per event (section 4).
- The candidate mutation gate (`mcv2-bounded-candidate-ast-score.mjs`, minimum 90 %) measured 88.93 % after the
  deletions (241 of 271); before the change it stood at 90.00 % (297 of 330). Of the survivors, three were in
  the new position rule. One was a branch no input reaches and was deleted; for the other two the independent
  oracle did not state the positive side of the rule (a reader container inside the source copy, the
  single-event helper with and without a named reader) and three assertions were added. The gate now measures
  90.00 % (243 of 270), exactly the minimum. No assertion was added for pre-existing survivors. The ratio is
  not used here as evidence of safety; section 8 is.
- Not executed: a real ChatGPT reply, a real Stellar Cyber ingest. No customer log was used.
- No merge and no deployment were performed. Ruby templates and their approval constants are unchanged.

## 11. Reproduce

```
npx tsc -b
npx vitest run
python3 -m unittest tests.test_semantic_conformance_corpus tests.test_mapping_correctness_v2
node scripts/verification/executable-contract-gate.mjs
node scripts/verification/mcv2-semantic-candidate-mutants.mjs
node scripts/verification/mcv2-canonical-ast-score.mjs
node scripts/verification/mcv2-bounded-candidate-ast-score.mjs --require-90
npx tsx scripts/verification/independent-semantic-identity-oracle.ts
npx tsx scripts/verification/mapping-hints-cross-consumer.ts
npm test --prefix backend
PARSER_STUDIO_BROWSER_BACKEND=1 npx playwright test tests/default-deny-mapping-20261128.spec.ts
```
