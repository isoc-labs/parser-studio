# Phase 3 P3-1..P3-3: ChatGPT Assisted on parsers with event profiles (2026-11-23)

## Problem

ChatGPT Assisted refused every draft with event profiles (for example PAN-OS TRAFFIC and CEF in one
stream): `prepare()` and `generateVerifiedDraft()` returned early and the Prepare button was disabled,
because ParserRecipe v0.2 cannot express type-specific mappings.

## Design (no Recipe contract change)

One event type is handled at a time (`src/guided/familyScopedAssist.ts`):

- `familyScopes` lists every event type of the routed draft with its records and state
  (READ, PARTIAL) plus the records of no type (UNRECOGNIZED).
- `projectFamilyDraft` gives the ordinary single-type draft that reads that type exactly as the routed
  draft does (shared mappings plus the type's mappings). ParserRecipe v0.2 can express it, so the existing
  prompt, review, one-change proposal, comparison, different-example and Regex checks run unchanged on the
  original lines of that type only.
- `mergeFamilyCandidate` puts a reviewed result back into that type only. It rejects a changed source
  format, shared mapping, enrichment or classification, a destination already written in the event
  (no duplicate destinations), a mapping whose source no record of that type contains
  (`SOURCE_NOT_IN_FAMILY`: a result made for another type, or a path of another type), and an invalid
  profile set. A result for unrecognized records becomes a new type selected by the existing discriminator.
- `familyPromptContext` adds the parser state to the prompt in its own section: discriminator, types still
  to support, shared mappings, and every type with record count, state and mappings. It carries names and
  counts only; the selected type's original lines are the prompt source, unmodified.

UI (`src/guided/ChatGPTAssist.tsx`): a draft with event profiles shows an event type selector
(first type that is not read completely is preselected), the identity card, and the existing
"Validate & Generate One Multi-Type Parser" control. The ChatGPT steps run on the selected type; after the
single-type files pass, "Apply to event type X" merges the result, and the multi-type parser is generated
and checked by the backend as before. Single-type drafts and Named Log Types are unchanged.

Root cause found by the Chromium E2E: the selected type's preview was not recomputed after an identity
edit, so the vendor namespace moved and the comparison reported 16 removed fields. The projected draft now
follows the parser, and every change of it is previewed again before use.

## Evidence

- Vitest: `familyScopedAssist20261123.test.ts` (9), `ChatGPTAssist.familyScope.test.tsx` (1),
  `chatGptFamilyWrongReplies20261123.test.ts` (11).
- Wrong replies (written by the test, not by ChatGPT; no AI success rate is implied), all blocked:
  missing field, changed value, false verification claim, nonexistent field, field of another type,
  change of how every type is read, unbounded Regex, contract violation, prose, and a correct CEF result
  applied to the PAN-OS type. A correct one-field correction passes every check; PAN-OS records are
  unchanged.
- Chromium E2E `tests/chatgpt-event-profile-scope-20261123.spec.ts`: Auto Parser routing, CEF scope,
  prompt (CEF lines only, no PAN-OS line), reply, two different examples, approval, single-type files,
  Apply, multi-type generation and download. Compiled project: `body.act -> action` in the CEF profile
  only; PAN-OS profile and shared mappings unchanged.
- Ruby 2.4.9 run of that downloaded parser: 7 lines in, 7 records out; the line of no event type is a
  failure record whose `parser_raw_msg` equals the line.

NOT VERIFIED: Stellar Cyber DP install, reception and indexing (owner test); real ChatGPT answers.
