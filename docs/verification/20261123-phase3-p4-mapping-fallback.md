# Phase 3 P4: mapping fallback on parsers with event profiles (2026-11-23)

Order: automatic Stellar Cyber 7.0 mapping, then a ChatGPT JSONata mapping proposal (manual copy and
paste), then manual mapping.

## Changes

- `createJsonataMappingPrompt` now carries, in addition to the source paths, coverage, optional values
  (opt-in) and local hints:
  - the relevant Stellar Cyber 7.0 dictionary entries (targets in use, local candidates and common
    security targets) with mapping type, group and documented meaning;
  - the existing official mappings;
  - the source fields without an official mapping;
  - for a parser with event profiles, the event types, their mappings and the types still to support
    (`familyPromptContext`).
- `JsonataMappingAssistant`: a parser with event profiles gets an event type selector. The selected type
  is projected to an ordinary single-type draft and its records only; the existing review (real values,
  dictionary type, semantic conflicts, duplicate sources and destinations, protected human mappings) and
  apply checks run unchanged; the result is merged into that type with `mergeFamilyCandidate`, so other
  types and the shared mappings are unchanged and no destination is written twice. Previously an apply on
  such a parser wrote shared mappings.

## Evidence

- Vitest: `jsonataMappingPromptContext20261123.test.ts` (2), `JsonataMappingAssistant.familyScope.test.tsx`
  (1: CEF `body.cef_name -> event_name`; preview gives `Login` for CEF records and nothing for PAN-OS).
- Chromium E2E `tests/chatgpt-jsonata-event-profile-20261123.spec.ts`: Auto Parser routing, Map Fields,
  JSONata assistant on the CEF type with values, reply, review, approval, apply, Create Parser Files.
  Compiled project: `body.cef_name -> event_name` in the CEF profile only; PAN-OS profile unchanged.
  The downloaded Ruby file matches the backend SHA-256.
- Ruby 2.4.9 run of that parser on PAN-OS, CEF, two different CEF lines and an unknown line: 7 in, 7 out;
  `event_name` is `Login`/`Logout` on CEF records only, PAN-OS `srcip`/`action` unchanged, the unknown
  line is a failure record whose `parser_raw_msg` equals the line.
- Manual per-type mapping: existing Review Fields controls ("Use Stellar 7.0 <type> <field>", output
  edit) remain covered by `tests/stellar7-reviewed-family-mapping-20261021.spec.ts` (passed).

## Limits

- JSONata is a selector subset: functions, conditions and arithmetic are refused, because only direct
  selectors compile to the Ruby 2.4.9 parser. JSONata "execution" means evaluating the selector against
  the real parsed values of every record.
- The replies in these tests are written by the tests, not by ChatGPT; no AI success rate is implied.
- NOT VERIFIED: Stellar Cyber DP install, reception and indexing (owner test).
