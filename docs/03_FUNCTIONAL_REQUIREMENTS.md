# 03. Current functional requirements and legacy disposition

**Status:** Current source parsing, mapping and export requirements. UI navigation
belongs to 02 and product scope to 14. The initial F01–F26 table is preserved in
[immutable Git history](https://github.com/isoc-labs/parser-studio/blob/14dcacddff48365001bfca2653c4466037d023b0/docs/03_FUNCTIONAL_REQUIREMENTS.md).
This document does not declare current test or release PASS.

## Parsing and mapping

<!-- requirement: PS-006 -->
Accept multiple named log types from one product and preserve their original records and labels. Qualify a combined parser only when source-backed routing and per-type evidence establish compatibility. Empty, duplicate or invalid groups must fail clearly. Browser-local versions restore their names and source without silently changing record separators.

<!-- requirement: PS-007 -->
The default parser listener port is 6801; a reviewed user override must reach the generated CONF and the matching sensor destination. Check port availability before deployment; authoring does not itself send sensor traffic.

<!-- requirement: PS-008 -->
Use the Stellar Cyber 7.0 dictionary only; never infer official fields from another release or unsupported semantics. Preserve type, timestamp unit and timezone, IP validity, port range and protocol evidence; reject invalid or conflicting official destinations. Automatic mapping is default deny: a matching name, alias, type or value range is not evidence of the official meaning. An official field is proposed automatically only when the shared Semantic Policy lists it (`autoApprovedTargets`: each entry quotes the 7.0 dictionary definition and states why a name can carry that meaning), only under the protections of that policy (type and range, closed vocabularies, transport evidence, translated endpoints), and only from a source that stands for the record itself: a root-level name, a name in the container the reader of the event writes the pairs of the record into, a whole path the alias table lists, or a key the format specification defines. A member of any other object of the record is never taken for a field of the record, and a translated (NAT) address or port is never taken for the original endpoint. Every other field — a 0–100 score (severity, fidelity, threat_score), hostname, a duration, and any dictionary field the policy does not list — keeps its source name and value, with no conversion, and remains available to reviewed ChatGPT mapping, which the user confirms, and to manual mapping. The browser proposals, which decide the generated parser, and the Python preview read the same list; a field joins it only with a recorded definition and basis.

<!-- requirement: PS-009 -->
Parsed fields without an approved official mapping stay in the actual manufacturer namespace with their original names and values. Demo placeholders must never be exported; actual manufacturer and product are required before generating files. Do not fabricate official field meanings or silently discard a value simply because no official mapping was found. Explicitly unsupported/non-emittable values and residuals remain visible as such; distinguish reviewed omission from loss.

<!-- requirement: PS-010 -->
Offer evidence-backed automatic mapping, optional reviewed ChatGPT mapping, and manual correction as fallback; manual or approved mapping is never overwritten by automatic suggestions. Manual edits in a multi-type parser affect the selected event type unless the rule is shared; collisions are blocked and other types remain intact.

<!-- requirement: PS-011 -->
Parsing correctness and source-value accounting precede mapping success. Preserve original UTF-8 source, exact event boundaries and unresolved spans; do not report FULL or verified output from a partial match or absent evidence. Independent byte/value accounting must distinguish missing evidence from actual loss. When a format cannot be parsed safely, expose the recovery route or return the complete raw event as an error record where supported (target delivery and retention are unverified); never invent a parser rule or force automatic mapping merely to reach 100 percent.

<!-- requirement: PS-012 -->
The pinned Stellar 7.0 native target profile is Ruby 2.4.9 with Fluentd 1.7.4; browser preview, native synthetic execution and actual proprietary DP import/indexing are distinct verification levels. Do not claim target import or live listener proof from a browser or synthetic test. Ruby/CONF generation is subject to the executable capability and regex safety contract.

## Additional retained invariants

- Extract supported structured and unstructured log formats; keep source record counts, unresolved text and meaningful errors visible. No universal catch-all that hides failures.
- For reviewed CSV and explicit multiline framing use the rules in 14; unsupported boundaries remain unverified.
- The portable draft and saved browser-local versions retain original sources and reviewed mappings. Use the native output and exact artifact hash checks described in 14.
- Retain deterministic fixtures, source/dictionary provenance and independent oracle evidence. Unit, browser, backend and native results must be tied to their actual exact candidate.
- Bound input sizes, parsing cost and execution; do not send private raw logs to third parties automatically or publish them in telemetry, GitHub or evidence. Release and production require separate approval.
- Authored UI and engineering explanations are English; preserve all original multilingual log values and identifiers unchanged (AGENTS.md).

## Initial requirement disposition

The prior table listed MVP and exploratory P1/P2 proposals. The following is a
scope disposition, not an implementation-completion ledger. It preserves every
initial ID rather than allowing retired features to re-enter through old prose.

| Original IDs | Current disposition / authority |
| --- | --- |
| F01, F13 | Browser-local draft and versions in 14, not a server project library. |
| F02, F03, F03A | Current sample/event routing and named log types, PS-006 and PS-011. |
| F04, F05, F06 | Auto format recognition, supported extractors and bounded framing, 14 and PS-011; no general format-selection wizard. |
| F07 | Contextual source/span and field review in 02/14; unrestricted visual rule authoring is not current scope. |
| F08, F14, F15, F18 | Supported Ruby/CONF export and exact runtime/evidence boundaries, 14 and PS-007/PS-012; real proprietary compatibility remains a separate gate. |
| F09, F10, F20 | Typed official field mapping, safe suggestions, preservation and review, PS-008–PS-010. |
| F11, F12 | In-flow raw/parsed/mapped evidence and diagnostics, 02/14; standalone Test Lab is retired. |
| F16 | Current privacy, bounded execution and manual AI boundary, 14. |
| F17 | Existing-parser import is not a current public workflow (02/14). |
| F19 | Standalone Library creation navigation retired; browser-local versions retained (14). |
| F21 | General source editor/GUI round-trip was an initial proposal, not current public acceptance. Constrained reviewed recipes remain in 14. |
| F22, F26 | Initial multi-user/team collaboration proposals, outside current scope. Reopening requires an accepted product decision. |
| F23 | Current optional manual ChatGPT assistance, 14 and PS-010. |
| F24 | Capability-gated operators only; no promise of all Fluentd plugins. |
| F25 | Server-operated lab/target integration excluded from current product scope (14). |
