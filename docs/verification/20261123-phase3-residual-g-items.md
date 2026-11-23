# Phase 3 residual audit items G-06, G-08, G-10..G-13 (2026-11-23)

Definitions: docs/verification/20261122-phase3-independent-audit2-b117e05-88c0768.md. Priority: wrong FULL,
lost data, wrong official mapping.

| Id | Effect | Decision | Change | Reproduction test |
|---|---|---|---|---|
| G-11 | Wrong FULL: `a=1&b=2&c=3` FULL with one field | Fixed (guard). Inside one token a key behind `&` is a pair, unless a `?` earlier in the value opened a URL query (`url=/a?x=1&y=2` stays one value). The event is PARTIAL instead of FULL; the pairs are not yet read as fields. | `src/grammar/parseStatus.ts` (`unquotedValueEnd`), generated Ruby (`grammar-core.generated.rb.tpl`, ts2rb), `runtime/multipass/source_kv.py` | `src/grammar/ampersandPairGuard20261123.test.ts`, `tests/test_kv_ampersand_pair_unread_20261123.py` |
| G-13 | Wrong official mapping: ICMP pseudo-ports approved as srcport/dstport when the protocol is written `protocol.name`, `flow.l4.proto`, `ip_protocol`, `l4_proto` or ECS `network.transport`; lower mapping rate: a TCP protocol object with `flags` kept the ports in review | Fixed. Protocol evidence is read by the path of each scalar: a protocol-named segment (or ECS `network.transport`) makes the scalars at or below it evidence, except `flags`, `tcp_flags`, `flag`, `state`, `direction`; only a protocol object or the ECS network object is descended into (another object is another family of the record); a bare `transport=` stays a port (FortiGate). | `src/guided/normalizationCandidates.ts` | `src/guided/protocolEvidenceNames20261123.test.ts`, 17 cases in `scripts/verification/mcv2-candidate-independent-oracle.mjs` |
| G-10 | Parity: the Python preview reported SOURCE_PARSED for a comma list of 101 pairs or with a repeated key while TS/RB decline | Fixed. The Python comma and delimited key=value frames decline a list of more than 100 pairs or with a repeated key, as `src/grammar/kvBody.ts` does; the event is PARTIAL with every value kept. | `runtime/multipass/generic_structural_poc.py` | `tests/test_comma_kv_limits_20261123.py` |
| G-06 | Ambiguous reading: one token `opts=rw,uid=1000,gid=1000` is read as three pairs (values preserved, split) | Open by design: one token cannot say which reading is meant; no value is lost. | - | - |
| G-08 | Lower mapping rate: a host beside a bare upper-case method word, or inside an object, stays a review proposal | Open: conservative (no wrong mapping); the user approves it in Map Fields. | - | - |
| G-12 | Parity (P3): a quoted list value ending in a backslash is PARTIAL in TS/RB, SOURCE_PARSED in Python | Open: the conservative grade (PARTIAL) is the one the generated parser uses. | - | - |

The G-11 change alters the generated Ruby grammar: template-set digest
09de3c540f0ef12341773c13764414408a1ea4400674a54d123e177198ee1ac5 -> see the final report (owner approval
required; KNOWN_TEMPLATES and approval constants unchanged).
