# 2026-11-16 Owner-approved Ruby Template and Template Set (PR #311)

The owner approved the following two exact SHA-256 values for PR #311 on 2026-11-16 (Issue #249):

| Value | SHA-256 | Constant |
|---|---|---|
| POC reviewed-template hash | `a829026d948b8a492db534ddf50e9009a8686f6a3a642abccaecb7f332bed246` | `KNOWN_TEMPLATES` (`backend/src/stellar-legacy-plan.ts`), `APPROVED_CURRENT_TEMPLATE_SHA256` (`backend/test/poc-template-approval.test.ts`) |
| Template-set digest | `3bd3172b620f0c09f87d5b8d9df548b2c187048b451a0cde7cf95cf287421936` | `APPROVED_TEMPLATE_SET_SHA256` (`backend/test/template-set-approval.test.ts`), parts in `contracts/ruby-template-set.v1.json` |

Both are the values of the generated Ruby of commit `129d2d3`; the commits `55d8adf` and `394ecfd` after it
change tests and documentation only. The same two values came from the local tests (Node 24.21), from an
independent recalculation that uses no project code, and from CI on Node 22.23.4 (runs 43805979860 and
43811691853). Older owner-approved template digests remain in `KNOWN_TEMPLATES` unchanged.

What the values cover and do not cover, the audits and the verification behind them are in
[`grammar-contract-and-semantic-oracle.md`](grammar-contract-and-semantic-oracle.md), sections "What the two
approval values cover", "Final audit and verification before the owner review" and "Audits of the changes made
after the first one". In short: they are identities of generated text, not statements about behaviour.

The approval of the POC hash is limited to the `KNOWN_TEMPLATES` allowlist for synthetic, disposable POC
writes. It does **not** authorize production or live sensor deployment, management API activation, new
tenants, or other releases. After this approval the following gates continue to apply unchanged:
- 127.0.0.1-only receiver, fixed disposable test naming and port range
- null output sink and synthetic-fixture-only project identity
- strict manifest, hash, byte-level recompile and source verification
- owner and tenant authorization and no arbitrary Ruby injection

Owner decisions recorded with the approval:
- Accuracy of parsing and of the Stellar Cyber 7.0 field mapping comes before throughput. A per-event cost of
  about twice `main` (JSON about four times) is accepted; throughput work is not a condition of this release.
  An endless loop, memory exhaustion or a lost event is not accepted.
- key=value escapes follow the stated grammar contract and the meaning of the original text; a JSON number
  that cannot be kept exactly is diagnosed, not rounded; a declined event is a diagnostic result, never a
  parsed one; behaviour that differs from `main` stays where the new contract was verified.
- Items that concern cost only (H1, H2, G8 of the last re-check) are documented and closed.

Any later change of a Ruby template changes both values and needs a new owner review.
