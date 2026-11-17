# 2026-11-17 Owner-approved Ruby Template and Template Set (PR #314)

The owner approved the following two exact SHA-256 values for PR #314 at `3e1fd49` on 2026-11-17:

| Value | SHA-256 | Constant |
|---|---|---|
| POC reviewed-template hash | `4efddd8b5446799c0173788a8ef913fa393162cf18c1e1463e7e3e2e338bbfb8` | `KNOWN_TEMPLATES` (`backend/src/stellar-legacy-plan.ts`), `APPROVED_CURRENT_TEMPLATE_SHA256` (`backend/test/poc-template-approval.test.ts`), the proof assertion of `backend/test/stellar-legacy-plan.test.ts` |
| Template-set digest | `16824f8e1201e8c1bb2a2244baa4516db75546caa6d3fdddff8abb1575b4c7e4` | `APPROVED_TEMPLATE_SET_SHA256` (`backend/test/template-set-approval.test.ts`), parts in `contracts/ruby-template-set.v1.json` |

Both are the values of the generated Ruby of commit `3e1fd49c8af64cbfa305a1e712b4aebf76877ed6`. Before the approval
the same 64-character values came from three independent sources:

- CI on Node 22 (run 44021748253 at `3e1fd49`): the two approval tests printed them as `actual`.
- An independent recalculation that uses no project code (dump of the compiled artifacts, digest in Python).
- The independent auditor's own recalculation (audit of `3e1fd49`, verdict PASS with 0 P1 and 0 P2).

What the generated Ruby changes against the previous approval (`a829026d…`, `3bd3172b…` of PR #311) and how it
was verified is recorded in [`20261116-template-changes-json-number-blank-value.md`](20261116-template-changes-json-number-blank-value.md):
JSON numbers in decimal or exponent spelling are read when the double stands for exactly the number written; a
mapped value of nothing but ASCII white space is a missing value; a JSON message behind a Syslog header that the
JSON contract does not read is declined (new parsers) or PARTIAL (existing ones), never free text. Older
owner-approved template digests remain in `KNOWN_TEMPLATES` unchanged.

The approval of the POC hash is limited to the `KNOWN_TEMPLATES` allowlist for synthetic, disposable POC
writes. It does **not** authorize production or live sensor deployment, management API activation, new
tenants, or other releases. The gates of the previous approval
([`20261116-owner-template-approval.md`](20261116-owner-template-approval.md)) continue to apply unchanged, and so do
the owner decisions recorded there (accuracy before throughput; a number that cannot be kept exactly is
diagnosed, never rounded; a declined event is a diagnostic result).

Any later change of a Ruby template changes these values and needs a new owner review.
