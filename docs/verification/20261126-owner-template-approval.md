# 2026-11-26 owner approval of Ruby template set (PR #7)

The owner explicitly approved the exact template-set SHA-256 presented in
the ChatGPT recertification report on 2026-11-26:

`6384710b9af630de6a4ceee86a344e12f7ecb9fddef1a72e7f284fcbec93f00f`

Candidate at approval: `a18c7d6c0a526d2525b42f0479884eac00a9abae`.
The committed manifest is `contracts/ruby-template-set.v1.json`.
The approval updates only the exact digest in
`backend/test/template-set-approval.test.ts`. It does not relax the
manifest consistency or coverage tests, modify the POC allowlist, approve
future template changes, or authorize deployment. Required CI, independent
review, and other acceptance requirements remain in force.

Previous approval: [2026-11-25](20261125-owner-template-approval.md).
