# Isolated lossless accounting increment — 2026-11-19

## Scope and identity

- Branch: `experiment/codex-accuracy-lab-20261117`
- Starting HEAD: `901927d3f8399418618773ebc709c62a3364e498`
- Work was performed in the isolated clone only. No push, PR, merge, release, target import, credential change, or template approval change was performed.
- Fixture provenance remains `AUTHORED_FROM_VENDOR_GRAMMAR` / vendor-grammar-derived where labeled. No captured original vendor sources were added or claimed.

## Implemented

- Lossless accounting now reconciles every supplied event's exact raw record, in order, to every nonempty source line. A missing, copied, reordered, or omitted record makes proof `UNKNOWN` and identifies the supplied event IDs as unaccounted.
- Residual spans must be positive integer UTF-8 byte ranges within the event raw bytes. Invalid spans and bounded/truncated path reports prevent `COMPLETE`.
- The mapping editor no longer prepends the artificial `parserstudio_source.` namespace to a source path shown to the author; the canonical path remains in mapping metadata and full source-tree review.
- Turning on `omitSourceRaw` now displays a prominent alert stating that the original line will not be emitted and only parsed/mapped fields remain.

## Exact local evidence

- RED before fix: `npx vitest run src/guided/losslessAccounting.test.ts` failed both added regressions (caller-reported FULL without full source reconciliation; invalid residual/path truncation still reported complete).
- GREEN focused: `npx vitest run src/guided/losslessAccounting.test.ts src/guided/NormalizationMappingReview.test.tsx src/guided/vendorHoldout20261116.test.ts src/guided/juniperSdNormalization20261104.test.ts src/guided/vendorFieldNames.test.ts` — 5 files, 61 tests passed.
- `npm run typecheck` — PASS.
- Full `npm test` — 237 files passed; 2066 tests passed, one test errored because spawning `python3` returned `EPERM` in the sandbox (`src/guided/pythonTestSender.test.ts`).
- `python3 -m unittest discover -s tests -p 'test_*.py'` — 191 tests run; 188 passed, three loopback server tests errored because opening a local socket returned `PermissionError: [Errno 1] Operation not permitted`.
- `git diff --check` — PASS.

## Open gates

- Exact broad adversarial accounting report across nested arrays/null/dotted or duplicate keys, depth and field caps, mixed CEF/LEEF/syslog/RFC3164/RFC5424, quoted CSV, incomplete/unknown records, and all holdouts is not yet produced. Existing holdout semantic tests are retained; they are not represented as a new independent runtime-emission proof.
- Browser Chromium and browser AI import journey were not run in this sandbox; loopback sockets are restricted.
- Ruby 2.4.9/Fluentd is unavailable; Docker daemon access is denied (`/var/run/docker.sock`). Native generated-Ruby parity remains UNVERIFIED.
- Stellar Cyber 7.0 import/indexing and captured original vendor source matrix remain UNVERIFIED / unavailable.
- Full frontend/Python suites are not recorded as PASS due to the runner errors above. Backend native suite and exact-head browser gates remain open.
