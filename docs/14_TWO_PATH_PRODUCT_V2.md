# Parser Studio 2.0 — Current product scope

**Status: ACTIVE for the two-path product and its scope boundaries.** Navigation
and stage order are defined by [02 — Current Web UI / UX Specification](02_WEB_UI_SPEC.md).
The earlier combined spec/roadmap, dated CI counts, historical UI prototypes and
old PR pointers remain available in [immutable Git history](https://github.com/isoc-labs/parser-studio/blob/14dcacddff48365001bfca2653c4466037d023b0/docs/14_TWO_PATH_PRODUCT_V2.md).
They are not current acceptance criteria. Use the roadmap for implementation status,
and exact-candidate evidence for completion; this specification makes no PASS claim.

## Auto Parser and ChatGPT Assisted Parser

Support the two creation methods defined in 02. Auto Parser detects supported
source formats without requiring the user to select a format or write regex.
Review source event accounting, extracted fields and normalized mappings before
generating a schema-checked extensionless Ruby parser and matching CONF.

Do not silently omit events, infer unsupported RFC3164 time, invent positional
CSV semantics or claim unsupported native parsing. Preserve source values and
report unmatched regions, ambiguous boundaries and unsupported compiler features.
For W3C/Zeek, distinguish metadata/header lines from logical events while preserving
both in source accounting. A source-parsed result does not imply native support.
Keep input-first layout, optional manufacturer/product/port metadata, named log
types, context-sensitive recovery and optional relay/prefix/postfix review.
Do not revive separate creation modes, the six-step Wizard, three-pane Workbench,
standalone Tools & Diagnostics, private Drain3 source grouping controls or
Existing Parser import in the public navigation.

## Privacy and AI proposal boundary

Typing and browser previews stay in the browser; explicit Analyze Logs sends the original sample to the same Parser Studio server for Multi-Pass analysis. No automatic source transfer to ChatGPT.

ChatGPT Assisted prepares a manually copied prompt containing the exact
user-entered source, source digest/count metadata and applicable declarative
recipe context. The user decides whether to redact source values before manually
sharing. Show one clear sensitive-data warning; no separate masking editor,
mandatory masking-consent checkbox, extra source-copy action or automatic
external LLM request. The separate same-origin Multi-Pass analysis request is
not a ChatGPT request. Keep the original source in browser memory and do not
automatically transfer it to a third-party service.

The restricted ParserRecipe v0.2 result must verify the exact source SHA, stage
order and allowed schema. If the v0.1 project is unavailable, use the local
draft identity and keep recovery REVIEW_ONLY and unverified. Changed supported
rules require local sample and applicable independent holdout regression and
explicit user approval before replacement or generation. Unrecognized raw
formats, unsafe regex, arbitrary Ruby/JSONata or arbitrary stage edits cannot
fabricate a deployable parser. Use a bounded, reviewed compiler subset, not
arbitrary code execution. Changing the source invalidates the prepared prompt.

## Results and excluded target operations

The current product excludes server-operated Test Lab recovery/evidence, DP parser upload/apply, sensor replay/sending and Interflow lookup/verification.

Retain optional browser-local versions and offline Python test sender as specified
below. Removed prototypes are historical, not public features to restore.
Test Lab/Interflow/sensor endpoints must not create user-visible or unauthorized
target actions. The separate generated Python sender is run manually by the user.
Real target compatibility must never be inferred from local preview or synthetic tests.

For an eligible reviewed source, provide the individual Ruby and CONF files and
supported ZIP. Validate matching hashes and source/CONF port consistency.
A tampered ZIP hash must never trigger a download or verified claim; missing ZIP
capability must not initiate a ZIP request or suppress valid individual files.
Reject malformed mapping destinations and ancestor/child path collisions before
generation. Restoring a valid mapping permits revalidation. Show native and target
verification status accurately; no unverified compatibility badge or deployment.

## Reviewed mixed CSV and explicit framing

CSV contains no trustworthy field names. For eligible candidate CSV rows, present
inline reviewed ordered column names and explicit comma, semicolon or TAB
delimiter. Preview, conversion and generation must use the reviewed schema,
not inferred names. Source/schema/delimiter edits revoke the approval.
Reject wrong column counts, invalid quotes, unrecognized families, unreviewed
prefix, unsupported multiline framing and source/CONF port mismatch.
Source-free authoring metadata and the explicit same-origin Multi-Pass analysis
request are different interfaces. Runtime family vocabulary and capability
compatibility are governed by the current executable schemas and native compiler
contracts, not the historical fixed-count snapshots in the old combined roadmap.

## Downloadable Python synthetic log sender

This is an optional utility inside the existing Auto Parser test/results
path, not a third authoring mode and not a live sensor API integration.

After reviewing representative logs, offer Generate Python Test Sender.
Generate and download a self-contained Python 3 script directly from the
browser using no third-party packages, credentials, backend log storage or
automatic sensor connection. On launch, prompt for the destination sensor
IP/hostname and port; validate them, default to UDP with explicit TCP
choice, confirm before connecting, and emit one event per second.
Default to a bounded event count, report progress and stop on Ctrl-C.

For each emitted event replace supported timestamp formats with the
current local/UTC time at transmission and independently randomize
recognized source/destination IP, location, username, email and other
structurally identified field values. Preserve RFC syslog/CEF/LEEF/
JSON/KV/CSV dialects, quoting, escaped delimiters, record boundaries
and constant IDs. Do not blindly substitute unrelated numbers or infer
vendor-specific semantics; unsupported ambiguous values remain
unchanged and are explicitly disclosed.

Only the downloaded Python script, running under user's control on
their machine, sends logs; Parser Studio/browser/backend never
connects to a sensor as a side effect of this feature. The script may
contain user-provided logs in plain text, so show a privacy warning.
This scoped opt-in user utility is distinct from the excluded
server-operated sensor sender, DP parser upload and ingest checking.

Acceptance: stdlib-only Python 3, interactive validated target IP/port,
explicit confirmation, deterministic one-per-second maximum rate,
bounded count/interrupt stop, current timestamps and safe value
randomization, no network API on generator creation, and independent
loopback UDP/TCP listener validation without any real sensor.

## Local experiment history

- Add one optional **Local Versions** workspace accessible from both supported
  parser creation paths, not a third authoring method.
- Save complete current source sample and portable draft/mapping configuration
  as a named, browser-only version; retain multiple versions and compare them
  with each other or the unsaved working copy.
- Restore one complete version without silently overwriting other versions,
  with a browser-local safety checkpoint before replacing unsaved work.
- Use IndexedDB (not the backend artifact revision/history endpoints), with
  a strict bounded schema, digest, capacity guards and visible storage warnings.
- No DP parser upload/apply, sensor send or ingest/index result verification;
  their historical prototype interfaces are not part of the product's scope.
- The owner decides whether to redact a manually copied ChatGPT prompt;
  show a warning without a mandatory masking-consent checkbox.

## ChatGPT-assisted JSONata field mapping

Within **Auto Parser → Map Fields** (not a third workflow), users can prepare a
privacy-reviewed ChatGPT prompt from extracted field paths, copy it manually,
paste a strict JSONata selector mapping proposal, review local dictionary/type/
semantic checks for every event, and explicitly approve compatible destination
fields. The feature never sends raw logs to an AI provider automatically.

The supported JSONata subset consists of direct property selectors only;
functions, calculations and arbitrary expressions remain unsupported because
this product must compile the same mapping to native Ruby/.conf. All unsupported
proposals are blocked and no unverified Stellar DP compatibility is claimed.
Detailed workflow, schema, semantic guards and tests are in
[the JSONata mapping acceptance note](verification/20261104-chatgpt-jsonata-mapping.md).

## Acceptance boundaries

The requirements in this file and 02 are intended behavior, not test results.
Use independent requirement-based checks, source/backend/native parity where
applicable, and real user-facing acceptance on the exact candidate. Retired
Wizard/Workbench tests remain historical, never current PASS. User approval
and separately authorized release actions remain unchanged.
