# 02. Parser Studio — Current Web UI / UX Specification

**Status: ACTIVE for user navigation and interaction.** Product scope is owned by
[14 — current product scope](14_TWO_PATH_PRODUCT_V2.md). This document supersedes
the retired Wizard/Workbench UI design; the original design is preserved in
[immutable Git history](https://github.com/isoc-labs/parser-studio/blob/14dcacddff48365001bfca2653c4466037d023b0/docs/02_WEB_UI_SPEC.md).

## Navigation and first use

The only creation methods are Auto Parser and ChatGPT Assisted Parser.

Auto Parser follows Add Logs → Review Fields → Map Fields → Create Parser.

- Auto Parser is the default. Paste/upload representative raw logs before optional
  source identity and listener-port settings. A user can name multiple log types.
- ChatGPT Assisted Parser is the alternative for a record or mapping requiring a
  reviewed proposal. Show a sensitive-data warning, prepare the exact source
  prompt for manual copy, accept a restricted recipe and require applicable local
  validation and explicit approval. No automatic external LLM request.
- Local Versions is a browser-local supporting action available from both paths,
  not a third creation method. New Parser confirms before discarding existing logs.
- Wizard, Workbench, standalone Library/Test Lab/Schema Explorer creation menus,
  separate Existing Parser import and standalone Tools & Diagnostics are not
  current public navigation. Legacy deep links to retired routes resolve to Auto
  Parser; preserve useful internal libraries where appropriate.

## Auto Parser stages

1. **Add Logs** — original sample, optional named log types, explicit Analyze Logs,
   source accounting and understandable recovery for unsupported input.
2. **Review Fields** — review actual detected fields and unresolved spans without
   silently losing records or values. Distinguish source parsing from export support.
3. **Map Fields** — review suggested Stellar Cyber mappings, resolve collision/type
   problems, use optional reviewed AI assistance, and correct mappings manually.
4. **Create Parser** — validate the reviewed source and mappings, create the
   matching Ruby/CONF pair only when eligible, and expose verified artifact
   downloads without implying live target compatibility.

Errors, unsupported structures, pending checks and unverified runtime evidence
must be distinct from PASS. Preserve original source, actionable explanations and
reversible edits. No unsupported format or ambiguous mapping may silently appear
successful. See the product scope for privacy, native verification and excluded
target operations; these constraints apply in both creation paths.

## Acceptance and maintenance

Verify the real rendered navigation and the ordered stage transitions against
this specification. Use actual browser evidence for final user acceptance, not
a static source match. Changes to the public stage order or exposed capabilities
must update this specification and applicable independent tests together.
