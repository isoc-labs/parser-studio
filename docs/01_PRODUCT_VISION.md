# 01. Parser Studio — Product Vision and Scope

**Status:** Product purpose and boundaries. Current UI, functional requirements and runtime evidence are defined in 02, 03 and 14; this is not a separate feature specification.

## 1. Problem and outcome

Stellar Cyber Parser Studio does not provide an effective field-engineer workflow for repeatedly developing and correcting custom log parsers. Our product will be a **separate Web application**, not a modification of the vendor's UI.

**Desired outcome:** A field SE or partner can turn representative raw logs into a validated, maintainable, Fluentd-compatible parser and Stellar Cyber-normalized event preview without writing parsing rules from scratch. Users may review fields, correct mappings and submit constrained parsing proposals in the two supported creation methods.

## 2. Personas

| Persona | Key tasks | Required experience |
| --- | --- | --- |
| Field SE / Partner | Onboard an unknown product's logs, test and export | Guided, visual, fast correction |
| Parser engineer | Complex conditional routing, nested extraction, transforms | Reviewed rules, source accounting and diagnostic trace |
| Reviewer / Customer | Validate samples, mappings and coverage | Readable errors, repeatable evidence |
| Product maintainer | Manage templates, regression fixtures, import/export adapters | Diff, history, reproducibility |

## 3. Principles

1. **Version-independent authoring.** No version choice is required to edit or test. Compatibility is an export and validation concern.
2. **Samples-first.** Work on a meaningful collection of variants, not a single hand-picked matching line.
3. **Explain every failure.** Show whether a record was split, routed, parsed, normalized, validated and exported.
4. **No false green.** An in-browser Regex match is not equal to Fluentd runtime success or Stellar import compatibility.
5. **GUI by default, source when needed.** Visual controls and reviewed proposals within the two supported workflows.
6. **Privacy by default.** Customer-origin logs stay private, redacted where feasible; external AI is opt-in only.
7. **Reproducibility.** Parsers, schema mappings, test fixtures, test environment and export manifests are separately versioned.
8. **Original UI and implementation.** Use competitor interactions as research, not proprietary source/assets.

## 4. End-to-end user journey

Use the current two creation methods, Auto Parser and ChatGPT Assisted Parser,
with browser-local working versions and in-flow mapping review. The authoritative
public navigation and exact stage order are in [02 — Current Web UI / UX
Specification](02_WEB_UI_SPEC.md); the current scope and excluded capabilities
are in [14 — Current product scope](14_TWO_PATH_PRODUCT_V2.md). Historical
import/workbench/review journeys are not current acceptance criteria; see
[immutable Git history](https://github.com/isoc-labs/parser-studio/blob/14dcacddff48365001bfca2653c4466037d023b0/docs/01_PRODUCT_VISION.md).

## 5. In scope

- Multiple raw log samples; event breaking, route variants, format detection, structured and unstructured extraction.
- Fluentd parser configuration support and native runtime validation for supported features.
- Interflow mapping, typed normalization, enrichment/transforms and preview.
- Reproducible diagnostics, regression coverage, templates and version history.
- Ruby/CONF draft export with explicit runtime and proprietary target verification status.
- Desktop-first Web UI. Authored product UI is English; original log values may contain any language (see AGENTS.md).

## 6. Explicit non-goals / boundaries

- No dependence on Stellar Cyber's embedded Parser Studio for editing.
- No implied support for all Fluentd plugins; use capability declarations.
- No promise that undocumented Stellar-specific legacy JSON/CONF and modular JSON are interchangeable.
- No auto-deployment into a live sensor or tenant in the initial phases.
- No direct production changes and no SaaS transfer of customer logs by default.
- No unverified AI-generated parser deployment.

## 7. Unresolved evidence—not blockers for spec work

Source-backed samples, the fixed Stellar 7.0 field catalog and pinned native runtime contracts are maintained in the current product repository. The exact candidate's real DP import, listener and indexing behavior remains separately unverified until independently exercised under the applicable approval. Do not infer that evidence from synthetic or browser tests.
