# Phase 3 P3: the ChatGPT Assisted parsing prompt (2026-11-23)

Scope: the prompt Parser Studio prepares for ChatGPT when the automatic parser cannot read a sample, or reads it
only in part. No LLM API is called; the user copies the prompt and pastes the reply back.

## What the prompt carries

| Required content | Where it comes from | State |
|---|---|---|
| Vendor, product, version | user-declared source hints (`reviewedSourcePromptContext`), marked unverified | existing |
| Original log samples | the exact source block between SHA-scoped markers | existing |
| Event types | observed event-type diversity (`buildEventCoverageEvidence`) | existing |
| Existing automatic result | validated baseline recipe when one exists | existing |
| Fields already extracted | source field paths of the local preview | existing |
| Automatic verdict per record, keys not read, problem codes | new block "Automatic parse result per original record" | **added** |
| Unparsed or uncertain parts | the records that are not FULL in that block, with the keys the loss guard did not find | **added** |
| Multiple event types to support | "Cover EVERY distinct observed kind" | existing |
| Parsing success criteria | new block "Parsing success criteria" | **added** |
| Recipe output contract | ParserRecipe v0.2, REVIEW_ONLY, exact identity | existing |

The new blocks hold names and codes only (verdict, reading format, number of extracted fields, key names, problem
codes); no field value of the log leaves the source block. Test: `src/guided/chatGptParsePromptResult20261123.test.ts`
(seen failing before the change).

## Not established here

How a returned recipe is judged (missing fields, changed values, false FULL, several event types, original-text
preservation, Ruby 2.4.9) is the existing review path (`autoParserRegression.compareCandidate`, baseline and holdout
comparison, loss guard in the preview); an end-to-end check with a deliberately wrong reply is open work.
