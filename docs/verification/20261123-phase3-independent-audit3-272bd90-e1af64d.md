# Independent audit 3: 272bd90^..e1af64d (2026-11-23)

Run by a separate agent that did not write the code, read-only on the takeover worktree at e1af64d.
Vitest of the 8 new test files: 45/45. Ruby was not available to the auditor (no native run by the audit).

| Id | Severity | Finding | Status |
|---|---|---|---|
| F1 | MAJOR | `familySource` used preview event indexes as physical line numbers; a sample with blank lines put another event type's line into the "selected type only" prompt and review (verified by the auditor). | FIXED: records are taken from the preview events (`suite.events[i].raw`). RED test with blank lines. |
| F2 | MINOR | `security_panos.py` accepted non-ASCII digits (`str.isdigit`): superscript `²` crashed the preview, Arabic-Indic digits named a THREAT record unlike the browser and Ruby grammars. | FIXED: ASCII `[0-9]` only for ports, dates and IPv4. RED test. |
| F3 | MINOR | The shared-mapping refusal had no effective test (routed PAN+CEF has no shared mapping). | FIXED: test with a shared mapping asserts `SHARED_MAPPING_CHANGED`. |
| F4 | MINOR | An unchanged result was reported as "Applied"; fields outside extraction, enrichment, classification and mappings are taken from the current parser; the merged draft is checked by the multi-type generation step, not re-previewed at apply time. | Unchanged result now refused (`NO_FAMILY_CHANGE`, RED test). The rest is by design (identity is edited on the parser itself) and documented. |
| F5 | MINOR | The JSONata prompt said "no field values" while the event type context carries discriminator values. | FIXED: the sentence names the exception. |
| F6 | NOTE | Routed parsers reject event types absent from the sample (`unknown: reject`): such a record keeps only the raw text. | By design (no guessing); reported as a limit. |
| F7 | NOTE | PAN-OS THREAT 0-59 and SYSTEM 0-25 match the PAN-OS 11.1 field pages; FUTURE_USE positions 0, 5, 21 carry names (same convention as TRAFFIC). | NOT VERIFIED for those names; 10.x not checked separately. |
| F8 | NOTE | `parser_raw_msg` correct and applied last; invalid UTF-8 becomes U+FFFD. | Documented. |
| F9 | NOTE | `KNOWN_TEMPLATES` unchanged; template-set digest 456e3134... -> 09de3c54... needs owner approval. | Approval gate, not a defect. |

G-items (definitions: docs/verification/20261122-phase3-independent-audit2-b117e05-88c0768.md):
G-09 RESOLVED (per-type official mappings; F6 caveat). G-06, G-08 (partly), G-10, G-11, G-12, G-13 OPEN:
no commit in this range touches their code; they are grammar changes that need template approval.
