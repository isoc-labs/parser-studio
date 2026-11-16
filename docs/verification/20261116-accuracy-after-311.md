# Accuracy after #311: wrong and lost automatic mappings, blocked logs (2026-11-16)

Scope: the automatic journey of the Auto Parser (Add Logs, Review Fields, Map Fields, Create Parser) on vendor
logs, after PR #311. Priority: parsing accuracy and the accuracy of the Stellar Cyber 7.0 field mapping. Throughput
is not part of this work.

No grammar, template or generated Ruby is changed here. The approved template hashes are untouched. Two repairs
that need a template change are prepared separately and wait for the approval of new hashes (see "Not fixed here").

## Method

- **Holdout logs.** 24 samples written from vendor log grammars that no earlier test or corpus used
  (`tests/fixtures/vendor-holdout-20261116`). Values are invented; the shapes are the vendors'. Each sample has a
  semantic oracle written from the vendor grammar, never from a parser run: per event the Stellar meaning
  (`canon`), source values that must survive (`values`) and Stellar fields that would be a wrong mapping
  (`forbid`).
- **Two executions.** The browser draft and preview in vitest (`src/guided/vendorHoldout20261116.test.ts`), and
  the real journey in Chromium with the downloaded Ruby run under Ruby 2.4.9. The second also checks that every
  emitted value is text of its own source line and of no other line.
- **Verdict per expected meaning.** CORRECT: the Stellar field holds the value. KEPT: no Stellar field, the value
  is a whole field of the output. EMBEDDED: the value is only part of a larger field. WRONG: the Stellar field
  holds another value. LOST: the value is nowhere in the output. WRONG and LOST are defects; KEPT and EMBEDDED are
  an incomplete normalization, not an error.
- The 68 samples of the earlier corpora were run again for regressions.

## Defects found and fixed

| # | Defect | Root cause | Before | After |
|---|---|---|---|---|
| 1 | F5 ASM CEF behind an RFC 3164 header needed "Apply 6 recommended matches" (main before #311 applied them) | The automatic Generic Structural draft discovered its source paths with the earlier reading (`generic.kv.*`); its preview and the generated parser use the dedicated CEF/LEEF grammar (`body.*`, `syslog.*`, owner policy D-2) | 37 of 38 automatic mappings read nothing; canonical 0 of 8 | canonical 8 of 8 without a click; no mapping reads an absent field |
| 2 | A field that is empty in one event was dropped for every event | `prepareAutoParserDraft` kept a field only when no event carried it empty | Sophos Firewall sample: `user_name`, the NAT address and the outgoing interface of the allowed connection were not in the output (these formats keep no other copy of the source) | every value of every event is in the output |
| 3 | A vendor field mapped to a Stellar field of another meaning when the record was read inside a container | The vendor-meaning guards looked for their evidence at the root of the event only | FortiGate wire form (`<PRI>date=... logid=...`): the requested web host mapped to `hostname`, `direction` to `direction`. Suricata alert inside RFC 5424: the 1-4 alert priority mapped to `severity` | the guards answer the same for every reading of one record |
| 4 | Imperva Cloud WAF: `srcport` held the server port | CEF names `spt` the source port; Imperva writes the client port as `cpt` and uses `spt` for the server port | `srcip` 203.0.113.77 with `srcport` 443 | `spt` beside `cpt` stays a vendor field |
| 5 | F5 ASM key-value record blocked on Add Logs ("kv token unrecognized") | The Python source preview asked for a blank after the RFC 3164 tag; the browser grammar, which builds the parser, does not. The step needs both to agree | no parser for `... ASM:unit_hostname="...",...` | parser downloaded; all fields read |
| 6 | No reason shown for a JSON number the grammar declines | The step reported "parser rule needs review" and pointed to ChatGPT, which cannot repair it | - | the number is named; nothing is said to be repairable by a rule |
| 7 | What a reading says about itself was written to the output as if the vendor had sent it | The automatic Generic Structural draft mapped every discovered path, also `syslog.variant`, `syslog.confidence` and `generic.profile` | F5 line: the vendor namespace held `variant:"rfc3164"`, `confidence:"strict"`; PAN-OS TRAFFIC sample: 97 automatic mappings | these three are not mapped (PAN-OS: 94). `syslog.facility` and `syslog.severity` stay: they are the PRI of the line, decoded |

Defects 2, 3, 4 and 7 were on main before #311 as well. Defect 1 came with #311.

## The 26 samples that had no download on the preview of 949c474

"Wire form" is what a sensor receives: one event per line or datagram, with the Syslog header the device sends.

| Sample | What it is | Stops at | Verdict |
|---|---|---|---|
| `r2_f5_asm_kv` | F5 ASM key-value, vendor documentation | source preview (Python) | **Unjustly blocked. Fixed (defect 5).** Now downloaded, golden values 5 of 5 |
| `cisco_asa_106023` | Cisco ASA 106023, vendor text | parsing of the message body | Header recognised; the body is free text that differs per message id. Needs a parsing rule: ChatGPT Assisted Parser. Declined with that reason, by design |
| `r2_bsd_tagged_classic` | three lines of three shapes, one is sshd free text | parsing of one line | 2 of 3 lines read; the free-text line needs a rule. Assisted |
| `juniper_srx_rtflow` | SRX structured data as printed in the vendor documentation, without `<PRI>1` | header | Not the wire form. The wire form is read: `juniper_srx_rtflow_pri`, holdout `h_srx_sd_close_deny` (13 of 13 canonical) |
| `panos_traffic_csv` | 38 columns without a Syslog header, synthetic ("not vendor original") | field names | Not the wire form. Real PAN-OS TRAFFIC is read: `gp_panos_syslog_125col`, holdout `h_panos_traffic` (12 of 12). The step asks for column names |
| `windows_4624_xml` | a Windows event rendered as XML over 48 lines | format | XML is not an input format; the step says so. The JSON export is read: `r2_windows_4624_json` |
| `w3c_iis` | W3C extended log file with `#Fields:` | compiler | The names are in a directive line that is not part of an event. There is no positional space-separated format with declared names. Assisted |
| `aws_cloudtrail_records` | a CloudTrail file object `{"Records":[...]}` printed over many lines | framing | Not the wire form. One record per line is read: holdout `h_cloudtrail_line` (2 of 2, 0 wrong) |
| `json_multiline_pretty` | pretty-printed JSON objects | framing | Document form of one-line JSON, which is read |
| `suricata_eve_alert_multiline` | pretty-printed EVE JSON from the documentation | framing | The one-line form is read: `suricata_eve_alert_oneline` |
| `csv_quoted_unicode` | CSV file with a header row | field names | The header row is not sent with each event; the step asks to confirm the names |
| `linux_audit` | auditd records | framing | Records are grouped by audit id and carry a nested `msg='...'`; no compiler container for it. Assisted |
| `gk_json_numbers` | JSON with the integer 9007199254740993 | parsing (owner policy) | A number that cannot be kept exactly declines the event. The reason is now shown (defect 6). See "Not fixed" |
| `gk_multi_mixed_kv` | a key repeated inside one event | owner policy D-1 | Every value is shown; no automatic files |
| `gd2_cef_v1_claim` | `CEF:1` | grammar contract | Only `CEF:0` is in the contract; declined with that reason. See "Not fixed" |
| `gk_leef_caret_mixed` | LEEF 2.0 with `^`; one event ends with the delimiter | grammar contract | An empty attribute declines the event. See "Not fixed" |
| `gd2_leef_empty_attr` | LEEF 2.0 whose attributes start with the delimiter | grammar contract | Not conformant; declined |
| `r2_cef_leef_escaped_envelopes` | LEEF value with an escaped custom delimiter `\^` | grammar contract | LEEF defines no such escape; declined |
| `r2_elastic_cef_envelopes` | a blank between `<PRI>` and the timestamp | header | Not RFC 3164; declined with that reason |
| `gc_f2_rfc5424_v2`, `r2_rfc5424_versions`, `r2_rfc5424_version0_neg` | RFC 5424 with VERSION 2, 12, 0 | header | RFC 5424 defines VERSION 1; declined with that reason |
| `gi_control_sep_kv` | a value that starts with U+001C | parsing | Abnormal input; declined |
| `neg_garbage`, `neg_truncated_json`, `neg_partial_kv_junk` | negative controls | - | Declined, as expected |

One of the 26 was a normal, supported vendor record that was blocked without cause; it is fixed. None of the other
25 is shown as a success, and each states what is missing.

## Holdout logs: results

Real Chromium journey and the downloaded parser under Ruby 2.4.9. "main" is the Development Preview of 949c474; "this change" is the same journey against this tree. "kept" counts expected Stellar meanings that are in the output under a vendor name (whole or inside a larger value); "declined" means the Add Logs step stopped with a diagnosis and offered no download.

| Sample | Vendor record | main 949c474 | this change |
|---|---|---|---|
| `h_checkpoint_logexporter` | Check Point Log Exporter (syslog format) | 6 correct, 4 kept | 6 correct, 4 kept |
| `h_cisco_asa_mixed` | Cisco ASA | declined | declined |
| `h_cisco_ftd_430003` | Cisco Firepower Threat Defense | declined | declined |
| `h_cloudflare_http` | Cloudflare HTTP requests (Logpush) | declined | declined |
| `h_cloudtrail_line` | AWS CloudTrail (one record per line, as delivered by CloudWatch Logs or Kinesis) | 2 correct | 2 correct |
| `h_fortigate_mixed` | Fortinet FortiGate 7.x | 6 correct, 9 kept | 6 correct, 9 kept |
| `h_fortigate_webfilter` | Fortinet FortiGate 7.x | 12 correct - **4 forbidden mapping** | 12 correct |
| `h_imperva_cef` | Imperva Cloud WAF (Incapsula) | 1 correct - **1 forbidden mapping** | 1 correct |
| `h_meraki_urls_flows` | Cisco Meraki MX | declined | declined |
| `h_nginx_combined` | NGINX access log (combined) | declined | declined |
| `h_okta_system_log` | Okta System Log | 1 correct | 1 correct |
| `h_panos_threat_url` | Palo Alto Networks PAN-OS 10.x | 1 correct, 4 kept | 1 correct, 4 kept |
| `h_panos_traffic` | Palo Alto Networks PAN-OS | 12 correct | 12 correct |
| `h_pfsense_filterlog` | pfSense filterlog | declined | declined |
| `h_sonicwall_fw` | SonicWall SonicOS | 0 correct, 10 kept | 0 correct, 10 kept |
| `h_sophos_xg_fw` | Sophos Firewall (SFOS) | 8 correct - **2 LOST** | 8 correct, 1 kept |
| `h_srx_sd_close_deny` | Juniper SRX (structured-data syslog) | 13 correct | 13 correct |
| `h_sshd_auth` | OpenSSH sshd via rsyslog | declined | declined |
| `h_stormshield_filter` | Stormshield SNS | 6 correct, 5 kept | 6 correct, 5 kept |
| `h_suricata_rfc5424` | Suricata EVE alert sent through syslog | 10 correct - **2 forbidden mapping** | 10 correct |
| `h_trendmicro_ds_leef` | Trend Micro Deep Security | declined | declined |
| `h_vpcflow_v2` | AWS VPC Flow Logs (version 2, default format) | declined | declined |
| `h_win4625_nxlog_json` | Windows Security 4625 forwarded by NXLog (JSON) | declined | declined |
| `h_zeek_conn_json` | Zeek conn.log (JSON writer) | declined | declined |

Over the 13 samples with a download (24 samples, 46 events in all):

| | main 949c474 | this change |
|---|---|---|
| Stellar meaning correct | 78 | 78 |
| kept under a vendor name | 32 | 33 |
| mapped to a wrong Stellar field (forbidden by the oracle) | 7 | 0 |
| wrong value in a Stellar field | 0 | 0 |
| lost (meaning or source value not in the output) | 2 | 0 |
| value that is not text of its own event | 0 | 0 |

The eleven declined samples are five free-text shapes, which need a parsing rule by design, and the six vendor
records of the next section.

## Not fixed here: what needs a grammar or template change

Each needs a change of the grammar or of the Ruby operators, and therefore of the approved template hashes. The
first seven are vendor records the automatic journey does not read; they are pinned as `declined` in the holdout
test so that a later change shows up. The last three are readings that main has as well and that this change does
not touch.

| Record | Why it is declined | Size of the fix |
|---|---|---|
| Zeek JSON (`"ts":1731719701.123456`) and any JSON number of 16 or 17 digits printed from a double | `hasUnsafeJsonNumbers` counts digits (more than 15 declines) | small; prepared as a separate change that needs new template hashes |
| JSON integers above 2^53 (NXLog `Keywords`, Cloudflare nanosecond times) | a browser number cannot hold them; owner policy: decline, never round | needs an exact integer value through the grammar, the preview and the Ruby |
| LEEF 2.0 without a delimiter field behind a Syslog header (Trend Micro Deep Security) | the grammar contract reads the implicit TAB form only for a bare line | contract change |
| Cisco Meraki `urls` record | space-separated key=value needs five pairs; a `urls` record has four | grammar threshold; risk of reading free text as key=value |
| Cisco FTD 430003 (`Key: value, Key: value`) | no grammar for a colon list | new grammar |
| PAN-OS THREAT | read as positional columns (`column_7`...); only TRAFFIC has column names | column table for THREAT |
| `CEF:1`, a trailing LEEF delimiter | grammar contract | contract change |
| A mapped value that is only white space (`user=" "`) | the run time skips the exact strings `""`, `N/A`, `-`; a blank-only value reaches the conversion, which rejects it, and the event takes the field-error path (source text kept, `parser_err_msg` set). Before defect 2 was fixed the sample hid this by dropping the field for every event; a parser built from a sample without the blank fails the same way on main | small: a blank-only value is a missing value in the browser and in the Ruby operators (template change) |
| Comma-separated pairs behind `TAG: ` with words before the first name, or with an apostrophe in an unquoted value (`myapp: Login failed user=bob,src=...`; `user=o'brien,...,dept=o'neil`) | the comma-record grammar takes the words into the first name and reads an apostrophe as an opening quote; the browser grades the first PARTIAL and still adopts the draft. The values stay in `message_raw` and `parserstudio_source`; no Stellar field is wrong. On main as well | grammar change: a name is one word; a quote opens a value only at its start |
| RFC 3164 tag directly followed by space-separated pairs (`kernel:IN=eth0 OUT=eth1 ...`) | the browser grammar glues the tag and the first pair into one positional token (`prefix_005:"kernel:IN=eth0"`, no `IN`); the Python preview reads `IN`. On main as well | grammar change (`priSpaceKv`) |

## Mapping left to the user on purpose

- A field that is present in only some events of a mixed sample is offered as "Check first", not applied: FortiGate
  traffic, web-filter and event records in one sample leave `srcport`, `dstport`, `url` unmapped. The value is in
  the output under its vendor name.
- `user`, `user_name`, `usr` are advisory aliases of `username` (semantic policy): kept, not mapped.
- Composite values are kept whole: SonicWall `src=10.1.10.25:51544:X0`, Meraki `src=ip:port`.
- A port beside a non-transport protocol name is not mapped (Stormshield `proto=https`).

## Independent audit

An independent auditor read and ran the first version of this change (8803471) and failed it: 1 P1, 7 P2, 6 P3.

| Finding | Disposition |
|---|---|
| P1-1 The Python preview no longer refused a tag without a blank; the later fallbacks re-read the line from the PRI and 189 of 4,789 adversarial lines went from partial to parsed, the first pair glued into a positional token | Fixed. The guard is back; one narrow route reads the tag directly followed by a complete comma-separated record of `name="value"` pairs that repeats no name (narrowed once more after the second audit, below). Over the auditor's 7,238 lines 12 verdicts change, all of them that F5 record |
| P2-1 Malformed or unsupported CEF/LEEF behind an adjacent tag came back as parsed | Fixed by the same change: CEF and LEEF are never taken through the adjacent route |
| P2-2 A repeated name in the F5 form was adopted automatically (owner policy D-1) | Fixed: a repeated name keeps its earlier verdict |
| P2-3 For the F5 key-value form `hostname` is taken from the Syslog header although `unit_hostname` is in the record | Not changed. The header host is the sender named by the transport; `unit_hostname` stays in the output under its own name. The rule that an applied target is not offered again is older than this change and PAN-OS depends on it (removing it loses `syslog.hostname -> hostname` there). Listed as a review item for the candidate logic |
| P2-4 A value that is only white space now makes its event take the field-error path | Not changed here; see "Not fixed". The earlier behaviour dropped the field for every event of the sample, which lost values. The repair is in the run-time operators and needs new template hashes |
| P2-5 Descriptors of the reading were written as vendor fields | Fixed for `syslog.variant`, `syslog.confidence`, `generic.profile` (defect 7). `syslog.facility`/`syslog.severity` are the decoded PRI and stay; `message_raw` is a copy of source text and stays |
| P2-6 The "loses nothing" half of the holdout test could not fail for Generic Structural drafts | Fixed: the copies of the whole source text are ignored, every automatic mapping must read a field some event has, and the number of correct Stellar meanings is pinned per sample |
| P2-7 No test held the text of the Add Logs panel | Fixed: component test |
| P3-1 Vendor evidence was combined across container levels | Fixed: all evidence must be in one container |
| P3-2 Imperva rule keyed on `cpt` anywhere | Partly: `cpt` must be beside `spt`. A record without `cpt` is not recognised |
| P3-3 Only the FortiGate rule is shared with the review of ChatGPT proposals | Not changed; proposals for Imperva `spt` and Suricata `alert.severity` come back as "Check first", not applied |
| P3-4 Wording of the number explanation; object behind structured data not found | Fixed |
| P3-5 Fixture epochs (2024) do not match the text dates (2026) | Not changed; nothing asserts the pair. The fixtures are frozen with the measurements of this document |
| P3-6 Two new tests were red on the old code for a missing function, not for the behaviour | Not changed; the behaviour is held by the other tests of the same files |

A second independent auditor re-ran every finding against 86415a6 and attacked the fixes (2,348 crafted lines and
1,500 random records for the adjacent tag, 55 crafted vendor records, 31 mutations of the fixed code): FAIL again,
0 P1, 2 P2, 6 P3. The earlier P1-1, P2-1, P2-2, P2-7 and P3-1 were confirmed fixed, the three descriptors of P2-5
confirmed gone, and the dispositions of the unchanged items accepted on their merits. For P2-4 the auditor ran a
parser built by main under Ruby 2.4.9: it writes `MappedFieldError` for `user=" "` as well, with every other field
kept. P2-3 was regraded P3: the Syslog header host is one of two defensible sources, not a wrong mapping.

| Finding of the second audit | Disposition |
|---|---|
| N1 (P2) The adjacent route also took words before the first name: `myapp:Login failed user=bob,src=...` came back as parsed with a field named "Login failed user" | Fixed. The route now takes only a message that is, from the colon to the end, two or more `name="value"` pairs joined by a comma and nothing but blanks after it (the F5 documentation prints `", `): every name one plain word, every value in double quotes |
| N2 (P2) Two apostrophes in unquoted values swallowed the pairs between them into one value | Fixed by the same rule: a value outside double quotes is not this form |
| N3 (P3) Names that are not a safe path (`bytes(in)`) were read and not mapped | No longer reached through this route (plain names only) |
| N4 (P3) In the F5 record `severity="Informational"` is written under a path-qualified vendor name because the decoded PRI severity keeps the short name | Not changed; both values are right. Follows from keeping `syslog.severity` |
| N5 (P3) Four mutations survived | A test now holds the shared FortiGate rule in the review of ChatGPT proposals (red with the old copy). The `+COMMA_KV` and status checks stand behind the new rule as a second line. Removing vendor-only mappings is caught by 17 other tests |
| N6 (P3) This document did not exist | It does now |

Both readings mis-segment the same two inputs when a blank follows the tag (`myapp: Login failed user=bob,...`), on
main as well: see "Not fixed".

Over the 9,306 lines of both audits, the Python preview of this tree differs from main for 270: each is a record of
double-quoted pairs behind an adjacent tag, went from partial to parsed, and its fields are exactly the pairs
written.

## Verification

Chromium journeys: code of 86415a6. The later commits change one Playwright expectation, the Python preview
rule for the adjacent tag (second audit; the journeys of the F5 samples were run again on it) and tests.

**Real Chromium journey, downloaded Ruby under Ruby 2.4.9** (92 samples, local stack of this tree):

| | main 949c474 (Development Preview) | this change |
|---|---|---|
| 24 holdout samples: downloaded | 13 | 13 |
| - Stellar meaning correct | 78 | 78 |
| - kept under a vendor name (whole 25, inside a larger value 8) | 32 | 33 |
| - mapped to a Stellar field the oracle forbids | 7 | 0 |
| - lost | 2 | 0 |
| 68 samples of the earlier corpora: downloaded | 42 | 43 (`r2_f5_asm_kv`) |
| - golden Stellar fields | 129 of 182 | 137 of 182 (`r2_f5_asm_cef` 0 of 8 to 8 of 8) |
| - golden source values in the output | 171 of 174, the other 3 inside a larger value | 176 of 179, the same 3 inside a larger value |
| - events / error records | 98 / 0 | 99 / 0 |
| - emitted values that are not text of their own line | 0 of 2,320 | 0 of 2,425 |
| - value of another event | 0 | 0 |
| - Stellar field whose source name does not carry the value | 0 of 760 | 0 of 819 |

Among the 42 samples that both trees download, the only differences are `r2_f5_asm_cef` (8 of 8) and the three
descriptors that are no longer written for Generic Structural samples.

**Gates run locally on this tree**: TypeScript build; vitest 235 files, 1,998 tests; Python suite 184 tests;
grammar and generated-Ruby generators `--verify` (no generated file changes); duplication ratchet 45 of 45;
candidate mutation gate 92.44% with the 8 reviewed equivalents; Python preview over the 9,306 lines of both audits:
270 verdicts change, all the record of double-quoted pairs. On c6ae049 (before the audit fixes, which touch no grammar):
translation conformance 19 of 19, semantic oracle (browser, native Ruby 2.4.9, Python), browser/Ruby
differential 44,858 cases with 0 differences, backend 771 of 775 (4 need Drain3 or a Ruby runner the host lacks).

**CI**: the ten checks of the pull request (web-quality, six browser shards, native-isolated-synthetic,
ruby24-fluentd-udp-reception, release-eligibility) pass on 6b3a20d; the result for the merged head is on #313.

**Not verified**: a real Stellar Cyber 7.0 sensor, loader, import or indexing; production.
