# Phase 3 P5: additional vendor end-to-end set (2026-11-23)

Eight cases were added to the existing corpus (FortiGate, PAN-OS, Cisco ASA, Juniper SRX, Check Point,
WatchGuard, F5 BIG-IP ASM, Trend Micro, Trellix, Suricata, Linux, ModSecurity WAF, Snort, SonicWall and
the Phase 3 structural set). Every new line is SYNTHETIC, written after the vendor's documented log format;
none is a vendor-provided or customer sample. Each case ran as a real Chromium Auto Parser journey at
e1af64d; when files were produced, the downloaded Ruby parser ran on Ruby 2.4.9 and was compared with the
original lines (events, error records, original values, values in the wrong line).

| Case | Format / event types | Auto Parser result | Ruby 2.4.9 |
|---|---|---|---|
| Windows Security (winlogbeat-style JSON) | JSON; 4624, 4625, 4688 | FULL, files created | 3 in / 3 out, 0 errors, 29 values, 0 mixing |
| Okta System Log | JSON; session start, MFA failure | FULL, files created | 2 / 2, 0 errors, 23 values, 0 mixing |
| PAN-OS TRAFFIC + SYSTEM | Syslog CSV; 2 event profiles | FULL, routed per type | 2 / 2, 0 errors, 183 values, 0 mixing |
| FortiGate traffic + UTM webfilter + VPN event | KV; 3 types | FULL, files created | 3 / 3, 0 errors, 53 values, 0 mixing |
| Cisco ASA AnyConnect 722051 / 113019 / 302013 | Syslog free-text bodies | PARTIAL detected: "asa message body unparsed" | not generated |
| Linux auditd SYSCALL / USER_LOGIN / USER_AUTH | KV with nested msg='...' | PARTIAL detected | not generated |
| BIND query log | free text | PARTIAL detected | not generated |
| Squid native access log | whitespace columns | PARTIAL detected | not generated |

The four PARTIAL cases are detected failures, not false FULL: the screen marks the unread part of each
event and the Create Parser step stays disabled; the next step offered is ChatGPT Assisted. They show a
product gap: these free-text grammars are not built in, and Regex parsers cannot be exported for the Ruby
2.4.9 target. Adding them is a grammar (template) change that needs owner template approval.

Mapping precision/recall for the new cases is NOT MEASURED: they have no reviewed golden mapping yet.
No real ChatGPT answer was used; no AI success rate is implied.
NOT VERIFIED: Stellar Cyber DP install, reception and indexing (owner test).
