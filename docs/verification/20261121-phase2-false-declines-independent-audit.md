# Phase 2: false declines, independent audit and its fixes (2026-11-21)

Continues `20261121-takeover-prototype-keys-mapping-recall.md`. Branch `experiment/codex-accuracy-lab-20261117`,
PR #316. No merge, no deployment, no change of an approval constant; the template-set digest is still
`400e046311f5aeeb18352a4a80483e040baae3871294af39d108e3f475c2cf44` (no template changed in Phase 2).

The measurements of the head that contains this document are in the PR comment and the hand-over note, so that
the browser and Ruby 2.4.9 runs are made on the same commit as the code.

## 1. False declines fixed

| Sample | Cause | Fix |
|---|---|---|
| PAN-OS TRAFFIC stored by a Syslog server without its PRI | the bounded Generic Structural compiler was asked only when the first scan reported unsupported events; this line reads as positional CSV without column names, so the user was sent to the CSV column review although the compiler names the columns (`panos_traffic_csv`) and the same line with a PRI was adopted | `AutoParser.tsx` asks the compiler for a headerless positional reading too; `buildSourceReviewedNamedPositionalDraft` adopts only a reading that names the columns from a verified record layout, for every event |
| Juniper SRX `RT_FLOW_SESSION_CLOSE` with NAT and application fields | the Python preview called structured data above 1024 bytes PARTIAL (`RFC5424_SD_BYTE_LIMIT`); the browser's Junos reader accepts 8192 bytes; one PARTIAL witness stopped the automatic journey for the whole sample | the preview uses the browser's 8192 bytes |

## 2. Independent audit

Run by a separate agent that had not seen the work, on `ee1cd73..39987c2`, with its own probes on both trees
(`dev-atlas:/home/aella/.local/state/ps-audit-20261121/REPORT.md`). It did not run a browser or Ruby.
Its verdict on `39987c2` was "do not merge as it is". Findings and what was done:

| ID | Finding at `39987c2` | Disposition |
|---|---|---|
| F1 (P1) | a headerless CSV whose first cell starts like a BSD timestamp was auto-adopted as Syslog + positional CSV: the host took the following cells, every column shifted, status FULL | fixed: the headerless route adopts `panos_traffic_csv` only; other readings keep the CSV column review. Regression: `headerlessCsvBoundedCompilerGate20261121.test.ts` |
| F2 (P1) | a headerless CSV with key=value pairs in one cell was auto-adopted as space key=value: the last value took the following cells (official `url` = `/index.html,10.0.0.9,8443,ok`) | fixed by the same rule; same test file |
| F3 (P1) | a sparse `srcport`/`dstport` was approved beside an ICMP record that names its protocol `ipproto`, keeps it in another container, or omits it | fixed: a sparse port needs TCP or UDP named by the record in every event that has the port; the protocol names read are now `protocol-id`, `protocol_id`, `protocol`, `proto`, `proto_name`, `protocol_name`, `ipproto`, `ip_proto`, `l4proto` (not `transport`: FortiGate writes the translated port there) |
| F4 (P1) | Zeek `id.orig_p`/`id.resp_p` of a log without `proto` (weird.log: ICMP type and code) were mapped to ports | fixed: these two aliases are ports only beside a TCP or UDP protocol, whatever the coverage |
| F5 (P2) | a sparse endpoint inside a nested object (`xlate.srcip`, `nat.srcip`, `outer.srcip`) became the official endpoint | fixed: sparse approval only for a record-level source (root, or a reader's own container `generic.kv`, `generic.fields`, `body`, `junos_sd`), and never under a translated segment |
| F6 (P2) | a sparse field called `url` was approved whatever its value | fixed: every value must be URL-shaped (scheme or leading `/`) |
| F9 (P3) | explicit port labels were sparse-approved too | fixed: explicit labels keep the full-coverage rule |
| F8 (P3) | the 65536-byte bound of `39987c2` was dead code, raised the worst case of the preview, and the stated reason was wrong for the browser | fixed: 8192 bytes, the browser's bound |
| F7 (P3) | a PAN-OS TRAFFIC record with exactly 53 columns is named from a second table (older than this branch, shared by TypeScript and Python) | open: changing it changes the Ruby template; needs the vendor's column list for that release |
| F11 | no unit test for the gate; no must-not-map cases | added: the cases of F1-F6 and F9 in vitest, in the independent candidate oracle and as mutants (18/18 killed; AST census 92.23%, floor 90) |

Verified as correct by the audit: prototype-member keys in every reader (30 probes), TRAFFIC names never applied to
another PAN-OS record type, plain CSV keeps the column review, `proto` name/number rule, the Junos `icmp_type` guard,
value checks of sparse addresses and ports, manual mappings never overridden, both policy copies identical, ts2rb in
sync, the test-expectation changes of Phase 1 restate the new policy and hide no failure.

Seen by the audit outside the diff (same at `ee1cd73`), open:

| Finding | Class |
|---|---|
| Zeek http.log: `host` (the HTTP Host header) is mapped to the official `hostname` | wrong official mapping, P2, older than this branch |
| Native key=value reads `a=1,b=2,src=10.0.0.1` (comma-separated, no spaces) as one pair whose value is the rest of the line, FULL | wrong complete parse, P2, older than this branch |
| A CSV column named `constructor` can be declared, but a mapping from it reports SOURCE_NOT_FOUND | P3 |

## 3. Not done in Phase 2

| Item of the work order | State | Cause |
|---|---|---|
| PAN-OS THREAT / SYSTEM column names | not done | no verified column list in the repository; the audit confirms nothing is guessed (`column_N`) |
| SRX IDP sample | not done | three records carry an RFC 5424 timestamp without an offset and one has no VERSION; both violate RFC 5424, so reading them needs an explicit vendor exception, and one unsupported event still stops the automatic journey |
| One parser for several record families with per-event acceptance (partial success) | not done | the automatic journey requires every event; this is a change of the Auto Parser flow, the mapping scope and the generated parser, not a grammar fix |
| Cisco ASA, Linux syslog, Snort fast (free text) | not done | the Python preview reads 7 of 8 ASA records, the browser grammar does not; a bounded message grammar for free text is a new grammar in TypeScript and therefore in the Ruby template |
| WatchGuard event records | not done | the browser reads them as header + message, the Python preview reports the message as residual; the witness rule does not accept that |
| ModSecurity audit JSON | not done | duplicate JSON keys are declined by the duplicate-key policy; changing it changes a security decision |
