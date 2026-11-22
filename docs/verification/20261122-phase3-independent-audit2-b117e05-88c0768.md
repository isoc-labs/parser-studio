# Phase 3 independent audit 2: b117e05 .. 88c0768 (HEAD 88c0768)

Auditor: independent, nothing fixed, worktree not touched. Date 2026-11-22.
Method: `git archive 88c0768` to `/home/aella/.local/state/ps-audit-20261122/tree` (and 7a255a6 to `tree7a` for old/new differentials), node_modules symlinked. Every result below was executed there unless marked NOT VERIFIED. Three executors on the same inputs: browser grammar (`preview(raw,{...createDraft(),format:'auto'})`, "TS"), Python preview (`multipass_preview_api.preview/preview_batch`, "PY", the real witness) and the generated Ruby (`grammar-runtime.rb.tpl` + `grammar-core.generated.rb.tpl` loaded in Ruby 3.2.3, `psg_read_event`, "RB"; also loaded as US-ASCII source). Adoption was reproduced as `AutoParser.tsx:665-667` with the real PY witness. vitest, Playwright, the Python tests, the mutant script and Ruby 2.4.9 were NOT run.

## 1. Findings

| ID | Sev | Commit | Short | Status |
|----|-----|--------|-------|--------|
| G-01 | P1 | b117e05, 97d7cb4, 88c0768 | First value with "=" swallows the pairs after it, FULL, wrong official `url` | CONFIRMED |
| G-02 | P1 | same | A pair behind a delimiter whose key is not ASCII-identifier (Korean, digit first, @, 97 chars) is invisible: FULL with one field | CONFIRMED |
| G-03 | P1 | 6395341 | F-01 class still adopted: pipe-separated cells, or two header cells behind a PRI | CONFIRMED |
| G-04 | P1 | cde614c | Regression: one event with a method outside nine tokens re-approves the requested host as `hostname` HIGH | CONFIRMED |
| G-05 | P2 | b117e05, 97d7cb4 | Regression: ordinary white-space key=value logs, correctly read, are now PARTIAL / fail | CONFIRMED |
| G-06 | P2 | 88c0768 | A one-pair body whose value holds `;k=v` or `,k=v` is now split into several fields, FULL | CONFIRMED |
| G-07 | P2 | a901a5c | F-03 remains for literal dotted keys inside a container (Syslog body, nested object) | CONFIRMED |
| G-08 | P2 | cde614c, 03415d1 | Genuine device host loses HIGH: log level TRACE, action=DELETE/CONNECT, ECS `host.hostname`, a referer beside | CONFIRMED |
| G-09 | P2 | 6395341 | PAN + CEF / PAN + LEEF still adopted; every official mapping is lost (0, PAN alone has 7) | CONFIRMED |
| G-10 | P2 | 88c0768 | PY: pair limit and repeated-key policy do not hold for a list (101 pairs SOURCE_PARSED; repeated key SOURCE_PARSED) while TS/RB decline | CONFIRMED |
| G-11 | P2 | b117e05 | Delimiter set is fixed to `, ; |`: `a=1&b=2&c=3` FULL with one field | CONFIRMED |
| G-12 | P3 | 88c0768 | TS/RB PARTIAL vs PY SOURCE_PARSED for a quoted list value ending in a backslash; same quoted token decoded differently by separator | CONFIRMED |
| G-13 | P3 | a901a5c | Protocol object with a non-protocol member blocks TCP ports; `protocol.name`, `flow.l4.proto`, `ip_protocol` not seen | CONFIRMED |

### G-01 (P1) a value with "=" before the first delimiter hides every following pair
- Where: `src/grammar/parseStatus.ts:117-125` (`if (ch === '=') return end;`), `runtime/multipass/source_kv.py:52-54`, list grammar `KV_LIST_BARE` excludes "=" (`src/grammar/kvBody.ts:54-74`), so the body falls back to the white-space grammar and the guard gives up at the first "=".
- Inputs, all FULL in TS and RB, SOURCE_PARSED in PY, ONE field:
  - `url=/login?user=bob,src=10.0.0.1,dst=10.0.0.2,action=allow` -> `url="/login?user=bob,src=10.0.0.1,dst=10.0.0.2,action=allow"`, candidate `url->url HIGH` (wrong value in an official field)
  - `token=YWJjZA==,user=bob,src=10.0.0.1,action=allow` (base64 padding)
  - `user=bob token=YWJj==,src=10.0.0.1 action=allow` -> `token="YWJj==,src=10.0.0.1"`, FULL
  - `<134>Nov 21 10:00:01 fw1 app: url=/login?user=bob,src=10.0.0.1,dst=10.0.0.2` and RFC 5424 `... ID47 - token=YWJj==,src=10.0.0.1,dst=10.0.0.2` -> FULL, one body field
- Expected: PARTIAL, as for the same pairs in another order (`src=10.0.0.1,url=/login?user=bob,dst=10.0.0.2,action=allow` is PARTIAL in all three).
- Side effect (executed): `Oct 15 00:14:27 bigip-waf01 ASM: uri=/api/login?next=/home,ip_client=203.0.113.210,method=POST,dest_port=443` - the compiler's correct four-field `delimited_kv` reading is graded PARTIAL by the same rule; with the query string in the middle the PY witness is PARTIAL and the BIG-IP sample is not adopted.
- Same result at 7a255a6: not a regression; Step A/B do not close it. The tests pin the one-value case only (`delimitedPairGuard.test.ts:33-40`).

### G-02 (P1) a pair whose key is outside `[A-Za-z_][A-Za-z0-9_.-]{0,95}` is not seen behind a delimiter
- Where: `parseStatus.ts:25,106-125` (delimiter not followed by a KV_KEY is skipped, then the foreign key's "=" ends the scan), `source_kv.py:52-58`.
- Inputs, FULL (TS, RB) / SOURCE_PARSED (PY), one field:
  - `src=10.0.0.1,\uC0AC\uC6A9\uC790=bob,dst=10.0.0.2` (Korean key) -> `src="10.0.0.1,\uC0AC\uC6A9\uC790=bob,dst=10.0.0.2"`; also behind `<134>Nov 21 10:00:01 fw1 app: `
  - `user=\uD64D\uAE38\uB3D9;\uBD80\uC11C=\uBCF4\uC548;ip=10.0.0.1` -> one field `user`
  - `src=10.0.0.1,3gpp=x,dst=10.0.0.2`, `src=10.0.0.1,@ts=2026,dst=10.0.0.2`, `a=1,<97 x k>=2,c=3`
- Expected: not FULL. The white-space form `src=10.0.0.1 \uC0AC\uC6A9\uC790=bob dst=10.0.0.2` is UNKNOWN (TS) / PARTIAL (PY).

### G-03 (P1) F-01 is closed only for `,` and `;` and for three or more header cells
- Where: `src/guided/genericStructuralAutoDraft.ts:235-236` (`holdsCells`: `,` `;`, >=3 parts), `:190-194` (the first scan knows CSV only for `, ; TAB`).
- Inputs (real witness SOURCE_PARSED, ADOPTED, FULL, mode `space_kv`):
  - `2026-11-21 10:00:00|web01|request user="bob" src=10.0.0.5 method=GET status=200 url=/index.html|10.0.0.9|8443|ok` -> `prefix_002="10:00:00|web01|request"`, official `url=/index.html|10.0.0.9|8443|ok`; same with `<14>` in front and as a two-line sample
  - `<14>2026-11-21 10:00:00,web01 user=bob src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok` -> `prefix_002="10:00:00,web01"`, official `url=/index.html,10.0.0.9,8443,ok`
- Expected: not adopted, as the four reported F-01 inputs now are. Same at 7a255a6 (not a regression; the class is not closed).

### G-04 (P1, regression) one unknown method re-approves the requested host
- Where: `src/guided/normalizationCandidates.ts:197-208` (nine upper-case tokens, request line needs `HTTP/x`), `:253` (`carriers.every`).
- Input (2 JSON lines): `{"ts":1763719200.1,"host":"example.com","method":"GET","uri":"/a","status_code":200}` + `{"ts":1763719201.1,"host":"dav.example.com","method":"PROPFIND","uri":"/dav","status_code":207}` -> `host->hostname HIGH`. Same with second line `"method":"-","uri":"-","status_code":400`. At 7a255a6 both samples gave NO hostname candidate.
- Still HIGH (same as before): `"verb":"get"` (lower case), `"request":"GET /cart"` (no version), `"request":"GET /a b HTTP/1.1"`, kv `host=shop.example.com request_uri=/cart status=200`, Zeek record without method (F-05 case 6), URL in another object (`"req":{"url":"https://example.com/a"}`).
- Expected: REVIEW at most.

### G-05 (P2, regression) correct white-space key=value events are now PARTIAL
- Where: `parseStatus.ts:117-125`, `source_kv.py:47-63,129-130`.
- Inputs, FULL at 7a255a6 with the same (correct) fields, now PARTIAL / status fail in TS, RB and PY (`KV_DELIMITED_PAIR_UNREAD`):
  - `src=10.0.0.1 content_type=text/html;charset=utf-8 status=200` (also behind RFC 3164 and RFC 5424 headers)
  - `src=10.0.0.1 url=/app/login;jsessionid=AB12 status=200`
  - `dev=sda1 opts=rw,uid=1000,gid=1000 action=mount`
  - `user=bob accept=text/html,application/xhtml+xml;q=0.9 status=200`, `method=POST ct=multipart/form-data;boundary=xyz len=512`, `src=10.0.0.1 ua=Mozilla/5.0;rv=109.0 status=200`
- Not affected: `cookie=theme=dark;lang=ko` (has "=" first, see G-01), quoted values, CEF and LEEF extensions, JSON.
- Expected: a decision that does not fail ordinary MIME / URL / option values; at least not `status=fail`.

### G-06 (P2) one value is now several fields, FULL
- `content_type=text/html;charset=utf-8` -> `content_type=text/html`, `charset=utf-8`; `opts=rw,uid=1000,gid=1000` -> three fields; `filter=host;port=80` -> two. FULL in TS, RB, PY. At 7a255a6: one field (old tree executed for the third input only). Ambiguous by nature, but reported FULL without review. `kvBody.ts:54-74`.

### G-07 (P2) F-03 inside a container
- Where: `normalizationCandidates.ts:113-127`: for `body.flow.sport` no object `body.flow` exists, the root is scanned, and no root key starts with `body.flow.`.
- Inputs: `<134>Nov 21 10:00:01 fw1 app: flow.src=10.0.0.3 flow.dst=8.8.8.8 flow.sport=8 flow.dport=0 flow.proto=icmp` -> `body.flow.sport->srcport HIGH`, `body.flow.dport->dstport HIGH`. Same for RFC 5424, a JSON body behind the Syslog header, the comma list form, and `{"event":{"flow.src":"10.0.0.3","flow.dst":"8.8.8.8","flow.sport":8,"flow.dport":0,"flow.proto":"icmp"}}`.
- Expected: REVIEW, as the same record at the root now gives.

### G-08 (P2) a genuine device host is refused HIGH (was HIGH at 7a255a6)
- `ts=... level=TRACE host=app01 thread=main msg="cache refreshed"` (x2) -> REVIEW (TRACE is a method token); `host=nas01 user=bob action=DELETE path=/share/a.txt` (x2) -> REVIEW; `host=vpn01 user=bob action=CONNECT src=203.0.113.5` (x2) -> REVIEW.
- `{"ts":"...","hostname":"waf01","action":"block","http_method":"POST","uri":"/login","vhost":"shop.example.com"}` -> `hostname->hostname REVIEW`.
- `{"@timestamp":"...","host":{"name":"web01","hostname":"web01"},"message":"service started"}` -> `host.hostname REVIEW`; `agent.hostname` REVIEW (`:251`, every nested host).
- `{"host":"fw01","src":"10.0.0.5","referer":"https://portal.example.com/","action":"allow"}` -> REVIEW (`:231-236`, any URL-valued sibling).
- Expected: HIGH; the decision depends on which tokens happen to be in the sample.

### G-09 (P2) mixed PAN sample keeps no official mapping
- Input: the `PAN` constant of `headerlessCsvBoundedCompilerGate20261121.test.ts:17` + `CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow` (also + `LEEF:1.0|V|P|1|E|src=10.1.1.1<TAB>dst=10.2.2.2<TAB>act=allow`). ADOPTED, both events FULL, normalized official fields: none for either event. PAN alone: `hostname, srcip, dstip, srcport, dstport, proto_name, action`. `keepsNativeReading` (`genericStructuralAutoDraft.ts:274-292`) compares extraction only. The new test file has no CEF/LEEF case.

### G-10 (P2) Python preview and the list limits
- `k0=v0,...,k100=v100` (101 pairs): TS/RB UNKNOWN (TOO_MANY_PAIRS), PY `SOURCE_PARSED syntax=GENERIC_STRUCTURAL+COMMA_KV`, 101 fields. The space-separated form is PARTIAL `KV_SOURCE_FIELD_LIMIT` in PY.
- 100 pairs + `,k0=x`: TS/RB UNKNOWN, PY `SOURCE_PARSED`, `k0=["v0","x"]`, no `DUPLICATE_SOURCE_FIELD` (owner policy D-1). At 7a255a6 PY gave one field. The commit message says duplicates and the limit "apply to a list as to any body"; that holds for TS/RB and for short lists in PY (`a=1,b=2,a=3` -> PARTIAL) only. `source_kv.py:86,120-121` plus the funnel's choice of the comma_kv frame (selection code not located).

### G-11 (P2) `user=bob&action=login&src=10.0.0.1` -> FULL, one field `user="bob&action=login&src=10.0.0.1"` (TS, RB, PY; also behind RFC 3164). Same class as Issue #315 with another delimiter; `a=1，b=2，c=3` (full-width comma) likewise. `parseStatus.ts:40-42`. Unchanged from 7a255a6.

### G-12 (P3) `path="C:\dir\",user="bob"`: TS/RB read two fields but grade PARTIAL (`parseStatus.ts:94-103` treats `\"` as an escape, the list grammar does not); PY SOURCE_PARSED. `path="C:\\Users\\bob",user="bob"` gives `C:\\Users\\bob`, the white-space form `path="C:\\Users\\bob" user="bob"` gives `C:\Users\bob` (documented, but one token, two values).

### G-13 (P3) `"protocol":{"name":"tcp","number":6,"flags":"SYN"}` beside `sport/dport`: ports REVIEW (HIGH at 7a255a6). ICMP with `"protocol.name":"icmp"`, `"flow.l4.proto":"icmp"` or `"ip_protocol":"icmp"`: ports HIGH. `"protocol":{"name":null}`: HIGH (documented choice).

## 2. F-01 .. F-08 at HEAD

| ID | State | Input used |
|----|-------|-----------|
| F-01 | partly | The four reported inputs (two-line quoted, quoted first word, semicolon, behind PRI): not adopted. Still adopted: G-03 |
| F-02 | partly | PAN + `<134>Nov 21 10:00:01 fw1 system: logdesc=login ...` and PAN + `... traffic: srcip=...`: not adopted. PAN + RFC 5424 kv, PAN + plain kv, PAN + Syslog comma list: not adopted. PAN + CEF / LEEF: adopted, zero official fields (G-09) |
| F-03 | partly | Reported JSON and kv samples, `net.protocol=1`, `Flow.Proto=ICMP`, Zeek `id.orig_p` + `proto`: REVIEW. Inside a Syslog body or nested object: still HIGH (G-07) |
| F-04 | fixed | `"protocol":{"name":"icmp","number":1}`, `"proto":["icmp"]`, `"proto":{"l4":{"name":"icmp"}}`: REVIEW; `{"name":"tcp","number":6}`: HIGH. Side effect G-13 |
| F-05 | partly | Reported cases 1-5 and 7-10: REVIEW. Case 6 still HIGH; new regression G-04 |
| F-06 | partly | Cases 1, 2: REVIEW (was no candidate); 3, 4, 5: HIGH. New refusals G-08 |
| F-07 | partly | `reviewJsonataMapping` host->hostname on the Zeek record: still `CHECK_FIRST` (executed), now consistent with REVIEW; the rule is still not exported. A hostname mutant exists in `mcv2-semantic-candidate-mutants.mjs:99-128` (read, NOT run) |
| F-08 | fixed | Unquoted + quoted BIG-IP lines, both orders, real witness: adopted, `delimited_kv`, FULL, ten fields each; quoted values with `,` and `=` intact; unquoted value with a space intact. Not adopted when an unquoted value holds "=" (G-01) |

## 3. Checked and found correct (executed)
- TS and generated Ruby agree on status and fields for all 148 events of five input sets (a1, a2, a3, a4, r1; the only differences are two CSV lines where my Ruby harness passed no column names); loading the Ruby as US-ASCII source changes nothing, Unicode and emoji values included.
- List grammar: `src=10.0.0.1,dst=10.0.0.2,action=allow` three fields FULL in TS, RB, PY; `;` and `|`; SP or TAB after the delimiter; quoted values with delimiters (`msg="a,b;c|d"`), empty quoted values, single quotes, Korean and emoji values, NBSP kept as data; behind RFC 3164 (with and without tag, pid, host), PRI-less BSD, RFC 5424 with and without STRUCTURED-DATA. Not FULL: mixed delimiters, empty item, empty value, trailing delimiter, list followed or preceded by white-space pairs, duplicate key, `constructor`, `__proto__`, U+0085 / U+2028 inside, 101 pairs (TS/RB), key of 96 characters accepted.
- No state between events: six-line and three-line mixed samples (comma, semicolon, space, mixed, quoted, duplicate) give per-line the single-line results; CRLF sample too.
- JSON, CEF (`msg=a,b=c`), LEEF 1.0 and 2.0 (delimiters `^` and `,`), Syslog + CEF, Junos structured data, FortiGate-style quoted kv, distinguished names: unchanged against 7a255a6, none mistaken for a list.
- Adoption: PAN alone adopted with 7 official fields; BIG-IP with PRI and adjacent tag (`ASM:unit_hostname="..."`, 4 to 10 pairs, other tags, other keys, unquoted, two lines, one-digit day, values with commas) adopted `delimited_kv` FULL; `<134>... web01 nginx: host=shop.example.com method=GET uri=/cart status=200` keeps `syslog_hostname->hostname HIGH` and drops `body.host`.
- F-06 case 5 (three device lines, one web-filter line): `host->hostname HIGH`.

## 4. Older behaviour seen on the way (same at 7a255a6, outside the range)
- `Nov 21 10:00:01 fw1 system: logdesc=login user=bob srcip=10.0.0.7 action=accept` (BSD header without PRI, with tag): native UNKNOWN, adopted FULL as `bsd_tagged_message` with one field `message`; no pair extracted, `srcip` not mapped. Without the tag the line is read natively.
- `<134>... bigip-4.pme-ds.f5.com ASM:` + three quoted pairs, or the semicolon form: not adopted, native UNKNOWN (four pairs or more are adopted).
- `<134>src=10.0.0.1,dst=10.0.0.2,action=allow` and `<134>src=10.0.0.1 dst=10.0.0.2 action=allow`: PY SOURCE_PARSED, TS UNKNOWN.

## 5. Not checked
- Ruby 2.4.9 / Fluentd (Ruby 3.2.3 only, grammar functions only; no full generated parser, no backend compile).
- vitest, Python test files, the oracle and mutant scripts, CI, the React component and Playwright flows.
- CSV with configured column names, WatchGuard, declared forwarders, blank-line event boundaries, events over 5 KB.
- Which funnel rule selects the comma_kv frame in G-10 (observed by execution only).

## 6. Reproduction (scratch, readable)
`/home/aella/.local/state/ps-audit-20261122/`: inputs `a1.json a2.json a4.json r1.json b2.json c1.json c2.json c3.json`, generators `gen_a3.py gen_b1.py gen_b3.py`; harnesses `ts.mts` (TS), `py.py` `py2.py` (PY), `rb.rb` `rb_ascii.rb` (RB), `cmp.py` (TS/RB/PY comparison), `wit.py` + `adopt.mts` (real witness + adoption), `cand.mts <tree> ...` (candidates, old and new), `f7.mts`; `old_*` = same against `tree7a`; outputs in `out/`. Run from `tree` with `node backend/node_modules/tsx/dist/cli.mjs <script> ...`.


---

## 7. Disposition (added by the implementer after the audit, 2026-11-22)

The sections above are the auditor's report. The only edit: a key written in Hangul in the inputs of G-02 is shown
as \u escapes, because the repository checks that authored prose is English. This section records what was done
with each finding.
"Fixed" means: a reproduction test was written first and failed, the change made it pass, and the mapping
mutation checks and the local battery were run afterwards. Nothing here has been verified by a second
independent audit yet.

| Finding | Status | Change | Reproduction test |
|---|---|---|---|
| G-01 | Fixed (guard): the event is PARTIAL instead of FULL. The pairs are still not read as fields. | loss guard v2 (`src/grammar/parseStatus.ts`, `runtime/multipass/source_kv.py`) | `src/grammar/delimitedPairGuard.test.ts` ("pairs behind a list delimiter in a line that is one token"), `tests/test_kv_delimited_pair_unread_20261121.py` |
| G-02 | Fixed (guard): PARTIAL instead of FULL. | same | same files ("whatever characters their key is written with") |
| G-03 | Fixed for pipe cells and for two header cells; the decimal fraction of a time is exempt. | `holdsCells` in `src/guided/genericStructuralAutoDraft.ts` | `src/guided/boundedAdoptionKeepsReading20261122.test.ts` ("G-03") |
| G-04 | Fixed. | host rule in `src/guided/normalizationCandidates.ts` (commit 7e3b4aa) | `src/guided/officialNameSparseCoverage20261121.test.ts` ("is not approved because one event writes its method in an unusual way"), independent oracle, 2 semantic mutants |
| G-05 | Fixed: a line whose pairs are separated by white space keeps a delimiter inside a value as value data. | loss guard v2 | `delimitedPairGuard.test.ts` ("a list delimiter inside a value of a white-space separated line is value data"), Python test file above |
| G-06 | Open, by design of the list grammar: a body that is exactly one token and a well-formed list (`opts=rw,uid=1000,gid=1000`) is read as a list. One token does not say which reading is meant. | - | - |
| G-07 | Fixed. | `holderOf` / `protocolValuesBeside` (commit 7e3b4aa) | `officialNameSparseCoverage20261121.test.ts` ("protocol evidence for a literal dotted key inside an object of the event"), independent oracle, 1 semantic mutant |
| G-08 | Partly fixed. A web URL of another host (an edge or proxy device, a referrer) no longer demotes the host. Still a review proposal: a host beside a bare upper-case method word (`level=TRACE`, `action=DELETE`) unless another record family carries the same host, and a host inside an object (`host.hostname`, `agent.hostname`). | host rule (commit 7e3b4aa) | `officialNameSparseCoverage20261121.test.ts` ("keeps the name of a device beside a web URL of another host", "does not take an everyday word for a request") |
| G-09 | Open. | - | - |
| G-10 | Open. | - | - |
| G-11 | Open. `&` is not a list delimiter of the guard or of the list grammar: adding it would make `url=/a?x=1&y=2` PARTIAL. | - | - |
| G-12 | Open. | - | - |
| G-13 | Open. | - | - |

Known cost of the guard change (G-01): a body that is one token and holds a value with a delimiter that a key
follows - `dn=CN=a,OU=b,DC=c` or `url=http://x/?a=1,b=2` with nothing else on the line - is now PARTIAL
(before: FULL with one field). With a second white-space separated pair on the line it is FULL as before.

Browser acceptance: the two failures of 88c0768 in `normalization-security-expanded*.spec.ts` (Akamai-style,
Zscaler ZIA-style) were the G-08 false refusal and are covered by the host rule change. The four failures in
`tests/prototype-key-source-fields-20261121.spec.ts` were an outdated expectation: since 88c0768 the quoted
comma list is read by the key=value list grammar, so the fields are `body.<key>` and no longer
`generic.fields.<key>`; names, values and official mappings are the same.
