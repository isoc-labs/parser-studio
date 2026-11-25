# ISOC single service and one release contract (2026-11-25)

Owner directive of 2026-11-25: act on the final independent audit, consolidate Parser Studio on the ISOC host and
repository, retire the XDR service, end development. This record describes what changed in the repository and why.
Deployment evidence (commit, process ids, engine comparison, browser journeys, Ruby 2.4.9) is in the
`deployment-receipt.json` of the release directory on `dev-atlas`, not here.

## Findings of the independent audit

| Id | Finding | Kind |
| --- | --- | --- |
| AUD-01 | After the release of `eb26205`, the engine process behind the ISOC host still ran the code of 2026-11-23. Its health endpoint answered 200. Four of twelve audit lines were read differently on the two hosts. | deployment |
| AUD-02 | The release and rollback procedure managed one engine unit. The second unit, which read the same files, was outside it. | deployment contract |
| AUD-03 | The service was released from `xdr-labs/parser-studio`; `isoc-labs/parser-studio` was a fork with one commit of its own (documentation links) and without that release. | repository |
| AUD-04 | A text prefix followed by five or more key=value pairs behind a Syslog header maps the header differently from the same line with fewer pairs. Values are kept. | accepted limit, unchanged |

AUD-01 was reproduced before any change: the public Multi-Pass API of the two hosts gave different answers for a CEF
line with a space after `CEF:`, comma key=value, semicolon key=value and JSON member names such as `__proto__`.
After a restart of the ISOC engine unit all twelve answers were equal. The restart is a repair of that day, not a fix.

## Root cause

Two public host names were served by two engine processes over one set of files, because an engine process trusts
exactly one browser origin. The release script listed one of the two units. Nothing in the procedure compared what
a running process answers with the code that was released: the checks were file hashes and health endpoints, and both
are satisfied by a process that still runs old code.

Adding the second unit to the restart list would have left the structure that produced the defect (two services to
keep equal by hand) and the blind spot (health as proof of version). Both are removed instead.

## What changed

Structure:

- One public host, `app.parser.isoc.ooo`; one repository, `isoc-labs/parser-studio`; one engine unit,
  `parser-studio-preview-multipass.service` on `127.0.0.1:4304`, which now trusts the ISOC origin; one authoring unit.
- The Nginx site file is `nginx-app.parser.isoc.ooo.conf`. It serves the built `index.html` unmodified: the page title
  is in the source (`Parser Studio — ISOC Labs`), not rewritten by the proxy.
- The XDR site file, the web-only release helper (`release_web.sh`, `deploy_web.sh.tpl`) and every reference to a
  second engine unit or port are gone from `ops/preview-domain/`.

Release contract, `ops/preview-domain/release.sh <sha> build|apply|verify|rollback|status`:

- before: the commit is `main` of the repository, every check run of it passed, the template approval tests pass
  in the built checkout, the run-time packages of the backend are the installed ones, the baseline is recorded;
- during: backend and engine are replaced only if they differ, a replaced part is restarted and must come back
  with a new process, any failed check restores the previous release;
- after: installed files equal the candidate; only the two units run the installed code; both processes started
  after their files were installed; the running engine answers byte for byte as the engine code of the commit, on
  its port and through the public host (`live_engine_check.py`); the public `index.html` and assets are the built
  ones; then Chromium on the public site and the downloaded parsers on Ruby 2.4.9 (`verify`).

`status` runs the after-checks at any time without changing anything.

Tests added:

- `tests/test_live_engine_check_20261125.py`: the check accepts the engine of the checkout, refuses a healthy
  process that answers as an older engine, fails on an unreachable service.
- `tests/test_preview_single_service_contract_20261125.py`: one site file for one host, exactly two unit files, one
  engine port, one release tool with the checks above, no second engine unit or port, the retired host named only as
  retired.
- `tests/deployed-preview-journey.deployed.ts` with `ops/preview-domain/playwright.deployed.config.ts`: the journeys
  `release.sh verify` runs against the deployed site.

## Found while exercising the contract

The tool was run before it was trusted: against the live host while the second engine still existed, in a sandbox
service set (own directories, throw-away units, other ports), and then for the first release.

- Against the live host with two engines, `status` failed on the second process, as intended. It also reported the
  first engine as older than its files. That was wrong: `ps` derives start times from the boot time and was 0.7 s
  off after 63 days of uptime. Start times now come from systemd, in microseconds.
- In the sandbox, a process that held the previous engine in memory while the files on disk were the release
  answered its health check, passed the file comparison and the start-time comparison, and was refused by the engine
  comparison on exactly the four audit lines of AUD-01. A second process over the same files, started from another
  directory with a relative path, was refused. A shell that only named the engine file on its command line was first
  counted as a process of the service; processes are now found by what an interpreter was started with.
- For the first release, root's `PATH` did not contain the run user's `gh`, so the check runs could not be read and
  the release stopped. The tool now adds the run user's own tool directory itself.
- The first release was done from the state of the release before `eb26205`, so that every part differed: backend
  swap and restart, engine files and restart, web, all checks; then `rollback` (the previous release ran again, with
  new processes), `apply` again and `verify`.

## Second independent audit of the result (2026-11-25) and what followed

A separate auditor checked the released state read-only: repository against installed files, running processes
against the released code (with lines of their own, and against the previous engine rebuilt from the rollback
material), duplicate services, the retired host, the release tool, the answers of the deployed engine, the Ruby
2.4.9 records. Repository, deployment, processes, parsing and data preservation held. Findings on the tool and the
site, and what was done:

| Finding | Kind | Change |
| --- | --- | --- |
| A second apply of the same release overwrote its rollback material; a rollback then restored only the backend and reported success | defect | The material is written once and marked; a rollback uses it once, checks what it restored, and only the installed release can be rolled back |
| No test ran the tool; its contract test only looked for names in the file | test gap | `tests/test_preview_release_contract_20261126.py` runs the committed script against a sandbox service set: apply, rollback, second apply, a failed check, unfinished checks, a stale process, a second process |
| The start-time check passed when a value could not be read, and trusted the stamp over the files | defect | It fails closed, and compares with the change time of the files as well |
| After a rollback the stamp named the release that had been rolled back | defect | The stamp gets the name the part had before |
| `status` without a built checkout compared nothing and answered OK | defect | It answers `STATUS_INCOMPLETE` |
| `verify` ended OK when no Ruby 2.4.9 runner was set | defect | It fails |
| The runbook named a tool path that does not exist on the host | documentation | The runbook takes the tool of the commit from Git |
| The receipt did not say that ChatGPT replies were written by the tests | documentation | It says so |
| As default server of its listener, the site served Parser Studio under names no site claims | pre-existing | The site answers 421 under every name but its own |

Not changed, reported to the owner: the repository is still a GitHub fork without branch protection; training pages
in the web root (outside this repository) still link to the retired host; the engine preview reads a text prefix
followed by key=value pairs behind a Syslog header as partial while the browser grammar reads it (unchanged
behaviour of `eb26205`).

## What did not change

No parsing, mapping, grammar or Ruby template code. The merge of `xdr-labs/parser-studio` main (`eb26205`, PR #316)
into this repository had no conflict; the tree equals `eb26205` plus the ISOC README links. The approved digests are
the ones computed from this source:

- template set `bb653102732e01001b5a30d4ac05b14917bb43dbe84eb484c88c409b261e0e8a`
- POC template `2b65c2706ebe7855cfd5a8a2086404bf5fda1ca65483c2d65437f9911dfd1466`

Contract identifiers that carry the former organisation name (`urn:xdr-labs:parser-project:v0.1`, the synthetic
native profile id, the package names, the header line of generated `.conf` files) are unchanged on purpose: they are
part of generated artifacts and of approved digests, not addresses.

Because the parsing and mapping code is the code of `eb26205`, the corpus measurements of that commit stand and were
not repeated: Golden 171/182, values 179/179, events 99/99, False FULL 0/64, Holdout 102/0, unseen values 236/236.

## Not verified by this change

Stellar Cyber installation, reception and indexing; the native Fluentd runtime of a sensor; device logs; the quality
of replies of a real ChatGPT session (the ChatGPT routes are exercised with replies written by the tests).
