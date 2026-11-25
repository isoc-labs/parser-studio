# Development Preview update runbook (deploy, verify, roll back)

Scope: updates of the public **Development Preview** at https://app.parser.isoc.ooo/ on `dev-atlas`, from the
repository `isoc-labs/parser-studio`. This is not a Stellar Cyber DP, a customer environment or a production
release. A production or tenant release needs its own owner approval and is out of scope here.

There is one service set, one deploy contract and one rollback contract: `ops/preview-domain/release.sh`.
Every update goes through it. Do not install files, restart a unit or roll back by hand, and do not write a
second script for a "small" update: a path that manages only part of the service set is how one process kept
running old code behind a healthy answer (section 7).

The first installation (Nginx site, systemd units, TLS) is described in `README.md` and is done once by the
owner. This runbook covers replacing the application files afterwards. Do not edit the Nginx site, the systemd
units, TLS certificates, `training/`, the favicons or any file outside the paths below as part of an update.

## 1. The service set

| Part | Location | How it is served | Changes when |
| --- | --- | --- | --- |
| Web UI | `/var/www/parser-studio-app` (`index.html`, `assets/`) | Nginx static files | anything under `src/`, `index.html`, `public/` |
| Authoring backend | `/opt/parser-studio-preview/backend/dist` | `parser-studio-preview-authoring.service`, `127.0.0.1:4305` | anything under `backend/` |
| Multi-Pass engine | `/opt/parser-studio-preview/multipass` | `parser-studio-preview-multipass.service`, `127.0.0.1:4304` | anything under `runtime/multipass/` |

This table and the block at the top of `release.sh` are the same list. Nothing else serves Parser Studio:
no second host name, no second engine process, no second unit. If a part is ever added, add it to that block,
to this table and to `tests/test_preview_single_service_contract_20261125.py` in the same change.

Facts that shape the procedure:

- Both services run as the Unix user `aella` with `Restart=on-failure`. Files in the paths above are owned by `aella`.
- A process keeps the code it loaded when it started. Replacing files changes nothing until the process is
  restarted, and its health endpoint answers 200 either way.
- The engine trusts exactly one browser origin (`PARSER_STUDIO_TRUSTED_ORIGIN` in its unit). One public host,
  one engine process.
- Nginx sends `Cache-Control: private, no-store`, so no cache purge is needed.
- `assets/` keeps older hashed bundles on purpose. New bundles are added next to them, so restoring
  `index.html` restores the previous web version. Do not delete old assets as part of an update.
- There is no CI deploy job. `.github/workflows/quality.yml` only tests. Deployment is this runbook.
- Release directories of earlier updates under `/home/aella/.local/state/parserstudio-public-rollouts/` are
  history and rollback material. Scripts inside them are pinned to one commit: never run them for a new version.

## 2. Preconditions

1. Read `AGENTS.md` and `.engineering/project.yaml`. Confirm that the owner approved updating the
   Development Preview for this change.
2. The change is merged into `main` of `isoc-labs/parser-studio` and you know the exact commit (40 hex digits).
3. Every required check of that commit passed on GitHub. `release.sh` reads the check runs itself and refuses a
   commit that is not `main`, has a check that is unfinished or failed, or lacks `web-quality` or `release-eligibility`.
4. The generated Ruby of that commit is the owner-approved one. `release.sh` runs the two approval tests of the
   checkout (`template-set-approval`, `poc-template-approval`). A changed template without an owner approval stops
   the release; the approval constants are never edited to make it pass.

Run as root on `dev-atlas` (the script does file work as `aella` and needs root only for `systemctl`). Through the
DR Link shell, start a step in the background (`nohup setsid ... &`) and read `$REL/release.log`: a step can take
longer than the 30 s command limit.

## 3. Deploy

```bash
SHA=<full 40-char sha of main>
# The tool of the commit being released, taken from Git. The shared clone is used for its object store only: which
# branch it has checked out, and where its `origin` points, do not matter.
CORE=/home/aella/.dev/parserstudio-core
runuser -u aella -- git -C $CORE fetch -q https://github.com/isoc-labs/parser-studio.git main
R=/root/parser-studio-release-${SHA:0:7}.sh
runuser -u aella -- git -C $CORE show $SHA:ops/preview-domain/release.sh > $R && chmod 700 $R

export PS_RUBY249_RUNNER=/home/aella/.local/state/parserstudio-public-rollouts/tools/ruby249-run.py
export PLAYWRIGHT_BROWSERS_PATH=/home/aella/.cache/ms-playwright-parserstudio

$R $SHA build      # changes nothing live
$R $SHA apply      # installs and restarts; rolls itself back on any failed check
$R $SHA verify     # browser journey on the public site, Ruby 2.4.9, receipt
```

`PS_RUBY249_RUNNER` is a host tool, not part of the repository: a command `<runner> <parser file> <file of lines>`
that prints `ruby <version>` and one record per line. On `dev-atlas` it runs the parser with the Ruby 2.4.9 of the
audit tools.

The release directory is `REL=/home/aella/.local/state/parserstudio-public-rollouts/release-<short-sha>-<date>`.

### build

1. Checks that the commit is `main` of the repository and that its check runs passed (`ci.txt`).
2. Records the baseline (`baseline-before.txt`): hashes of the live web files, unit state and process ids, health,
   the release each part was last installed from. Stops if the public `index.html` is not the installed one, or if a
   process other than the two units runs the installed code.
3. Creates a detached worktree of the exact commit in `$REL/src`, runs `npm ci`, `tsc`, Vitest and both builds.
4. Runs the template approval tests in that checkout, and checks that the run-time packages the backend of this
   commit needs are the ones installed next to the backend (a release replaces `dist`, not `node_modules`; a commit
   that changes them stops here and needs the first-installation step of `README.md`).
5. Writes `compare.txt`: what an apply would change in the web root, the backend and the engine. Read it. Anything
   you did not expect from the change is a reason to stop and look, not to push on.

### apply

1. Repeats the commit and check-run checks, and refuses if the live `index.html` changed since the build.
2. Backs up what will be replaced into `$REL/rollback/` (and the previous backend as `.dist_rollback_<short-sha>`).
   This material is written once, by the first apply of a release, and names the state before that release. Applying
   the same release again keeps it: a second apply never turns the release itself into its own rollback target.
3. Backend, if it differs: swaps the whole `dist` by rename and restarts the unit.
4. Engine, if it differs: installs the changed files atomically and restarts the unit.
5. Web: adds new hashed assets, switches `index.html` last. An existing asset is never overwritten with other content.
6. Checks that the release is what runs (section 4). On any failure it restores the previous release and says so.

A unit is restarted only if its own files changed, and then it must come back with a new process id.

### verify

1. Chromium opens the public site and goes through the journeys of `playwright.deployed.config.ts`: the first-user
   journey (default port 6801 and a typed port, downloads equal to the generated files, no page error, requests to
   the site's own origin only), CEF with and without a space after `CEF:`, a bare PRI before CEF, messages that only
   claim CEF, comma and semicolon key=value, nested JSON, JSON member names such as `__proto__`, a text prefix
   before key=value, mixed readable and unreadable events, the ChatGPT Assisted Parser routes, automatic,
   ChatGPT-assisted and manual mapping per event type. Replies "from ChatGPT" are written by the tests: they
   exercise the paste-and-apply route and prove nothing about a real reply.
2. Every downloaded parser is run on Ruby 2.4.9 by `PS_RUBY249_RUNNER` over its sample lines and over lines it has
   not seen. Each line must give a record, and the records must contain the values listed in `runtime.expect` where
   a journey wrote one (fields that were not in the sample, the whole text of a line that cannot be read). Without a
   runner `verify` fails: a release is not verified until its parsers ran on Ruby 2.4.9.
3. Repeats the checks of section 4.
4. Writes `$REL/deployment-receipt.json`.

Use only sample logs without customer data. Do not call a deploy done before `VERIFY_OK`.

## 4. What "deployed" means

A health endpoint that answers 200 says that a process listens. It does not say which code that process runs.
`apply`, `verify` and `status` therefore check all of the following, and each line is in `release.log`:

| Check | What it proves |
| --- | --- |
| installed files equal the candidate | web, backend and engine files on disk are the built commit |
| only the two units run the installed code | no second process (another unit, a leftover, a manual start) serves the same files |
| both processes started after their files were installed | no process still runs code it loaded before the install |
| the engine answers byte for byte as the candidate code | `live_engine_check.py` computes the answers of the checkout's engine for a fixed set of lines and compares them with the answers of the running process, on its own port and through the public host |
| public `index.html` and assets equal the built files | the public host serves this build, unmodified |
| health, and a large request body answers 422 | both services answer; Nginx passes bodies above its memory buffer to the backend |

`release.sh <sha> status` runs these checks at any time and changes nothing on the service. It needs the built
checkout of that commit (`$REL/src`, left by `build`): without it nothing can be compared and the answer is
`STATUS_INCOMPLETE`, not OK. Use it when in doubt about what runs.

The start-time check compares the start of each process, as systemd recorded it, with the release stamp and with
the last change of any of its files (change time, which a copy cannot preserve). For the backend the folders count
as well: a prepared tree that is renamed into place keeps the times of its files, but not the time of the folder. The file `.parser-studio-release` in
the backend and engine directories names the commit a part was last installed from, or the name it had before when
a rollback put it back; a release that does not change a part leaves its stamp alone, so the stamp can name an
earlier commit while the files still equal the current one.

The engine is compared by behaviour. The authoring backend is not: for it the proof is file equality, one managed
process, and a start after the last change of its files.

If the large-body check answers 500 and `/var/log/nginx/error.log` shows `open() "/var/lib/nginx/body/..." failed
(13: Permission denied)`, the temporary directories of Nginx no longer belong to its worker user. Repair:
`chown www-data /var/lib/nginx/{body,proxy,fastcgi,scgi,uwsgi}` (the user of `user` in `/etc/nginx/nginx.conf`).
This happened on 2026-11-14 after the Python suite was run as root.

## 5. Roll back

```bash
$R $SHA rollback
```

Use the tool of the commit that is `main` now, also to roll back the directory of an older release: the tool of an
older commit does not know what later versions record (which release is installed, material that is used once).
Remove copies of older tools (`/root/parser-studio-release-*.sh`) when a newer one is taken from Git.

Restores, from `$REL/rollback/`, the previous `index.html`, the previous backend `dist` and the previous engine
files, restarts the units whose files were restored, and checks that the restored backend and engine files are the
ones that were replaced, that only the two units run them, and that the previous page is public. `apply` does the
same by itself when one of its checks fails. Roll back when a check of `apply` or `verify` fails and cannot be
explained, or when the owner asks.

A rollback restores the state before that release, once: afterwards the material is marked used, and a second
rollback of the same release is refused. Only the installed release can be rolled back
(`parserstudio-public-rollouts/current-release` names it); a release whose apply failed and whose automatic rollback
could not finish can be rolled back as well, as long as nothing was applied after it. To go back further, roll back the release directories one
after the other, newest first: each holds the material of the release it replaced. A release that changed no
installed file restores nothing; the release before it restores what it had replaced.

After a rollback the public `index.html` hash must equal the one in `baseline-before.txt`. The failed candidate
stays in place as `.dist_failed_<short-sha>_<time>` for diagnosis. Keep the release directory: it is the evidence, and the
rollback material of the release that is live now.

## 6. The receipt

`deployment-receipt.json` names the repository, the target, the deployed commit and tree, the time of the apply, the
baseline, what changed, the check runs, the template approval status, the unit state after the install, the checks
of section 4, the engine comparison, the browser journey and Ruby 2.4.9 results, the rollback command, and what is
NOT VERIFIED by a deploy (Stellar Cyber installation and reception, the native Fluentd runtime of a sensor, device
logs). It holds no secrets and no customer logs.

## 7. Why there is one contract

Until 2026-11-25 Parser Studio was served under two host names, each with its own engine process over the same
files, and the release script restarted only one of them. After an update the other process answered its health
check with 200 and kept reading logs with the code of the previous release: four of twelve audit lines were read
differently on the two hosts. The host name `app.parser.xdr.ooo` was retired on 2026-11-25 and its engine unit was
removed; Parser Studio is no longer served there. What prevents a repeat is not a longer restart list: there is one
host, one engine process and one unit list, and a release is accepted only when the running processes are shown to
run the released code (section 4).

## 8. Do not

- Do not change the Nginx site, systemd units, TLS certificates or security headers as part of an update.
- Do not add a second public host name, a second engine process or a second release script. The site answers 421
  under every name but its own, also when it is the default server of the listener.
- Do not delete `training/`, favicons, older hashed assets, older `.dist_rollback_*` directories or earlier receipts.
  Pruning old rollback material is a separate decision for the owner.
- Do not deploy untested or unmerged code, and do not skip `verify`.
- Do not run the repository's test suites as root on `dev-atlas` (use `runuser -u aella -- ...`): a test that starts
  a system binary acts on the host with root's rights.
- Do not describe the Development Preview as production, and do not claim Stellar Cyber or native Fluentd
  compatibility from a deploy check: those remain NOT VERIFIED.
