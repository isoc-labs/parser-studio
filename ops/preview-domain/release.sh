#!/bin/bash
# Development Preview release tool (see UPDATE_RUNBOOK.md). Run as root on dev-atlas.
#
# One contract for the one service set of the one public host. Every release goes through this file; there is no
# second, partial path. The service set is the block below and nothing else.
#
#   release.sh <full-40-char-sha> build      preflight, candidate from the exact commit, comparison (nothing live changes)
#   release.sh <full-40-char-sha> apply      install web, backend and Multi-Pass, restart what changed, check the
#                                            running processes; any failed check restores the previous release
#   release.sh <full-40-char-sha> verify     browser journey on the public site, optional Ruby 2.4.9 run, receipt
#   release.sh <full-40-char-sha> rollback   restore the release that `apply` replaced
#   release.sh <full-40-char-sha> status     the process, file and engine checks only; changes nothing
set -uo pipefail

REPO=isoc-labs/parser-studio
SITE=app.parser.isoc.ooo
WEB=/var/www/parser-studio-app
BACKEND=/opt/parser-studio-preview/backend
MULTIPASS=/opt/parser-studio-preview/multipass
AUTHORING_UNIT=parser-studio-preview-authoring.service
AUTHORING_PORT=4305
MULTIPASS_UNIT=parser-studio-preview-multipass.service
MULTIPASS_PORT=4304
RUN_USER=aella

SHA=${1:-}; STEP=${2:-}
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "usage: $0 <full-40-char-sha> build|apply|verify|rollback|status"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "need root"; exit 2; }
S=${SHA:0:7}
ST=${PS_ROLLOUTS:-/home/aella/.local/state/parserstudio-public-rollouts}
CORE=${PS_CORE:-/home/aella/.dev/parserstudio-core}
REL=$(ls -d "$ST"/release-"$S"-* 2>/dev/null | head -1)
[ -n "$REL" ] || REL=$ST/release-$S-$(date -u +%Y%m%d)
SRC=$REL/src
ORIGIN=https://$SITE

# Commands of the run user: its home, and its own tools (gh is installed in ~/.local/bin, which root's PATH lacks).
as_user() { runuser -u "$RUN_USER" -- env HOME=/home/"$RUN_USER" PATH="/home/$RUN_USER/.local/bin:$PATH" NO_COLOR=1 "$@"; }
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$REL/release.log"; }
sha() { sha256sum "$1" | cut -c1-64; }
public_sha() { curl -fsS -m 15 -H 'Cache-Control: no-cache' "$ORIGIN/$1" | sha256sum | cut -c1-64; }
health() { for _ in $(seq 1 40); do [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "http://127.0.0.1:$1/health")" = 200 ] && return 0; sleep 0.8; done; return 1; }
main_pid() { systemctl show "$1" -p MainPID --value; }
# Start of the main process of a unit, in microseconds, as systemd recorded it. (`ps` derives start times from the
# boot time and is off by up to a second after weeks of uptime.)
started_at() { date -d "$(systemctl show "$1" -p ExecMainStartTimestamp --timestamp=us+utc --value)" +%s%6N; }
# Differences between a built tree and an installed one, ignoring what the host adds (byte code, the release stamp).
tree_diff() { diff -rq -x __pycache__ -x .parser-studio-release "$1" "$2"; }

# Process ids of interpreters (python, node) that were started with this file as an argument, however the path was
# written. A shell or editor that merely names the file on its command line is not one of them.
running_entry() {
  python3 - "$1" <<'ENTRY'
import os, sys
entry = os.path.realpath(sys.argv[1])
for pid in filter(str.isdigit, os.listdir('/proc')):
    if int(pid) == os.getpid():
        continue  # this lookup itself is a python started with the file as an argument
    try:
        argv = [part.decode('utf-8', 'replace') for part in open('/proc/%s/cmdline' % pid, 'rb').read().split(b'\0') if part]
        cwd = os.readlink('/proc/%s/cwd' % pid)
    except OSError:
        continue
    if len(argv) > 1 and os.path.basename(argv[0]).startswith(('python', 'node')) \
            and any(os.path.realpath(os.path.join(cwd, part)) == entry for part in argv[1:]):
        print(pid)
ENTRY
}

# --- checks -----------------------------------------------------------------------------------------------------

require_canonical_head() {
  local head; head=$(as_user git ls-remote "https://github.com/$REPO.git" refs/heads/main | cut -c1-40)
  [ "$head" = "$SHA" ] || { log "CHECK_FAIL main of $REPO is ${head:-unknown}, not $SHA"; return 1; }
  log "check: $SHA is main of $REPO"
}

require_ci_success() {
  # Every check run of the commit is finished, none failed, and the two gates that qualify a release passed.
  local runs; runs=$(as_user gh api "repos/$REPO/commits/$SHA/check-runs?per_page=100" \
    --jq '.check_runs[] | [.name, .status, (.conclusion // "none")] | @tsv') || { log "CHECK_FAIL the check runs of $SHA cannot be read"; return 1; }
  printf '%s\n' "$runs" > "$REL/ci.txt"
  [ -n "$runs" ] || { log "CHECK_FAIL $SHA has no check run"; return 1; }
  if printf '%s\n' "$runs" | awk -F'\t' '$2!="completed" || ($3!="success" && $3!="skipped" && $3!="neutral")' | grep -q .; then
    log "CHECK_FAIL a check run of $SHA is not finished or did not pass (ci.txt)"; return 1
  fi
  for gate in web-quality release-eligibility; do
    printf '%s\n' "$runs" | awk -F'\t' -v g="$gate" '$1==g && $3=="success"' | grep -q . || { log "CHECK_FAIL gate $gate did not pass on $SHA"; return 1; }
  done
  log "check: every check run of $SHA passed ($(printf '%s\n' "$runs" | wc -l) runs)"
}

require_template_approval() {
  # The generated Ruby of the candidate is the owner-approved one: the two approval tests of the repository pass.
  ( cd "$SRC/backend" && as_user node node_modules/tsx/dist/cli.mjs --test test/template-set-approval.test.ts test/poc-template-approval.test.ts ) \
    > "$REL/template-approval.log" 2>&1 || { log "CHECK_FAIL the generated Ruby of $SHA has no owner approval (template-approval.log)"; return 1; }
  log "check: $(grep -ao 'TEMPLATE_SET_STATUS.*' "$REL/template-approval.log" | head -1) | $(grep -ao 'POC_TEMPLATE_STATUS.*' "$REL/template-approval.log" | head -1)"
}

require_managed_processes() {
  # Every process that runs the installed engine or backend is the main process of its unit. A second process of
  # the same files (another unit, a leftover, a manual start) would keep answering with whatever code it loaded.
  local ok=0 unit entry pid others
  for pair in "$MULTIPASS_UNIT|$MULTIPASS/multipass_preview_api.py" "$AUTHORING_UNIT|$BACKEND/dist/src/mainline-authoring-server.js"; do
    unit=${pair%%|*}; entry=${pair#*|}
    [ "$(systemctl is-active "$unit")" = active ] || { log "CHECK_FAIL $unit is not active"; ok=1; continue; }
    pid=$(main_pid "$unit")
    others=$(running_entry "$entry" | grep -vx "$pid" | tr '\n' ' ')
    running_entry "$entry" | grep -qx "$pid" || { log "CHECK_FAIL the main process of $unit does not run $entry"; ok=1; }
    [ -z "$others" ] || { log "CHECK_FAIL processes outside $unit run $entry: $others"; ok=1; }
  done
  [ "$ok" = 0 ] && log "check: only $MULTIPASS_UNIT and $AUTHORING_UNIT run the installed code"
  return $ok
}

installed_at() {
  # When the files of a part were last installed, in microseconds: the stamp `apply` writes, else the newest file.
  if [ -f "$1/.parser-studio-release" ]; then awk '{print $2}' "$1/.parser-studio-release"
  else find "$1" -type f -not -path '*/__pycache__/*' -printf '%T@\n' | sort -n | tail -1 | awk -F. '{print $1 substr($2 "000000", 1, 6)}'; fi
}

require_process_newer_than_files() {
  # A process that started before its files were installed still runs the code it loaded then.
  local ok=0 unit dir pid
  for pair in "$MULTIPASS_UNIT|$MULTIPASS" "$AUTHORING_UNIT|$BACKEND/dist"; do
    unit=${pair%%|*}; dir=${pair#*|}; pid=$(main_pid "$unit")
    if [ "$(started_at "$unit")" -lt "$(installed_at "$dir")" ]; then
      log "CHECK_FAIL $unit (pid $pid) started before the files in $dir were installed"; ok=1
    fi
  done
  [ "$ok" = 0 ] && log "check: both processes started after their files were installed"
  return $ok
}

require_installed_equals_candidate() {
  tree_diff "$SRC/backend/dist" "$BACKEND/dist" > /dev/null || { log "CHECK_FAIL the installed backend differs from the candidate"; return 1; }
  tree_diff "$SRC/runtime/multipass" "$MULTIPASS" > /dev/null || { log "CHECK_FAIL the installed Multi-Pass differs from the candidate"; return 1; }
  [ "$(sha "$WEB/index.html")" = "$(sha "$SRC/dist/index.html")" ] || { log "CHECK_FAIL the installed index.html differs from the candidate"; return 1; }
  log "check: installed web, backend and Multi-Pass files equal the candidate"
}

require_public_equals_candidate() {
  local f
  [ "$(public_sha '')" = "$(sha "$SRC/dist/index.html")" ] || { log "CHECK_FAIL the public index.html is not the built file"; return 1; }
  for f in $(cd "$SRC/dist/assets" && ls); do
    [ "$(public_sha "assets/$f")" = "$(sha "$SRC/dist/assets/$f")" ] || { log "CHECK_FAIL the public asset $f is not the built file"; return 1; }
  done
  log "check: the public index.html and assets of $ORIGIN equal the built files"
}

require_engine_is_candidate() {
  # The running engine answers exactly as the engine code of the candidate does: on its own port and through the public host.
  local url
  for url in "http://127.0.0.1:$MULTIPASS_PORT" "$ORIGIN"; do
    as_user python3 "$SRC/ops/preview-domain/live_engine_check.py" --source "$SRC" --url "$url" --origin "$ORIGIN" \
      >> "$REL/engine-check.log" 2>&1 || { log "CHECK_FAIL the engine behind $url does not answer as the candidate code does (engine-check.log)"; return 1; }
  done
  log "check: the running engine answers byte for byte as the candidate code ($(grep -c '^same' "$REL/engine-check.log") answers)"
}

require_services_answer() {
  health "$AUTHORING_PORT" && health "$MULTIPASS_PORT" || { log "CHECK_FAIL a health endpoint does not answer"; return 1; }
  # A request body above the memory buffer of nginx must reach the backend (422 from the backend, not 500 from nginx).
  local code; code=$(curl -s -o /dev/null -w '%{http_code}' -m 15 -X POST -H 'Content-Type: application/json' -H "Origin: $ORIGIN" \
    --data "{\"x\":\"$(head -c 60000 /dev/zero | tr '\0' a)\"}" "$ORIGIN/api/v1/parser-pairs/package")
  [ "$code" = 422 ] || { log "CHECK_FAIL a large request body answers $code, not 422"; return 1; }
  log "check: both health endpoints answer and a large request body reaches the backend"
}

require_backend_dependencies() {
  # The backend runs on the packages installed next to it. A release only replaces dist, so the packages the
  # candidate needs at run time must be the installed ones, version for version.
  python3 - "$SRC/backend/package-lock.json" "$BACKEND/node_modules/.package-lock.json" <<'DEPS' || { log "CHECK_FAIL the run-time packages of the backend differ from the installed ones: install them first (README.md, first installation)"; return 1; }
import json, sys
wanted = {name: entry.get('version') for name, entry in json.load(open(sys.argv[1]))['packages'].items() if name and not entry.get('dev')}
installed = {name: entry.get('version') for name, entry in json.load(open(sys.argv[2]))['packages'].items()}
different = sorted(name for name in set(wanted) | set(installed) if wanted.get(name) != installed.get(name))
if different: print('different packages:', ', '.join(different))
sys.exit(1 if different else 0)
DEPS
  log "check: the run-time packages of the backend are the installed ones"
}

stamp() { echo "$SHA $(date +%s%6N)" > "$1/.parser-studio-release"; chown "$RUN_USER:$RUN_USER" "$1/.parser-studio-release"; }

restart_and_confirm() {
  # $1 unit, $2 port: the unit has a new main process after the restart and answers.
  local before after; before=$(main_pid "$1")
  systemctl restart "$1"; health "$2" || { log "CHECK_FAIL $1 does not answer after the restart"; return 1; }
  after=$(main_pid "$1")
  [ "$after" != "$before" ] && [ "$after" != 0 ] || { log "CHECK_FAIL $1 kept its process $before"; return 1; }
  log "$1 restarted: pid $before -> $after"
}

# --- steps ------------------------------------------------------------------------------------------------------

rollback() {
  log "ROLLBACK start"
  if [ -f "$REL/rollback/index.html" ]; then
    cp -p "$REL/rollback/index.html" "$WEB/.idx.rb" && chown "$RUN_USER:$RUN_USER" "$WEB/.idx.rb" && mv -f "$WEB/.idx.rb" "$WEB/index.html" && log "web index restored"
  fi
  if [ -d "$BACKEND/.dist_rollback_$S" ]; then
    mv "$BACKEND/dist" "$BACKEND/.dist_failed_${S}_$(date -u +%Y%m%dT%H%M%SZ)" && mv "$BACKEND/.dist_rollback_$S" "$BACKEND/dist" && stamp "$BACKEND/dist" \
      && restart_and_confirm "$AUTHORING_UNIT" "$AUTHORING_PORT" && log "backend restored"
  fi
  if [ -s "$REL/rollback/multipass.changed" ] || [ -s "$REL/rollback/multipass.new" ] || [ -s "$REL/rollback/multipass.removed" ]; then
    local f
    for f in $(cat "$REL/rollback/multipass.new"); do rm -f "$MULTIPASS/$f"; done
    for f in $(cat "$REL/rollback/multipass.changed" "$REL/rollback/multipass.removed" 2>/dev/null); do
      cp -p "$REL/rollback/multipass/$f" "$MULTIPASS/.rb.$f" && chown "$RUN_USER:$RUN_USER" "$MULTIPASS/.rb.$f" && mv -f "$MULTIPASS/.rb.$f" "$MULTIPASS/$f"
    done
    stamp "$MULTIPASS" && restart_and_confirm "$MULTIPASS_UNIT" "$MULTIPASS_PORT" && log "Multi-Pass restored"
  fi
  # The previous release is what runs again: its page is public, the two units run the restored files.
  local rc=0
  require_managed_processes && require_process_newer_than_files && require_services_answer || rc=1
  if [ -f "$REL/rollback/index.html" ] && [ "$(public_sha '')" != "$(sha "$REL/rollback/index.html")" ]; then
    log "CHECK_FAIL the public index.html is not the one of the previous release"; rc=1
  fi
  [ "$rc" = 0 ] && log "ROLLBACK_OK the previous release is installed and is what runs on $ORIGIN" || log "ROLLBACK_INCOMPLETE read the lines above"
  return $rc
}

build() {
  install -d -o "$RUN_USER" -g "$RUN_USER" -m 700 "$REL"
  log "BUILD $SHA for $ORIGIN"
  require_canonical_head && require_ci_success || return 1
  { echo "utc $(date -u +%FT%TZ)"
    echo "live index: $(sha "$WEB/index.html")"
    echo "public index: $(public_sha '')"
    for u in "$AUTHORING_UNIT" "$MULTIPASS_UNIT"; do echo "$u active=$(systemctl is-active "$u") pid=$(main_pid "$u") since=$(systemctl show "$u" -p ActiveEnterTimestamp --value)"; done
    echo "$AUTHORING_PORT: $(curl -fsS -m 5 "http://127.0.0.1:$AUTHORING_PORT/health")"
    echo "$MULTIPASS_PORT: $(curl -fsS -m 5 "http://127.0.0.1:$MULTIPASS_PORT/health")"
    echo "installed releases: backend=$(cat "$BACKEND/dist/.parser-studio-release" 2>/dev/null || echo unrecorded) multipass=$(cat "$MULTIPASS/.parser-studio-release" 2>/dev/null || echo unrecorded)"
    (cd "$WEB" && find . -type f -not -path './training/*' | sort | xargs sha256sum)
  } > "$REL/baseline-before.txt" 2>&1
  chown "$RUN_USER:$RUN_USER" "$REL/baseline-before.txt"
  [ "$(sha "$WEB/index.html")" = "$(public_sha '')" ] || { log "CHECK_FAIL the public index.html is not the installed one: find out why first"; return 1; }
  require_managed_processes || return 1
  as_user git -C "$CORE" fetch -q "https://github.com/$REPO.git" main > "$REL/fetch.log" 2>&1 || { log "BUILD_FAIL fetch"; return 1; }
  [ -e "$SRC" ] || as_user git -C "$CORE" worktree add -q --detach "$SRC" "$SHA" || { log "BUILD_FAIL worktree"; return 1; }
  [ "$(as_user git -C "$SRC" rev-parse HEAD)" = "$SHA" ] && [ -z "$(as_user git -C "$SRC" status --porcelain)" ] || { log "BUILD_FAIL the checkout is not a clean $SHA"; return 1; }
  as_user git -C "$SRC" rev-parse HEAD 'HEAD^{tree}' > "$REL/commit.txt"
  ( cd "$SRC" && as_user npm ci --no-audit --no-fund > "$REL/npm_ci_web.log" 2>&1 ) || { log "BUILD_FAIL npm ci"; return 1; }
  ( cd "$SRC" && as_user npx tsc --noEmit -p . > "$REL/tsc.log" 2>&1 ) || { log "BUILD_FAIL tsc"; return 1; }
  ( cd "$SRC" && as_user npx vitest run --reporter=dot > "$REL/vitest.log" 2>&1 ) || { log "BUILD_FAIL vitest"; return 1; }
  ( cd "$SRC" && as_user npm run build > "$REL/build_web.log" 2>&1 ) || { log "BUILD_FAIL web build"; return 1; }
  ( cd "$SRC/backend" && as_user npm ci --no-audit --no-fund > "$REL/npm_ci_backend.log" 2>&1 && as_user npm run build > "$REL/build_backend.log" 2>&1 ) || { log "BUILD_FAIL backend build"; return 1; }
  require_template_approval && require_backend_dependencies || return 1
  { echo "web new or changed: $(cd "$SRC/dist" && find . -type f | sort | while read -r f; do cmp -s "$f" "$WEB/$f" || echo "$f"; done | tr '\n' ' ')"
    echo "backend: $(tree_diff "$SRC/backend/dist" "$BACKEND/dist" | wc -l) differences"
    tree_diff "$SRC/backend/dist" "$BACKEND/dist" | sed "s#$SRC/##" | head -80
    echo "multipass: $(tree_diff "$SRC/runtime/multipass" "$MULTIPASS" | wc -l) differences"
    tree_diff "$SRC/runtime/multipass" "$MULTIPASS" | sed "s#$SRC/##"
  } > "$REL/compare.txt" 2>&1
  log "BUILD_OK (compare.txt lists what an apply changes)"
}

apply() {
  grep -q BUILD_OK "$REL/release.log" 2>/dev/null || { echo "build $SHA first"; return 2; }
  log "APPLY $SHA"
  require_canonical_head && require_ci_success || return 1
  [ "$(as_user git -C "$SRC" rev-parse HEAD)" = "$SHA" ] && [ -z "$(as_user git -C "$SRC" status --porcelain)" ] || { log "CHECK_FAIL the candidate checkout changed"; return 1; }
  [ "$(sha "$WEB/index.html")" = "$(grep '^live index:' "$REL/baseline-before.txt" | awk '{print $3}')" ] || { log "CHECK_FAIL the live index.html changed since the build: build again"; return 1; }
  require_managed_processes && require_backend_dependencies || return 1
  # 1. back up what will be replaced
  mkdir -p -m 700 "$REL/rollback/multipass" && chown -R "$RUN_USER:$RUN_USER" "$REL/rollback"
  cp -p "$WEB/index.html" "$REL/rollback/index.html"
  : > "$REL/rollback/multipass.new"; : > "$REL/rollback/multipass.changed"; : > "$REL/rollback/multipass.removed"
  local f backend_changed=0 multipass_changed=0
  for f in $(cd "$SRC/runtime/multipass" && ls *.py *.json); do
    if [ -f "$MULTIPASS/$f" ]; then cmp -s "$SRC/runtime/multipass/$f" "$MULTIPASS/$f" || { cp -p "$MULTIPASS/$f" "$REL/rollback/multipass/$f"; echo "$f" >> "$REL/rollback/multipass.changed"; }
    else echo "$f" >> "$REL/rollback/multipass.new"; fi
  done
  for f in $(cd "$MULTIPASS" && ls *.py *.json); do
    [ -f "$SRC/runtime/multipass/$f" ] || { cp -p "$MULTIPASS/$f" "$REL/rollback/multipass/$f"; echo "$f" >> "$REL/rollback/multipass.removed"; }
  done
  [ -s "$REL/rollback/multipass.new" ] || [ -s "$REL/rollback/multipass.changed" ] || [ -s "$REL/rollback/multipass.removed" ] && multipass_changed=1
  tree_diff "$SRC/backend/dist" "$BACKEND/dist" > /dev/null || backend_changed=1
  log "backup done: backend changed=$backend_changed, Multi-Pass files changed=$(wc -l < "$REL/rollback/multipass.changed") new=$(wc -l < "$REL/rollback/multipass.new") removed=$(wc -l < "$REL/rollback/multipass.removed")"
  # 2. backend: the whole dist is swapped by rename, then the service is restarted
  if [ "$backend_changed" = 1 ]; then
    rm -rf "$BACKEND/.dist_candidate_$S"; cp -a "$SRC/backend/dist" "$BACKEND/.dist_candidate_$S" && chown -R "$RUN_USER:$RUN_USER" "$BACKEND/.dist_candidate_$S"
    ( cd "$BACKEND/dist" && find . -type f | sort | xargs sha256sum ) > "$REL/rollback/backend-dist.sha256"
    mv "$BACKEND/dist" "$BACKEND/.dist_rollback_$S" && mv "$BACKEND/.dist_candidate_$S" "$BACKEND/dist" && stamp "$BACKEND/dist" \
      && restart_and_confirm "$AUTHORING_UNIT" "$AUTHORING_PORT" || { rollback; return 1; }
  fi
  # 3. Multi-Pass: changed and new files atomically, then the service is restarted
  if [ "$multipass_changed" = 1 ]; then
    for f in $(cat "$REL/rollback/multipass.changed" "$REL/rollback/multipass.new"); do
      install -o "$RUN_USER" -g "$RUN_USER" -m 644 "$SRC/runtime/multipass/$f" "$MULTIPASS/.new.$f" && mv -f "$MULTIPASS/.new.$f" "$MULTIPASS/$f"
    done
    for f in $(cat "$REL/rollback/multipass.removed"); do rm -f "$MULTIPASS/$f"; done
    stamp "$MULTIPASS" && restart_and_confirm "$MULTIPASS_UNIT" "$MULTIPASS_PORT" || { rollback; return 1; }
  fi
  # 4. web: new assets first, index.html last; an existing asset is never overwritten with other content
  for f in $(cd "$SRC/dist" && find . -type f -not -name index.html | sed 's#^\./##' | sort); do
    if [ -f "$WEB/$f" ]; then cmp -s "$SRC/dist/$f" "$WEB/$f" || { log "CHECK_FAIL $f exists with other content"; rollback; return 1; }
    else install -D -o "$RUN_USER" -g "$RUN_USER" -m 644 "$SRC/dist/$f" "$WEB/$f.new" && mv -f "$WEB/$f.new" "$WEB/$f"; fi
  done
  install -o "$RUN_USER" -g "$RUN_USER" -m 644 "$SRC/dist/index.html" "$WEB/.new.idx" && mv -f "$WEB/.new.idx" "$WEB/index.html"
  # 5. the release is what runs: files, processes, engine, public host
  : > "$REL/engine-check.log"
  require_installed_equals_candidate && require_managed_processes && require_process_newer_than_files \
    && require_engine_is_candidate && require_public_equals_candidate && require_services_answer || { rollback; return 1; }
  { echo "utc $(date -u +%FT%TZ)"; echo "commit $SHA"
    for u in "$AUTHORING_UNIT" "$MULTIPASS_UNIT"; do echo "$u active=$(systemctl is-active "$u") pid=$(main_pid "$u") since=$(systemctl show "$u" -p ActiveEnterTimestamp --value)"; done
    echo "public index: $(public_sha '')"
    echo "last installed from: backend=$(cut -c1-40 "$BACKEND/dist/.parser-studio-release" 2>/dev/null || echo unrecorded) multipass=$(cut -c1-40 "$MULTIPASS/.parser-studio-release" 2>/dev/null || echo unrecorded)"
  } > "$REL/post-install.txt"
  log "APPLY_OK $SHA is installed and is what runs on $ORIGIN"
}

status() {
  mkdir -p "$REL"; : > "$REL/engine-check.log"
  require_managed_processes; local a=$?
  require_process_newer_than_files; local b=$?
  local c=0 d=0 e=0
  if [ -d "$SRC" ]; then
    require_installed_equals_candidate; c=$?
    require_engine_is_candidate; d=$?
    require_public_equals_candidate; e=$?
  else log "status: no candidate checkout of $SHA; file and engine comparisons skipped"; fi
  require_services_answer; local g=$?
  [ $((a+b+c+d+e+g)) = 0 ] && log "STATUS_OK" || { log "STATUS_FAIL"; return 1; }
}

verify() {
  grep -E ' (APPLY_OK|ROLLBACK start)' "$REL/release.log" 2>/dev/null | tail -1 | grep -q APPLY_OK || { echo "apply $SHA first"; return 2; }
  local ev="$REL/browser-evidence" dir c
  rm -rf "$ev"; install -d -o "$RUN_USER" -g "$RUN_USER" "$ev"
  log "VERIFY browser journey on $ORIGIN"
  ( cd "$SRC" && as_user env PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-}" PARSER_STUDIO_DEPLOYED_URL="$ORIGIN" PARSER_STUDIO_DEPLOYED_OUT="$ev" \
      npx playwright test --config ops/preview-domain/playwright.deployed.config.ts --project=chromium > "$ev/playwright.log" 2>&1 )
  local rc=$?
  [ -z "$(as_user git -C "$SRC" status --porcelain)" ] || log "note: the candidate checkout has untracked test output"
  [ "$rc" = 0 ] || { log "VERIFY_FAIL the browser journey failed (browser-evidence/playwright.log); roll back or repair"; return 1; }
  log "browser journey: $(grep -E '^\s+[0-9]+ (passed|failed|skipped|flaky)' "$ev/playwright.log" | tr '\n' ' ')"
  # Ruby 2.4.9: PS_RUBY249_RUNNER is a command `<runner> <parser file> <file of input lines>` that prints one record per line.
  for dir in "$ev"/*/; do
    c=$(basename "$dir"); [ -f "$dir/parser.rb" ] || continue
    if [ -z "${PS_RUBY249_RUNNER:-}" ]; then log "ruby 2.4.9 $c: NOT RUN (PS_RUBY249_RUNNER is not set)"; continue; fi
    $PS_RUBY249_RUNNER "$dir/parser.rb" "$dir/runtime.lines" > "$dir/ruby249.txt" 2>&1 && head -1 "$dir/ruby249.txt" | grep -q '^ruby 2\.4\.9' \
      || { log "VERIFY_FAIL the parser of $c does not run on Ruby 2.4.9 ($dir/ruby249.txt)"; return 1; }
    # runtime.expect: texts the records must contain (values of fields the sample did not have, text of unread lines).
    if [ -f "$dir/runtime.expect" ]; then
      while IFS= read -r text; do
        [ -z "$text" ] || grep -qF -- "$text" "$dir/ruby249.txt" || { log "VERIFY_FAIL the Ruby 2.4.9 records of $c do not contain: $text"; return 1; }
      done < "$dir/runtime.expect"
    fi
    log "ruby 2.4.9 $c: lines=$(grep -c . "$dir/runtime.lines") records=$(grep -c '^u[0-9]' "$dir/ruby249.txt") error_records=$(grep -c parser_err_msg "$dir/ruby249.txt")"
  done
  status || return 1
  python3 - "$REL" "$SHA" "$REPO" "$ORIGIN" <<'RECEIPT' || { log "VERIFY_FAIL receipt"; return 1; }
import hashlib, json, os, re, sys
rel, commit, repo, origin = sys.argv[1:5]
read = lambda name: open(os.path.join(rel, name)).read() if os.path.exists(os.path.join(rel, name)) else ''
log = read('release.log')
receipt = {
  'repository': repo, 'target': 'Development Preview ' + origin + ' (not production)', 'deployed_commit': commit,
  'deployed_tree': read('commit.txt').split()[-1] if read('commit.txt') else None,
  'applied': re.findall(r'(\S+) APPLY_OK', log)[-1:],
  'baseline_before': read('baseline-before.txt').splitlines()[:8],
  'changed': read('compare.txt').splitlines()[:3],
  'ci_check_runs': read('ci.txt').splitlines(),
  'template_approval': re.findall(r'(?:TEMPLATE_SET|POC_TEMPLATE)_STATUS[^\n]*', read('template-approval.log')),
  'post_install': read('post-install.txt').splitlines(),
  'checks': [line.split(' ', 1)[1] for line in log.splitlines() if ' check: ' in line][-12:],
  'engine_check': [line for line in read('engine-check.log').splitlines() if line.startswith('ENGINE_CHECK')],
  'browser_journey': [line.split(' ', 1)[1] for line in log.splitlines() if 'browser journey:' in line or 'ruby 2.4.9' in line],
  'rollback': {'command': 'ops/preview-domain/release.sh ' + commit + ' rollback', 'material': os.path.join(rel, 'rollback')},
  'not_verified': ['Stellar Cyber installation, reception and indexing', 'native Fluentd runtime on a sensor', 'device logs'],
}
json.dump(receipt, open(os.path.join(rel, 'deployment-receipt.json'), 'w'), indent=1)
RECEIPT
  chown "$RUN_USER:$RUN_USER" "$REL/deployment-receipt.json"
  log "VERIFY_OK receipt: $REL/deployment-receipt.json"
}

case "$STEP" in
  build) build ;;
  apply) apply ;;
  verify) verify ;;
  status) status ;;
  rollback) [ -d "$REL/rollback" ] || { echo "no rollback material for $SHA"; exit 2; }; rollback ;;
  *) echo "usage: $0 <full-40-char-sha> build|apply|verify|rollback|status"; exit 2 ;;
esac
