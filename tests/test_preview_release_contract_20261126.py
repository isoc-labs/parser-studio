"""Behaviour of the release tool (ops/preview-domain/release.sh): apply, rollback and status against a sandbox
service set (independent audit of 2026-11-25, findings on the release contract).

The committed script is run as it is, except for its service-set block: the three directories, the two ports, the
run user and the public address point at a temporary directory and loopback ports, and the root requirement is
dropped. Everything else is the released code. Around it stand:
  - two real processes, the Multi-Pass engine of this repository and a small node server in the place of the
    authoring backend, started and restarted by a stand-in for systemctl;
  - a loopback server in the place of the public host (static files, the engine routes, the large-body answer);
  - stand-ins for runuser, gh, git ls-remote, chown and install that need no privileges and no network.
Nothing of a real host is touched and nothing public is called.
"""
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'ops' / 'preview-domain' / 'release.sh'
ENGINE = ROOT / 'runtime' / 'multipass'
AUTHORING_UNIT = 'parser-studio-preview-authoring.service'
MULTIPASS_UNIT = 'parser-studio-preview-multipass.service'

SYSTEMCTL = r'''#!/usr/bin/env python3
# Stand-in for systemctl: two units, each one real process. State: $PS_STUB/<unit>.json
import datetime, json, os, signal, subprocess, sys, time
stub = os.environ['PS_STUB']; units = json.load(open(stub + '/units.json'))
args = sys.argv[1:]; verb = next(a for a in args if not a.startswith('-'))
rest = args[args.index(verb) + 1:]; unit = next((a for a in rest if a.endswith('.service')), None)
def state():
    try: return json.load(open('%s/%s.json' % (stub, unit)))
    except OSError: return {'pid': 0, 'started': 0}
def alive(pid):
    if not pid: return False
    try:
        os.kill(pid, 0)
        return open('/proc/%d/stat' % pid).read().split(') ')[1][0] != 'Z'
    except OSError: return False
if verb == 'restart':
    old = state()['pid']
    if alive(old):
        os.kill(old, signal.SIGTERM)
        for _ in range(100):
            if not alive(old): break
            time.sleep(0.05)
        else: os.kill(old, signal.SIGKILL)
    spec = units[unit]; started = time.time()
    child = subprocess.Popen(spec['argv'], env={**os.environ, **spec['env']}, cwd=spec['cwd'], start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    json.dump({'pid': child.pid, 'started': started}, open('%s/%s.json' % (stub, unit), 'w'))
elif verb == 'is-active':
    ok = alive(state()['pid']); print('active' if ok else 'inactive'); sys.exit(0 if ok else 3)
elif verb == 'show':
    prop = rest[rest.index('-p') + 1]; now = state()
    if prop == 'MainPID': print(now['pid'] if alive(now['pid']) else 0)
    elif prop == 'ExecMainStartTimestamp' and os.path.exists(stub + '/no-start-time'): print('n/a')
    else: print(datetime.datetime.fromtimestamp(now['started'], datetime.timezone.utc).strftime('%a %Y-%m-%d %H:%M:%S.%f UTC'))
else: sys.exit('systemctl stand-in: ' + verb)
'''
RUNUSER = '#!/bin/sh\n# runuser -u <user> -- <command>: no user switch in the sandbox\nwhile [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n'
GH = '#!/bin/sh\n# gh api .../check-runs --jq ...: the check runs of the commit, as name, status, conclusion\ncat "$PS_STUB/check-runs.tsv"\n'
GIT = '#!/bin/sh\n# git ls-remote <url> refs/heads/main answers from a file; every other git command is the real one\nfor a in "$@"; do [ "$a" = ls-remote ] && { printf \'%s\\trefs/heads/main\\n\' "$(cat "$PS_STUB/main")"; exit 0; }; done\nexec "$PS_REAL_GIT" "$@"\n'
CHOWN = '#!/bin/sh\nexit 0\n'
INSTALL = r'''#!/usr/bin/env python3
# install without -o/-g (no privileges in the sandbox); every other option goes to the real install
import os, sys
args = sys.argv[1:]; kept = []
while args:
    a = args.pop(0)
    if a in ('-o', '-g'): args.pop(0)
    else: kept.append(a)
os.execv(os.environ['PS_REAL_INSTALL'], ['install'] + kept)
'''
BACKEND = '''// stand-in for the authoring backend of release %s
require('http').createServer((q, r) => { r.writeHead(q.url === '/health' ? 200 : 404, {'Content-Type': 'application/json'});
  r.end('{"status":"ok","release":"%s"}'); }).listen(Number(process.env.PARSER_BACKEND_PORT), '127.0.0.1');
'''
GREEN_RUNS = 'web-quality\tcompleted\tsuccess\nrelease-eligibility\tcompleted\tsuccess\nBrowser regression (shard 1/6)\tcompleted\tsuccess\n'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


class Sandbox:
    """A previous release that is installed and runs, and the built checkout of the commit to release."""

    def __init__(self, test):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix='ps-release-'))
        test.addCleanup(self.close)
        self.stub = self.dir / 'stub'; self.bin = self.dir / 'bin'
        self.web = self.dir / 'web'; self.backend = self.dir / 'backend'; self.multipass = self.dir / 'multipass'
        self.rollouts = self.dir / 'rollouts'
        for d in (self.stub, self.bin, self.web / 'assets', self.backend / 'dist' / 'src', self.backend / 'node_modules', self.rollouts):
            d.mkdir(parents=True)
        self.authoring_port, self.multipass_port = free_port(), free_port()
        self.public = PublicHost(self)
        self.origin = 'http://127.0.0.1:%d' % self.public.port
        # the tool under test: the committed text with a sandbox service set
        text = SCRIPT.read_text()
        for old, new in (
                ('WEB=/var/www/parser-studio-app\n', 'WEB=%s\n' % self.web),
                ('BACKEND=/opt/parser-studio-preview/backend\n', 'BACKEND=%s\n' % self.backend),
                ('MULTIPASS=/opt/parser-studio-preview/multipass\n', 'MULTIPASS=%s\n' % self.multipass),
                ('AUTHORING_PORT=4305\n', 'AUTHORING_PORT=%d\n' % self.authoring_port),
                ('MULTIPASS_PORT=4304\n', 'MULTIPASS_PORT=%d\n' % self.multipass_port),
                ('RUN_USER=aella\n', 'RUN_USER=ps-sandbox\n'),
                ('ORIGIN=https://$SITE\n', 'ORIGIN=%s\n' % self.origin),
                ('[ "$(id -u)" = 0 ] || { echo "need root"; exit 2; }\n', '')):
            if text.count(old) != 1:
                raise AssertionError('release.sh no longer has the line: ' + old.strip())
            text = text.replace(old, new)
        self.tool = self.dir / 'release.sh'
        self.tool.write_text(text)
        for name, body in (('systemctl', SYSTEMCTL), ('runuser', RUNUSER), ('gh', GH), ('git', GIT), ('chown', CHOWN), ('install', INSTALL)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        (self.stub / 'units.json').write_text(json.dumps({
            AUTHORING_UNIT: {'argv': ['node', str(self.backend / 'dist/src/mainline-authoring-server.js')], 'cwd': str(self.backend),
                             'env': {'PARSER_BACKEND_PORT': str(self.authoring_port)}},
            MULTIPASS_UNIT: {'argv': [sys.executable, str(self.multipass / 'multipass_preview_api.py'), '--port', str(self.multipass_port)],
                             'cwd': str(self.multipass), 'env': {'PARSER_STUDIO_TRUSTED_ORIGIN': 'https://app.parser.isoc.ooo'}},
        }))
        self.env = {**os.environ, 'PATH': '%s:%s' % (self.bin, os.environ['PATH']), 'PS_STUB': str(self.stub),
                    'PS_REAL_GIT': shutil.which('git'), 'PS_REAL_INSTALL': shutil.which('install'),
                    'PS_ROLLOUTS': str(self.rollouts), 'PS_CORE': str(self.dir), 'PYTHONDONTWRITEBYTECODE': '1'}
        self._candidate()
        self._previous_release()
        (self.stub / 'main').write_text(self.commit)
        (self.stub / 'check-runs.tsv').write_text(GREEN_RUNS)
        for unit, port in ((AUTHORING_UNIT, self.authoring_port), (MULTIPASS_UNIT, self.multipass_port)):
            subprocess.run([str(self.bin / 'systemctl'), 'restart', unit], env=self.env, check=True)
            self.wait_health(port)
        (self.release / 'baseline-before.txt').write_text('live index: %s\n' % sha(self.web / 'index.html'))
        (self.release / 'release.log').write_text('2026-01-01T00:00:00Z BUILD_OK (sandbox: the candidate was built by the test)\n')

    def _candidate(self):
        """Release B: a clean Git checkout with the built web, the backend and the engine of this repository."""
        staging = self.dir / 'candidate'
        (staging / 'dist/assets').mkdir(parents=True)
        (staging / 'dist/index.html').write_text('<title>release B</title><script src="assets/app-b.js"></script>\n')
        (staging / 'dist/assets/app-b.js').write_text('console.log("B")\n')
        (staging / 'backend/dist/src').mkdir(parents=True)
        (staging / 'backend/dist/src/mainline-authoring-server.js').write_text(BACKEND % ('B', 'B'))
        (staging / 'backend/package-lock.json').write_text(json.dumps({'packages': {'': {}, 'node_modules/x': {'version': '1.0.0'}}}))
        shutil.copytree(ENGINE, staging / 'runtime/multipass', ignore=shutil.ignore_patterns('__pycache__'))
        (staging / 'ops/preview-domain').mkdir(parents=True)
        shutil.copy(ROOT / 'ops/preview-domain/live_engine_check.py', staging / 'ops/preview-domain/')
        (staging / '.gitignore').write_text('__pycache__/\n')
        git = ['git', '-C', str(staging), '-c', 'user.name=test', '-c', 'user.email=test@example.invalid']
        subprocess.run(git + ['init', '-q'], check=True)
        subprocess.run(git + ['add', '-A'], check=True)
        subprocess.run(git + ['commit', '-q', '-m', 'release B'], check=True)
        self.commit = subprocess.run(git + ['rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip()
        self.release = self.rollouts / ('release-%s-sandbox' % self.commit[:7])
        self.release.mkdir()
        self.src = self.release / 'src'
        staging.rename(self.src)

    def _previous_release(self):
        """Release A, installed: other page, other backend, and an engine that answers with other bytes."""
        (self.web / 'index.html').write_text('<title>release A</title>\n')
        (self.web / 'assets/app-a.js').write_text('console.log("A")\n')
        (self.backend / 'dist/src/mainline-authoring-server.js').write_text(BACKEND % ('A', 'A'))
        (self.backend / 'node_modules/.package-lock.json').write_text(json.dumps({'packages': {'node_modules/x': {'version': '1.0.0'}}}))
        shutil.copytree(self.src / 'runtime/multipass', self.multipass)
        api = self.multipass / 'multipass_preview_api.py'
        compact, spaced = "separators=(',',':')", "separators=(', ',': ')"
        if api.read_text().count(compact) != 1:
            raise AssertionError('the engine handler no longer serializes with ' + compact)
        api.write_text(api.read_text().replace(compact, spaced))
        self.old_engine = api.read_bytes()

    def wait_health(self, port):
        for _ in range(100):
            try:
                with urllib.request.urlopen('http://127.0.0.1:%d/health' % port, timeout=2) as answer:
                    if answer.status == 200:
                        return
            except OSError:
                time.sleep(0.1)
        raise AssertionError('no service on port %d' % port)

    def run(self, step, commit=None):
        done = subprocess.run(['bash', str(self.tool), commit or self.commit, step], env=self.env, cwd=str(self.dir),
                              capture_output=True, text=True, timeout=180)
        return done.returncode, done.stdout + done.stderr

    def must(self, step):
        """Run a step that has to succeed; a failure shows everything the tool said."""
        code, out = self.run(step)
        if code != 0:
            raise AssertionError('%s failed with %d:\n%s' % (step, code, out))
        return out

    def pid(self, unit):
        return json.loads((self.stub / (unit + '.json')).read_text())['pid']

    def backend_release(self):
        with urllib.request.urlopen('http://127.0.0.1:%d/health' % self.authoring_port, timeout=5) as answer:
            return json.load(answer)['release']

    def engine_is_release_b(self):
        return (self.multipass / 'multipass_preview_api.py').read_bytes() == (self.src / 'runtime/multipass/multipass_preview_api.py').read_bytes()

    def page(self):
        return (self.web / 'index.html').read_text()

    def installed(self):
        """Which release each part is, as a user of the service set would find it."""
        return ('B' if 'release B' in self.page() else 'A', self.backend_release(), 'B' if self.engine_is_release_b() else 'A')

    def close(self):
        self.public.close()
        for unit in (AUTHORING_UNIT, MULTIPASS_UNIT):
            try:
                os.kill(self.pid(unit), signal.SIGKILL)
            except (OSError, ValueError):
                pass
        shutil.rmtree(self.dir, ignore_errors=True)


class PublicHost:
    """The public host of the sandbox: the web root, the two engine routes, and 422 for a large package request."""

    def __init__(self, box):
        self.replace_page = None  # set to bytes: the proxy serves a page other than the installed one
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                name = self.path.lstrip('/') or 'index.html'
                target = box.web / name
                if name == 'index.html' and outer.replace_page is not None:
                    return self._send(200, outer.replace_page)
                self._send(200, target.read_bytes()) if target.is_file() else self._send(404, b'')

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if self.path.startswith('/api/v1/multipass/'):
                    request = urllib.request.Request('http://127.0.0.1:%d%s' % (box.multipass_port, self.path), data=body, method='POST',
                                                     headers={'Content-Type': 'application/json', 'Origin': self.headers.get('Origin', '')})
                    try:
                        with urllib.request.urlopen(request, timeout=20) as answer:
                            return self._send(answer.status, answer.read())
                    except urllib.error.HTTPError as error:
                        return self._send(error.code, error.read())
                    except OSError:
                        return self._send(502, b'')
                self._send(422 if self.path == '/api/v1/parser-pairs/package' else 404, b'{}')

            def _send(self, status, payload):
                self.send_response(status)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@unittest.skipUnless(shutil.which('node') and shutil.which('curl') and shutil.which('bash'), 'needs node, curl and bash')
class ReleaseContract(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox(self)

    def test_apply_installs_every_part_and_restarts_what_changed(self):
        box = self.box
        before = box.pid(AUTHORING_UNIT), box.pid(MULTIPASS_UNIT)
        self.assertEqual(box.installed(), ('A', 'A', 'A'))
        code, out = box.run('apply')
        self.assertEqual(code, 0, out)
        self.assertIn('APPLY_OK', out)
        self.assertEqual(box.installed(), ('B', 'B', 'B'))
        self.assertNotEqual(box.pid(AUTHORING_UNIT), before[0])
        self.assertNotEqual(box.pid(MULTIPASS_UNIT), before[1])
        self.assertTrue((box.web / 'assets/app-a.js').is_file(), 'assets of the previous release stay')
        code, out = box.run('status')
        self.assertEqual(code, 0, out)

    def test_rollback_makes_the_previous_release_run_again(self):
        box = self.box
        box.must('apply')
        applied = box.pid(AUTHORING_UNIT), box.pid(MULTIPASS_UNIT)
        code, out = box.run('rollback')
        self.assertEqual(code, 0, out)
        self.assertIn('ROLLBACK_OK', out)
        self.assertEqual(box.installed(), ('A', 'A', 'A'))
        self.assertEqual((box.multipass / 'multipass_preview_api.py').read_bytes(), box.old_engine)
        self.assertNotEqual(box.pid(AUTHORING_UNIT), applied[0])
        self.assertNotEqual(box.pid(MULTIPASS_UNIT), applied[1])
        # and the release can be applied again afterwards
        code, out = box.run('apply')
        self.assertEqual(code, 0, out)
        self.assertEqual(box.installed(), ('B', 'B', 'B'))

    def test_a_second_apply_does_not_replace_the_rollback_material(self):
        # Audit F-01: apply, apply again, rollback left web and engine at the new release and the backend at the old one.
        box = self.box
        box.must('apply')
        code, out = box.run('apply')
        self.assertEqual(code, 0, out)
        self.assertEqual(box.installed(), ('B', 'B', 'B'))
        code, out = box.run('rollback')
        self.assertEqual(code, 0, out)
        self.assertEqual(box.installed(), ('A', 'A', 'A'), 'every part is the previous release, not a mixture')

    def test_rollback_of_a_release_that_is_not_applied_changes_nothing(self):
        box = self.box
        code, out = box.run('rollback')
        self.assertNotEqual(code, 0, out)
        self.assertNotIn('ROLLBACK_OK', out)
        self.assertEqual(box.installed(), ('A', 'A', 'A'))
        # also after it was applied and rolled back once: the material is used up
        box.must('apply')
        box.must('rollback')
        pids = box.pid(AUTHORING_UNIT), box.pid(MULTIPASS_UNIT)
        code, out = box.run('rollback')
        self.assertNotEqual(code, 0, out)
        self.assertEqual((box.pid(AUTHORING_UNIT), box.pid(MULTIPASS_UNIT)), pids, 'nothing was restarted')

    def test_the_stamp_names_what_is_installed_after_a_rollback(self):
        # Audit F-04: after a rollback the files of the previous release carried the name of the release rolled back.
        box = self.box
        box.must('apply')
        self.assertIn(box.commit, (box.backend / 'dist/.parser-studio-release').read_text())
        box.must('rollback')
        for part in (box.backend / 'dist', box.multipass):
            self.assertNotIn(box.commit, (part / '.parser-studio-release').read_text())

    def test_a_failed_check_after_the_install_restores_the_previous_release(self):
        box = self.box
        box.public.replace_page = b'<title>rewritten by a proxy</title>\n'   # the public page is not the built file
        code, out = box.run('apply')
        self.assertNotEqual(code, 0, out)
        self.assertNotIn('APPLY_OK', out)
        self.assertIn('ROLLBACK', out)
        self.assertEqual(box.installed(), ('A', 'A', 'A'))

    def test_a_commit_that_is_not_main_or_has_unfinished_checks_is_not_applied(self):
        box = self.box
        (box.stub / 'check-runs.tsv').write_text(GREEN_RUNS.replace('web-quality\tcompleted\tsuccess', 'web-quality\tin_progress\tnone'))
        code, out = box.run('apply')
        self.assertNotEqual(code, 0, out)
        self.assertEqual(box.installed(), ('A', 'A', 'A'))
        (box.stub / 'check-runs.tsv').write_text(GREEN_RUNS.replace('release-eligibility\tcompleted\tsuccess\n', ''))
        self.assertNotEqual(box.run('apply')[0], 0, 'a release gate that did not run')
        (box.stub / 'check-runs.tsv').write_text(GREEN_RUNS)
        (box.stub / 'main').write_text('0' * 40)
        code, out = box.run('apply')
        self.assertNotEqual(code, 0, out)
        self.assertEqual(box.installed(), ('A', 'A', 'A'))

    def test_status_refuses_a_process_that_still_holds_the_previous_engine(self):
        # Audit AUD-01: files on disk are the release, the process answers its health check, and runs older code.
        box = self.box
        box.must('apply')
        api = box.multipass / 'multipass_preview_api.py'
        released = api.read_bytes(); times = api.stat()
        api.write_bytes(box.old_engine)
        subprocess.run([str(box.bin / 'systemctl'), 'restart', MULTIPASS_UNIT], env=box.env, check=True)
        box.wait_health(box.multipass_port)
        api.write_bytes(released)
        os.utime(api, ns=(times.st_atime_ns, times.st_mtime_ns))             # even the modification time is the old one
        self.assertEqual(box.installed(), ('B', 'B', 'B'))
        code, out = box.run('status')
        self.assertNotEqual(code, 0, out)
        self.assertIn('CHECK_FAIL', out)
        self.assertIn('does not answer as the candidate code does', out)

    def test_status_refuses_a_second_process_over_the_same_files(self):
        # Audit AUD-02: a process outside the managed units keeps whatever code it loaded.
        box = self.box
        box.must('apply')
        extra = subprocess.Popen([sys.executable, 'multipass_preview_api.py', '--port', str(free_port())], cwd=str(box.multipass),
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (extra.kill(), extra.wait()))
        time.sleep(0.5)
        code, out = box.run('status')
        self.assertNotEqual(code, 0, out)
        self.assertIn('processes outside ' + MULTIPASS_UNIT, out)
        self.assertIn(str(extra.pid), out)

    def test_status_refuses_a_backend_that_was_swapped_behind_the_tool(self):
        # Second audit R-1: a prepared tree renamed into place keeps the times of its files. The process answers as
        # the previous release, the files are the release, and nothing compares the answers of the backend.
        box = self.box
        box.must('apply')
        dist, released, older = box.backend / 'dist', box.backend / 'released', box.backend / 'older'
        shutil.copytree(dist, older)
        (older / 'src/mainline-authoring-server.js').write_text(BACKEND % ('A', 'A'))
        dist.rename(released)
        older.rename(dist)
        subprocess.run([str(box.bin / 'systemctl'), 'restart', AUTHORING_UNIT], env=box.env, check=True)
        box.wait_health(box.authoring_port)
        dist.rename(older)
        released.rename(dist)                                # the files are the release again, with their old times
        self.assertEqual(box.backend_release(), 'A')
        self.assertIn('release B', (dist / 'src/mainline-authoring-server.js').read_text())
        code, out = box.run('status')
        self.assertNotEqual(code, 0, out)
        self.assertIn(AUTHORING_UNIT, out)
        self.assertIn('last changed', out)

    def test_a_start_time_that_cannot_be_read_is_a_failure(self):
        box = self.box
        box.must('apply')
        (box.stub / 'no-start-time').write_text('')
        code, out = box.run('status')
        self.assertNotEqual(code, 0, out)
        self.assertIn('cannot be read', out)

    def test_rollback_is_refused_while_a_newer_release_is_the_installed_one(self):
        # Releases go back in order: this one is not the installed one, and it is not an unfinished apply either.
        box = self.box
        box.must('apply')
        (box.rollouts / 'current-release').write_text('release-of-a-later-commit\n')
        pids = box.pid(AUTHORING_UNIT), box.pid(MULTIPASS_UNIT)
        code, out = box.run('rollback')
        self.assertNotEqual(code, 0, out)
        self.assertIn('ROLLBACK_REFUSED', out)
        self.assertEqual(box.installed(), ('B', 'B', 'B'))
        self.assertEqual((box.pid(AUTHORING_UNIT), box.pid(MULTIPASS_UNIT)), pids)

    def test_rollback_does_not_report_ok_when_the_kept_backend_is_not_the_one_replaced(self):
        box = self.box
        box.must('apply')
        kept = next(box.backend.glob('.dist_rollback_*')) / 'src/mainline-authoring-server.js'
        kept.write_text(kept.read_text() + '// changed after it was kept\n')
        code, out = box.run('rollback')
        self.assertNotEqual(code, 0, out)
        self.assertNotIn('ROLLBACK_OK', out)
        self.assertIn('the backend is not the one this release replaced', out)

    def test_rollback_does_not_report_ok_when_a_kept_engine_file_is_not_the_one_replaced(self):
        box = self.box
        box.must('apply')
        kept = box.release / 'rollback/multipass/multipass_preview_api.py'
        kept.write_text(kept.read_text() + '# changed after it was kept\n')
        code, out = box.run('rollback')
        self.assertNotEqual(code, 0, out)
        self.assertNotIn('ROLLBACK_OK', out)
        self.assertIn('the engine files are not the ones this release replaced', out)

    def test_a_rollback_that_was_interrupted_can_be_finished(self):
        # Second audit R-4: the automatic rollback of a failed apply could not confirm the previous page, and the
        # operator's rollback was then refused although nothing newer was installed.
        box = self.box
        box.public.replace_page = b'<title>rewritten by a proxy</title>\n'
        code, out = box.run('apply')
        self.assertNotEqual(code, 0, out)
        self.assertIn('ROLLBACK_INCOMPLETE', out)
        box.public.replace_page = None
        code, out = box.run('rollback')
        self.assertEqual(code, 0, out)
        self.assertIn('ROLLBACK_OK', out)
        self.assertEqual(box.installed(), ('A', 'A', 'A'))
        code, out = box.run('rollback')
        self.assertNotEqual(code, 0, out)                    # used once

    def test_status_without_the_candidate_does_not_report_ok(self):
        # Audit F-06: with no checkout of the commit nothing was compared, and the answer was STATUS_OK.
        box = self.box
        code, out = box.run('status', commit='1' * 40)
        self.assertNotEqual(code, 0, out)
        self.assertNotIn('STATUS_OK', out)


if __name__ == '__main__':
    unittest.main()
