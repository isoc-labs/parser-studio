"""The release check that a running Multi-Pass engine executes the code of the checkout (ops/preview-domain/
live_engine_check.py; independent audit AUD-01 of 2026-11-25).

A process that kept an older engine in memory answered /health with 200 while its installed files matched the build.
The check compares the response bytes of the running service with the bytes the engine of the checkout computes.
These tests start the real handler and a stand-in for a stale process on loopback ports; nothing public is called.
"""
import json
import pathlib
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECK = ROOT / 'ops' / 'preview-domain' / 'live_engine_check.py'
sys.path.insert(0, str(ROOT / 'runtime' / 'multipass'))

from multipass_preview_api import Handler, preview, preview_batch  # noqa: E402

ORIGIN = 'http://127.0.0.1:5180'


class StaleEngine(BaseHTTPRequestHandler):
    """Healthy, same routes, valid JSON of the same contract: but one family is read as an older engine read it."""

    def do_GET(self):
        self._send(200, b'{"status":"ok","contract":"parser-studio.multipass-source-preview.v0.1"}')

    def do_POST(self):
        raw = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['raw']
        if raw.startswith('srcip=10.0.0.1,'):
            # The comma separated pairs read as other text: a valid answer of the same contract, but not this engine's.
            result = preview('srcip=10.0.0.1 dstip=10.0.0.2 action=deny')
        else:
            result = preview_batch(raw) if self.path.endswith('preview-batch') else preview(raw)
        self._send(200, json.dumps(result, ensure_ascii=True, separators=(',', ':')).encode())

    def _send(self, status, payload):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class Quiet(Handler):
    def log_message(self, *args):
        pass


def run_check(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return subprocess.run([sys.executable, str(CHECK), '--source', str(ROOT),
                               '--url', 'http://127.0.0.1:%d' % server.server_port, '--origin', ORIGIN],
                              capture_output=True, text=True, timeout=120)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class LiveEngineCheck(unittest.TestCase):
    def test_engine_of_the_checkout_is_accepted(self):
        result = run_check(Quiet)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ENGINE_CHECK_OK', result.stdout)
        self.assertNotIn('DIFFERENT', result.stdout)

    def test_healthy_process_with_an_older_engine_is_refused(self):
        result = run_check(StaleEngine)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('DIFFERENT comma_kv', result.stdout)
        self.assertIn('ENGINE_CHECK_FAIL 1 of', result.stdout)

    def test_unreachable_service_is_a_failure_not_a_pass(self):
        result = subprocess.run([sys.executable, str(CHECK), '--source', str(ROOT), '--url', 'http://127.0.0.1:9',
                                 '--origin', ORIGIN], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('not reachable', result.stdout)

    def test_a_directory_without_an_engine_is_a_usage_error(self):
        result = subprocess.run([sys.executable, str(CHECK), '--source', str(ROOT / 'docs'), '--url', 'http://127.0.0.1:9',
                                 '--origin', ORIGIN], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
