"""One deployment contract for one service (independent audit AUD-01, AUD-02 of 2026-11-25).

The Development Preview ran two Multi-Pass processes, one per public host, from the same files. The release tooling
knew only one of them, so an update replaced the files, restarted one process and left the other running the old
code: the second host answered with an older engine although every file hash matched.

The structure is now one public host, one web root, one authoring backend and one Multi-Pass engine, and the files
below must describe exactly that set. These tests read the committed files; they start nothing and change nothing.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / 'ops' / 'preview-domain'
SITE = 'app.parser.isoc.ooo'
RETIRED = 'app.parser.xdr.ooo'


def read(name: str) -> str:
    return (OPS / name).read_text()


class SingleServiceContract(unittest.TestCase):
    def test_one_public_host_and_one_upstream_per_part(self):
        self.assertFalse((OPS / 'nginx-app.parser.xdr.ooo.conf').exists(), 'the retired host still has a site file')
        site = read('nginx-app.parser.isoc.ooo.conf')
        self.assertEqual(set(re.findall(r'server_name\s+([^;]+);', site)), {SITE})
        self.assertEqual(set(re.findall(r'proxy_pass\s+http://127\.0\.0\.1:(\d+);', site)), {'4304', '4305'})
        # The origin gate of the site and the trusted origin of the engine are the same single origin.
        self.assertIn('"POST|https://' + SITE + '" 0;', site)
        self.assertNotIn('sub_filter', site, 'the served page must be the built file, byte for byte')

    def test_units_are_the_two_services_of_that_host(self):
        units = sorted(path.name for path in OPS.glob('*.service'))
        self.assertEqual(units, ['parser-studio-preview-authoring.service', 'parser-studio-preview-multipass.service'])
        engine = read('parser-studio-preview-multipass.service')
        self.assertIn('Environment=PARSER_STUDIO_TRUSTED_ORIGIN=https://' + SITE, engine)
        self.assertIn('multipass_preview_api.py --port 4304', engine)
        self.assertIn('Environment=PARSER_BACKEND_PORT=4305', read('parser-studio-preview-authoring.service'))

    def test_release_tool_names_the_same_service_set(self):
        tool = read('release.sh')
        for line in ('REPO=isoc-labs/parser-studio', 'SITE=' + SITE,
                     'AUTHORING_UNIT=parser-studio-preview-authoring.service', 'AUTHORING_PORT=4305',
                     'MULTIPASS_UNIT=parser-studio-preview-multipass.service', 'MULTIPASS_PORT=4304'):
            self.assertIn(line, tool)
        # The steps of the contract: nothing is called deployed on file hashes or on HTTP 200 alone.
        for step in ('require_ci_success', 'require_template_approval', 'require_managed_processes',
                     'require_process_newer_than_files', 'live_engine_check.py', 'rollback'):
            self.assertIn(step, tool)
        self.assertFalse((OPS / 'release_web.sh').exists(), 'a second, web-only release path is a second contract')
        self.assertFalse((OPS / 'deploy_web.sh.tpl').exists())

    def test_no_file_of_the_contract_serves_or_updates_the_retired_host(self):
        for path in sorted(OPS.iterdir()):
            if path.is_dir():
                continue
            text = path.read_text()
            self.assertNotIn('multipass-isoc', text, path.name)
            self.assertNotIn(':4306', text, path.name)
            for line in text.splitlines():
                if RETIRED in line:
                    self.assertIn(path.name, ('README.md', 'UPDATE_RUNBOOK.md'), path.name)
                    self.assertRegex(line, r'retired|no longer|was served', path.name + ': ' + line)

    def test_runbook_describes_the_release_tool_and_the_running_process_checks(self):
        runbook = read('UPDATE_RUNBOOK.md')
        for text in ('https://' + SITE, 'isoc-labs/parser-studio', 'release.sh', 'build', 'apply', 'verify', 'rollback',
                     'process', 'deployment-receipt.json'):
            self.assertIn(text, runbook)


if __name__ == '__main__':
    unittest.main()
