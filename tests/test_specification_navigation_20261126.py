"""Bounded requirements-first navigation/scope checks. Static, not browser E2E."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


class SpecificationNavigationContract(unittest.TestCase):
    def test_two_creation_modes(self):
        ui = read("docs/02_WEB_UI_SPEC.md")
        self.assertIn("The only creation methods are Auto Parser and ChatGPT Assisted Parser.", ui)
        self.assertNotIn("**Workbench** — main 3-pane editing flow", ui)
        app = read("src/App.tsx")
        self.assertIn("type Workspace='auto'|'chatgpt';", app)
        self.assertIn("<span>Auto Parser</span>", app)
        self.assertIn("<span>ChatGPT Assisted Parser</span>", app)

    def test_four_ordered_stages(self):
        self.assertIn("Auto Parser follows Add Logs → Review Fields → Map Fields → Create Parser.", read("docs/02_WEB_UI_SPEC.md"))
        self.assertNotIn("Add Logs → Fix Problems → Test & Create", read("docs/14_TWO_PATH_PRODUCT_V2.md"))
        self.assertIn("const STEPS=['Add Logs','Review Fields','Map Fields','Create Parser'] as const;",
                      read("src/guided/AutoParser.tsx"))

    def test_target_actions_excluded(self):
        scope = read("docs/14_TWO_PATH_PRODUCT_V2.md")
        self.assertIn("The current product excludes server-operated Test Lab recovery/evidence, DP parser upload/apply, sensor replay/sending and Interflow lookup/verification.", scope)
        self.assertNotIn("status of DP Apply, Sensor Replay and Interflow verification", scope)
        self.assertNotIn("A server-side Test Lab session is not terminated", scope)
        self.assertIn("ordinary Auto Parser review never exposes Test Lab, Interflow or sensor commands",
                      read("tests/evidence-recovery.spec.ts"))
        self.assertIn("advanced={false}", read("src/App.tsx"))

    def test_explicit_first_party_transfer_not_automatic_llm(self):
        scope = read("docs/14_TWO_PATH_PRODUCT_V2.md")
        self.assertIn("Typing and browser previews stay in the browser; explicit Analyze Logs sends the original sample to the same Parser Studio server for Multi-Pass analysis. No automatic source transfer to ChatGPT.", scope)
        self.assertNotIn("analyze all events locally", scope)
        self.assertIn("Clicking Analyze Logs sends the original sample to this Parser Studio server",
                      read("src/App.tsx"))
        self.assertIn("body:JSON.stringify({raw})", read("src/guided/multipassPreviewClient.ts"))
        self.assertIn("MANUAL COPY & PASTE", read("src/guided/ChatGPTAssist.tsx"))

    def test_local_replay_is_not_sensor_replay(self):
        self.assertIn("The optional browser-only synthetic replay preview never sends logs to a sensor or starts a server session.", read("docs/14_TWO_PATH_PRODUCT_V2.md"))
        self.assertIn("<AutoParserLocalReplay sample={sample} draft={draft}/>",
                      read("src/guided/AutoParser.tsx"))
        replay = read("src/guided/AutoParserLocalReplay.tsx")
        self.assertIn("Validate the *entire* current sample", replay)
        self.assertIn("return ()=>stopTimer();", replay)
        self.assertIn("does not upload, store, or transmit these events.", replay)
        self.assertIn("This local preview is not available for mixed or multi-line parser formats.", replay)

    def test_inventory_and_traceability(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/specification_contract.py"), "--root", str(ROOT),
             "--manifest", ".engineering/specification.json", "--require-implemented"],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SPECIFICATION_STRUCTURE=PASS", result.stdout)
        self.assertIn("SEMANTIC_CONSISTENCY=UNVERIFIED", result.stdout)
        self.assertIn("AUTHORIZES_RELEASE=NO", result.stdout)


if __name__ == "__main__":
    unittest.main()
