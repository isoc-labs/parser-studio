"""Bounded requirements-first navigation/scope checks. Static, not browser E2E."""
import json
import hashlib
import shutil
import tempfile
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

    def test_vision_language_and_architecture_are_current(self):
        vision = read("docs/01_PRODUCT_VISION.md")
        self.assertNotIn("bilingual-ready Web UI", vision)
        self.assertIn("Authored product UI is English", vision)
        architecture = read("docs/04_ARCHITECTURE.md")
        self.assertNotIn("initial repository is docs only", architecture)
        self.assertNotIn("| Web Workbench |", architecture)
        scope = read("docs/14_TWO_PATH_PRODUCT_V2.md")
        self.assertIn("base64 (not encryption)", scope)
        self.assertIn("pinned static cost proof", scope)

    def test_old_functional_requirements_have_explicit_dispositions(self):
        text = read("docs/03_FUNCTIONAL_REQUIREMENTS.md")
        self.assertIn("Initial requirement disposition", text)
        for ident in [f"F{i:02}" for i in range(1, 27)] + ["F03A"]:
            self.assertRegex(text, r"\b" + ident + r"\b")
        self.assertNotIn("| F12 | P0 | Test Lab |", text)
        self.assertNotIn("| F17 | P1 | Import existing parser |", text)
        self.assertIn("Parsing correctness and source-value accounting precede mapping success.", text)

    def test_real_inventory_negative_controls(self):
        manifest = json.loads(read(".engineering/specification.json"))
        required_files = set(manifest["documents"])
        for req in manifest["requirements"]:
            required_files.add(req["source"]["path"])
            required_files.update(x["path"] for key in ("implementation", "tests") for x in req[key])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for filename in required_files:
                target = root / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / filename, target)
            path = root / ".engineering/specification.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            def check(data, expected):
                path.write_text(json.dumps(data), encoding="utf-8")
                result = subprocess.run([sys.executable, str(ROOT / "tools/specification_contract.py"),
                    "--root", str(root), "--require-implemented"], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0 if expected is None else 1, result.stdout+result.stderr)
                if expected:
                    self.assertIn(expected, result.stderr)
            check(manifest, None)
            omitted = json.loads(json.dumps(manifest))
            omitted["requirements"] = [r for r in omitted["requirements"] if r["id"] != "PS-007"]
            check(omitted, "declared requirement missing trace: PS-007")
            extra = root / "docs/03_DUPLICATE_SCOPE.md"
            extra.write_text("Unclassified competing scope", encoding="utf-8")
            check(manifest, "unclassified specification files")
            extra.unlink()
            source = root / "docs/03_FUNCTIONAL_REQUIREMENTS.md"
            before = source.read_bytes()
            source.write_bytes(before.replace(b"default parser listener port is 6801", b"default parser listener port is 7801"))
            changed = json.loads(json.dumps(manifest))
            changed["documents"]["docs/03_FUNCTIONAL_REQUIREMENTS.md"]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            check(changed, "PS-007 source: marker missing")
            source.write_bytes(before)
            code = root / "src/guided/contract.ts"
            code.write_bytes(code.read_bytes().replace(b"DEFAULT_PARSER_LISTENER_PORT = 6801", b"DEFAULT_PARSER_LISTENER_PORT = 7801"))
            check(manifest, "PS-007 implementation: marker missing")

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
