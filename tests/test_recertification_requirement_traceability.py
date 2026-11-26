"""Evidence index completeness, not a product acceptance assertion."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs/verification/20261126-requirement-traceability.json"

class RequirementTraceability(unittest.TestCase):
    def test_all_functional_requirements_have_exactly_one_disposition(self):
        data = json.loads(INDEX.read_text())
        self.assertEqual(data["contract"], "parser-studio.recertification-requirement-traceability.v1")
        source = ROOT / data["source"]
        ids = re.findall(r"^\| (F[0-9]+[A-Z]?) \|", source.read_text(), re.M)
        rows = data["requirements"]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sorted(ids), sorted(r["id"] for r in rows))
        for row in rows:
            with self.subTest(requirement=row["id"]):
                self.assertIn(row["scope"], ("ACTIVE", "CONTEXTUAL", "GATED", "DEFERRED"))
                self.assertIn(row["status"], ("PARTIAL", "UNVERIFIED"))
                self.assertTrue(row["gap"].strip())
                if row["status"] == "PARTIAL":
                    self.assertTrue(row["implementation"])
                    self.assertTrue(row["evidence"])
                if row["scope"] == "ACTIVE":
                    self.assertTrue(row["implementation"])
                for path in row["implementation"] + row["evidence"]:
                    self.assertTrue((ROOT / path).is_file(), path)
                    self.assertNotIn("legacy-removed-ui", path)
        for path in data["scopeAuthority"]:
            self.assertTrue((ROOT / path).is_file(), path)

if __name__ == "__main__":
    unittest.main()
