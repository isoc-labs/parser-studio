"""Baseline document scope census; not a semantic acceptance oracle."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class DocumentDispositionTests(unittest.TestCase):
    def test_every_baseline_document_and_contract_has_one_disposition(self):
        inventory=json.loads((ROOT/"docs/verification/20261126-recertification-inventory.json").read_text())
        reviewed=json.loads((ROOT/"docs/verification/20261126-document-dispositions.json").read_text())
        manifest=json.loads((ROOT/".engineering/specification.json").read_text())
        self.assertEqual(inventory["baseline"],reviewed["baseline"])
        originals={r["path"]:r["sha256"] for r in inventory["items"]}
        rows=reviewed["items"]
        self.assertEqual(len(rows),len(originals))
        self.assertEqual(originals,{r["path"]:r["baselineSha256"] for r in rows})
        for row in rows:
            with self.subTest(path=row["path"]):
                self.assertTrue(row["reason"])
                self.assertGreater(row["baselineLines"],0)
                if row["path"].startswith("contracts/"):
                    self.assertEqual(row["disposition"],"executable_or_oracle")
                else:
                    self.assertEqual(row["disposition"],manifest["documents"][row["path"]]["status"])
                if row["path"].startswith("docs/verification/"):
                    self.assertEqual(row["disposition"],"historical")
        self.assertEqual({p for p,d in manifest["documents"].items() if d["status"]=="active"},
            {"docs/02_WEB_UI_SPEC.md","docs/03_FUNCTIONAL_REQUIREMENTS.md","docs/14_TWO_PATH_PRODUCT_V2.md"})

if __name__=="__main__":
    unittest.main()
