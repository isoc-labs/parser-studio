"""Negative controls for the independent mapping native gate, not product evidence."""
import contextlib
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "verification"))
gate = importlib.import_module("mapping-native-gate")

def make_record(expected):
    record = {}
    for path, value in expected.items():
        parts = path.split("/")
        parent = record
        for key in parts[:-1]:
            parent = parent.setdefault(key, {})
        parent[parts[-1]] = value
    return record

def fake_output():
    return {"ruby": "2.4.9", "results": {
        f"mapping-{scenario}-{i}": {"calls": [[None, make_record(c["required"])]]}
        for scenario, spec in gate.SCENARIOS.items()
        for i, c in enumerate(spec["cases"])
    }}

class MappingNativeGateTests(unittest.TestCase):
    def check(self, output):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "output.json"
            path.write_text(json.dumps(output, ensure_ascii=False))
            with contextlib.redirect_stdout(io.StringIO()):
                gate.compare(path)

    def test_complete_fixture_shape_passes(self):
        self.check(fake_output())

    def test_source_value_loss_and_unauthorized_mapping_are_detected(self):
        output = fake_output()
        record = output["results"]["mapping-assisted-unmapped-0"]["calls"][0][1]
        del record["Demo"]["src_ip"]
        with self.assertRaisesRegex(ValueError, "MAPPING_NATIVE_VALUE"):
            self.check(output)
        output = fake_output()
        output["results"]["mapping-assisted-unmapped-0"]["calls"][0][1]["srcip"] = "198.51.100.10"
        with self.assertRaisesRegex(ValueError, "MAPPING_NATIVE_UNAPPROVED_FIELD"):
            self.check(output)

    def test_placeholder_namespace_is_rejected(self):
        output = fake_output()
        record = output["results"]["mapping-assisted-unmapped-0"]["calls"][0][1]
        record["Demo Local Draft"] = {"unexpected": "value"}
        with self.assertRaisesRegex(ValueError, "MAPPING_NATIVE_PLACEHOLDER_NAMESPACE"):
            self.check(output)

    def test_cross_event_scope_and_port_type_are_detected(self):
        output = fake_output()
        output["results"]["mapping-jsonata-event-0"]["calls"][0][1]["event_name"] = "Login"
        with self.assertRaisesRegex(ValueError, "MAPPING_NATIVE_UNAPPROVED_FIELD"):
            self.check(output)
        output = fake_output()
        output["results"]["mapping-manual-event-0"]["calls"][0][1]["srcport"] = "51522"
        with self.assertRaisesRegex(ValueError, "MAPPING_NATIVE_VALUE"):
            self.check(output)

    def test_missing_or_duplicate_event_and_wrong_runtime_are_detected(self):
        output = fake_output()
        output["results"]["mapping-manual-event-0"]["calls"].append([None, None])
        with self.assertRaisesRegex(ValueError, "MAPPING_NATIVE_EVENT_COUNT"):
            self.check(output)
        output = fake_output()
        del output["results"]["mapping-manual-event-0"]
        with self.assertRaises(KeyError):
            self.check(output)
        output = fake_output()
        output["ruby"] = "3.2.11"
        with self.assertRaisesRegex(ValueError, "MAPPING_NATIVE_RUBY_VERSION"):
            self.check(output)

if __name__ == "__main__":
    unittest.main()
