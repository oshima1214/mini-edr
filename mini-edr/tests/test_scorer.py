import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scorer


def load_json(relative_path):
    with (ROOT / relative_path).open("r", encoding="utf-8") as file:
        return json.load(file)


class ScorerTest(unittest.TestCase):
    def setUp(self):
        self.rules = load_json("rules.json")

    def test_suspicious_office_macro_is_high_risk(self):
        events = load_json("events/suspicious_office_macro.json")
        result = scorer.score(events, self.rules)

        self.assertGreaterEqual(result["score"], 80)
        self.assertEqual(result["severity"], "HIGH")
        self.assertGreaterEqual(len(result["findings"]), 4)

    def test_normal_dev_workflow_is_info(self):
        events = load_json("events/normal_dev_workflow.json")
        result = scorer.score(events, self.rules)

        self.assertLess(result["score"], 20)
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()

