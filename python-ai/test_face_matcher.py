import unittest
import subprocess
import json
import sys
from pathlib import Path

CLI = Path(__file__).resolve().parent / "face_match_cli.py"

def compare(payload):
    result = subprocess.run(
        [sys.executable, str(CLI)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30
    )
    return json.loads(result.stdout)

class FaceMatcherTests(unittest.TestCase):

    def test_invalid_images(self):
        result = compare({
            "enrolled": "invalid",
            "camera": "invalid"
        })
        self.assertEqual(result["status"], "inconclusive")

    def test_empty_images(self):
        result = compare({
            "enrolled": "",
            "camera": ""
        })
        self.assertEqual(result["status"], "inconclusive")

    def test_missing_reference(self):
        result = compare({
            "camera": "invalid"
        })
        self.assertEqual(result["status"], "inconclusive")

if __name__ == "__main__":
    unittest.main(verbosity=2)
