import unittest
import base64
import json
import subprocess
import sys
from pathlib import Path

import cv2
import numpy as np

ENGINE = Path(__file__).resolve().parent / "face_engine.py"

def run_engine(payload):
    result = subprocess.run(
        [sys.executable, str(ENGINE)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=30
    )

    return json.loads(result.stdout)

class FaceEngineTests(unittest.TestCase):

    def test_blank_image_rejected(self):
        image = np.zeros((480, 640, 3), dtype=np.uint8)
        success, encoded = cv2.imencode(".jpg", image)
        self.assertTrue(success)

        result = run_engine({
            "mode": "inspect",
            "image": base64.b64encode(encoded).decode()
        })

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["faceCount"], 0)

    def test_invalid_image_not_accepted(self):
        result = run_engine({
            "mode": "inspect",
            "image": "invalid-image-data"
        })

        self.assertNotEqual(result["status"], "passed")

    def test_empty_image_not_accepted(self):
        result = run_engine({
            "mode": "inspect",
            "image": ""
        })

        self.assertNotEqual(result["status"], "passed")

    def test_missing_camera_frames_rejected(self):
        result = run_engine({
            "mode": "liveness",
            "frames": []
        })

        self.assertEqual(result["status"], "failed")

    def test_invalid_camera_frames_not_accepted(self):
        result = run_engine({
            "mode": "liveness",
            "frames": ["invalid", "invalid", "invalid"]
        })

        self.assertNotEqual(result["status"], "passed")

if __name__ == "__main__":
    unittest.main(verbosity=2)
