import base64
import io
import json
import sys
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageOps

MODELS = Path(__file__).resolve().parent / "models"

Image.MAX_IMAGE_PIXELS = 12_000_000
cv2.setNumThreads(1)

detector = cv2.FaceDetectorYN.create(
    str(MODELS / "face_detection_yunet_2023mar.onnx"),
    "",
    (320, 320),
    0.85,
    0.3,
    5000
)

def decode_image(encoded):
    raw = base64.b64decode(encoded, validate=True)

    if len(raw) > 3 * 1024 * 1024:
        raise ValueError("Image exceeds 3 MB")

    with Image.open(io.BytesIO(raw)) as image:
        image = ImageOps.exif_transpose(image)

        if image.width * image.height > 12_000_000:
            raise ValueError("Image dimensions too large")

        image = image.convert("RGB")
        image.thumbnail((1280, 1280))

        return cv2.cvtColor(
            np.array(image),
            cv2.COLOR_RGB2BGR
        )

def inspect_image(image):
    h, w = image.shape[:2]

    detector.setInputSize((w, h))
    _, faces = detector.detect(image)

    count = 0 if faces is None else len(faces)

    if count != 1:
        return {
            "status": "failed",
            "faceCount": count,
            "reason": "Exactly one visible face is required"
        }

    x, y, fw, fh = map(int, faces[0][:4])

    if min(fw, fh) < 100:
        return {
            "status": "failed",
            "faceCount": count,
            "reason": "Move closer to the camera"
        }

    crop = image[
        max(0, y):min(h, y + fh),
        max(0, x):min(w, x + fw)
    ]

    gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)

    brightness = float(gray.mean())
    sharpness = float(cv2.Laplacian(
        gray, cv2.CV_64F
    ).var())

    if brightness < 40 or brightness > 225:
        return {
            "status": "failed",
            "reason": "Improve the lighting"
        }

    if sharpness < 35:
        return {
            "status": "failed",
            "reason": "Image is too blurry"
        }

    return {
        "status": "passed",
        "faceCount": count,
        "brightness": round(brightness, 2),
        "sharpness": round(sharpness, 2),
        "reason": "Image quality check passed"
    }

def main():
    raw = sys.stdin.read(13_000_001)

    if len(raw) > 13_000_000:
        raise ValueError("Request too large")

    payload = json.loads(raw)

    if payload.get("mode") == "liveness":
        from liveness_engine import assess_sequence
        print(json.dumps(assess_sequence(payload["frames"])))
        return

    if payload.get("mode") != "inspect":
        raise ValueError("Unsupported operation")

    image = decode_image(payload["image"])
    print(json.dumps(inspect_image(image)))

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({
            "status": "inconclusive",
            "reason": "Image processing failed"
        }))
