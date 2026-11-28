import json
import sys
from face_matcher import compare_faces

MAX_INPUT = 9_000_000

def main():
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)

        if len(raw) > MAX_INPUT:
            raise ValueError("Input too large.")

        payload = json.loads(raw)

        enrolled = payload.get("enrolled")
        camera = payload.get("camera")

        if not isinstance(enrolled, str):
            raise ValueError("Missing enrolled image.")

        if not isinstance(camera, str):
            raise ValueError("Missing camera image.")

        if not enrolled or not camera:
            raise ValueError("Empty image.")

        result = compare_faces(enrolled, camera)

        print(json.dumps(result, allow_nan=False))

    except Exception:
        print(json.dumps({
            "status": "inconclusive",
            "message": "Invalid facial comparison request."
        }))

if __name__ == "__main__":
    main()
