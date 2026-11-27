import cv2
import numpy as np
from face_engine import detector, decode_image

def assess_frame(encoded):
    image = decode_image(encoded)
    h, w = image.shape[:2]

    detector.setInputSize((w, h))
    _, faces = detector.detect(image)

    if faces is None or len(faces) != 1:
        raise ValueError("Exactly one face is required")

    face = faces[0]
    landmarks = face[4:14].reshape(5, 2)

    eye_a = landmarks[0]
    eye_b = landmarks[1]
    nose = landmarks[2]

    eye_center = (eye_a + eye_b) / 2
    eye_distance = float(np.linalg.norm(eye_a - eye_b))

    if eye_distance < 20:
        raise ValueError("Face is too far from camera")

    yaw_proxy = float(
        (nose[0] - eye_center[0]) / eye_distance
    )

    return {
        "yawProxy": yaw_proxy,
        "eyeDistance": eye_distance
    }

def assess_sequence(frames):
    if len(frames) != 3:
        return {
            "status": "failed",
            "reason": "Three camera frames required"
        }

    try:
        points = [assess_frame(f) for f in frames]

        first, middle, last = [
            p["yawProxy"] for p in points
        ]

        movement = abs(middle - first)
        return_error = abs(last - first)

        passed = (
            movement >= 0.12 and
            return_error <= 0.08
        )

        return {
            "status": "passed" if passed else "failed",
            "movement": round(movement, 4),
            "returnError": round(return_error, 4),
            "method": "facial_landmark_motion",
            "reason": (
                "Head movement detected"
                if passed else
                "Required head movement not detected"
            )
        }

    except Exception:
        return {
            "status": "inconclusive",
            "reason": "Unable to assess facial movement"
        }
