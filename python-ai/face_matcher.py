import cv2
from pathlib import Path

from face_engine import decode_image

cv2.setNumThreads(1)

MODELS = Path(__file__).resolve().parent / "models"

DETECTOR_MODEL = str(
    MODELS / "face_detection_yunet_2023mar.onnx"
)

RECOGNITION_MODEL = str(
    MODELS / "face_recognition_sface_2021dec.onnx"
)

def extract_feature(image, detector, recognizer):
    height, width = image.shape[:2]
    detector.setInputSize((width, height))

    _, faces = detector.detect(image)

    if faces is None or len(faces) != 1:
        raise ValueError("Exactly one face is required.")

    face = faces[0]

    if min(face[2], face[3]) < 100:
        raise ValueError("Face is too small.")

    aligned = recognizer.alignCrop(image, face)
    return recognizer.feature(aligned)


def compare_faces(enrolled_image, camera_image):
    try:
        detector = cv2.FaceDetectorYN.create(
            DETECTOR_MODEL, "", (320, 320),
            0.9, 0.3, 5000
        )

        recognizer = cv2.FaceRecognizerSF.create(
            RECOGNITION_MODEL, ""
        )

        enrolled = decode_image(enrolled_image)
        camera = decode_image(camera_image)

        feature_a = extract_feature(
            enrolled, detector, recognizer
        )

        feature_b = extract_feature(
            camera, detector, recognizer
        )

        similarity = float(recognizer.match(
            feature_a,
            feature_b,
            cv2.FaceRecognizerSF_FR_COSINE
        ))

        return {
            "status": "compared",
            "cosineSimilarity": round(similarity, 6),
            "method": "opencv_sface"
        }

    except Exception:
        return {
            "status": "inconclusive",
            "message": "Facial comparison could not be completed."
        }
