"""Compare user-uploaded photos to their encrypted registration selfie.

This does NOT establish liveness, account ownership, or image ownership.
"""
import io
import tempfile
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError

MAX_BYTES = 3 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 12_000_000


def _normalise(raw):
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('Photo is missing or exceeds 3 MB')
    try:
        with Image.open(io.BytesIO(raw)) as original:
            photo = ImageOps.exif_transpose(original)
            if min(photo.size) < 160 or photo.width * photo.height > 12_000_000:
                raise ValueError('Photo dimensions are not supported')
            result = io.BytesIO()
            photo.convert('RGB').save(result, 'JPEG', quality=90)
            return result.getvalue()
    except (OSError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
        raise ValueError('Invalid image data') from exc


def compare_photo_to_registration(registration_jpeg, uploaded_jpeg):
    """One-to-one facial similarity only; no camera or liveness required.

    Returns match/mismatch/inconclusive with optional ArcFace distance.
    """
    from deepface import DeepFace

    ref = _normalise(registration_jpeg)
    candidate = _normalise(uploaded_jpeg)
    with tempfile.TemporaryDirectory(prefix='privacy_face_match_') as folder:
        a = Path(folder) / 'registration.jpg'
        b = Path(folder) / 'uploaded.jpg'
        a.write_bytes(ref)
        b.write_bytes(candidate)
        try:
            # Reject photos with zero or multiple faces, and ambiguous reference images.
            for path in (a, b):
                faces = DeepFace.extract_faces(
                    img_path=str(path), detector_backend='opencv',
                    enforce_detection=True, anti_spoofing=False)
                if len(faces) != 1:
                    return {'result': 'inconclusive', 'reason': 'expected_one_face',
                            'distance': None, 'threshold': None}
            value = DeepFace.verify(
                img1_path=str(a), img2_path=str(b), model_name='ArcFace',
                detector_backend='opencv', distance_metric='cosine',
                enforce_detection=True, align=True)
        except ValueError:
            return {'result': 'inconclusive', 'reason': 'face_not_detected',
                    'distance': None, 'threshold': None}

    distance = float(value['distance'])
    threshold = float(value['threshold'])
    return {'result': 'match' if value.get('verified') else 'no_match',
            'reason': 'arcface_cosine', 'distance': distance,
            'threshold': threshold}
