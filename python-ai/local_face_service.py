"""Local one-to-one image screening; NOT real-time liveness verification."""
import io
import tempfile
from pathlib import Path
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_BYTES = 3 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 12_000_000


def normalize(raw):
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('Photo missing or too large')
    try:
        with Image.open(io.BytesIO(raw)) as original:
            image = ImageOps.exif_transpose(original)
            if image.width < 160 or image.height < 160 or image.width * image.height > 12_000_000:
                raise ValueError('Unsupported image dimensions')
            image = image.convert('RGB')
            buffer = io.BytesIO()
            image.save(buffer, format='JPEG', quality=90)
            return buffer.getvalue()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError('Invalid image') from exc


def screen_face(reference_bytes, candidate_bytes):
    from deepface import DeepFace
    reference = normalize(reference_bytes)
    candidate = normalize(candidate_bytes)
    with tempfile.TemporaryDirectory(prefix='pm_face_') as folder:
        ref_path = Path(folder) / 'reference.jpg'
        cand_path = Path(folder) / 'candidate.jpg'
        ref_path.write_bytes(reference)
        cand_path.write_bytes(candidate)
        faces = DeepFace.extract_faces(
            img_path=str(cand_path), detector_backend='opencv',
            enforce_detection=True, anti_spoofing=False)
        if len(faces) != 1:
            return {'status':'failed', 'reason':'face_count'}
        try:
            spoof = DeepFace.extract_faces(
                img_path=str(cand_path), detector_backend='opencv',
                enforce_detection=True, anti_spoofing=True)
        except ValueError:
            return {'status':'failed', 'reason':'anti_spoofing_failed'}
        if len(spoof) != 1 or spoof[0].get('is_real') is not True:
            return {'status':'failed', 'reason':'anti_spoofing_failed'}
        match = DeepFace.verify(
            img1_path=str(ref_path), img2_path=str(cand_path),
            model_name='ArcFace', detector_backend='opencv',
            enforce_detection=True, align=True)
        if not match.get('verified'):
            return {'status':'failed', 'reason':'face_mismatch'}
        return {'status':'review_required', 'reason':'face_screening_passed'}
