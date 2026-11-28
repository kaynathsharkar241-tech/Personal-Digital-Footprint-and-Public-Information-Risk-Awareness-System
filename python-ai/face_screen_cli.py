#!/usr/bin/env python3
"""Optional local ArcFace screening CLI. Reads one JSON request from stdin."""
import base64
import contextlib
import io
import json
import sys

MAX_ENCODED = 4_300_000

def main():
    raw = sys.stdin.read(MAX_ENCODED + 1)
    if len(raw) > MAX_ENCODED:
        raise ValueError('Request exceeds the permitted size.')
    payload = json.loads(raw)
    if payload.get('mode') != 'compare':
        raise ValueError('Unsupported screening mode.')
    reference = base64.b64decode(payload['reference'], validate=True)
    candidate = base64.b64decode(payload['candidate'], validate=True)
    if len(reference) > 3 * 1024 * 1024 or len(candidate) > 3 * 1024 * 1024:
        raise ValueError('Each image must be 3 MB or smaller.')
    # Keep framework/model logs off stdout so the Node caller receives one JSON object.
    from face_photo_matcher import compare_photo_to_registration
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        result = compare_photo_to_registration(reference, candidate)
    sys.stdout.write(json.dumps(result, separators=(',', ':')))

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.stdout.write(json.dumps({'result': 'inconclusive', 'reason': type(exc).__name__, 'message': str(exc)[:240]}))
        sys.exit(0)
