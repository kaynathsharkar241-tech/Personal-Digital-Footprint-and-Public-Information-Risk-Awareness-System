# Privacy Monitor (CSE299 Junior Design Project) - Frontend v1

A simple Flask frontend for the "Personal Digital Footprint and Public Information Risk Awareness System".

**Important:** all findings, scores, cases and notifications are SAMPLE / DEMONSTRATION data.
No scanning, login, passkey, database or AI feature is real yet.

## Run on macOS

```bash
cd privacy_monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Pages

| URL | Page |
|-----|------|
| /login | Login |
| /register | Registration |
| /dashboard | Dashboard |
| /monitoring | Monitoring Setup |
| /scan-results | Scan Results |
| /questionnaire | Privacy Questionnaire |
| /cases | Case Management |
| /settings | Settings |

## Later additions
- SQLite: use Python's built-in `sqlite3`, replace the sample lists in `app.py`.
- Authentication: Flask `session` + hashed passwords (`werkzeug.security`); passkeys via WebAuthn.
- Scanning: a separate `scanner.py` called from a `/scan` route.
- AI: a function that sends case text to an AI API and returns the assessment.
