# Privacy Monitor: Flask setup + passkey login (Week 1-2)

Covers feature 1 (Flask setup, SQLite schema) and feature 2 (Face ID / passkey signup and login, recovery codes, fallback PIN).

## Run it

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
flask --app app run                # then open http://localhost:5000
pytest                             # run the tests
```

**Open it at `http://localhost:5000`, not `127.0.0.1`.** Browsers only allow passkeys on `localhost` or on HTTPS, and the passkey is tied to the exact hostname.

### Trying Face ID on a real iPhone
A phone can't reach your laptop's `localhost`, and passkeys need HTTPS. Put the app behind an HTTPS tunnel (for example `cloudflared tunnel --url http://localhost:5000` or `ngrok http 5000`), then start Flask with that hostname:

```bash
RP_ID=your-tunnel-hostname.example ORIGIN=https://your-tunnel-hostname.example flask --app app run
```

Passkeys created under one hostname will not work on another. Reset the database (`rm instance/privacy_monitor.sqlite`) when you change it.

## What's here

| File | Purpose |
|---|---|
| `schema.sql` | 17 tables from the ER entity list. `cases` is used instead of `case` (reserved SQL word). |
| `db.py` | SQLite connection (foreign keys on) and `flask init-db`. |
| `app.py` | App factory, config, secret key handling. |
| `auth.py` | All sign-in logic (blueprint `auth`). Use `@login_required` on your own routes. |
| `templates/`, `static/` | Signup, login, recovery, codes, settings and dashboard pages, plus `auth.js`. |
| `tests/` | Schema tests and auth tests. |

## How sign-in works

- **Signup:** pick a nickname, then the device's Face ID / fingerprint / screen lock creates a passkey. No email or password. 8 recovery codes are shown once.
- **Login:** one tap, the device offers its passkey. No typing.
- **Recovery code:** nickname + one code. Each code works once. The user lands on Settings with a prompt to add a passkey on their new device.
- **Fallback PIN:** optional, 6 digits, set in Settings. 5 wrong tries (PIN or recovery code) locks those two methods for 15 minutes. Passkey login is not affected and clears the lock.
- Recovery codes and PINs are stored hashed. Failed logins give one generic message so the app doesn't reveal which nicknames exist.

## Notes for teammates

- `credential.credential_id` is the base64url WebAuthn credential id (text), not an auto-number.
- Deleting a user cascades to all their rows, so Week 6 "delete account" is one `DELETE FROM user`.
- `finding` has `UNIQUE (user_id, url_hash)`. The scanner can use this to tell new results from ones already seen.
- Not done yet (assigned to later weeks): auto-logout timer (feature 16), email verification (feature 5), PWA manifest (feature 3).
- Before deploying anywhere real: set `FLASK_SECRET_KEY`, use HTTPS, and set `SESSION_COOKIE_SECURE=True`.
