"""Authentication: passkeys (Face ID / Touch ID / Windows Hello), recovery codes, fallback PIN."""
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Blueprint, current_app, jsonify, redirect, render_template,
                   request, session, url_for)
from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (InvalidAuthenticationResponse,
                                         InvalidJSONStructure,
                                         InvalidRegistrationResponse)
from webauthn.helpers.structs import (AuthenticatorAttachment,
                                      AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db

bp = Blueprint("auth", __name__)

WEBAUTHN_ERRORS = (InvalidRegistrationResponse, InvalidAuthenticationResponse,
                   InvalidJSONStructure)
NICKNAME_RE = re.compile(r"^[\w .'-]{2,30}$")
PIN_RE = re.compile(r"^\d{6}$")
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I to avoid misreads
GENERIC_LOGIN_ERROR = "Those details didn't work."


# ---------- helpers ----------
def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _error(message, status=400):
    return jsonify(ok=False, error=message), status


def _json():
    return request.get_json(silent=True) or {}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return _error("Please sign in first.", 401)
            return redirect(url_for("auth.login_page"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM user WHERE user_id = ?", (uid,)).fetchone()


def _start_session(user_id, recovered=False):
    session.clear()
    session["user_id"] = user_id
    if recovered:
        session["recovered"] = True


def _generate_recovery_codes(db, user_id):
    """Replace all of a user's codes with a fresh set. Returns the plain codes (shown once)."""
    db.execute("DELETE FROM recovery_code WHERE user_id = ?", (user_id,))
    codes = []
    for _ in range(current_app.config["RECOVERY_CODE_COUNT"]):
        raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
        db.execute("INSERT INTO recovery_code (user_id, code_hash) VALUES (?, ?)",
                   (user_id, generate_password_hash(raw)))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def _normalize_code(text):
    return re.sub(r"[^A-Z0-9]", "", (text or "").upper())


def _lock_remaining(user):
    """Seconds left on a lockout, or 0."""
    if user["locked_until"]:
        left = (_parse(user["locked_until"]) - _now()).total_seconds()
        if left > 0:
            return int(left) + 1
    return 0


def _record_failure(db, user):
    attempts = user["failed_attempts"] + 1
    locked_until = None
    if attempts >= current_app.config["PIN_MAX_ATTEMPTS"]:
        locked_until = _iso(_now() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"]))
        attempts = 0
    db.execute("UPDATE user SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
               (attempts, locked_until, user["user_id"]))
    db.commit()


def _clear_failures(db, user_id):
    db.execute("UPDATE user SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
               (user_id,))


def _locked_response(seconds):
    minutes = max(1, round(seconds / 60))
    return _error(f"Too many attempts. Try again in about {minutes} minute(s), "
                  "or sign in with your passkey.", 429)


def _registration_options(user_handle, user_name, exclude_ids):
    return generate_registration_options(
        rp_id=current_app.config["RP_ID"],
        rp_name=current_app.config["RP_NAME"],
        user_id=user_handle,
        user_name=user_name,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c))
                             for c in exclude_ids],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,   # Face ID / Touch ID / Hello
            resident_key=ResidentKeyRequirement.REQUIRED,                # lets login work without typing a name
            user_verification=UserVerificationRequirement.REQUIRED,      # the biometric/PIN check
        ),
    )


def _verify_registration(credential):
    challenge = session.get("reg_challenge")
    if not challenge:
        return None
    return verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(challenge),
        expected_rp_id=current_app.config["RP_ID"],
        expected_origin=current_app.config["ORIGIN"],
        require_user_verification=True,
    )


# ---------- pages ----------
@bp.get("/signup")
def signup_page():
    return render_template("signup.html")


@bp.get("/login")
def login_page():
    return render_template("login.html")


@bp.get("/recovery")
def recovery_page():
    return render_template("recovery.html")


@bp.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user())


@bp.get("/settings")
@login_required
def settings_page():
    db = get_db()
    user = current_user()
    creds = db.execute("SELECT credential_id, device_name, created_at FROM credential "
                       "WHERE user_id = ? ORDER BY created_at", (user["user_id"],)).fetchall()
    codes_left = db.execute("SELECT COUNT(*) FROM recovery_code WHERE user_id = ? AND used = 0",
                            (user["user_id"],)).fetchone()[0]
    return render_template("settings.html", user=user, creds=creds, codes_left=codes_left,
                           has_pin=bool(user["pin_hash"]), recovered=session.get("recovered"))


@bp.get("/recovery-codes")
@login_required
def recovery_codes_page():
    codes = session.pop("new_codes", None)
    if not codes:
        return redirect(url_for("auth.settings_page"))
    return render_template("codes.html", codes=codes)


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login_page"))


# ---------- passkey signup ----------
@bp.post("/api/register/options")
def register_options():
    nickname = (_json().get("nickname") or "").strip()
    if not NICKNAME_RE.match(nickname):
        return _error("Pick a nickname of 2-30 letters, numbers or spaces. You don't need your real name.")
    taken = get_db().execute("SELECT 1 FROM user WHERE nickname = ?", (nickname,)).fetchone()
    if taken:
        return _error("That nickname is taken. Try another.")
    handle = secrets.token_bytes(16)
    options = _registration_options(handle, nickname, [])
    session["reg_challenge"] = bytes_to_base64url(options.challenge)
    session["reg_nickname"] = nickname
    return current_app.response_class(options_to_json(options), mimetype="application/json")


@bp.post("/api/register/verify")
def register_verify():
    body = _json()
    nickname = session.get("reg_nickname")
    if not nickname or "credential" not in body:
        return _error("Signup expired. Please start again.")
    try:
        verified = _verify_registration(body["credential"])
    except WEBAUTHN_ERRORS:
        return _error("We couldn't verify that passkey. Please try again.")
    if verified is None:
        return _error("Signup expired. Please start again.")

    db = get_db()
    try:
        cur = db.execute("INSERT INTO user (nickname) VALUES (?)", (nickname,))
    except Exception:  # nickname raced with another signup (UNIQUE violation)
        db.rollback()
        return _error("That nickname is taken. Try another.")
    user_id = cur.lastrowid
    db.execute("INSERT INTO credential (credential_id, user_id, public_key, sign_count, device_name) "
               "VALUES (?, ?, ?, ?, ?)",
               (bytes_to_base64url(verified.credential_id), user_id, verified.credential_public_key,
                verified.sign_count, (body.get("device_name") or "This device")[:60]))
    codes = _generate_recovery_codes(db, user_id)
    db.commit()

    _start_session(user_id)
    session["new_codes"] = codes
    return jsonify(ok=True, redirect=url_for("auth.recovery_codes_page"))


# ---------- passkey login ----------
@bp.post("/api/login/options")
def login_options():
    options = generate_authentication_options(
        rp_id=current_app.config["RP_ID"],
        user_verification=UserVerificationRequirement.REQUIRED,
    )   # no allow-list: the device offers whichever passkey it holds for this site
    session["auth_challenge"] = bytes_to_base64url(options.challenge)
    return current_app.response_class(options_to_json(options), mimetype="application/json")


@bp.post("/api/login/verify")
def login_verify():
    credential = _json().get("credential")
    challenge = session.pop("auth_challenge", None)
    if not credential or not challenge:
        return _error("Sign-in expired. Please try again.")
    db = get_db()
    row = db.execute("SELECT * FROM credential WHERE credential_id = ?",
                     (credential.get("id", ""),)).fetchone()
    if row is None:
        return _error("This passkey isn't registered here. Use your recovery code instead.")
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=current_app.config["RP_ID"],
            expected_origin=current_app.config["ORIGIN"],
            credential_public_key=row["public_key"],
            credential_current_sign_count=row["sign_count"],
            require_user_verification=True,
        )
    except WEBAUTHN_ERRORS:
        return _error("We couldn't verify that passkey. Please try again.")
    db.execute("UPDATE credential SET sign_count = ? WHERE credential_id = ?",
               (verified.new_sign_count, row["credential_id"]))
    _clear_failures(db, row["user_id"])
    db.commit()
    _start_session(row["user_id"])
    return jsonify(ok=True, redirect=url_for("auth.dashboard"))


# ---------- add another device (signed in) ----------
@bp.post("/api/passkey/options")
@login_required
def add_passkey_options():
    user = current_user()
    existing = [r["credential_id"] for r in get_db().execute(
        "SELECT credential_id FROM credential WHERE user_id = ?", (user["user_id"],))]
    options = _registration_options(str(user["user_id"]).encode(), user["nickname"], existing)
    session["reg_challenge"] = bytes_to_base64url(options.challenge)
    return current_app.response_class(options_to_json(options), mimetype="application/json")


@bp.post("/api/passkey/verify")
@login_required
def add_passkey_verify():
    body = _json()
    try:
        verified = _verify_registration(body.get("credential"))
    except WEBAUTHN_ERRORS:
        return _error("We couldn't verify that passkey. Please try again.")
    if verified is None:
        return _error("Request expired. Please try again.")
    db = get_db()
    db.execute("INSERT INTO credential (credential_id, user_id, public_key, sign_count, device_name) "
               "VALUES (?, ?, ?, ?, ?)",
               (bytes_to_base64url(verified.credential_id), session["user_id"],
                verified.credential_public_key, verified.sign_count,
                (body.get("device_name") or "New device")[:60]))
    db.commit()
    session.pop("recovered", None)
    return jsonify(ok=True, redirect=url_for("auth.settings_page"))


@bp.post("/api/passkey/delete")
@login_required
def delete_passkey():
    cred_id = _json().get("credential_id", "")
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM credential WHERE user_id = ?",
                       (session["user_id"],)).fetchone()[0]
    if count <= 1:
        return _error("You can't remove your only passkey. Add another device first.")
    db.execute("DELETE FROM credential WHERE credential_id = ? AND user_id = ?",
               (cred_id, session["user_id"]))
    db.commit()
    return jsonify(ok=True)


# ---------- recovery codes ----------
@bp.post("/api/recovery/login")
def recovery_login():
    body = _json()
    nickname = (body.get("nickname") or "").strip()
    code = _normalize_code(body.get("code"))
    db = get_db()
    user = db.execute("SELECT * FROM user WHERE nickname = ?", (nickname,)).fetchone()
    if user is None:
        return _error(GENERIC_LOGIN_ERROR, 401)
    if _lock_remaining(user):
        return _locked_response(_lock_remaining(user))

    for row in db.execute("SELECT * FROM recovery_code WHERE user_id = ? AND used = 0",
                          (user["user_id"],)):
        if check_password_hash(row["code_hash"], code):
            db.execute("UPDATE recovery_code SET used = 1 WHERE code_id = ?", (row["code_id"],))
            _clear_failures(db, user["user_id"])
            db.commit()
            _start_session(user["user_id"], recovered=True)
            return jsonify(ok=True, redirect=url_for("auth.settings_page"))
    _record_failure(db, user)
    return _error(GENERIC_LOGIN_ERROR, 401)


@bp.post("/api/recovery/regenerate")
@login_required
def regenerate_codes():
    db = get_db()
    codes = _generate_recovery_codes(db, session["user_id"])
    db.commit()
    session["new_codes"] = codes
    return jsonify(ok=True, redirect=url_for("auth.recovery_codes_page"))


# ---------- fallback PIN ----------
@bp.post("/api/pin/set")
@login_required
def set_pin():
    pin = str(_json().get("pin", ""))
    if not PIN_RE.match(pin):
        return _error("Your PIN must be exactly 6 digits.")
    if len(set(pin)) == 1 or pin in ("123456", "654321"):
        return _error("That PIN is too easy to guess. Pick another.")
    db = get_db()
    db.execute("UPDATE user SET pin_hash = ? WHERE user_id = ?",
               (generate_password_hash(pin), session["user_id"]))
    db.commit()
    return jsonify(ok=True)


@bp.post("/api/pin/remove")
@login_required
def remove_pin():
    db = get_db()
    db.execute("UPDATE user SET pin_hash = NULL WHERE user_id = ?", (session["user_id"],))
    db.commit()
    return jsonify(ok=True)


@bp.post("/api/pin/login")
def pin_login():
    body = _json()
    nickname = (body.get("nickname") or "").strip()
    pin = str(body.get("pin", ""))
    db = get_db()
    user = db.execute("SELECT * FROM user WHERE nickname = ?", (nickname,)).fetchone()
    if user is None or not user["pin_hash"]:
        return _error(GENERIC_LOGIN_ERROR, 401)
    if _lock_remaining(user):
        return _locked_response(_lock_remaining(user))
    if not check_password_hash(user["pin_hash"], pin):
        _record_failure(db, user)
        return _error(GENERIC_LOGIN_ERROR, 401)
    _clear_failures(db, user["user_id"])
    db.commit()
    _start_session(user["user_id"])
    return jsonify(ok=True, redirect=url_for("auth.dashboard"))
