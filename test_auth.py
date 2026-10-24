from types import SimpleNamespace

import pytest

import auth
from db import get_db
from webauthn.helpers import bytes_to_base64url

CRED_BYTES = b"credential-1"
CRED_ID = bytes_to_base64url(CRED_BYTES)


@pytest.fixture
def fake_webauthn(monkeypatch):
    """Real browsers/authenticators can't run in tests, so fake the cryptographic verify step.
    Everything else (challenge handling, sessions, DB writes) is exercised for real."""
    monkeypatch.setattr(auth, "verify_registration_response",
                        lambda **kw: SimpleNamespace(credential_id=CRED_BYTES,
                                                     credential_public_key=b"pubkey", sign_count=0))
    monkeypatch.setattr(auth, "verify_authentication_response",
                        lambda **kw: SimpleNamespace(new_sign_count=5))


def signup(client, nickname="alice"):
    r = client.post("/api/register/options", json={"nickname": nickname})
    assert r.status_code == 200
    r = client.post("/api/register/verify", json={"credential": {"id": CRED_ID}, "device_name": "Test phone"})
    assert r.get_json()["ok"] is True
    return r


def get_codes(client):
    html = client.get("/recovery-codes").get_data(as_text=True)
    import re
    return re.findall(r"<li>([A-Z0-9]{4}-[A-Z0-9]{4})</li>", html)


# ----- signup -----
def test_registration_options_shape(client):
    r = client.post("/api/register/options", json={"nickname": "alice"})
    data = r.get_json()
    assert data["rp"]["id"] == "localhost"
    assert data["authenticatorSelection"]["userVerification"] == "required"
    assert data["authenticatorSelection"]["residentKey"] == "required"
    assert data["authenticatorSelection"]["authenticatorAttachment"] == "platform"
    assert data["challenge"]


@pytest.mark.parametrize("bad", ["", "a", "x" * 31, "<script>"])
def test_bad_nicknames_rejected(client, bad):
    assert client.post("/api/register/options", json={"nickname": bad}).status_code == 400


def test_signup_creates_user_credential_and_codes(client, app, fake_webauthn):
    signup(client)
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM user").fetchone()[0] == 1
        cred = db.execute("SELECT * FROM credential").fetchone()
        assert cred["credential_id"] == CRED_ID and cred["device_name"] == "Test phone"
        assert db.execute("SELECT COUNT(*) FROM recovery_code WHERE used = 0").fetchone()[0] == 8
        # codes are stored hashed, never in plain text
        stored = [r[0] for r in db.execute("SELECT code_hash FROM recovery_code")]
        assert all(h.startswith(("scrypt:", "pbkdf2:")) for h in stored)
    assert len(get_codes(client)) == 8
    assert client.get("/dashboard").status_code == 200


def test_codes_shown_only_once(client, fake_webauthn):
    signup(client)
    assert len(get_codes(client)) == 8
    r = client.get("/recovery-codes")
    assert r.status_code == 302  # gone on refresh


def test_verify_without_options_fails(client, fake_webauthn):
    r = client.post("/api/register/verify", json={"credential": {"id": CRED_ID}})
    assert r.status_code == 400


def test_duplicate_nickname_rejected(client, fake_webauthn):
    signup(client, "alice")
    client.post("/logout")
    assert client.post("/api/register/options", json={"nickname": "ALICE"}).status_code == 400


def test_failed_verification_creates_no_user(client, app, monkeypatch):
    def boom(**kw):
        raise auth.InvalidRegistrationResponse("bad")
    monkeypatch.setattr(auth, "verify_registration_response", boom)
    client.post("/api/register/options", json={"nickname": "bob"})
    r = client.post("/api/register/verify", json={"credential": {"id": CRED_ID}})
    assert r.status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM user").fetchone()[0] == 0


# ----- passkey login -----
def test_login_options_has_no_allow_list(client):
    data = client.post("/api/login/options").get_json()
    assert data["challenge"] and not data.get("allowCredentials")


def test_passkey_login_updates_sign_count(client, app, fake_webauthn):
    signup(client)
    client.post("/logout")
    client.post("/api/login/options")
    r = client.post("/api/login/verify", json={"credential": {"id": CRED_ID}})
    assert r.get_json()["ok"] is True
    assert client.get("/dashboard").status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT sign_count FROM credential").fetchone()[0] == 5


def test_unknown_passkey_rejected(client, fake_webauthn):
    client.post("/api/login/options")
    r = client.post("/api/login/verify", json={"credential": {"id": "nope"}})
    assert r.status_code == 400


def test_challenge_is_single_use(client, fake_webauthn):
    signup(client)
    client.post("/logout")
    client.post("/api/login/options")
    assert client.post("/api/login/verify", json={"credential": {"id": CRED_ID}}).status_code == 200
    client.post("/logout")
    assert client.post("/api/login/verify", json={"credential": {"id": CRED_ID}}).status_code == 400


def test_dashboard_requires_login(client):
    assert client.get("/dashboard").status_code == 302
    assert client.post("/api/pin/set", json={"pin": "483920"}).status_code == 401


# ----- recovery codes -----
def test_recovery_code_works_once(client, fake_webauthn):
    signup(client)
    codes = get_codes(client)
    client.post("/logout")

    r = client.post("/api/recovery/login", json={"nickname": "alice", "code": codes[0].lower()})
    assert r.get_json()["ok"] is True
    assert client.get("/settings").status_code == 200

    client.post("/logout")
    r = client.post("/api/recovery/login", json={"nickname": "alice", "code": codes[0]})
    assert r.status_code == 401
    r = client.post("/api/recovery/login", json={"nickname": "alice", "code": codes[1].replace("-", " ")})
    assert r.status_code == 200  # other codes still work, formatting is forgiving


def test_recovery_wrong_code_and_unknown_user_look_the_same(client, fake_webauthn):
    signup(client)
    client.post("/logout")
    a = client.post("/api/recovery/login", json={"nickname": "alice", "code": "AAAA-AAAA"})
    b = client.post("/api/recovery/login", json={"nickname": "ghost", "code": "AAAA-AAAA"})
    assert a.status_code == b.status_code == 401
    assert a.get_json() == b.get_json()


def test_regenerate_invalidates_old_codes(client, fake_webauthn):
    signup(client)
    old = get_codes(client)
    r = client.post("/api/recovery/regenerate")
    assert r.get_json()["ok"] is True
    new = get_codes(client)
    assert len(new) == 8 and not set(old) & set(new)
    client.post("/logout")
    assert client.post("/api/recovery/login", json={"nickname": "alice", "code": old[0]}).status_code == 401
    assert client.post("/api/recovery/login", json={"nickname": "alice", "code": new[0]}).status_code == 200


def test_recovery_attempts_lock_account(client, fake_webauthn):
    signup(client)
    client.post("/logout")
    for _ in range(5):
        client.post("/api/recovery/login", json={"nickname": "alice", "code": "AAAA-AAAA"})
    assert client.post("/api/recovery/login", json={"nickname": "alice", "code": "AAAA-AAAA"}).status_code == 429


# ----- add / remove passkeys -----
def test_cannot_remove_only_passkey(client, fake_webauthn):
    signup(client)
    r = client.post("/api/passkey/delete", json={"credential_id": CRED_ID})
    assert r.status_code == 400


def test_add_second_passkey_then_remove_one(client, app, fake_webauthn, monkeypatch):
    signup(client)
    client.post("/api/passkey/options")
    monkeypatch.setattr(auth, "verify_registration_response",
                        lambda **kw: SimpleNamespace(credential_id=b"credential-2",
                                                     credential_public_key=b"k2", sign_count=0))
    assert client.post("/api/passkey/verify", json={"credential": {"id": "x"}}).get_json()["ok"]
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM credential").fetchone()[0] == 2
    assert client.post("/api/passkey/delete", json={"credential_id": CRED_ID}).get_json()["ok"]


# ----- PIN -----
def setup_pin(client, pin="483920"):
    signup(client)
    assert client.post("/api/pin/set", json={"pin": pin}).get_json()["ok"]
    client.post("/logout")


@pytest.mark.parametrize("bad", ["12345", "1234567", "abcdef", "111111", "123456", ""])
def test_weak_or_malformed_pin_rejected(client, fake_webauthn, bad):
    signup(client)
    assert client.post("/api/pin/set", json={"pin": bad}).status_code == 400


def test_pin_login_and_hashed_storage(client, app, fake_webauthn):
    setup_pin(client)
    with app.app_context():
        stored = get_db().execute("SELECT pin_hash FROM user").fetchone()[0]
        assert stored and "483920" not in stored
    r = client.post("/api/pin/login", json={"nickname": "alice", "pin": "483920"})
    assert r.get_json()["ok"] is True
    assert client.get("/dashboard").status_code == 200


def test_pin_login_fails_when_no_pin_set(client, fake_webauthn):
    signup(client)
    client.post("/logout")
    assert client.post("/api/pin/login", json={"nickname": "alice", "pin": "483920"}).status_code == 401


def test_pin_lockout_after_five_failures(client, app, fake_webauthn):
    setup_pin(client)
    for _ in range(5):
        r = client.post("/api/pin/login", json={"nickname": "alice", "pin": "000001"})
        assert r.status_code == 401
    # even the correct PIN is refused while locked
    assert client.post("/api/pin/login", json={"nickname": "alice", "pin": "483920"}).status_code == 429

    # passkey still works while the PIN is locked, and clears the lock
    client.post("/api/login/options")
    assert client.post("/api/login/verify", json={"credential": {"id": CRED_ID}}).status_code == 200
    client.post("/logout")
    assert client.post("/api/pin/login", json={"nickname": "alice", "pin": "483920"}).status_code == 200


def test_lockout_expires(client, app, fake_webauthn):
    setup_pin(client)
    for _ in range(5):
        client.post("/api/pin/login", json={"nickname": "alice", "pin": "000001"})
    with app.app_context():
        db = get_db()
        db.execute("UPDATE user SET locked_until = '2000-01-01T00:00:00.000000Z'")
        db.commit()
    assert client.post("/api/pin/login", json={"nickname": "alice", "pin": "483920"}).status_code == 200


def test_remove_pin(client, fake_webauthn):
    setup_pin(client)
    client.post("/api/pin/login", json={"nickname": "alice", "pin": "483920"})
    assert client.post("/api/pin/remove").get_json()["ok"]
    client.post("/logout")
    assert client.post("/api/pin/login", json={"nickname": "alice", "pin": "483920"}).status_code == 401


# ----- pages render -----
@pytest.mark.parametrize("path", ["/login", "/signup", "/recovery"])
def test_public_pages_render(client, path):
    r = client.get(path)
    assert r.status_code == 200 and b"auth.js" in r.data


def test_settings_page_renders_when_signed_in(client, fake_webauthn):
    signup(client)
    r = client.get("/settings")
    assert r.status_code == 200 and b"Test phone" in r.data and b"8 unused" in r.data


def test_index_redirects(client, fake_webauthn):
    assert client.get("/").headers["Location"].endswith("/login")
    signup(client)
    assert client.get("/").headers["Location"].endswith("/dashboard")
