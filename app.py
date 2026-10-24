import os
import secrets
from pathlib import Path

from flask import Flask, redirect, session, url_for

import auth
import db


def _load_secret_key(instance_path):
    """Use FLASK_SECRET_KEY if set, otherwise create and reuse a local key file."""
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        return env_key
    key_file = Path(instance_path) / "secret.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return key_file.read_text().strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config.update(
        DATABASE=os.path.join(app.instance_path, "privacy_monitor.sqlite"),
        # WebAuthn only works on https or on "localhost" (NOT 127.0.0.1).
        RP_ID=os.environ.get("RP_ID", "localhost"),
        RP_NAME="Privacy Monitor",
        ORIGIN=os.environ.get("ORIGIN", "http://localhost:5000"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PIN_MAX_ATTEMPTS=5,
        LOCKOUT_MINUTES=15,
        RECOVERY_CODE_COUNT=8,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_secret_key(app.instance_path)

    db.init_app(app)
    with app.app_context():
        db.init_db()

    app.register_blueprint(auth.bp)

    @app.get("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("auth.dashboard"))
        return redirect(url_for("auth.login_page"))

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
