import sqlite3
from pathlib import Path

import pytest

SCHEMA = (Path(__file__).parent.parent / "schema.sql").read_text()

EXPECTED_TABLES = {
    "user", "credential", "recovery_code", "reference_photo", "monitor_setting",
    "monitor_term", "scan_run", "finding", "notification", "question", "answer",
    "platform", "check_log", "cases", "evidence", "response_action", "ai_result",
}


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("PRAGMA foreign_keys = ON")
    c.executescript(SCHEMA)
    yield c
    c.close()


def _user(conn, name="alice"):
    return conn.execute("INSERT INTO user (nickname) VALUES (?)", (name,)).lastrowid


def _finding(conn, uid, url="https://x.test/1"):
    scan = conn.execute("INSERT INTO scan_run (user_id, trigger) VALUES (?, 'manual')", (uid,)).lastrowid
    return conn.execute("INSERT INTO finding (user_id, scan_id, url_hash, url) VALUES (?,?,?,?)",
                        (uid, scan, "h" + url, url)).lastrowid


def test_all_tables_exist(conn):
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    assert names == EXPECTED_TABLES


def test_schema_is_idempotent(conn):
    conn.executescript(SCHEMA)  # second run must not fail


def test_foreign_key_check_is_clean(conn):
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_orphan_credential_rejected(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO credential (credential_id, user_id, public_key) VALUES ('c', 999, x'00')")


def test_nickname_unique_case_insensitive(conn):
    _user(conn, "Alice")
    with pytest.raises(sqlite3.IntegrityError):
        _user(conn, "alice")


def test_monitor_setting_is_one_to_one(conn):
    uid = _user(conn)
    conn.execute("INSERT INTO monitor_setting (user_id) VALUES (?)", (uid,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO monitor_setting (user_id) VALUES (?)", (uid,))


def test_finding_to_case_is_zero_or_one(conn):
    uid = _user(conn)
    fid = _finding(conn, uid)
    conn.execute("INSERT INTO cases (user_id, finding_id, case_type) VALUES (?,?, 'impersonation')", (uid, fid))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO cases (user_id, finding_id, case_type) VALUES (?,?, 'leak')", (uid, fid))
    # many cases with no finding are fine (nullable)
    conn.execute("INSERT INTO cases (user_id, case_type) VALUES (?, 'a')", (uid,))
    conn.execute("INSERT INTO cases (user_id, case_type) VALUES (?, 'b')", (uid,))


def test_duplicate_finding_url_rejected_per_user(conn):
    uid = _user(conn)
    _finding(conn, uid)
    with pytest.raises(sqlite3.IntegrityError):
        _finding(conn, uid)


def test_enum_checks(conn):
    uid = _user(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO monitor_setting (user_id, scan_frequency) VALUES (?, 'hourly')", (uid,))


def test_deleting_user_removes_everything(conn):
    uid = _user(conn)
    fid = _finding(conn, uid)
    cid = conn.execute("INSERT INTO cases (user_id, finding_id, case_type) VALUES (?,?, 't')", (uid, fid)).lastrowid
    conn.execute("INSERT INTO evidence (case_id, file_path) VALUES (?, 'f')", (cid,))
    conn.execute("INSERT INTO credential (credential_id, user_id, public_key) VALUES ('c', ?, x'00')", (uid,))
    conn.execute("INSERT INTO recovery_code (user_id, code_hash) VALUES (?, 'h')", (uid,))
    conn.execute("DELETE FROM user WHERE user_id = ?", (uid,))
    for table in EXPECTED_TABLES - {"question", "platform"}:
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
