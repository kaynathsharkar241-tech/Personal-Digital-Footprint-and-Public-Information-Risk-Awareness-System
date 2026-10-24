-- Privacy Monitor: SQLite schema (17 tables, from the ER entity list)
-- Foreign keys are enforced per-connection via PRAGMA foreign_keys=ON (see db.py).
-- Child rows cascade when a user is deleted, which the Week-6 "delete account" feature relies on.

CREATE TABLE IF NOT EXISTS user (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pin_hash        TEXT,                                  -- optional fallback PIN
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,                                  -- ISO-8601 UTC, NULL = not locked
    email           TEXT,
    email_verified  INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0,1)),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS credential (
    credential_id TEXT PRIMARY KEY,                        -- base64url WebAuthn credential id
    user_id       INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    device_name   TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS recovery_code (
    code_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0,1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS reference_photo (
    photo_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    image_url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_setting (
    setting_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL UNIQUE REFERENCES user(user_id) ON DELETE CASCADE,  -- 1:1
    monitoring_on  INTEGER NOT NULL DEFAULT 0 CHECK (monitoring_on IN (0,1)),
    scan_frequency TEXT NOT NULL DEFAULT 'weekly' CHECK (scan_frequency IN ('daily','weekly','monthly')),
    next_scan_at   TEXT,
    last_scan_at   TEXT,
    notify_by      TEXT NOT NULL DEFAULT 'in-app' CHECK (notify_by IN ('in-app','email','push'))
);

CREATE TABLE IF NOT EXISTS monitor_term (
    term_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    term_type TEXT NOT NULL CHECK (term_type IN ('name','handle','email','city')),
    value     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_run (
    scan_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    trigger     TEXT NOT NULL CHECK (trigger IN ('scheduled','manual')),
    started_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    new_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS finding (
    finding_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    scan_id       INTEGER NOT NULL REFERENCES scan_run(scan_id) ON DELETE CASCADE,
    url_hash      TEXT NOT NULL,
    url           TEXT NOT NULL,
    title         TEXT,
    snippet       TEXT,
    category      TEXT,
    safety_level  TEXT CHECK (safety_level IN ('fine','review','action')),
    user_feedback TEXT CHECK (user_feedback IN ('me','not me','ignored')),
    found_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (user_id, url_hash)                             -- lets the scanner detect "new" results
);

CREATE TABLE IF NOT EXISTS notification (
    notif_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES finding(finding_id) ON DELETE CASCADE,
    message    TEXT NOT NULL,
    read       INTEGER NOT NULL DEFAULT 0 CHECK (read IN (0,1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS question (
    question_id INTEGER PRIMARY KEY AUTOINCREMENT,
    text        TEXT NOT NULL,
    category    TEXT,
    risk_weight INTEGER NOT NULL DEFAULT 1,
    fix_steps   TEXT
);

CREATE TABLE IF NOT EXISTS answer (
    answer_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    question_id INTEGER NOT NULL REFERENCES question(question_id) ON DELETE CASCADE,
    response    TEXT NOT NULL,
    answered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS platform (
    platform_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    url_template TEXT NOT NULL,
    type         TEXT NOT NULL CHECK (type IN ('text','image'))
);

CREATE TABLE IF NOT EXISTS check_log (
    check_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    platform_id INTEGER NOT NULL REFERENCES platform(platform_id) ON DELETE CASCADE,
    query       TEXT NOT NULL,
    checked_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- "case" is a reserved word in SQL, so the table is named "cases".
CREATE TABLE IF NOT EXISTS cases (
    case_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES user(user_id) ON DELETE CASCADE,
    platform_id INTEGER REFERENCES platform(platform_id),
    finding_id  INTEGER UNIQUE REFERENCES finding(finding_id) ON DELETE SET NULL,  -- 1:0..1
    case_type   TEXT NOT NULL,
    url         TEXT,
    risk_level  TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    found_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    note        TEXT,
    added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS response_action (
    action_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    done        INTEGER NOT NULL DEFAULT 0 CHECK (done IN (0,1)),
    done_at     TEXT
);

CREATE TABLE IF NOT EXISTS ai_result (
    ai_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER REFERENCES cases(case_id) ON DELETE CASCADE,
    finding_id    INTEGER REFERENCES finding(finding_id) ON DELETE CASCADE,
    feature       TEXT NOT NULL,
    input_summary TEXT,
    output        TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_credential_user  ON credential(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_user    ON recovery_code(user_id);
CREATE INDEX IF NOT EXISTS idx_finding_user     ON finding(user_id, found_at);
CREATE INDEX IF NOT EXISTS idx_notification_user ON notification(user_id, read);
CREATE INDEX IF NOT EXISTS idx_cases_user       ON cases(user_id);
