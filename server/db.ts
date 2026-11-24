import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const INSTANCE_DIR = process.env.PRIVACY_INSTANCE_DIR
  ? path.resolve(process.env.PRIVACY_INSTANCE_DIR)
  : path.resolve(process.cwd(), 'instance');
fs.mkdirSync(INSTANCE_DIR, { recursive: true });

export const DB_PATH = process.env.PRIVACY_DB_PATH
  ? path.resolve(process.env.PRIVACY_DB_PATH)
  : path.join(INSTANCE_DIR, 'privacy.sqlite3');

export const db = new DatabaseSync(DB_PATH);

db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    fallback_pin_hash TEXT,
    email_verified_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    last_active_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT 'Device Passkey',
    public_key_b64 TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_used_at TEXT
  );

  CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS email_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS identity_enrollments (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_selfie BLOB NOT NULL,
    iv BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    mime TEXT NOT NULL DEFAULT 'image/jpeg',
    selfie_sha256 TEXT NOT NULL,
    consent_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_review',
    reviewed_at TEXT,
    reviewer_note TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS monitoring_photos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_image BLOB NOT NULL,
    iv BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    mime TEXT NOT NULL DEFAULT 'image/jpeg',
    sha256 TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT 'Uploaded Photo',
    status TEXT NOT NULL DEFAULT 'pending_review',
    reviewer_note TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT,
    match_result TEXT NOT NULL DEFAULT 'not_checked',
    match_reason TEXT,
    match_confidence REAL,
    matched_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS liveness_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'started',
    confidence REAL,
    verification_method TEXT NOT NULL DEFAULT 'local_sequence',
    created_at TEXT NOT NULL,
    completed_at TEXT
  );

  CREATE TABLE IF NOT EXISTS local_camera_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'issued',
    completed_at TEXT
  );

  CREATE TABLE IF NOT EXISTS verification_review_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES liveness_sessions(id) ON DELETE CASCADE,
    reviewer_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_evidence', 'screening_accepted', 'screening_rejected')),
    reason TEXT NOT NULL,
    reviewed_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reviewer_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    passcode_hash TEXT NOT NULL,
    claimed_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS monitors (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    terms TEXT NOT NULL DEFAULT '',
    domains TEXT NOT NULL DEFAULT '',
    frequency TEXT NOT NULL DEFAULT 'weekly',
    enabled INTEGER NOT NULL DEFAULT 1,
    authorization_confirmed INTEGER NOT NULL DEFAULT 0,
    authorization_at TEXT,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS priority_weights (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    confidence_weight REAL NOT NULL DEFAULT 0.45,
    severity_weight REAL NOT NULL DEFAULT 0.35,
    recency_weight REAL NOT NULL DEFAULT 0.20,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    provider_summary TEXT NOT NULL DEFAULT '[]',
    authorized_at TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    signature TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    source_name TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    found_at TEXT NOT NULL,
    risk TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL,
    ai_advice TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.5,
    severity REAL NOT NULL DEFAULT 0.5,
    recency_score REAL NOT NULL DEFAULT 1.0,
    priority REAL NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'Unverified',
    user_verified INTEGER NOT NULL DEFAULT 0,
    UNIQUE(user_id, signature)
  );

  CREATE TABLE IF NOT EXISTS api_cache (
    cache_key TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS provider_telemetry (
    provider_id TEXT PRIMARY KEY,
    provider_name TEXT NOT NULL,
    requests_today INTEGER NOT NULL DEFAULT 0,
    requests_date TEXT NOT NULL,
    cache_hits INTEGER NOT NULL DEFAULT 0,
    last_status TEXT NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    last_checked_at TEXT,
    rate_limit_remaining TEXT NOT NULL DEFAULT '',
    rate_limit_reset TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS answers (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    question_id INTEGER NOT NULL,
    value INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, question_id)
  );

  CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    occurred_at TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    notes TEXT NOT NULL DEFAULT '',
    ai_draft TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mime TEXT NOT NULL,
    encrypted BLOB NOT NULL,
    iv BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    read_at TEXT
  );
CREATE TABLE IF NOT EXISTS auth_rate_limits (
    bucket TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    window_started_at TEXT NOT NULL,
    locked_until TEXT,
    last_attempt_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reviewer_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS finding_review_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS case_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    mode TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    redirect_origin TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

function ensureColumn(table: string, column: string, definition: string) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
  }
}

ensureColumn('users', 'google_sub', "TEXT NOT NULL DEFAULT ''");
db.exec(
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub) WHERE google_sub != '';"
);

ensureColumn('monitors', 'domains', "TEXT NOT NULL DEFAULT ''");
ensureColumn('monitors', 'authorization_confirmed', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('monitors', 'authorization_at', 'TEXT');
ensureColumn('monitors', 'last_scheduled_scan_at', 'TEXT');

ensureColumn('scans', 'provider_summary', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('scans', 'authorized_at', "TEXT NOT NULL DEFAULT ''");

ensureColumn('findings', 'source_name', "TEXT NOT NULL DEFAULT ''");
ensureColumn('findings', 'evidence', "TEXT NOT NULL DEFAULT ''");
ensureColumn('findings', 'verification_status', "TEXT NOT NULL DEFAULT 'Unverified'");
ensureColumn('findings', 'review_note', "TEXT NOT NULL DEFAULT ''");
ensureColumn('findings', 'reviewed_at', 'TEXT');

ensureColumn('cases', 'resolved_at', 'TEXT');
ensureColumn('cases', 'resolution_summary', "TEXT NOT NULL DEFAULT ''");

ensureColumn('identity_enrollments', 'ai_biometric_consent', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('identity_enrollments', 'ai_biometric_consent_at', 'TEXT');

ensureColumn('passkeys', 'transports', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('passkeys', 'device_type', "TEXT NOT NULL DEFAULT 'singleDevice'");
ensureColumn('passkeys', 'backed_up', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('passkeys', 'rp_id', "TEXT NOT NULL DEFAULT ''");
ensureColumn('passkeys', 'webauthn_user_id', "TEXT NOT NULL DEFAULT ''");

ensureColumn('webauthn_challenges', 'rp_id', "TEXT NOT NULL DEFAULT ''");
ensureColumn('webauthn_challenges', 'expected_origin', "TEXT NOT NULL DEFAULT ''");
ensureColumn('webauthn_challenges', 'webauthn_user_id', "TEXT NOT NULL DEFAULT ''");

// Remove any legacy synthetic/demo rows from existing databases
const findingCols = db.prepare('PRAGMA table_info(findings)').all() as Array<{ name: string }>;
if (findingCols.some((c) => c.name === 'is_synthetic')) {
  db.exec('DELETE FROM findings WHERE is_synthetic = 1;');
}
db.exec("DELETE FROM scans WHERE mode = 'synthetic';");

export function utcNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}
