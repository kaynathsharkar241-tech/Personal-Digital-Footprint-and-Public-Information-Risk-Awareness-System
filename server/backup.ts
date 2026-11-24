import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import zlib from 'node:zlib';
import { DB_PATH, db, utcNow } from './db.ts';

const BACKUP_FORMAT_VERSION = 1;
const BACKUP_MAGIC = 'PRIVACY_MONITOR_ENC_BACKUP_V1';

interface EncryptedBackupEnvelope {
  magic: string;
  version: number;
  kdf: 'scrypt';
  kdfParams: { N: number; r: number; p: number; keyLen: number };
  cipher: 'aes-256-gcm';
  saltB64: string;
  ivB64: string;
  authTagB64: string;
  ciphertextB64: string;
  createdAt: string;
}

interface BackupPayload {
  formatVersion: number;
  createdAt: string;
  dbSha256: string;
  compressedDbB64: string;
}

const RESTORE_TABLES_IN_ORDER = [
  'users',
  'sessions',
  'recovery_codes',
  'passkeys',
  'webauthn_challenges',
  'email_tokens',
  'identity_enrollments',
  'monitoring_photos',
  'liveness_sessions',
  'local_camera_challenges',
  'verification_review_events',
  'reviewer_config',
  'reviewer_sessions',
  'monitors',
  'priority_weights',
  'scans',
  'findings',
  'api_cache',
  'provider_telemetry',
  'answers',
  'cases',
  'evidence',
  'notifications',
] as const;

export function assertValidBackupPassphrase(passphrase: string): void {
  if (typeof passphrase !== 'string' || passphrase.length < 12) {
    throw new Error('Backup passphrase must be at least 12 characters long.');
  }
}

export function createEncryptedBackup(passphrase: string): {
  archiveBuffer: Buffer;
  dbSha256: string;
  createdAt: string;
  snapshotBytes: number;
} {
  assertValidBackupPassphrase(passphrase);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-backup-'));
  const snapshotPath = path.join(tmpDir, 'snapshot.sqlite3');

  try {
    const escapedPath = snapshotPath.replace(/'/g, "''");
    db.exec(`VACUUM INTO '${escapedPath}';`);
    const dbBytes = fs.readFileSync(snapshotPath);
    const dbSha256 = crypto.createHash('sha256').update(dbBytes).digest('hex');
    const compressedDb = zlib.gzipSync(dbBytes, { level: 6 });
    const createdAt = utcNow();

    const payload: BackupPayload = {
      formatVersion: BACKUP_FORMAT_VERSION,
      createdAt,
      dbSha256,
      compressedDbB64: compressedDb.toString('base64'),
    };
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');

    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const kdfParams = { N: 16384, r: 8, p: 1, keyLen: 32 };
    const key = crypto.scryptSync(passphrase, salt, kdfParams.keyLen, {
      N: kdfParams.N,
      r: kdfParams.r,
      p: kdfParams.p,
    });

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(BACKUP_MAGIC, 'utf8'));
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const envelope: EncryptedBackupEnvelope = {
      magic: BACKUP_MAGIC,
      version: BACKUP_FORMAT_VERSION,
      kdf: 'scrypt',
      kdfParams,
      cipher: 'aes-256-gcm',
      saltB64: salt.toString('base64'),
      ivB64: iv.toString('base64'),
      authTagB64: authTag.toString('base64'),
      ciphertextB64: encrypted.toString('base64'),
      createdAt,
    };

    const archiveBuffer = Buffer.from(JSON.stringify(envelope, null, 2), 'utf8');
    return {
      archiveBuffer,
      dbSha256,
      createdAt,
      snapshotBytes: dbBytes.length,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

export function decryptAndValidateBackup(
  archiveBuffer: Buffer,
  passphrase: string
): {
  dbBytes: Buffer;
  dbSha256: string;
  createdAt: string;
  tableCounts: Record<string, number>;
} {
  assertValidBackupPassphrase(passphrase);

  let envelope: EncryptedBackupEnvelope;
  try {
    envelope = JSON.parse(archiveBuffer.toString('utf8')) as EncryptedBackupEnvelope;
  } catch {
    throw new Error('Backup file is not valid JSON.');
  }

  if (
    envelope.magic !== BACKUP_MAGIC ||
    envelope.version !== BACKUP_FORMAT_VERSION ||
    envelope.cipher !== 'aes-256-gcm' ||
    envelope.kdf !== 'scrypt'
  ) {
    throw new Error('Unsupported or corrupted encrypted backup envelope.');
  }

  const salt = Buffer.from(envelope.saltB64, 'base64');
  const iv = Buffer.from(envelope.ivB64, 'base64');
  const authTag = Buffer.from(envelope.authTagB64, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertextB64, 'base64');

  const key = crypto.scryptSync(passphrase, salt, envelope.kdfParams.keyLen || 32, {
    N: envelope.kdfParams.N || 16384,
    r: envelope.kdfParams.r || 8,
    p: envelope.kdfParams.p || 1,
  });

  let plaintext: Buffer;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from(BACKUP_MAGIC, 'utf8'));
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('Decryption failed: incorrect passphrase or tampered backup archive.');
  }

  const payload = JSON.parse(plaintext.toString('utf8')) as BackupPayload;
  const dbBytes = zlib.gunzipSync(Buffer.from(payload.compressedDbB64, 'base64'));
  const actualSha = crypto.createHash('sha256').update(dbBytes).digest('hex');
  if (actualSha !== payload.dbSha256) {
    throw new Error('Backup SHA-256 checksum mismatch after decryption.');
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-verify-'));
  const tmpDbPath = path.join(tmpDir, 'verify.sqlite3');
  const tableCounts: Record<string, number> = {};

  try {
    fs.writeFileSync(tmpDbPath, dbBytes, { mode: 0o600 });
    const testDb = new DatabaseSync(tmpDbPath, { readOnly: true });
    try {
      const integrity = testDb.prepare('PRAGMA integrity_check').get() as
        | { integrity_check?: string }
        | undefined;
      if (integrity?.integrity_check !== 'ok') {
        throw new Error('SQLite PRAGMA integrity_check failed on backup snapshot.');
      }

      const existingTables = new Set(
        (
          testDb
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .all() as Array<{ name: string }>
        ).map((t) => t.name)
      );
      for (const reqTable of ['users', 'findings', 'cases', 'identity_enrollments', 'monitors']) {
        if (!existingTables.has(reqTable)) {
          throw new Error(`Backup database is missing required table "${reqTable}".`);
        }
      }
      for (const tbl of RESTORE_TABLES_IN_ORDER) {
        if (existingTables.has(tbl)) {
          const row = testDb.prepare(`SELECT COUNT(*) AS n FROM ${tbl}`).get() as { n: number };
          tableCounts[tbl] = row.n;
        }
      }
    } finally {
      testDb.close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return {
    dbBytes,
    dbSha256: actualSha,
    createdAt: payload.createdAt,
    tableCounts,
  };
}

export function restoreEncryptedBackupLive(
  archiveBuffer: Buffer,
  passphrase: string
): {
  restoredAt: string;
  dbSha256: string;
  tableCounts: Record<string, number>;
} {
  const verified = decryptAndValidateBackup(archiveBuffer, passphrase);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-restore-'));
  const tmpDbPath = path.join(tmpDir, 'restore.sqlite3');

  try {
    fs.writeFileSync(tmpDbPath, verified.dbBytes, { mode: 0o600 });
    const srcDb = new DatabaseSync(tmpDbPath, { readOnly: true });
    try {
      const srcTables = new Set(
        (
          srcDb
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .all() as Array<{ name: string }>
        ).map((t) => t.name)
      );

      db.exec('PRAGMA foreign_keys = OFF;');
      db.exec('BEGIN IMMEDIATE;');
      try {
        for (const tbl of [...RESTORE_TABLES_IN_ORDER].reverse()) {
          db.exec(`DELETE FROM ${tbl};`);
        }

        for (const tbl of RESTORE_TABLES_IN_ORDER) {
          if (!srcTables.has(tbl)) continue;
          const targetCols = (
            db.prepare(`PRAGMA table_info(${tbl})`).all() as Array<{ name: string }>
          ).map((c) => c.name);
          const sourceCols = new Set(
            (srcDb.prepare(`PRAGMA table_info(${tbl})`).all() as Array<{ name: string }>).map(
              (c) => c.name
            )
          );
          const commonCols = targetCols.filter((c) => sourceCols.has(c));
          if (commonCols.length === 0) continue;

          const colList = commonCols.join(', ');
          const placeholders = commonCols.map(() => '?').join(', ');
          const rows = srcDb.prepare(`SELECT ${colList} FROM ${tbl}`).all() as Array<
            Record<string, unknown>
          >;
          const insertStmt = db.prepare(`INSERT INTO ${tbl} (${colList}) VALUES (${placeholders})`);
          for (const r of rows) {
            insertStmt.run(...commonCols.map((c) => r[c] as never));
          }
        }

        const fkViolations = db.prepare('PRAGMA foreign_key_check').all();
        if (fkViolations.length > 0) {
          throw new Error('Restored backup failed SQLite foreign_key_check integrity.');
        }

        db.exec('COMMIT;');
      } catch (err) {
        db.exec('ROLLBACK;');
        throw err;
      } finally {
        db.exec('PRAGMA foreign_keys = ON;');
      }
    } finally {
      srcDb.close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return {
    restoredAt: utcNow(),
    dbSha256: verified.dbSha256,
    tableCounts: verified.tableCounts,
  };
}

export function restoreEncryptedBackupToFile(
  archiveBuffer: Buffer,
  passphrase: string,
  targetDbPath: string = DB_PATH
): {
  restoredAt: string;
  dbSha256: string;
  targetDbPath: string;
  tableCounts: Record<string, number>;
} {
  const verified = decryptAndValidateBackup(archiveBuffer, passphrase);
  const absTarget = path.resolve(targetDbPath);
  const parent = path.dirname(absTarget);
  fs.mkdirSync(parent, { recursive: true });
  const stagePath = path.join(parent, `.restore-${crypto.randomBytes(6).toString('hex')}.sqlite3`);

  try {
    fs.writeFileSync(stagePath, verified.dbBytes, { mode: 0o600 });
    for (const suffix of ['-wal', '-shm', '-journal']) {
      if (fs.existsSync(`${absTarget}${suffix}`)) {
        fs.unlinkSync(`${absTarget}${suffix}`);
      }
    }
    fs.renameSync(stagePath, absTarget);
  } catch (err) {
    if (fs.existsSync(stagePath)) fs.unlinkSync(stagePath);
    throw err;
  }

  return {
    restoredAt: utcNow(),
    dbSha256: verified.dbSha256,
    targetDbPath: absTarget,
    tableCounts: verified.tableCounts,
  };
}
