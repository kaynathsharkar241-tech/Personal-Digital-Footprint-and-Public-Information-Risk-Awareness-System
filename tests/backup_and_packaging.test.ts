import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  TEST_INSTANCE_DIR,
  apiFetch,
  cleanupTestInstance,
  makeValidPngDataUrl,
  startIsolatedServer,
} from './helpers.ts';
import {
  createDeterministicZip,
  isForbiddenArchivePath,
  listZipEntryNames,
} from '../scripts/package-prod.ts';

let baseUrl = '';
let closeServer: (() => Promise<void>) | null = null;
let reviewerToken = '';

describe('Encrypted Backup Restoration & Clean Production ZIP Tests', () => {
  before(async () => {
    process.env.REVIEWER_PASSCODE = 'BackupAdminPass#2026';
    const srv = await startIsolatedServer(false);
    baseUrl = srv.baseUrl;
    closeServer = srv.close;

    const unlock = await apiFetch(baseUrl, '/api/reviewer/unlock', {
      method: 'POST',
      body: { passcode: 'BackupAdminPass#2026' },
    });
    assert.equal(unlock.status, 200);
    reviewerToken = unlock.data.reviewerToken as string;
  });

  after(async () => {
    if (closeServer) await closeServer();
    cleanupTestInstance();
  });

  it('exports AES-256-GCM backup, rejects wrong passphrase/tampering, restores wiped DB & decrypts evidence', async () => {
    const reg = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Backup Subject',
        email: 'backup@example.org',
        password: 'BackupUserPass#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(15, 70, 140),
      },
    });
    assert.equal(reg.status, 201);
    const userToken = reg.data.token as string;

    const caseRes = await apiFetch(baseUrl, '/api/cases', {
      method: 'POST',
      token: userToken,
      body: {
        title: 'Critical Exposure Evidence',
        category: 'Public Records',
        description: 'Encrypted evidence before simulated data loss.',
        url: 'https://example.org/exposure',
      },
    });
    assert.equal(caseRes.status, 201);
    const caseId = caseRes.data.caseItem.id as number;

    const secretText = Buffer.from('Sensitive encrypted evidence document payload 2026', 'utf8');
    const evRes = await apiFetch(baseUrl, `/api/cases/${caseId}/evidence`, {
      method: 'POST',
      token: userToken,
      body: {
        name: 'evidence.txt',
        mime: 'text/plain',
        dataBase64: secretText.toString('base64'),
      },
    });
    assert.equal(evRes.status, 201);
    const evId = evRes.data.id as number;

    // Export encrypted backup via Reviewer HTTP endpoint
    const exportRes = await apiFetch(baseUrl, '/api/reviewer/backup/export', {
      method: 'POST',
      reviewerToken,
      body: { passphrase: 'VaultBackupPassphrase#2026!' },
    });
    assert.equal(exportRes.status, 200);
    assert.ok(Buffer.isBuffer(exportRes.data));
    const backupBuf = exportRes.data;
    const backupText = backupBuf.toString('utf8');
    assert.ok(backupText.includes('PRIVACY_MONITOR_ENC_BACKUP_V1'));
    assert.ok(!backupText.includes('Sensitive encrypted evidence'));

    // Verify wrong passphrase rejected
    const badPassVerify = await apiFetch(baseUrl, '/api/reviewer/backup/verify', {
      method: 'POST',
      reviewerToken,
      body: {
        passphrase: 'WrongPassphrase#2026!',
        backupBase64: backupBuf.toString('base64'),
      },
    });
    assert.equal(badPassVerify.status, 400);

    // Verify tampered ciphertext rejected
    const parsedEnv = JSON.parse(backupText) as Record<string, unknown>;
    parsedEnv.ciphertextB64 = Buffer.from('tampered-data').toString('base64');
    const tamperedVerify = await apiFetch(baseUrl, '/api/reviewer/backup/verify', {
      method: 'POST',
      reviewerToken,
      body: {
        passphrase: 'VaultBackupPassphrase#2026!',
        backupBase64: Buffer.from(JSON.stringify(parsedEnv)).toString('base64'),
      },
    });
    assert.equal(tamperedVerify.status, 400);

    // Valid backup verification passes integrity_check
    const goodVerify = await apiFetch(baseUrl, '/api/reviewer/backup/verify', {
      method: 'POST',
      reviewerToken,
      body: {
        passphrase: 'VaultBackupPassphrase#2026!',
        backupBase64: backupBuf.toString('base64'),
      },
    });
    assert.equal(goodVerify.status, 200);
    assert.equal(goodVerify.data.valid, true);
    assert.equal(goodVerify.data.tableCounts.users, 1);
    assert.equal(goodVerify.data.tableCounts.evidence, 1);

    // Simulate total account deletion / data loss
    const delRes = await apiFetch(baseUrl, '/api/settings/account', {
      method: 'DELETE',
      token: userToken,
      body: { password: 'BackupUserPass#2026!' },
    });
    assert.equal(delRes.status, 200);

    // Restore from encrypted backup
    const restoreRes = await apiFetch(baseUrl, '/api/reviewer/backup/restore', {
      method: 'POST',
      reviewerToken,
      body: {
        passphrase: 'VaultBackupPassphrase#2026!',
        backupBase64: backupBuf.toString('base64'),
      },
    });
    assert.equal(restoreRes.status, 200);
    assert.equal(restoreRes.data.ok, true);

    // Verify restored user can sign in and download decrypted evidence bytes identically
    const loginAfter = await apiFetch(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'backup@example.org',
        method: 'password',
        secret: 'BackupUserPass#2026!',
      },
    });
    assert.equal(loginAfter.status, 200);

    const restoredEv = await apiFetch(baseUrl, `/api/cases/${caseId}/evidence/${evId}`, {
      token: loginAfter.data.token as string,
    });
    assert.equal(restoredEv.status, 200);
    assert.equal(Buffer.compare(restoredEv.data, secretText), 0);

    // Also test file-level restoreEncryptedBackupToFile
    const { restoreEncryptedBackupToFile } = await import('../server/backup.ts');
    const restoredPath = path.join(TEST_INSTANCE_DIR, 'cold-restore.sqlite3');
    const fileRes = restoreEncryptedBackupToFile(
      backupBuf,
      'VaultBackupPassphrase#2026!',
      restoredPath
    );
    assert.equal(fs.existsSync(restoredPath), true);
    assert.equal(fileRes.dbSha256, goodVerify.data.dbSha256);
  });

  it('builds deterministic production ZIP containing zero SQLite databases, WAL files, secrets, or Python scripts', () => {
    const outZip = path.join(TEST_INSTANCE_DIR, 'test-prod.zip');
    const result = createDeterministicZip(process.cwd(), outZip);
    assert.ok(result.files.length > 10);
    assert.ok(result.files.includes('package.json'));
    assert.ok(result.files.includes('server.ts'));
    assert.ok(result.files.includes('server/app.ts'));
    assert.ok(result.files.includes('src/App.tsx'));

    const entries = listZipEntryNames(outZip);
    assert.equal(entries.length, result.files.length);
    for (const entry of entries) {
      assert.equal(
        isForbiddenArchivePath(entry),
        false,
        `Forbidden sensitive file found in ZIP: ${entry}`
      );
      assert.ok(!entry.startsWith('tests/'), `Test files should not ship in prod ZIP: ${entry}`);
    }
  });
});
