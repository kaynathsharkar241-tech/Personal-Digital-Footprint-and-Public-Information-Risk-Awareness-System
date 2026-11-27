import assert from 'node:assert/strict';
import { installEmailMock, getDeliveredOTP } from './emailMock.ts';

let restoreEmailMock: (() => void) | null = null;
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  TEST_INSTANCE_DIR,
  apiFetch,
  cleanupTestInstance,
  makeValidPngBuffer,
  makeValidPngDataUrl,
  startIsolatedServer,
} from './helpers.ts';

let baseUrl = '';
let closeServer: (() => Promise<void>) | null = null;

describe('Security, Authentication, Encryption, Reviewer & Consent Tests', () => {
  before(async () => {
    const { DB_PATH } = await import('../server/db.ts');
    assert.ok(DB_PATH.startsWith(TEST_INSTANCE_DIR), 'Test must never touch live instance DB');
    restoreEmailMock = installEmailMock();
    const srv = await startIsolatedServer(false);
    baseUrl = srv.baseUrl;
    closeServer = srv.close;
  });

  after(async () => {
    if (closeServer) await closeServer();
    restoreEmailMock?.();
    cleanupTestInstance();
  });

  it('validates runtime configuration safely', async () => {
    const { validateRuntimeConfiguration } = await import('../server/security.ts');
    const bad = validateRuntimeConfiguration({ isProd: false, sessionSecret: 'short' });
    assert.equal(bad.ok, false);
    assert.ok(bad.errors.some((e) => e.includes('at least 32 characters')));

    const placeholder = validateRuntimeConfiguration({
      isProd: false,
      sessionSecret: 'change_me',
    });
    assert.equal(placeholder.ok, false);

    const good = validateRuntimeConfiguration({
      isProd: false,
      sessionSecret: 'a'.repeat(64),
    });
    assert.equal(good.ok, true);
  });

  it('sets mandatory HTTP security headers across API responses', async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    assert.equal(res.headers.get('x-dns-prefetch-control'), 'off');
    assert.equal(res.headers.get('cross-origin-resource-policy'), 'same-origin');
    assert.ok((res.headers.get('cache-control') || '').includes('no-store'));
    const csp = res.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("default-src 'self'"));
    assert.ok(csp.includes("object-src 'none'"));
    assert.ok(csp.includes('frame-ancestors'));
  });

  it('registers user, confirms email, checks resend cooldown, encrypts/decrypts selfie & evidence, and isolates users (IDOR)', async () => {
    const selfiePng = makeValidPngBuffer(20, 120, 180);
    const selfieDataUrl = `data:image/png;base64,${selfiePng.toString('base64')}`;

    const regA = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Alice Security',
        email: 'alice@example.org',
        password: 'StrongPassword#2026!',
        biometricConsent: true,
        aiBiometricConsent: false,
        selfieDataUrl,
      },
    });
    assert.equal(regA.status, 201);
    const tokenA = regA.data.token as string;
    const recoveryCodesA = regA.data.recoveryCodes as string[];
    const verifyTokenA = getDeliveredOTP('alice@example.org');
    assert.match(verifyTokenA, /^\d{6}$/);
    assert.equal(regA.data.previewVerificationToken, undefined);
    assert.equal(recoveryCodesA.length, 8);
    assert.equal(regA.data.user.aiBiometricConsent, false);

    // Resend immediately must trigger 60s cooldown (429)
    const resendCooldown = await apiFetch(baseUrl, '/api/auth/verify-email/resend', {
      method: 'POST',
      token: tokenA,
    });
    assert.equal(resendCooldown.status, 429);

    // Confirm email with single-use token
    const confirmOk = await apiFetch(baseUrl, '/api/auth/verify-email/confirm', {
      method: 'POST',
      token: tokenA,
      body: { token: verifyTokenA },
    });
    assert.equal(confirmOk.status, 200);
    assert.equal(confirmOk.data.user.emailVerified, true);

    // Reusing the same email verification token must fail
    const confirmReplay = await apiFetch(baseUrl, '/api/auth/verify-email/confirm', {
      method: 'POST',
      token: tokenA,
      body: { token: verifyTokenA },
    });
    assert.equal(confirmReplay.status, 400);

    // Encrypted enrollment selfie retrieval matches exact plaintext PNG bytes
    const selfieGet = await apiFetch(baseUrl, '/api/identity/selfie', { token: tokenA });
    assert.equal(selfieGet.status, 200);
    assert.ok(Buffer.isBuffer(selfieGet.data));
    assert.equal(Buffer.compare(selfieGet.data, selfiePng), 0);

    // Set fallback PIN & verify login via PIN and single-use recovery code
    const pinSet = await apiFetch(baseUrl, '/api/auth/pin', {
      method: 'POST',
      token: tokenA,
      body: { pin: '246810' },
    });
    assert.equal(pinSet.status, 200);

    const pinLogin = await apiFetch(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'alice@example.org', method: 'pin', secret: '246810' },
    });
    assert.equal(pinLogin.status, 200);
    assert.ok(pinLogin.data.token);

    const recLogin1 = await apiFetch(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'alice@example.org', method: 'recovery', secret: recoveryCodesA[0] },
    });
    assert.equal(recLogin1.status, 200);

    const recLoginReplay = await apiFetch(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'alice@example.org', method: 'recovery', secret: recoveryCodesA[0] },
    });
    assert.equal(recLoginReplay.status, 401);

    // Monitoring photo upload WITHOUT aiBiometricConsent must NOT invoke Gemini and stores photo encrypted
    const photoPng = makeValidPngBuffer(200, 80, 40);
    const photoUpload = await apiFetch(baseUrl, '/api/photos', {
      method: 'POST',
      token: tokenA,
      body: {
        label: 'Local-Only Photo',
        imageDataUrl: `data:image/png;base64,${photoPng.toString('base64')}`,
      },
    });
    assert.equal(photoUpload.status, 201);
    assert.equal(photoUpload.data.aiScreeningUsed, false);
    assert.equal(photoUpload.data.matchResult, 'not_checked');

    const photoFetch = await apiFetch(baseUrl, `/api/photos/${photoUpload.data.id}/image`, {
      token: tokenA,
    });
    assert.equal(photoFetch.status, 200);
    assert.equal(Buffer.compare(photoFetch.data, photoPng), 0);

    // Toggle AI biometric consent on and off
    const aiOn = await apiFetch(baseUrl, '/api/identity/ai-consent', {
      method: 'PUT',
      token: tokenA,
      body: { consent: true },
    });
    assert.equal(aiOn.status, 200);
    assert.equal(aiOn.data.user.aiBiometricConsent, true);

    const aiOff = await apiFetch(baseUrl, '/api/identity/ai-consent', {
      method: 'PUT',
      token: tokenA,
      body: { consent: false },
    });
    assert.equal(aiOff.status, 200);
    assert.equal(aiOff.data.user.aiBiometricConsent, false);

    // Create case + encrypted evidence
    const caseRes = await apiFetch(baseUrl, '/api/cases', {
      method: 'POST',
      token: tokenA,
      body: {
        title: 'Leak Report',
        category: 'Contact Details',
        description: 'Testing encrypted vault storage.',
        url: 'https://example.org/item',
      },
    });
    assert.equal(caseRes.status, 201);
    const caseId = caseRes.data.caseItem.id as number;

    const evidenceBytes = Buffer.from('%PDF-1.4\n%Encrypted evidence payload\n', 'utf8');
    const evUp = await apiFetch(baseUrl, `/api/cases/${caseId}/evidence`, {
      method: 'POST',
      token: tokenA,
      body: {
        name: 'notice.pdf',
        mime: 'application/pdf',
        dataBase64: evidenceBytes.toString('base64'),
      },
    });
    assert.equal(evUp.status, 201);

    const evDown = await apiFetch(baseUrl, `/api/cases/${caseId}/evidence/${evUp.data.id}`, {
      token: tokenA,
    });
    assert.equal(evDown.status, 200);
    assert.equal(Buffer.compare(evDown.data, evidenceBytes), 0);

    // Register User B and assert User B cannot access User A's selfie, photo, case, or evidence (IDOR defense)
    const regB = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Bob Attacker',
        email: 'bob@example.org',
        password: 'AnotherStrongPassword#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(99, 99, 99),
      },
    });
    assert.equal(regB.status, 201);
    const tokenB = regB.data.token as string;

    const idorPhoto = await apiFetch(baseUrl, `/api/photos/${photoUpload.data.id}/image`, {
      token: tokenB,
    });
    assert.equal(idorPhoto.status, 404);

    const idorCase = await apiFetch(baseUrl, `/api/cases/${caseId}`, { token: tokenB });
    assert.equal(idorCase.status, 404);

    const idorEvidence = await apiFetch(baseUrl, `/api/cases/${caseId}/evidence/${evUp.data.id}`, {
      token: tokenB,
    });
    assert.equal(idorEvidence.status, 404);

    const unauthScan = await apiFetch(baseUrl, '/api/scan', { method: 'POST' });
    assert.equal(unauthScan.status, 401);
  });

  it('enforces login brute-force lockout after 5 failures', async () => {
    for (let i = 0; i < 5; i++) {
      const fail = await apiFetch(baseUrl, '/api/auth/login', {
        method: 'POST',
        body: { email: 'lockout-target@example.org', method: 'password', secret: 'WrongPass#123' },
      });
      assert.equal(fail.status, 401);
    }
    const locked = await apiFetch(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'lockout-target@example.org', method: 'password', secret: 'WrongPass#123' },
    });
    assert.equal(locked.status, 429);
    assert.ok(Number(locked.headers.get('retry-after')) >= 1);
  });

  it('hardens reviewer claim, enforces brute-force lockout, supports revocable lock, and unlocks live scans', async () => {
    process.env.REVIEWER_BOOTSTRAP_TOKEN = 'bootstrap-secret-987654';

    // Short passcode rejected
    const weakClaim = await apiFetch(baseUrl, '/api/reviewer/claim', {
      method: 'POST',
      body: { passcode: 'short123', bootstrapToken: 'bootstrap-secret-987654' },
    });
    assert.equal(weakClaim.status, 400);

    // Wrong bootstrap token rejected
    const badBoot = await apiFetch(baseUrl, '/api/reviewer/claim', {
      method: 'POST',
      body: { passcode: 'StrongReviewer#2026', bootstrapToken: 'wrong-token' },
    });
    assert.equal(badBoot.status, 403);

    // Valid first-run claim succeeds
    const validClaim = await apiFetch(baseUrl, '/api/reviewer/claim', {
      method: 'POST',
      body: { passcode: 'StrongReviewer#2026', bootstrapToken: 'bootstrap-secret-987654' },
    });
    assert.equal(validClaim.status, 200);
    const revTok1 = validClaim.data.reviewerToken as string;

    // Second claim must fail with 409
    const secondClaim = await apiFetch(baseUrl, '/api/reviewer/claim', {
      method: 'POST',
      body: { passcode: 'AnotherPasscode#2026', bootstrapToken: 'bootstrap-secret-987654' },
    });
    assert.equal(secondClaim.status, 409);

    delete process.env.REVIEWER_BOOTSTRAP_TOKEN;

    // Lock console revokes token server-side
    const queueOk = await apiFetch(baseUrl, '/api/reviewer/queue', { reviewerToken: revTok1 });
    assert.equal(queueOk.status, 200);

    const lockRes = await apiFetch(baseUrl, '/api/reviewer/lock', {
      method: 'POST',
      reviewerToken: revTok1,
    });
    assert.equal(lockRes.status, 200);

    const queueAfterLock = await apiFetch(baseUrl, '/api/reviewer/queue', {
      reviewerToken: revTok1,
    });
    assert.equal(queueAfterLock.status, 403);

    // 5 failed reviewer unlocks trigger 429 lockout
    for (let i = 0; i < 5; i++) {
      const badUnlock = await apiFetch(baseUrl, '/api/reviewer/unlock', {
        method: 'POST',
        body: { passcode: `wrong-${i}` },
      });
      assert.equal(badUnlock.status, 401);
    }
    const revLocked = await apiFetch(baseUrl, '/api/reviewer/unlock', {
      method: 'POST',
      body: { passcode: 'StrongReviewer#2026' },
    });
    assert.equal(revLocked.status, 429);

    // Reset rate limit bucket directly to verify clean unlock + identity approval workflow
    const { resetRateLimitBucket } = await import('../server/security.ts');
    resetRateLimitBucket('reviewer_unlock:127.0.0.1');
    const cleanUnlock = await apiFetch(baseUrl, '/api/reviewer/unlock', {
      method: 'POST',
      body: { passcode: 'StrongReviewer#2026' },
    });
    assert.equal(cleanUnlock.status, 200);
    const revTok2 = cleanUnlock.data.reviewerToken as string;

    // Approve Alice (user_id = 1)
    const decide = await apiFetch(baseUrl, '/api/reviewer/decide', {
      method: 'POST',
      reviewerToken: revTok2,
      body: {
        targetType: 'identity',
        targetId: 1,
        decision: 'approved',
        reason: 'Verified test identity enrollment',
      },
    });
    assert.equal(decide.status, 200);

    // Check Alice now has liveScanReady = true
    const aliceLogin = await apiFetch(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'alice@example.org', method: 'password', secret: 'StrongPassword#2026!' },
    });
    assert.equal(aliceLogin.status, 200);
    assert.equal(aliceLogin.data.user.liveScanReady, true);
  });

  it('cascades account deletion across all encrypted tables and invalidates sessions', async () => {
    const loginRes = await apiFetch(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'bob@example.org', method: 'password', secret: 'AnotherStrongPassword#2026!' },
    });
    assert.equal(loginRes.status, 200);
    const bobToken = loginRes.data.token as string;
    const bobId = loginRes.data.user.id as number;

    const wrongDel = await apiFetch(baseUrl, '/api/settings/account', {
      method: 'DELETE',
      token: bobToken,
      body: { password: 'WrongPassword!' },
    });
    assert.equal(wrongDel.status, 403);

    const okDel = await apiFetch(baseUrl, '/api/settings/account', {
      method: 'DELETE',
      token: bobToken,
      body: { password: 'AnotherStrongPassword#2026!' },
    });
    assert.equal(okDel.status, 200);

    const meAfter = await apiFetch(baseUrl, '/api/auth/me', { token: bobToken });
    assert.equal(meAfter.status, 401);

    const { db } = await import('../server/db.ts');
    assert.equal(db.prepare('SELECT id FROM users WHERE id = ?').get(bobId), undefined);
    assert.equal(
      db.prepare('SELECT user_id FROM identity_enrollments WHERE user_id = ?').get(bobId),
      undefined
    );
    assert.equal(db.prepare('SELECT user_id FROM monitors WHERE user_id = ?').get(bobId), undefined);
  });
});
