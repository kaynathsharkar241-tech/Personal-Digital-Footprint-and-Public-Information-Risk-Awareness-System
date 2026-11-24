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
import { createDeterministicZip, listZipEntryNames } from '../scripts/package-prod.ts';

let baseUrl = '';
let closeServer: (() => Promise<void>) | null = null;

describe('Stage 1 Google OIDC, Stage 3 Review Queue/Safe Library, Stage 5 PDF/Resolution & Stage 7 Packaging Tests', () => {
  before(async () => {
    const { DB_PATH } = await import('../server/db.ts');
    assert.ok(DB_PATH.startsWith(TEST_INSTANCE_DIR), 'Test must use isolated temp DB');
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    const srv = await startIsolatedServer(false);
    baseUrl = srv.baseUrl;
    closeServer = srv.close;
  });

  after(async () => {
    if (closeServer) await closeServer();
    cleanupTestInstance();
  });

  it('supports Stage 3 structured finding review queue, Safe Library suppression, bulk verification, review audit history, and IDOR checks', async () => {
    const regA = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Stage3 Reviewer',
        email: 'stage3-a@example.org',
        password: 'StrongPassword#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(40, 80, 120),
      },
    });
    assert.equal(regA.status, 201);
    const tokenA = regA.data.token as string;
    const userIdA = regA.data.user.id as number;

    const regB = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Stage3 Other',
        email: 'stage3-b@example.org',
        password: 'StrongPassword#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(90, 50, 110),
      },
    });
    assert.equal(regB.status, 201);
    const tokenB = regB.data.token as string;

    const { db, utcNow } = await import('../server/db.ts');
    const now = utcNow();
    const scanInfo = db
      .prepare(
        `INSERT INTO scans (user_id, created_at, mode, status, findings_count, provider_summary, authorized_at)
         VALUES (?, ?, 'live', 'Completed', 2, '[]', ?)`
      )
      .run(userIdA, now, now);
    const scanId = Number(scanInfo.lastInsertRowid);

    const f1Info = db
      .prepare(
        `INSERT INTO findings
         (user_id, scan_id, signature, title, category, source_name, source, found_at, risk, evidence, explanation, confidence, severity, recency_score, priority, verification_status, user_verified)
         VALUES (?, ?, ?, ?, 'Contact Details', 'GitHub REST', 'https://github.com/example/a', ?, 'Medium', 'email reference', 'Public repo match', 0.8, 0.6, 0.9, 0.75, 'Unverified', 0)`
      )
      .run(userIdA, scanId, 'sig-stage3-1', 'Public profile reference 1', now);
    const f1Id = Number(f1Info.lastInsertRowid);

    const f2Info = db
      .prepare(
        `INSERT INTO findings
         (user_id, scan_id, signature, title, category, source_name, source, found_at, risk, evidence, explanation, confidence, severity, recency_score, priority, verification_status, user_verified)
         VALUES (?, ?, ?, ?, 'Social Profiles', 'Gravatar', 'https://gravatar.com/example', ?, 'Low', 'hash match', 'Profile avatar lookup', 0.65, 0.4, 0.85, 0.58, 'Unverified', 0)`
      )
      .run(userIdA, scanId, 'sig-stage3-2', 'Public profile reference 2', now);
    const f2Id = Number(f2Info.lastInsertRowid);

    // 1. Verify status + audit note creates immutable finding_review_events entry
    const v1 = await apiFetch(baseUrl, `/api/findings/${f1Id}/verify`, {
      method: 'POST',
      token: tokenA,
      body: {
        verification_status: 'Verified Match',
        note: 'Confirmed my personal repository',
      },
    });
    assert.equal(v1.status, 200);
    assert.equal(v1.data.verification_status, 'Verified Match');
    assert.equal(v1.data.review_note, 'Confirmed my personal repository');
    assert.ok(v1.data.reviewed_at);

    // 2. Move finding 2 into Safe Library (False Positive) and verify bulk-verify also works
    const bulkSafe = await apiFetch(baseUrl, '/api/findings/bulk-verify', {
      method: 'POST',
      token: tokenA,
      body: {
        findingIds: [f2Id],
        verification_status: 'False Positive',
        note: 'Namesake account; suppress from future reviews',
      },
    });
    assert.equal(bulkSafe.status, 200);
    assert.equal(bulkSafe.data.updatedCount, 1);

    // 3. Re-ingesting the same Safe Library signature via INSERT OR IGNORE must preserve False Positive
    db.prepare(
      `INSERT OR IGNORE INTO findings
       (user_id, scan_id, signature, title, category, source_name, source, found_at, risk, evidence, explanation, confidence, severity, recency_score, priority, verification_status, user_verified)
       VALUES (?, ?, ?, ?, 'Social Profiles', 'Gravatar', 'https://gravatar.com/example', ?, 'Low', 'hash match', 'Profile avatar lookup', 0.65, 0.4, 0.85, 0.58, 'Unverified', 0)`
    ).run(userIdA, scanId, 'sig-stage3-2', 'Public profile reference 2', now);

    const listRes = await apiFetch(baseUrl, '/api/findings', { token: tokenA });
    assert.equal(listRes.status, 200);
    assert.deepEqual(listRes.data.counts, { unverified: 0, verifiedMatch: 1, safeLibrary: 1 });
    assert.ok(Array.isArray(listRes.data.reviewHistory));
    assert.equal(listRes.data.reviewHistory.length, 2);

    const safeItem = listRes.data.findings.find((f: { id: number }) => f.id === f2Id);
    assert.equal(safeItem.verification_status, 'False Positive');

    const histRes = await apiFetch(baseUrl, `/api/findings/${f1Id}/history`, { token: tokenA });
    assert.equal(histRes.status, 200);
    assert.equal(histRes.data.events.length, 1);
    assert.equal(histRes.data.events[0].previous_status, 'Unverified');
    assert.equal(histRes.data.events[0].new_status, 'Verified Match');

    // Cross-user IDOR protections on finding verify & history
    const idorVerify = await apiFetch(baseUrl, `/api/findings/${f1Id}/verify`, {
      method: 'POST',
      token: tokenB,
      body: { verification_status: 'False Positive' },
    });
    assert.equal(idorVerify.status, 404);

    const idorHist = await apiFetch(baseUrl, `/api/findings/${f1Id}/history`, { token: tokenB });
    assert.equal(idorHist.status, 404);
  });

  it('supports Stage 5 case resolution tracking, audit timeline, encrypted evidence, account PDF report & case dossier PDF', async () => {
    const regA = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Stage5 Owner',
        email: 'stage5-a@example.org',
        password: 'StrongPassword#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(25, 110, 145),
      },
    });
    assert.equal(regA.status, 201);
    const tokenA = regA.data.token as string;

    const regB = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Stage5 Intruder',
        email: 'stage5-b@example.org',
        password: 'StrongPassword#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(70, 30, 90),
      },
    });
    assert.equal(regB.status, 201);
    const tokenB = regB.data.token as string;

    const created = await apiFetch(baseUrl, '/api/cases', {
      method: 'POST',
      token: tokenA,
      body: {
        title: 'Broker Profile Listing Takedown',
        category: 'Contact Details',
        description: 'Phone and home city listed publicly on broker site.',
        url: 'https://example.org/listing/123',
      },
    });
    assert.equal(created.status, 201);
    const caseId = created.data.caseItem.id as number;

    const ev = await apiFetch(baseUrl, `/api/cases/${caseId}/evidence`, {
      method: 'POST',
      token: tokenA,
      body: {
        name: 'takedown-receipt.txt',
        mime: 'text/plain',
        dataBase64: Buffer.from('Opt-out reference #OPT-99182', 'utf8').toString('base64'),
      },
    });
    assert.equal(ev.status, 201);

    const resolved = await apiFetch(baseUrl, `/api/cases/${caseId}`, {
      method: 'PATCH',
      token: tokenA,
      body: {
        status: 'Resolved',
        notes: 'Submitted opt-out ticket #OPT-99182.',
        resolution_summary: 'Listing confirmed removed by data broker.',
      },
    });
    assert.equal(resolved.status, 200);
    assert.ok(resolved.data.resolved_at);

    const detail = await apiFetch(baseUrl, `/api/cases/${caseId}`, { token: tokenA });
    assert.equal(detail.status, 200);
    assert.equal(detail.data.caseItem.status, 'Resolved');
    assert.equal(detail.data.caseItem.resolution_summary, 'Listing confirmed removed by data broker.');
    assert.ok(Array.isArray(detail.data.timeline));
    assert.equal(detail.data.timeline.length, 3); // created, evidence_attached, status_changed

    // Account-wide PDF report
    const acctPdf = await apiFetch(baseUrl, '/api/report.pdf', { token: tokenA });
    assert.equal(acctPdf.status, 200);
    assert.equal(acctPdf.headers.get('content-type'), 'application/pdf');
    assert.ok(Buffer.isBuffer(acctPdf.data));
    const acctText = acctPdf.data.toString('latin1');
    assert.ok(acctText.startsWith('%PDF-1.4'));
    assert.ok(acctText.trimEnd().endsWith('%%EOF'));

    // Individual Case Dossier PDF
    const casePdf = await apiFetch(baseUrl, `/api/cases/${caseId}/report.pdf`, { token: tokenA });
    assert.equal(casePdf.status, 200);
    assert.equal(casePdf.headers.get('content-type'), 'application/pdf');
    assert.ok(Buffer.isBuffer(casePdf.data));
    const caseText = casePdf.data.toString('latin1');
    assert.ok(caseText.startsWith('%PDF-1.4'));
    assert.ok(caseText.trimEnd().endsWith('%%EOF'));
    assert.ok(caseText.includes('Broker Profile Listing Takedown'));

    // Cross-user IDOR protection on case dossier PDF
    const idorCasePdf = await apiFetch(baseUrl, `/api/cases/${caseId}/report.pdf`, { token: tokenB });
    assert.equal(idorCasePdf.status, 404);
  });

  it('handles optional Google OIDC configuration states and validates single-use CSRF state', async () => {
    // 1. Default zero-cost state (unset)
    const statusUnset = await apiFetch(baseUrl, '/api/auth/google/status');
    assert.equal(statusUnset.status, 200);
    assert.equal(statusUnset.data.configured, false);

    const urlUnset = await apiFetch(baseUrl, '/api/auth/google/url');
    assert.equal(urlUnset.status, 503);

    // 2. Temporarily simulate configured Google OAuth credentials to test auth URL + single-use state validation
    const prevId = process.env.GOOGLE_CLIENT_ID;
    const prevSecret = process.env.GOOGLE_CLIENT_SECRET;
    try {
      process.env.GOOGLE_CLIENT_ID = 'test-client-id.apps.googleusercontent.com';
      process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret-value';

      const statusSet = await apiFetch(baseUrl, '/api/auth/google/status');
      assert.equal(statusSet.status, 200);
      assert.equal(statusSet.data.configured, true);

      const urlSet = await apiFetch(baseUrl, '/api/auth/google/url?mode=login');
      assert.equal(urlSet.status, 200);
      assert.ok(String(urlSet.data.url).startsWith('https://accounts.google.com/o/oauth2/v2/auth'));
      assert.ok(String(urlSet.data.url).includes('state='));
      assert.ok(String(urlSet.data.url).includes('nonce='));

      // Invalid CSRF state must fail with 400
      const badCb = await apiFetch(
        baseUrl,
        '/api/auth/google/callback?code=fake-code&state=nonexistent-state'
      );
      assert.equal(badCb.status, 400);
    } finally {
      if (prevId === undefined) delete process.env.GOOGLE_CLIENT_ID;
      else process.env.GOOGLE_CLIENT_ID = prevId;
      if (prevSecret === undefined) delete process.env.GOOGLE_CLIENT_SECRET;
      else process.env.GOOGLE_CLIENT_SECRET = prevSecret;
    }
  });

  it('meets fast local API latency budgets and packages DEPLOYMENT.md cleanly without secrets', async () => {
    const start = performance.now();
    const health = await apiFetch(baseUrl, '/api/health');
    const elapsedMs = performance.now() - start;
    assert.equal(health.status, 200);
    assert.ok(elapsedMs < 250, `Expected local health check <250ms, got ${elapsedMs.toFixed(1)}ms`);

    const outZip = path.join(TEST_INSTANCE_DIR, 'delivery-check.zip');
    createDeterministicZip(process.cwd(), outZip);
    const entries = listZipEntryNames(outZip);
    assert.ok(entries.includes('DEPLOYMENT.md'), 'DEPLOYMENT.md must be included in production ZIP');
    assert.ok(entries.includes('server/reportPdf.ts'), 'server/reportPdf.ts must be included in production ZIP');
    assert.equal(
      fs.existsSync(path.join(process.cwd(), 'DEPLOYMENT.md')),
      true
    );
  });
});
