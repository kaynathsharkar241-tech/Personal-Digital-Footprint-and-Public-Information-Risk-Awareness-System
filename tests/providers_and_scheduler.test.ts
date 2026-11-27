import assert from 'node:assert/strict';
import { installEmailMock, getDeliveredOTP } from './emailMock.ts';
import { after, before, describe, it } from 'node:test';
import {
  apiFetch,
  cleanupTestInstance,
  makeValidPngDataUrl,
  startIsolatedServer,
} from './helpers.ts';

let baseUrl = '';
let closeServer: (() => Promise<void>) | null = null;
let userToken = '';
let userId = 0;
let restoreEmailMock: (() => void) | null = null;

describe('OSINT Provider Coverage, Scheduled Worker & Live Free API Tests', () => {
  before(async () => {
    process.env.REVIEWER_PASSCODE = 'SchedulerReviewer#2026';
    restoreEmailMock = installEmailMock();
    const srv = await startIsolatedServer(false);
    baseUrl = srv.baseUrl;
    closeServer = srv.close;

    // Register user + verify email + approve selfie via reviewer
    const reg = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Octocat Security',
        email: 'security-test@gmail.com',
        password: 'ScanUserPassword#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(),
      },
    });
    assert.equal(reg.status, 201);
    userToken = reg.data.token as string;
    userId = reg.data.user.id as number;

    const verify = await apiFetch(baseUrl, '/api/auth/verify-email/confirm', {
      method: 'POST',
      token: userToken,
      body: { token: getDeliveredOTP('security-test@gmail.com') },
    });
    assert.equal(verify.status, 200);

    const revUnlock = await apiFetch(baseUrl, '/api/reviewer/unlock', {
      method: 'POST',
      body: { passcode: 'SchedulerReviewer#2026' },
    });
    assert.equal(revUnlock.status, 200);

    const approve = await apiFetch(baseUrl, '/api/reviewer/decide', {
      method: 'POST',
      reviewerToken: revUnlock.data.reviewerToken,
      body: {
        targetType: 'identity',
        targetId: userId,
        decision: 'approved',
        reason: 'Automated test approval',
      },
    });
    assert.equal(approve.status, 200);
  });

  after(async () => {
    if (closeServer) await closeServer();
    restoreEmailMock?.();
    cleanupTestInstance();
  });

  it('computes due monitoring schedules cleanly via isMonitorDue()', async () => {
    const { isMonitorDue } = await import('../server/scheduler.ts');
    const now = Date.parse('2026-11-24T12:00:00Z');

    assert.equal(
      isMonitorDue(
        {
          enabled: 1,
          authorization_confirmed: 1,
          frequency: 'daily',
          last_scheduled_scan_at: null,
          email_verified_at: '2026-11-20T00:00:00Z',
          selfie_status: 'approved',
          full_name: 'Alice',
        },
        now
      ),
      true
    );

    assert.equal(
      isMonitorDue(
        {
          enabled: 1,
          authorization_confirmed: 1,
          frequency: 'daily',
          last_scheduled_scan_at: '2026-11-24T06:00:00Z', // 6h ago < 24h
          email_verified_at: '2026-11-20T00:00:00Z',
          selfie_status: 'approved',
          full_name: 'Alice',
        },
        now
      ),
      false
    );

    assert.equal(
      isMonitorDue(
        {
          enabled: 1,
          authorization_confirmed: 0,
          frequency: 'daily',
          last_scheduled_scan_at: null,
          email_verified_at: '2026-11-20T00:00:00Z',
          selfie_status: 'approved',
          full_name: 'Alice',
        },
        now
      ),
      false
    );
  });

  it('reports skipped providers accurately when optional domain/username inputs are omitted', async () => {
    const saveMon = await apiFetch(baseUrl, '/api/monitoring', {
      method: 'PUT',
      token: userToken,
      body: {
        full_name: 'Octocat Security',
        username: '',
        terms: 'openssl',
        domains: '',
        frequency: 'daily',
        enabled: 1,
        authorization_confirmed: 1,
      },
    });
    assert.equal(saveMon.status, 200);

    const scanRes = await apiFetch(baseUrl, '/api/scan', {
      method: 'POST',
      token: userToken,
      body: { authorized: true },
    });
    assert.equal(scanRes.status, 200);
    assert.equal(scanRes.data.ok, true);
    assert.ok(scanRes.data.skippedCount > 0, 'Should report skipped providers when domains/username are blank');
    assert.equal(scanRes.data.hasSkippedProviders, true);
    assert.ok(Array.isArray(scanRes.data.skippedProviders));
    assert.ok(
      scanRes.data.skippedProviders.some((p: { providerId: string }) => p.providerId === 'crtsh')
    );

    // Dashboard & /api/findings must also include skippedCount and skippedProviders
    const dash = await apiFetch(baseUrl, '/api/dashboard', { token: userToken });
    assert.equal(dash.status, 200);
    assert.ok(dash.data.lastScan.skippedCount > 0);
    assert.ok(Array.isArray(dash.data.lastScan.skippedProviders));

    const findRes = await apiFetch(baseUrl, '/api/findings', { token: userToken });
    assert.equal(findRes.status, 200);
    assert.ok(findRes.data.scans[0].skippedCount > 0);
  });

  it('executes scheduled scan worker runDueScheduledScansOnce() and verifies live free OSINT APIs', async () => {
    // Configure full monitoring profile with handle + domain + keywords
    const saveFull = await apiFetch(baseUrl, '/api/monitoring', {
      method: 'PUT',
      token: userToken,
      body: {
        full_name: 'Octocat',
        username: 'octocat',
        terms: 'openssl',
        domains: 'example.com',
        frequency: 'daily',
        enabled: 1,
        authorization_confirmed: 1,
      },
    });
    assert.equal(saveFull.status, 200);

    const { runDueScheduledScansOnce, getSchedulerStatus } = await import('../server/scheduler.ts');
    const tickRes = await runDueScheduledScansOnce(Date.now());
    assert.equal(tickRes.processedUsers, 1);
    assert.equal(tickRes.errors, 0);

    const schedHttp = await apiFetch(baseUrl, '/api/scheduler/status', { token: userToken });
    assert.equal(schedHttp.status, 200);
    assert.ok(schedHttp.data.lastScheduledScanAt, 'Scheduled scan timestamp must be recorded');
    assert.ok(getSchedulerStatus(userId).nextDueAt);

    // Verify scheduled scan appears in scan history with mode = 'scheduled'
    const findRes = await apiFetch(baseUrl, '/api/findings', { token: userToken });
    assert.equal(findRes.status, 200);
    const latestScan = findRes.data.scans[0];
    assert.equal(latestScan.mode, 'scheduled');

    const statusMap = new Map<string, { status: string; findingsCount: number; message: string }>(
      (latestScan.providerSummary as Array<{ providerId: string; status: string; findingsCount: number; message: string }>).map(
        (p) => [p.providerId, { status: p.status, findingsCount: p.findingsCount, message: p.message }]
      )
    );
    for (const id of ['github', 'gravatar', 'stopforumspam', 'rdap_dns', 'nvd_cve', 'cisa_kev', 'hn_algolia', 'wikipedia']) {
      assert.equal(statusMap.get(id)?.status, 'ok', `Expected live free provider ${id} to return status=ok, got ${JSON.stringify(statusMap.get(id))}`);
    }
    console.log('LIVE_PROVIDER_EVIDENCE:', JSON.stringify(Object.fromEntries(statusMap)));

    // Also test real HIBP Pwned Passwords k-anonymity range check against known breached password
    const pwRes = await apiFetch(baseUrl, '/api/security/check-password', {
      method: 'POST',
      token: userToken,
      body: { password: 'password123', label: 'Known Compromised Test', recordFinding: true },
    });
    assert.equal(pwRes.status, 200);
    assert.equal(pwRes.data.compromised, true);
    assert.ok(pwRes.data.pwnedCount > 1000);
    assert.ok(pwRes.data.recordedFindingId);
  });
});
