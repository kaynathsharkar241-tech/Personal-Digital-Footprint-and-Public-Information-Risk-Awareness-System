import { sha256Hex } from './crypto.ts';
import { db, utcNow } from './db.ts';
import { getProviderCatalog, runOsintScan } from './providers/registry.ts';
import { computePriority } from './scanner.ts';

const FREQUENCY_MS: Record<string, number> = {
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
  monthly: 30 * 24 * 60 * 60 * 1000,
};

export interface DueMonitorRow {
  user_id: number;
  email: string;
  full_name: string;
  username: string;
  terms: string;
  domains: string;
  frequency: string;
  enabled: number;
  authorization_confirmed: number;
  authorization_at: string | null;
  last_scheduled_scan_at: string | null;
  email_verified_at: string | null;
  selfie_status: string | null;
}

let schedulerTimer: ReturnType<typeof setInterval> | null = null;
let schedulerRunning = false;
let lastTickAt: string | null = null;
let lastTickSummary: { processedUsers: number; newFindings: number; errors: number } | null = null;

function getPriorityWeightsForUser(userId: number) {
  const row = db
    .prepare('SELECT confidence_weight, severity_weight, recency_weight FROM priority_weights WHERE user_id = ?')
    .get(userId) as
    | { confidence_weight: number; severity_weight: number; recency_weight: number }
    | undefined;
  return (
    row ?? {
      confidence_weight: 0.45,
      severity_weight: 0.35,
      recency_weight: 0.2,
    }
  );
}

export async function executeScanForUser(
  userId: number,
  mode: 'live' | 'scheduled',
  overrideAuthorizedAt?: string
) {
  const userRow = db
    .prepare(
      `SELECT u.id, u.email, u.email_verified_at, e.status AS selfie_status,
              m.full_name, m.username, m.terms, m.domains, m.enabled,
              m.authorization_confirmed, m.authorization_at
       FROM users u
       LEFT JOIN identity_enrollments e ON e.user_id = u.id
       LEFT JOIN monitors m ON m.user_id = u.id
       WHERE u.id = ?`
    )
    .get(userId) as
    | {
        id: number;
        email: string;
        email_verified_at: string | null;
        selfie_status: string | null;
        full_name: string | null;
        username: string | null;
        terms: string | null;
        domains: string | null;
        enabled: number | null;
        authorization_confirmed: number | null;
        authorization_at: string | null;
      }
    | undefined;

  if (!userRow) throw new Error('Account not found.');
  if (!userRow.email_verified_at || userRow.selfie_status !== 'approved') {
    throw new Error('Identity verification (verified email and approved selfie) is required before scanning.');
  }
  if (!userRow.full_name?.trim()) {
    throw new Error('Save your monitoring profile before running a scan.');
  }
  if (!userRow.enabled) {
    throw new Error('Monitoring is currently paused.');
  }

  const authorizedAt = overrideAuthorizedAt || userRow.authorization_at || utcNow();
  if (!userRow.authorization_confirmed && !overrideAuthorizedAt) {
    throw new Error('Explicit user authorization is required before querying OSINT providers.');
  }

  const termsList = (userRow.terms || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length >= 2);
  const domainsList = (userRow.domains || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length >= 3);

  const now = utcNow();
  const scanOutcome = await runOsintScan({
    userId,
    email: userRow.email,
    fullName: userRow.full_name,
    username: userRow.username || '',
    terms: termsList,
    domains: domainsList,
    authorizedAt,
  });

  const compactSummary = scanOutcome.providerResults.map((p) => ({
    providerId: p.providerId,
    providerName: p.providerName,
    categoryFocus: p.categoryFocus,
    status: p.status,
    findingsCount: p.findings.length,
    cached: p.cached,
    latencyMs: p.latencyMs,
    requiresKey: p.requiresKey,
    keyEnvVar: p.keyEnvVar,
    message: p.message,
  }));

  const parts = [`${scanOutcome.okProviders} active provider(s) succeeded`];
  if (scanOutcome.skippedCount > 0) {
    parts.push(`${scanOutcome.skippedCount} skipped`);
  }
  if (scanOutcome.failedOrUnavailableProviders.length > 0) {
    parts.push(`${scanOutcome.failedOrUnavailableProviders.length} unavailable/failed`);
  }

  const scanStatusText = scanOutcome.incompleteCoverage
    ? `Partial coverage (${mode}): ${parts.join('; ')}`
    : scanOutcome.hasSkippedProviders
    ? `Completed with skipped checks (${mode}): ${parts.join('; ')}`
    : `Completed (${mode}): ${parts.join('; ')}`;

  const scanRes = db
    .prepare(
      `INSERT INTO scans (user_id, created_at, mode, status, findings_count, provider_summary, authorized_at)
       VALUES (?, ?, ?, ?, 0, ?, ?)`
    )
    .run(userId, now, mode, scanStatusText, JSON.stringify(compactSummary), authorizedAt);
  const scanId = Number(scanRes.lastInsertRowid);

  const weights = getPriorityWeightsForUser(userId);
  let inserted = 0;
  const insertStmt = db.prepare(
    `INSERT OR IGNORE INTO findings
     (user_id, scan_id, signature, title, category, source_name, source, found_at, risk, evidence, explanation, confidence, severity, recency_score, priority, verification_status, user_verified)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
  );

  for (const f of scanOutcome.findings) {
    const sig = sha256Hex(`${f.sourceName}|${f.category}|${f.sourceUrl}|${f.title}`);
    // Unverified matches must not be treated as
    // confirmed personal privacy exposures.
    const isVerified = f.verificationStatus === 'Verified Match';

    const priority = isVerified
      ? computePriority(
          f.confidence,
          f.severity,
          f.recencyScore,
          weights
        )
      : 0;
    const r = insertStmt.run(
      userId,
      scanId,
      sig,
      f.title,
      f.category,
      f.sourceName,
      f.sourceUrl,
      f.foundAt,
      f.risk,
      f.evidence,
      f.explanation,
      f.confidence,
      f.severity,
      f.recencyScore,
      priority,
      f.verificationStatus
    );
    inserted += Number(r.changes);
  }

  db.prepare('UPDATE scans SET findings_count = ? WHERE id = ?').run(inserted, scanId);

  if (mode === 'scheduled') {
    db.prepare('UPDATE monitors SET last_scheduled_scan_at = ? WHERE user_id = ?').run(now, userId);
  }

  const label = mode === 'scheduled' ? 'Scheduled OSINT scan' : 'Real OSINT scan';
  db.prepare('INSERT INTO notifications (user_id, body, created_at) VALUES (?, ?, ?)').run(
    userId,
    `${label} recorded ${inserted} new match(es) (${parts.join(', ')}).`,
    now
  );

  return {
    ok: true,
    scanId,
    mode,
    newFindings: inserted,
    totalReturned: scanOutcome.findings.length,
    okProviders: scanOutcome.okProviders,
    skippedCount: scanOutcome.skippedCount,
    totalProviders: scanOutcome.totalProviders,
    incompleteCoverage: scanOutcome.incompleteCoverage,
    hasSkippedProviders: scanOutcome.hasSkippedProviders,
    skippedProviders: scanOutcome.skippedProviders,
    failedOrUnavailableProviders: scanOutcome.failedOrUnavailableProviders,
    providerResults: compactSummary,
    providers: getProviderCatalog(),
  };
}

export function isMonitorDue(
  monitor: {
    enabled: number;
    authorization_confirmed: number;
    frequency: string;
    last_scheduled_scan_at: string | null;
    email_verified_at: string | null;
    selfie_status: string | null;
    full_name: string;
  },
  nowMs = Date.now()
): boolean {
  if (!monitor.enabled || !monitor.authorization_confirmed) return false;
  if (!monitor.email_verified_at || monitor.selfie_status !== 'approved') return false;
  if (!monitor.full_name?.trim()) return false;

  if (!monitor.last_scheduled_scan_at) return true;
  const lastMs = Date.parse(monitor.last_scheduled_scan_at);
  if (!Number.isFinite(lastMs)) return true;

  const interval = FREQUENCY_MS[monitor.frequency] ?? FREQUENCY_MS.weekly;
  return nowMs - lastMs >= interval;
}

export async function runDueScheduledScansOnce(nowMs = Date.now()): Promise<{
  processedUsers: number;
  newFindings: number;
  errors: number;
}> {
  if (schedulerRunning) {
    return { processedUsers: 0, newFindings: 0, errors: 0 };
  }
  schedulerRunning = true;
  let processedUsers = 0;
  let newFindings = 0;
  let errors = 0;

  try {
    const candidates = db
      .prepare(
        `SELECT m.user_id, u.email, m.full_name, m.username, m.terms, m.domains,
                m.frequency, m.enabled, m.authorization_confirmed, m.authorization_at,
                m.last_scheduled_scan_at, u.email_verified_at, e.status AS selfie_status
         FROM monitors m
         JOIN users u ON u.id = m.user_id
         LEFT JOIN identity_enrollments e ON e.user_id = m.user_id
         WHERE m.enabled = 1 AND m.authorization_confirmed = 1`
      )
      .all() as unknown as DueMonitorRow[];

    for (const candidate of candidates) {
      if (!isMonitorDue(candidate, nowMs)) continue;
      try {
        const res = await executeScanForUser(
          candidate.user_id,
          'scheduled',
          candidate.authorization_at || utcNow()
        );
        processedUsers++;
        newFindings += res.newFindings;
      } catch (err) {
        errors++;
        db.prepare(
          `INSERT INTO scans (user_id, created_at, mode, status, findings_count, provider_summary, authorized_at)
           VALUES (?, ?, 'scheduled', ?, 0, '[]', ?)`
        ).run(
          candidate.user_id,
          utcNow(),
          `Scheduled scan failed: ${(err instanceof Error ? err.message : String(err)).slice(0, 180)}`,
          candidate.authorization_at || utcNow()
        );
      }
    }

    lastTickAt = utcNow();
    lastTickSummary = { processedUsers, newFindings, errors };
    return { processedUsers, newFindings, errors };
  } finally {
    schedulerRunning = false;
  }
}

export function startScheduler(intervalMs = 60_000): void {
  if (schedulerTimer || process.env.DISABLE_SCHEDULER === 'true') return;
  schedulerTimer = setInterval(() => {
    runDueScheduledScansOnce().catch((err) => {
      console.error('Scheduled scan worker error:', err);
    });
  }, intervalMs);
  schedulerTimer.unref?.();
}

export function stopScheduler(): void {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
  }
}

export function getSchedulerStatus(userId?: number) {
  let userMonitor:
    | {
        frequency: string;
        enabled: number;
        authorization_confirmed: number;
        last_scheduled_scan_at: string | null;
      }
    | undefined;
  if (userId) {
    userMonitor = db
      .prepare(
        'SELECT frequency, enabled, authorization_confirmed, last_scheduled_scan_at FROM monitors WHERE user_id = ?'
      )
      .get(userId) as typeof userMonitor;
  }
  let nextDueAt: string | null = null;
  if (userMonitor?.enabled && userMonitor.authorization_confirmed) {
    if (!userMonitor.last_scheduled_scan_at) {
      nextDueAt = utcNow();
    } else {
      const interval = FREQUENCY_MS[userMonitor.frequency] ?? FREQUENCY_MS.weekly;
      const lastMs = Date.parse(userMonitor.last_scheduled_scan_at);
      if (Number.isFinite(lastMs)) {
        nextDueAt = new Date(lastMs + interval).toISOString().replace(/\.\d{3}Z$/, 'Z');
      }
    }
  }
  return {
    active: Boolean(schedulerTimer),
    currentlyRunning: schedulerRunning,
    lastTickAt,
    lastTickSummary,
    nextDueAt,
    lastScheduledScanAt: userMonitor?.last_scheduled_scan_at ?? null,
  };
}
