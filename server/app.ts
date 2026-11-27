import crypto from 'node:crypto';
import { inspectFace, assessMovement } from './faceEngine.ts';
import {
  generateEmailOTP,
  hashEmailOTP,
  getOTPExpiry,
  isEmailConfigured,
  sendVerificationEmail,
} from './email.ts';
import type http from 'node:http';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { db, utcNow } from './db.ts';
import {
  decryptBuffer,
  encryptBuffer,
  generateRecoveryCodes,
  generateToken,
  hashSecret,
  loadOrCreateSessionSecret,
  sha256Hex,
  verifySecret,
} from './crypto.ts';
import {
  assessSingleFinding,
  draftCaseResponse,
  extractGeminiError,
  generateExposureOverview,
  screenFaceSimilarityWithAI,
} from './gemini.ts';
import { CATEGORIES, QUESTIONS, RESPONSE_GUIDES, computePriority } from './scanner.ts';
import { getProviderCatalog } from './providers/registry.ts';
import { checkPwnedPasswordRange } from './providers/threatWebOsint.ts';
import {
  checkAndConsumeRateLimit,
  createRateLimitMiddleware,
  getClientIp,
  resetRateLimitBucket,
  resolveWebAuthnRP,
  securityHeadersMiddleware,
} from './security.ts';
import {
  createEncryptedBackup,
  decryptAndValidateBackup,
  restoreEncryptedBackupLive,
} from './backup.ts';
import { executeScanForUser, getSchedulerStatus } from './scheduler.ts';
import { buildAccountReportPdf, buildCaseDossierPdf } from './reportPdf.ts';

dotenv.config();

const SESSION_SIGNING_SECRET = loadOrCreateSessionSecret();

function resolvePublicBaseUrl(req: Request): string {
  const envUrl = process.env.PUBLIC_BASE_URL?.trim() || process.env.APP_URL?.trim();
  if (envUrl && /^https?:\/\//i.test(envUrl)) {
    return envUrl.replace(/\/+$/, '');
  }
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '127.0.0.1:3000')
    .split(',')[0]
    .trim();
  return `${proto}://${host}`;
}

function getGoogleOAuthConfig() {
  const clientId = process.env.GOOGLE_CLIENT_ID?.trim() || '';
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim() || '';
  return {
    configured: Boolean(clientId && clientSecret),
    clientId,
    clientSecret,
  };
}

export interface AuthedRequest extends Request {
  userId?: number;
  userEmail?: string;
}

function parseDataUrlImage(dataUrl: string): { buffer: Buffer; mime: string } {
  const match = /^data:(image\/(?:jpeg|jpg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl.trim());
  if (!match) {
    throw new Error('Image must be a valid base64 JPEG, PNG, or WebP data URL.');
  }
  const mime = match[1] === 'image/jpg' ? 'image/jpeg' : match[1];
  const buffer = Buffer.from(match[2], 'base64');
  if (buffer.length < 32 || buffer.length > 10 * 1024 * 1024) {
    throw new Error('Image size must be between 32 bytes and 10 MB.');
  }
  return { buffer, mime };
}

function safeParseJsonArray<T>(raw: string | null | undefined): T[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }
  const tokenHash = sha256Hex(token);
  const now = utcNow();
  const row = db
    .prepare(
      `SELECT s.id AS session_id, s.user_id, s.expires_at, u.email
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ?`
    )
    .get(tokenHash) as
    | { session_id: number; user_id: number; expires_at: string; email: string }
    | undefined;

  if (!row || row.expires_at < now) {
    if (row) {
      db.prepare('DELETE FROM sessions WHERE id = ?').run(row.session_id);
    }
    res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
    return;
  }

  const nextExpiry = new Date(Date.now() + 30 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  db.prepare('UPDATE sessions SET last_active_at = ?, expires_at = ? WHERE id = ?').run(
    now,
    nextExpiry,
    row.session_id
  );
  req.userId = row.user_id;
  req.userEmail = row.email;
  next();
}

function createSessionForUser(userId: number): string {
  const { raw, hash } = generateToken(32);
  const now = utcNow();
  const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  db.prepare(
    'INSERT INTO sessions (user_id, token_hash, expires_at, last_active_at, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, hash, expires, now, now);
  return raw;
}

export function getEnrollmentState(userId: number) {
  const user = db
    .prepare(
      'SELECT id, name, email, email_verified_at, fallback_pin_hash, google_sub, created_at FROM users WHERE id = ?'
    )
    .get(userId) as
    | {
        id: number;
        name: string;
        email: string;
        email_verified_at: string | null;
        fallback_pin_hash: string | null;
        google_sub: string;
        created_at: string;
      }
    | undefined;
  if (!user) return null;

  const enrollment = db
    .prepare(
      'SELECT status, consent_at, reviewed_at, reviewer_note, ai_biometric_consent, ai_biometric_consent_at FROM identity_enrollments WHERE user_id = ?'
    )
    .get(userId) as
    | {
        status: string;
        consent_at: string;
        reviewed_at: string | null;
        reviewer_note: string;
        ai_biometric_consent: number;
        ai_biometric_consent_at: string | null;
      }
    | undefined;

  const latestLiveness = db
    .prepare(
      'SELECT id, status, verification_method, created_at, completed_at FROM liveness_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1'
    )
    .get(userId) as
    | {
        id: number;
        status: string;
        verification_method: string;
        created_at: string;
        completed_at: string | null;
      }
    | undefined;

  const passkeyCount = (
    db.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?').get(userId) as { n: number }
  ).n;
  const recoveryCodesRemaining = (
    db
      .prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
      .get(userId) as { n: number }
  ).n;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.created_at,
    emailVerified: Boolean(user.email_verified_at),
    emailVerifiedAt: user.email_verified_at,
    selfieStatus: enrollment?.status ?? 'missing',
    selfieConsentAt: enrollment?.consent_at ?? null,
    selfieReviewedAt: enrollment?.reviewed_at ?? null,
    selfieReviewerNote: enrollment?.reviewer_note ?? '',
    aiBiometricConsent: Boolean(enrollment?.ai_biometric_consent),
    aiBiometricConsentAt: enrollment?.ai_biometric_consent_at ?? null,
    latestLiveness: latestLiveness ?? null,
    hasFallbackPin: Boolean(user.fallback_pin_hash),
    passkeyCount,
    recoveryCodesRemaining,
    googleLinked: Boolean(user.google_sub),
    liveScanReady: Boolean(user.email_verified_at && enrollment?.status === 'approved'),
  };
}

function getExposureScore(userId: number): number | null {
  const questionIds = QUESTIONS.map((q) => q.id);
  const placeholders = questionIds.map(() => '?').join(', ');
  const rows = db
    .prepare(`SELECT question_id, value FROM answers WHERE user_id = ? AND question_id IN (${placeholders})`)
    .all(userId, ...questionIds) as Array<{ question_id: number; value: number }>;
  if (rows.length !== QUESTIONS.length) return null;
  let weighted = 0;
  let maxWeight = 0;
  for (const q of QUESTIONS) {
    maxWeight += q.weight * 2;
    const ans = rows.find((r) => r.question_id === q.id);
    if (ans) weighted += q.weight * ans.value;
  }
  return maxWeight > 0 ? Math.round((weighted / maxWeight) * 100) : 0;
}

function getPriorityWeights(userId: number) {
  const row = db
    .prepare(
      'SELECT confidence_weight, severity_weight, recency_weight FROM priority_weights WHERE user_id = ?'
    )
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

function issueReviewerToken(): string {
  const expMs = Date.now() + 30 * 60 * 1000;
  const payload = `${expMs}.${crypto.randomBytes(16).toString('hex')}`;
  const sig = crypto
    .createHmac('sha256', SESSION_SIGNING_SECRET)
    .update(payload)
    .digest('base64url');
  const token = `${payload}.${sig}`;
  const now = utcNow();
  const expiresIso = new Date(expMs).toISOString().replace(/\.\d{3}Z$/, 'Z');

  db.prepare('DELETE FROM reviewer_sessions WHERE expires_at < ?').run(now);
  db.prepare(
    'INSERT INTO reviewer_sessions (token_hash, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?)'
  ).run(sha256Hex(token), expiresIso, now, now);

  return token;
}

function verifyReviewerToken(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [expStr, nonce, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_SIGNING_SECRET)
    .update(`${expStr}.${nonce}`)
    .digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  const now = utcNow();
  const row = db
    .prepare('SELECT token_hash, expires_at FROM reviewer_sessions WHERE token_hash = ?')
    .get(sha256Hex(token)) as { token_hash: string; expires_at: string } | undefined;
  if (!row || row.expires_at < now) {
    if (row) db.prepare('DELETE FROM reviewer_sessions WHERE token_hash = ?').run(row.token_hash);
    return false;
  }
  db.prepare('UPDATE reviewer_sessions SET last_used_at = ? WHERE token_hash = ?').run(
    now,
    row.token_hash
  );
  return true;
}

function requireReviewer(req: Request, res: Response, next: NextFunction) {
  const token = String(req.headers['x-reviewer-token'] || '');
  if (!token || !verifyReviewerToken(token)) {
    res.status(403).json({ error: 'Reviewer authentication required.' });
    return;
  }
  next();
}

function isReviewerConfigured(): {
  configured: boolean;
  viaEnv: boolean;
  bootstrapRequired: boolean;
} {
  if (process.env.REVIEWER_PASSCODE?.trim()) {
    return { configured: true, viaEnv: true, bootstrapRequired: false };
  }
  const row = db.prepare('SELECT id FROM reviewer_config WHERE id = 1').get();
  const configured = Boolean(row);
  return {
    configured,
    viaEnv: false,
    bootstrapRequired: Boolean(!configured && process.env.REVIEWER_BOOTSTRAP_TOKEN?.trim()),
  };
}

function enrichScanSummary(scanRow: {
  id: number;
  created_at: string;
  mode: string;
  status: string;
  findings_count: number;
  provider_summary: string;
  authorized_at: string;
}) {
  const parsedSummary = safeParseJsonArray<{
    providerId?: string;
    providerName?: string;
    status?: string;
    message?: string;
    categoryFocus?: string;
    findingsCount?: number;
    cached?: boolean;
    latencyMs?: number;
    requiresKey?: boolean;
    keyEnvVar?: string;
  }>(scanRow.provider_summary);

  const unavailableCount = parsedSummary.filter(
    (p) => p.status === 'unavailable' || p.status === 'error' || p.status === 'rate_limited'
  ).length;
  const skippedProviders = parsedSummary
    .filter((p) => p.status === 'skipped')
    .map((p) => ({
      providerId: p.providerId || '',
      providerName: p.providerName || 'Unknown Provider',
      reason: p.message || 'Skipped for missing required identifier',
    }));

  return {
    ...scanRow,
    providerSummary: parsedSummary,
    incompleteCoverage: unavailableCount > 0,
    unavailableCount,
    skippedCount: skippedProviders.length,
    hasSkippedProviders: skippedProviders.length > 0,
    skippedProviders,
    totalProviders: parsedSummary.length,
  };
}

export async function createApp(options?: {
  isProd?: boolean;
  httpServer?: http.Server;
  skipVite?: boolean;
}) {
  const isProd = options?.isProd ?? process.env.NODE_ENV === 'production';
  const app = express();
  app.set('trust proxy', 1);
  app.use(securityHeadersMiddleware(isProd));
  app.use(express.json({ limit: '15mb' }));

  const registerIpLimiter = createRateLimitMiddleware({
    prefix: 'auth_register_ip',
    maxAttempts: 10,
    windowMs: 15 * 60 * 1000,
    lockDurationMs: 15 * 60 * 1000,
    message: 'Too many registration attempts from this network. Please wait before trying again.',
  });

  const loginIpLimiter = createRateLimitMiddleware({
    prefix: 'auth_login_ip',
    maxAttempts: 30,
    windowMs: 15 * 60 * 1000,
    lockDurationMs: 15 * 60 * 1000,
    message: 'Too many login requests. Please retry after cooldown.',
  });

  const passkeyLimiter = createRateLimitMiddleware({
    prefix: 'auth_passkey',
    maxAttempts: 25,
    windowMs: 15 * 60 * 1000,
    lockDurationMs: 10 * 60 * 1000,
    message: 'Too many passkey requests. Please try again later.',
  });

  const emailResendLimiter = createRateLimitMiddleware({
    prefix: 'email_resend',
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000,
    lockDurationMs: 15 * 60 * 1000,
    keyFn: (req) => String((req as AuthedRequest).userId || getClientIp(req)),
    message: 'Too many verification email requests. Please wait before issuing another token.',
  });

  const emailConfirmLimiter = createRateLimitMiddleware({
    prefix: 'email_confirm',
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000,
    lockDurationMs: 15 * 60 * 1000,
    keyFn: (req) => String((req as AuthedRequest).userId || getClientIp(req)),
    message: 'Too many email verification attempts. Please wait and issue a new token.',
  });

  const reviewerClaimLimiter = createRateLimitMiddleware({
    prefix: 'reviewer_claim',
    maxAttempts: 10,
    windowMs: 15 * 60 * 1000,
    lockDurationMs: 15 * 60 * 1000,
    message: 'Too many reviewer claim attempts. Please retry later.',
  });

  const sensitiveAccountLimiter = createRateLimitMiddleware({
    prefix: 'account_sensitive',
    maxAttempts: 6,
    windowMs: 15 * 60 * 1000,
    lockDurationMs: 15 * 60 * 1000,
    keyFn: (req) => `${(req as AuthedRequest).userId || 'anon'}:${getClientIp(req)}`,
    message: 'Too many sensitive account verification failures. Try again later.',
  });

  // Health
  app.get('/api/health', (_req, res) => {
    const catalog = getProviderCatalog();
    const sched = getSchedulerStatus();
    res.json({
      ok: true,
      freeProvidersAvailable: catalog.filter((p) => !p.isPaidTier && p.configured).length,
      totalProviders: catalog.length,
      urlhausConfigured: Boolean(process.env.URLHAUS_AUTH_KEY?.trim()),
      githubTokenConfigured: Boolean(process.env.GITHUB_TOKEN?.trim()),
      nvdKeyConfigured: Boolean(process.env.NVD_API_KEY?.trim()),
      braveConfigured: Boolean(process.env.BRAVE_API_KEY?.trim()),
      hibpConfigured: Boolean(process.env.HIBP_API_KEY?.trim()),
      schedulerActive: sched.active,
    });
  });

  app.get('/api/providers/status', requireAuth, (_req: AuthedRequest, res) => {
    res.json({ providers: getProviderCatalog() });
  });

  app.get('/api/scheduler/status', requireAuth, (req: AuthedRequest, res) => {
    res.json(getSchedulerStatus(req.userId!));
  });

  app.post('/api/security/check-password', requireAuth, async (req: AuthedRequest, res) => {
    const password = String(req.body?.password || '');
    const label = String(req.body?.label || 'Account password check').trim().slice(0, 80);
    const recordFinding = req.body?.recordFinding === true;

    if (!password || password.length > 256) {
      res
        .status(400)
        .json({ error: 'Enter a password (1–256 characters) to check via k-anonymity range.' });
      return;
    }

    try {
      const result = await checkPwnedPasswordRange(password);
      let recordedFindingId: number | null = null;

      if (recordFinding && result.compromised) {
        const now = utcNow();
        const scanRes = db
          .prepare(
            `INSERT INTO scans (user_id, created_at, mode, status, findings_count, provider_summary, authorized_at)
             VALUES (?, ?, 'password_check', ?, 0, ?, ?)`
          )
          .run(
            req.userId!,
            now,
            'Completed (HIBP Pwned Passwords k-anonymity check)',
            JSON.stringify([
              {
                providerId: 'hibp_pwned_passwords',
                providerName: result.sourceName,
                status: 'ok',
                findingsCount: 1,
              },
            ]),
            now
          );
        const scanId = Number(scanRes.lastInsertRowid);
        const sig = sha256Hex(`HIBP_PW|${result.sha1Prefix}|${label}`);
        const weights = getPriorityWeights(req.userId!);
        const priority = computePriority(0.99, 1.0, 0.95, weights);

        const ins = db
          .prepare(
            `INSERT OR IGNORE INTO findings
             (user_id, scan_id, signature, title, category, source_name, source, found_at, risk, evidence, explanation, confidence, severity, recency_score, priority, verification_status, user_verified)
             VALUES (?, ?, ?, ?, 'Breached Credentials', ?, ?, ?, 'High', ?, ?, 0.99, 1.0, 0.95, ?, 'Verified Match', 1)`
          )
          .run(
            req.userId!,
            scanId,
            sig,
            `Compromised password detected in "${label}" (${result.pwnedCount.toLocaleString()} breach appearances)`,
            result.sourceName,
            result.sourceUrl,
            result.checkedAt,
            `SHA-1 k-anonymity range prefix ${result.sha1Prefix} matched a hash suffix seen ${result.pwnedCount.toLocaleString()} time(s) in Have I Been Pwned Pwned Passwords. Plaintext password was never transmitted or stored.`,
            'This password appears in known public data breaches. Replace it immediately with a unique password generated by a password manager and enable MFA.',
            priority
          );
        db.prepare('UPDATE scans SET findings_count = ? WHERE id = ?').run(Number(ins.changes), scanId);
        if (ins.changes > 0) recordedFindingId = Number(ins.lastInsertRowid);
      }

      res.json({ ...result, recordedFindingId });
    } catch (err) {
      res.status(503).json({
        error: err instanceof Error ? err.message : 'Unable to reach Pwned Passwords API.',
      });
    }
  });

  // --- Auth & Registration ---
  app.post('/api/auth/register', registerIpLimiter, async (req, res) => {
    try {
      const name = String(req.body?.fullName || '').trim().slice(0, 120);
      const email = String(req.body?.email || '').trim().toLowerCase().slice(0, 254);
      const password = String(req.body?.password || '');
      const biometricConsent = req.body?.biometricConsent === true;
      const aiBiometricConsent = req.body?.aiBiometricConsent === true;
      const selfieDataUrl = String(req.body?.selfieDataUrl || '');

      if (!name) {
        res.status(400).json({ error: 'Full name is required.' });
        return;
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        res.status(400).json({ error: 'Enter a valid email address.' });
        return;
      }
      if (password.length < 12) {
        res.status(400).json({ error: 'Password must be at least 12 characters.' });
        return;
      }
      if (!biometricConsent || !selfieDataUrl) {
        res.status(400).json({ error: 'Biometric consent and an enrollment selfie are required.' });
        return;
      }

      const { buffer: selfieBuf, mime } = parseDataUrlImage(selfieDataUrl);
      const encSelfie = encryptBuffer(selfieBuf);
      const selfieHash = sha256Hex(selfieBuf);
      const now = utcNow();

      const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if (existing) {
        res.status(409).json({ error: 'This email address is already registered.' });
        return;
      }

      const insertUser = db
        .prepare('INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(name, email, hashSecret(password), now);
      const userId = Number(insertUser.lastInsertRowid);

      db.prepare(
        `INSERT INTO identity_enrollments
         (user_id, encrypted_selfie, iv, auth_tag, mime, selfie_sha256, consent_at, status, ai_biometric_consent, ai_biometric_consent_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_review', ?, ?)`
      ).run(
        userId,
        encSelfie.encrypted,
        encSelfie.iv,
        encSelfie.authTag,
        mime,
        selfieHash,
        now,
        aiBiometricConsent ? 1 : 0,
        aiBiometricConsent ? now : null
      );

      db.prepare(
        `INSERT INTO monitors (user_id, full_name, username, terms, frequency, enabled, updated_at)
         VALUES (?, ?, '', '', 'weekly', 1, ?)`
      ).run(userId, name, now);

      db.prepare(
        `INSERT INTO priority_weights (user_id, confidence_weight, severity_weight, recency_weight, updated_at)
         VALUES (?, 0.45, 0.35, 0.20, ?)`
      ).run(userId, now);

      const recoveryCodes = generateRecoveryCodes(8);
      const insertCode = db.prepare(
        'INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)'
      );
      for (const c of recoveryCodes) {
        insertCode.run(userId, c.hash, now);
      }

      let emailSent = false;

      if (isEmailConfigured()) {
        const otp = generateEmailOTP();
        const otpHash = hashEmailOTP(userId, otp, SESSION_SIGNING_SECRET);

        db.prepare(
          'INSERT INTO email_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)'
        ).run(userId, otpHash, getOTPExpiry(), now);

        try {
          await sendVerificationEmail(email, otp);
          emailSent = true;
        } catch {
          db.prepare('DELETE FROM email_tokens WHERE user_id = ? AND token_hash = ?')
            .run(userId, otpHash);
        }
      }

      db.prepare('INSERT INTO notifications (user_id, body, created_at) VALUES (?, ?, ?)').run(
        userId,
        'Account created. Complete email verification and identity review to unlock live search scanning.',
        now
      );

      const sessionToken = createSessionForUser(userId);
      const userState = getEnrollmentState(userId);

      res.status(201).json({
        token: sessionToken,
        user: userState,
        recoveryCodes: recoveryCodes.map((c) => c.plain),
        emailSent,
        emailConfigured: isEmailConfigured(),
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Registration failed.' });
    }
  });

  app.post('/api/auth/login', loginIpLimiter, (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const method = String(req.body?.method || 'password');
    const secret = String(req.body?.secret || req.body?.password || '');
    const clientIp = getClientIp(req);
    const lockoutBucket = `auth_login_fail:${email || 'empty'}:${clientIp}`;

    // Pre-check account lockout without incrementing
    const lockCheck = checkAndConsumeRateLimit({
      bucket: lockoutBucket,
      maxAttempts: 5,
      windowMs: 15 * 60 * 1000,
      lockDurationMs: 15 * 60 * 1000,
      increment: false,
    });
    if (!lockCheck.allowed) {
      res.setHeader('Retry-After', String(lockCheck.retryAfterSeconds));
      res.status(429).json({
        error: `Too many failed sign-in attempts. Account login locked for ${lockCheck.retryAfterSeconds} second(s).`,
        retryAfterSeconds: lockCheck.retryAfterSeconds,
      });
      return;
    }

    const user = db
      .prepare('SELECT id, password_hash, fallback_pin_hash FROM users WHERE email = ?')
      .get(email) as { id: number; password_hash: string; fallback_pin_hash: string | null } | undefined;

    if (!user) {
      const consumed = checkAndConsumeRateLimit({
        bucket: lockoutBucket,
        maxAttempts: 5,
        windowMs: 15 * 60 * 1000,
        lockDurationMs: 15 * 60 * 1000,
        increment: true,
      });
      if (!consumed.allowed) {
        res.setHeader('Retry-After', String(consumed.retryAfterSeconds));
        res.status(429).json({
          error: `Too many failed sign-in attempts. Retry in ${consumed.retryAfterSeconds} second(s).`,
          retryAfterSeconds: consumed.retryAfterSeconds,
        });
        return;
      }
      res.status(401).json({ error: 'Invalid credentials.' });
      return;
    }

    let valid = false;
    if (method === 'password') {
      valid = verifySecret(secret, user.password_hash);
    } else if (method === 'pin') {
      if (!user.fallback_pin_hash) {
        res.status(400).json({ error: 'No fallback PIN configured for this account.' });
        return;
      }
      valid = verifySecret(secret, user.fallback_pin_hash);
    } else if (method === 'recovery') {
      const codeHash = sha256Hex(secret.trim().toUpperCase());
      const codeRow = db
        .prepare('SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
        .get(user.id, codeHash) as { id: number } | undefined;
      if (codeRow) {
        db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ?').run(utcNow(), codeRow.id);
        valid = true;
      }
    }

    if (!valid) {
      const consumed = checkAndConsumeRateLimit({
        bucket: lockoutBucket,
        maxAttempts: 5,
        windowMs: 15 * 60 * 1000,
        lockDurationMs: 15 * 60 * 1000,
        increment: true,
      });
      if (!consumed.allowed) {
        res.setHeader('Retry-After', String(consumed.retryAfterSeconds));
        res.status(429).json({
          error: `Too many failed sign-in attempts. Locked for ${consumed.retryAfterSeconds} second(s).`,
          retryAfterSeconds: consumed.retryAfterSeconds,
        });
        return;
      }
      res.status(401).json({ error: 'Invalid credentials.' });
      return;
    }

    resetRateLimitBucket(lockoutBucket);
    const token = createSessionForUser(user.id);
    res.json({ token, user: getEnrollmentState(user.id) });
  });

  // --- Standards-Compliant WebAuthn Passkeys (@simplewebauthn/server) ---
  app.post('/api/auth/passkey/register/options', requireAuth, passkeyLimiter, async (req: AuthedRequest, res) => {
    try {
      const user = db
        .prepare('SELECT id, name, email FROM users WHERE id = ?')
        .get(req.userId!) as { id: number; name: string; email: string } | undefined;
      if (!user) {
        res.status(401).json({ error: 'Account not found.' });
        return;
      }

      const { rpID } = resolveWebAuthnRP(req);
      const existingKeys = db
        .prepare('SELECT credential_id, transports FROM passkeys WHERE user_id = ?')
        .all(req.userId!) as Array<{ credential_id: string; transports: string }>;

      const options = await generateRegistrationOptions({
        rpName: 'Privacy Monitor',
        rpID,
        userName: user.email,
        userDisplayName: user.name,
        attestationType: 'none',
        excludeCredentials: existingKeys.map((k) => ({
          id: k.credential_id,
          transports: safeParseJsonArray<AuthenticatorTransport>(k.transports),
        })),
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
        timeout: 60000,
      });

      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
      db.prepare(
        `INSERT INTO webauthn_challenges
         (id, user_id, purpose, rp_id, expected_origin, webauthn_user_id, expires_at, created_at)
         VALUES (?, ?, 'register', ?, '', ?, ?, ?)`
      ).run(options.challenge, user.id, rpID, options.user.id, expiresAt, utcNow());

      res.json({ options });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Unable to generate passkey registration options.',
      });
    }
  });

  app.post('/api/auth/passkey/register/verify', requireAuth, passkeyLimiter, async (req: AuthedRequest, res) => {
    const label = String(req.body?.label || 'Device Passkey').trim().slice(0, 60) || 'Device Passkey';
    const responsePayload = req.body?.response as RegistrationResponseJSON | undefined;
    const explicitChallenge = String(req.body?.challenge || '');

    if (!responsePayload?.id || !responsePayload?.response?.clientDataJSON) {
      res.status(400).json({ error: 'Valid WebAuthn registration response payload is required.' });
      return;
    }

    let extractedChallenge = explicitChallenge;
    try {
      const clientData = JSON.parse(
        Buffer.from(responsePayload.response.clientDataJSON, 'base64url').toString('utf8')
      ) as { challenge?: string };
      if (clientData.challenge) {
        if (explicitChallenge && explicitChallenge !== clientData.challenge) {
          res.status(400).json({ error: 'WebAuthn challenge mismatch.' });
          return;
        }
        extractedChallenge = clientData.challenge;
      }
    } catch {
      res.status(400).json({ error: 'Malformed clientDataJSON in WebAuthn registration.' });
      return;
    }

    const ch = db
      .prepare(
        "SELECT id, rp_id, webauthn_user_id, expires_at FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'register'"
      )
      .get(extractedChallenge, req.userId!) as
      | { id: string; rp_id: string; webauthn_user_id: string; expires_at: string }
      | undefined;

    if (!ch) {
      res.status(400).json({ error: 'WebAuthn registration challenge not found or already consumed.' });
      return;
    }
    db.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(ch.id);

    if (ch.expires_at < utcNow()) {
      res.status(400).json({ error: 'WebAuthn registration challenge expired.' });
      return;
    }

    const { rpID, expectedOrigins } = resolveWebAuthnRP(req);
    if (ch.rp_id && ch.rp_id !== rpID) {
      res.status(400).json({ error: 'Relying Party ID changed during registration ceremony.' });
      return;
    }

    try {
      const verification = await verifyRegistrationResponse({
        response: responsePayload,
        expectedChallenge: ch.id,
        expectedOrigin: expectedOrigins,
        expectedRPID: ch.rp_id || rpID,
        requireUserPresence: true,
        requireUserVerification: false,
      });

      if (!verification.verified || !verification.registrationInfo) {
        res.status(400).json({ error: 'Passkey registration failed cryptographic verification.' });
        return;
      }

      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
      const pubKeyB64 = Buffer.from(credential.publicKey).toString('base64');
      const transportsJson = JSON.stringify(
        credential.transports ?? responsePayload.response.transports ?? []
      );

      db.prepare(
        `INSERT INTO passkeys
         (user_id, credential_id, label, public_key_b64, counter, transports, device_type, backed_up, rp_id, webauthn_user_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        req.userId!,
        credential.id,
        label,
        pubKeyB64,
        credential.counter,
        transportsJson,
        credentialDeviceType,
        credentialBackedUp ? 1 : 0,
        ch.rp_id || rpID,
        ch.webauthn_user_id || '',
        utcNow()
      );

      res.json({ ok: true, user: getEnrollmentState(req.userId!) });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey registration verification failed.';
      if (message.includes('UNIQUE constraint')) {
        res.status(409).json({ error: 'This passkey credential is already registered.' });
        return;
      }
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/auth/passkey/authenticate/options', passkeyLimiter, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const { rpID } = resolveWebAuthnRP(req);

    let userId: number | null = null;
    let allowCredentials: Array<{ id: string; transports?: AuthenticatorTransport[] }> | undefined;

    if (email) {
      const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as
        | { id: number }
        | undefined;
      if (!user) {
        res.status(400).json({ error: 'No passkey registered for this email address.' });
        return;
      }
      const keys = db
        .prepare('SELECT credential_id, transports, rp_id FROM passkeys WHERE user_id = ?')
        .all(user.id) as Array<{ credential_id: string; transports: string; rp_id: string }>;
      if (keys.length === 0) {
        res.status(400).json({ error: 'No passkey registered for this email address.' });
        return;
      }
      userId = user.id;
      allowCredentials = keys.map((k) => ({
        id: k.credential_id,
        transports: safeParseJsonArray<AuthenticatorTransport>(k.transports),
      }));
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60000,
    });

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    db.prepare(
      `INSERT INTO webauthn_challenges
       (id, user_id, purpose, rp_id, expected_origin, webauthn_user_id, expires_at, created_at)
       VALUES (?, ?, 'authenticate', ?, '', '', ?, ?)`
    ).run(options.challenge, userId, rpID, expiresAt, utcNow());

    res.json({ options });
  });

  app.post('/api/auth/passkey/authenticate/verify', passkeyLimiter, async (req, res) => {
    const responsePayload = req.body?.response as AuthenticationResponseJSON | undefined;
    const explicitChallenge = String(req.body?.challenge || '');

    if (!responsePayload?.id || !responsePayload?.response?.clientDataJSON) {
      res.status(400).json({ error: 'Valid WebAuthn authentication response payload is required.' });
      return;
    }

    let extractedChallenge = explicitChallenge;
    try {
      const clientData = JSON.parse(
        Buffer.from(responsePayload.response.clientDataJSON, 'base64url').toString('utf8')
      ) as { challenge?: string };
      if (clientData.challenge) {
        if (explicitChallenge && explicitChallenge !== clientData.challenge) {
          res.status(401).json({ error: 'WebAuthn challenge mismatch.' });
          return;
        }
        extractedChallenge = clientData.challenge;
      }
    } catch {
      res.status(401).json({ error: 'Malformed clientDataJSON in WebAuthn assertion.' });
      return;
    }

    const ch = db
      .prepare(
        "SELECT id, user_id, rp_id, expires_at FROM webauthn_challenges WHERE id = ? AND purpose = 'authenticate'"
      )
      .get(extractedChallenge) as
      | { id: string; user_id: number | null; rp_id: string; expires_at: string }
      | undefined;

    if (!ch) {
      res.status(400).json({ error: 'Passkey challenge not found or already consumed.' });
      return;
    }
    db.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(ch.id);

    if (ch.expires_at < utcNow()) {
      res.status(400).json({ error: 'Passkey challenge expired.' });
      return;
    }

    const pk = db
      .prepare(
        'SELECT id, user_id, credential_id, public_key_b64, counter, transports, rp_id FROM passkeys WHERE credential_id = ?'
      )
      .get(responsePayload.id) as
      | {
          id: number;
          user_id: number;
          credential_id: string;
          public_key_b64: string;
          counter: number;
          transports: string;
          rp_id: string;
        }
      | undefined;

    if (!pk) {
      res.status(401).json({ error: 'Passkey not recognized.' });
      return;
    }

    if (ch.user_id !== null && pk.user_id !== ch.user_id) {
      res.status(401).json({ error: 'Passkey does not belong to the requested account.' });
      return;
    }

    const { rpID, expectedOrigins } = resolveWebAuthnRP(req);
    const expectedRPID = ch.rp_id || rpID;
    if (pk.rp_id && pk.rp_id !== expectedRPID) {
      res.status(401).json({ error: 'Passkey RP ID does not match active Relying Party.' });
      return;
    }

    try {
      const verification = await verifyAuthenticationResponse({
        response: responsePayload,
        expectedChallenge: ch.id,
        expectedOrigin: expectedOrigins,
        expectedRPID,
        credential: {
          id: pk.credential_id,
          publicKey: new Uint8Array(Buffer.from(pk.public_key_b64, 'base64')),
          counter: pk.counter,
          transports: safeParseJsonArray<AuthenticatorTransport>(pk.transports),
        },
        requireUserVerification: false,
      });

      if (!verification.verified) {
        res.status(401).json({ error: 'Passkey cryptographic assertion failed verification.' });
        return;
      }

      const newCounter = verification.authenticationInfo.newCounter;
      if (pk.counter > 0 && newCounter <= pk.counter) {
        res
          .status(401)
          .json({ error: 'Authenticator signature counter rollback detected; possible cloned passkey.' });
        return;
      }

      db.prepare(
        'UPDATE passkeys SET counter = ?, device_type = ?, backed_up = ?, last_used_at = ? WHERE id = ?'
      ).run(
        newCounter,
        verification.authenticationInfo.credentialDeviceType,
        verification.authenticationInfo.credentialBackedUp ? 1 : 0,
        utcNow(),
        pk.id
      );

      const token = createSessionForUser(pk.user_id);
      res.json({ token, user: getEnrollmentState(pk.user_id) });
    } catch (err) {
      res.status(401).json({
        error: err instanceof Error ? err.message : 'Passkey assertion could not be verified.',
      });
    }
  });

  app.get('/api/auth/passkeys', requireAuth, (req: AuthedRequest, res) => {
    const rows = db
      .prepare('SELECT id, label, device_type, backed_up, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY id DESC')
      .all(req.userId!);
    res.json({ passkeys: rows });
  });

  app.delete('/api/auth/passkeys/:id', requireAuth, (req: AuthedRequest, res) => {
    db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(
      Number(req.params.id),
      req.userId!
    );
    res.json({ ok: true, user: getEnrollmentState(req.userId!) });
  });

  app.post('/api/auth/logout', requireAuth, (req: AuthedRequest, res) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.slice(7).trim();
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256Hex(token));
    res.json({ ok: true });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
    const state = getEnrollmentState(req.userId!);
    if (!state) {
      res.status(401).json({ error: 'Account not found.' });
      return;
    }
    res.json({ user: state });
  });

  // --- Optional Google OpenID Connect Authentication (never mandatory; requires GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET) ---
  app.get('/api/auth/google/status', (_req, res) => {
    const cfg = getGoogleOAuthConfig();
    res.json({
      configured: cfg.configured,
      reason: cfg.configured
        ? 'Google OpenID Connect configured.'
        : 'GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not set in environment.',
    });
  });

  app.get('/api/auth/google/url', (req: AuthedRequest, res) => {
    const cfg = getGoogleOAuthConfig();
    if (!cfg.configured) {
      res.status(503).json({
        error: 'Google OAuth is not configured on this server (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET unset).',
      });
      return;
    }

    const mode = req.query.mode === 'link' ? 'link' : 'login';
    let linkUserId: number | null = null;
    if (mode === 'link') {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
      if (!token) {
        res.status(401).json({ error: 'Authentication required to link Google account.' });
        return;
      }
      const sess = db
        .prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?')
        .get(sha256Hex(token)) as { user_id: number; expires_at: string } | undefined;
      if (!sess || sess.expires_at < utcNow()) {
        res.status(401).json({ error: 'Session invalid or expired.' });
        return;
      }
      linkUserId = sess.user_id;
    }

    const baseUrl = resolvePublicBaseUrl(req);
    const redirectUri = `${baseUrl}/api/auth/google/callback`;
    const state = crypto.randomBytes(24).toString('base64url');
    const nonce = crypto.randomBytes(24).toString('base64url');
    const now = utcNow();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

    db.prepare('DELETE FROM oauth_states WHERE expires_at < ?').run(now);
    db.prepare(
      `INSERT INTO oauth_states (state, nonce, mode, user_id, redirect_origin, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(state, nonce, mode, linkUserId, baseUrl, expiresAt, now);

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', cfg.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid email profile');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);
    authUrl.searchParams.set('prompt', 'select_account');

    res.json({ url: authUrl.toString(), redirectUri });
  });

  app.get('/api/auth/google/callback', async (req, res) => {
    const renderCallbackHtml = (payload: Record<string, unknown>, targetOrigin: string, status = 200) => {
      const safeOriginJson = JSON.stringify(targetOrigin);
      const safePayloadJson = JSON.stringify(payload);
      const msgText = String(payload.error || payload.message || 'Authentication completed.');
      const escapedMsg = msgText
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      res.status(status).setHeader('Content-Type', 'text/html; charset=utf-8').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Google Sign-In</title></head>
<body style="font-family:system-ui,sans-serif;padding:24px;color:#0f172a;background:#f8fafc;">
<p>${escapedMsg}</p>
<script>
try {
  if (window.opener) {
    window.opener.postMessage(${safePayloadJson}, ${safeOriginJson});
    window.close();
  }
} catch (e) {}
</script>
</body></html>`);
    };

    const fallbackOrigin = resolvePublicBaseUrl(req);
    const cfg = getGoogleOAuthConfig();
    if (!cfg.configured) {
      renderCallbackHtml(
        { type: 'pm_google_auth', ok: false, error: 'Google OAuth is not configured on this server.' },
        fallbackOrigin,
        503
      );
      return;
    }

    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    const oauthErr = String(req.query.error || '');

    if (oauthErr) {
      renderCallbackHtml(
        { type: 'pm_google_auth', ok: false, error: `Google authorization cancelled or denied (${oauthErr}).` },
        fallbackOrigin,
        400
      );
      return;
    }

    if (!code || !state) {
      renderCallbackHtml(
        { type: 'pm_google_auth', ok: false, error: 'Missing authorization code or CSRF state parameter.' },
        fallbackOrigin,
        400
      );
      return;
    }

    const stateRow = db
      .prepare('SELECT state, nonce, mode, user_id, redirect_origin, expires_at FROM oauth_states WHERE state = ?')
      .get(state) as
      | {
          state: string;
          nonce: string;
          mode: string;
          user_id: number | null;
          redirect_origin: string;
          expires_at: string;
        }
      | undefined;

    if (!stateRow) {
      renderCallbackHtml(
        { type: 'pm_google_auth', ok: false, error: 'Invalid or already consumed OAuth CSRF state.' },
        fallbackOrigin,
        400
      );
      return;
    }
    db.prepare('DELETE FROM oauth_states WHERE state = ?').run(stateRow.state);

    if (stateRow.expires_at < utcNow()) {
      renderCallbackHtml(
        { type: 'pm_google_auth', ok: false, error: 'OAuth sign-in state expired. Please retry.' },
        stateRow.redirect_origin,
        400
      );
      return;
    }

    try {
      const redirectUri = `${stateRow.redirect_origin}/api/auth/google/callback`;
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: cfg.clientId,
          client_secret: cfg.clientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code',
        }),
        signal: AbortSignal.timeout(12_000),
      });
      if (!tokenRes.ok) {
        throw new Error(`Google token exchange failed (HTTP ${tokenRes.status}).`);
      }
      const tokenJson = (await tokenRes.json()) as { id_token?: string };
      if (!tokenJson.id_token) {
        throw new Error('Google response omitted OpenID Connect id_token.');
      }

      const infoRes = await fetch(
        `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(tokenJson.id_token)}`,
        { signal: AbortSignal.timeout(10_000) }
      );
      if (!infoRes.ok) {
        throw new Error('Google ID token failed verification.');
      }
      const claims = (await infoRes.json()) as {
        aud?: string;
        iss?: string;
        sub?: string;
        email?: string;
        email_verified?: string | boolean;
        nonce?: string;
      };

      const validIss =
        claims.iss === 'https://accounts.google.com' || claims.iss === 'accounts.google.com';
      const emailVerified = claims.email_verified === true || claims.email_verified === 'true';
      if (
        claims.aud !== cfg.clientId ||
        !validIss ||
        !claims.sub ||
        !claims.email ||
        !emailVerified ||
        (claims.nonce && claims.nonce !== stateRow.nonce)
      ) {
        throw new Error('Google ID token claims failed audience, issuer, nonce, or verified-email checks.');
      }

      const googleSub = claims.sub;
      const email = claims.email.trim().toLowerCase();
      const now = utcNow();

      if (stateRow.mode === 'link' && stateRow.user_id) {
        const existingOther = db
          .prepare('SELECT id FROM users WHERE google_sub = ? AND id != ?')
          .get(googleSub, stateRow.user_id);
        if (existingOther) {
          throw new Error('This Google account is already linked to another user.');
        }
        db.prepare('UPDATE users SET google_sub = ? WHERE id = ?').run(googleSub, stateRow.user_id);
        renderCallbackHtml(
          {
            type: 'pm_google_auth',
            ok: true,
            mode: 'link',
            message: 'Google account linked cleanly. You may close this window.',
            user: getEnrollmentState(stateRow.user_id),
          },
          stateRow.redirect_origin
        );
        return;
      }

      const matched =
        (db.prepare('SELECT id, email_verified_at, google_sub FROM users WHERE google_sub = ?').get(googleSub) as
          | { id: number; email_verified_at: string | null; google_sub: string }
          | undefined) ??
        (db.prepare('SELECT id, email_verified_at, google_sub FROM users WHERE email = ?').get(email) as
          | { id: number; email_verified_at: string | null; google_sub: string }
          | undefined);

      if (!matched) {
        throw new Error(
          'No Privacy Monitor account matches this Google email yet. Register first with biometric selfie consent, then sign in or link Google.'
        );
      }

      if (!matched.google_sub) {
        db.prepare('UPDATE users SET google_sub = ? WHERE id = ?').run(googleSub, matched.id);
      }
      if (!matched.email_verified_at) {
        db.prepare('UPDATE users SET email_verified_at = ? WHERE id = ?').run(now, matched.id);
      }

      const sessionToken = createSessionForUser(matched.id);
      renderCallbackHtml(
        {
          type: 'pm_google_auth',
          ok: true,
          mode: 'login',
          token: sessionToken,
          user: getEnrollmentState(matched.id),
          message: 'Signed in via Google OpenID Connect.',
        },
        stateRow.redirect_origin
      );
    } catch (err) {
      renderCallbackHtml(
        {
          type: 'pm_google_auth',
          ok: false,
          error: err instanceof Error ? err.message : 'Google authentication failed.',
        },
        stateRow.redirect_origin,
        400
      );
    }
  });

  app.delete('/api/auth/google/link', requireAuth, (req: AuthedRequest, res) => {
    db.prepare("UPDATE users SET google_sub = '' WHERE id = ?").run(req.userId!);
    res.json({ ok: true, user: getEnrollmentState(req.userId!) });
  });

  app.post('/api/auth/pin', requireAuth, sensitiveAccountLimiter, (req: AuthedRequest, res) => {
    const pin = String(req.body?.pin || '').trim();
    if (!/^\d{4,8}$/.test(pin)) {
      res.status(400).json({ error: 'Fallback PIN must be 4 to 8 digits.' });
      return;
    }
    db.prepare('UPDATE users SET fallback_pin_hash = ? WHERE id = ?').run(
      hashSecret(pin),
      req.userId!
    );
    res.json({ ok: true, user: getEnrollmentState(req.userId!) });
  });

  app.post(
    '/api/auth/recovery-codes/regenerate',
    requireAuth,
    sensitiveAccountLimiter,
    (req: AuthedRequest, res) => {
      const now = utcNow();
      db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(req.userId!);
      const codes = generateRecoveryCodes(8);
      const stmt = db.prepare(
        'INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)'
      );
      for (const c of codes) stmt.run(req.userId!, c.hash, now);
      res.json({ recoveryCodes: codes.map((c) => c.plain), user: getEnrollmentState(req.userId!) });
    }
  );

  app.post('/api/auth/verify-email/resend', requireAuth, emailResendLimiter, async (req: AuthedRequest, res) => {
    const user = getEnrollmentState(req.userId!);
    if (!user) {
      res.status(401).json({ error: 'Account not found.' });
      return;
    }
    if (user.emailVerified) {
      res.json({ alreadyVerified: true, user });
      return;
    }

    const latestTok = db
      .prepare('SELECT created_at FROM email_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1')
      .get(req.userId!) as { created_at: string } | undefined;
    if (latestTok) {
      const elapsedSec = (Date.now() - Date.parse(latestTok.created_at)) / 1000;
      if (Number.isFinite(elapsedSec) && elapsedSec < 60) {
        const waitSec = Math.max(1, Math.ceil(60 - elapsedSec));
        res.setHeader('Retry-After', String(waitSec));
        res.status(429).json({
          error: `Please wait ${waitSec} second(s) before requesting a new verification token.`,
          retryAfterSeconds: waitSec,
        });
        return;
      }
    }

    if (!isEmailConfigured()) {
      res.status(503).json({ error: 'Email delivery is not configured.' });
      return;
    }

    const now = utcNow();
    const userId = req.userId!;
    const otp = generateEmailOTP();
    const otpHash = hashEmailOTP(userId, otp, SESSION_SIGNING_SECRET);

    db.prepare('DELETE FROM email_tokens WHERE user_id = ?').run(userId);

    db.prepare(
      'INSERT INTO email_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)'
    ).run(userId, otpHash, getOTPExpiry(), now);

    try {
      await sendVerificationEmail(req.userEmail!, otp);
      res.json({ sent: true });
    } catch {
      db.prepare('DELETE FROM email_tokens WHERE user_id = ? AND token_hash = ?')
        .run(userId, otpHash);

      res.status(503).json({
        error: 'Unable to send verification email. Please try again later.'
      });
    }
  });

  app.post('/api/auth/verify-email/confirm', requireAuth, emailConfirmLimiter, (req: AuthedRequest, res) => {
    const token = String(req.body?.token || '').trim();
    if (!/^\d{6}$/.test(token)) {
      res.status(400).json({ error: 'Enter a valid six-digit verification code.' });
      return;
    }
    const now = utcNow();
    const row = db
      .prepare(
        'SELECT id, user_id, expires_at, used_at FROM email_tokens WHERE token_hash = ? AND user_id = ?'
      )
      .get(hashEmailOTP(req.userId!, token, SESSION_SIGNING_SECRET), req.userId!) as
      | { id: number; user_id: number; expires_at: string; used_at: string | null }
      | undefined;

    if (!row || row.used_at || row.expires_at < now) {
      res.status(400).json({ error: 'Verification token is invalid, expired, or already used.' });
      return;
    }

    db.prepare('UPDATE users SET email_verified_at = ? WHERE id = ?').run(now, req.userId!);
    db.prepare('UPDATE email_tokens SET used_at = ? WHERE id = ?').run(now, row.id);
    db.prepare('INSERT INTO notifications (user_id, body, created_at) VALUES (?, ?, ?)').run(
      req.userId!,
      'Email ownership verified via single-use verification token.',
      now
    );
    res.json({ ok: true, user: getEnrollmentState(req.userId!) });
  });

  // --- Explicit Opt-In Consent for Google Gemini Biometric Visual Screening ---
  app.put('/api/identity/ai-consent', requireAuth, (req: AuthedRequest, res) => {
    const consent = req.body?.consent === true;
    const now = utcNow();
    const existing = db
      .prepare('SELECT user_id FROM identity_enrollments WHERE user_id = ?')
      .get(req.userId!);
    if (!existing) {
      res.status(404).json({ error: 'Identity enrollment record not found.' });
      return;
    }
    db.prepare(
      'UPDATE identity_enrollments SET ai_biometric_consent = ?, ai_biometric_consent_at = ? WHERE user_id = ?'
    ).run(consent ? 1 : 0, consent ? now : null, req.userId!);

    db.prepare('INSERT INTO notifications (user_id, body, created_at) VALUES (?, ?, ?)').run(
      req.userId!,
      consent
        ? 'Enabled optional Google Gemini third-party biometric visual screening for selfie comparison.'
        : 'Disabled third-party Google Gemini biometric visual screening; all images remain local AES-256-GCM encrypted only.',
      now
    );

    res.json({ ok: true, user: getEnrollmentState(req.userId!) });
  });

  // --- Identity Selfie, Liveness Sequence & Monitoring Photos ---
  app.get('/api/identity/selfie', requireAuth, (req: AuthedRequest, res) => {
    const row = db
      .prepare('SELECT encrypted_selfie, iv, auth_tag, mime FROM identity_enrollments WHERE user_id = ?')
      .get(req.userId!) as
      | { encrypted_selfie: Uint8Array; iv: Uint8Array; auth_tag: Uint8Array; mime: string }
      | undefined;
    if (!row) {
      res.status(404).json({ error: 'Enrollment selfie not found.' });
      return;
    }
    const plain = decryptBuffer(row.encrypted_selfie, row.iv, row.auth_tag);
    res.setHeader('Content-Type', row.mime || 'image/jpeg');
    res.send(plain);
  });

  app.post('/api/liveness/challenge/start', requireAuth, (req: AuthedRequest, res) => {
    const enrollment = db
      .prepare('SELECT user_id FROM identity_enrollments WHERE user_id = ?')
      .get(req.userId!);
    if (!enrollment) {
      res.status(400).json({ error: 'Enrollment selfie required first.' });
      return;
    }
    const oneHourAgo = new Date(Date.now() - 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    const recentCount = (
      db
        .prepare('SELECT COUNT(*) AS n FROM local_camera_challenges WHERE user_id = ? AND issued_at >= ?')
        .get(req.userId!, oneHourAgo) as { n: number }
    ).n;
    if (recentCount >= 12) {
      res.status(429).json({ error: 'Too many challenge attempts this hour.' });
      return;
    }

    const challengeId = `local_seq_${crypto.randomBytes(16).toString('base64url')}`;
    const now = utcNow();
    const expires = new Date(Date.now() + 90 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    db.prepare(
      `INSERT INTO local_camera_challenges (id, user_id, issued_at, expires_at, status)
       VALUES (?, ?, ?, ?, 'issued')`
    ).run(challengeId, req.userId!, now, expires);

    res.json({
      challengeId,
      expiresInSeconds: 90,
      instructions:
        'Look directly at the camera for the first frame. Turn your head gently for the second frame, then return to center for the third frame.',
      notice:
        'This prototype sequence check verifies frame timing and visual screening for trusted review; it does not establish certified biometric liveness alone.',
    });
  });

  app.post('/api/liveness/challenge/finish', requireAuth, async (req: AuthedRequest, res) => {
    const challengeId = String(req.body?.challengeId || '');
    const frames = Array.isArray(req.body?.frames) ? req.body.frames : [];

    if (!challengeId.startsWith('local_seq_') || frames.length !== 3) {
      res.status(400).json({ error: 'Valid challengeId and 3 captured camera frames are required.' });
      return;
    }

    const row = db
      .prepare('SELECT status, issued_at, expires_at FROM local_camera_challenges WHERE id = ? AND user_id = ?')
      .get(challengeId, req.userId!) as
      | { status: string; issued_at: string; expires_at: string }
      | undefined;

    if (!row || row.status !== 'issued') {
      res.status(400).json({ error: 'Unknown or already consumed camera challenge.' });
      return;
    }

    const now = utcNow();
    const updated = db
      .prepare(
        `UPDATE local_camera_challenges SET status = 'consumed', completed_at = ?
         WHERE id = ? AND user_id = ? AND status = 'issued'`
      )
      .run(now, challengeId, req.userId!);
    if (updated.changes !== 1) {
      res.status(400).json({ error: 'Challenge already consumed.' });
      return;
    }

    const issuedMs = Date.parse(row.issued_at);
    const expiresMs = Date.parse(row.expires_at);
    if (Date.now() > expiresMs || Date.now() - issuedMs < 2000) {
      res
        .status(400)
        .json({ error: 'Challenge expired or completed too quickly (< 2 seconds). Please retry.' });
      return;
    }

    let parsedFrames: Array<{ buffer: Buffer; mime: string }>;
    try {
      parsedFrames = frames.map((f: unknown) => parseDataUrlImage(String(f || '')));
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid frame data.' });
      return;
    }

    for (let i = 0; i < parsedFrames.length; i++) {
      const assessment = await inspectFace(parsedFrames[i].buffer);

      if (assessment.status !== 'passed') {
        res.status(422).json({
          error: `Camera frame ${i + 1}: ${assessment.reason}`
        });
        return;
      }
    }

    const movementAssessment = await assessMovement(
      parsedFrames.map(f => f.buffer)
    );

    if (movementAssessment.status !== 'passed') {
      res.status(422).json({
        error: movementAssessment.reason
      });
      return;
    }

    const hashes = parsedFrames.map((f) => sha256Hex(f.buffer));
    const uniqueCount = new Set(hashes).size;

    const enrolled = db
      .prepare(
        'SELECT encrypted_selfie, iv, auth_tag, mime, ai_biometric_consent FROM identity_enrollments WHERE user_id = ?'
      )
      .get(req.userId!) as
      | {
          encrypted_selfie: Uint8Array;
          iv: Uint8Array;
          auth_tag: Uint8Array;
          mime: string;
          ai_biometric_consent: number;
        }
      | undefined;

    if (!enrolled) {
      res.status(400).json({ error: 'Enrollment selfie missing.' });
      return;
    }

    const status: 'review_required' | 'failed' =
      uniqueCount === 3 ? 'review_required' : 'failed';

    const confidence: number | null = null;

    const message = uniqueCount === 3
      ? 'Local image quality and head movement checks passed. Identity verification remains incomplete.'
      : 'Insufficient variation across camera frames. Please retry.';

    db.prepare(
      `INSERT INTO liveness_sessions
       (user_id, session_key, status, confidence, verification_method, created_at, completed_at)
       VALUES (?, ?, ?, ?, 'local_sequence', ?, ?)`
    ).run(req.userId!, challengeId, status, confidence, row.issued_at, utcNow());

    res.json({ status, confidence, message, user: getEnrollmentState(req.userId!) });
  });

  app.get('/api/verification-status', requireAuth, (req: AuthedRequest, res) => {
    const assessments = db
      .prepare(
        `SELECT id, status, confidence, verification_method, created_at, completed_at
         FROM liveness_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 30`
      )
      .all(req.userId!);
    const events = db
      .prepare(
        `SELECT e.id, e.session_id, e.reviewer_id, e.decision, e.reason, e.reviewed_at
         FROM verification_review_events e
         JOIN liveness_sessions l ON l.id = e.session_id
         WHERE l.user_id = ? ORDER BY e.id DESC LIMIT 30`
      )
      .all(req.userId!);
    res.json({ state: getEnrollmentState(req.userId!), assessments, reviewEvents: events });
  });

  // --- Monitoring Photos (Encrypted + Optional Opt-In 1:1 Face Comparison) ---
  app.get('/api/photos', requireAuth, (req: AuthedRequest, res) => {
    const photos = db
      .prepare(
        `SELECT id, label, status, reviewer_note, reviewed_at, match_result, match_reason, match_confidence, matched_at, created_at
         FROM monitoring_photos WHERE user_id = ? ORDER BY id DESC`
      )
      .all(req.userId!);
    res.json({ photos });
  });

  app.post('/api/photos', requireAuth, async (req: AuthedRequest, res) => {
    try {
      const count = (
        db.prepare('SELECT COUNT(*) AS n FROM monitoring_photos WHERE user_id = ?').get(req.userId!) as {
          n: number;
        }
      ).n;
      if (count >= 20) {
        res.status(429).json({ error: 'Photo limit (20) reached. Delete an existing photo first.' });
        return;
      }

      const label = String(req.body?.label || 'Monitoring Photo').trim().slice(0, 120) || 'Monitoring Photo';
      const imageDataUrl = String(req.body?.imageDataUrl || '');
      const { buffer, mime } = parseDataUrlImage(imageDataUrl);
      const enc = encryptBuffer(buffer);
      const hash = sha256Hex(buffer);
      const now = utcNow();

      const enrolled = db
        .prepare(
          'SELECT encrypted_selfie, iv, auth_tag, mime, ai_biometric_consent FROM identity_enrollments WHERE user_id = ?'
        )
        .get(req.userId!) as
        | {
            encrypted_selfie: Uint8Array;
            iv: Uint8Array;
            auth_tag: Uint8Array;
            mime: string;
            ai_biometric_consent: number;
          }
        | undefined;

      let matchResult = 'not_checked';
      let matchReason =
        'Third-party Google Gemini biometric screening is disabled (opt-in required). Photo encrypted locally and queued for manual reviewer inspection.';
      let matchConfidence: number | null = null;

      if (enrolled && enrolled.ai_biometric_consent === 1) {
        matchResult = 'inconclusive';
        matchReason = 'AI visual screening unavailable; manual review required.';
        try {
          const refBuf = decryptBuffer(enrolled.encrypted_selfie, enrolled.iv, enrolled.auth_tag);
          const ai = await screenFaceSimilarityWithAI(
            refBuf.toString('base64'),
            enrolled.mime,
            buffer.toString('base64'),
            mime
          );
          if (ai.result === 'match' || ai.result === 'no_match' || ai.result === 'inconclusive') {
            matchResult = ai.result;
          }
          const baseReason = String(ai.reason || 'Visual screening completed.');
          const anomalyNote = ai.visualAnomalyNote ? ` Visual anomaly note: ${String(ai.visualAnomalyNote)}` : '';
          matchReason = `${baseReason}${anomalyNote}`.slice(0, 400);
          matchConfidence = typeof ai.confidence === 'number' ? ai.confidence : null;
        } catch {
          matchResult = 'inconclusive';
          matchReason = 'Automated visual screening unavailable; queued for manual ownership review.';
        }
      }

      const info = db
        .prepare(
          `INSERT INTO monitoring_photos
           (user_id, encrypted_image, iv, auth_tag, mime, sha256, label, status, match_result, match_reason, match_confidence, matched_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_review', ?, ?, ?, ?, ?)`
        )
        .run(
          req.userId!,
          enc.encrypted,
          enc.iv,
          enc.authTag,
          mime,
          hash,
          label,
          matchResult,
          matchReason,
          matchConfidence,
          now,
          now
        );

      res.status(201).json({
        id: Number(info.lastInsertRowid),
        matchResult,
        matchReason,
        matchConfidence,
        aiScreeningUsed: Boolean(enrolled?.ai_biometric_consent === 1),
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Photo upload failed.' });
    }
  });

  app.get('/api/photos/:id/image', requireAuth, (req: AuthedRequest, res) => {
    const row = db
      .prepare('SELECT encrypted_image, iv, auth_tag, mime FROM monitoring_photos WHERE id = ? AND user_id = ?')
      .get(Number(req.params.id), req.userId!) as
      | { encrypted_image: Uint8Array; iv: Uint8Array; auth_tag: Uint8Array; mime: string }
      | undefined;
    if (!row) {
      res.status(404).json({ error: 'Photo not found.' });
      return;
    }
    const plain = decryptBuffer(row.encrypted_image, row.iv, row.auth_tag);
    res.setHeader('Content-Type', row.mime || 'image/jpeg');
    res.send(plain);
  });

  app.delete('/api/photos/:id', requireAuth, (req: AuthedRequest, res) => {
    db.prepare('DELETE FROM monitoring_photos WHERE id = ? AND user_id = ?').run(
      Number(req.params.id),
      req.userId!
    );
    res.json({ ok: true });
  });

  // --- Reviewer Audit Console (Hardened First-Run Claim, Brute-Force Lockout, Revocable Sessions, Backups) ---
  app.get('/api/reviewer/status', (_req, res) => {
    res.json(isReviewerConfigured());
  });

  app.post('/api/reviewer/claim', reviewerClaimLimiter, (req, res) => {
    const status = isReviewerConfigured();
    if (status.configured) {
      res.status(409).json({ error: 'Reviewer passcode is already configured.' });
      return;
    }

    const bootstrapEnv = process.env.REVIEWER_BOOTSTRAP_TOKEN?.trim();
    if (bootstrapEnv) {
      const providedBootstrap = String(
        req.body?.bootstrapToken || req.headers['x-reviewer-bootstrap-token'] || ''
      ).trim();
      const a = Buffer.from(providedBootstrap);
      const b = Buffer.from(bootstrapEnv);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        res.status(403).json({ error: 'Valid server bootstrap token is required to claim reviewer access.' });
        return;
      }
    }

    const passcode = String(req.body?.passcode || '').trim();
    if (passcode.length < 12) {
      res.status(400).json({ error: 'Reviewer passcode must be at least 12 characters.' });
      return;
    }

    const ins = db
      .prepare('INSERT OR IGNORE INTO reviewer_config (id, passcode_hash, claimed_at) VALUES (1, ?, ?)')
      .run(hashSecret(passcode), utcNow());
    if (Number(ins.changes) !== 1) {
      res.status(409).json({ error: 'Reviewer passcode was already claimed.' });
      return;
    }

    res.json({ reviewerToken: issueReviewerToken(), configured: true });
  });

  app.post('/api/reviewer/unlock', (req, res) => {
    const clientIp = getClientIp(req);
    const lockBucket = `reviewer_unlock:${clientIp}`;
    const check = checkAndConsumeRateLimit({
      bucket: lockBucket,
      maxAttempts: 5,
      windowMs: 15 * 60 * 1000,
      lockDurationMs: 15 * 60 * 1000,
      increment: false,
    });
    if (!check.allowed) {
      res.setHeader('Retry-After', String(check.retryAfterSeconds));
      res.status(429).json({
        error: `Too many failed reviewer unlock attempts. Try again in ${check.retryAfterSeconds} second(s).`,
        retryAfterSeconds: check.retryAfterSeconds,
      });
      return;
    }

    const passcode = String(req.body?.passcode || '').trim();
    const envPass = process.env.REVIEWER_PASSCODE?.trim();
    let authorized = false;

    if (envPass) {
      const a = Buffer.from(passcode);
      const b = Buffer.from(envPass);
      authorized = a.length === b.length && crypto.timingSafeEqual(a, b);
    } else {
      const row = db.prepare('SELECT passcode_hash FROM reviewer_config WHERE id = 1').get() as
        | { passcode_hash: string }
        | undefined;
      authorized = Boolean(row && verifySecret(passcode, row.passcode_hash));
    }

    if (!authorized) {
      const consumed = checkAndConsumeRateLimit({
        bucket: lockBucket,
        maxAttempts: 5,
        windowMs: 15 * 60 * 1000,
        lockDurationMs: 15 * 60 * 1000,
        increment: true,
      });
      if (!consumed.allowed) {
        res.setHeader('Retry-After', String(consumed.retryAfterSeconds));
        res.status(429).json({
          error: `Too many failed reviewer unlock attempts. Locked for ${consumed.retryAfterSeconds} second(s).`,
          retryAfterSeconds: consumed.retryAfterSeconds,
        });
        return;
      }
      res.status(401).json({ error: 'Invalid reviewer passcode.' });
      return;
    }

    resetRateLimitBucket(lockBucket);
    res.json({ reviewerToken: issueReviewerToken() });
  });

  app.post('/api/reviewer/lock', (req, res) => {
    const token = String(req.headers['x-reviewer-token'] || '');
    if (token) {
      db.prepare('DELETE FROM reviewer_sessions WHERE token_hash = ?').run(sha256Hex(token));
    }
    res.json({ ok: true });
  });

  app.get('/api/reviewer/queue', requireReviewer, (_req, res) => {
    const enrollments = db
      .prepare(
        `SELECT e.user_id, u.name, u.email, u.email_verified_at, e.consent_at, e.status, e.reviewed_at, e.reviewer_note, e.ai_biometric_consent
         FROM identity_enrollments e
         JOIN users u ON u.id = e.user_id
         ORDER BY CASE WHEN e.status = 'pending_review' THEN 0 ELSE 1 END, e.consent_at DESC`
      )
      .all();
    const photos = db
      .prepare(
        `SELECT p.id, p.user_id, u.name AS user_name, p.label, p.status, p.match_result, p.match_reason, p.match_confidence, p.created_at
         FROM monitoring_photos p
         JOIN users u ON u.id = p.user_id
         ORDER BY CASE WHEN p.status = 'pending_review' THEN 0 ELSE 1 END, p.created_at DESC`
      )
      .all();
    const assessments = db
      .prepare(
        `SELECT l.id, l.user_id, u.name AS user_name, l.status, l.confidence, l.verification_method, l.created_at, l.completed_at
         FROM liveness_sessions l
         JOIN users u ON u.id = l.user_id
         ORDER BY l.id DESC LIMIT 30`
      )
      .all();
    res.json({ enrollments, photos, assessments });
  });

  app.get('/api/reviewer/photo/:kind/:id', requireReviewer, (req, res) => {
    const { kind, id } = req.params;
    if (kind === 'identity') {
      const row = db
        .prepare('SELECT encrypted_selfie, iv, auth_tag, mime FROM identity_enrollments WHERE user_id = ?')
        .get(Number(id)) as
        | { encrypted_selfie: Uint8Array; iv: Uint8Array; auth_tag: Uint8Array; mime: string }
        | undefined;
      if (!row) {
        res.status(404).end();
        return;
      }
      res.setHeader('Content-Type', row.mime || 'image/jpeg');
      res.send(decryptBuffer(row.encrypted_selfie, row.iv, row.auth_tag));
      return;
    }
    if (kind === 'photo') {
      const row = db
        .prepare('SELECT encrypted_image, iv, auth_tag, mime FROM monitoring_photos WHERE id = ?')
        .get(Number(id)) as
        | { encrypted_image: Uint8Array; iv: Uint8Array; auth_tag: Uint8Array; mime: string }
        | undefined;
      if (!row) {
        res.status(404).end();
        return;
      }
      res.setHeader('Content-Type', row.mime || 'image/jpeg');
      res.send(decryptBuffer(row.encrypted_image, row.iv, row.auth_tag));
      return;
    }
    res.status(400).end();
  });

  app.post('/api/reviewer/decide', requireReviewer, (req, res) => {
    const targetType = String(req.body?.targetType || '');
    const targetId = Number(req.body?.targetId);
    const decision = String(req.body?.decision || '');
    const reason = String(req.body?.reason || '').trim().slice(0, 400);
    const reviewerId = String(req.body?.reviewerId || 'Trusted Reviewer').trim().slice(0, 80);

    if (!reason) {
      res.status(400).json({ error: 'A review reason is required.' });
      return;
    }

    const now = utcNow();
    if (targetType === 'identity') {
      if (decision !== 'approved' && decision !== 'rejected') {
        res.status(400).json({ error: 'Invalid decision for identity enrollment.' });
        return;
      }
      db.prepare(
        'UPDATE identity_enrollments SET status = ?, reviewed_at = ?, reviewer_note = ? WHERE user_id = ?'
      ).run(decision, now, reason, targetId);
      db.prepare('INSERT INTO notifications (user_id, body, created_at) VALUES (?, ?, ?)').run(
        targetId,
        `Identity enrollment marked "${decision}" by ${reviewerId}: ${reason}`,
        now
      );
      res.json({ ok: true });
      return;
    }

    if (targetType === 'photo') {
      if (decision !== 'approved' && decision !== 'rejected') {
        res.status(400).json({ error: 'Invalid decision for monitoring photo.' });
        return;
      }
      db.prepare(
        'UPDATE monitoring_photos SET status = ?, reviewed_at = ?, reviewer_note = ? WHERE id = ?'
      ).run(decision, now, reason, targetId);
      res.json({ ok: true });
      return;
    }

    if (targetType === 'assessment') {
      if (!['needs_more_evidence', 'screening_accepted', 'screening_rejected'].includes(decision)) {
        res.status(400).json({ error: 'Invalid assessment review decision.' });
        return;
      }
      db.prepare(
        'INSERT INTO verification_review_events (session_id, reviewer_id, decision, reason, reviewed_at) VALUES (?, ?, ?, ?, ?)'
      ).run(targetId, reviewerId, decision, reason, now);
      res.json({ ok: true });
      return;
    }

    res.status(400).json({ error: 'Unknown review target type.' });
  });

  // --- Encrypted Database Backup & Restoration (Reviewer-Authenticated) ---
  app.post('/api/reviewer/backup/export', requireReviewer, (req, res) => {
    try {
      const passphrase = String(req.body?.passphrase || '');
      const backup = createEncryptedBackup(passphrase);
      const stamp = backup.createdAt.replace(/[:]/g, '-');
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="privacy-monitor-backup-${stamp}.pmbackup"`
      );
      res.setHeader('X-Backup-Sha256', backup.dbSha256);
      res.send(backup.archiveBuffer);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Backup export failed.' });
    }
  });

  app.post('/api/reviewer/backup/verify', requireReviewer, (req, res) => {
    try {
      const passphrase = String(req.body?.passphrase || '');
      const backupBase64 = String(req.body?.backupBase64 || '');
      if (!backupBase64) {
        res.status(400).json({ error: 'Backup file payload is required.' });
        return;
      }
      const buf = Buffer.from(backupBase64, 'base64');
      const verified = decryptAndValidateBackup(buf, passphrase);
      res.json({
        valid: true,
        createdAt: verified.createdAt,
        dbSha256: verified.dbSha256,
        tableCounts: verified.tableCounts,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Backup verification failed.' });
    }
  });

  app.post('/api/reviewer/backup/restore', requireReviewer, (req, res) => {
    try {
      const passphrase = String(req.body?.passphrase || '');
      const backupBase64 = String(req.body?.backupBase64 || '');
      if (!backupBase64) {
        res.status(400).json({ error: 'Backup file payload is required.' });
        return;
      }
      const buf = Buffer.from(backupBase64, 'base64');
      const restored = restoreEncryptedBackupLive(buf, passphrase);
      res.json({ ok: true, ...restored });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Backup restoration failed.' });
    }
  });

  // --- Dashboard & Priority Weights ---
  app.get('/api/dashboard', requireAuth, (req: AuthedRequest, res) => {
    const userId = req.userId!;
    const riskRows = db
      .prepare('SELECT risk, COUNT(*) AS n FROM findings WHERE user_id = ? GROUP BY risk')
      .all(userId) as Array<{ risk: string; n: number }>;
    const riskCounts = { High: 0, Medium: 0, Low: 0 };
    for (const r of riskRows) {
      if (r.risk in riskCounts) riskCounts[r.risk as keyof typeof riskCounts] = r.n;
    }

    const catRows = db
      .prepare('SELECT category, COUNT(*) AS n FROM findings WHERE user_id = ? GROUP BY category')
      .all(userId) as Array<{ category: string; n: number }>;
    const categoryCounts: Record<string, number> = {};
    for (const c of CATEGORIES) categoryCounts[c] = 0;
    for (const r of catRows) categoryCounts[r.category] = r.n;

    const lastScanRaw = db
      .prepare(
        'SELECT id, created_at, mode, status, findings_count, provider_summary, authorized_at FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 1'
      )
      .get(userId) as
      | {
          id: number;
          created_at: string;
          mode: string;
          status: string;
          findings_count: number;
          provider_summary: string;
          authorized_at: string;
        }
      | undefined;

    const lastScan = lastScanRaw ? enrichScanSummary(lastScanRaw) : null;

    const notifications = db
      .prepare('SELECT id, body, created_at, read_at FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 12')
      .all(userId);
    const openCasesCount = (
      db
        .prepare("SELECT COUNT(*) AS n FROM cases WHERE user_id = ? AND status != 'Resolved'")
        .get(userId) as { n: number }
    ).n;
    const resolvedCasesCount = (
      db
        .prepare("SELECT COUNT(*) AS n FROM cases WHERE user_id = ? AND status = 'Resolved'")
        .get(userId) as { n: number }
    ).n;
    const photosCount = (
      db.prepare('SELECT COUNT(*) AS n FROM monitoring_photos WHERE user_id = ?').get(userId) as {
        n: number;
      }
    ).n;

    const verRows = db
      .prepare('SELECT verification_status, COUNT(*) AS n FROM findings WHERE user_id = ? GROUP BY verification_status')
      .all(userId) as Array<{ verification_status: string; n: number }>;
    const reviewCounts = { unverified: 0, verifiedMatch: 0, safeLibrary: 0 };
    for (const vr of verRows) {
      if (vr.verification_status === 'Verified Match') reviewCounts.verifiedMatch = vr.n;
      else if (vr.verification_status === 'False Positive') reviewCounts.safeLibrary = vr.n;
      else reviewCounts.unverified += vr.n;
    }

    res.json({
      exposureScore: getExposureScore(userId),
      totalFindings: riskCounts.High + riskCounts.Medium + riskCounts.Low,
      riskCounts,
      reviewCounts,
      categoryCounts,
      lastScan,
      priorityWeights: getPriorityWeights(userId),
      notifications,
      openCasesCount,
      resolvedCasesCount,
      photosCount,
      user: getEnrollmentState(userId),
    });
  });

  app.put('/api/priority-weights', requireAuth, (req: AuthedRequest, res) => {
    const c = Number(req.body?.confidence_weight);
    const s = Number(req.body?.severity_weight);
    const r = Number(req.body?.recency_weight);
    if ([c, s, r].some((v) => !Number.isFinite(v) || v < 0 || v > 1)) {
      res.status(400).json({ error: 'Weights must be numbers between 0 and 1.' });
      return;
    }
    const sum = c + s + r;
    if (Math.abs(sum - 1) > 0.015) {
      res.status(400).json({ error: `Priority weights must sum to 1.00 (currently ${sum.toFixed(2)}).` });
      return;
    }
    const normC = Math.round((c / sum) * 100) / 100;
    const normS = Math.round((s / sum) * 100) / 100;
    const normR = Math.round((1 - normC - normS) * 100) / 100;

    const now = utcNow();
    db.prepare(
      `INSERT INTO priority_weights (user_id, confidence_weight, severity_weight, recency_weight, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         confidence_weight = excluded.confidence_weight,
         severity_weight = excluded.severity_weight,
         recency_weight = excluded.recency_weight,
         updated_at = excluded.updated_at`
    ).run(req.userId!, normC, normS, normR, now);

    const rows = db
      .prepare('SELECT id, confidence, severity, recency_score FROM findings WHERE user_id = ?')
      .all(req.userId!) as Array<{
      id: number;
      confidence: number;
      severity: number;
      recency_score: number;
    }>;
    const upd = db.prepare('UPDATE findings SET priority = ? WHERE id = ? AND user_id = ?');
    for (const f of rows) {
      const p = computePriority(f.confidence, f.severity, f.recency_score, {
        confidence_weight: normC,
        severity_weight: normS,
        recency_weight: normR,
      });
      upd.run(p, f.id, req.userId!);
    }

    res.json({
      weights: { confidence_weight: normC, severity_weight: normS, recency_weight: normR },
      recalculated: rows.length,
    });
  });

  // --- Monitoring Setup & Scans ---
  app.get('/api/monitoring', requireAuth, (req: AuthedRequest, res) => {
    const monitor = db
      .prepare(
        'SELECT full_name, username, terms, domains, frequency, enabled, authorization_confirmed, authorization_at, last_scheduled_scan_at, updated_at FROM monitors WHERE user_id = ?'
      )
      .get(req.userId!);
    const state = getEnrollmentState(req.userId!);
    res.json({
      monitor: monitor ?? {
        full_name: state?.name ?? '',
        username: '',
        terms: '',
        domains: '',
        frequency: 'weekly',
        enabled: 1,
        authorization_confirmed: 0,
        authorization_at: null,
        last_scheduled_scan_at: null,
      },
      email: state?.email ?? '',
      providers: getProviderCatalog(),
      liveScanReady: state?.liveScanReady ?? false,
      scheduler: getSchedulerStatus(req.userId!),
    });
  });

  app.put('/api/monitoring', requireAuth, (req: AuthedRequest, res) => {
    const fullName = String(req.body?.full_name || '').trim().slice(0, 120);
    const username = String(req.body?.username || '').trim().slice(0, 120);
    const terms = String(req.body?.terms || '').trim().slice(0, 500);
    const domains = String(req.body?.domains || '').trim().slice(0, 500);
    const frequency = ['daily', 'weekly', 'monthly'].includes(String(req.body?.frequency))
      ? String(req.body.frequency)
      : 'weekly';
    const enabled = req.body?.enabled ? 1 : 0;
    const authorizationConfirmed = req.body?.authorization_confirmed ? 1 : 0;
    const now = utcNow();

    if (!fullName) {
      res.status(400).json({ error: 'Full name is required for monitoring.' });
      return;
    }

    db.prepare(
      `INSERT INTO monitors (user_id, full_name, username, terms, domains, frequency, enabled, authorization_confirmed, authorization_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         full_name = excluded.full_name,
         username = excluded.username,
         terms = excluded.terms,
         domains = excluded.domains,
         frequency = excluded.frequency,
         enabled = excluded.enabled,
         authorization_confirmed = excluded.authorization_confirmed,
         authorization_at = CASE WHEN excluded.authorization_confirmed = 1 THEN COALESCE(monitors.authorization_at, excluded.authorization_at) ELSE NULL END,
         updated_at = excluded.updated_at`
    ).run(
      req.userId!,
      fullName,
      username,
      terms,
      domains,
      frequency,
      enabled,
      authorizationConfirmed,
      authorizationConfirmed ? now : null,
      now
    );

    res.json({ ok: true });
  });

  app.post('/api/scan', requireAuth, async (req: AuthedRequest, res) => {
    const userId = req.userId!;
    const monitor = db
      .prepare(
        'SELECT full_name, username, terms, domains, enabled, authorization_confirmed, authorization_at FROM monitors WHERE user_id = ?'
      )
      .get(userId) as
      | {
          full_name: string;
          username: string;
          terms: string;
          domains: string;
          enabled: number;
          authorization_confirmed: number;
          authorization_at: string | null;
        }
      | undefined;

    if (!monitor || !monitor.full_name.trim()) {
      res.status(400).json({ error: 'Save your monitoring profile before running a scan.' });
      return;
    }
    if (!monitor.enabled) {
      res.status(400).json({ error: 'Monitoring is currently paused. Enable it in Monitoring Setup.' });
      return;
    }

    const state = getEnrollmentState(userId);
    if (!state?.liveScanReady) {
      res.status(403).json({
        error:
          'Scanning personal identifiers requires both verified email and an approved enrollment selfie. Complete Identity Verification first.',
      });
      return;
    }

    const explicitlyAuthorized = req.body?.authorized === true || Boolean(monitor.authorization_confirmed);
    if (!explicitlyAuthorized) {
      res.status(403).json({
        error:
          'Explicit authorization required: confirm that you are searching your own personal identifiers and authorized domains before querying external OSINT APIs.',
      });
      return;
    }

    const now = utcNow();
    const authorizedAt = monitor.authorization_at || now;
    if (req.body?.authorized === true && !monitor.authorization_confirmed) {
      db.prepare('UPDATE monitors SET authorization_confirmed = 1, authorization_at = ? WHERE user_id = ?').run(
        authorizedAt,
        userId
      );
    }

    try {
      const result = await executeScanForUser(userId, 'live', authorizedAt);
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'OSINT scan failed.';
      db.prepare(
        `INSERT INTO scans (user_id, created_at, mode, status, findings_count, provider_summary, authorized_at)
         VALUES (?, ?, 'live', ?, 0, '[]', ?)`
      ).run(userId, now, `Scan failed: ${msg.slice(0, 180)}`, authorizedAt);
      res.status(503).json({ error: msg });
    }
  });

  app.get('/api/findings', requireAuth, (req: AuthedRequest, res) => {
    const findings = db
      .prepare('SELECT * FROM findings WHERE user_id = ? ORDER BY priority DESC, id DESC')
      .all(req.userId!) as Array<{ verification_status: string } & Record<string, unknown>>;
    const reviewHistory = db
      .prepare(
        `SELECT id, finding_id, previous_status, new_status, note, reviewed_at
         FROM finding_review_events WHERE user_id = ? ORDER BY id DESC LIMIT 200`
      )
      .all(req.userId!);
    const scans = db
      .prepare('SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 20')
      .all(req.userId!) as Array<{
      id: number;
      created_at: string;
      mode: string;
      status: string;
      findings_count: number;
      provider_summary: string;
      authorized_at: string;
    }>;
    const parsedScans = scans.map(enrichScanSummary);
    const counts = {
      unverified: findings.filter(
        (f) => f.verification_status !== 'Verified Match' && f.verification_status !== 'False Positive'
      ).length,
      verifiedMatch: findings.filter((f) => f.verification_status === 'Verified Match').length,
      safeLibrary: findings.filter((f) => f.verification_status === 'False Positive').length,
    };
    res.json({
      findings,
      reviewHistory,
      counts,
      scans: parsedScans,
      categories: CATEGORIES,
      guides: RESPONSE_GUIDES,
    });
  });

  app.get('/api/findings/:id/history', requireAuth, (req: AuthedRequest, res) => {
    const findingId = Number(req.params.id);
    const owned = db
      .prepare('SELECT id FROM findings WHERE id = ? AND user_id = ?')
      .get(findingId, req.userId!);
    if (!owned) {
      res.status(404).json({ error: 'Finding not found.' });
      return;
    }
    const events = db
      .prepare(
        'SELECT id, finding_id, previous_status, new_status, note, reviewed_at FROM finding_review_events WHERE finding_id = ? AND user_id = ? ORDER BY id DESC'
      )
      .all(findingId, req.userId!);
    res.json({ events });
  });

  app.post('/api/findings/bulk-verify', requireAuth, (req: AuthedRequest, res) => {
    const rawIds: unknown[] = Array.isArray(req.body?.findingIds) ? req.body.findingIds : [];
    const findingIds: number[] = Array.from(
      new Set<number>(rawIds.map((v) => Number(v)).filter((n) => Number.isInteger(n) && n > 0))
    ).slice(0, 100);
    const requestedStatus = String(req.body?.verification_status || '').trim();
    const note = String(req.body?.note || '').trim().slice(0, 500);

    if (
      findingIds.length === 0 ||
      (requestedStatus !== 'Unverified' &&
        requestedStatus !== 'Verified Match' &&
        requestedStatus !== 'False Positive')
    ) {
      res.status(400).json({ error: 'Select findings and a valid verification status.' });
      return;
    }

    const verificationStatus = requestedStatus as 'Unverified' | 'Verified Match' | 'False Positive';
    const verifiedBit = verificationStatus === 'Verified Match' ? 1 : 0;
    const now = utcNow();

    const getStmt = db.prepare(
      'SELECT id, verification_status FROM findings WHERE id = ? AND user_id = ?'
    );
    const updStmt = db.prepare(
      'UPDATE findings SET verification_status = ?, user_verified = ?, review_note = ?, reviewed_at = ? WHERE id = ? AND user_id = ?'
    );
    const evtStmt = db.prepare(
      `INSERT INTO finding_review_events (finding_id, user_id, previous_status, new_status, note, reviewed_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    );

    let updatedCount = 0;
    db.exec('BEGIN;');
    try {
      for (const fid of findingIds) {
        const existing = getStmt.get(fid, req.userId!) as
          | { id: number; verification_status: string }
          | undefined;
        if (!existing) continue;
        updStmt.run(verificationStatus, verifiedBit, note, now, fid, req.userId!);
        evtStmt.run(
          fid,
          req.userId!,
          existing.verification_status || 'Unverified',
          verificationStatus,
          note || `Bulk updated to ${verificationStatus}`,
          now
        );
        updatedCount++;
      }
      db.exec('COMMIT;');
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }

    res.json({ ok: true, updatedCount, verification_status: verificationStatus });
  });

  app.post('/api/findings/:id/verify', requireAuth, (req: AuthedRequest, res) => {
    const findingId = Number(req.params.id);
    const existing = db
      .prepare('SELECT id, verification_status, review_note FROM findings WHERE id = ? AND user_id = ?')
      .get(findingId, req.userId!) as
      | { id: number; verification_status: string; review_note: string }
      | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Finding not found.' });
      return;
    }

    const requestedStatus = String(req.body?.verification_status || '').trim();
    let verificationStatus: 'Unverified' | 'Verified Match' | 'False Positive';
    if (
      requestedStatus === 'Unverified' ||
      requestedStatus === 'Verified Match' ||
      requestedStatus === 'False Positive'
    ) {
      verificationStatus = requestedStatus;
    } else {
      verificationStatus = req.body?.verified ? 'Verified Match' : 'Unverified';
    }
    const hasExplicitNote = typeof req.body?.note === 'string';
    const nextNote = hasExplicitNote ? String(req.body.note).trim().slice(0, 500) : existing.review_note;
    const verifiedBit = verificationStatus === 'Verified Match' ? 1 : 0;
    const now = utcNow();

    db.exec('BEGIN;');
    try {
      db.prepare(
        'UPDATE findings SET verification_status = ?, user_verified = ?, review_note = ?, reviewed_at = ? WHERE id = ? AND user_id = ?'
      ).run(verificationStatus, verifiedBit, nextNote, now, findingId, req.userId!);
      db.prepare(
        `INSERT INTO finding_review_events (finding_id, user_id, previous_status, new_status, note, reviewed_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).run(
        findingId,
        req.userId!,
        existing.verification_status || 'Unverified',
        verificationStatus,
        nextNote,
        now
      );
      db.exec('COMMIT;');
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }

    res.json({
      ok: true,
      verification_status: verificationStatus,
      user_verified: verifiedBit,
      review_note: nextNote,
      reviewed_at: now,
    });
  });

  app.post('/api/findings/:id/ai-assess', requireAuth, async (req: AuthedRequest, res) => {
    const finding = db
      .prepare('SELECT * FROM findings WHERE id = ? AND user_id = ?')
      .get(Number(req.params.id), req.userId!) as
      | { id: number; title: string; category: string; source: string; risk: string; explanation: string }
      | undefined;
    if (!finding) {
      res.status(404).json({ error: 'Finding not found.' });
      return;
    }
    try {
      const assessment = await assessSingleFinding(finding);
      db.prepare('UPDATE findings SET ai_advice = ? WHERE id = ? AND user_id = ?').run(
        JSON.stringify(assessment),
        finding.id,
        req.userId!
      );
      res.json({ assessment });
    } catch (err) {
      const mapped = extractGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });

  app.post('/api/ai/overview', requireAuth, async (req: AuthedRequest, res) => {
    const userId = req.userId!;
    const findings = db
      .prepare(
        'SELECT title, category, source, risk, explanation FROM findings WHERE user_id = ? ORDER BY priority DESC LIMIT 20'
      )
      .all(userId) as Array<{
      title: string;
      category: string;
      source: string;
      risk: string;
      explanation: string;
    }>;
    const categoryCounts: Record<string, number> = {};
    for (const c of CATEGORIES) categoryCounts[c] = 0;
    for (const f of findings) categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;

    const score = getExposureScore(userId) ?? 0;
    try {
      const overview = await generateExposureOverview({
        exposureScore: score,
        findings,
        categoriesCount: categoryCounts,
      });
      res.json({ overview });
    } catch (err) {
      const mapped = extractGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });

  app.get('/api/report.csv', requireAuth, (req: AuthedRequest, res) => {
    const rows = db
      .prepare(
        'SELECT title, category, source_name, source, found_at, evidence, confidence, risk, priority, verification_status FROM findings WHERE user_id = ? ORDER BY priority DESC'
      )
      .all(req.userId!) as Array<{
      title: string;
      category: string;
      source_name: string;
      source: string;
      found_at: string;
      evidence: string;
      confidence: number;
      risk: string;
      priority: number;
      verification_status: string;
    }>;

    const escapeCsv = (val: unknown) => {
      let s = String(val ?? '');
      if (/^[=+\-@]/.test(s)) s = `'${s}`;
      return `"${s.replace(/"/g, '""')}"`;
    };

    const lines = [
      [
        'Finding',
        'Category',
        'Source Name',
        'Source URL',
        'Date Retrieved',
        'Evidence',
        'Confidence',
        'Risk Severity',
        'Priority',
        'Verification Status',
      ].join(','),
    ];
    for (const r of rows) {
      lines.push(
        [
          escapeCsv(r.title),
          escapeCsv(r.category),
          escapeCsv(r.source_name || 'External Source'),
          escapeCsv(r.source),
          escapeCsv(r.found_at),
          escapeCsv(r.evidence),
          escapeCsv(r.confidence),
          escapeCsv(r.risk),
          escapeCsv(r.priority),
          escapeCsv(r.verification_status || 'Unverified'),
        ].join(',')
      );
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="privacy_exposure_report.csv"');
    res.send('\uFEFF' + lines.join('\n'));
  });

  app.get('/api/report.pdf', requireAuth, (req: AuthedRequest, res) => {
    const userState = getEnrollmentState(req.userId!);
    if (!userState) {
      res.status(401).json({ error: 'Account not found.' });
      return;
    }
    const findings = db
      .prepare(
        `SELECT id, title, category, source_name, source, found_at, risk, evidence, confidence, priority, verification_status, review_note
         FROM findings WHERE user_id = ? ORDER BY priority DESC, id DESC`
      )
      .all(req.userId!) as Array<{
      id: number;
      title: string;
      category: string;
      source_name: string;
      source: string;
      found_at: string;
      risk: string;
      evidence: string;
      confidence: number;
      priority: number;
      verification_status: string;
      review_note: string;
    }>;

    const cases = db
      .prepare(
        `SELECT c.id, c.title, c.category, c.description, c.url, c.status, c.notes, c.resolution_summary, c.created_at, c.resolved_at,
                (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id) AS evidenceCount
         FROM cases c WHERE c.user_id = ? ORDER BY c.id DESC`
      )
      .all(req.userId!) as Array<{
      id: number;
      title: string;
      category: string;
      description: string;
      url: string;
      status: string;
      notes: string;
      resolution_summary: string;
      created_at: string;
      resolved_at: string | null;
      evidenceCount: number;
    }>;

    const pdfBuffer = buildAccountReportPdf({
      userName: userState.name,
      userEmail: userState.email,
      emailVerified: userState.emailVerified,
      selfieStatus: userState.selfieStatus,
      exposureScore: getExposureScore(req.userId!),
      generatedAt: utcNow(),
      findings,
      cases,
    });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="privacy_monitor_report.pdf"');
    res.send(pdfBuffer);
  });

  // --- Questionnaire ---
  app.get('/api/questionnaire', requireAuth, (req: AuthedRequest, res) => {
    const rows = db
      .prepare('SELECT question_id, value FROM answers WHERE user_id = ?')
      .all(req.userId!) as Array<{ question_id: number; value: number }>;
    const answers: Record<number, number> = {};
    for (const r of rows) answers[r.question_id] = r.value;
    res.json({ questions: QUESTIONS, answers, score: getExposureScore(req.userId!) });
  });

  app.post('/api/questionnaire', requireAuth, (req: AuthedRequest, res) => {
    const answers = req.body?.answers as Record<string, unknown> | undefined;
    if (!answers || typeof answers !== 'object') {
      res.status(400).json({ error: 'Provide answers for all questions.' });
      return;
    }
    const now = utcNow();
    const stmt = db.prepare(
      `INSERT INTO answers (user_id, question_id, value, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id, question_id) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
    );
    for (const q of QUESTIONS) {
      const val = Number(answers[String(q.id)]);
      if (val !== 0 && val !== 1 && val !== 2) {
        res.status(400).json({ error: `Complete question ${q.id}.` });
        return;
      }
      stmt.run(req.userId!, q.id, val, now);
    }
    const score = getExposureScore(req.userId!);
    res.json({ score });
  });

  // --- Guided Search & Response Guides ---
  app.get('/api/guided-search', requireAuth, (req: AuthedRequest, res) => {
    const monitor = db
      .prepare('SELECT full_name, username, terms FROM monitors WHERE user_id = ?')
      .get(req.userId!) as { full_name: string; username: string; terms: string } | undefined;
    const rawTerms = monitor
      ? [monitor.full_name, monitor.username, ...monitor.terms.split(',')]
      : [];
    const terms = Array.from(new Set(rawTerms.map((t) => t.trim()).filter((t) => t.length >= 2))).slice(0, 12);
    const links = terms.map((term) => ({
      term,
      googleUrl: `https://www.google.com/search?q=${encodeURIComponent(`"${term}"`)}`,
      duckDuckGoUrl: `https://duckduckgo.com/?q=${encodeURIComponent(`"${term}"`)}`,
    }));
    res.json({ links, guides: RESPONSE_GUIDES });
  });

  // --- Cases & Encrypted Evidence Vault ---
  app.get('/api/cases', requireAuth, (req: AuthedRequest, res) => {
    const cases = db
      .prepare('SELECT * FROM cases WHERE user_id = ? ORDER BY id DESC')
      .all(req.userId!);
    res.json({ cases, categories: CATEGORIES, guides: RESPONSE_GUIDES });
  });

  app.post('/api/cases', requireAuth, (req: AuthedRequest, res) => {
    const title = String(req.body?.title || '').trim().slice(0, 150);
    const category = String(req.body?.category || 'Contact Details');
    const description = String(req.body?.description || '').trim().slice(0, 5000);
    const url = String(req.body?.url || '').trim().slice(0, 1000);
    const occurredAt = req.body?.occurredAt ? String(req.body.occurredAt).slice(0, 32) : null;

    if (!title || !description || !(CATEGORIES as readonly string[]).includes(category)) {
      res.status(400).json({ error: 'Title, description, and valid category are required.' });
      return;
    }
    if (url && !/^https?:\/\//i.test(url)) {
      res.status(400).json({ error: 'Reference URL must start with http:// or https://.' });
      return;
    }

    const now = utcNow();
    const info = db
      .prepare(
        `INSERT INTO cases (user_id, title, category, description, url, occurred_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(req.userId!, title, category, description, url, occurredAt, now);
    const caseId = Number(info.lastInsertRowid);

    db.prepare(
      `INSERT INTO case_events (case_id, user_id, event_type, status, summary, created_at)
       VALUES (?, ?, 'created', 'Open', ?, ?)`
    ).run(caseId, req.userId!, `Opened misuse case "${title}" (${category}).`, now);

    const created = db.prepare('SELECT * FROM cases WHERE id = ?').get(caseId);
    res.status(201).json({ caseItem: created });
  });

  app.get('/api/cases/:id', requireAuth, (req: AuthedRequest, res) => {
    const caseItem = db
      .prepare('SELECT * FROM cases WHERE id = ? AND user_id = ?')
      .get(Number(req.params.id), req.userId!) as { category: keyof typeof RESPONSE_GUIDES } | undefined;
    if (!caseItem) {
      res.status(404).json({ error: 'Case not found.' });
      return;
    }
    const evidence = db
      .prepare('SELECT id, name, mime, created_at FROM evidence WHERE case_id = ? ORDER BY id DESC')
      .all(Number(req.params.id));
    const timeline = db
      .prepare(
        'SELECT id, case_id, event_type, status, summary, created_at FROM case_events WHERE case_id = ? AND user_id = ? ORDER BY id DESC'
      )
      .all(Number(req.params.id), req.userId!);
    res.json({
      caseItem,
      evidence,
      timeline,
      guide: RESPONSE_GUIDES[caseItem.category] ?? RESPONSE_GUIDES['Contact Details'],
    });
  });

  app.patch('/api/cases/:id', requireAuth, (req: AuthedRequest, res) => {
    const caseId = Number(req.params.id);
    const existing = db
      .prepare('SELECT id, status, notes, resolution_summary, resolved_at FROM cases WHERE id = ? AND user_id = ?')
      .get(caseId, req.userId!) as
      | {
          id: number;
          status: string;
          notes: string;
          resolution_summary: string;
          resolved_at: string | null;
        }
      | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Case not found.' });
      return;
    }

    const status = String(req.body?.status || existing.status || 'Open');
    const notes = String(req.body?.notes ?? existing.notes ?? '').slice(0, 5000);
    const resolutionSummary = String(
      req.body?.resolution_summary ?? existing.resolution_summary ?? ''
    )
      .trim()
      .slice(0, 2000);
    if (!['Open', 'Under Review', 'Resolved'].includes(status)) {
      res.status(400).json({ error: 'Invalid case status.' });
      return;
    }

    const now = utcNow();
    const resolvedAt =
      status === 'Resolved' ? existing.resolved_at || now : null;

    db.prepare(
      'UPDATE cases SET status = ?, notes = ?, resolution_summary = ?, resolved_at = ? WHERE id = ? AND user_id = ?'
    ).run(status, notes, resolutionSummary, resolvedAt, caseId, req.userId!);

    const eventType = status !== existing.status ? 'status_changed' : 'notes_updated';
    const summary =
      status !== existing.status
        ? `Status updated from ${existing.status} to ${status}${resolutionSummary ? ` — ${resolutionSummary.slice(0, 120)}` : ''}.`
        : 'Updated case investigation notes / resolution details.';
    db.prepare(
      `INSERT INTO case_events (case_id, user_id, event_type, status, summary, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(caseId, req.userId!, eventType, status, summary, now);

    res.json({ ok: true, resolved_at: resolvedAt });
  });

  app.get('/api/cases/:id/report.pdf', requireAuth, (req: AuthedRequest, res) => {
    const caseId = Number(req.params.id);
    const userState = getEnrollmentState(req.userId!);
    const c = db
      .prepare('SELECT * FROM cases WHERE id = ? AND user_id = ?')
      .get(caseId, req.userId!) as
      | {
          id: number;
          title: string;
          category: string;
          description: string;
          url: string;
          status: string;
          notes: string;
          resolution_summary: string;
          created_at: string;
          resolved_at: string | null;
        }
      | undefined;
    if (!c || !userState) {
      res.status(404).json({ error: 'Case not found.' });
      return;
    }
    const evidence = db
      .prepare('SELECT id, name, mime, created_at FROM evidence WHERE case_id = ? ORDER BY id DESC')
      .all(caseId) as Array<{ id: number; name: string; mime: string; created_at: string }>;
    const timeline = db
      .prepare(
        'SELECT event_type, status, summary, created_at FROM case_events WHERE case_id = ? AND user_id = ? ORDER BY id DESC'
      )
      .all(caseId, req.userId!) as Array<{
      event_type: string;
      status: string;
      summary: string;
      created_at: string;
    }>;

    const pdfBuffer = buildCaseDossierPdf({
      userName: userState.name,
      userEmail: userState.email,
      generatedAt: utcNow(),
      caseItem: { ...c, evidenceCount: evidence.length },
      evidence,
      timeline,
    });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="privacy_case_${c.id}_dossier.pdf"`
    );
    res.send(pdfBuffer);
  });

  app.post('/api/cases/:id/ai-draft', requireAuth, async (req: AuthedRequest, res) => {
    const caseItem = db
      .prepare('SELECT id, title, category, description, url FROM cases WHERE id = ? AND user_id = ?')
      .get(Number(req.params.id), req.userId!) as
      | { id: number; title: string; category: string; description: string; url: string }
      | undefined;
    if (!caseItem) {
      res.status(404).json({ error: 'Case not found.' });
      return;
    }
    try {
      const draft = await draftCaseResponse(caseItem);
      db.prepare('UPDATE cases SET ai_draft = ? WHERE id = ? AND user_id = ?').run(
        JSON.stringify(draft),
        caseItem.id,
        req.userId!
      );
      res.json({ draft });
    } catch (err) {
      const mapped = extractGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });

  app.post('/api/cases/:id/evidence', requireAuth, (req: AuthedRequest, res) => {
    const caseId = Number(req.params.id);
    const owned = db
      .prepare('SELECT id FROM cases WHERE id = ? AND user_id = ?')
      .get(caseId, req.userId!);
    if (!owned) {
      res.status(404).json({ error: 'Case not found.' });
      return;
    }

    const name = path.basename(String(req.body?.name || 'evidence')).slice(0, 150);
    const mime = String(req.body?.mime || '');
    const dataBase64 = String(req.body?.dataBase64 || '');
    const allowedMimes = new Set(['image/png', 'image/jpeg', 'application/pdf', 'text/plain']);
    if (!allowedMimes.has(mime)) {
      res.status(400).json({ error: 'Allowed evidence types: PNG, JPEG, PDF, TXT.' });
      return;
    }
    const raw = Buffer.from(dataBase64, 'base64');
    if (raw.length === 0 || raw.length > 5 * 1024 * 1024) {
      res.status(400).json({ error: 'Evidence file must be between 1 byte and 5 MB.' });
      return;
    }
    if (mime === 'application/pdf' && !raw.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
      res.status(400).json({ error: 'Invalid PDF header.' });
      return;
    }
    if (mime === 'image/png' && !raw.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) {
      res.status(400).json({ error: 'Invalid PNG header.' });
      return;
    }
    if (mime === 'image/jpeg' && !raw.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) {
      res.status(400).json({ error: 'Invalid JPEG header.' });
      return;
    }

    const enc = encryptBuffer(raw);
    const evNow = utcNow();
    const info = db
      .prepare(
        'INSERT INTO evidence (case_id, name, mime, encrypted, iv, auth_tag, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      )
      .run(caseId, name, mime, enc.encrypted, enc.iv, enc.authTag, evNow);

    const caseStatusRow = db.prepare('SELECT status FROM cases WHERE id = ?').get(caseId) as
      | { status: string }
      | undefined;
    db.prepare(
      `INSERT INTO case_events (case_id, user_id, event_type, status, summary, created_at)
       VALUES (?, ?, 'evidence_attached', ?, ?, ?)`
    ).run(
      caseId,
      req.userId!,
      caseStatusRow?.status || 'Open',
      `Attached AES-256-GCM encrypted evidence "${name}" (${mime}).`,
      evNow
    );

    res.status(201).json({ id: Number(info.lastInsertRowid), name, mime });
  });

  app.get('/api/cases/:id/evidence/:eid', requireAuth, (req: AuthedRequest, res) => {
    const owned = db
      .prepare('SELECT id FROM cases WHERE id = ? AND user_id = ?')
      .get(Number(req.params.id), req.userId!);
    if (!owned) {
      res.status(404).json({ error: 'Case not found.' });
      return;
    }
    const ev = db
      .prepare('SELECT name, mime, encrypted, iv, auth_tag FROM evidence WHERE id = ? AND case_id = ?')
      .get(Number(req.params.eid), Number(req.params.id)) as
      | { name: string; mime: string; encrypted: Uint8Array; iv: Uint8Array; auth_tag: Uint8Array }
      | undefined;
    if (!ev) {
      res.status(404).json({ error: 'Evidence not found.' });
      return;
    }
    const plain = decryptBuffer(ev.encrypted, ev.iv, ev.auth_tag);
    res.setHeader('Content-Type', ev.mime);
    res.setHeader('Content-Disposition', `attachment; filename="${ev.name.replace(/"/g, '')}"`);
    res.send(plain);
  });

  // --- Settings & Account Deletion ---
  app.patch('/api/settings/profile', requireAuth, (req: AuthedRequest, res) => {
    const name = String(req.body?.fullName || '').trim().slice(0, 120);
    if (!name) {
      res.status(400).json({ error: 'Name is required.' });
      return;
    }
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.userId!);
    res.json({ ok: true, user: getEnrollmentState(req.userId!) });
  });

  app.post('/api/settings/password', requireAuth, sensitiveAccountLimiter, (req: AuthedRequest, res) => {
    const oldPassword = String(req.body?.oldPassword || '');
    const newPassword = String(req.body?.newPassword || '');
    const row = db
      .prepare('SELECT password_hash FROM users WHERE id = ?')
      .get(req.userId!) as { password_hash: string };

    if (!verifySecret(oldPassword, row.password_hash)) {
      res.status(400).json({ error: 'Current password is incorrect.' });
      return;
    }
    if (newPassword.length < 12) {
      res.status(400).json({ error: 'New password must be at least 12 characters.' });
      return;
    }
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(
      hashSecret(newPassword),
      req.userId!
    );
    res.json({ ok: true });
  });

  app.delete('/api/settings/account', requireAuth, sensitiveAccountLimiter, (req: AuthedRequest, res) => {
    const password = String(req.body?.password || '');
    const row = db
      .prepare('SELECT password_hash FROM users WHERE id = ?')
      .get(req.userId!) as { password_hash: string };
    if (!verifySecret(password, row.password_hash)) {
      res.status(403).json({ error: 'Password incorrect. Account was not deleted.' });
      return;
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(req.userId!);
    res.json({ ok: true });
  });

  // --- Vite / Static Serving ---
  if (!options?.skipVite) {
    if (!isProd) {
      const hmrDisabled = process.env.DISABLE_HMR === 'true';
      const vite = await createViteServer({
        server: {
          middlewareMode: true,
          ws: hmrDisabled ? false : options?.httpServer ? { server: options.httpServer } : undefined,
          hmr: hmrDisabled ? false : options?.httpServer ? { server: options.httpServer } : true,
        },
        appType: 'spa',
      });
      if (hmrDisabled) {
        app.get('/@vite/client', async (_req, res, next) => {
          try {
            const result = await vite.transformRequest('/@vite/client');
            if (!result) {
              next();
              return;
            }
            const patched = result.code.replace(
              /let wsTransport = createWebSocketModuleRunnerTransport\(\{[\s\S]*?\}\);/,
              'let wsTransport = { async connect() {}, async disconnect() {}, send() {} };'
            );
            res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
            res.send(patched);
          } catch (err) {
            next(err);
          }
        });
      }
      app.use(vite.middlewares);
    } else {
      const distDir = path.resolve(process.cwd(), 'dist');
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  return app;
}
