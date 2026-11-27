import type { NextFunction, Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { getMasterKeyLength } from './crypto.ts';
import { DB_PATH, db, utcNow } from './db.ts';

export function getClientIp(req: Request): string {
  const fwd = String(req.headers['x-forwarded-for'] || '')
    .split(',')[0]
    .trim();
  return fwd || req.ip || req.socket.remoteAddress || 'unknown';
}

export function securityHeadersMiddleware(isProd: boolean) {
  return (req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader(
      'Permissions-Policy',
      'camera=(self), microphone=(), geolocation=(), payment=(), usb=()'
    );

    const scriptSrc = isProd ? "script-src 'self'" : "script-src 'self' 'unsafe-inline'";
    const csp = [
      "default-src 'self'",
      scriptSrc,
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob:",
      "connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com",
      "frame-ancestors 'self' https://aistudio.google.com https://*.google.com https://*.googleusercontent.com",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ');
    res.setHeader('Content-Security-Policy', csp);

    const isHttps = isProd || req.secure || req.headers['x-forwarded-proto'] === 'https';
    if (isHttps) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
    }

    next();
  };
}

export interface ConfigValidationResult {
  ok: boolean;
  warnings: string[];
  errors: string[];
}

export function validateRuntimeConfiguration(opts: {
  isProd: boolean;
  sessionSecret: string;
  distDir?: string;
}): ConfigValidationResult {
  const warnings: string[] = [];
  const errors: string[] = [];

  if (!opts.sessionSecret || opts.sessionSecret.length < 32) {
    errors.push('SESSION_SECRET must be at least 32 characters.');
  }
  if (/^(change_me|changeme|secret|default|dev-secret)$/i.test(opts.sessionSecret)) {
    errors.push('SESSION_SECRET uses a known insecure placeholder value.');
  }
  if (getMasterKeyLength() !== 32) {
    errors.push('EVIDENCE_KEY must decode to 32 bytes (256-bit AES-GCM key).');
  }

  try {
    const fk = db.prepare('PRAGMA foreign_keys').get() as { foreign_keys?: number } | undefined;
    if (fk?.foreign_keys !== 1) {
      errors.push('SQLite PRAGMA foreign_keys is not enabled.');
    }
    if (!fs.existsSync(DB_PATH)) {
      warnings.push('SQLite database file will be initialized on first write.');
    }
  } catch (err) {
    errors.push(`Database readiness check failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (opts.isProd) {
    const distDir = opts.distDir ?? path.resolve(process.cwd(), 'dist');
    if (!fs.existsSync(path.join(distDir, 'index.html'))) {
      errors.push(`Production frontend bundle not found at ${distDir}/index.html. Run "npm run build" first.`);
    }
    if (!process.env.APP_URL?.trim() && !process.env.PUBLIC_BASE_URL?.trim()) {
      warnings.push('APP_URL / PUBLIC_BASE_URL not set; WebAuthn RP ID falls back to request Host header.');
    }
  }

  const envReviewer = process.env.REVIEWER_PASSCODE?.trim();
  if (envReviewer && envReviewer.length < 12) {
    warnings.push('REVIEWER_PASSCODE environment variable is shorter than 12 characters.');
  }

  return {
    ok: errors.length === 0,
    warnings,
    errors,
  };
}

export function checkAndConsumeRateLimit(params: {
  bucket: string;
  maxAttempts: number;
  windowMs: number;
  lockDurationMs?: number;
  increment?: boolean;
}): { allowed: boolean; retryAfterSeconds: number; remaining: number } {
  const nowMs = Date.now();
  const nowIso = utcNow();
  const increment = params.increment !== false;

  const row = db
    .prepare('SELECT attempts, window_started_at, locked_until FROM auth_rate_limits WHERE bucket = ?')
    .get(params.bucket) as
    | { attempts: number; window_started_at: string; locked_until: string | null }
    | undefined;

  if (row?.locked_until) {
    const lockedUntilMs = Date.parse(row.locked_until);
    if (Number.isFinite(lockedUntilMs) && lockedUntilMs > nowMs) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((lockedUntilMs - nowMs) / 1000)),
        remaining: 0,
      };
    }
  }

  const windowStartMs = row ? Date.parse(row.window_started_at) : 0;
  const inWindow = row && Number.isFinite(windowStartMs) && nowMs - windowStartMs < params.windowMs;
  const currentAttempts = inWindow ? row.attempts : 0;
  const effectiveWindowStart = inWindow ? row.window_started_at : nowIso;

  if (currentAttempts >= params.maxAttempts) {
    const retryMs =
      params.lockDurationMs ??
      Math.max(1000, params.windowMs - Math.max(0, nowMs - (inWindow ? windowStartMs : nowMs)));
    const lockUntilIso = new Date(nowMs + retryMs).toISOString().replace(/\.\d{3}Z$/, 'Z');
    db.prepare(
      `INSERT INTO auth_rate_limits (bucket, attempts, window_started_at, locked_until, last_attempt_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(bucket) DO UPDATE SET
         attempts = excluded.attempts,
         window_started_at = excluded.window_started_at,
         locked_until = excluded.locked_until,
         last_attempt_at = excluded.last_attempt_at`
    ).run(params.bucket, currentAttempts, effectiveWindowStart, lockUntilIso, nowIso);

    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil(retryMs / 1000)),
      remaining: 0,
    };
  }

  const nextAttempts = increment ? currentAttempts + 1 : currentAttempts;
  if (increment) {
    db.prepare(
      `INSERT INTO auth_rate_limits (bucket, attempts, window_started_at, locked_until, last_attempt_at)
       VALUES (?, ?, ?, NULL, ?)
       ON CONFLICT(bucket) DO UPDATE SET
         attempts = excluded.attempts,
         window_started_at = excluded.window_started_at,
         locked_until = NULL,
         last_attempt_at = excluded.last_attempt_at`
    ).run(params.bucket, nextAttempts, effectiveWindowStart, nowIso);
  }

  return {
    allowed: true,
    retryAfterSeconds: 0,
    remaining: Math.max(0, params.maxAttempts - nextAttempts),
  };
}

export function resetRateLimitBucket(bucket: string): void {
  db.prepare('DELETE FROM auth_rate_limits WHERE bucket = ?').run(bucket);
}

export function createRateLimitMiddleware(opts: {
  prefix: string;
  maxAttempts: number;
  windowMs: number;
  lockDurationMs?: number;
  keyFn?: (req: Request) => string;
  message?: string;
}) {
  return (req: Request, res: Response, next: NextFunction) => {
    const keyPart = opts.keyFn ? opts.keyFn(req) : getClientIp(req);
    const result = checkAndConsumeRateLimit({
      bucket: `${opts.prefix}:${keyPart}`,
      maxAttempts: opts.maxAttempts,
      windowMs: opts.windowMs,
      lockDurationMs: opts.lockDurationMs,
      increment: true,
    });
    if (!result.allowed) {
      res.setHeader('Retry-After', String(result.retryAfterSeconds));
      res.status(429).json({
        error:
          opts.message ||
          `Too many requests. Please retry after ${result.retryAfterSeconds} second(s).`,
        retryAfterSeconds: result.retryAfterSeconds,
      });
      return;
    }
    next();
  };
}

export function resolveWebAuthnRP(req: Request): { rpID: string; expectedOrigins: string[] } {
  const configuredOrigins = new Set<string>();
  const configuredRps: string[] = [];

  for (const envUrl of [process.env.APP_URL, process.env.PUBLIC_BASE_URL]) {
    const clean = envUrl?.trim();
    if (!clean || clean === 'MY_APP_URL') continue;
    try {
      const parsed = new URL(clean);
      if (parsed.protocol === 'https:' || parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
        configuredOrigins.add(parsed.origin);
        configuredRps.push(parsed.hostname.toLowerCase());
      }
    } catch {
      // ignore invalid URL
    }
  }

  if (configuredRps.length > 0) {
    return {
      rpID: configuredRps[0],
      expectedOrigins: Array.from(configuredOrigins),
    };
  }

  const origins = new Set<string>();
  const rpCandidates: string[] = [];

  const forwardedHost = String(req.headers['x-forwarded-host'] || '')
    .split(',')[0]
    .trim();
  const rawHost = forwardedHost || String(req.headers.host || '').trim();
  if (rawHost) {
    const hostname = rawHost.split(':')[0].toLowerCase();
    const validHostname =
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(
        hostname
      );
    if (validHostname) {
      const proto =
        String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https' ||
        req.secure ||
        (hostname !== 'localhost' && hostname !== '127.0.0.1')
          ? 'https'
          : 'http';
      origins.add(`${proto}://${rawHost}`);
      if (hostname === 'localhost' || hostname === '127.0.0.1') {
        origins.add(`http://${rawHost}`);
        origins.add(`https://${rawHost}`);
      }
      rpCandidates.push(hostname);
    }
  }

  const reqOrigin = String(req.headers.origin || '').trim();
  if (reqOrigin) {
    try {
      const parsed = new URL(reqOrigin);
      const isLocal = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
      if ((parsed.protocol === 'https:' || (parsed.protocol === 'http:' && isLocal)) && rpCandidates.includes(parsed.hostname)) {
        origins.add(parsed.origin);
      }
    } catch {
      // ignore malformed origin
    }
  }

  const rpID = rpCandidates[0] || 'localhost';
  if (origins.size === 0) {
    origins.add('http://localhost:3000');
  }
  return {
    rpID,
    expectedOrigins: Array.from(origins),
  };
}
