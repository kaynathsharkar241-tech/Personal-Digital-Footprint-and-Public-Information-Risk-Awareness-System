import { db, utcNow } from '../db.ts';
import type { ProviderStatus } from './types.ts';

const lastCallByProvider = new Map<string, number>();

export async function waitForRateLimit(providerId: string, minIntervalMs: number): Promise<void> {
  if (minIntervalMs <= 0) return;
  const prev = lastCallByProvider.get(providerId) ?? 0;
  const elapsed = Date.now() - prev;
  if (elapsed < minIntervalMs) {
    await new Promise((r) => setTimeout(r, minIntervalMs - elapsed));
  }
  lastCallByProvider.set(providerId, Date.now());
}

export function getCachedValue<T>(cacheKey: string): { value: T; fetchedAt: string } | null {
  const now = utcNow();
  const row = db
    .prepare('SELECT response_json, fetched_at, expires_at FROM api_cache WHERE cache_key = ?')
    .get(cacheKey) as
    | { response_json: string; fetched_at: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (row.expires_at <= now) {
    db.prepare('DELETE FROM api_cache WHERE cache_key = ?').run(cacheKey);
    return null;
  }
  try {
    return { value: JSON.parse(row.response_json) as T, fetchedAt: row.fetched_at };
  } catch {
    return null;
  }
}

export function setCachedValue(
  cacheKey: string,
  providerId: string,
  value: unknown,
  ttlSeconds: number
): void {
  const now = utcNow();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  db.prepare(
    `INSERT INTO api_cache (cache_key, provider_id, response_json, fetched_at, expires_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(cache_key) DO UPDATE SET
       response_json = excluded.response_json,
       fetched_at = excluded.fetched_at,
       expires_at = excluded.expires_at`
  ).run(cacheKey, providerId, JSON.stringify(value), now, expiresAt);
}

export function recordProviderTelemetry(params: {
  providerId: string;
  providerName: string;
  status: ProviderStatus;
  error?: string;
  cacheHit?: boolean;
  madeRequest?: boolean;
  rateLimitRemaining?: string;
  rateLimitReset?: string;
}): void {
  const today = utcNow().slice(0, 10);
  const now = utcNow();
  const existing = db
    .prepare('SELECT requests_today, requests_date, cache_hits FROM provider_telemetry WHERE provider_id = ?')
    .get(params.providerId) as
    | { requests_today: number; requests_date: string; cache_hits: number }
    | undefined;

  const baseReqs = existing && existing.requests_date === today ? existing.requests_today : 0;
  const nextReqs = baseReqs + (params.madeRequest ? 1 : 0);
  const nextCacheHits = (existing?.cache_hits ?? 0) + (params.cacheHit ? 1 : 0);

  db.prepare(
    `INSERT INTO provider_telemetry
     (provider_id, provider_name, requests_today, requests_date, cache_hits, last_status, last_error, last_checked_at, rate_limit_remaining, rate_limit_reset)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(provider_id) DO UPDATE SET
       provider_name = excluded.provider_name,
       requests_today = excluded.requests_today,
       requests_date = excluded.requests_date,
       cache_hits = excluded.cache_hits,
       last_status = excluded.last_status,
       last_error = excluded.last_error,
       last_checked_at = excluded.last_checked_at,
       rate_limit_remaining = CASE WHEN excluded.rate_limit_remaining != '' THEN excluded.rate_limit_remaining ELSE provider_telemetry.rate_limit_remaining END,
       rate_limit_reset = CASE WHEN excluded.rate_limit_reset != '' THEN excluded.rate_limit_reset ELSE provider_telemetry.rate_limit_reset END`
  ).run(
    params.providerId,
    params.providerName,
    nextReqs,
    today,
    nextCacheHits,
    params.status,
    (params.error || '').slice(0, 300),
    now,
    params.rateLimitRemaining || '',
    params.rateLimitReset || ''
  );
}

export class ProviderRateLimitError extends Error {
  statusCode = 429;
  retryAfterSeconds?: number;
  constructor(message: string, retryAfterSeconds?: number) {
    super(message);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export async function fetchWithRetry(
  url: string,
  init: RequestInit & { timeoutMs?: number; maxRetries?: number; providerId: string; minIntervalMs?: number }
): Promise<{ response: Response; rateLimitRemaining?: string; rateLimitReset?: string }> {
  const maxRetries = init.maxRetries ?? 2;
  const timeoutMs = init.timeoutMs ?? 15_000;
  const minIntervalMs = init.minIntervalMs ?? 350;

  let lastErr: Error | null = null;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    await waitForRateLimit(init.providerId, minIntervalMs);
    try {
      const res = await fetch(url, {
        ...init,
        headers: {
          'User-Agent': 'PrivacyMonitor-OSINT/1.0',
          ...(init.headers || {}),
        },
        signal: AbortSignal.timeout(timeoutMs),
      });

      const rateLimitRemaining =
        res.headers.get('x-ratelimit-remaining') ||
        res.headers.get('x-rate-limit-remaining') ||
        undefined;
      const rateLimitReset =
        res.headers.get('x-ratelimit-reset') ||
        res.headers.get('retry-after') ||
        undefined;

      if (res.status === 429 || res.status === 503 || res.status === 502 || res.status === 504) {
        const retryHeader = Number(res.headers.get('retry-after'));
        if (attempt < maxRetries) {
          const backoffMs =
            Number.isFinite(retryHeader) && retryHeader > 0 && retryHeader <= 15
              ? retryHeader * 1000
              : Math.min(4000, 600 * Math.pow(2, attempt) + Math.floor(Math.random() * 250));
          await new Promise((r) => setTimeout(r, backoffMs));
          continue;
        }
        if (res.status === 429) {
          throw new ProviderRateLimitError(
            `Rate limit exceeded (HTTP 429) on ${init.providerId}.`,
            Number.isFinite(retryHeader) ? retryHeader : undefined
          );
        }
      }

      return { response: res, rateLimitRemaining, rateLimitReset };
    } catch (err) {
      if (err instanceof ProviderRateLimitError) throw err;
      lastErr = err instanceof Error ? err : new Error(String(err));
      if (attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, 500 * Math.pow(2, attempt)));
        continue;
      }
    }
  }
  throw lastErr ?? new Error(`Network failure contacting ${init.providerId}.`);
}

const CONSUMER_EMAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'icloud.com',
  'me.com',
  'proton.me',
  'protonmail.com',
  'aol.com',
  'gmx.com',
  'mail.com',
]);

export function normalizeDomain(input: string): string | null {
  const cleaned = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^\.+|\.+$/g, '');
  if (!cleaned || cleaned.length > 253) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleaned)) return null;
  if (cleaned === 'localhost' || cleaned.endsWith('.local') || cleaned.endsWith('.internal')) {
    return null;
  }
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

export function isConsumerEmailDomain(domain: string): boolean {
  return CONSUMER_EMAIL_DOMAINS.has(domain.toLowerCase());
}
