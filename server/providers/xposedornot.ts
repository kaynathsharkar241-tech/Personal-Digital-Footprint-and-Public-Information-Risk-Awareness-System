import { utcNow } from '../db.ts';
import {
  ProviderRateLimitError,
  fetchWithRetry,
  getCachedValue,
  recordProviderTelemetry,
  setCachedValue,
} from './http.ts';
import type { NormalizedFinding, OsintProvider, ProviderResult, ScanContext } from './types.ts';

interface XposedPayload {
  breaches?: unknown;
  [key: string]: unknown;
}

export const xposedOrNotProvider: OsintProvider = {
  id: 'xposedornot',
  name: 'XposedOrNot Public Breach API',
  categoryFocus: 'Breached Credentials',
  description: 'Checks the monitored email address against the public XposedOrNot breach index.',
  freeTierLimit: 'Public API; subject to service rate limits and availability.',
  requiresKey: false,
  minIntervalMs: 1200,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const started = Date.now();
    const email = ctx.email.trim().toLowerCase();
    const base = {
      providerId: this.id,
      providerName: this.name,
      categoryFocus: this.categoryFocus,
      requiresKey: this.requiresKey,
      freeTierLimit: this.freeTierLimit,
    };
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      const message = 'A valid email address is required for this breach check.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'skipped', error: message });
      return { ...base, status: 'skipped', findings: [], message, cached: false, latencyMs: Date.now() - started };
    }

    const cacheKey = `xposedornot:${email}`;
    let cached = false;
    try {
      let payload = getCachedValue<XposedPayload>(cacheKey)?.value;
      if (payload) {
        cached = true;
        recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
      } else {
        const url = `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`;
        const { response, rateLimitRemaining, rateLimitReset } = await fetchWithRetry(url, {
          providerId: this.id,
          minIntervalMs: this.minIntervalMs,
          headers: { Accept: 'application/json' },
        });
        if (response.status === 404) {
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
          return {
            ...base, status: 'ok', findings: [],
            message: 'XposedOrNot returned no breach matches for this email address.',
            cached: false, latencyMs: Date.now() - started,
          };
        }
        if (response.status === 429) throw new ProviderRateLimitError('XposedOrNot rate limit reached.');
        if (!response.ok) throw new Error(`XposedOrNot API returned HTTP ${response.status}.`);
        payload = (await response.json()) as XposedPayload;
        setCachedValue(cacheKey, this.id, payload, 1800);
        recordProviderTelemetry({
          providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true,
          rateLimitRemaining, rateLimitReset,
        });
      }

      let names = payload.breaches;
      if (names && typeof names === 'object' && !Array.isArray(names)) {
        const obj = names as Record<string, unknown>;
        names = obj.breaches ?? obj.name ?? Object.values(obj);
      }
      if (Array.isArray(names) && names.length === 1 && Array.isArray(names[0])) names = names[0];
      const breachNames = Array.isArray(names) ? names.map((v) => String(v)).filter(Boolean) : [];
      const retrievedAt = utcNow();
      const findings: NormalizedFinding[] = breachNames.map((name) => ({
        title: `Email address reported in ${name} breach`,
        category: 'Breached Credentials',
        sourceName: this.name,
        sourceUrl: 'https://xposedornot.com/',
        foundAt: retrievedAt,
        evidence: `XposedOrNot public API returned the breach name "${name}" for the monitored email address. The API response did not provide verified exposed data classes in this result.`,
        explanation: 'This is a breach-index match for the monitored email address. Review the breach details and change any affected or reused passwords; this result does not establish that a password is currently valid.',
        confidence: 0.82,
        severity: 0.78,
        recencyScore: 0.7,
        risk: 'High',
        verificationStatus: 'Unverified',
      }));
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok' });
      return {
        ...base, status: 'ok', findings,
        message: breachNames.length
          ? `XposedOrNot returned ${breachNames.length} breach match(es).`
          : 'XposedOrNot returned no breach matches for this email address.',
        cached, latencyMs: Date.now() - started,
      };
    } catch (error) {
      const status = error instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const message = error instanceof Error ? error.message : 'Unknown XposedOrNot provider error.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status, error: message });
      return { ...base, status, findings: [], message, cached, latencyMs: Date.now() - started };
    }
  },
};
