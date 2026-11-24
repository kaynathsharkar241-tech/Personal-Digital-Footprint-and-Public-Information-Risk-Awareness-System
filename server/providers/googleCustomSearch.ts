import { utcNow } from '../db.ts';
import {
  ProviderRateLimitError,
  fetchWithRetry,
  getCachedValue,
  recordProviderTelemetry,
  setCachedValue,
} from './http.ts';
import type { NormalizedFinding, OsintProvider, ProviderResult, ScanContext } from './types.ts';

interface GoogleItem { title?: string; link?: string; snippet?: string; }
interface GooglePayload { items?: GoogleItem[]; }

function googleQueries(ctx: ScanContext): string[] {
  const terms = new Set<string>();
  if (ctx.fullName.trim().length >= 3) terms.add(`"${ctx.fullName.trim()}"`);
  if (ctx.username.trim().length >= 3) terms.add(`"${ctx.username.trim().replace(/^@/, '')}"`);
  for (const term of ctx.terms) if (term.trim().length >= 3) terms.add(`"${term.trim()}"`);
  for (const domain of ctx.domains) if (domain.trim().length >= 4) terms.add(`"${domain.trim()}"`);
  return Array.from(terms).slice(0, 3);
}

export const googleCustomSearchProvider: OsintProvider = {
  id: 'google_custom_search',
  name: 'Google Programmable Search',
  categoryFocus: 'Public Web and Social Profiles',
  description: 'Searches Google Programmable Search using exact phrases supplied in the user-authorized monitoring profile.',
  freeTierLimit: 'Requires Google API key and Programmable Search Engine ID; quota depends on Google account.',
  requiresKey: true,
  keyEnvVar: 'GOOGLE_API_KEY + GOOGLE_CSE_ID',
  minIntervalMs: 1100,
  isConfigured: () => Boolean(process.env.GOOGLE_API_KEY?.trim() && process.env.GOOGLE_CSE_ID?.trim()),
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const started = Date.now();
    const apiKey = process.env.GOOGLE_API_KEY?.trim();
    const engineId = process.env.GOOGLE_CSE_ID?.trim();
    const base = {
      providerId: this.id, providerName: this.name, categoryFocus: this.categoryFocus,
      requiresKey: this.requiresKey, keyEnvVar: this.keyEnvVar, freeTierLimit: this.freeTierLimit,
    };
    if (!apiKey || !engineId) {
      const message = 'GOOGLE_API_KEY and GOOGLE_CSE_ID are not both configured. No Google search was performed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'unavailable', error: message });
      return { ...base, status: 'unavailable', findings: [], message, cached: false, latencyMs: Date.now() - started };
    }
    const queries = googleQueries(ctx);
    if (!queries.length) {
      const message = 'No eligible monitoring identifiers were supplied. Google search was skipped.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'skipped', error: message });
      return { ...base, status: 'skipped', findings: [], message, cached: false, latencyMs: Date.now() - started };
    }
    const findings: NormalizedFinding[] = [];
    let cached = false;
    try {
      for (const query of queries) {
        const cacheKey = `google_cse:${query.toLowerCase()}`;
        let payload = getCachedValue<GooglePayload>(cacheKey)?.value;
        if (payload) {
          cached = true;
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
        } else {
          const url = new URL('https://www.googleapis.com/customsearch/v1');
          url.searchParams.set('key', apiKey);
          url.searchParams.set('cx', engineId);
          url.searchParams.set('q', query);
          url.searchParams.set('num', '5');
          const { response, rateLimitRemaining, rateLimitReset } = await fetchWithRetry(url.toString(), {
            providerId: this.id, minIntervalMs: this.minIntervalMs,
            headers: { Accept: 'application/json' },
          });
          if (response.status === 429 || response.status === 403) {
            throw new ProviderRateLimitError(`Google Programmable Search quota or rate limit reached (HTTP ${response.status}).`);
          }
          if (!response.ok) throw new Error(`Google Programmable Search returned HTTP ${response.status}.`);
          payload = (await response.json()) as GooglePayload;
          setCachedValue(cacheKey, this.id, payload, 300);
          recordProviderTelemetry({
            providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true,
            rateLimitRemaining, rateLimitReset,
          });
        }
        const retrievedAt = utcNow();
        for (const item of payload.items ?? []) {
          const link = String(item.link || '');
          if (!/^https?:\/\//i.test(link)) continue;
          const title = String(item.title || link).slice(0, 220);
          const snippet = String(item.snippet || '').slice(0, 700);
          const social = /(facebook|instagram|linkedin|twitter|x\.com|tiktok|github|reddit)\./i.test(link);
          findings.push({
            title: `Public web result: ${title}`,
            category: social ? 'Social Profiles and Images' : 'Public Records',
            sourceName: this.name,
            sourceUrl: link,
            foundAt: retrievedAt,
            evidence: snippet || `Google Programmable Search returned this result for the exact-phrase query ${query}.`,
            explanation: 'This is a potential public-web match returned by Google. A matching name or term alone does not prove that the page refers to you; open the source and verify it manually.',
            confidence: 0.48,
            severity: 0.4,
            recencyScore: 0.5,
            risk: 'Low',
            verificationStatus: 'Unverified',
          });
        }
      }
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok' });
      return {
        ...base, status: 'ok', findings,
        message: `Google Programmable Search returned ${findings.length} real result(s) across ${queries.length} query/queries.`,
        cached, latencyMs: Date.now() - started,
      };
    } catch (error) {
      const status = error instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const message = error instanceof Error ? error.message : 'Unknown Google Search provider error.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status, error: message });
      return { ...base, status, findings: [], message, cached, latencyMs: Date.now() - started };
    }
  },
};
