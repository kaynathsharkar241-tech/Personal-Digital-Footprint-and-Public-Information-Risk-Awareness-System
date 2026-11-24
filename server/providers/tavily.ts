import { utcNow } from '../db.ts';
import {
  ProviderRateLimitError,
  fetchWithRetry,
  getCachedValue,
  recordProviderTelemetry,
  setCachedValue,
} from './http.ts';
import type { NormalizedFinding, OsintProvider, ProviderResult, ScanContext } from './types.ts';

interface TavilyResult {
  title?: string;
  url?: string;
  content?: string;
  score?: number;
  published_date?: string;
}

interface TavilyPayload {
  results?: TavilyResult[];
}

function buildQueries(ctx: ScanContext): string[] {
  const identifiers = new Set<string>();
  if (ctx.fullName.trim().length >= 3) identifiers.add(`"${ctx.fullName.trim()}"`);
  if (ctx.username.trim().length >= 2) identifiers.add(`"${ctx.username.trim().replace(/^@/, '')}"`);
  for (const term of ctx.terms) {
    const clean = term.trim();
    if (clean.length >= 3) identifiers.add(`"${clean}"`);
  }
  for (const domain of ctx.domains) {
    const clean = domain.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (clean.length >= 4) identifiers.add(`"${clean}"`);
  }
  return Array.from(identifiers).slice(0, 3).map((term) => `${term} public profile OR contact OR mention`);
}

function categoryForUrl(url: string): NormalizedFinding['category'] {
  const lower = url.toLowerCase();
  if (/(facebook|instagram|linkedin|x\.com|twitter|tiktok|github|reddit)\./.test(lower)) {
    return 'Social Profiles and Images';
  }
  return 'Public Records';
}

export const tavilySearchProvider: OsintProvider = {
  id: 'tavily_search',
  name: 'Tavily Public Web Search',
  categoryFocus: 'Public Records and Social Profiles',
  description: 'Searches the public web for user-authorized names, usernames, terms, and domains using Tavily Search.',
  freeTierLimit: 'Usage depends on the Tavily account plan and remaining monthly credits.',
  requiresKey: true,
  keyEnvVar: 'TAVILY_API_KEY',
  minIntervalMs: 1000,
  isConfigured: () => Boolean(process.env.TAVILY_API_KEY?.trim()),
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const started = Date.now();
    const apiKey = process.env.TAVILY_API_KEY?.trim();
    const queries = buildQueries(ctx);
    const base = {
      providerId: this.id,
      providerName: this.name,
      categoryFocus: this.categoryFocus,
      requiresKey: this.requiresKey,
      keyEnvVar: this.keyEnvVar,
      freeTierLimit: this.freeTierLimit,
    };

    if (!apiKey) {
      const message = 'TAVILY_API_KEY is not configured. No Tavily search was performed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'unavailable', error: message });
      return { ...base, status: 'unavailable', findings: [], message, cached: false, latencyMs: Date.now() - started };
    }
    if (!queries.length) {
      const message = 'No eligible name, username, additional term, or domain was supplied. No Tavily search was performed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'skipped', error: message });
      return { ...base, status: 'skipped', findings: [], message, cached: false, latencyMs: Date.now() - started };
    }

    const findings: NormalizedFinding[] = [];
    let usedCache = false;
    try {
      for (const query of queries) {
        const cacheKey = `tavily:${query.toLowerCase()}`;
        let payload = getCachedValue<TavilyPayload>(cacheKey)?.value;
        if (payload) {
          usedCache = true;
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
        } else {
          const { response, rateLimitRemaining, rateLimitReset } = await fetchWithRetry('https://api.tavily.com/search', {
            method: 'POST',
            providerId: this.id,
            minIntervalMs: this.minIntervalMs,
            headers: {
              Authorization: `Bearer ${apiKey}`,
              'Content-Type': 'application/json',
              Accept: 'application/json',
            },
            body: JSON.stringify({
              query,
              topic: 'general',
              search_depth: 'basic',
              max_results: 5,
              include_answer: false,
              include_raw_content: false,
            }),
          });
          if (response.status === 401 || response.status === 403) {
            throw new Error(`Tavily authentication/authorization failed (HTTP ${response.status}). Check TAVILY_API_KEY and account access.`);
          }
          if (response.status === 429) throw new ProviderRateLimitError('Tavily rate limit or credit limit reached.');
          if (!response.ok) throw new Error(`Tavily Search API returned HTTP ${response.status}.`);
          payload = (await response.json()) as TavilyPayload;
          setCachedValue(cacheKey, this.id, payload, 300);
          recordProviderTelemetry({
            providerId: this.id,
            providerName: this.name,
            status: 'ok',
            madeRequest: true,
            rateLimitRemaining,
            rateLimitReset,
          });
        }

        const retrievedAt = utcNow();
        for (const item of (payload.results ?? [])) {
          const url = String(item.url || '');
          if (!/^https?:\/\//i.test(url)) continue;
          const title = String(item.title || url).slice(0, 240);
          const content = String(item.content || '').slice(0, 700);
          const score = Number.isFinite(Number(item.score)) ? Math.max(0, Math.min(1, Number(item.score))) : 0.45;
          findings.push({
            title: `Public web result: ${title}`,
            category: categoryForUrl(url),
            sourceName: this.name,
            sourceUrl: url,
            foundAt: retrievedAt,
            evidence: content || `Tavily returned this public URL for query: ${query}`,
            explanation: 'This is a potential public-web match returned by Tavily, not proof that the page refers to the account owner. Open the source and verify it manually.',
            confidence: score,
            severity: 0.4,
            recencyScore: item.published_date ? 0.75 : 0.5,
            risk: score >= 0.8 ? 'Medium' : 'Low',
            verificationStatus: 'Unverified',
          });
        }
      }

      const message = `Tavily returned ${findings.length} real public-web result(s) across ${queries.length} query/queries.`;
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok' });
      return { ...base, status: 'ok', findings, message, cached: usedCache, latencyMs: Date.now() - started };
    } catch (error) {
      const status = error instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const message = error instanceof Error ? error.message : 'Unknown Tavily provider error.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status, error: message });
      return { ...base, status, findings: [], message, cached: usedCache, latencyMs: Date.now() - started };
    }
  },
};
