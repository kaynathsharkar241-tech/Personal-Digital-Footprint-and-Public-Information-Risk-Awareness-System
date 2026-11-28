import { evaluateRelevance } from './relevance.ts';
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
  return Array.from(identifiers).slice(0, 5);
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
    const seenUrls = new Set<string>();
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
              max_results: 10,
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
          let normalizedUrl: URL;

          try {
            normalizedUrl = new URL(url);
          } catch {
            continue;
          }

          normalizedUrl.hash = '';

          const canonicalUrl = normalizedUrl.toString();

          if (seenUrls.has(canonicalUrl)) continue;


          const title = String(item.title || url).slice(0, 240);
          const content = String(item.content || '').slice(0, 700);

          const match = evaluateRelevance(
            title,
            content,
            url,
            {
              fullName: ctx.fullName,
              username: ctx.username.replace(/^@/, '')
            }
          );

          const matchedTypes = new Set(
            match.matchedIdentifiers
          );

          for (const term of ctx.terms) {
            const clean = term.trim();

            const result = evaluateRelevance(
              title, content, url,
              clean.includes('@')
                ? { email: clean }
                : { fullName: clean }
            );

            if (result.relevance !== 'none') {
              matchedTypes.add('additional monitored term');
            }
          }

          for (const domain of ctx.domains) {
            const clean = domain.trim()
              .replace(/^https?:\/\//i, '')
              .replace(/\/$/, '');

            const result = evaluateRelevance(
              title, content, url,
              { domain: clean }
            );

            if (result.relevance !== 'none') {
              matchedTypes.add('domain');
            }
          }

          if (matchedTypes.size === 0) continue;

          seenUrls.add(canonicalUrl);

          const score =
            typeof item.score === 'number' &&
            Number.isFinite(item.score) &&
            item.score >= 0 &&
            item.score <= 1
              ? item.score
              : 0;

          const evidenceLabels = [...matchedTypes]
            .map(type => type === 'fullName'
              ? 'full name'
              : type)
            .join(', ');

          findings.push({
            title: `Public web result: ${title}`,
            category: categoryForUrl(url),
            sourceName: this.name,
            sourceUrl: url,
            foundAt: retrievedAt,
            evidence: content || `Tavily returned this public URL for query: ${query}`,
            explanation: `Detected identifiers: ${evidenceLabels}. Search relevance does not establish identity or harmful exposure. The provider score measures search relevance, not identity confidence. Review the original source before confirming this finding.`,
            confidence: score,
            severity: 0,
            recencyScore: (() => {
            if (!item.published_date) return 0;

            const published = Date.parse(item.published_date);

            if (!Number.isFinite(published)) return 0;
            if (published > Date.now()) return 0;

            const ageDays =
              (Date.now() - published) / 86400000;

            return Math.round(
              Math.max(0, 1 - ageDays / 365) * 1000
            ) / 1000;
          })(),
            risk: 'Low',
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
      return { ...base, status, findings, message, cached: usedCache, latencyMs: Date.now() - started };
    }
  },
};
