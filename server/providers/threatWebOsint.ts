import crypto from 'node:crypto';
import { utcNow } from '../db.ts';
import {
  ProviderRateLimitError,
  fetchWithRetry,
  getCachedValue,
  isConsumerEmailDomain,
  normalizeDomain,
  recordProviderTelemetry,
  setCachedValue,
} from './http.ts';
import type {
  NormalizedFinding,
  OsintProvider,
  ProviderResult,
  RiskSeverity,
  ScanContext,
} from './types.ts';

function extractKeywords(ctx: ScanContext): string[] {
  const set = new Set<string>();
  for (const t of ctx.terms) {
    const clean = t.trim();
    if (clean.length >= 3) set.add(clean);
  }
  for (const d of ctx.domains) {
    const norm = normalizeDomain(d);
    if (norm) {
      const root = norm.split('.')[0];
      if (root && root.length >= 3) set.add(root);
    }
  }
  const emailDomain = ctx.email.split('@')[1];
  if (emailDomain) {
    const norm = normalizeDomain(emailDomain);
    if (norm && !isConsumerEmailDomain(norm)) {
      const root = norm.split('.')[0];
      if (root && root.length >= 3) set.add(root);
    }
  }
  return Array.from(set).slice(0, 4);
}

function mapCvssToRisk(score: number | null): { risk: RiskSeverity; severity: number } {
  if (score === null) return { risk: 'Medium', severity: 0.55 };
  if (score >= 7.0) return { risk: 'High', severity: 0.95 };
  if (score >= 4.0) return { risk: 'Medium', severity: 0.6 };
  return { risk: 'Low', severity: 0.3 };
}

export const nvdProvider: OsintProvider = {
  id: 'nvd_cve',
  name: 'NVD CVE 2.0 Vulnerability API',
  categoryFocus: 'Public Records',
  description:
    'Queries the NIST National Vulnerability Database (CVE 2.0) for known software or infrastructure CVEs matching your monitored tech/domain keywords.',
  freeTierLimit: '5 requests/30s free without key (50 requests/30s with optional free NVD_API_KEY)',
  requiresKey: false,
  keyEnvVar: 'NVD_API_KEY',
  minIntervalMs: process.env.NVD_API_KEY?.trim() ? 700 : 6200,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const keywords = extractKeywords(ctx);
    if (keywords.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message:
          'Add software, stack keywords, or owned domains (3+ chars) in Additional Terms / Monitored Domains to query NVD CVEs.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const apiKey = process.env.NVD_API_KEY?.trim();
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (apiKey) headers.apiKey = apiKey;

    const findings: NormalizedFinding[] = [];
    let usedCache = false;
    const targetKeywords = keywords.slice(0, 2);

    try {
      for (const kw of targetKeywords) {
        const cacheKey = `nvd:${kw.toLowerCase()}`;
        let payload = getCachedValue<{
          vulnerabilities?: Array<{
            cve?: {
              id?: string;
              published?: string;
              descriptions?: Array<{ lang?: string; value?: string }>;
              metrics?: {
                cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
                cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
                cvssMetricV2?: Array<{ cvssData?: { baseScore?: number }; baseSeverity?: string }>;
              };
            };
          }>;
        }>(cacheKey)?.value;

        if (payload) {
          usedCache = true;
          recordProviderTelemetry({
            providerId: this.id,
            providerName: this.name,
            status: 'ok',
            cacheHit: true,
          });
        } else {
          const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
            kw
          )}&resultsPerPage=3`;
          const { response, rateLimitRemaining, rateLimitReset } = await fetchWithRetry(url, {
            providerId: this.id,
            minIntervalMs: apiKey ? 700 : 6200,
            timeoutMs: 18_000,
            headers,
          });
          if (response.status === 403 || response.status === 429) {
            throw new ProviderRateLimitError(`NVD API rate limit exceeded (HTTP ${response.status}).`);
          }
          if (!response.ok) {
            throw new Error(`NVD API returned HTTP ${response.status}.`);
          }
          payload = (await response.json()) as typeof payload;
          setCachedValue(cacheKey, this.id, payload, 1800);
          recordProviderTelemetry({
            providerId: this.id,
            providerName: this.name,
            status: 'ok',
            madeRequest: true,
            rateLimitRemaining,
            rateLimitReset,
          });
        }

        const now = utcNow();
        for (const item of (payload?.vulnerabilities ?? []).slice(0, 3)) {
          const cve = item.cve;
          if (!cve?.id) continue;
          const desc =
            cve.descriptions?.find((d) => d.lang === 'en')?.value ||
            cve.descriptions?.[0]?.value ||
            'No description available.';
          const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? null;
          const v30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? null;
          const v2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null;
          const score = v31 ?? v30 ?? v2;
          const mapped = mapCvssToRisk(score);

          findings.push({
            title: `${cve.id} vulnerability matching keyword "${kw}"`,
            category: 'Public Records',
            sourceName: this.name,
            sourceUrl: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`,
            foundAt: now,
            evidence: `NVD CVE ID=${cve.id}, Published=${String(cve.published || '').slice(0, 10) || 'n/a'}, CVSS=${
              score !== null ? score.toFixed(1) : 'Unscored'
            }. Summary: ${desc.slice(0, 260)}`,
            explanation: `NIST NVD lists ${cve.id} matching your monitored stack/keyword "${kw}". Confirm whether you operate affected versions of this software or service.`,
            confidence: 0.72,
            severity: mapped.severity,
            recencyScore: 0.75,
            risk: mapped.risk,
            verificationStatus: 'Unverified',
          });
        }
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Checked NVD CVE 2.0 for [${targetKeywords.join(', ')}]; returned ${findings.length} CVE record(s).`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const status = err instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const msg = err instanceof Error ? err.message : 'NVD lookup failed.';
      recordProviderTelemetry({
        providerId: this.id,
        providerName: this.name,
        status,
        error: msg,
        madeRequest: true,
      });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status,
        findings,
        message: msg,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    }
  },
};

export const cisaKevProvider: OsintProvider = {
  id: 'cisa_kev',
  name: 'CISA Known Exploited Vulnerabilities (KEV)',
  categoryFocus: 'Public Records',
  description:
    'Cross-references your monitored domains, vendor names, and technology terms against the live CISA KEV actively exploited catalog.',
  freeTierLimit: 'Permanently free public JSON feed, no API key required',
  requiresKey: false,
  minIntervalMs: 500,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const keywords = extractKeywords(ctx);
    if (keywords.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message: 'Add software/vendor keywords or owned domains to check against the CISA KEV catalog.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    interface CisaKevCatalog {
      catalogVersion?: string;
      count?: number;
      vulnerabilities?: Array<{
        cveID?: string;
        vendorProject?: string;
        product?: string;
        vulnerabilityName?: string;
        dateAdded?: string;
        dueDate?: string;
        shortDescription?: string;
        knownRansomwareCampaignUse?: string;
      }>;
    }

    const cacheKey = 'cisa:kev:catalog';
    try {
      let catalog = getCachedValue<CisaKevCatalog>(cacheKey)?.value;
      let usedCache = false;

      if (catalog) {
        usedCache = true;
        recordProviderTelemetry({
          providerId: this.id,
          providerName: this.name,
          status: 'ok',
          cacheHit: true,
        });
      } else {
        const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
        const { response } = await fetchWithRetry(url, {
          providerId: this.id,
          minIntervalMs: this.minIntervalMs,
          timeoutMs: 20_000,
        });
        if (!response.ok) {
          throw new Error(`CISA KEV feed returned HTTP ${response.status}.`);
        }
        const full = (await response.json()) as CisaKevCatalog;
        catalog = {
          catalogVersion: full?.catalogVersion,
          count: full?.count,
          vulnerabilities: (full?.vulnerabilities ?? []).map((v) => ({
            cveID: v.cveID,
            vendorProject: v.vendorProject,
            product: v.product,
            vulnerabilityName: v.vulnerabilityName,
            dateAdded: v.dateAdded,
            dueDate: v.dueDate,
            shortDescription: v.shortDescription,
            knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
          })),
        };
        setCachedValue(cacheKey, this.id, catalog, 21_600);
        recordProviderTelemetry({
          providerId: this.id,
          providerName: this.name,
          status: 'ok',
          madeRequest: true,
        });
      }

      const vulns = catalog?.vulnerabilities ?? [];
      const findings: NormalizedFinding[] = [];
      const seenCves = new Set<string>();
      const now = utcNow();

      for (const kw of keywords) {
        const needle = kw.toLowerCase();
        // Require word-boundary match for shorter tokens to reduce false hits
        const regex = new RegExp(`\\b${needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
        let matchedForKw = 0;
        for (const v of vulns) {
          if (matchedForKw >= 3 || findings.length >= 6) break;
          const hay = `${v.vendorProject || ''} ${v.product || ''} ${v.vulnerabilityName || ''}`;
          if (regex.test(hay) && v.cveID && !seenCves.has(v.cveID)) {
            seenCves.add(v.cveID);
            matchedForKw++;
            findings.push({
              title: `CISA KEV active exploit advisory: ${v.cveID} (${v.vendorProject} ${v.product})`,
              category: 'Public Records',
              sourceName: this.name,
              sourceUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(
                v.cveID
              )}`,
              foundAt: now,
              evidence: `Catalog v${catalog?.catalogVersion || 'live'}: CVE=${v.cveID}, Vendor=${
                v.vendorProject
              }, Product=${v.product}, Added=${v.dateAdded || 'n/a'}, Ransomware=${
                v.knownRansomwareCampaignUse || 'Unknown'
              }.`,
              explanation: `${v.vulnerabilityName || v.shortDescription || 'Actively exploited vulnerability'} matches monitored term "${kw}". Patch or mitigate immediately if deployed.`,
              confidence: 0.78,
              severity: 0.95,
              recencyScore: 0.9,
              risk: 'High',
              verificationStatus: 'Unverified',
            });
          }
        }
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Checked ${vulns.length} CISA KEV entries (catalog v${catalog?.catalogVersion || 'live'}); matched ${findings.length} advisory(ies).`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'CISA KEV lookup failed.';
      recordProviderTelemetry({
        providerId: this.id,
        providerName: this.name,
        status: 'error',
        error: msg,
        madeRequest: true,
      });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'error',
        findings: [],
        message: msg,
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }
  },
};

export const hnAlgoliaProvider: OsintProvider = {
  id: 'hn_algolia',
  name: 'Hacker News Algolia Search API',
  categoryFocus: 'Public Records',
  description: 'Searches public Hacker News stories and discussions mentioning your full name, handle, or domains.',
  freeTierLimit: '10,000 requests/hour free, no API key required',
  requiresKey: false,
  minIntervalMs: 300,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const candidates = [
      ctx.fullName.trim(),
      ctx.username.trim().replace(/^@/, ''),
      ...ctx.domains.map((d) => normalizeDomain(d) || ''),
    ].filter((v) => v.length >= 4);
    const unique = Array.from(new Set(candidates)).slice(0, 3);

    if (unique.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message: 'Provide a name, handle, or domain (4+ chars) to search public Hacker News discussions.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const findings: NormalizedFinding[] = [];
    let usedCache = false;
    try {
      for (const term of unique) {
        const cacheKey = `hn:${term.toLowerCase()}`;
        let data = getCachedValue<{
          hits?: Array<{
            objectID?: string;
            title?: string;
            story_title?: string;
            url?: string;
            author?: string;
            created_at?: string;
            comment_text?: string;
          }>;
        }>(cacheKey)?.value;

        if (data) {
          usedCache = true;
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
        } else {
          const apiUrl = `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(
            `"${term}"`
          )}&hitsPerPage=3`;
          const { response } = await fetchWithRetry(apiUrl, {
            providerId: this.id,
            minIntervalMs: this.minIntervalMs,
          });
          if (!response.ok) throw new Error(`HN Algolia returned HTTP ${response.status}.`);
          data = (await response.json()) as typeof data;
          setCachedValue(cacheKey, this.id, data, 900);
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
        }

        const now = utcNow();
        for (const hit of (data?.hits ?? []).slice(0, 3)) {
          const itemTitle = String(hit.title || hit.story_title || '').trim();
          const hnUrl = hit.objectID
            ? `https://news.ycombinator.com/item?id=${encodeURIComponent(hit.objectID)}`
            : String(hit.url || '');
          if (!hnUrl) continue;
          findings.push({
            title: `Hacker News mention matching "${term}": ${itemTitle || `item #${hit.objectID}`}`.slice(0, 190),
            category: 'Public Records',
            sourceName: this.name,
            sourceUrl: hnUrl,
            foundAt: now,
            evidence: `HN author="${hit.author || 'unknown'}", created=${String(hit.created_at || '').slice(0, 10)}, item_id=${hit.objectID || 'n/a'}.`,
            explanation: `A public Hacker News post or thread matched exact phrase "${term}". Review whether it refers to you or your domain.`,
            confidence: 0.45,
            severity: 0.3,
            recencyScore: 0.7,
            risk: 'Low',
            verificationStatus: 'Unverified',
          });
        }
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Searched Hacker News for ${unique.length} identifier(s); found ${findings.length} mention(s).`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'HN Algolia search failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'error', error: msg, madeRequest: true });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'error',
        findings,
        message: msg,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    }
  },
};

export const wikipediaProvider: OsintProvider = {
  id: 'wikipedia',
  name: 'Wikipedia MediaWiki Search API',
  categoryFocus: 'Public Records',
  description: 'Searches public Wikipedia articles and encyclopedic references mentioning your name or organization/domain.',
  freeTierLimit: 'Permanently free public API, no API key required',
  requiresKey: false,
  minIntervalMs: 300,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const targets = [
      ctx.fullName.trim(),
      ...ctx.domains.map((d) => normalizeDomain(d) || ''),
    ].filter((s) => s.length >= 4);
    const unique = Array.from(new Set(targets)).slice(0, 2);

    if (unique.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message: 'Provide a full name or domain (4+ chars) to check Wikipedia public references.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const findings: NormalizedFinding[] = [];
    let usedCache = false;
    try {
      for (const term of unique) {
        const cacheKey = `wiki:${term.toLowerCase()}`;
        let data = getCachedValue<{
          query?: {
            search?: Array<{ pageid?: number; title?: string; snippet?: string; timestamp?: string }>;
          };
        }>(cacheKey)?.value;

        if (data) {
          usedCache = true;
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
        } else {
          const url = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(
            `"${term}"`
          )}&srlimit=3&format=json`;
          const { response } = await fetchWithRetry(url, {
            providerId: this.id,
            minIntervalMs: this.minIntervalMs,
          });
          if (!response.ok) throw new Error(`Wikipedia API returned HTTP ${response.status}.`);
          data = (await response.json()) as typeof data;
          setCachedValue(cacheKey, this.id, data, 1800);
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
        }

        const now = utcNow();
        for (const row of (data?.query?.search ?? []).slice(0, 3)) {
          const title = String(row.title || '').trim();
          if (!title) continue;
          const plainSnippet = String(row.snippet || '').replace(/<[^>]+>/g, '').slice(0, 240);
          findings.push({
            title: `Wikipedia reference "${title}" mentioning "${term}"`,
            category: 'Public Records',
            sourceName: this.name,
            sourceUrl: `https://en.wikipedia.org/wiki/${encodeURIComponent(title.replace(/\s+/g, '_'))}`,
            foundAt: now,
            evidence: `Wikipedia pageid=${row.pageid ?? 'n/a'}, updated=${String(row.timestamp || '').slice(0, 10)}. Excerpt: ${plainSnippet}`,
            explanation: `A public Wikipedia article matched exact phrase "${term}". Confirm whether it refers to you or someone with a shared name.`,
            confidence: 0.4,
            severity: 0.25,
            recencyScore: 0.6,
            risk: 'Low',
            verificationStatus: 'Unverified',
          });
        }
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Searched Wikipedia for ${unique.length} identifier(s); found ${findings.length} article reference(s).`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Wikipedia search failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'error', error: msg, madeRequest: true });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'error',
        findings,
        message: msg,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    }
  },
};

export const braveSearchProvider: OsintProvider = {
  id: 'brave_search',
  name: 'Brave Web Search API (Optional / Paid Tier)',
  categoryFocus: 'Public Records',
  description:
    'General open-web SERP discovery. Brave Search requires a paid subscription / billing card after limited credits, so it is optional and never mandatory.',
  freeTierLimit: 'Paid / credit-based ($5/mo free credit grant requires billing setup); use Guided Manual Search links at zero cost',
  requiresKey: true,
  keyEnvVar: 'BRAVE_API_KEY',
  minIntervalMs: 1100,
  isConfigured: () => Boolean(process.env.BRAVE_API_KEY?.trim()),
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const key = process.env.BRAVE_API_KEY?.trim();
    if (!key) {
      recordProviderTelemetry({
        providerId: this.id,
        providerName: this.name,
        status: 'unavailable',
        error: 'BRAVE_API_KEY not configured (requires billing-enabled Brave Search plan).',
      });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: true,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'unavailable',
        findings: [],
        message:
          'BRAVE_API_KEY is not configured (general web SERP indexing via Brave is billing-gated). Open-web coverage is incomplete; use the free Guided Manual Search links alongside the free OSINT APIs.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const terms = Array.from(
      new Set([ctx.fullName, ctx.username.replace(/^@/, ''), ...ctx.terms].map((t) => t.trim()).filter((t) => t.length >= 3))
    ).slice(0, 3);

    const findings: NormalizedFinding[] = [];
    try {
      for (const term of terms) {
        const url = new URL('https://api.search.brave.com/res/v1/web/search');
        url.searchParams.set('q', `"${term.slice(0, 120).replace(/"/g, '')}"`);
        url.searchParams.set('count', '5');
        url.searchParams.set('safesearch', 'moderate');

        const { response, rateLimitRemaining, rateLimitReset } = await fetchWithRetry(url.toString(), {
          providerId: this.id,
          minIntervalMs: this.minIntervalMs,
          headers: {
            'X-Subscription-Token': key,
            Accept: 'application/json',
          },
        });
        if (response.status === 429) {
          throw new ProviderRateLimitError('Brave Search quota/rate limit reached.');
        }
        if (!response.ok) {
          throw new Error(`Brave Search API returned HTTP ${response.status}.`);
        }
        const data = (await response.json()) as {
          web?: { results?: Array<{ url?: string; title?: string; description?: string }> };
        };
        recordProviderTelemetry({
          providerId: this.id,
          providerName: this.name,
          status: 'ok',
          madeRequest: true,
          rateLimitRemaining,
          rateLimitReset,
        });
        const now = utcNow();
        for (const item of data.web?.results ?? []) {
          const itemUrl = item.url ?? '';
          if (!/^https:\/\//i.test(itemUrl)) continue;
          findings.push({
            title: String(item.title || itemUrl).slice(0, 190),
            category: 'Public Records',
            sourceName: this.name,
            sourceUrl: itemUrl,
            foundAt: now,
            evidence: String(item.description || 'Indexed web result returned by Brave Search API.').slice(0, 320),
            explanation: `Brave Search web index matched monitored identifier "${term}". Confirm whether this page pertains to you before taking action.`,
            confidence: 0.4,
            severity: 0.3,
            recencyScore: 0.85,
            risk: 'Low',
            verificationStatus: 'Unverified',
          });
        }
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: true,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Checked Brave Search for ${terms.length} identifier(s); found ${findings.length} web result(s).`,
        cached: false,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const status = err instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const msg = err instanceof Error ? err.message : 'Brave Search request failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status, error: msg, madeRequest: true });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: true,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status,
        findings,
        message: msg,
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }
  },
};

/**
 * Have I Been Pwned Pwned Passwords Range API (k-Anonymity).
 * Permanently free, requires no API key, and NEVER transmits the full password or full SHA-1 hash.
 */
export async function checkPwnedPasswordRange(password: string): Promise<{
  compromised: boolean;
  pwnedCount: number;
  sha1Prefix: string;
  checkedAt: string;
  cached: boolean;
  sourceName: string;
  sourceUrl: string;
}> {
  const providerId = 'hibp_pwned_passwords';
  const providerName = 'Have I Been Pwned Pwned Passwords (k-Anonymity Range API)';

  const fullSha1 = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const prefix = fullSha1.slice(0, 5);
  const suffix = fullSha1.slice(5);
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;
  const cacheKey = `hibp_pw:${prefix}`;

  try {
    let bodyText = getCachedValue<string>(cacheKey)?.value;
    let usedCache = false;
    if (bodyText !== undefined) {
      usedCache = true;
      recordProviderTelemetry({ providerId, providerName, status: 'ok', cacheHit: true });
    } else {
      const { response } = await fetchWithRetry(url, {
        providerId,
        minIntervalMs: 150,
        headers: {
          'Add-Padding': 'true',
        },
      });
      if (!response.ok) {
        throw new Error(`Pwned Passwords API returned HTTP ${response.status}.`);
      }
      bodyText = await response.text();
      setCachedValue(cacheKey, providerId, bodyText, 3600);
      recordProviderTelemetry({ providerId, providerName, status: 'ok', madeRequest: true });
    }

    let pwnedCount = 0;
    for (const line of bodyText.split(/\r?\n/)) {
      const [lineSuffix, countStr] = line.trim().split(':');
      if (lineSuffix && lineSuffix.toUpperCase() === suffix) {
        pwnedCount = Number.parseInt(countStr || '0', 10) || 0;
        break;
      }
    }

    return {
      compromised: pwnedCount > 0,
      pwnedCount,
      sha1Prefix: prefix,
      checkedAt: utcNow(),
      cached: usedCache,
      sourceName: providerName,
      sourceUrl: 'https://haveibeenpwned.com/Passwords',
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Pwned Passwords check failed.';
    recordProviderTelemetry({ providerId, providerName, status: 'error', error: msg, madeRequest: true });
    throw err;
  }
}
