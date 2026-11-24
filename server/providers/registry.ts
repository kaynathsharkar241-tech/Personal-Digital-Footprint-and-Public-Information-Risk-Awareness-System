import { db } from '../db.ts';
import { crtshProvider, rdapDnsProvider, urlhausProvider } from './domainInfraOsint.ts';
import {
  githubProvider,
  gravatarProvider,
  hibpEmailProvider,
  stopForumSpamProvider,
} from './identityOsint.ts';
import {
  braveSearchProvider,
  cisaKevProvider,
  hnAlgoliaProvider,
  nvdProvider,
  wikipediaProvider,
} from './threatWebOsint.ts';
import type { NormalizedFinding, OsintProvider, ProviderResult, ScanContext } from './types.ts';
import { tavilySearchProvider } from './tavily.ts';
import { xposedOrNotProvider } from './xposedornot.ts';
import { googleCustomSearchProvider } from './googleCustomSearch.ts';

export const OSINT_PROVIDERS: OsintProvider[] = [
  tavilySearchProvider,
  googleCustomSearchProvider,
  xposedOrNotProvider,
  githubProvider,
  gravatarProvider,
  stopForumSpamProvider,
  crtshProvider,
  rdapDnsProvider,
  nvdProvider,
  cisaKevProvider,
  hnAlgoliaProvider,
  wikipediaProvider,
  urlhausProvider,
  hibpEmailProvider,
  braveSearchProvider,
];

export interface ProviderCatalogItem {
  id: string;
  name: string;
  categoryFocus: string;
  description: string;
  freeTierLimit: string;
  requiresKey: boolean;
  keyEnvVar?: string;
  configured: boolean;
  isPaidTier: boolean;
  requestsToday: number;
  cacheHits: number;
  lastStatus: string;
  lastError: string;
  lastCheckedAt: string | null;
  rateLimitRemaining: string;
}

const PAID_PROVIDER_IDS = new Set(['hibp_email', 'brave_search']);

export function getProviderCatalog(): ProviderCatalogItem[] {
  const telemetryRows = db
    .prepare('SELECT * FROM provider_telemetry')
    .all() as Array<{
    provider_id: string;
    requests_today: number;
    requests_date: string;
    cache_hits: number;
    last_status: string;
    last_error: string;
    last_checked_at: string | null;
    rate_limit_remaining: string;
  }>;
  const telemetryMap = new Map(telemetryRows.map((r) => [r.provider_id, r]));
  const today = new Date().toISOString().slice(0, 10);

  const items: ProviderCatalogItem[] = OSINT_PROVIDERS.map((p) => {
    const t = telemetryMap.get(p.id);
    return {
      id: p.id,
      name: p.name,
      categoryFocus: p.categoryFocus,
      description: p.description,
      freeTierLimit: p.freeTierLimit,
      requiresKey: p.requiresKey,
      keyEnvVar: p.keyEnvVar,
      configured: p.isConfigured(),
      isPaidTier: PAID_PROVIDER_IDS.has(p.id),
      requestsToday: t && t.requests_date === today ? t.requests_today : 0,
      cacheHits: t?.cache_hits ?? 0,
      lastStatus: t?.last_status ?? (p.isConfigured() ? 'ready' : 'unavailable'),
      lastError: t?.last_error ?? '',
      lastCheckedAt: t?.last_checked_at ?? null,
      rateLimitRemaining: t?.rate_limit_remaining ?? '',
    };
  });

  // Include standalone Pwned Passwords Range API in telemetry catalog
  const pwTel = telemetryMap.get('hibp_pwned_passwords');
  items.unshift({
    id: 'hibp_pwned_passwords',
    name: 'Have I Been Pwned Pwned Passwords (k-Anonymity)',
    categoryFocus: 'Breached Credentials',
    description:
      'On-demand k-anonymity password breach check sending only the first 5 SHA-1 hash hex characters.',
    freeTierLimit: 'Permanently free, unlimited range queries, no API key required',
    requiresKey: false,
    configured: true,
    isPaidTier: false,
    requestsToday: pwTel && pwTel.requests_date === today ? pwTel.requests_today : 0,
    cacheHits: pwTel?.cache_hits ?? 0,
    lastStatus: pwTel?.last_status ?? 'ready',
    lastError: pwTel?.last_error ?? '',
    lastCheckedAt: pwTel?.last_checked_at ?? null,
    rateLimitRemaining: pwTel?.rate_limit_remaining ?? '',
  });

  return items;
}

export interface SkippedProviderInfo {
  providerId: string;
  providerName: string;
  reason: string;
}

export async function runOsintScan(ctx: ScanContext): Promise<{
  findings: NormalizedFinding[];
  providerResults: ProviderResult[];
  incompleteCoverage: boolean;
  hasSkippedProviders: boolean;
  okProviders: number;
  skippedCount: number;
  totalProviders: number;
  skippedProviders: SkippedProviderInfo[];
  failedOrUnavailableProviders: string[];
}> {
  const settled = await Promise.allSettled(OSINT_PROVIDERS.map((provider) => provider.run(ctx)));
  const providerResults: ProviderResult[] = [];
  const findings: NormalizedFinding[] = [];

  for (let i = 0; i < settled.length; i++) {
    const p = OSINT_PROVIDERS[i];
    const res = settled[i];
    if (res.status === 'fulfilled') {
      providerResults.push(res.value);
      findings.push(...res.value.findings);
    } else {
      providerResults.push({
        providerId: p.id,
        providerName: p.name,
        categoryFocus: p.categoryFocus,
        requiresKey: p.requiresKey,
        keyEnvVar: p.keyEnvVar,
        freeTierLimit: p.freeTierLimit,
        status: 'error',
        findings: [],
        message: res.reason instanceof Error ? res.reason.message : 'Unexpected provider error.',
        cached: false,
        latencyMs: 0,
      });
    }
  }

  const failedOrUnavailableProviders = providerResults
    .filter((r) => r.status === 'error' || r.status === 'rate_limited' || r.status === 'unavailable')
    .map((r) => r.providerName);

  const skippedProviders: SkippedProviderInfo[] = providerResults
    .filter((r) => r.status === 'skipped')
    .map((r) => ({
      providerId: r.providerId,
      providerName: r.providerName,
      reason: r.message,
    }));

  const okProviders = providerResults.filter((r) => r.status === 'ok').length;
  const skippedCount = skippedProviders.length;
  const incompleteCoverage = failedOrUnavailableProviders.length > 0;
  const hasSkippedProviders = skippedCount > 0;

  return {
    findings,
    providerResults,
    incompleteCoverage,
    hasSkippedProviders,
    okProviders,
    skippedCount,
    totalProviders: OSINT_PROVIDERS.length,
    skippedProviders,
    failedOrUnavailableProviders,
  };
}
