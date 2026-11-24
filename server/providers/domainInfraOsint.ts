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
import type { NormalizedFinding, OsintProvider, ProviderResult, ScanContext } from './types.ts';

function getTargetDomains(ctx: ScanContext): string[] {
  const set = new Set<string>();
  for (const d of ctx.domains) {
    const norm = normalizeDomain(d);
    if (norm) set.add(norm);
  }
  const emailDomain = ctx.email.split('@')[1];
  if (emailDomain) {
    const norm = normalizeDomain(emailDomain);
    if (norm && !isConsumerEmailDomain(norm)) {
      set.add(norm);
    }
  }
  return Array.from(set).slice(0, 3);
}

export const crtshProvider: OsintProvider = {
  id: 'crtsh',
  name: 'crt.sh Certificate Transparency (+ CertSpotter Fallback)',
  categoryFocus: 'Public Records',
  description: 'Queries Certificate Transparency logs for TLS certificates and publicly discoverable subdomains of your authorized domains.',
  freeTierLimit: 'Permanently free, no API key required (rate-limited by upstream CT log servers)',
  requiresKey: false,
  minIntervalMs: 1200,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const domains = getTargetDomains(ctx);
    if (domains.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message:
          'Add an owned domain (e.g., yoursite.com) in Monitored Domains & Keywords to inspect Certificate Transparency logs and subdomains (shared consumer mail domains like gmail.com are skipped automatically).',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const findings: NormalizedFinding[] = [];
    let usedCache = false;
    let sourceLabel = 'crt.sh Certificate Transparency';

    try {
      for (const domain of domains) {
        const cacheKey = `crtsh:${domain}`;
        let records = getCachedValue<{
          providerUsed: string;
          subdomains: string[];
          certCount: number;
          latestEntry: string;
          issuer: string;
          queryUrl: string;
        }>(cacheKey);

        if (records) {
          usedCache = true;
          sourceLabel = records.value.providerUsed;
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
        } else {
          let parsedData: {
            providerUsed: string;
            subdomains: string[];
            certCount: number;
            latestEntry: string;
            issuer: string;
            queryUrl: string;
          } | null = null;

          const crtUrl = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
          try {
            const { response } = await fetchWithRetry(crtUrl, {
              providerId: this.id,
              minIntervalMs: this.minIntervalMs,
              timeoutMs: 16_000,
              maxRetries: 1,
            });
            if (response.ok) {
              const rows = (await response.json()) as Array<{
                name_value?: string;
                common_name?: string;
                issuer_name?: string;
                entry_timestamp?: string;
              }>;
              const subs = new Set<string>();
              for (const r of rows) {
                for (const name of String(r.name_value || r.common_name || '').split('\n')) {
                  const clean = name.trim().toLowerCase().replace(/^\*\./, '');
                  if (clean.endsWith(domain)) subs.add(clean);
                }
              }
              parsedData = {
                providerUsed: 'crt.sh Certificate Transparency',
                subdomains: Array.from(subs).slice(0, 25),
                certCount: rows.length,
                latestEntry: String(rows[0]?.entry_timestamp || '').slice(0, 19),
                issuer: String(rows[0]?.issuer_name || 'Unknown CA').slice(0, 120),
                queryUrl: `https://crt.sh/?q=${encodeURIComponent(domain)}`,
              };
            }
          } catch {
            // Fall through to CertSpotter CT fallback
          }

          if (!parsedData) {
            const csUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
            const { response: csRes } = await fetchWithRetry(csUrl, {
              providerId: this.id,
              minIntervalMs: this.minIntervalMs,
              timeoutMs: 14_000,
              maxRetries: 1,
            });
            if (csRes.status === 429) {
              throw new ProviderRateLimitError('CT log rate limit exceeded on crt.sh and CertSpotter.');
            }
            if (!csRes.ok) {
              throw new Error(`CT log lookup failed (HTTP ${csRes.status}).`);
            }
            const rows = (await csRes.json()) as Array<{
              dns_names?: string[];
              not_before?: string;
            }>;
            const subs = new Set<string>();
            for (const r of rows) {
              for (const name of r.dns_names ?? []) {
                const clean = name.trim().toLowerCase().replace(/^\*\./, '');
                if (clean.endsWith(domain)) subs.add(clean);
              }
            }
            parsedData = {
              providerUsed: 'CertSpotter CT Fallback (crt.sh unavailable)',
              subdomains: Array.from(subs).slice(0, 25),
              certCount: rows.length,
              latestEntry: String(rows[0]?.not_before || '').slice(0, 19),
              issuer: 'Public Certificate Transparency Log',
              queryUrl: `https://crt.sh/?q=${encodeURIComponent(domain)}`,
            };
          }

          sourceLabel = parsedData.providerUsed;
          setCachedValue(cacheKey, this.id, parsedData, 900);
          records = { value: parsedData, fetchedAt: utcNow() };
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
        }

        const val = records.value;
        if (val.certCount > 0) {
          findings.push({
            title: `Certificate Transparency exposure for "${domain}" (${val.subdomains.length} hostnames in ${val.certCount} cert records)`,
            category: 'Public Records',
            sourceName: val.providerUsed,
            sourceUrl: val.queryUrl,
            foundAt: utcNow(),
            evidence: `Discovered hostnames/subdomains: ${val.subdomains.slice(0, 10).join(', ')}${val.subdomains.length > 10 ? ` (+${val.subdomains.length - 10} more)` : ''}. Latest timestamp: ${val.latestEntry || 'n/a'}. Issuer: ${val.issuer}.`,
            explanation: `Public Certificate Transparency logs permanently record subdomains (including staging, dev, or admin hostnames) when TLS certificates are issued for ${domain}.`,
            confidence: 0.94,
            severity: val.subdomains.some((s) => /(dev|staging|test|admin|internal|vpn)/.test(s)) ? 0.65 : 0.35,
            recencyScore: 0.85,
            risk: val.subdomains.some((s) => /(dev|staging|test|admin|internal|vpn)/.test(s)) ? 'Medium' : 'Low',
            verificationStatus: 'Unverified',
          });
        }
      }

      return {
        providerId: this.id,
        providerName: sourceLabel,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Checked CT logs for ${domains.join(', ')}; discovered ${findings.length} record summary.`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const status = err instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const msg = err instanceof Error ? err.message : 'crt.sh query failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status, error: msg, madeRequest: true });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
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

export const rdapDnsProvider: OsintProvider = {
  id: 'rdap_dns',
  name: 'Authoritative RDAP + Google DNS-over-HTTPS',
  categoryFocus: 'Public Records',
  description: 'Inspects domain registration visibility (RDAP) and public SPF/DMARC email spoofing protections (DoH) for authorized domains.',
  freeTierLimit: 'Permanently free, no API key required',
  requiresKey: false,
  minIntervalMs: 300,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const domains = getTargetDomains(ctx);
    if (domains.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message: 'Add an owned domain in Monitored Domains to inspect RDAP WHOIS exposure and SPF/DMARC records.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const findings: NormalizedFinding[] = [];
    let usedCache = false;

    try {
      // Load IANA RDAP Bootstrap (cached 24h)
      let bootstrap = getCachedValue<{ services?: Array<[string[], string[]]> }>('iana:rdap:bootstrap')?.value;
      if (!bootstrap) {
        const { response } = await fetchWithRetry('https://data.iana.org/rdap/dns.json', {
          providerId: this.id,
          minIntervalMs: 200,
        });
        if (response.ok) {
          bootstrap = (await response.json()) as { services?: Array<[string[], string[]]> };
          setCachedValue('iana:rdap:bootstrap', this.id, bootstrap, 86_400);
        }
      }

      for (const domain of domains) {
        const tld = domain.split('.').pop() || '';
        const cacheKey = `rdap_dns:${domain}`;
        const cached = getCachedValue<{
          rdapUrl?: string;
          registrar?: string;
          statusList?: string[];
          hasSpf: boolean;
          hasDmarc: boolean;
          txtRecords: string[];
        }>(cacheKey);

        let info: {
          rdapUrl?: string;
          registrar?: string;
          statusList?: string[];
          hasSpf: boolean;
          hasDmarc: boolean;
          txtRecords: string[];
        };

        if (cached) {
          usedCache = true;
          info = cached.value;
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
        } else {
          // Google DoH TXT & DMARC
          const [txtRes, dmarcRes] = await Promise.all([
            fetchWithRetry(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`, {
              providerId: this.id,
              minIntervalMs: 200,
            }),
            fetchWithRetry(`https://dns.google/resolve?name=${encodeURIComponent(`_dmarc.${domain}`)}&type=TXT`, {
              providerId: this.id,
              minIntervalMs: 200,
            }),
          ]);

          const txtJson = txtRes.response.ok
            ? ((await txtRes.response.json()) as { Answer?: Array<{ data?: string }> })
            : { Answer: [] };
          const dmarcJson = dmarcRes.response.ok
            ? ((await dmarcRes.response.json()) as { Answer?: Array<{ data?: string }> })
            : { Answer: [] };

          const txtRecords = (txtJson.Answer ?? []).map((a) => String(a.data || ''));
          const dmarcRecords = (dmarcJson.Answer ?? []).map((a) => String(a.data || ''));
          const hasSpf = txtRecords.some((r) => r.toLowerCase().includes('v=spf1'));
          const hasDmarc = dmarcRecords.some((r) => r.toLowerCase().includes('v=dmarc1'));

          let rdapUrl: string | undefined;
          let registrar: string | undefined;
          let statusList: string[] | undefined;

          const svc = bootstrap?.services?.find(([tlds]) => tlds.includes(tld));
          const baseRdap = svc?.[1]?.[0];
          if (baseRdap) {
            const fullRdap = `${baseRdap.replace(/\/$/, '')}/domain/${encodeURIComponent(domain)}`;
            rdapUrl = fullRdap;
            try {
              const { response: rRes } = await fetchWithRetry(fullRdap, {
                providerId: this.id,
                minIntervalMs: 250,
              });
              if (rRes.ok) {
                const rdapData = (await rRes.json()) as {
                  status?: string[];
                  entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
                };
                statusList = rdapData.status;
                const regEnt = rdapData.entities?.find((e) => e.roles?.includes('registrar'));
                registrar = regEnt ? 'Registrar listed in RDAP' : undefined;
              }
            } catch {
              // ignore non-fatal RDAP server refusal
            }
          }

          info = { rdapUrl, registrar, statusList, hasSpf, hasDmarc, txtRecords };
          setCachedValue(cacheKey, this.id, info, 3600);
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
        }

        const now = utcNow();
        if (!info.hasSpf || !info.hasDmarc) {
          findings.push({
            title: `Email spoofing protection gap on "${domain}" (SPF: ${info.hasSpf ? 'Present' : 'Missing'}, DMARC: ${info.hasDmarc ? 'Present' : 'Missing'})`,
            category: 'Possible Impersonation',
            sourceName: 'Google DNS-over-HTTPS (TXT)',
            sourceUrl: `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`,
            foundAt: now,
            evidence: `TXT records inspected: ${info.txtRecords.length}. SPF v=spf1=${info.hasSpf}; _dmarc v=DMARC1=${info.hasDmarc}.`,
            explanation: `Without both SPF and DMARC records, attackers can more easily spoof emails appearing to originate from "${domain}".`,
            confidence: 0.95,
            severity: 0.7,
            recencyScore: 0.9,
            risk: 'Medium',
            verificationStatus: 'Unverified',
          });
        }
        if (info.rdapUrl && info.statusList?.length) {
          findings.push({
            title: `Public RDAP registry record active for "${domain}"`,
            category: 'Public Records',
            sourceName: 'Authoritative IANA/TLD RDAP',
            sourceUrl: info.rdapUrl,
            foundAt: now,
            evidence: `RDAP status flags: ${info.statusList.join(', ')}. ${info.registrar || ''}`.trim(),
            explanation: `Domain registration status is publicly queryable via RDAP. Verify registrant WHOIS privacy protection is enabled with your registrar.`,
            confidence: 0.92,
            severity: 0.3,
            recencyScore: 0.75,
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
        message: `Checked DNS SPF/DMARC and authoritative RDAP for ${domains.join(', ')}.`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'RDAP/DNS check failed.';
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

export const urlhausProvider: OsintProvider = {
  id: 'urlhaus',
  name: 'URLhaus Threat Intelligence (abuse.ch)',
  categoryFocus: 'Public Records',
  description: 'Checks authorized domains and hostnames against abuse.ch URLhaus malware-distribution intelligence.',
  freeTierLimit: 'Free abuse.ch account Auth-Key required (URLHAUS_AUTH_KEY from auth.abuse.ch)',
  requiresKey: true,
  keyEnvVar: 'URLHAUS_AUTH_KEY',
  minIntervalMs: 500,
  isConfigured: () => Boolean(process.env.URLHAUS_AUTH_KEY?.trim()),
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const authKey = process.env.URLHAUS_AUTH_KEY?.trim();
    if (!authKey) {
      recordProviderTelemetry({
        providerId: this.id,
        providerName: this.name,
        status: 'unavailable',
        error: 'URLHAUS_AUTH_KEY not configured (free key at https://auth.abuse.ch/).',
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
          'URLHAUS_AUTH_KEY is not configured. abuse.ch retired unauthenticated URLhaus API access (HTTP 401/410); obtain a free Auth-Key at https://auth.abuse.ch/ to enable URLhaus host checks.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const domains = getTargetDomains(ctx);
    if (domains.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: true,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message: 'Add an owned domain in Monitored Domains to query URLhaus host reputation.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const findings: NormalizedFinding[] = [];
    let usedCache = false;
    try {
      for (const domain of domains) {
        const cacheKey = `urlhaus:${domain}`;
        let data = getCachedValue<Record<string, unknown>>(cacheKey)?.value;
        if (data) {
          usedCache = true;
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
        } else {
          const { response } = await fetchWithRetry('https://urlhaus-api.abuse.ch/v1/host/', {
            method: 'POST',
            providerId: this.id,
            minIntervalMs: this.minIntervalMs,
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Auth-Key': authKey,
            },
            body: `host=${encodeURIComponent(domain)}`,
          });
          if (!response.ok) {
            throw new Error(`URLhaus API returned HTTP ${response.status}.`);
          }
          data = (await response.json()) as Record<string, unknown>;
          setCachedValue(cacheKey, this.id, data, 900);
          recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
        }

        if (data.query_status === 'ok' && Number(data.url_count ?? 0) > 0) {
          const urls = Array.isArray(data.urls) ? (data.urls as Array<Record<string, unknown>>) : [];
          findings.push({
            title: `URLhaus reported ${String(data.url_count)} malicious URL(s) on host "${domain}"`,
            category: 'Possible Impersonation',
            sourceName: this.name,
            sourceUrl: String(data.urlhaus_reference || `https://urlhaus.abuse.ch/host/${encodeURIComponent(domain)}/`),
            foundAt: utcNow(),
            evidence: `URLhaus host lookup: url_count=${String(data.url_count)}, firstseen=${String(data.firstseen || 'n/a')}, sample_threat=${String(urls[0]?.threat || 'malware_download')}.`,
            explanation: `abuse.ch URLhaus recorded malicious URLs under "${domain}". Investigate potential domain compromise or unauthorized subdomain abuse.`,
            confidence: 0.95,
            severity: 1.0,
            recencyScore: 0.95,
            risk: 'High',
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
        message: `Checked ${domains.length} domain(s) against URLhaus.`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'URLhaus query failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'error', error: msg, madeRequest: true });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: true,
        keyEnvVar: this.keyEnvVar,
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
