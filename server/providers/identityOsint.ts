import crypto from 'node:crypto';
import { utcNow } from '../db.ts';
import {
  ProviderRateLimitError,
  fetchWithRetry,
  getCachedValue,
  recordProviderTelemetry,
  setCachedValue,
} from './http.ts';
import type { NormalizedFinding, OsintProvider, ProviderResult, ScanContext } from './types.ts';

export const githubProvider: OsintProvider = {
  id: 'github',
  name: 'GitHub REST API',
  categoryFocus: 'Social Profiles and Images',
  description: 'Searches public GitHub user profiles and repositories matching your handle, name, or verified email.',
  freeTierLimit: '10 search requests/min unauthenticated (30/min with optional free GITHUB_TOKEN)',
  requiresKey: false,
  keyEnvVar: 'GITHUB_TOKEN',
  minIntervalMs: 650,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const token = process.env.GITHUB_TOKEN?.trim();
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
    };
    if (token) headers.Authorization = `Bearer ${token}`;

    const queries: Array<{ label: string; q: string; endpoint: 'users' | 'repositories'; conf: number }> = [];
    if (ctx.username.trim().length >= 2) {
      const cleanHandle = ctx.username.trim().replace(/^@/, '');
      queries.push({ label: `handle "${cleanHandle}"`, q: `${cleanHandle} in:login`, endpoint: 'users', conf: 0.78 });
    }
    if (ctx.email.includes('@')) {
      queries.push({ label: `email "${ctx.email}"`, q: `${ctx.email} in:email`, endpoint: 'users', conf: 0.92 });
    }
    if (ctx.fullName.trim().length >= 3) {
      queries.push({ label: `name "${ctx.fullName.trim()}"`, q: `"${ctx.fullName.trim()}" in:name`, endpoint: 'users', conf: 0.45 });
    }
    for (const term of ctx.terms.slice(0, 2)) {
      if (term.length >= 3) {
        queries.push({ label: `repo term "${term}"`, q: `"${term}"`, endpoint: 'repositories', conf: 0.5 });
      }
    }

    if (queries.length === 0) {
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: this.requiresKey,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'skipped',
        findings: [],
        message: 'No username, email, or name supplied for GitHub search.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const findings: NormalizedFinding[] = [];
    let usedCache = false;
    let lastRemaining: string | undefined;
    let lastReset: string | undefined;

    try {
      for (const item of queries.slice(0, 4)) {
        const cacheKey = `github:${item.endpoint}:${item.q.toLowerCase()}`;
        const cached = getCachedValue<{ items?: Array<Record<string, unknown>> }>(cacheKey);
        let payload: { items?: Array<Record<string, unknown>> };

        if (cached) {
          usedCache = true;
          payload = cached.value;
          recordProviderTelemetry({
            providerId: this.id,
            providerName: this.name,
            status: 'ok',
            cacheHit: true,
          });
        } else {
          const url = `https://api.github.com/search/${item.endpoint}?q=${encodeURIComponent(item.q)}&per_page=4`;
          const { response, rateLimitRemaining, rateLimitReset } = await fetchWithRetry(url, {
            providerId: this.id,
            minIntervalMs: this.minIntervalMs,
            headers,
          });
          lastRemaining = rateLimitRemaining;
          lastReset = rateLimitReset;

          if (response.status === 403 || response.status === 429) {
            throw new ProviderRateLimitError(
              `GitHub API rate limit reached (HTTP ${response.status}).`,
              Number(response.headers.get('retry-after')) || undefined
            );
          }
          if (!response.ok) {
            throw new Error(`GitHub REST API returned HTTP ${response.status}.`);
          }
          payload = (await response.json()) as { items?: Array<Record<string, unknown>> };
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
        for (const entry of (payload.items ?? []).slice(0, 4)) {
          if (item.endpoint === 'users') {
            const login = String(entry.login || '');
            const htmlUrl = String(entry.html_url || `https://github.com/${login}`);
            const score = Number(entry.score || 0);
            findings.push({
              title: `Public GitHub account "@${login}" matched ${item.label}`,
              category: 'Social Profiles and Images',
              sourceName: this.name,
              sourceUrl: htmlUrl,
              foundAt: retrievedAt,
              evidence: `GitHub User API returned login="${login}", id=${String(entry.id || '')}, type=${String(entry.type || 'User')}, match_score=${score.toFixed(1)}.`,
              explanation: `A public GitHub profile matched ${item.label}. Confirm whether this account is yours and check if public commits or bio fields expose personal emails or location.`,
              confidence: item.conf,
              severity: item.q.includes('in:email') ? 0.65 : 0.4,
              recencyScore: 0.85,
              risk: item.q.includes('in:email') ? 'Medium' : 'Low',
              verificationStatus: 'Unverified',
            });
          } else {
            const fullName = String(entry.full_name || '');
            const htmlUrl = String(entry.html_url || '');
            const desc = String(entry.description || '').slice(0, 220);
            const updatedAt = String(entry.updated_at || retrievedAt);
            if (!htmlUrl) continue;
            findings.push({
              title: `Public GitHub repository "${fullName}" matched ${item.label}`,
              category: 'Public Records',
              sourceName: this.name,
              sourceUrl: htmlUrl,
              foundAt: retrievedAt,
              evidence: `Repository "${fullName}" (updated ${updatedAt.slice(0, 10)}): ${desc || 'No repository description'}.`,
              explanation: `Public repository metadata matched ${item.label}. Verify whether configuration files, commits, or READMEs expose sensitive personal or organizational details.`,
              confidence: item.conf,
              severity: 0.45,
              recencyScore: 0.8,
              risk: 'Low',
              verificationStatus: 'Unverified',
            });
          }
        }
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: this.requiresKey,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Checked ${Math.min(queries.length, 4)} query pattern(s); found ${findings.length} public match(es).`,
        cached: usedCache,
        latencyMs: Date.now() - t0,
        rateLimitRemaining: lastRemaining,
        rateLimitReset: lastReset,
      };
    } catch (err) {
      const status = err instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const msg = err instanceof Error ? err.message : 'GitHub lookup failed.';
      recordProviderTelemetry({
        providerId: this.id,
        providerName: this.name,
        status,
        error: msg,
        madeRequest: true,
        rateLimitRemaining: lastRemaining,
        rateLimitReset: lastReset,
      });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: this.requiresKey,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status,
        findings,
        message: msg,
        cached: usedCache,
        latencyMs: Date.now() - t0,
        rateLimitRemaining: lastRemaining,
        rateLimitReset: lastReset,
      };
    }
  },
};

export const gravatarProvider: OsintProvider = {
  id: 'gravatar',
  name: 'Gravatar Public Profile API',
  categoryFocus: 'Social Profiles and Images',
  description: 'Checks whether your verified email hash publishes a public Gravatar profile, bio, avatar, or linked accounts.',
  freeTierLimit: 'Permanently free, no API key required',
  requiresKey: false,
  minIntervalMs: 250,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const cleanEmail = ctx.email.trim().toLowerCase();
    const md5 = crypto.createHash('md5').update(cleanEmail).digest('hex');
    const cacheKey = `gravatar:${md5}`;
    const url = `https://en.gravatar.com/${md5}.json`;

    try {
      const cached = getCachedValue<{ found: boolean; entry?: Record<string, unknown> }>(cacheKey);
      let data: { found: boolean; entry?: Record<string, unknown> };
      let usedCache = false;

      if (cached) {
        usedCache = true;
        data = cached.value;
        recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
      } else {
        const { response } = await fetchWithRetry(url, {
          providerId: this.id,
          minIntervalMs: this.minIntervalMs,
        });
        if (response.status === 404) {
          data = { found: false };
        } else if (!response.ok) {
          throw new Error(`Gravatar returned HTTP ${response.status}.`);
        } else {
          const json = (await response.json()) as { entry?: Array<Record<string, unknown>> };
          data = { found: Boolean(json.entry?.[0]), entry: json.entry?.[0] };
        }
        setCachedValue(cacheKey, this.id, data, 600);
        recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
      }

      const findings: NormalizedFinding[] = [];
      if (data.found && data.entry) {
        const displayName = String(data.entry.displayName || data.entry.preferredUsername || 'Gravatar User');
        const profileUrl = String(data.entry.profileUrl || `https://gravatar.com/${md5}`);
        const location = data.entry.currentLocation ? ` Location: ${String(data.entry.currentLocation)}.` : '';
        const accounts = Array.isArray(data.entry.accounts) ? data.entry.accounts.length : 0;
        findings.push({
          title: `Public Gravatar profile linked to ${cleanEmail} ("${displayName}")`,
          category: 'Social Profiles and Images',
          sourceName: this.name,
          sourceUrl: profileUrl,
          foundAt: utcNow(),
          evidence: `Gravatar JSON entry for email MD5 ${md5}: displayName="${displayName}", linked_accounts=${accounts}.${location}`,
          explanation: `Anyone who hashes your email address (${cleanEmail}) can resolve this public Gravatar profile, avatar, and ${accounts} linked account(s).`,
          confidence: 0.96,
          severity: accounts > 0 ? 0.65 : 0.45,
          recencyScore: 0.9,
          risk: accounts > 0 ? 'Medium' : 'Low',
          verificationStatus: 'Unverified',
        });
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: findings.length > 0 ? 'Public Gravatar profile found for verified email.' : 'No public Gravatar profile published for this email.',
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Gravatar check failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'error', error: msg, madeRequest: true });
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

export const stopForumSpamProvider: OsintProvider = {
  id: 'stopforumspam',
  name: 'StopForumSpam Public Abuse API',
  categoryFocus: 'Breached Credentials',
  description: 'Checks whether your email or handle has been reported in public forum spam or credential-abuse feeds.',
  freeTierLimit: '20,000 requests/day free, no API key required',
  requiresKey: false,
  minIntervalMs: 300,
  isConfigured: () => true,
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const params = new URLSearchParams({ json: '' });
    params.set('email', ctx.email.trim().toLowerCase());
    if (ctx.username.trim().length >= 3) {
      params.set('username', ctx.username.trim().replace(/^@/, ''));
    }
    const url = `https://api.stopforumspam.org/api?${params.toString()}`;
    const cacheKey = `sfs:${params.toString()}`;

    try {
      const cached = getCachedValue<Record<string, unknown>>(cacheKey);
      let payload: Record<string, unknown>;
      let usedCache = false;

      if (cached) {
        usedCache = true;
        payload = cached.value;
        recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', cacheHit: true });
      } else {
        const { response } = await fetchWithRetry(url, {
          providerId: this.id,
          minIntervalMs: this.minIntervalMs,
        });
        if (!response.ok) throw new Error(`StopForumSpam returned HTTP ${response.status}.`);
        payload = (await response.json()) as Record<string, unknown>;
        setCachedValue(cacheKey, this.id, payload, 900);
        recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
      }

      const findings: NormalizedFinding[] = [];
      const emailObj = payload.email as { appears?: number; frequency?: number; lastseen?: string; confidence?: number } | undefined;
      if (emailObj && Number(emailObj.appears) > 0) {
        findings.push({
          title: `Email "${ctx.email}" flagged in StopForumSpam public abuse reports`,
          category: 'Possible Impersonation',
          sourceName: this.name,
          sourceUrl: `https://www.stopforumspam.com/search?q=${encodeURIComponent(ctx.email)}`,
          foundAt: utcNow(),
          evidence: `StopForumSpam email check: appears=${emailObj.appears}, frequency=${emailObj.frequency ?? 0}, confidence=${emailObj.confidence ?? 0}%, lastseen=${emailObj.lastseen || 'unknown'}.`,
          explanation: `Your verified email appeared ${emailObj.frequency ?? 1} time(s) in public abuse/spam reporting logs. This can indicate third-party email spoofing or credential stuffing attempts.`,
          confidence: Math.min(0.95, Math.max(0.55, Number(emailObj.confidence ?? 60) / 100)),
          severity: 0.75,
          recencyScore: 0.85,
          risk: 'Medium',
          verificationStatus: 'Unverified',
        });
      }

      const userObj = payload.username as { appears?: number; frequency?: number; lastseen?: string; confidence?: number } | undefined;
      if (userObj && Number(userObj.appears) > 0 && ctx.username.trim()) {
        findings.push({
          title: `Handle "${ctx.username.trim()}" appears in StopForumSpam public reports`,
          category: 'Possible Impersonation',
          sourceName: this.name,
          sourceUrl: `https://www.stopforumspam.com/search?q=${encodeURIComponent(ctx.username.trim().replace(/^@/, ''))}`,
          foundAt: utcNow(),
          evidence: `StopForumSpam username check: appears=${userObj.appears}, frequency=${userObj.frequency ?? 0}, confidence=${userObj.confidence ?? 0}%, lastseen=${userObj.lastseen || 'unknown'}.`,
          explanation: `Your monitored handle matches ${userObj.frequency ?? 1} public spam-abuse report(s). Note that common usernames can collide with unrelated users.`,
          confidence: 0.45,
          severity: 0.35,
          recencyScore: 0.7,
          risk: 'Low',
          verificationStatus: 'Unverified',
        });
      }

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: false,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: findings.length > 0 ? `Found ${findings.length} public abuse listing(s).` : 'No reports found in StopForumSpam public logs.',
        cached: usedCache,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'StopForumSpam check failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'error', error: msg, madeRequest: true });
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

export const hibpEmailProvider: OsintProvider = {
  id: 'hibp_email',
  name: 'Have I Been Pwned Breached Account v3',
  categoryFocus: 'Breached Credentials',
  description: 'Checks whether your verified email appears in known public data breaches (requires paid HIBP API v3 subscription key).',
  freeTierLimit: 'Paid HIBP v3 subscription required (Pwned Passwords range check remains permanently free)',
  requiresKey: true,
  keyEnvVar: 'HIBP_API_KEY',
  minIntervalMs: 1600,
  isConfigured: () => Boolean(process.env.HIBP_API_KEY?.trim()),
  async run(ctx: ScanContext): Promise<ProviderResult> {
    const t0 = Date.now();
    const key = process.env.HIBP_API_KEY?.trim();
    if (!key) {
      recordProviderTelemetry({
        providerId: this.id,
        providerName: this.name,
        status: 'unavailable',
        error: 'HIBP_API_KEY not configured (requires paid HIBP subscription).',
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
          'HIBP_API_KEY not configured (Have I Been Pwned email breach lookup requires a paid v3 key). Email breach coverage is incomplete; use the free Pwned Passwords checker below for password checks.',
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }

    const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(ctx.email)}?truncateResponse=false`;
    try {
      const { response, rateLimitRemaining, rateLimitReset } = await fetchWithRetry(url, {
        providerId: this.id,
        minIntervalMs: this.minIntervalMs,
        headers: {
          'hibp-api-key': key,
          Accept: 'application/json',
        },
      });
      if (response.status === 404) {
        recordProviderTelemetry({ providerId: this.id, providerName: this.name, status: 'ok', madeRequest: true });
        return {
          providerId: this.id,
          providerName: this.name,
          categoryFocus: this.categoryFocus,
          requiresKey: true,
          keyEnvVar: this.keyEnvVar,
          freeTierLimit: this.freeTierLimit,
          status: 'ok',
          findings: [],
          message: 'Verified email not found in HIBP breach records.',
          cached: false,
          latencyMs: Date.now() - t0,
        };
      }
      if (!response.ok) {
        throw new Error(`HIBP v3 returned HTTP ${response.status}.`);
      }
      const breaches = (await response.json()) as Array<{
        Name?: string;
        Domain?: string;
        BreachDate?: string;
        DataClasses?: string[];
      }>;
      const now = utcNow();
      const findings: NormalizedFinding[] = breaches
        .filter((b) => b && b.Name)
        .map((b) => ({
          title: `Verified email exposed in "${b.Name}" data breach`,
          category: 'Breached Credentials',
          sourceName: this.name,
          sourceUrl: 'https://haveibeenpwned.com/',
          foundAt: now,
          evidence: `Breach="${b.Name}", Domain=${b.Domain || 'n/a'}, BreachDate=${b.BreachDate || 'n/a'}, DataClasses=${(b.DataClasses || []).join(', ')}`,
          explanation: `Have I Been Pwned reports your verified email in the ${b.Name} breach. Rotate passwords and enable MFA immediately.`,
          confidence: 0.96,
          severity: 1.0,
          recencyScore: 0.9,
          risk: 'High',
          verificationStatus: 'Unverified',
        }));

      recordProviderTelemetry({
        providerId: this.id,
        providerName: this.name,
        status: 'ok',
        madeRequest: true,
        rateLimitRemaining,
        rateLimitReset,
      });

      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: true,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status: 'ok',
        findings,
        message: `Checked HIBP v3; found ${findings.length} breach record(s).`,
        cached: false,
        latencyMs: Date.now() - t0,
        rateLimitRemaining,
        rateLimitReset,
      };
    } catch (err) {
      const status = err instanceof ProviderRateLimitError ? 'rate_limited' : 'error';
      const msg = err instanceof Error ? err.message : 'HIBP v3 request failed.';
      recordProviderTelemetry({ providerId: this.id, providerName: this.name, status, error: msg, madeRequest: true });
      return {
        providerId: this.id,
        providerName: this.name,
        categoryFocus: this.categoryFocus,
        requiresKey: true,
        keyEnvVar: this.keyEnvVar,
        freeTierLimit: this.freeTierLimit,
        status,
        findings: [],
        message: msg,
        cached: false,
        latencyMs: Date.now() - t0,
      };
    }
  },
};
