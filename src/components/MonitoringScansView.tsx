import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  FolderPlus,
  History,
  KeyRound,
  Lock,
  RefreshCw,
  Search,
  Sparkles,
} from 'lucide-react';
import { getFindingPresentation, formatFindingPriority, formatFindingRisk } from '../utils/findingPresentation.ts';
import { apiRequest } from '../lib/api.ts';
import type {
  Finding,
  FindingReviewEvent,
  ProviderCatalogItem,
  ResponseGuide,
  ScanRecord,
  SchedulerStatus,
  UserState,
} from '../lib/types.ts';

interface MonitoringScansViewProps {
  user: UserState;
  onRefreshDashboard: () => void;
  onCreateCaseFromFinding: (prefill: {
    title: string;
    category: string;
    description: string;
    url: string;
  }) => void;
}

interface AiFindingAssessment {
  suggestedCategory: string;
  suggestedRisk: string;
  plainExplanation: string;
  recommendedActions: string[];
  takedownDraft: string;
}

export const MonitoringScansView: React.FC<MonitoringScansViewProps> = ({
  user,
  onRefreshDashboard,
  onCreateCaseFromFinding,
}) => {
  const [monitor, setMonitor] = useState({
    full_name: user.name,
    username: '',
    terms: '',
    domains: '',
    frequency: 'weekly',
    enabled: 1,
    authorization_confirmed: 0,
    authorization_at: null as string | null,
  });
  const [providers, setProviders] = useState<ProviderCatalogItem[]>([]);
  const [scheduler, setScheduler] = useState<SchedulerStatus | null>(null);
  const [savingMonitor, setSavingMonitor] = useState(false);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [reviewHistory, setReviewHistory] = useState<FindingReviewEvent[]>([]);
  const [counts, setCounts] = useState<{ unverified: number; verifiedMatch: number; safeLibrary: number }>({
    unverified: 0,
    verifiedMatch: 0,
    safeLibrary: 0,
  });
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [guides, setGuides] = useState<Record<string, ResponseGuide>>({});

  const [scanning, setScanning] = useState(false);
  const [scanAuthorized, setScanAuthorized] = useState(false);

  // HIBP Pwned Passwords (free k-anonymity range check)
  const [pwInput, setPwInput] = useState('');
  const [pwLabel, setPwLabel] = useState('Primary Account Password');
  const [pwRecordFinding, setPwRecordFinding] = useState(true);
  const [pwChecking, setPwChecking] = useState(false);
  const [pwResult, setPwResult] = useState<{
    compromised: boolean;
    pwnedCount: number;
    sha1Prefix: string;
    checkedAt: string;
    sourceName: string;
    sourceUrl: string;
    recordedFindingId: number | null;
  } | null>(null);

  const [statusTab, setStatusTab] = useState<'Unverified' | 'Verified Match' | 'False Positive' | 'All'>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [riskFilter, setRiskFilter] = useState('All');
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [bulkNote, setBulkNote] = useState('');
  const [noteDrafts, setNoteDrafts] = useState<Record<number, string>>({});
  const [expandedHistoryId, setExpandedHistoryId] = useState<number | null>(null);

  const [assessingId, setAssessingId] = useState<number | null>(null);
  const [expandedAdviceId, setExpandedAdviceId] = useState<number | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadAll = async () => {
    try {
      const [mRes, fRes] = await Promise.all([
        apiRequest<{
          monitor: typeof monitor;
          providers: ProviderCatalogItem[];
          scheduler?: SchedulerStatus;
        }>('/api/monitoring'),
        apiRequest<{
          findings: Finding[];
          reviewHistory?: FindingReviewEvent[];
          counts?: { unverified: number; verifiedMatch: number; safeLibrary: number };
          scans: ScanRecord[];
          categories: string[];
          guides: Record<string, ResponseGuide>;
        }>('/api/findings'),
      ]);
      setMonitor(mRes.monitor);
      setScanAuthorized(Boolean(mRes.monitor.authorization_confirmed));
      setProviders(mRes.providers ?? []);
      setScheduler(mRes.scheduler ?? null);
      setFindings(fRes.findings);
      setReviewHistory(fRes.reviewHistory ?? []);
      if (fRes.counts) setCounts(fRes.counts);
      setScans(fRes.scans);
      setCategories(fRes.categories);
      setGuides(fRes.guides);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load monitoring data.');
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleSaveMonitor = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setStatusMsg(null);
    setSavingMonitor(true);
    try {
      await apiRequest('/api/monitoring', {
        method: 'PUT',
        body: JSON.stringify({
          ...monitor,
          authorization_confirmed: scanAuthorized ? 1 : 0,
        }),
      });
      setStatusMsg('Monitoring identifiers, authorized domains, and schedule saved.');
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save monitoring configuration.');
    } finally {
      setSavingMonitor(false);
    }
  };

  const handleRunRealScan = async () => {
    setError(null);
    setStatusMsg(null);
    setScanning(true);
    try {
      const res = await apiRequest<{
        ok: boolean;
        newFindings: number;
        totalReturned: number;
        okProviders: number;
        skippedCount: number;
        incompleteCoverage: boolean;
        failedOrUnavailableProviders: string[];
        providers: ProviderCatalogItem[];
      }>('/api/scan', {
        method: 'POST',
        body: JSON.stringify({ authorized: scanAuthorized }),
      });
      setProviders(res.providers ?? []);
      if (res.incompleteCoverage) {
        setStatusMsg(
          `Real OSINT scan completed across ${res.okProviders} active provider(s) (${res.skippedCount} skipped): ${res.newFindings} new unique match(es) stored (${res.totalReturned} inspected). Coverage incomplete — unavailable/failed: ${res.failedOrUnavailableProviders.join(', ')}.`
        );
      } else {
        setStatusMsg(
          `Real OSINT scan finished across ${res.okProviders} active provider(s)${
            res.skippedCount > 0 ? ` (${res.skippedCount} skipped for missing identifiers)` : ''
          }: ${res.newFindings} new match(es) stored (${res.totalReturned} inspected).`
        );
      }
      await loadAll();
      onRefreshDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'OSINT scan failed.');
      await loadAll();
    } finally {
      setScanning(false);
    }
  };

  const handlePasswordCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setPwResult(null);
    setPwChecking(true);
    try {
      const res = await apiRequest<NonNullable<typeof pwResult>>('/api/security/check-password', {
        method: 'POST',
        body: JSON.stringify({
          password: pwInput,
          label: pwLabel,
          recordFinding: pwRecordFinding,
        }),
      });
      setPwInput('');
      setPwResult(res);
      if (res.recordedFindingId) {
        await loadAll();
        onRefreshDashboard();
      } else {
        const statusRes = await apiRequest<{ providers: ProviderCatalogItem[] }>('/api/providers/status');
        setProviders(statusRes.providers);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Password breach check failed.');
    } finally {
      setPwChecking(false);
    }
  };

  const handleSetVerification = async (
    f: Finding,
    status: 'Unverified' | 'Verified Match' | 'False Positive',
    explicitNote?: string
  ) => {
    try {
      const note = explicitNote !== undefined ? explicitNote : noteDrafts[f.id] ?? f.review_note ?? '';
      await apiRequest(`/api/findings/${f.id}/verify`, {
        method: 'POST',
        body: JSON.stringify({ verification_status: status, note }),
      });
      await loadAll();
      onRefreshDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update verification status.');
    }
  };

  const handleBulkVerify = async (status: 'Unverified' | 'Verified Match' | 'False Positive') => {
    if (selectedIds.length === 0) return;
    setError(null);
    setStatusMsg(null);
    try {
      const res = await apiRequest<{ ok: boolean; updatedCount: number }>('/api/findings/bulk-verify', {
        method: 'POST',
        body: JSON.stringify({
          findingIds: selectedIds,
          verification_status: status,
          note: bulkNote.trim(),
        }),
      });
      setSelectedIds([]);
      setBulkNote('');
      setStatusMsg(`Updated ${res.updatedCount} finding(s) to "${status}".`);
      await loadAll();
      onRefreshDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk verification update failed.');
    }
  };

  const toggleSelectFinding = (id: number) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const handleAiAssess = async (f: Finding) => {
    setError(null);
    setAssessingId(f.id);
    try {
      const res = await apiRequest<{ assessment: AiFindingAssessment }>(
        `/api/findings/${f.id}/ai-assess`,
        { method: 'POST' }
      );
      setFindings((prev) =>
        prev.map((row) =>
          row.id === f.id ? { ...row, ai_advice: JSON.stringify(res.assessment) } : row
        )
      );
      setExpandedAdviceId(f.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI risk assessment failed.');
    } finally {
      setAssessingId(null);
    }
  };

  const handleExportCsv = async () => {
    const blob = await apiRequest<Blob>('/api/report.csv');
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'privacy_exposure_report.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportPdf = async () => {
    const blob = await apiRequest<Blob>('/api/report.pdf');
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'privacy_monitor_report.pdf';
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const status = f.verification_status || (f.user_verified ? 'Verified Match' : 'Unverified');
      if (statusTab !== 'All' && status !== statusTab) return false;
      if (categoryFilter !== 'All' && f.category !== categoryFilter) return false;
      if (riskFilter !== 'All' && formatFindingRisk(f.risk, status) !== riskFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        return (
          f.title.toLowerCase().includes(q) ||
          f.source.toLowerCase().includes(q) ||
          (f.source_name || '').toLowerCase().includes(q) ||
          (f.evidence || '').toLowerCase().includes(q) ||
          f.explanation.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findings, statusTab, categoryFilter, riskFilter, searchQuery]);

  const parseAdvice = (raw: string): AiFindingAssessment | null => {
    if (!raw) return null;
    try {
      return JSON.parse(raw) as AiFindingAssessment;
    } catch {
      return null;
    }
  };

  const latestScan = scans[0];
  const latestUnavailable =
    latestScan?.providerSummary?.filter(
      (p) => p.status === 'unavailable' || p.status === 'error' || p.status === 'rate_limited'
    ) ?? [];
  const latestSkipped =
    latestScan?.providerSummary?.filter((p) => p.status === 'skipped') ?? [];

  const freeActiveCount = providers.filter((p) => !p.isPaidTier && p.configured).length;

  return (
    <div className="space-y-6">
      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 px-4 py-3 text-sm text-red-800 dark:text-red-200"
        >
          {error}
        </div>
      )}
      {statusMsg && (
        <div className="rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/30 px-4 py-3 text-sm text-emerald-800 dark:text-emerald-200">
          {statusMsg}
        </div>
      )}

      {(latestUnavailable.length > 0 || latestSkipped.length > 0) && (
        <div
          role="status"
          className="rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50/70 dark:bg-amber-950/30 px-5 py-4 text-xs text-amber-900 dark:text-amber-200 space-y-2"
        >
          <div className="flex items-center gap-2 font-semibold text-sm">
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
            <span>
              {latestUnavailable.length > 0
                ? 'Incomplete Scan Coverage Warning'
                : `${latestSkipped.length} Provider Check(s) Skipped on Latest Scan`}
            </span>
          </div>
          {latestUnavailable.length > 0 && (
            <div className="space-y-1">
              <p>
                Unavailable or errored providers are never reported as clean matches:
              </p>
              <ul className="list-disc pl-5 space-y-0.5 font-mono">
                {latestUnavailable.map((p) => (
                  <li key={p.providerId}>
                    {p.providerName} [{p.status}]: {p.message}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {latestSkipped.length > 0 && (
            <div className="space-y-1">
              <p>
                Skipped providers (add a handle, domain, or stack keyword above to include them):
              </p>
              <ul className="list-disc pl-5 space-y-0.5 font-mono">
                {latestSkipped.map((p) => (
                  <li key={p.providerId}>
                    {p.providerName} [skipped]: {p.message}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Monitoring Profile Configuration + Real OSINT Launcher */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Authorized Personal Identifiers &amp; Domains
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            All queries execute exclusively from the server for account{' '}
            <span className="font-mono">{user.email}</span>.
          </p>

          <form onSubmit={handleSaveMonitor} className="mt-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={monitor.full_name}
                  onChange={(e) => setMonitor((m) => ({ ...m, full_name: e.target.value }))}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1">Primary Username / Handle</label>
                <input
                  type="text"
                  value={monitor.username}
                  onChange={(e) => setMonitor((m) => ({ ...m, username: e.target.value }))}
                  placeholder="@handle"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium mb-1">
                  Owned Domains (comma-separated, for crt.sh, RDAP, SPF/DMARC)
                </label>
                <input
                  type="text"
                  value={monitor.domains}
                  onChange={(e) => setMonitor((m) => ({ ...m, domains: e.target.value }))}
                  placeholder="example.org, portfolio.dev"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1">
                  Stack / Additional Keywords (for NVD CVE, CISA KEV, GitHub repos)
                </label>
                <input
                  type="text"
                  value={monitor.terms}
                  onChange={(e) => setMonitor((m) => ({ ...m, terms: e.target.value }))}
                  placeholder="openssl, wordpress, company-name"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4 pt-1">
              <div className="flex items-center gap-4">
                <div>
                  <label className="block text-xs font-medium mb-1">Cadence</label>
                  <select
                    value={monitor.frequency}
                    onChange={(e) => setMonitor((m) => ({ ...m, frequency: e.target.value }))}
                    className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-1.5 text-xs"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
                <label className="flex items-center gap-2 text-xs font-medium mt-4 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={Boolean(monitor.enabled)}
                    onChange={(e) => setMonitor((m) => ({ ...m, enabled: e.target.checked ? 1 : 0 }))}
                    className="rounded border-slate-300"
                  />
                  <span>Monitoring enabled</span>
                </label>
              </div>
              <button
                type="submit"
                disabled={savingMonitor}
                className="px-4 py-2 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white text-xs font-medium disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {savingMonitor ? 'Saving...' : 'Save Profile'}
              </button>
            </div>
          </form>
        </section>

        <section className="lg:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between space-y-5">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Run Real-World OSINT Scan
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
              Queries {freeActiveCount} active free OSINT feeds (GitHub, Gravatar, StopForumSpam, crt.sh, IANA RDAP + DNS DoH, NVD CVE, CISA KEV, Hacker News, Wikipedia) plus any configured optional keys. Zero fabricated results.
            </p>
            <div className="mt-4 space-y-2 text-xs border-t border-slate-100 dark:border-slate-800 pt-3">
              <div className="flex justify-between">
                <span className="text-slate-500">Identity Gate</span>
                <span
                  className={
                    user.liveScanReady
                      ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                      : 'text-amber-600 dark:text-amber-400 font-medium'
                  }
                >
                  {user.liveScanReady ? 'Ready (Email + Selfie Approved)' : 'Locked (Verify Identity)'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Free Active Providers</span>
                <span className="font-mono">{freeActiveCount} ready</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Authorization Status</span>
                <span className="font-mono">
                  {scanAuthorized ? 'Authorized' : 'Confirmation required'}
                </span>
              </div>
              {scheduler && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Scheduled Cadence</span>
                  <span className="font-mono">
                    {monitor.enabled && scanAuthorized
                      ? scheduler.nextDueAt
                        ? `Due ${scheduler.nextDueAt.slice(0, 16).replace('T', ' ')} UTC`
                        : 'Armed'
                      : 'Paused / awaiting authorization'}
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="space-y-3">
            <label className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3">
              <input
                type="checkbox"
                checked={scanAuthorized}
                onChange={(e) => setScanAuthorized(e.target.checked)}
                className="mt-0.5 rounded border-slate-300"
              />
              <span>
                I explicitly authorize Privacy Monitor to query external OSINT APIs strictly for my own identifiers and authorized domains above.
              </span>
            </label>

            <button
              type="button"
              disabled={scanning || !user.liveScanReady || !scanAuthorized}
              onClick={handleRunRealScan}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white py-2.5 px-4 text-xs font-medium disabled:opacity-45 whitespace-nowrap cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
              {scanning ? 'Querying External APIs...' : 'Run Real OSINT Scan'}
            </button>
          </div>
        </section>
      </div>

      {/* Free Password Breach Checker (HIBP Pwned Passwords k-Anonymity) */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-[#15395A] dark:text-sky-400" />
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Pwned Passwords Breach Check (Free k-Anonymity API)
              </h2>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Uses the permanently free Have I Been Pwned Pwned Passwords Range API with local SHA-1 prefix k-anonymity. Only the first 5 SHA-1 hex characters are ever sent; passwords are never stored or logged.
            </p>
          </div>
          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-700 dark:text-emerald-400">
            <Lock className="w-3 h-3" />
            k-Anonymity Range Protected
          </span>
        </div>

        <form onSubmit={handlePasswordCheck} className="mt-4 grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-4">
            <label className="block text-xs font-medium mb-1">Password Label (for your record)</label>
            <input
              type="text"
              value={pwLabel}
              onChange={(e) => setPwLabel(e.target.value)}
              placeholder="e.g. Personal Email Password"
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs"
            />
          </div>
          <div className="md:col-span-4">
            <label className="block text-xs font-medium mb-1">Password to Check</label>
            <input
              type="password"
              required
              value={pwInput}
              onChange={(e) => setPwInput(e.target.value)}
              placeholder="Enter password to verify safely"
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs font-mono"
            />
          </div>
          <div className="md:col-span-4 flex flex-wrap items-center justify-between gap-3">
            <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={pwRecordFinding}
                onChange={(e) => setPwRecordFinding(e.target.checked)}
                className="rounded border-slate-300"
              />
              <span>Save match to Findings</span>
            </label>
            <button
              type="submit"
              disabled={pwChecking || !pwInput}
              className="px-4 py-2 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white text-xs font-medium disabled:opacity-50 whitespace-nowrap cursor-pointer"
            >
              {pwChecking ? 'Checking Range...' : 'Check Breach Exposure'}
            </button>
          </div>
        </form>

        {pwResult && (
          <div
            className={`mt-4 rounded-lg border px-4 py-3 text-xs space-y-1 ${
              pwResult.compromised
                ? 'border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-red-900 dark:text-red-200'
                : 'border-emerald-300 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-900 dark:text-emerald-200'
            }`}
          >
            <div className="font-semibold">
              {pwResult.compromised
                ? `Compromised: SHA-1 prefix ${pwResult.sha1Prefix} matched ${pwResult.pwnedCount.toLocaleString()} breach appearance(s).`
                : `Not found in Pwned Passwords range (${pwResult.sha1Prefix}).`}
            </div>
            <div className="text-[11px] opacity-90">
              Source: {pwResult.sourceName} · Retrieved: {pwResult.checkedAt}
              {pwResult.recordedFindingId ? ' · Saved to Findings.' : ''}
            </div>
          </div>
        )}
      </section>

      {/* Findings Queue, Safe Library & Controls */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Finding Review Queue &amp; Safe Library ({filteredFindings.length})
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Triage discovered records with explicit source URLs, timestamps, audit notes, and persistent false-positive suppression.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleExportCsv}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              Export CSV Report
            </button>
            <button
              type="button"
              onClick={handleExportPdf}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              Download PDF Report
            </button>
          </div>
        </div>

        {/* Review Queue / Safe Library Segmented Tabs */}
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg w-fit mb-4">
          {(
            [
              { key: 'Unverified', label: 'Review Queue', count: counts.unverified },
              { key: 'Verified Match', label: 'Verified Matches', count: counts.verifiedMatch },
              { key: 'False Positive', label: 'Safe Library', count: counts.safeLibrary },
              { key: 'All', label: 'All Findings', count: findings.length },
            ] as const
          ).map((t) => (
            <button
              key={t.key}
              type="button"
              onClick={() => {
                setStatusTab(t.key);
                setSelectedIds([]);
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer tabular-nums ${
                statusTab === t.key
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              {t.label} ({t.count})
            </button>
          ))}
        </div>

        {statusTab === 'False Positive' && (
          <p className="mb-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 px-4 py-2.5 text-xs text-slate-600 dark:text-slate-300">
            Items marked <strong>False Positive</strong> remain stored in your Safe Library and are automatically suppressed across future manual and scheduled OSINT scans unless restored to the Review Queue.
          </p>
        )}

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by title, source, evidence, or summary..."
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 pl-8 pr-3 py-1.5 text-xs"
            />
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-1.5 text-xs"
          >
            <option value="All">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-1.5 text-xs"
          >
            <option value="All">All Assessment Labels</option>
            <option value="High (heuristic)">High (heuristic)</option>
            <option value="Medium (heuristic)">Medium (heuristic)</option>
            <option value="Low (heuristic)">Low (heuristic)</option>
            <option value="Not assessed">Not assessed</option>
            <option value="Excluded">Excluded</option>
            <option value="Unavailable">Unavailable</option>
          </select>
        </div>

        {/* Bulk Triage Bar */}
        {selectedIds.length > 0 && (
          <div className="mb-4 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950/70 p-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="font-semibold tabular-nums">{selectedIds.length} selected</span>
            <input
              type="text"
              value={bulkNote}
              onChange={(e) => setBulkNote(e.target.value)}
              placeholder="Optional bulk audit note..."
              className="flex-1 min-w-[180px] rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs"
            />
            <button
              type="button"
              onClick={() => handleBulkVerify('Verified Match')}
              className="rounded bg-emerald-700 hover:bg-emerald-800 text-white px-2.5 py-1 font-medium cursor-pointer whitespace-nowrap"
            >
              Verify Selected
            </button>
            <button
              type="button"
              onClick={() => handleBulkVerify('False Positive')}
              className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 font-medium cursor-pointer whitespace-nowrap"
            >
              Move to Safe Library
            </button>
            <button
              type="button"
              onClick={() => handleBulkVerify('Unverified')}
              className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 font-medium cursor-pointer whitespace-nowrap"
            >
              Return to Queue
            </button>
          </div>
        )}

        {filteredFindings.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 dark:border-slate-800 p-8 text-center text-xs text-slate-500">
            No findings match your current filter. Authorize and run a Real OSINT Scan or switch tabs above.
          </div>
        ) : (
          <div className="divide-y divide-slate-200 dark:divide-slate-800">
            {filteredFindings.map((f) => {
              const advice = parseAdvice(f.ai_advice);
              const guide = guides[f.category];
              const isExpanded = expandedAdviceId === f.id;
              const isHistoryOpen = expandedHistoryId === f.id;
              const itemHistory = reviewHistory.filter((ev) => ev.finding_id === f.id);
              const currentVerification =
                f.verification_status || (f.user_verified ? 'Verified Match' : 'Unverified');

              return (
                <article key={f.id} className="py-4 space-y-2.5">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <input
                          type="checkbox"
                          aria-label={`Select finding ${f.title}`}
                          checked={selectedIds.includes(f.id)}
                          onChange={() => toggleSelectFinding(f.id)}
                          className="rounded border-slate-300"
                        />
                        <span className="font-semibold text-slate-600 dark:text-slate-300">
                          Risk: {formatFindingRisk(f.risk, currentVerification)}
                        </span>
                        <span aria-hidden="true" className="text-slate-300">
                          ·
                        </span>
                        <span className="font-medium text-slate-700 dark:text-slate-300">
                          {f.category}
                        </span>
                        <span aria-hidden="true" className="text-slate-300">
                          ·
                        </span>
                        <span className="font-mono tabular-nums text-slate-500">
                          Priority: {formatFindingPriority(f.priority, currentVerification)}
                        </span>
                        <span aria-hidden="true" className="text-slate-300">
                          ·
                        </span>
                        <span
                          className={`font-medium ${
                            currentVerification === 'Verified Match'
                              ? 'text-emerald-700 dark:text-emerald-400'
                              : currentVerification === 'False Positive'
                              ? 'text-slate-400 line-through'
                              : 'text-amber-600 dark:text-amber-400'
                          }`}
                        >
                          {getFindingPresentation(currentVerification).label}
                        </span>
                      </div>

                      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {f.title}
                      </h3>
                      <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                        {f.explanation}
                      </p>

                      {f.evidence && (
                        <div className="rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 px-3 py-2 text-[11px] font-mono text-slate-600 dark:text-slate-300 break-words">
                          <span className="font-semibold text-slate-800 dark:text-slate-200">
                            Evidence:{' '}
                          </span>
                          {f.evidence}
                        </div>
                      )}

                      <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500 pt-0.5">
                        <span className="font-medium text-slate-700 dark:text-slate-300">
                          Source: {f.source_name || 'External OSINT'}
                        </span>
                        <span aria-hidden="true">·</span>
                        {f.source.startsWith('http') ? (
                          <a
                            href={f.source}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-[#15395A] dark:text-sky-400 hover:underline font-mono truncate max-w-md"
                          >
                            {f.source}
                            <ExternalLink className="w-3 h-3 shrink-0" />
                          </a>
                        ) : (
                          <span className="font-mono">{f.source}</span>
                        )}
                        <span aria-hidden="true">·</span>
                        <span className="font-mono tabular-nums">
                          Retrieved {f.found_at.replace('T', ' ').replace('Z', ' UTC')}
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <select
                        aria-label="Verification status"
                        value={currentVerification}
                        onChange={(e) =>
                          handleSetVerification(
                            f,
                            e.target.value as 'Unverified' | 'Verified Match' | 'False Positive'
                          )
                        }
                        className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-medium cursor-pointer"
                      >
                        <option value="Unverified">Unverified</option>
                        <option value="Verified Match">Verified Match</option>
                        <option value="False Positive">False Positive</option>
                      </select>

                      <button
                        type="button"
                        disabled={assessingId === f.id}
                        onClick={() =>
                          advice && !isExpanded ? setExpandedAdviceId(f.id) : handleAiAssess(f)
                        }
                        className="inline-flex items-center gap-1.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white px-2.5 py-1.5 text-xs font-medium disabled:opacity-50 whitespace-nowrap cursor-pointer"
                      >
                        <Sparkles className="w-3.5 h-3.5" />
                        {assessingId === f.id
                          ? 'Assessing...'
                          : advice
                          ? isExpanded
                            ? 'Re-run AI Advice'
                            : 'View AI Advice'
                          : 'AI Risk Assessment'}
                      </button>

                      <button
                        type="button"
                        onClick={() =>
                          onCreateCaseFromFinding({
                            title: f.title.slice(0, 140),
                            category: f.category,
                            description: `${f.explanation}\n\nSource: ${f.source_name || 'OSINT'} (${f.found_at})\nEvidence: ${f.evidence || 'See source URL'}\nStatus: ${getFindingPresentation(currentVerification).label} | Risk: ${formatFindingRisk(f.risk, currentVerification)} | Priority: ${formatFindingPriority(f.priority, currentVerification)}`,
                            url: f.source.startsWith('http') ? f.source : '',
                          })
                        }
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 px-2.5 py-1.5 text-xs font-medium whitespace-nowrap cursor-pointer"
                      >
                        <FolderPlus className="w-3.5 h-3.5" />
                        Promote to Case
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedHistoryId((cur) => (cur === f.id ? null : f.id))
                        }
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 px-2.5 py-1.5 text-xs font-medium whitespace-nowrap cursor-pointer tabular-nums"
                      >
                        <History className="w-3.5 h-3.5" />
                        History ({itemHistory.length})
                      </button>
                    </div>
                  </div>

                  {/* Per-finding Review Note & Review Audit Trail */}
                  <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                    <input
                      type="text"
                      value={noteDrafts[f.id] ?? f.review_note ?? ''}
                      onChange={(e) =>
                        setNoteDrafts((prev) => ({ ...prev, [f.id]: e.target.value }))
                      }
                      placeholder="Add triage note (e.g. Confirmed owned domain / not me)..."
                      className="flex-1 min-w-[220px] rounded border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-2.5 py-1 text-xs"
                    />
                    <button
                      type="button"
                      onClick={() =>
                        handleSetVerification(
                          f,
                          currentVerification,
                          noteDrafts[f.id] ?? f.review_note ?? ''
                        )
                      }
                      className="rounded border border-slate-200 dark:border-slate-700 px-2.5 py-1 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer whitespace-nowrap"
                    >
                      Save Note
                    </button>
                    {f.reviewed_at && (
                      <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                        Last reviewed {f.reviewed_at.slice(0, 16).replace('T', ' ')}
                      </span>
                    )}
                  </div>

                  {isHistoryOpen && (
                    <div className="mt-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3 space-y-1.5 text-xs">
                      <div className="font-semibold text-slate-800 dark:text-slate-200">
                        Verification Audit History
                      </div>
                      {itemHistory.length === 0 ? (
                        <p className="text-slate-500">
                          No status changes recorded yet for this finding.
                        </p>
                      ) : (
                        <ul className="divide-y divide-slate-200/70 dark:divide-slate-800">
                          {itemHistory.map((ev) => (
                            <li key={ev.id} className="py-1.5 flex flex-wrap justify-between gap-2">
                              <span>
                                <span className="font-medium">{ev.previous_status}</span> →{' '}
                                <span className="font-semibold">{ev.new_status}</span>
                                {ev.note ? ` · ${ev.note}` : ''}
                              </span>
                              <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                                {ev.reviewed_at.slice(0, 19).replace('T', ' ')}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}

                  {advice && isExpanded && (
                    <div className="mt-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-4 space-y-2.5 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          Gemini Risk Analysis · {advice.suggestedCategory} ({advice.suggestedRisk})
                        </span>
                        <button
                          type="button"
                          onClick={() => setExpandedAdviceId(null)}
                          className="text-slate-500 hover:text-slate-900 dark:hover:text-white cursor-pointer"
                        >
                          Hide
                        </button>
                      </div>
                      <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                        {advice.plainExplanation}
                      </p>
                      {Array.isArray(advice.recommendedActions) && advice.recommendedActions.length > 0 && (
                        <div>
                          <span className="font-semibold text-slate-800 dark:text-slate-200">
                            Practical Action Steps:
                          </span>
                          <ul className="list-disc pl-4 mt-1 space-y-1 text-slate-600 dark:text-slate-400">
                            {advice.recommendedActions.map((step, idx) => (
                              <li key={idx}>{step}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {advice.takedownDraft && (
                        <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
                          <span className="font-semibold">Suggested Outreach Note:</span>
                          <p className="mt-1 text-slate-600 dark:text-slate-300 whitespace-pre-wrap">
                            {advice.takedownDraft}
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  {guide && (
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      Response playbook: {guide.summary} (
                      <a
                        href={guide.resourceUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="underline hover:text-slate-800 dark:hover:text-slate-200"
                      >
                        {guide.resourceLabel}
                      </a>
                      )
                    </p>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>

      {/* Modular OSINT Provider Status & Quota Telemetry */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#15395A] dark:text-sky-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Modular OSINT Providers &amp; API Quota Monitor
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Rate-limited, cached external integrations. Missing paid keys or unavailable providers are always shown honestly.
              </p>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Provider</th>
                <th className="py-2 pr-4 font-medium">Tier / Key Status</th>
                <th className="py-2 pr-4 font-medium">Rate / Free Limit</th>
                <th className="py-2 pr-4 font-medium">Requests / Cache</th>
                <th className="py-2 font-medium">Latest Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {providers.map((p) => (
                <tr key={p.id}>
                  <td className="py-2.5 pr-4">
                    <div className="font-medium text-slate-900 dark:text-slate-100">{p.name}</div>
                    <div className="text-[11px] text-slate-500">{p.categoryFocus}</div>
                  </td>
                  <td className="py-2.5 pr-4 whitespace-nowrap">
                    {!p.requiresKey ? (
                      <span className="text-emerald-700 dark:text-emerald-400 font-medium">
                        Free · No key required
                      </span>
                    ) : p.configured ? (
                      <span className="text-emerald-700 dark:text-emerald-400 font-medium">
                        Configured ({p.keyEnvVar})
                      </span>
                    ) : p.isPaidTier ? (
                      <span className="text-amber-600 dark:text-amber-400 font-medium">
                        Paid key unset ({p.keyEnvVar})
                      </span>
                    ) : (
                      <span className="text-amber-600 dark:text-amber-400 font-medium">
                        Free key unset ({p.keyEnvVar})
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4 text-slate-600 dark:text-slate-400 max-w-xs">
                    {p.freeTierLimit}
                    {p.rateLimitRemaining && (
                      <span className="block font-mono text-[11px] text-slate-500">
                        Remaining header: {p.rateLimitRemaining}
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4 font-mono tabular-nums text-slate-600 dark:text-slate-300 whitespace-nowrap">
                    {p.requestsToday} today / {p.cacheHits} cached
                  </td>
                  <td className="py-2.5">
                    <div className="flex items-center gap-1.5">
                      {p.lastStatus === 'ok' || p.lastStatus === 'ready' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      )}
                      <span className="font-mono capitalize">{p.lastStatus}</span>
                    </div>
                    {p.lastError && (
                      <p className="text-[11px] text-slate-500 max-w-xs truncate" title={p.lastError}>
                        {p.lastError}
                      </p>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Scan History Log */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-4">
          Recent Scan History
        </h2>
        {scans.length === 0 ? (
          <p className="text-xs text-slate-500">No scan executions logged yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                <tr>
                  <th className="py-2 pr-4 font-medium">ID</th>
                  <th className="py-2 pr-4 font-medium">Type</th>
                  <th className="py-2 pr-4 font-medium">New Findings</th>
                  <th className="py-2 pr-4 font-medium">Coverage Status</th>
                  <th className="py-2 font-medium">Authorized / Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td className="py-2.5 pr-4 font-mono tabular-nums">#{s.id}</td>
                    <td className="py-2.5 pr-4 font-medium capitalize">{s.mode.replace('_', ' ')}</td>
                    <td className="py-2.5 pr-4 font-mono tabular-nums">{s.findings_count}</td>
                    <td className="py-2.5 pr-4 text-slate-600 dark:text-slate-300">{s.status}</td>
                    <td className="py-2.5 font-mono tabular-nums text-slate-500">
                      {s.created_at.slice(0, 19).replace('T', ' ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
