import React, { useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Download,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { apiRequest } from '../lib/api.ts';
import type { DashboardData, PriorityWeights } from '../lib/types.ts';

interface DashboardViewProps {
  data: DashboardData;
  onRefresh: () => void;
  onNavigate: (tab: string) => void;
  onRunScan: () => Promise<void>;
  scanning: boolean;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  data,
  onRefresh,
  onNavigate,
  onRunScan,
  scanning,
}) => {
  const [weights, setWeights] = useState<PriorityWeights>(data.priorityWeights);
  const [savingWeights, setSavingWeights] = useState(false);
  const [weightMessage, setWeightMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [aiOverview, setAiOverview] = useState<{
    executiveSummary: string;
    keyInferenceRisks: string[];
    priorityNextSteps: string[];
    advisoryDisclaimer: string;
  } | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const weightSum =
    weights.confidence_weight + weights.severity_weight + weights.recency_weight;

  const handleSaveWeights = async () => {
    setWeightMessage(null);
    setSavingWeights(true);
    try {
      const res = await apiRequest<{ weights: PriorityWeights; recalculated: number }>(
        '/api/priority-weights',
        {
          method: 'PUT',
          body: JSON.stringify(weights),
        }
      );
      setWeights(res.weights);
      setWeightMessage(`Saved weights and recalculated ${res.recalculated} finding(s).`);
      onRefresh();
    } catch (err) {
      setWeightMessage(err instanceof Error ? err.message : 'Failed to save priority weights.');
    } finally {
      setSavingWeights(false);
    }
  };

  const handleGenerateOverview = async () => {
    setAiError(null);
    setAiLoading(true);
    try {
      const res = await apiRequest<{
        overview: {
          executiveSummary: string;
          keyInferenceRisks: string[];
          priorityNextSteps: string[];
          advisoryDisclaimer: string;
        };
      }>('/api/ai/overview', { method: 'POST' });
      setAiOverview(res.overview);
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'AI exposure assessment failed.');
    } finally {
      setAiLoading(false);
    }
  };

  const handleQuickScan = async () => {
    setScanError(null);
    try {
      await onRunScan();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Real OSINT scan could not run.');
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

  const scoreValue = data.exposureScore;
  const scoreTone =
    scoreValue === null
      ? 'Not assessed'
      : scoreValue >= 65
      ? 'Elevated awareness risk'
      : scoreValue >= 35
      ? 'Moderate exposure'
      : 'Lower exposure';

  const incompleteProviders =
    data.lastScan?.providerSummary?.filter(
      (p) => p.status === 'unavailable' || p.status === 'error' || p.status === 'rate_limited'
    ) ?? [];
  const skippedProviders =
    data.lastScan?.providerSummary?.filter((p) => p.status === 'skipped') ?? [];

  return (
    <div className="space-y-8">
      {!data.user.liveScanReady && (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50/70 dark:bg-amber-950/30 px-5 py-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Identity verification required before searching personal identifiers
              </h2>
              <p className="text-sm text-slate-600 dark:text-slate-300 mt-0.5">
                Email: {data.user.emailVerified ? 'Verified' : 'Unverified'} · Selfie Review:{' '}
                {data.user.selfieStatus.replace('_', ' ')}. Complete ownership verification to unlock external OSINT scans.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('identity')}
            className="inline-flex items-center gap-1.5 rounded-lg bg-[#15395A] px-4 py-2 text-xs font-medium text-white hover:bg-[#102d47] whitespace-nowrap shrink-0 cursor-pointer"
          >
            Complete Verification
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {(incompleteProviders.length > 0 || skippedProviders.length > 0) && (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50/70 dark:bg-amber-950/30 px-5 py-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
            <div className="space-y-1">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {incompleteProviders.length > 0
                  ? `Incomplete OSINT Coverage (${incompleteProviders.length} unavailable/failed, ${skippedProviders.length} skipped)`
                  : `${skippedProviders.length} OSINT Check(s) Skipped Due to Missing Identifiers`}
              </h2>
              {incompleteProviders.length > 0 && (
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  Unavailable or errored sources:{' '}
                  <span className="font-mono">
                    {incompleteProviders.map((p) => `${p.providerName} (${p.status})`).join('; ')}
                  </span>
                </p>
              )}
              {skippedProviders.length > 0 && (
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  Skipped checks:{' '}
                  <span className="font-mono">
                    {skippedProviders.map((p) => `${p.providerName}: ${p.message}`).join('; ')}
                  </span>
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('monitoring')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-amber-400 dark:border-amber-700 bg-white dark:bg-slate-900 px-3.5 py-2 text-xs font-medium hover:bg-amber-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            Inspect Coverage &amp; Quotas
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {scanError && (
        <div
          role="alert"
          className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 px-4 py-3 text-sm text-red-800 dark:text-red-200"
        >
          {scanError}
        </div>
      )}

      {/* Primary KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Exposure Questionnaire Score
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="font-mono text-3xl font-semibold tabular-nums text-slate-900 dark:text-white">
              {scoreValue === null ? '—' : `${scoreValue}/100`}
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
            <span>{scoreTone}</span>
            <button
              type="button"
              onClick={() => onNavigate('questionnaire')}
              className="text-[#15395A] dark:text-sky-400 font-medium hover:underline cursor-pointer"
            >
              {scoreValue === null ? 'Take assessment' : 'Retake'}
            </button>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Discovered Findings
          </div>
          <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-slate-900 dark:text-white">
            {data.totalFindings}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs tabular-nums">
            <span className="text-red-600 dark:text-red-400 font-medium">
              {data.riskCounts.High} High
            </span>
            <span aria-hidden="true" className="text-slate-300">
              ·
            </span>
            <span className="text-amber-600 dark:text-amber-400 font-medium">
              {data.riskCounts.Medium} Medium
            </span>
            <span aria-hidden="true" className="text-slate-300">
              ·
            </span>
            <span className="text-slate-600 dark:text-slate-400">
              {data.riskCounts.Low} Low
            </span>
          </div>
          {data.reviewCounts && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
              <span>{data.reviewCounts.unverified} queued</span>
              <span aria-hidden="true">·</span>
              <span>{data.reviewCounts.verifiedMatch} verified</span>
              <span aria-hidden="true">·</span>
              <span>{data.reviewCounts.safeLibrary} safe</span>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Active Misuse Cases &amp; Photos
          </div>
          <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-slate-900 dark:text-white">
            {data.openCasesCount}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400 tabular-nums">
            <span>Open</span>
            {typeof data.resolvedCasesCount === 'number' && (
              <>
                <span aria-hidden="true">·</span>
                <span>{data.resolvedCasesCount} resolved</span>
              </>
            )}
            <span aria-hidden="true">·</span>
            <span>{data.photosCount} photo(s)</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Latest Scan Status
          </div>
          <div className="mt-2 font-mono text-sm font-semibold tabular-nums text-slate-900 dark:text-white truncate">
            {data.lastScan ? data.lastScan.created_at.slice(0, 16).replace('T', ' ') : 'No scans yet'}
          </div>
          <div className="mt-2 text-xs text-slate-600 dark:text-slate-400 truncate">
            {data.lastScan ? data.lastScan.status : 'Authorize identifiers & run real OSINT scan'}
          </div>
        </div>
      </div>

      {/* Category Breakdown + Priority Weights */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Exposure by Category
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Verified &amp; unverified real-world findings across the 5 privacy categories
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleExportCsv}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                Export CSV
              </button>
              <button
                type="button"
                onClick={handleExportPdf}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                Export PDF
              </button>
              <button
                type="button"
                disabled={scanning}
                onClick={data.user.liveScanReady ? handleQuickScan : () => onNavigate('monitoring')}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white px-3 py-1.5 text-xs font-medium disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
                {scanning
                  ? 'Scanning OSINT APIs...'
                  : data.user.liveScanReady
                  ? 'Run OSINT Scan'
                  : 'Configure Monitoring'}
              </button>
            </div>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {Object.entries(data.categoryCounts).map(([category, count]) => {
              const pct = data.totalFindings > 0 ? Math.round((count / data.totalFindings) * 100) : 0;
              return (
                <div key={category} className="py-3 flex items-center justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium text-slate-800 dark:text-slate-200 truncate">
                        {category}
                      </span>
                      <span className="font-mono text-xs tabular-nums text-slate-600 dark:text-slate-400 ml-3">
                        {count} ({pct}%)
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 w-full rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                      <div
                        className="h-full bg-[#15395A] dark:bg-sky-500 transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <section className="lg:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Rule-Based Priority Weights
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Adjust how match confidence, site severity, and recency rank findings (sum must equal 1.00).
            </p>

            <div className="mt-5 space-y-4">
              <div>
                <div className="flex justify-between text-xs font-medium mb-1">
                  <span>Identity Match Confidence</span>
                  <span className="font-mono tabular-nums">
                    {weights.confidence_weight.toFixed(2)}
                  </span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={weights.confidence_weight}
                  onChange={(e) =>
                    setWeights((w) => ({ ...w, confidence_weight: Number(e.target.value) }))
                  }
                  className="w-full accent-[#15395A]"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs font-medium mb-1">
                  <span>Platform / Risk Severity</span>
                  <span className="font-mono tabular-nums">
                    {weights.severity_weight.toFixed(2)}
                  </span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={weights.severity_weight}
                  onChange={(e) =>
                    setWeights((w) => ({ ...w, severity_weight: Number(e.target.value) }))
                  }
                  className="w-full accent-[#15395A]"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs font-medium mb-1">
                  <span>Recency</span>
                  <span className="font-mono tabular-nums">
                    {weights.recency_weight.toFixed(2)}
                  </span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={weights.recency_weight}
                  onChange={(e) =>
                    setWeights((w) => ({ ...w, recency_weight: Number(e.target.value) }))
                  }
                  className="w-full accent-[#15395A]"
                />
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">Total Weight Sum</span>
              <span
                className={`font-mono font-semibold tabular-nums ${
                  Math.abs(weightSum - 1) <= 0.015
                    ? 'text-emerald-700 dark:text-emerald-400'
                    : 'text-red-600 dark:text-red-400'
                }`}
              >
                {weightSum.toFixed(2)} / 1.00
              </span>
            </div>
            {weightMessage && (
              <p className="text-xs text-slate-600 dark:text-slate-300">{weightMessage}</p>
            )}
            <button
              type="button"
              disabled={savingWeights}
              onClick={handleSaveWeights}
              className="w-full rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white py-2 text-xs font-medium transition-colors disabled:opacity-50 cursor-pointer"
            >
              {savingWeights ? 'Recalculating...' : 'Apply & Recalculate Priorities'}
            </button>
          </div>
        </section>
      </div>

      {/* AI Assessment Overview & Recent Notifications */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                AI Exposure Assessment &amp; Advice
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Plain-language inference risk summary powered by Gemini (advisory only, never a final verdict)
              </p>
            </div>
            <button
              type="button"
              disabled={aiLoading}
              onClick={handleGenerateOverview}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] px-3.5 py-2 text-xs font-medium text-white disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {aiLoading ? 'Assessing...' : 'Generate AI Summary'}
            </button>
          </div>

          {aiError && (
            <div className="mt-4 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 p-3 text-xs text-red-700 dark:text-red-300">
              {aiError}
            </div>
          )}

          {aiOverview ? (
            <div className="mt-5 space-y-4 text-sm">
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                {aiOverview.executiveSummary}
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-100 dark:border-slate-800">
                <div>
                  <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    Combined Trace Inference Risks
                  </h3>
                  <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-400 list-disc pl-4">
                    {aiOverview.keyInferenceRisks.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    Recommended Next Steps
                  </h3>
                  <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-400 list-disc pl-4">
                    {aiOverview.priorityNextSteps.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 pt-2 border-t border-slate-100 dark:border-slate-800">
                {aiOverview.advisoryDisclaimer}
              </p>
            </div>
          ) : (
            <div className="mt-6 rounded-lg border border-dashed border-slate-200 dark:border-slate-800 p-6 text-center text-xs text-slate-500 dark:text-slate-400">
              Click <strong>Generate AI Summary</strong> to analyze your current findings and questionnaire score as an integrated privacy footprint.
            </div>
          )}
        </section>

        <section className="lg:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Activity &amp; Alerts
            </h2>
            <ShieldCheck className="w-4 h-4 text-slate-400" />
          </div>
          {data.notifications.length === 0 ? (
            <p className="text-xs text-slate-500 dark:text-slate-400">No notifications yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.notifications.map((n) => (
                <li key={n.id} className="py-2.5 text-xs">
                  <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{n.body}</p>
                  <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                    {n.created_at.slice(0, 16).replace('T', ' ')}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
};
