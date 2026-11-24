import React, { useEffect, useState } from 'react';
import {
  Download,
  ExternalLink,
  FileUp,
  FolderPlus,
  Lock,
  Sparkles,
} from 'lucide-react';
import { apiRequest, getSessionToken } from '../lib/api.ts';
import type { CaseEvent, CaseItem, EvidenceItem, ResponseGuide } from '../lib/types.ts';

interface CasesViewProps {
  initialPrefill: {
    title: string;
    category: string;
    description: string;
    url: string;
  } | null;
  onClearPrefill: () => void;
  onRefreshDashboard: () => void;
}

export const CasesView: React.FC<CasesViewProps> = ({
  initialPrefill,
  onClearPrefill,
  onRefreshDashboard,
}) => {
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<{
    caseItem: CaseItem;
    evidence: EvidenceItem[];
    timeline?: CaseEvent[];
    guide: ResponseGuide;
  } | null>(null);

  // Create case form
  const [showCreate, setShowCreate] = useState(Boolean(initialPrefill));
  const [title, setTitle] = useState(initialPrefill?.title || '');
  const [category, setCategory] = useState(initialPrefill?.category || 'Contact Details');
  const [description, setDescription] = useState(initialPrefill?.description || '');
  const [url, setUrl] = useState(initialPrefill?.url || '');

  // Detail editing
  const [editStatus, setEditStatus] = useState<'Open' | 'Under Review' | 'Resolved'>('Open');
  const [editNotes, setEditNotes] = useState('');
  const [editResolutionSummary, setEditResolutionSummary] = useState('');
  const [draftLoading, setDraftLoading] = useState(false);
  const [uploadingEv, setUploadingEv] = useState(false);

  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialPrefill) {
      setShowCreate(true);
      setTitle(initialPrefill.title);
      setCategory(initialPrefill.category);
      setDescription(initialPrefill.description);
      setUrl(initialPrefill.url);
    }
  }, [initialPrefill]);

  const loadCases = async (selectId?: number) => {
    try {
      const res = await apiRequest<{ cases: CaseItem[]; categories: string[] }>('/api/cases');
      setCases(res.cases);
      setCategories(res.categories);
      const target = selectId ?? selectedId ?? res.cases[0]?.id ?? null;
      if (target) setSelectedId(target);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load cases.');
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const loadDetail = async (id: number) => {
    try {
      const res = await apiRequest<{
        caseItem: CaseItem;
        evidence: EvidenceItem[];
        timeline?: CaseEvent[];
        guide: ResponseGuide;
      }>(`/api/cases/${id}`);
      setDetail(res);
      setEditStatus(res.caseItem.status);
      setEditNotes(res.caseItem.notes || '');
      setEditResolutionSummary(res.caseItem.resolution_summary || '');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load case details.');
    }
  };

  useEffect(() => {
    if (selectedId) loadDetail(selectedId);
    else setDetail(null);
  }, [selectedId]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setMsg(null);
    try {
      const res = await apiRequest<{ caseItem: CaseItem }>('/api/cases', {
        method: 'POST',
        body: JSON.stringify({ title, category, description, url }),
      });
      setTitle('');
      setDescription('');
      setUrl('');
      setShowCreate(false);
      onClearPrefill();
      setMsg('Misuse case created.');
      await loadCases(res.caseItem.id);
      onRefreshDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create case.');
    }
  };

  const handleSaveDetail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!detail) return;
    setError(null);
    setMsg(null);
    try {
      await apiRequest(`/api/cases/${detail.caseItem.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: editStatus,
          notes: editNotes,
          resolution_summary: editResolutionSummary,
        }),
      });
      setMsg('Case status, resolution summary, and investigation notes saved.');
      await loadCases(detail.caseItem.id);
      await loadDetail(detail.caseItem.id);
      onRefreshDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update case.');
    }
  };

  const handleDownloadCasePdf = async () => {
    if (!detail) return;
    try {
      const blob = await apiRequest<Blob>(`/api/cases/${detail.caseItem.id}/report.pdf`);
      const objUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl;
      a.download = `privacy_case_${detail.caseItem.id}_dossier.pdf`;
      a.click();
      URL.revokeObjectURL(objUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not download case PDF dossier.');
    }
  };

  const handleGenerateAiDraft = async () => {
    if (!detail) return;
    setError(null);
    setDraftLoading(true);
    try {
      await apiRequest(`/api/cases/${detail.caseItem.id}/ai-draft`, { method: 'POST' });
      await loadDetail(detail.caseItem.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to draft takedown notice.');
    } finally {
      setDraftLoading(false);
    }
  };

  const handleUploadEvidence = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !detail) return;
    setError(null);
    setMsg(null);
    setUploadingEv(true);
    try {
      const base64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const str = String(reader.result || '');
          const idx = str.indexOf(',');
          resolve(idx >= 0 ? str.slice(idx + 1) : str);
        };
        reader.onerror = () => reject(new Error('Could not read evidence file.'));
        reader.readAsDataURL(file);
      });

      await apiRequest(`/api/cases/${detail.caseItem.id}/evidence`, {
        method: 'POST',
        body: JSON.stringify({
          name: file.name,
          mime: file.type || 'application/octet-stream',
          dataBase64: base64,
        }),
      });
      setMsg(`Encrypted evidence "${file.name}" saved to vault.`);
      await loadDetail(detail.caseItem.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Evidence upload failed.');
    } finally {
      setUploadingEv(false);
      e.target.value = '';
    }
  };

  const handleDownloadEvidence = async (ev: EvidenceItem) => {
    if (!detail) return;
    try {
      const token = getSessionToken();
      const res = await fetch(`/api/cases/${detail.caseItem.id}/evidence/${ev.id}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error('Download failed.');
      const blob = await res.blob();
      const objUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl;
      a.download = ev.name;
      a.click();
      URL.revokeObjectURL(objUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not download encrypted evidence.');
    }
  };

  const parsedDraft = (() => {
    if (!detail?.caseItem.ai_draft) return null;
    try {
      const raw = JSON.parse(detail.caseItem.ai_draft) as {
        subjectLine?: string;
        noticeDraft?: string;
        noticeBody?: string;
        checklist?: string[];
        escalationChecklist?: string[];
      };
      return {
        subjectLine: raw.subjectLine || `Privacy Removal Request — Case #${detail.caseItem.id}`,
        noticeBody: raw.noticeDraft || raw.noticeBody || '',
        escalationChecklist: Array.isArray(raw.checklist)
          ? raw.checklist
          : Array.isArray(raw.escalationChecklist)
          ? raw.escalationChecklist
          : [],
      };
    } catch {
      return null;
    }
  })();

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 px-4 py-3 text-sm text-red-800 dark:text-red-200">
          {error}
        </div>
      )}
      {msg && (
        <div className="rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30 px-4 py-3 text-sm text-emerald-800 dark:text-emerald-200">
          {msg}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Misuse Case Tracker &amp; Encrypted Evidence Vault
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Track impersonation, leaked credentials, or unwanted listings and keep encrypted screenshots or PDFs.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate((v) => !v)}
          className="inline-flex items-center gap-1.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white px-4 py-2 text-xs font-medium cursor-pointer whitespace-nowrap shrink-0"
        >
          <FolderPlus className="w-3.5 h-3.5" />
          {showCreate ? 'Close Form' : 'New Misuse Case'}
        </button>
      </div>

      {showCreate && (
        <form
          onSubmit={handleCreateCase}
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4"
        >
          <h3 className="text-sm font-semibold">Open New Case</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium mb-1">Case Title</label>
              <input
                type="text"
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Unwanted People-Search Listing"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Category</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
              >
                {(categories.length > 0
                  ? categories
                  : [
                      'Credentials & Accounts',
                      'Contact Details',
                      'Social Profiles',
                      'Public Documents',
                      'Impersonation & Photo Misuse',
                    ]
                ).map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Reference URL (optional)</label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/profile"
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono"
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Description</label>
            <textarea
              required
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe what data appeared, where it is hosted, and what action you want to track..."
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              type="submit"
              className="px-5 py-2 rounded-lg bg-[#15395A] text-white text-xs font-medium cursor-pointer"
            >
              Create Case
            </button>
            <button
              type="button"
              onClick={() => {
                setShowCreate(false);
                onClearPrefill();
              }}
              className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium cursor-pointer"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Master-Detail Case Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className="lg:col-span-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-600 dark:text-slate-300">
            Your Cases ({cases.length})
          </div>
          {cases.length === 0 ? (
            <div className="p-6 text-xs text-slate-500 text-center">
              No cases tracked yet. Open a case or promote any finding from Monitoring &amp; Scans.
            </div>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {cases.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => setSelectedId(c.id)}
                  className={`w-full text-left px-4 py-3.5 transition-colors cursor-pointer ${
                    selectedId === c.id
                      ? 'bg-slate-100/90 dark:bg-slate-800'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span
                      className={`font-semibold ${
                        c.status === 'Resolved'
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : c.status === 'Under Review'
                          ? 'text-amber-600 dark:text-amber-400'
                          : 'text-[#15395A] dark:text-sky-400'
                      }`}
                    >
                      {c.status}
                    </span>
                    <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                      #{c.id}
                    </span>
                  </div>
                  <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100 truncate">
                    {c.title}
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500 truncate">{c.category}</div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="lg:col-span-8 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
          {!detail ? (
            <div className="py-12 text-center text-xs text-slate-500">
              Select a case on the left to inspect its response guide, draft a takedown notice, and attach encrypted evidence.
            </div>
          ) : (
            <div className="space-y-6">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-4">
                <div>
                  <div className="text-xs text-slate-500">
                    Case #{detail.caseItem.id} · {detail.caseItem.category} · Opened{' '}
                    <span className="font-mono tabular-nums">
                      {detail.caseItem.created_at.slice(0, 10)}
                    </span>
                    {detail.caseItem.resolved_at && (
                      <>
                        {' '}
                        · Resolved{' '}
                        <span className="font-mono tabular-nums text-emerald-700 dark:text-emerald-400">
                          {detail.caseItem.resolved_at.slice(0, 10)}
                        </span>
                      </>
                    )}
                  </div>
                  <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                    {detail.caseItem.title}
                  </h3>
                  {detail.caseItem.url && (
                    <a
                      href={detail.caseItem.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-mono text-[#15395A] dark:text-sky-400 hover:underline mt-1"
                    >
                      {detail.caseItem.url}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={handleDownloadCasePdf}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 px-3 py-2 text-xs font-medium whitespace-nowrap cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download Case PDF
                  </button>
                  <button
                    type="button"
                    disabled={draftLoading}
                    onClick={handleGenerateAiDraft}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white px-3.5 py-2 text-xs font-medium disabled:opacity-50 whitespace-nowrap cursor-pointer"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    {draftLoading ? 'Drafting Notice...' : 'AI Draft Takedown Notice'}
                  </button>
                </div>
              </div>

              <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed">
                {detail.caseItem.description}
              </p>

              {/* Category Response Playbook */}
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-4 space-y-2 text-xs">
                <div className="font-semibold text-slate-900 dark:text-slate-100">
                  Response Guide: {detail.caseItem.category}
                </div>
                <p className="text-slate-600 dark:text-slate-400">{detail.guide.summary}</p>
                <ol className="list-decimal pl-4 space-y-1 text-slate-700 dark:text-slate-300">
                  {detail.guide.steps.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ol>
              </div>

              {/* AI Draft */}
              {parsedDraft && (
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 space-y-3 text-xs">
                  <div className="font-semibold text-slate-900 dark:text-slate-100">
                    Gemini Draft Takedown / Opt-Out Notice
                  </div>
                  <div className="font-mono text-slate-700 dark:text-slate-300">
                    Subject: {parsedDraft.subjectLine}
                  </div>
                  <pre className="whitespace-pre-wrap font-sans text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-950 p-3 rounded border border-slate-200 dark:border-slate-800 leading-relaxed">
                    {parsedDraft.noticeBody}
                  </pre>
                  <div>
                    <span className="font-semibold">Escalation Checklist:</span>
                    <ul className="list-disc pl-4 mt-1 space-y-1 text-slate-600 dark:text-slate-400">
                      {parsedDraft.escalationChecklist.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* Status & Notes */}
              <form onSubmit={handleSaveDetail} className="space-y-3 pt-2 border-t border-slate-100 dark:border-slate-800">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-center">
                  <label className="text-xs font-medium">Case Status</label>
                  <select
                    value={editStatus}
                    onChange={(e) =>
                      setEditStatus(e.target.value as 'Open' | 'Under Review' | 'Resolved')
                    }
                    className="sm:col-span-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs"
                  >
                    <option value="Open">Open</option>
                    <option value="Under Review">Under Review</option>
                    <option value="Resolved">Resolved</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1">Investigation Notes</label>
                  <textarea
                    rows={3}
                    value={editNotes}
                    onChange={(e) => setEditNotes(e.target.value)}
                    placeholder="Record outreach dates, ticket numbers, or confirmation responses..."
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1">
                    Resolution Summary (recorded when marking Resolved)
                  </label>
                  <textarea
                    rows={2}
                    value={editResolutionSummary}
                    onChange={(e) => setEditResolutionSummary(e.target.value)}
                    placeholder="e.g. Data broker confirmed removal and cache de-indexation on..."
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs"
                  />
                </div>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-[#15395A] text-white text-xs font-medium cursor-pointer"
                >
                  Save Status &amp; Resolution
                </button>
              </form>

              {/* Encrypted Evidence Vault */}
              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-slate-500" />
                    <span className="text-xs font-semibold">
                      Encrypted Case Evidence (PNG, JPEG, PDF, TXT · max 5 MB)
                    </span>
                  </div>
                  <label className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 dark:border-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer">
                    <FileUp className="w-3.5 h-3.5" />
                    <span>{uploadingEv ? 'Encrypting...' : 'Attach Evidence'}</span>
                    <input
                      type="file"
                      accept=".png,.jpg,.jpeg,.pdf,.txt,image/png,image/jpeg,application/pdf,text/plain"
                      disabled={uploadingEv}
                      onChange={handleUploadEvidence}
                      className="sr-only"
                    />
                  </label>
                </div>

                {detail.evidence.length === 0 ? (
                  <p className="text-xs text-slate-500">No evidence files attached yet.</p>
                ) : (
                  <div className="divide-y divide-slate-100 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded-lg">
                    {detail.evidence.map((ev) => (
                      <div
                        key={ev.id}
                        className="px-3.5 py-2.5 flex items-center justify-between gap-3 text-xs"
                      >
                        <div className="min-w-0">
                          <div className="font-medium text-slate-800 dark:text-slate-200 truncate">
                            {ev.name}
                          </div>
                          <div className="font-mono text-[11px] text-slate-400">
                            {ev.mime} · {ev.created_at.slice(0, 16).replace('T', ' ')}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleDownloadEvidence(ev)}
                          className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 px-2.5 py-1 hover:bg-slate-50 dark:hover:bg-slate-800 shrink-0 cursor-pointer"
                        >
                          <Download className="w-3 h-3" />
                          Decrypt &amp; Download
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Case Audit & Resolution Timeline */}
              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-2.5">
                <span className="text-xs font-semibold block">Case Audit &amp; Resolution Timeline</span>
                {!detail.timeline || detail.timeline.length === 0 ? (
                  <p className="text-xs text-slate-500">No case timeline events logged yet.</p>
                ) : (
                  <ul className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                    {detail.timeline.map((ev) => (
                      <li key={ev.id} className="py-2 flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <span className="font-medium text-slate-800 dark:text-slate-200">
                            [{ev.status}]
                          </span>{' '}
                          <span className="text-slate-600 dark:text-slate-300">{ev.summary}</span>
                        </div>
                        <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                          {ev.created_at.slice(0, 19).replace('T', ' ')}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
