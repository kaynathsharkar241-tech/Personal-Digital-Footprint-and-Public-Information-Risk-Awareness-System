import React, { useEffect, useState } from 'react';
import { Archive, CheckCircle2, Download, Lock, RotateCcw, ShieldCheck, X } from 'lucide-react';
import { apiRequest, getReviewerToken, setReviewerToken } from '../lib/api.ts';
import { ProtectedImage } from './ProtectedImage.tsx';

interface ReviewerConsoleViewProps {
  onClose: () => void;
  onDecisionApplied: () => void;
}

interface EnrollmentQueueItem {
  user_id: number;
  name: string;
  email: string;
  email_verified_at: string | null;
  consent_at: string;
  status: string;
  reviewed_at: string | null;
  reviewer_note: string;
  ai_biometric_consent?: number;
}

interface PhotoQueueItem {
  id: number;
  user_id: number;
  user_name: string;
  label: string;
  status: string;
  match_result: string;
  match_reason: string;
  match_confidence: number | null;
  created_at: string;
}

interface AssessmentQueueItem {
  id: number;
  user_id: number;
  user_name: string;
  status: string;
  confidence: number | null;
  verification_method: string;
  created_at: string;
}

export const ReviewerConsoleView: React.FC<ReviewerConsoleViewProps> = ({
  onClose,
  onDecisionApplied,
}) => {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [viaEnv, setViaEnv] = useState(false);
  const [bootstrapRequired, setBootstrapRequired] = useState(false);
  const [unlocked, setUnlocked] = useState(Boolean(getReviewerToken()));

  const [passcode, setPasscode] = useState('');
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [reviewerId, setReviewerId] = useState('Trusted Reviewer');
  const [reasons, setReasons] = useState<Record<string, string>>({});

  const [enrollments, setEnrollments] = useState<EnrollmentQueueItem[]>([]);
  const [photos, setPhotos] = useState<PhotoQueueItem[]>([]);
  const [assessments, setAssessments] = useState<AssessmentQueueItem[]>([]);

  // Encrypted Backup & Restoration state
  const [backupPassphrase, setBackupPassphrase] = useState('');
  const [backupFileB64, setBackupFileB64] = useState('');
  const [backupFileName, setBackupFileName] = useState('');
  const [backupVerification, setBackupVerification] = useState<{
    createdAt: string;
    dbSha256: string;
    tableCounts: Record<string, number>;
  } | null>(null);
  const [backupBusy, setBackupBusy] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const loadQueue = async () => {
    try {
      const q = await apiRequest<{
        enrollments: EnrollmentQueueItem[];
        photos: PhotoQueueItem[];
        assessments: AssessmentQueueItem[];
      }>('/api/reviewer/queue');
      setEnrollments(q.enrollments);
      setPhotos(q.photos);
      setAssessments(q.assessments);
      setUnlocked(true);
    } catch {
      setReviewerToken(null);
      setUnlocked(false);
    }
  };

  useEffect(() => {
    apiRequest<{ configured: boolean; viaEnv: boolean; bootstrapRequired?: boolean }>(
      '/api/reviewer/status'
    )
      .then((s) => {
        setConfigured(s.configured);
        setViaEnv(s.viaEnv);
        setBootstrapRequired(Boolean(s.bootstrapRequired));
        if (getReviewerToken()) loadQueue();
      })
      .catch(() => setConfigured(false));

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const handleClaim = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const res = await apiRequest<{ reviewerToken: string; configured: boolean }>(
        '/api/reviewer/claim',
        {
          method: 'POST',
          body: JSON.stringify({
            passcode,
            bootstrapToken: bootstrapRequired ? bootstrapToken : undefined,
          }),
        }
      );
      setReviewerToken(res.reviewerToken);
      setConfigured(true);
      setPasscode('');
      setBootstrapToken('');
      await loadQueue();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not claim reviewer console.');
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const res = await apiRequest<{ reviewerToken: string }>('/api/reviewer/unlock', {
        method: 'POST',
        body: JSON.stringify({ passcode }),
      });
      setReviewerToken(res.reviewerToken);
      setPasscode('');
      await loadQueue();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid reviewer passcode.');
    }
  };

  const handleDecide = async (
    targetType: 'identity' | 'photo' | 'assessment',
    targetId: number,
    decision: string
  ) => {
    const key = `${targetType}:${targetId}`;
    const reason = (reasons[key] || '').trim();
    if (!reason) {
      setError('Enter a mandatory audit reason before recording a reviewer decision.');
      return;
    }
    setError(null);
    setMsg(null);
    try {
      await apiRequest('/api/reviewer/decide', {
        method: 'POST',
        body: JSON.stringify({ targetType, targetId, decision, reason, reviewerId }),
      });
      setMsg(`Decision "${decision}" saved for ${targetType} #${targetId}.`);
      await loadQueue();
      onDecisionApplied();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Decision failed.');
    }
  };

  const handleLock = async () => {
    try {
      await apiRequest('/api/reviewer/lock', { method: 'POST' });
    } catch {
      // clear locally even on network error
    }
    setReviewerToken(null);
    setUnlocked(false);
    setEnrollments([]);
    setPhotos([]);
    setAssessments([]);
    setBackupPassphrase('');
    setBackupFileB64('');
    setBackupVerification(null);
  };

  const handleExportBackup = async () => {
    setError(null);
    setMsg(null);
    if (backupPassphrase.length < 12) {
      setError('Enter an encryption passphrase of at least 12 characters to export a backup.');
      return;
    }
    setBackupBusy(true);
    try {
      const blob = await apiRequest<Blob>('/api/reviewer/backup/export', {
        method: 'POST',
        body: JSON.stringify({ passphrase: backupPassphrase }),
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `privacy-monitor-backup-${new Date().toISOString().slice(0, 10)}.pmbackup`;
      a.click();
      URL.revokeObjectURL(url);
      setMsg('Encrypted database backup downloaded (.pmbackup, AES-256-GCM + scrypt).');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Encrypted backup export failed.');
    } finally {
      setBackupBusy(false);
    }
  };

  const handleBackupFileSelected = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    setBackupVerification(null);
    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      setBackupFileB64(btoa(bin));
      setBackupFileName(file.name);
    } catch {
      setError('Could not read selected backup archive.');
    }
  };

  const handleVerifyBackup = async () => {
    setError(null);
    setMsg(null);
    setBackupVerification(null);
    if (!backupFileB64 || backupPassphrase.length < 12) {
      setError('Select a .pmbackup file and enter its 12+ character passphrase first.');
      return;
    }
    setBackupBusy(true);
    try {
      const res = await apiRequest<{
        valid: boolean;
        createdAt: string;
        dbSha256: string;
        tableCounts: Record<string, number>;
      }>('/api/reviewer/backup/verify', {
        method: 'POST',
        body: JSON.stringify({ passphrase: backupPassphrase, backupBase64: backupFileB64 }),
      });
      setBackupVerification({
        createdAt: res.createdAt,
        dbSha256: res.dbSha256,
        tableCounts: res.tableCounts,
      });
      setMsg('Backup decrypted and passed SQLite PRAGMA integrity verification.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Backup verification failed.');
    } finally {
      setBackupBusy(false);
    }
  };

  const handleRestoreBackup = async () => {
    setError(null);
    setMsg(null);
    if (!backupFileB64 || backupPassphrase.length < 12) {
      setError('Select a verified .pmbackup file and enter its passphrase first.');
      return;
    }
    setBackupBusy(true);
    try {
      const res = await apiRequest<{ ok: boolean; restoredAt: string; dbSha256: string }>(
        '/api/reviewer/backup/restore',
        {
          method: 'POST',
          body: JSON.stringify({ passphrase: backupPassphrase, backupBase64: backupFileB64 }),
        }
      );
      setMsg(`Database restored safely (${res.dbSha256.slice(0, 12)}...) at ${res.restoredAt}.`);
      await loadQueue();
      onDecisionApplied();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Database restoration failed.');
    } finally {
      setBackupBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Trusted Reviewer Audit Console"
      className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-xs flex items-center justify-center p-4"
    >
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden shadow-xl">
        <header className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[#15395A] dark:text-sky-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Trusted Reviewer Audit Console
              </h2>
              <p className="text-xs text-slate-500">
                Human review gate for enrollment selfies, monitoring photos, camera sequences, and encrypted backups.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {unlocked && (
              <button
                type="button"
                onClick={handleLock}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-1.5 text-xs font-medium cursor-pointer"
              >
                <Lock className="w-3.5 h-3.5" />
                Lock Console
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close reviewer console"
              className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </header>

        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {error && (
            <div className="rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 px-4 py-3 text-xs text-red-800 dark:text-red-200">
              {error}
            </div>
          )}
          {msg && (
            <div className="rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30 px-4 py-3 text-xs text-emerald-800 dark:text-emerald-200">
              {msg}
            </div>
          )}

          {!unlocked ? (
            configured === false ? (
              <form onSubmit={handleClaim} className="max-w-md space-y-4">
                <h3 className="text-sm font-semibold">First-Run Reviewer Passcode Claim</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  No <span className="font-mono">REVIEWER_PASSCODE</span> is set yet. Claim the Trusted Reviewer console by choosing a 12+ character passcode.
                </p>
                {bootstrapRequired && (
                  <input
                    type="password"
                    required
                    value={bootstrapToken}
                    onChange={(e) => setBootstrapToken(e.target.value)}
                    placeholder="Server REVIEWER_BOOTSTRAP_TOKEN"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono"
                  />
                )}
                <input
                  type="password"
                  required
                  minLength={12}
                  value={passcode}
                  onChange={(e) => setPasscode(e.target.value)}
                  placeholder="Create reviewer passcode (12+ chars)"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
                />
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-[#15395A] text-white text-xs font-medium cursor-pointer"
                >
                  Claim &amp; Unlock Reviewer Console
                </button>
              </form>
            ) : (
              <form onSubmit={handleUnlock} className="max-w-md space-y-4">
                <h3 className="text-sm font-semibold">Unlock Reviewer Audit Console</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Enter the {viaEnv ? 'configured environment' : 'claimed'} reviewer passcode to inspect encrypted enrollment submissions.
                </p>
                <input
                  type="password"
                  required
                  value={passcode}
                  onChange={(e) => setPasscode(e.target.value)}
                  placeholder="Enter reviewer passcode"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
                />
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-[#15395A] text-white text-xs font-medium cursor-pointer"
                >
                  Unlock Console
                </button>
              </form>
            )
          ) : (
            <div className="space-y-8">
              <div className="flex flex-wrap items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                <label className="text-xs font-medium">Auditor Identifier:</label>
                <input
                  type="text"
                  value={reviewerId}
                  onChange={(e) => setReviewerId(e.target.value)}
                  className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-1.5 text-xs w-56"
                />
              </div>

              {/* Identity Enrollments */}
              <section className="space-y-3">
                <h3 className="text-sm font-semibold">
                  Identity Enrollment Selfies ({enrollments.length})
                </h3>
                {enrollments.length === 0 ? (
                  <p className="text-xs text-slate-500">No enrollments in queue.</p>
                ) : (
                  <div className="space-y-3">
                    {enrollments.map((item) => {
                      const key = `identity:${item.user_id}`;
                      return (
                        <div
                          key={item.user_id}
                          className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 flex flex-col sm:flex-row gap-4"
                        >
                          <ProtectedImage
                            src={`/api/reviewer/photo/identity/${item.user_id}`}
                            alt={`Enrollment selfie for ${item.name}`}
                            useReviewerToken
                            className="w-24 h-24 rounded-lg object-cover border border-slate-200 dark:border-slate-700 shrink-0"
                          />
                          <div className="flex-1 space-y-2 text-xs">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div>
                                <span className="font-semibold text-sm">{item.name}</span>{' '}
                                <span className="font-mono text-slate-500">({item.email})</span>
                              </div>
                              <span
                                className={`font-semibold ${
                                  item.status === 'approved'
                                    ? 'text-emerald-700 dark:text-emerald-400'
                                    : item.status === 'rejected'
                                    ? 'text-red-600'
                                    : 'text-amber-600 dark:text-amber-400'
                                }`}
                              >
                                {item.status.replace('_', ' ')}
                              </span>
                            </div>
                            <div className="text-slate-500">
                              Email: {item.email_verified_at ? 'Verified' : 'Unverified'} · Consent:{' '}
                              <span className="font-mono">{item.consent_at.slice(0, 16)}</span> · AI screening:{' '}
                              {item.ai_biometric_consent ? 'Opted in' : 'Local only'}
                            </div>
                            <div className="flex flex-wrap items-center gap-2 pt-1">
                              <input
                                type="text"
                                value={reasons[key] || ''}
                                onChange={(e) =>
                                  setReasons((r) => ({ ...r, [key]: e.target.value }))
                                }
                                placeholder="Mandatory decision note (e.g. Clear face photo matches enrollment)"
                                className="flex-1 min-w-[200px] rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs"
                              />
                              <button
                                type="button"
                                onClick={() => handleDecide('identity', item.user_id, 'approved')}
                                className="rounded bg-emerald-700 hover:bg-emerald-800 text-white px-3 py-1.5 font-medium cursor-pointer"
                              >
                                Approve
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDecide('identity', item.user_id, 'rejected')}
                                className="rounded border border-red-300 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30 px-3 py-1.5 font-medium cursor-pointer"
                              >
                                Reject
                              </button>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              {/* Monitoring Photos */}
              <section className="space-y-3">
                <h3 className="text-sm font-semibold">
                  Monitoring Photos Queue ({photos.length})
                </h3>
                {photos.length === 0 ? (
                  <p className="text-xs text-slate-500">No monitoring photos uploaded.</p>
                ) : (
                  <div className="space-y-3">
                    {photos.map((p) => {
                      const key = `photo:${p.id}`;
                      return (
                        <div
                          key={p.id}
                          className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 flex flex-col sm:flex-row gap-4"
                        >
                          <ProtectedImage
                            src={`/api/reviewer/photo/photo/${p.id}`}
                            alt={p.label}
                            useReviewerToken
                            className="w-24 h-24 rounded-lg object-cover border border-slate-200 dark:border-slate-700 shrink-0"
                          />
                          <div className="flex-1 space-y-2 text-xs">
                            <div className="flex flex-wrap justify-between gap-2">
                              <div>
                                <span className="font-semibold text-sm">{p.label}</span>{' '}
                                <span className="text-slate-500">by {p.user_name}</span>
                              </div>
                              <span className="font-semibold">{p.status.replace('_', ' ')}</span>
                            </div>
                            <div className="text-slate-600 dark:text-slate-400">
                              1:1 Screening: <strong>{p.match_result}</strong>
                              {p.match_confidence !== null &&
                                ` (${Math.round(p.match_confidence * 100)}%)`}{' '}
                              — {p.match_reason}
                            </div>
                            <div className="flex flex-wrap items-center gap-2 pt-1">
                              <input
                                type="text"
                                value={reasons[key] || ''}
                                onChange={(e) =>
                                  setReasons((r) => ({ ...r, [key]: e.target.value }))
                                }
                                placeholder="Mandatory decision note"
                                className="flex-1 min-w-[200px] rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs"
                              />
                              <button
                                type="button"
                                onClick={() => handleDecide('photo', p.id, 'approved')}
                                className="rounded bg-emerald-700 hover:bg-emerald-800 text-white px-3 py-1.5 font-medium cursor-pointer"
                              >
                                Approve
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDecide('photo', p.id, 'rejected')}
                                className="rounded border border-red-300 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30 px-3 py-1.5 font-medium cursor-pointer"
                              >
                                Reject
                              </button>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              {/* Camera Sequence Assessments */}
              <section className="space-y-3">
                <h3 className="text-sm font-semibold">
                  Camera Sequence Assessments ({assessments.length})
                </h3>
                {assessments.length === 0 ? (
                  <p className="text-xs text-slate-500">No camera sequence sessions recorded.</p>
                ) : (
                  <div className="space-y-3">
                    {assessments.map((a) => {
                      const key = `assessment:${a.id}`;
                      return (
                        <div
                          key={a.id}
                          className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 text-xs space-y-2"
                        >
                          <div className="flex flex-wrap justify-between gap-2">
                            <span>
                              <strong>Session #{a.id}</strong> · {a.user_name} ·{' '}
                              {a.verification_method}
                            </span>
                            <span className="font-mono">
                              {a.status}
                              {a.confidence !== null ? ` (${Math.round(a.confidence * 100)}%)` : ''}
                            </span>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <input
                              type="text"
                              value={reasons[key] || ''}
                              onChange={(e) =>
                                setReasons((r) => ({ ...r, [key]: e.target.value }))
                              }
                              placeholder="Mandatory audit reason"
                              className="flex-1 min-w-[200px] rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs"
                            />
                            <button
                              type="button"
                              onClick={() =>
                                handleDecide('assessment', a.id, 'screening_accepted')
                              }
                              className="rounded bg-emerald-700 text-white px-2.5 py-1.5 font-medium cursor-pointer"
                            >
                              Accept
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleDecide('assessment', a.id, 'needs_more_evidence')
                              }
                              className="rounded border border-slate-300 dark:border-slate-700 px-2.5 py-1.5 font-medium cursor-pointer"
                            >
                              Request Evidence
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleDecide('assessment', a.id, 'screening_rejected')
                              }
                              className="rounded border border-red-300 text-red-600 px-2.5 py-1.5 font-medium cursor-pointer"
                            >
                              Reject
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              {/* Encrypted Backup & Restoration */}
              <section className="space-y-3 pt-4 border-t border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Archive className="w-4 h-4 text-[#15395A] dark:text-sky-400" />
                  <h3 className="text-sm font-semibold">Encrypted Database Backup &amp; Restore</h3>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Creates a consistent SQLite snapshot encrypted with AES-256-GCM and a passphrase-derived scrypt key. Host secrets and session keys are never bundled inside backup archives.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <input
                    type="password"
                    value={backupPassphrase}
                    onChange={(e) => setBackupPassphrase(e.target.value)}
                    placeholder="Backup passphrase (12+ chars)"
                    className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 font-mono"
                  />
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      disabled={backupBusy}
                      onClick={handleExportBackup}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white px-3.5 py-2 font-medium disabled:opacity-50 cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Export Backup
                    </button>
                    <label className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 dark:border-slate-700 px-3 py-2 font-medium cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800">
                      <span>{backupFileName || 'Select .pmbackup'}</span>
                      <input
                        type="file"
                        accept=".pmbackup,application/octet-stream,application/json"
                        onChange={handleBackupFileSelected}
                        className="sr-only"
                      />
                    </label>
                    <button
                      type="button"
                      disabled={backupBusy || !backupFileB64}
                      onClick={handleVerifyBackup}
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-300 dark:border-slate-700 px-3 py-2 font-medium disabled:opacity-50 cursor-pointer"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Verify
                    </button>
                    <button
                      type="button"
                      disabled={backupBusy || !backupFileB64}
                      onClick={handleRestoreBackup}
                      className="inline-flex items-center gap-1 rounded-lg border border-red-300 text-red-600 px-3 py-2 font-medium disabled:opacity-50 cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      Restore
                    </button>
                  </div>
                </div>
                {backupVerification && (
                  <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3 text-xs font-mono space-y-1">
                    <div>Created: {backupVerification.createdAt}</div>
                    <div>SHA-256: {backupVerification.dbSha256}</div>
                    <div>
                      Tables: users={backupVerification.tableCounts.users ?? 0}, findings=
                      {backupVerification.tableCounts.findings ?? 0}, cases=
                      {backupVerification.tableCounts.cases ?? 0}, evidence=
                      {backupVerification.tableCounts.evidence ?? 0}
                    </div>
                  </div>
                )}
              </section>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
