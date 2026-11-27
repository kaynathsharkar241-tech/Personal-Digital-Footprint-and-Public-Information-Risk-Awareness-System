import React, { useEffect, useRef, useState } from 'react';
import { Camera, CheckCircle2, KeyRound, Mail, ShieldAlert, ShieldCheck } from 'lucide-react';
import { apiRequest, registerBrowserPasskey } from '../lib/api.ts';
import type { UserState } from '../lib/types.ts';
import { ProtectedImage } from './ProtectedImage.tsx';

interface IdentityViewProps {
  user: UserState;
  previewVerifyToken: string | null;
  onUserUpdated: (user: UserState) => void;
  onOpenReviewer: () => void;
}

export const IdentityView: React.FC<IdentityViewProps> = ({
  user,
  previewVerifyToken,
  onUserUpdated,
  onOpenReviewer,
}) => {
  const [tokenInput, setTokenInput] = useState('');

  const [pinInput, setPinInput] = useState('');
  const [passkeyLabel, setPasskeyLabel] = useState('My Device Passkey');
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // 3-frame liveness sequence state
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [instructions, setInstructions] = useState<string>('');
  const [capturingSeq, setCapturingSeq] = useState(false);
  const [seqProgress, setSeqProgress] = useState<string>('');

  const [assessments, setAssessments] = useState<
    Array<{ id: number; status: string; confidence: number | null; verification_method: string; created_at: string }>
  >([]);
  const [reviewEvents, setReviewEvents] = useState<
    Array<{ id: number; session_id: number; reviewer_id: string; decision: string; reason: string; reviewed_at: string }>
  >([]);

  const loadVerificationStatus = async () => {
    try {
      const res = await apiRequest<{
        state: UserState;
        assessments: typeof assessments;
        reviewEvents: typeof reviewEvents;
      }>('/api/verification-status');
      onUserUpdated(res.state);
      setAssessments(res.assessments);
      setReviewEvents(res.reviewEvents);
    } catch {
      // silent
    }
  };

  useEffect(() => {
    loadVerificationStatus();
    return () => {
      streamRef.current?.getTracks().forEach((t) => t.stop());
    };
  }, []);

  const handleResendEmail = async () => {
    setError(null);
    setStatusMsg(null);
    try {
      const res = await apiRequest<{
        sent?: boolean;
        alreadyVerified?: boolean;
        previewVerificationToken?: string | null;
      }>('/api/auth/verify-email/resend', { method: 'POST' });
      if (res.alreadyVerified) {
        setStatusMsg('Email is already verified.');
      } else {
        setStatusMsg('Verification email sent. Check your inbox.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to issue verification token.');
    }
  };

  const handleConfirmEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setStatusMsg(null);
    try {
      const res = await apiRequest<{ ok: boolean; user: UserState }>('/api/auth/verify-email/confirm', {
        method: 'POST',
        body: JSON.stringify({ token: tokenInput }),
      });
      onUserUpdated(res.user);
      setTokenInput('');
      setStatusMsg('Email ownership verified.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Email verification failed.');
    }
  };

  useEffect(() => {
    if (challengeId && videoRef.current && streamRef.current) {
      videoRef.current.srcObject = streamRef.current;
      videoRef.current.play().catch(() => {
        setError('Unable to start camera preview.');
      });
    }
  }, [challengeId]);

  const handleStartSequence = async () => {
    setError(null);
    setStatusMsg(null);
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('Camera API unavailable in this browser.');
      return;
    }
    try {
      const ch = await apiRequest<{ challengeId: string; instructions: string }>(
        '/api/liveness/challenge/start',
        { method: 'POST' }
      );
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } },
        audio: false,
      });
      streamRef.current = stream;
      if (videoRef.current) videoRef.current.srcObject = stream;
      setChallengeId(ch.challengeId);
      setInstructions(ch.instructions);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start camera sequence.');
    }
  };

  const handleRunSequenceCapture = async () => {
    if (!challengeId || !videoRef.current) return;

    if (
      videoRef.current.readyState < 2 ||
      !videoRef.current.videoWidth ||
      !videoRef.current.videoHeight
    ) {
      setError('Camera is not ready. Please try again.');
      return;
    }

    setCapturingSeq(true);
    setError(null);
    const frames: string[] = [];

    const snap = () => {
      const video = videoRef.current!;
      const c = document.createElement('canvas');
      c.width = video.videoWidth || 640;
      c.height = video.videoHeight || 480;
      c.getContext('2d')?.drawImage(video, 0, 0);
      return c.toDataURL('image/jpeg', 0.85);
    };

    try {
      setSeqProgress('Sampling frame 1 of 3 (center)...');
      frames.push(snap());
      await new Promise((r) => setTimeout(r, 2500));

      setSeqProgress('Sampling frame 2 of 3 (turn head slightly)...');
      frames.push(snap());
      await new Promise((r) => setTimeout(r, 2500));

      setSeqProgress('Sampling frame 3 of 3 (return center)...');
      frames.push(snap());

      streamRef.current?.getTracks().forEach((t) => t.stop());
      streamRef.current = null;

      setSeqProgress('Submitting sequence for visual screening...');
      const res = await apiRequest<{ message: string; user: UserState }>(
        '/api/liveness/challenge/finish',
        {
          method: 'POST',
          body: JSON.stringify({ challengeId, frames }),
        }
      );
      setChallengeId(null);
      setSeqProgress('');
      setStatusMsg(res.message);
      onUserUpdated(res.user);
      loadVerificationStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sequence capture failed.');
      streamRef.current?.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
      setChallengeId(null);
      setSeqProgress('');
    } finally {
      setCapturingSeq(false);
    }
  };

  const handleSavePin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setStatusMsg(null);
    try {
      const res = await apiRequest<{ ok: boolean; user: UserState }>('/api/auth/pin', {
        method: 'POST',
        body: JSON.stringify({ pin: pinInput }),
      });
      onUserUpdated(res.user);
      setPinInput('');
      setStatusMsg('Salted fallback PIN saved.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save PIN.');
    }
  };

  const handleAddPasskey = async () => {
    setError(null);
    setStatusMsg(null);
    try {
      await registerBrowserPasskey(user.email, user.name, passkeyLabel);
      setStatusMsg('WebAuthn passkey registered for passwordless sign-in.');
      loadVerificationStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not register passkey.');
    }
  };

  const handleToggleAiConsent = async (nextConsent: boolean) => {
    setError(null);
    setStatusMsg(null);
    try {
      const res = await apiRequest<{ ok: boolean; user: UserState }>('/api/identity/ai-consent', {
        method: 'PUT',
        body: JSON.stringify({ consent: nextConsent }),
      });
      onUserUpdated(res.user);
      setStatusMsg(
        nextConsent
          ? 'Opted in to optional third-party Google Gemini visual screening.'
          : 'Third-party Google Gemini visual screening disabled; images stay local.'
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update AI biometric consent preference.');
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 px-4 py-3 text-sm text-red-800 dark:text-red-200">
          {error}
        </div>
      )}
      {statusMsg && (
        <div className="rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/40 px-4 py-3 text-sm text-emerald-800 dark:text-emerald-200">
          {statusMsg}
        </div>
      )}

      {/* Verification Gates Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gate 1: Email */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold">1. Email Ownership</h2>
            <Mail className="w-4 h-4 text-slate-400" />
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Status:{' '}
            <strong className={user.emailVerified ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}>
              {user.emailVerified ? 'Verified' : 'Pending verification'}
            </strong>
          </p>
          {!user.emailVerified && (
            <form onSubmit={handleConfirmEmail} className="space-y-3">
              
              <input
                type="text"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                placeholder="Enter six-digit code"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                pattern="[0-9]{6}"
                required
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs font-mono"
              />
              <div className="flex items-center gap-2">
                <button
                  type="submit"
                  className="px-3.5 py-2 rounded-lg bg-[#15395A] text-white text-xs font-medium cursor-pointer"
                >
                  Verify Email
                </button>
                <button
                  type="button"
                  onClick={handleResendEmail}
                  className="px-3.5 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium cursor-pointer"
                >
                  Send Code
                </button>
              </div>
            </form>
          )}
        </section>

        {/* Gate 2: Enrollment Selfie & Reviewer Audit */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold">2. Reference Photograph</h2>
            {user.selfieStatus === 'approved' ? (
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-amber-600" />
            )}
          </div>
          <div className="flex items-center gap-4">
            <ProtectedImage
              src="/api/identity/selfie"
              alt="Encrypted enrollment selfie"
              className="w-16 h-16 rounded-lg object-cover border border-slate-200 dark:border-slate-700 shrink-0"
            />
            <div className="text-xs space-y-1">
              <div>
                Status:{' '}
                <strong
                  className={
                    user.selfieStatus === 'approved'
                      ? 'text-emerald-700 dark:text-emerald-400'
                      : user.selfieStatus === 'rejected'
                      ? 'text-red-600'
                      : 'text-amber-600 dark:text-amber-400'
                  }
                >
                  {user.selfieStatus.replace('_', ' ')}
                </strong>
              </div>
              {user.selfieReviewerNote && (
                <p className="text-slate-500 dark:text-slate-400">Note: {user.selfieReviewerNote}</p>
              )}
            </div>
          </div>
          <p className="text-xs text-slate-500">
              Complete the live camera verification to
              assess your enrolled photograph.
            </p>
        </section>

        {/* Gate 3: 3-Frame Camera Sequence */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold">3. Live Camera Verification</h2>
            <Camera className="w-4 h-4 text-slate-400" />
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Captures 3 timed frames for local movement variation and records an audit item for the trusted reviewer.
          </p>
          <label className="flex items-start gap-2 text-[11px] text-slate-600 dark:text-slate-300 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={user.aiBiometricConsent}
              onChange={(e) => handleToggleAiConsent(e.target.checked)}
              className="mt-0.5 rounded border-slate-300"
            />
            <span>
              Optional third-party AI disclosure: transmit frames to Google Gemini API for 1:1 similarity screening (currently{' '}
              <strong>{user.aiBiometricConsent ? 'enabled' : 'disabled'}</strong>).
            </span>
          </label>
          {!challengeId ? (
            <button
              type="button"
              onClick={handleStartSequence}
              className="w-full rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white py-2 text-xs font-medium cursor-pointer"
            >
              Start Live Camera
            </button>
          ) : (
            <div className="space-y-3">
              <p className="text-xs font-medium text-slate-700 dark:text-slate-300">{instructions}</p>
              <video
                ref={videoRef}
                autoPlay
                playsInline
                muted
                className="w-full h-36 rounded-lg bg-slate-950 object-cover"
              />
              {seqProgress && <p className="text-xs text-sky-700 dark:text-sky-400">{seqProgress}</p>}
              <button
                type="button"
                disabled={capturingSeq}
                onClick={handleRunSequenceCapture}
                className="w-full rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white py-2 text-xs font-medium disabled:opacity-50 cursor-pointer"
              >
                {capturingSeq ? 'Capturing 3 Frames...' : 'Begin Live Verification'}
              </button>
            </div>
          )}
        </section>
      </div>

      {/* Passwordless & Fallback Recovery Setup */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold">WebAuthn Passkey</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Registered passkeys: <span className="font-mono tabular-nums">{user.passkeyCount}</span>
              </p>
            </div>
            <KeyRound className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex flex-wrap gap-2">
            <input
              type="text"
              value={passkeyLabel}
              onChange={(e) => setPasskeyLabel(e.target.value)}
              placeholder="Passkey label (e.g. Laptop Touch ID)"
              className="flex-1 min-w-[180px] rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
            />
            <button
              type="button"
              onClick={handleAddPasskey}
              className="px-4 py-2 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer"
            >
              Register Passkey
            </button>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold">Fallback PIN</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {user.hasFallbackPin ? 'Configured (salted scrypt hash)' : 'Not configured yet'} ·{' '}
                {user.recoveryCodesRemaining} recovery code(s) unused
              </p>
            </div>
            {user.hasFallbackPin && <CheckCircle2 className="w-4 h-4 text-emerald-600" />}
          </div>
          <form onSubmit={handleSavePin} className="flex flex-wrap gap-2">
            <input
              type="password"
              inputMode="numeric"
              pattern="\d{4,8}"
              required
              value={pinInput}
              onChange={(e) => setPinInput(e.target.value)}
              placeholder="4 to 8 digits"
              className="flex-1 min-w-[160px] rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono"
            />
            <button
              type="submit"
              className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer"
            >
              {user.hasFallbackPin ? 'Update PIN' : 'Set Fallback PIN'}
            </button>
          </form>
        </section>
      </div>

      {/* Assessment & Audit Log */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <h2 className="text-base font-semibold mb-4">Verification &amp; Audit History</h2>
        {assessments.length === 0 ? (
          <p className="text-xs text-slate-500">No camera sequence assessments recorded yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                <tr>
                  <th className="py-2 pr-4 font-medium">ID</th>
                  <th className="py-2 pr-4 font-medium">Method</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 pr-4 font-medium">AI Confidence</th>
                  <th className="py-2 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {assessments.map((a) => (
                  <tr key={a.id}>
                    <td className="py-2.5 pr-4 font-mono tabular-nums">#{a.id}</td>
                    <td className="py-2.5 pr-4">{a.verification_method}</td>
                    <td className="py-2.5 pr-4 font-medium">{a.status}</td>
                    <td className="py-2.5 pr-4 font-mono tabular-nums">
                      {a.confidence !== null ? `${Math.round(a.confidence * 100)}%` : '—'}
                    </td>
                    <td className="py-2.5 font-mono tabular-nums text-slate-500">
                      {a.created_at.slice(0, 19).replace('T', ' ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {reviewEvents.length > 0 && (
          <div className="mt-5 pt-4 border-t border-slate-100 dark:border-slate-800 space-y-2">
            <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-300">
              Reviewer Decisions
            </h3>
            {reviewEvents.map((ev) => (
              <div key={ev.id} className="text-xs text-slate-600 dark:text-slate-400">
                <span className="font-mono">Session #{ev.session_id}</span> ·{' '}
                <strong>{ev.decision}</strong> · {ev.reason} ({ev.reviewer_id})
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
