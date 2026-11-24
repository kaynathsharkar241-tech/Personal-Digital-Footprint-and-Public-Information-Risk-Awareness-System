import React, { useEffect, useRef, useState } from 'react';
import { Camera, CheckCircle2, KeyRound, Lock, Shield, Upload, UserCheck } from 'lucide-react';
import { apiRequest, authenticateWithPasskey, fileToDataUrl, setSessionToken } from '../lib/api.ts';
import type { UserState } from '../lib/types.ts';

interface AuthViewProps {
  onAuthenticated: (user: UserState, recoveryCodes?: string[], previewVerifyToken?: string | null) => void;
  onOpenReviewer: () => void;
}

export const AuthView: React.FC<AuthViewProps> = ({ onAuthenticated, onOpenReviewer }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [loginMethod, setLoginMethod] = useState<'password' | 'pin' | 'recovery'>('password');

  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginSecret, setLoginSecret] = useState('');

  // Register fields
  const [fullName, setFullName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [consent, setConsent] = useState(false);
  const [aiConsent, setAiConsent] = useState(false);
  const [selfieDataUrl, setSelfieDataUrl] = useState('');

  // Camera state
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [cameraActive, setCameraActive] = useState(false);
  const [cameraStatus, setCameraStatus] = useState('Start camera or upload a clear selfie photo.');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [googleStatus, setGoogleStatus] = useState<{ configured: boolean; reason: string } | null>(
    null
  );

  const stopCamera = () => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    setCameraActive(false);
  };

  useEffect(() => {
    apiRequest<{ configured: boolean; reason: string }>('/api/auth/google/status')
      .then((res) => setGoogleStatus(res))
      .catch(() => setGoogleStatus({ configured: false, reason: 'Status unavailable.' }));

    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      const data = event.data as
        | { type?: string; ok?: boolean; token?: string; user?: UserState; error?: string }
        | undefined;
      if (!data || data.type !== 'pm_google_auth') return;
      setLoading(false);
      if (!data.ok || !data.token || !data.user) {
        setError(data.error || 'Google sign-in failed.');
        return;
      }
      setSessionToken(data.token);
      onAuthenticated(data.user);
    };
    window.addEventListener('message', onMessage);
    return () => {
      stopCamera();
      window.removeEventListener('message', onMessage);
    };
  }, [onAuthenticated]);

  const startCamera = async () => {
    setError(null);
    if (!navigator.mediaDevices?.getUserMedia) {
      setCameraStatus('Camera API unavailable here. Use the photo upload option below.');
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } },
        audio: false,
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }
      setCameraActive(true);
      setCameraStatus('Camera active. Position your face in the frame and capture.');
    } catch {
      setCameraStatus('Camera access denied or unavailable. You can upload a JPEG/PNG selfie instead.');
    }
  };

  const captureSelfie = () => {
    const video = videoRef.current;
    if (!video || !video.videoWidth) return;
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.drawImage(video, 0, 0);
    const dataUrl = canvas.toDataURL('image/jpeg', 0.9);
    setSelfieDataUrl(dataUrl);
    stopCamera();
    setCameraStatus('Enrollment selfie captured.');
  };

  const handleUploadSelfie = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const url = await fileToDataUrl(file);
      setSelfieDataUrl(url);
      stopCamera();
      setCameraStatus(`Selected ${file.name} as enrollment selfie.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not read image.');
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await apiRequest<{ token: string; user: UserState }>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: loginEmail,
          method: loginMethod,
          secret: loginSecret,
        }),
      });
      setSessionToken(res.token);
      onAuthenticated(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed.');
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeySignIn = async () => {
    if (!loginEmail.trim()) {
      setError('Enter your registered email address before using a passkey.');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = (await authenticateWithPasskey(loginEmail.trim().toLowerCase())) as {
        token: string;
        user: UserState;
      };
      setSessionToken(res.token);
      onAuthenticated(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await apiRequest<{ url: string }>('/api/auth/google/url?mode=login');
      const popup = window.open(res.url, 'pm_google_auth', 'width=520,height=640');
      if (!popup) {
        setLoading(false);
        setError('Popup window was blocked by the browser. Allow popups to use Google Sign-In.');
      }
    } catch (err) {
      setLoading(false);
      setError(err instanceof Error ? err.message : 'Google Sign-In unavailable.');
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Password and confirmation do not match.');
      return;
    }
    if (!selfieDataUrl) {
      setError('Capture or upload an enrollment selfie.');
      return;
    }
    if (!consent) {
      setError('Biometric enrollment consent is required.');
      return;
    }

    setLoading(true);
    try {
      const res = await apiRequest<{
        token: string;
        user: UserState;
        recoveryCodes: string[];
        previewVerificationToken: string | null;
      }>('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          fullName,
          email: regEmail,
          password,
          biometricConsent: consent,
          aiBiometricConsent: aiConsent,
          selfieDataUrl,
        }),
      });
      setSessionToken(res.token);
      onAuthenticated(res.user, res.recoveryCodes, res.previewVerificationToken);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between gap-8">
          <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
            <Shield className="w-5 h-5 text-[#15395A] dark:text-sky-400" />
            <span className="font-display text-lg font-bold tracking-tight">Privacy Monitor</span>
          </div>
          <div className="flex items-center gap-4 shrink-0">
            <button
              type="button"
              onClick={onOpenReviewer}
              className="text-sm font-medium text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white underline-offset-4 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
            >
              Reviewer Audit Console
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
        <section className="lg:col-span-5 space-y-6 pt-2">
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-[#15395A] dark:text-sky-400">
              Personal Digital Footprint &amp; Risk Awareness
            </p>
            <h1 className="mt-2 text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 dark:text-slate-50 text-balance">
              See what is public about you before it is misused.
            </h1>
            <p className="mt-4 text-base text-slate-600 dark:text-slate-300 leading-relaxed">
              Privacy Monitor brings identifier scanning, weighted exposure scoring, AI-assisted plain-language risk explanations, response playbooks, and encrypted case evidence into one self-service progressive web app.
            </p>
          </div>

          <div className="border-t border-slate-200 dark:border-slate-800 pt-6 space-y-4">
            <div className="flex items-start gap-3">
              <UserCheck className="w-4 h-4 mt-1 text-[#15395A] dark:text-sky-400 shrink-0" />
              <div>
                <h2 className="text-sm font-semibold">Identity-gated monitoring</h2>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Enrollment selfies and uploaded photos are encrypted at rest with AES-256-GCM; live web scans require verified ownership.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <KeyRound className="w-4 h-4 mt-1 text-[#15395A] dark:text-sky-400 shrink-0" />
              <div>
                <h2 className="text-sm font-semibold">Passkeys, fallback PIN &amp; recovery codes</h2>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Register a WebAuthn passkey, configure a salted fallback PIN, and keep single-use recovery codes for account access.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Lock className="w-4 h-4 mt-1 text-[#15395A] dark:text-sky-400 shrink-0" />
              <div>
                <h2 className="text-sm font-semibold">Real OSINT intelligence &amp; transparent coverage</h2>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Every scan queries live public APIs only after explicit authorization, never fabricates results, and highlights any unavailable providers.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 sm:p-8">
          <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg w-fit mb-6">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
                stopCamera();
              }}
              className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                mode === 'login'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                mode === 'register'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Create Account
            </button>
          </div>

          {error && (
            <div
              role="alert"
              className="mb-5 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 px-4 py-3 text-sm text-red-800 dark:text-red-200"
            >
              {error}
            </div>
          )}

          {mode === 'login' ? (
            <form onSubmit={handleLogin} className="space-y-5">
              <div>
                <label htmlFor="login-email" className="block text-sm font-medium mb-1.5">
                  Email address
                </label>
                <input
                  id="login-email"
                  type="email"
                  required
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#15395A] dark:focus:ring-sky-500"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm font-medium">Authentication method</span>
                  <div className="flex items-center gap-1 p-0.5 bg-slate-100 dark:bg-slate-800 rounded-md">
                    {(['password', 'pin', 'recovery'] as const).map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => {
                          setLoginMethod(m);
                          setLoginSecret('');
                        }}
                        className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer ${
                          loginMethod === m
                            ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                            : 'text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        {m === 'password' ? 'Password' : m === 'pin' ? 'Fallback PIN' : 'Recovery Code'}
                      </button>
                    ))}
                  </div>
                </div>
                <input
                  type={loginMethod === 'recovery' ? 'text' : 'password'}
                  required
                  value={loginSecret}
                  onChange={(e) => setLoginSecret(e.target.value)}
                  placeholder={
                    loginMethod === 'password'
                      ? 'Enter your password'
                      : loginMethod === 'pin'
                      ? '4–8 digit fallback PIN'
                      : 'PM-XXXX-XXXX'
                  }
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#15395A] dark:focus:ring-sky-500"
                />
              </div>

              <div className="flex flex-wrap items-center gap-3 pt-1">
                <button
                  type="submit"
                  disabled={loading}
                  className="px-5 py-2.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white text-sm font-medium transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {loading ? 'Signing in...' : 'Sign In'}
                </button>
                <button
                  type="button"
                  disabled={loading}
                  onClick={handlePasskeySignIn}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-sm font-medium transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <KeyRound className="w-4 h-4" />
                  Sign In with Passkey
                </button>
              </div>

              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <span className="text-xs font-medium text-slate-600 dark:text-slate-400">
                    Optional Google OpenID Connect
                  </span>
                  {googleStatus?.configured ? (
                    <button
                      type="button"
                      disabled={loading}
                      onClick={handleGoogleSignIn}
                      className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-xs font-medium transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Sign In with Google
                    </button>
                  ) : (
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      Not configured on this host (optional)
                    </span>
                  )}
                </div>
                {googleStatus && !googleStatus.configured && (
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Google Sign-In remains optional and disabled when{' '}
                    <span className="font-mono">GOOGLE_CLIENT_ID</span> and{' '}
                    <span className="font-mono">GOOGLE_CLIENT_SECRET</span> are unset. Use Password, Fallback PIN, Recovery Code, or Passkey above.
                  </p>
                )}
              </div>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="reg-name" className="block text-sm font-medium mb-1">
                    Full name
                  </label>
                  <input
                    id="reg-name"
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Alex Rahman"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#15395A]"
                  />
                </div>
                <div>
                  <label htmlFor="reg-email" className="block text-sm font-medium mb-1">
                    Email address
                  </label>
                  <input
                    id="reg-email"
                    type="email"
                    required
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="alex@example.com"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#15395A]"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="reg-pass" className="block text-sm font-medium mb-1">
                    Password (12+ chars)
                  </label>
                  <input
                    id="reg-pass"
                    type="password"
                    required
                    minLength={12}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Minimum 12 characters"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#15395A]"
                  />
                </div>
                <div>
                  <label htmlFor="reg-confirm" className="block text-sm font-medium mb-1">
                    Confirm password
                  </label>
                  <input
                    id="reg-confirm"
                    type="password"
                    required
                    minLength={12}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat password"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#15395A]"
                  />
                </div>
              </div>

              <div className="border border-slate-200 dark:border-slate-800 rounded-lg p-4 space-y-3 bg-slate-50/70 dark:bg-slate-950/60">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold">Enrollment Selfie (Encrypted at Rest)</h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">{cameraStatus}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {!cameraActive ? (
                      <button
                        type="button"
                        onClick={startCamera}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium hover:bg-slate-50 cursor-pointer"
                      >
                        <Camera className="w-3.5 h-3.5" />
                        Start Camera
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={captureSelfie}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#15395A] text-white text-xs font-medium cursor-pointer"
                      >
                        <Camera className="w-3.5 h-3.5" />
                        Capture Selfie
                      </button>
                    )}
                    <label className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium hover:bg-slate-50 cursor-pointer">
                      <Upload className="w-3.5 h-3.5" />
                      Upload Photo
                      <input
                        type="file"
                        accept="image/jpeg,image/png,image/webp"
                        onChange={handleUploadSelfie}
                        className="sr-only"
                      />
                    </label>
                  </div>
                </div>

                {cameraActive && (
                  <video
                    ref={videoRef}
                    autoPlay
                    playsInline
                    muted
                    className="w-full max-h-56 rounded-lg bg-slate-900 object-cover"
                  />
                )}

                {selfieDataUrl && (
                  <div className="flex items-center gap-3">
                    <img
                      src={selfieDataUrl}
                      alt="Captured enrollment selfie"
                      className="w-20 h-20 rounded-lg object-cover border border-slate-200 dark:border-slate-700"
                    />
                    <div className="text-xs text-emerald-700 dark:text-emerald-400 flex items-center gap-1.5 font-medium">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Selfie ready for encrypted enrollment</span>
                    </div>
                  </div>
                )}
              </div>

              <label className="flex items-start gap-2.5 text-xs text-slate-600 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(e) => setConsent(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300"
                />
                <span>
                  I consent to storing this encrypted reference photo locally for identity verification and monitoring photo comparison. I understand I can delete my account and all encrypted data at any time.
                </span>
              </label>

              <label className="flex items-start gap-2.5 text-xs text-slate-600 dark:text-slate-300 cursor-pointer rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3">
                <input
                  type="checkbox"
                  checked={aiConsent}
                  onChange={(e) => setAiConsent(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300"
                />
                <span>
                  <strong>Optional third-party AI visual screening:</strong> Allow sending my enrollment selfie and monitoring/sequence photos to the external Google Gemini API for automated 1:1 facial similarity comparison. If unchecked, images stay encrypted locally and are reviewed manually.
                </span>
              </label>

              <button
                type="submit"
                disabled={loading}
                className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white text-sm font-medium transition-colors disabled:opacity-50 cursor-pointer"
              >
                {loading ? 'Creating account...' : 'Create Account & Generate Recovery Codes'}
              </button>
            </form>
          )}
        </section>
      </main>
    </div>
  );
};
