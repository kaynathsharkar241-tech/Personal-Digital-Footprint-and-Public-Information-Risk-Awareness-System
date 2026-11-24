import React, { useEffect, useState } from 'react';
import { KeyRound, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react';
import { apiRequest } from '../lib/api.ts';
import type { UserState } from '../lib/types.ts';

interface PasskeyRow {
  id: number;
  label: string;
  created_at: string;
  last_used_at: string | null;
}

interface SettingsViewProps {
  user: UserState;
  onUserUpdated: (user: UserState) => void;
  onAccountDeleted: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  user,
  onUserUpdated,
  onAccountDeleted,
}) => {
  const [fullName, setFullName] = useState(user.name);
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [deletePassword, setDeletePassword] = useState('');

  const [passkeys, setPasskeys] = useState<PasskeyRow[]>([]);
  const [newCodes, setNewCodes] = useState<string[] | null>(null);
  const [googleStatus, setGoogleStatus] = useState<{ configured: boolean; reason: string } | null>(
    null
  );
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadPasskeys = async () => {
    try {
      const res = await apiRequest<{ passkeys: PasskeyRow[] }>('/api/auth/passkeys');
      setPasskeys(res.passkeys);
    } catch {
      // silent
    }
  };

  useEffect(() => {
    loadPasskeys();
    apiRequest<{ configured: boolean; reason: string }>('/api/auth/google/status')
      .then((res) => setGoogleStatus(res))
      .catch(() => setGoogleStatus({ configured: false, reason: 'Status unavailable.' }));

    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      const data = event.data as
        | { type?: string; ok?: boolean; mode?: string; user?: UserState; error?: string; message?: string }
        | undefined;
      if (!data || data.type !== 'pm_google_auth' || data.mode !== 'link') return;
      if (!data.ok || !data.user) {
        setError(data.error || 'Could not link Google account.');
        return;
      }
      onUserUpdated(data.user);
      setMsg(data.message || 'Google account linked.');
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [onUserUpdated]);

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setMsg(null);
    try {
      const res = await apiRequest<{ ok: boolean; user: UserState }>('/api/settings/profile', {
        method: 'PATCH',
        body: JSON.stringify({ fullName }),
      });
      onUserUpdated(res.user);
      setMsg('Display name updated.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Profile update failed.');
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setMsg(null);
    try {
      await apiRequest('/api/settings/password', {
        method: 'POST',
        body: JSON.stringify({ oldPassword, newPassword }),
      });
      setOldPassword('');
      setNewPassword('');
      setMsg('Password updated.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Password change failed.');
    }
  };

  const handleDeletePasskey = async (id: number) => {
    setError(null);
    try {
      const res = await apiRequest<{ ok: boolean; user: UserState }>(`/api/auth/passkeys/${id}`, {
        method: 'DELETE',
      });
      onUserUpdated(res.user);
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove passkey.');
    }
  };

  const handleRegenerateCodes = async () => {
    setError(null);
    setMsg(null);
    try {
      const res = await apiRequest<{ recoveryCodes: string[]; user: UserState }>(
        '/api/auth/recovery-codes/regenerate',
        { method: 'POST' }
      );
      setNewCodes(res.recoveryCodes);
      onUserUpdated(res.user);
      setMsg('8 new single-use recovery codes generated. Previous codes are invalidated.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not regenerate recovery codes.');
    }
  };

  const handleDeleteAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await apiRequest('/api/settings/account', {
        method: 'DELETE',
        body: JSON.stringify({ password: deletePassword }),
      });
      onAccountDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Account deletion failed.');
    }
  };

  const handleLinkGoogle = async () => {
    setError(null);
    setMsg(null);
    try {
      const res = await apiRequest<{ url: string }>('/api/auth/google/url?mode=link');
      const popup = window.open(res.url, 'pm_google_link', 'width=520,height=640');
      if (!popup) {
        setError('Popup window was blocked. Allow popups to link your Google account.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not initiate Google linking.');
    }
  };

  const handleUnlinkGoogle = async () => {
    setError(null);
    setMsg(null);
    try {
      const res = await apiRequest<{ ok: boolean; user: UserState }>('/api/auth/google/link', {
        method: 'DELETE',
      });
      onUserUpdated(res.user);
      setMsg('Google account link removed.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not unlink Google account.');
    }
  };

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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Profile */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <h2 className="text-base font-semibold">Profile Information</h2>
          <form onSubmit={handleSaveProfile} className="space-y-4">
            <div>
              <label className="block text-xs font-medium mb-1">Display Name</label>
              <input
                type="text"
                required
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Account Email</label>
              <input
                type="text"
                disabled
                value={user.email}
                className="w-full rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950/60 px-3 py-2 text-sm font-mono text-slate-500"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-[#15395A] text-white text-xs font-medium cursor-pointer"
            >
              Update Profile
            </button>
          </form>
        </section>

        {/* Password */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <h2 className="text-base font-semibold">Change Password</h2>
          <form onSubmit={handleChangePassword} className="space-y-4">
            <div>
              <label className="block text-xs font-medium mb-1">Current Password</label>
              <input
                type="password"
                required
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">New Password (12+ characters)</label>
              <input
                type="password"
                required
                minLength={12}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-xs font-medium cursor-pointer"
            >
              Update Password
            </button>
          </form>
        </section>
      </div>

      {/* Recovery Codes & Passkeys */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold">Single-Use Recovery Codes</h2>
              <p className="text-xs text-slate-500">
                Remaining unused codes:{' '}
                <span className="font-mono tabular-nums font-semibold">
                  {user.recoveryCodesRemaining}
                </span>
              </p>
            </div>
            <button
              type="button"
              onClick={handleRegenerateCodes}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 dark:border-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Regenerate 8 Codes
            </button>
          </div>
          {newCodes && (
            <div className="rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50/70 dark:bg-amber-950/30 p-4 space-y-2">
              <div className="text-xs font-semibold">
                Save these new recovery codes offline now — they are only shown once:
              </div>
              <div className="grid grid-cols-2 gap-2 font-mono text-xs select-all">
                {newCodes.map((c) => (
                  <div
                    key={c}
                    className="rounded bg-white dark:bg-slate-900 px-2.5 py-1.5 border border-slate-200 dark:border-slate-700"
                  >
                    {c}
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold">Registered Passkeys ({passkeys.length})</h2>
            <KeyRound className="w-4 h-4 text-slate-400" />
          </div>
          {passkeys.length === 0 ? (
            <p className="text-xs text-slate-500">
              No passkeys registered. Register one from Identity Verification.
            </p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {passkeys.map((pk) => (
                <div key={pk.id} className="py-2.5 flex items-center justify-between gap-3 text-xs">
                  <div>
                    <div className="font-medium">{pk.label}</div>
                    <div className="font-mono text-[11px] text-slate-400">
                      Added {pk.created_at.slice(0, 10)}
                      {pk.last_used_at ? ` · Last used ${pk.last_used_at.slice(0, 10)}` : ''}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleDeletePasskey(pk.id)}
                    className="text-red-600 dark:text-red-400 hover:underline inline-flex items-center gap-1 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Optional Google OpenID Connect Linking */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">Optional Google OpenID Connect Sign-In</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Status:{' '}
            <span className="font-medium text-slate-700 dark:text-slate-300">
              {user.googleLinked ? 'Linked to Google subject ID' : 'Not linked'}
            </span>
            {googleStatus && !googleStatus.configured && (
              <> · Server credentials (<span className="font-mono">GOOGLE_CLIENT_ID</span> / <span className="font-mono">GOOGLE_CLIENT_SECRET</span>) unset</>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {user.googleLinked && (
            <button
              type="button"
              onClick={handleUnlinkGoogle}
              className="px-3.5 py-2 rounded-lg border border-red-300 text-red-600 dark:border-red-900 dark:text-red-400 text-xs font-medium hover:bg-red-50 dark:hover:bg-red-950/30 whitespace-nowrap cursor-pointer"
            >
              Unlink Google
            </button>
          )}
          {googleStatus?.configured && !user.googleLinked && (
            <button
              type="button"
              onClick={handleLinkGoogle}
              className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-xs font-medium whitespace-nowrap cursor-pointer"
            >
              Link Google Account
            </button>
          )}
        </div>
      </section>

      {/* Cascading Account Deletion */}
      <section className="rounded-xl border border-red-200 dark:border-red-900/60 bg-white dark:bg-slate-900 p-6 space-y-4">
        <div className="flex items-start gap-2.5">
          <ShieldAlert className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
          <div>
            <h2 className="text-base font-semibold text-red-700 dark:text-red-400">
              Permanently Delete Account &amp; Encrypted Vault
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              Deletes your profile, encrypted enrollment selfie, monitoring photos, studio images, scan findings, cases, and encrypted evidence files immediately.
            </p>
          </div>
        </div>
        <form onSubmit={handleDeleteAccount} className="flex flex-wrap items-center gap-3">
          <input
            type="password"
            required
            value={deletePassword}
            onChange={(e) => setDeletePassword(e.target.value)}
            placeholder="Confirm with your password"
            className="flex-1 min-w-[220px] max-w-sm rounded-lg border border-red-300 dark:border-red-900 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
          />
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-medium cursor-pointer"
          >
            Delete Account Forever
          </button>
        </form>
      </section>
    </div>
  );
};
