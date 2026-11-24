/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useState } from 'react';
import {
  Camera,
  ClipboardCheck,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Radar,
  Settings,
  Shield,
  ShieldCheck,
  Sun,
  UserCheck,
  X,
} from 'lucide-react';
import { apiRequest, setReviewerToken, setSessionToken } from './lib/api.ts';
import type { DashboardData, UserState } from './lib/types.ts';
import { AuthView } from './components/AuthView.tsx';
import { DashboardView } from './components/DashboardView.tsx';
import { IdentityView } from './components/IdentityView.tsx';
import { MonitoringScansView } from './components/MonitoringScansView.tsx';
import { QuestionnaireView } from './components/QuestionnaireView.tsx';
import { PhotosView } from './components/PhotosView.tsx';
import { CasesView } from './components/CasesView.tsx';
import { SettingsView } from './components/SettingsView.tsx';
import { ReviewerConsoleView } from './components/ReviewerConsoleView.tsx';
import { OfflineIndicator, PWAInstallButton } from './components/PWAInstallButton.tsx';

type TabKey =
  | 'dashboard'
  | 'identity'
  | 'monitoring'
  | 'questionnaire'
  | 'photos'
  | 'cases'
  | 'settings';

const NAV_ITEMS: Array<{ key: TabKey; label: string; icon: React.FC<{ className?: string }> }> = [
  { key: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { key: 'identity', label: 'Identity Verification', icon: UserCheck },
  { key: 'monitoring', label: 'Monitoring & Scans', icon: Radar },
  { key: 'questionnaire', label: 'Exposure & Guides', icon: ClipboardCheck },
  { key: 'photos', label: 'Photo Vault', icon: Camera },
  { key: 'cases', label: 'Cases & Evidence', icon: FolderKanban },
  { key: 'settings', label: 'Account Settings', icon: Settings },
];

export default function App() {
  const [user, setUser] = useState<UserState | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [darkMode, setDarkMode] = useState(() => {
    try {
      return localStorage.getItem('pm_theme') === 'dark';
    } catch {
      return false;
    }
  });

  const [reviewerOpen, setReviewerOpen] = useState(false);
  const [recoveryCodesModal, setRecoveryCodesModal] = useState<string[] | null>(null);
  const [previewVerifyToken, setPreviewVerifyToken] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [casePrefill, setCasePrefill] = useState<{
    title: string;
    category: string;
    description: string;
    url: string;
  } | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) root.classList.add('dark');
    else root.classList.remove('dark');
    try {
      localStorage.setItem('pm_theme', darkMode ? 'dark' : 'light');
    } catch {
      // ignore storage errors
    }
  }, [darkMode]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (recoveryCodesModal) setRecoveryCodesModal(null);
      else if (mobileMenuOpen) setMobileMenuOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [recoveryCodesModal, mobileMenuOpen]);

  const refreshDashboard = useCallback(async () => {
    try {
      const data = await apiRequest<DashboardData>('/api/dashboard');
      setDashboard(data);
      setUser(data.user);
    } catch {
      // If session expired, clear local auth state cleanly
      setSessionToken(null);
      setUser(null);
      setDashboard(null);
    }
  }, []);

  useEffect(() => {
    if (user) {
      refreshDashboard();
    }
  }, [user?.id, refreshDashboard]);

  const handleAuthenticated = (
    nextUser: UserState,
    recoveryCodes?: string[],
    verifyToken?: string | null
  ) => {
    setUser(nextUser);
    setActiveTab('dashboard');
    if (recoveryCodes && recoveryCodes.length > 0) {
      setRecoveryCodesModal(recoveryCodes);
    }
    if (verifyToken) {
      setPreviewVerifyToken(verifyToken);
    }
  };

  const handleLogout = async () => {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      // ignore network error on sign out
    }
    setSessionToken(null);
    setReviewerToken(null);
    setUser(null);
    setDashboard(null);
    setPreviewVerifyToken(null);
    setRecoveryCodesModal(null);
  };

  const handleQuickDashboardScan = async () => {
    setScanning(true);
    try {
      await apiRequest('/api/scan', {
        method: 'POST',
        body: JSON.stringify({ authorized: true }),
      });
      await refreshDashboard();
    } finally {
      setScanning(false);
    }
  };

  const handleCreateCaseFromFinding = (prefill: {
    title: string;
    category: string;
    description: string;
    url: string;
  }) => {
    setCasePrefill(prefill);
    setActiveTab('cases');
  };

  const currentTitle = NAV_ITEMS.find((i) => i.key === activeTab)?.label || 'Overview';

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-[#15395A] focus:px-4 focus:py-2 focus:text-xs focus:font-semibold focus:text-white focus:shadow-lg"
      >
        Skip to main content
      </a>
      {!user ? (
        <AuthView
          onAuthenticated={handleAuthenticated}
          onOpenReviewer={() => setReviewerOpen(true)}
        />
      ) : (
        <div className="min-h-screen flex">
          {/* Desktop Sidebar */}
          <aside className="hidden lg:flex w-64 flex-col border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shrink-0">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center gap-2.5">
              <Shield className="w-5 h-5 text-[#15395A] dark:text-sky-400 shrink-0" />
              <span className="font-bold tracking-tight text-base whitespace-nowrap">
                Privacy Monitor
              </span>
            </div>

            <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Workspace navigation">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const active = activeTab === item.key;
                return (
                  <button
                    key={item.key}
                    type="button"
                    aria-current={active ? 'page' : undefined}
                    onClick={() => setActiveTab(item.key)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap cursor-pointer ${
                      active
                        ? 'bg-[#15395A] text-white dark:bg-sky-500/20 dark:text-sky-300'
                        : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>

            <div className="p-4 border-t border-slate-200 dark:border-slate-800 space-y-2">
              <button
                type="button"
                onClick={() => setReviewerOpen(true)}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-[#15395A] dark:text-sky-400 shrink-0" />
                <span>Reviewer Audit Console</span>
              </button>
              <button
                type="button"
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5 shrink-0" />
                <span>Sign Out</span>
              </button>
            </div>
          </aside>

          {/* Mobile Drawer */}
          {mobileMenuOpen && (
            <div className="fixed inset-0 z-40 lg:hidden flex">
              <div
                className="fixed inset-0 bg-slate-950/50"
                onClick={() => setMobileMenuOpen(false)}
              />
              <aside className="relative z-50 w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col">
                <div className="px-4 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold">
                    <Shield className="w-5 h-5 text-[#15395A] dark:text-sky-400" />
                    <span>Privacy Monitor</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setMobileMenuOpen(false)}
                    aria-label="Close navigation menu"
                    className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <nav className="flex-1 p-3 space-y-1" aria-label="Mobile navigation">
                  {NAV_ITEMS.map((item) => {
                    const Icon = item.icon;
                    const active = activeTab === item.key;
                    return (
                      <button
                        key={item.key}
                        type="button"
                        aria-current={active ? 'page' : undefined}
                        onClick={() => {
                          setActiveTab(item.key);
                          setMobileMenuOpen(false);
                        }}
                        className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium cursor-pointer ${
                          active
                            ? 'bg-[#15395A] text-white dark:bg-sky-500/20 dark:text-sky-300'
                            : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                        <span>{item.label}</span>
                      </button>
                    );
                  })}
                </nav>
                <div className="p-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
                  <button
                    type="button"
                    onClick={() => {
                      setMobileMenuOpen(false);
                      setReviewerOpen(true);
                    }}
                    className="w-full flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium cursor-pointer"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Reviewer Audit Console</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium text-slate-600 dark:text-slate-300 cursor-pointer"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              </aside>
            </div>
          )}

          {/* Main Content Area */}
          <div className="flex-1 flex flex-col min-w-0">
            <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-3.5">
              <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
                <div className="flex items-center gap-3 min-w-0">
                  <button
                    type="button"
                    onClick={() => setMobileMenuOpen(true)}
                    aria-label="Open navigation menu"
                    aria-expanded={mobileMenuOpen}
                    className="lg:hidden p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 cursor-pointer"
                  >
                    <Menu className="w-4 h-4" />
                  </button>
                  <div className="min-w-0">
                    <h1 className="text-base font-semibold text-slate-900 dark:text-slate-100 truncate">
                      {currentTitle}
                    </h1>
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                      {user.name} · <span className="font-mono">{user.email}</span>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <PWAInstallButton />
                  <button
                    type="button"
                    onClick={() => setDarkMode((d) => !d)}
                    aria-label={darkMode ? 'Switch to light theme' : 'Switch to dark theme'}
                    className="p-2 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer shrink-0"
                  >
                    {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </header>

            <main id="main-content" tabIndex={-1} className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 focus:outline-none">
              {activeTab === 'dashboard' && dashboard && (
                <DashboardView
                  data={dashboard}
                  onRefresh={refreshDashboard}
                  onNavigate={(tab) => setActiveTab(tab as TabKey)}
                  onRunScan={handleQuickDashboardScan}
                  scanning={scanning}
                />
              )}

              {activeTab === 'identity' && (
                <IdentityView
                  user={user}
                  previewVerifyToken={previewVerifyToken}
                  onUserUpdated={(u) => {
                    setUser(u);
                    refreshDashboard();
                  }}
                  onOpenReviewer={() => setReviewerOpen(true)}
                />
              )}

              {activeTab === 'monitoring' && (
                <MonitoringScansView
                  user={user}
                  onRefreshDashboard={refreshDashboard}
                  onCreateCaseFromFinding={handleCreateCaseFromFinding}
                />
              )}

              {activeTab === 'questionnaire' && (
                <QuestionnaireView onScoreSaved={refreshDashboard} />
              )}

              {activeTab === 'photos' && (
                <PhotosView
                  user={user}
                  onUserUpdated={(u) => {
                    setUser(u);
                    refreshDashboard();
                  }}
                  onRefreshDashboard={refreshDashboard}
                />
              )}

              {activeTab === 'cases' && (
                <CasesView
                  initialPrefill={casePrefill}
                  onClearPrefill={() => setCasePrefill(null)}
                  onRefreshDashboard={refreshDashboard}
                />
              )}

              {activeTab === 'settings' && (
                <SettingsView
                  user={user}
                  onUserUpdated={(u) => {
                    setUser(u);
                    refreshDashboard();
                  }}
                  onAccountDeleted={handleLogout}
                />
              )}
            </main>
          </div>
        </div>
      )}

      {/* One-Time Recovery Codes Modal upon registration */}
      {recoveryCodesModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Save Your Single-Use Recovery Codes"
          className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-xs flex items-center justify-center p-4"
        >
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
              Save Your 8 Single-Use Recovery Codes
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              Store these codes safely offline. Each code works once to recover access if you lose your password or passkey. They will not be displayed again unless you regenerate them in Account Settings.
            </p>
            <div className="grid grid-cols-2 gap-2 font-mono text-xs select-all">
              {recoveryCodesModal.map((code) => (
                <div
                  key={code}
                  className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-2 text-center font-semibold"
                >
                  {code}
                </div>
              ))}
            </div>
            <button
              type="button"
              onClick={() => setRecoveryCodesModal(null)}
              className="w-full rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white py-2.5 text-xs font-medium cursor-pointer"
            >
              I Have Saved My Recovery Codes
            </button>
          </div>
        </div>
      )}

      {reviewerOpen && (
        <ReviewerConsoleView
          onClose={() => setReviewerOpen(false)}
          onDecisionApplied={() => {
            if (user) refreshDashboard();
          }}
        />
      )}

      <OfflineIndicator />
    </div>
  );
}
