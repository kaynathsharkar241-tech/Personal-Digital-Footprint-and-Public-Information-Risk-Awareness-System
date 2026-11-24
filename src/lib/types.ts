export interface UserState {
  id: number;
  name: string;
  email: string;
  createdAt: string;
  emailVerified: boolean;
  emailVerifiedAt: string | null;
  selfieStatus: 'missing' | 'pending_review' | 'approved' | 'rejected';
  selfieConsentAt: string | null;
  selfieReviewedAt: string | null;
  selfieReviewerNote: string;
  aiBiometricConsent: boolean;
  aiBiometricConsentAt: string | null;
  latestLiveness: {
    id: number;
    status: string;
    verification_method: string;
    created_at: string;
    completed_at: string | null;
  } | null;
  hasFallbackPin: boolean;
  passkeyCount: number;
  recoveryCodesRemaining: number;
  liveScanReady: boolean;
  googleLinked?: boolean;
}

export interface PriorityWeights {
  confidence_weight: number;
  severity_weight: number;
  recency_weight: number;
}

export interface Finding {
  id: number;
  scan_id: number;
  title: string;
  category: string;
  source_name: string;
  source: string;
  found_at: string;
  risk: 'High' | 'Medium' | 'Low';
  evidence: string;
  explanation: string;
  ai_advice: string;
  confidence: number;
  severity: number;
  recency_score: number;
  priority: number;
  verification_status: 'Unverified' | 'Verified Match' | 'False Positive';
  user_verified: number;
  review_note?: string;
  reviewed_at?: string | null;
}

export interface FindingReviewEvent {
  id: number;
  finding_id: number;
  previous_status: string;
  new_status: string;
  note: string;
  reviewed_at: string;
}

export interface ProviderRunSummary {
  providerId: string;
  providerName: string;
  categoryFocus: string;
  status: 'ok' | 'unavailable' | 'rate_limited' | 'error' | 'skipped';
  findingsCount: number;
  cached: boolean;
  latencyMs: number;
  requiresKey: boolean;
  keyEnvVar?: string;
  message: string;
}

export interface ProviderCatalogItem {
  id: string;
  name: string;
  categoryFocus: string;
  description: string;
  freeTierLimit: string;
  requiresKey: boolean;
  keyEnvVar?: string;
  configured: boolean;
  isPaidTier: boolean;
  requestsToday: number;
  cacheHits: number;
  lastStatus: string;
  lastError: string;
  lastCheckedAt: string | null;
  rateLimitRemaining: string;
}

export interface SkippedProviderInfo {
  providerId: string;
  providerName: string;
  reason: string;
}

export interface ScanRecord {
  id: number;
  created_at: string;
  mode: string;
  status: string;
  findings_count: number;
  authorized_at?: string;
  providerSummary?: ProviderRunSummary[];
  incompleteCoverage?: boolean;
  unavailableCount?: number;
  skippedCount?: number;
  hasSkippedProviders?: boolean;
  skippedProviders?: SkippedProviderInfo[];
  totalProviders?: number;
}

export interface SchedulerStatus {
  active: boolean;
  currentlyRunning: boolean;
  lastTickAt: string | null;
  lastTickSummary: { processedUsers: number; newFindings: number; errors: number } | null;
  nextDueAt: string | null;
  lastScheduledScanAt: string | null;
}

export interface DashboardData {
  exposureScore: number | null;
  totalFindings: number;
  riskCounts: { High: number; Medium: number; Low: number };
  reviewCounts?: { unverified: number; verifiedMatch: number; safeLibrary: number };
  categoryCounts: Record<string, number>;
  lastScan: ScanRecord | null;
  priorityWeights: PriorityWeights;
  notifications: Array<{ id: number; body: string; created_at: string; read_at: string | null }>;
  openCasesCount: number;
  resolvedCasesCount?: number;
  photosCount: number;
  user: UserState;
}

export interface ResponseGuide {
  summary: string;
  steps: string[];
  resourceLabel: string;
  resourceUrl: string;
}

export interface CaseItem {
  id: number;
  title: string;
  category: string;
  description: string;
  url: string;
  occurred_at: string | null;
  status: 'Open' | 'Under Review' | 'Resolved';
  notes: string;
  resolution_summary?: string;
  resolved_at?: string | null;
  ai_draft: string;
  created_at: string;
}

export interface CaseEvent {
  id: number;
  case_id: number;
  event_type: string;
  status: string;
  summary: string;
  created_at: string;
}

export interface EvidenceItem {
  id: number;
  name: string;
  mime: string;
  created_at: string;
}

export interface MonitoringPhoto {
  id: number;
  label: string;
  status: 'pending_review' | 'approved' | 'rejected';
  reviewer_note: string;
  reviewed_at: string | null;
  match_result: string;
  match_reason: string | null;
  match_confidence: number | null;
  matched_at: string | null;
  created_at: string;
}

export interface StudioImageItem {
  id: number;
  prompt: string;
  mode: 'create' | 'edit';
  model: string;
  aspect_ratio: string;
  image_size: string;
  mime: string;
  assistant_note: string;
  created_at: string;
}
