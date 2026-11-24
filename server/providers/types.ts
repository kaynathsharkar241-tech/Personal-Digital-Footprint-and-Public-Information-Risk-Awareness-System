export const CATEGORIES = [
  'Contact Details',
  'Social Profiles and Images',
  'Breached Credentials',
  'Public Records',
  'Possible Impersonation',
] as const;

export type Category = (typeof CATEGORIES)[number];

export type RiskSeverity = 'High' | 'Medium' | 'Low';
export type VerificationStatus = 'Unverified' | 'Verified Match' | 'False Positive';

export interface ScanContext {
  userId: number;
  email: string;
  fullName: string;
  username: string;
  terms: string[];
  domains: string[];
  authorizedAt: string;
}

export interface NormalizedFinding {
  title: string;
  category: Category;
  sourceName: string;
  sourceUrl: string;
  foundAt: string;
  evidence: string;
  explanation: string;
  confidence: number;
  severity: number;
  recencyScore: number;
  risk: RiskSeverity;
  verificationStatus: VerificationStatus;
}

export type ProviderStatus =
  | 'ok'
  | 'unavailable'
  | 'rate_limited'
  | 'error'
  | 'skipped';

export interface ProviderResult {
  providerId: string;
  providerName: string;
  categoryFocus: string;
  requiresKey: boolean;
  keyEnvVar?: string;
  freeTierLimit: string;
  status: ProviderStatus;
  findings: NormalizedFinding[];
  message: string;
  cached: boolean;
  latencyMs: number;
  rateLimitRemaining?: string;
  rateLimitReset?: string;
}

export interface OsintProvider {
  id: string;
  name: string;
  categoryFocus: string;
  description: string;
  freeTierLimit: string;
  requiresKey: boolean;
  keyEnvVar?: string;
  minIntervalMs: number;
  isConfigured(): boolean;
  run(ctx: ScanContext): Promise<ProviderResult>;
}
