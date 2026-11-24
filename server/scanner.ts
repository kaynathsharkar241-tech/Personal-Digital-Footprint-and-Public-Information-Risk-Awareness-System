export { CATEGORIES, type Category } from './providers/types.ts';
import type { Category } from './providers/types.ts';

export const QUESTIONS = [
  { id: 101, weight: 3, text: 'How often do you use the same password on different accounts?', options: [{ value: 0, label: 'Never; every account has its own password' }, { value: 1, label: 'Sometimes' }, { value: 2, label: 'Often' }] },
  { id: 102, weight: 3, text: 'Do you use two-factor authentication (2FA) on your important accounts?', options: [{ value: 0, label: 'Yes, on all important accounts' }, { value: 1, label: 'On some accounts' }, { value: 2, label: 'No' }] },
  { id: 103, weight: 3, text: 'Can people see your phone number, email, or home address on your public profiles?', options: [{ value: 0, label: 'No, none are visible' }, { value: 1, label: 'One or two are visible' }, { value: 2, label: 'Yes, most are visible' }] },
  { id: 104, weight: 2, text: 'How are your social media profiles set up?', options: [{ value: 0, label: 'Private; I review settings regularly' }, { value: 1, label: 'Partly public' }, { value: 2, label: 'Fully public' }] },
  { id: 105, weight: 2, text: 'How often do you use public Wi-Fi without a VPN?', options: [{ value: 0, label: 'Never' }, { value: 1, label: 'Sometimes' }, { value: 2, label: 'Often' }] },
  { id: 106, weight: 1, text: 'Do you use a password manager?', options: [{ value: 0, label: 'Yes' }, { value: 1, label: 'I am considering it' }, { value: 2, label: 'No' }] },
  { id: 107, weight: 1, text: 'How often do you delete old accounts and review app permissions?', options: [{ value: 0, label: 'A few times a year' }, { value: 1, label: 'Rarely' }, { value: 2, label: 'Never' }] },
] as const;

export const RESPONSE_GUIDES: Record<
  Category,
  { summary: string; steps: string[]; resourceLabel: string; resourceUrl: string }
> = {
  'Contact Details': {
    summary: 'Remove exposed phone numbers, addresses, and personal emails from public pages and search indexes.',
    steps: [
      'Edit public social bios and directory profiles to hide direct phone numbers and home addresses.',
      'Submit removal requests for pages displaying sensitive contact info through search engine removal tools.',
      'Use an alias or dedicated secondary address for public registrations and newsletters.',
    ],
    resourceLabel: 'Google Results About You Help',
    resourceUrl: 'https://support.google.com/websearch/answer/12719076',
  },
  'Social Profiles and Images': {
    summary: 'Restrict profile visibility, strip location metadata from uploads, and report unauthorized reposts.',
    steps: [
      'Audit follower/friend visibility settings on major social platforms and disable search-engine indexing of profiles.',
      'Strip EXIF geolocation metadata before posting photos online.',
      'Save the offending URL and timestamp, then file a privacy/copyright or unauthorized-image report with the host.',
    ],
    resourceLabel: 'Review Platform Privacy Controls',
    resourceUrl: 'https://www.eff.org/issues/privacy',
  },
  'Breached Credentials': {
    summary: 'Rotate compromised passwords immediately, enable hardware or app-based MFA, and audit active sessions.',
    steps: [
      'Change the password on the breached service and any other account that ever reused that password.',
      'Enable multi-factor authentication (passkey or authenticator app, avoiding SMS when possible).',
      'Revoke unrecognized OAuth third-party app permissions and active login sessions.',
    ],
    resourceLabel: 'Have I Been Pwned',
    resourceUrl: 'https://haveibeenpwned.com/',
  },
  'Public Records': {
    summary: 'Contact publishers regarding redaction or correction policies and avoid amplifying sensitive URLs.',
    steps: [
      'Verify whether the record actually refers to you or someone with a similar name before requesting removal.',
      'Contact the publisher or data broker using their documented opt-out or redaction process.',
      'Document correspondence and keep copies in your encrypted Case Tracker.',
    ],
    resourceLabel: 'Data Removal Request Guide',
    resourceUrl: 'https://privacyrights.org/',
  },
  'Possible Impersonation': {
    summary: 'Preserve evidence immediately, report the account through official impersonation channels, and warn contacts.',
    steps: [
      'Capture screenshots and exact URLs, then upload them into an encrypted Case in this workspace.',
      'File an impersonation report with the hosting platform using their identity verification workflow.',
      'Notify close contacts if the impersonating profile is sending messages or fake endorsements.',
    ],
    resourceLabel: 'Report Impersonation Guidance',
    resourceUrl: 'https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams',
  },
};

export function computePriority(
  confidence: number,
  severity: number,
  recency: number,
  weights: { confidence_weight: number; severity_weight: number; recency_weight: number }
): number {
  const raw =
    weights.confidence_weight * confidence +
    weights.severity_weight * severity +
    weights.recency_weight * recency;
  return Math.round(raw * 1000) / 1000;
}
