import type { MatchEvidence } from './relevance.ts';

export function describeEvidence(match: MatchEvidence): string {
  if (match.relevance === 'none') {
    return 'No monitored identifier detected.';
  }

  const labels: Record<string, string> = {
    fullName: 'full name',
    email: 'email address',
    username: 'username',
    domain: 'domain'
  };

  const matched = match.matchedIdentifiers
    .map(key => labels[key] || key)
    .join(', ');

  return (
    `Matching evidence: ${matched}. ` +
    'Personal identity and harmful exposure remain unverified.'
  );
}

export function getEvidenceLabel(match: MatchEvidence): string {
  switch (match.relevance) {
    case 'multiple_identifiers':
      return 'Multiple identifiers detected';
    case 'single_identifier':
      return 'Potential match';
    default:
      return 'No relevant evidence';
  }
}
