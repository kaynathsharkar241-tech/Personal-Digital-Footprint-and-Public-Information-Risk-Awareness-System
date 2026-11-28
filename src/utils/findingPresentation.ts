export function getFindingPresentation(
  verificationStatus: string
) {
  switch (verificationStatus) {
    case 'Verified Match':
      return {
        label: 'Verified Match',
        description: 'Confirmed relevant to your identity.',
        showPriority: true,
        includeInVerifiedCount: true
      };

    case 'False Positive':
      return {
        label: 'False Positive',
        description: 'Excluded from personal exposure assessment.',
        showPriority: false,
        includeInVerifiedCount: false
      };

    default:
      return {
        label: 'Potential Match',
        description: 'Identity and privacy risk remain unverified.',
        showPriority: false,
        includeInVerifiedCount: false
      };
  }
}

export function formatFindingPriority(
  priority: number | null | undefined,
  verificationStatus: string
): string {
  if (verificationStatus === 'False Positive') {
    return 'Excluded';
  }

  if (verificationStatus !== 'Verified Match') {
    return 'Not assessed';
  }

  if (
    typeof priority !== 'number' ||
    !Number.isFinite(priority) ||
    priority < 0 ||
    priority > 1
  ) {
    return 'Unavailable';
  }

  return `${priority.toFixed(3)} (heuristic)`;
}

export function formatFindingRisk(risk: string, verificationStatus: string): string {
  if (verificationStatus === 'False Positive') return 'Excluded';
  if (verificationStatus !== 'Verified Match') return 'Not assessed';
  return ['High', 'Medium', 'Low'].includes(risk) ? `${risk} (heuristic)` : 'Unavailable';
}
