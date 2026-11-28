export interface SearchIdentifiers {
  fullName?: string;
  email?: string;
  username?: string;
  domain?: string;
}

export interface MatchEvidence {
  matchedIdentifiers: string[];
  relevance: 'multiple_identifiers' | 'single_identifier' | 'none';
  identityVerified: false;
}

function normalize(value: string): string {
  return value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function exactMatch(text: string, identifier: string, type: string): boolean {
  const value = normalize(identifier);

  if (value.length < 3) return false;

  const boundary = type === 'fullName'
    ? '[\\p{L}\\p{N}]'
    : '[\\p{L}\\p{N}_.@+\\-]';

  const pattern = new RegExp(
    `(?<!${boundary})${escapeRegex(value)}(?!${boundary})`,
    'u'
  );

  return pattern.test(text);
}

export function evaluateRelevance(
  title: string,
  content: string,
  url: string,
  identifiers: SearchIdentifiers
): MatchEvidence {

  const text = normalize(`${title}\n${content}\n${url}`);
  const matchedIdentifiers: string[] = [];

  for (const [type, value] of Object.entries(identifiers)) {
    if (typeof value !== 'string' || !value.trim()) continue;

    if (exactMatch(text, value, type)) {
      matchedIdentifiers.push(type);
    }
  }

  return {
    matchedIdentifiers,
    relevance:
      matchedIdentifiers.length >= 2
        ? 'multiple_identifiers'
        : matchedIdentifiers.length === 1
          ? 'single_identifier'
          : 'none',
    identityVerified: false
  };
}
