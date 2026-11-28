import { readFileSync } from 'node:fs';

interface ReviewedFinding {
  provider: string;
  verdict: 'relevant' | 'irrelevant' | 'uncertain';
}

const file = process.argv[2];

if (!file) {
  console.error(
    'Usage: npx tsx scripts/evaluate-osint.ts findings.json'
  );
  process.exit(1);
}

const findings = JSON.parse(
  readFileSync(file, 'utf8')
) as ReviewedFinding[];

if (
  !Array.isArray(findings) ||
  findings.some(f =>
    !f ||
    typeof f.provider !== 'string' ||
    !['relevant', 'irrelevant', 'uncertain']
      .includes(f.verdict)
  )
) {
  throw new Error('Invalid evaluation dataset.');
}

function evaluate(items: ReviewedFinding[]) {
  const tp = items.filter(
    f => f.verdict === 'relevant'
  ).length;

  const fp = items.filter(
    f => f.verdict === 'irrelevant'
  ).length;

  const uncertain = items.filter(
    f => f.verdict === 'uncertain'
  ).length;

  const reviewed = tp + fp;

  return {
    total: items.length,
    relevant: tp,
    irrelevant: fp,
    uncertain,
    precision: reviewed ? tp / reviewed : null,
    falseDiscoveryRate: reviewed ? fp / reviewed : null,
    reviewCoverage: items.length
      ? reviewed / items.length
      : null
  };
}

const providers = [...new Set(
  findings.map(f => f.provider)
)];

console.log(JSON.stringify({
  evaluatedAt: new Date().toISOString(),
  overall: evaluate(findings),
  providers: providers.map(provider => ({
    provider,
    ...evaluate(
      findings.filter(f => f.provider === provider)
    )
  }))
}, null, 2));
