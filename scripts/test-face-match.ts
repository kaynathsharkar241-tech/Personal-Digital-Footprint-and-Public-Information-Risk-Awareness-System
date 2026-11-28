import fs from 'node:fs';
import { compareEnrolledFace } from '../server/faceMatcher.ts';

async function main() {
  const [first, second] = process.argv.slice(2);

  if (!first || !second) {
    console.error('Provide two image paths.');
    process.exitCode = 1;
    return;
  }

  const enrolled = fs.readFileSync(first).toString('base64');
  const camera = fs.readFileSync(second).toString('base64');

  const started = performance.now();

  const result = await compareEnrolledFace(enrolled, camera);

  console.log(JSON.stringify({
    ...result,
    processingTimeMs: Math.round(performance.now() - started)
  }, null, 2));

  if (result.status !== 'compared') {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error('Comparison test failed:', error.message);
  process.exitCode = 1;
});
