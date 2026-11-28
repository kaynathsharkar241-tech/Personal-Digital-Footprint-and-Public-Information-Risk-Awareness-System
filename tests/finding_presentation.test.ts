import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  getFindingPresentation,
  formatFindingRisk,
  formatFindingPriority
} from '../src/utils/findingPresentation.ts';

describe('V2 Finding Presentation', () => {

  it('does not present unverified matches as confirmed', () => {
    const result = getFindingPresentation('Unverified');

    assert.equal(result.label, 'Potential Match');
    assert.equal(result.showPriority, false);
  });

  it('excludes false positives from verified counts', () => {
    const result = getFindingPresentation('False Positive');

    assert.equal(result.includeInVerifiedCount, false);
  });

  it('recognizes user-verified findings', () => {
    const result = getFindingPresentation('Verified Match');

    assert.equal(result.includeInVerifiedCount, true);
  });

  it('does not display unverified numerical risk', () => {
    assert.equal(
      formatFindingPriority(0.95, 'Unverified'),
      'Not assessed'
    );
  });

  it('rejects missing numerical assessments', () => {
    assert.equal(
      formatFindingPriority(null, 'Verified Match'),
      'Unavailable'
    );
  });

  it('labels numerical priority as heuristic', () => {
    assert.equal(
      formatFindingPriority(0.75, 'Verified Match'),
      '0.750 (heuristic)'
    );
  });

});

it('suppresses risk labels for unverified and excluded findings', () => {
  assert.equal(formatFindingRisk('High', 'Unverified'), 'Not assessed');
  assert.equal(formatFindingRisk('High', 'False Positive'), 'Excluded');
});
it('labels verified severity as heuristic and rejects unknown severity', () => {
  assert.equal(formatFindingRisk('High', 'Verified Match'), 'High (heuristic)');
  assert.equal(formatFindingRisk('unknown', 'Verified Match'), 'Unavailable');
});
