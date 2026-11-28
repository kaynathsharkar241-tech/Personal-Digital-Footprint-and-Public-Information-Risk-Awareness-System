import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { evaluateRelevance } from '../server/providers/relevance.ts';

describe('V2 OSINT Evidence Relevance', () => {

  it('rejects unrelated results', () => {
    const result = evaluateRelevance(
      'Unrelated article', 'General news', '',
      { fullName: 'Alex Morgan' }
    );

    assert.equal(result.relevance, 'none');
  });

  it('rejects partial username matches', () => {
    const result = evaluateRelevance(
      'alex12345', '', '',
      { username: 'alex123' }
    );

    assert.equal(result.relevance, 'none');
  });

  it('detects exact username matches', () => {
    const result = evaluateRelevance(
      'Public profile', '',
      'https://example.com/alex123',
      { username: 'alex123' }
    );

    assert.equal(result.relevance, 'single_identifier');
  });

  it('detects multiple matching identifiers', () => {
    const result = evaluateRelevance(
      'Alex Morgan',
      'Contact: alex@example.com',
      '',
      {
        fullName: 'Alex Morgan',
        email: 'alex@example.com'
      }
    );

    assert.equal(result.relevance, 'multiple_identifiers');
  });

  it('never claims verified identity from text matches', () => {
    const result = evaluateRelevance(
      'Alex Morgan',
      'alex@example.com',
      '',
      {
        fullName: 'Alex Morgan',
        email: 'alex@example.com'
      }
    );

    assert.equal(result.identityVerified, false);
  });

  it('rejects empty and excessively short identifiers', () => {
    const result = evaluateRelevance(
      'A public article', '', '',
      { fullName: '', username: 'a' }
    );

    assert.equal(result.relevance, 'none');
  });

});

describe('Identifier Boundary Validation', () => {

  it('recognizes names followed by punctuation', () => {
    const result = evaluateRelevance(
      'Interview with Alex Morgan.',
      '', '',
      { fullName: 'Alex Morgan' }
    );

    assert.equal(result.relevance, 'single_identifier');
  });

  it('recognizes case-insensitive names', () => {
    const result = evaluateRelevance(
      'ALEX MORGAN',
      '', '',
      { fullName: 'Alex Morgan' }
    );

    assert.equal(result.relevance, 'single_identifier');
  });

  it('rejects misleading email extensions', () => {
    const result = evaluateRelevance(
      'alex@example.com.fake',
      '', '',
      { email: 'alex@example.com' }
    );

    assert.equal(result.relevance, 'none');
  });

});
