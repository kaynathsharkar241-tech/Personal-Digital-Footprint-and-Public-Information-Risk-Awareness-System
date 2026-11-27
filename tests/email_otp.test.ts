import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  generateEmailOTP,
  hashEmailOTP,
  getOTPExpiry
} from '../server/email.ts';

describe('V2 Email OTP Security', () => {

  it('generates exactly six numeric digits', () => {
    for (let i = 0; i < 100; i++) {
      assert.match(generateEmailOTP(), /^\d{6}$/);
    }
  });

  it('produces deterministic HMAC hashes', () => {
    const a = hashEmailOTP(1, '123456', 'test-secret');
    const b = hashEmailOTP(1, '123456', 'test-secret');

    assert.equal(a, b);
    assert.match(a, /^[a-f0-9]{64}$/);
    assert.notEqual(a, '123456');
  });

  it('binds OTP hashes to individual users', () => {
    assert.notEqual(
      hashEmailOTP(1, '123456', 'test-secret'),
      hashEmailOTP(2, '123456', 'test-secret')
    );
  });

  it('distinguishes different verification codes', () => {
    assert.notEqual(
      hashEmailOTP(1, '123456', 'test-secret'),
      hashEmailOTP(1, '123457', 'test-secret')
    );
  });

  it('binds OTP hashes to the signing secret', () => {
    assert.notEqual(
      hashEmailOTP(1, '123456', 'secret-a'),
      hashEmailOTP(1, '123456', 'secret-b')
    );
  });

  it('sets expiry approximately five minutes ahead', () => {
    const difference = Date.parse(getOTPExpiry()) - Date.now();

    assert.ok(difference >= 298000);
    assert.ok(difference <= 300000);
  });

});
