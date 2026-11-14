import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { signBody, verifySignature } from '../src/hmac.js';

const SECRET = 'test-only-hmac-secret';

describe('hmac', () => {
  it('signs and verifies a round-trip', () => {
    const body = Buffer.from('{"hello":"world"}');
    const sig = signBody(SECRET, body);
    assert.equal(verifySignature(SECRET, body, sig), true);
  });

  it('matches a textbook HMAC-SHA256 hex digest', () => {
    const body = Buffer.from('abc');
    const expected = createHmac('sha256', SECRET).update(body).digest('hex');
    assert.equal(signBody(SECRET, body), expected);
  });

  it('rejects a tampered body', () => {
    const sig = signBody(SECRET, Buffer.from('{"a":1}'));
    assert.equal(verifySignature(SECRET, Buffer.from('{"a":2}'), sig), false);
  });

  it('rejects the wrong secret', () => {
    const body = Buffer.from('{"a":1}');
    const sig = signBody(SECRET, body);
    assert.equal(verifySignature('different-secret', body, sig), false);
  });

  it('rejects missing/empty/garbage signatures', () => {
    const body = Buffer.from('{"a":1}');
    assert.equal(verifySignature(SECRET, body, undefined), false);
    assert.equal(verifySignature(SECRET, body, ''), false);
    assert.equal(verifySignature(SECRET, body, 'not-a-signature'), false);
  });

  it('accepts a base64 encoding of the same HMAC', () => {
    const body = Buffer.from('{"a":1}');
    const b64 = createHmac('sha256', SECRET).update(body).digest('base64');
    assert.equal(verifySignature(SECRET, body, b64), true);
  });

  it('is case-insensitive for hex signatures', () => {
    const body = Buffer.from('{"a":1}');
    const sig = signBody(SECRET, body).toUpperCase();
    assert.equal(verifySignature(SECRET, body, sig), true);
  });
});
