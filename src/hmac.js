/**
 * PEGASUS — HMAC-SHA256 signing helpers.
 *
 * The platform signs every inbound request and expects every response signed,
 * both with header `x-agent-games-signature` computed over the RAW body.
 * Verification MUST happen before JSON parsing.
 *
 * Encoding assumption (practice-validation item): the platform's docs say
 * "HMAC-SHA256 over the raw body" without naming the header encoding. Hex
 * (lowercase, no 0x prefix) is the common convention and is what PEGASUS
 * emits. Verification accepts hex OR base64, since both encode the same
 * HMAC — an attacker still needs the secret either way.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_HEADER = 'x-agent-games-signature';

export function signBody(secret, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
  return createHmac('sha256', secret).update(body).digest('hex');
}

function safeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function verifySignature(secret, rawBody, headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) {
    return false;
  }
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
  const hmac = createHmac('sha256', secret).update(body);
  const hex = hmac.digest('hex');
  if (safeEqual(headerValue.trim().toLowerCase(), hex)) return true;
  const base64 = createHmac('sha256', secret)
    .update(body)
    .digest('base64');
  return safeEqual(headerValue.trim(), base64);
}
