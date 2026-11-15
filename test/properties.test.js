/**
 * Deterministic property-style tests (NEPTUN). No fast-check dependency
 * (still a user decision): cases come from a seeded PRNG in
 * test/helpers.js, so every run replays the exact same sequence.
 *
 * Fault classes covered (from the NEPTUN ADU experiments, whose P7/Q3
 * generators lived in /tmp and were never part of this repo):
 *   C3 — hex comparisons must vary BOTH sides: equal values spelled
 *        differently on each side must still compare equal, and
 *        different values must compare different, for VKs and for
 *        recipient addresses alike.
 *   C9 — numeric domains must include explicit zero: 0 is a valid
 *        integer (not a blank), and boundary decisions at 0 must match
 *        an independent reference implementation.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decideGatekeeper } from '../src/gatekeeper.js';
import { toField } from '../src/proof.js';
import {
  mulberry32,
  seededHex,
  seededInt,
  validGatekeeperInput,
} from './helpers.js';

// Random 0x-prefixed spelling of the same hex bytes: random per-byte
// case, random 0x/0X prefix, optional surrounding whitespace. The
// envelope contract always carries a 0x prefix; unprefixed spellings
// are out of contract and are not generated here.
function respell(rng, hexBytes) {
  let s = '';
  for (const ch of hexBytes) {
    s += /[a-f]/.test(ch) && rng() < 0.5 ? ch.toUpperCase() : ch;
  }
  const prefix = rng() < 0.5 ? '0x' : '0X';
  const pad = rng() < 0.25 ? ' ' : '';
  return `${pad}${prefix}${s}${pad}`;
}

describe('property C3: both sides of every hex comparison vary', () => {
  it('VK equality survives independent respellings of each side', () => {
    const rng = mulberry32(0xc3a7);
    for (let i = 0; i < 200; i += 1) {
      const bytes = seededHex(rng, 32);
      const input = validGatekeeperInput({
        registered_vk: respell(rng, bytes),
        proof_vk: respell(rng, bytes),
      });
      const r = decideGatekeeper(input, { isReplay: false });
      assert.equal(r.decision, 'APPROVE', `case ${i}: same VK, respelled`);
      assert.equal(r.trap, 'VALID_CONDITION');
    }
  });

  it('VK inequality is detected when the two sides differ', () => {
    const rng = mulberry32(0xc3b1);
    for (let i = 0; i < 200; i += 1) {
      const a = seededHex(rng, 32);
      let b = seededHex(rng, 32);
      if (a === b) b = (b[0] === '0' ? '1' : '0') + b.slice(1);
      const input = validGatekeeperInput({
        registered_vk: respell(rng, a),
        proof_vk: respell(rng, b),
      });
      const r = decideGatekeeper(input, { isReplay: false });
      assert.equal(r.trap, 'VK_SUBSTITUTION', `case ${i}`);
      assert.equal(r.decision, 'REJECT');
    }
  });

  it('recipient equality/inequality survives independent respellings', () => {
    const rng = mulberry32(0xc3c5);
    for (let i = 0; i < 200; i += 1) {
      const bytes = seededHex(rng, 20);
      const same = rng() < 0.5;
      let other = seededHex(rng, 20);
      if (same) other = bytes;
      else if (other === bytes) other = (other[0] === '0' ? '1' : '0') + other.slice(1);
      const input = validGatekeeperInput({
        recipient: respell(rng, bytes),
        condition_recipient: respell(rng, other),
      });
      const r = decideGatekeeper(input, { isReplay: false });
      if (same) {
        assert.equal(r.decision, 'APPROVE', `case ${i}: same recipient, respelled`);
      } else {
        assert.equal(r.trap, 'RECIPIENT_MISMATCH', `case ${i}`);
      }
    }
  });

  it('toField is spelling-insensitive for 0x hex values', () => {
    // NOTE: toField only recognizes the lowercase '0x' prefix (the
    // envelope contract; the decider's normalizeHex additionally
    // accepts '0X'). Respelling here varies case + whitespace only,
    // keeping the '0x' prefix intact.
    const rng = mulberry32(0xc3d9);
    for (let i = 0; i < 100; i += 1) {
      const bytes = seededHex(rng, seededInt(rng, 1, 32));
      let respelled = '';
      for (const ch of bytes) {
        respelled += /[a-f]/.test(ch) && rng() < 0.5 ? ch.toUpperCase() : ch;
      }
      const pad = rng() < 0.25 ? ' ' : '';
      const a = toField(`0x${bytes}`);
      const b = toField(`${pad}0x${respelled}${pad}`);
      assert.equal(a, b, `case ${i}`);
    }
  });
});

// Independent reference for the numeric checks, written directly from
// the documented boundary rules (VKs/recipients fixed equal, no replay).
function numericOracle(input) {
  if (BigInt(input.current_block) >= BigInt(input.expiry_block)) {
    return ['REJECT', 'EXPIRED_CONDITION'];
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return ['REJECT', 'THRESHOLD_MISMATCH'];
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return ['REJECT', 'AMOUNT_OVERFLOW'];
  }
  return ['APPROVE', 'VALID_CONDITION'];
}

describe('property C9: explicit zero is in every numeric domain', () => {
  it('decisions match the reference oracle over a zero-heavy grid', () => {
    const values = ['0', '1', '999', '1000', '1001'];
    const blocks = [
      [0, 0],
      [0, 1],
      [1, 1],
      [1, 0],
      [8430000, 8430000],
    ];
    let cases = 0;
    for (const minimum of values) {
      for (const balance of values) {
        for (const amount of values) {
          for (const max of values) {
            for (const [current, expiry] of blocks) {
              const input = validGatekeeperInput({
                minimum,
                public_balance: balance,
                amount,
                max_transfer: max,
                current_block: current,
                expiry_block: expiry,
              });
              const [decision, trap] = numericOracle(input);
              const r = decideGatekeeper(input, { isReplay: false });
              assert.equal(r.decision, decision, JSON.stringify(input));
              assert.equal(r.trap, trap, JSON.stringify(input));
              cases += 1;
            }
          }
        }
      }
    }
    assert.ok(cases > 3000, `grid covered ${cases} cases`);
  });

  it('decisions match the reference oracle on seeded random values incl. 0', () => {
    const rng = mulberry32(0xc9e1);
    const pool = [
      0n,
      1n,
      2n,
      999n,
      1000n,
      1001n,
      2n ** 64n,
      2n ** 128n,
      123456789012345678901234567890n,
    ];
    const pick = () =>
      (rng() < 0.35 ? pool[seededInt(rng, 0, pool.length - 1)] : BigInt(seededInt(rng, 0, 2000000))).toString();
    for (let i = 0; i < 500; i += 1) {
      const input = validGatekeeperInput({
        minimum: pick(),
        public_balance: pick(),
        amount: pick(),
        max_transfer: pick(),
        current_block: Number(pick()) % 9000000,
        expiry_block: Number(pick()) % 9000000,
      });
      const [decision, trap] = numericOracle(input);
      const r = decideGatekeeper(input, { isReplay: false });
      assert.equal(r.decision, decision, `case ${i}: ${JSON.stringify(input)}`);
      assert.equal(r.trap, trap, `case ${i}`);
    }
  });

  it('toField passes zero through unchanged in every spelling', () => {
    assert.equal(toField(0n), 0n);
    assert.equal(toField(0), 0n);
    assert.equal(toField('0'), 0n);
    assert.equal(toField('0x0'), 0n);
    assert.equal(toField('0x00'), 0n);
  });
});
