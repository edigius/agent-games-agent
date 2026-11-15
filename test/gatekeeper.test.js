import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decideGatekeeper } from '../src/gatekeeper.js';
import { REASON_CODE } from '../src/reasonCodes.js';
import { ADDR_B, PROOF_TX, VK_A, VK_B, validGatekeeperInput } from './helpers.js';

describe('gatekeeper decisions', () => {
  it('approves a valid condition', () => {
    const r = decideGatekeeper(validGatekeeperInput(), { isReplay: false });
    assert.equal(r.decision, 'APPROVE');
    assert.equal(r.reasonCode, REASON_CODE.VALID_PROOF);
    assert.equal(r.trap, 'VALID_CONDITION');
    assert.ok(r.checks.every((c) => c.passed));
  });

  it('rejects VK substitution', () => {
    const r = decideGatekeeper(validGatekeeperInput({ proof_vk: VK_B }), { isReplay: false });
    assert.equal(r.decision, 'REJECT');
    assert.equal(r.reasonCode, REASON_CODE.VK_SUBSTITUTION);
    assert.equal(r.trap, 'VK_SUBSTITUTION');
  });

  it('rejects a replayed proof reference', () => {
    const r = decideGatekeeper(validGatekeeperInput(), { isReplay: true });
    assert.equal(r.decision, 'REJECT');
    assert.equal(r.reasonCode, REASON_CODE.PROOF_REPLAY);
    assert.equal(r.trap, 'PROOF_REUSED');
  });

  it('rejects below-threshold balance', () => {
    const r = decideGatekeeper(validGatekeeperInput({ public_balance: '999' }), {
      isReplay: false,
    });
    assert.equal(r.decision, 'REJECT');
    assert.equal(r.reasonCode, REASON_CODE.THRESHOLD_MISMATCH);
  });

  it('rejects an expired condition', () => {
    const r = decideGatekeeper(validGatekeeperInput({ current_block: 8430001 }), {
      isReplay: false,
    });
    assert.equal(r.decision, 'REJECT');
    assert.equal(r.trap, 'EXPIRED_CONDITION');
    assert.equal(r.reasonCode, REASON_CODE.PUBLIC_INPUT_MISMATCH);
  });

  it('rejects a recipient mismatch', () => {
    const r = decideGatekeeper(validGatekeeperInput({ recipient: ADDR_B }), {
      isReplay: false,
    });
    assert.equal(r.decision, 'REJECT');
    assert.equal(r.trap, 'RECIPIENT_MISMATCH');
    assert.equal(r.reasonCode, REASON_CODE.PUBLIC_INPUT_MISMATCH);
  });

  it('rejects amount overflow', () => {
    const r = decideGatekeeper(validGatekeeperInput({ amount: '1001' }), { isReplay: false });
    assert.equal(r.decision, 'REJECT');
    assert.equal(r.trap, 'AMOUNT_OVERFLOW');
    assert.equal(r.reasonCode, REASON_CODE.PUBLIC_INPUT_MISMATCH);
  });

  it('is deterministic: same input, same output', () => {
    const input = validGatekeeperInput({ amount: '1001' });
    assert.deepEqual(
      decideGatekeeper(input, { isReplay: false }),
      decideGatekeeper(input, { isReplay: false }),
    );
  });
});

describe('gatekeeper boundaries', () => {
  it('balance exactly equal to minimum passes', () => {
    const r = decideGatekeeper(validGatekeeperInput({ public_balance: '1000' }), {
      isReplay: false,
    });
    assert.equal(r.decision, 'APPROVE');
  });

  it('amount exactly equal to max_transfer passes', () => {
    const r = decideGatekeeper(validGatekeeperInput({ amount: '1000' }), { isReplay: false });
    assert.equal(r.decision, 'APPROVE');
  });

  it('current_block exactly equal to expiry_block IS expired (STRICT, circuit-confirmed)', () => {
    const r = decideGatekeeper(validGatekeeperInput({ current_block: 8430000 }), {
      isReplay: false,
    });
    assert.equal(r.decision, 'REJECT');
    assert.equal(r.trap, 'EXPIRED_CONDITION');
  });

  it('current_block one past expiry_block is expired', () => {
    const r = decideGatekeeper(validGatekeeperInput({ current_block: 8430001 }), {
      isReplay: false,
    });
    assert.equal(r.decision, 'REJECT');
  });

  it('handles very large balances with BigInt (no float precision loss)', () => {
    const big = '123456789012345678901234567890';
    const r = decideGatekeeper(
      validGatekeeperInput({ minimum: big, public_balance: big }),
      { isReplay: false },
    );
    assert.equal(r.decision, 'APPROVE');
    const r2 = decideGatekeeper(
      validGatekeeperInput({
        minimum: big,
        public_balance: '123456789012345678901234567889',
      }),
      { isReplay: false },
    );
    assert.equal(r2.decision, 'REJECT');
    assert.equal(r2.reasonCode, REASON_CODE.THRESHOLD_MISMATCH);
  });

  it('treats checksummed vs lowercase spellings of the same VK/address as equal', () => {
    const r = decideGatekeeper(
      validGatekeeperInput({
        proof_vk: VK_A.toUpperCase().replace('0X', '0x'),
        recipient: '0xde42aabbccddeeff001122334455667788990011',
      }),
      { isReplay: false },
    );
    assert.equal(r.decision, 'APPROVE');
  });

  it('applies checks in fixed priority order (replay beats VK beats expiry)', () => {
    const input = validGatekeeperInput({
      proof_vk: VK_B,
      current_block: 9999999,
    });
    const r = decideGatekeeper(input, { isReplay: true });
    assert.equal(r.trap, 'PROOF_REUSED');
    const r2 = decideGatekeeper(input, { isReplay: false });
    assert.equal(r2.trap, 'VK_SUBSTITUTION');
    const r3 = decideGatekeeper(validGatekeeperInput({ current_block: 9999999 }), {
      isReplay: false,
    });
    assert.equal(r3.trap, 'EXPIRED_CONDITION');
  });

  it('throws a clear error on non-integer amount fields', () => {
    assert.throws(
      () => decideGatekeeper(validGatekeeperInput({ amount: 'not-a-number' }), {}),
      /amount/,
    );
  });

  it('rejects empty/whitespace-only numeric fields (BigInt("") coerces to 0n)', () => {
    // A blank minimum/balance/amount/block must fail closed, never read
    // as zero: a blank minimum would pass every threshold check.
    for (const field of ['minimum', 'public_balance', 'amount', 'max_transfer']) {
      for (const blank of ['', '   ']) {
        assert.throws(
          () => decideGatekeeper(validGatekeeperInput({ [field]: blank }), {}),
          new RegExp(field),
        );
      }
    }
    for (const blank of ['', '   ']) {
      assert.throws(
        () => decideGatekeeper(validGatekeeperInput({ current_block: blank }), {}),
        /current_block/,
      );
      assert.throws(
        () => decideGatekeeper(validGatekeeperInput({ expiry_block: blank }), {}),
        /expiry_block/,
      );
    }
    // Explicit zero is still a valid integer, not a blank.
    const r = decideGatekeeper(
      validGatekeeperInput({ minimum: '0', public_balance: '0', amount: '0', max_transfer: '0' }),
      { isReplay: false },
    );
    assert.equal(r.decision, 'APPROVE');
  });

  it('keeps the proof_tx value available to the caller for echo', () => {
    assert.equal(validGatekeeperInput().proof_tx, PROOF_TX);
  });
});
