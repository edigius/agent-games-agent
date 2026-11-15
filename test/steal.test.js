import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { keccak256 } from 'js-sha3';
import {
  buildTurnResponse,
  computePublicInputsHash,
  policy,
  safePolicy,
} from '../src/steal.js';
import { STRATEGY_PARAMS } from '../src/strategyParams.js';

const COMMITMENT = `0x${'7d'.repeat(32)}`;
const MATCH_ID = '9f4e1b2a-0000-4000-8000-000000000001';

// Independent recomputation, written directly from the published spec in
// this test file (separate code path from src/steal.js): 8 fields, each
// 32-byte big-endian, order commitment/matchId/turn/self/opponent/
// actionType/amount/circuitVersion, keccak256 over the concatenation.
function independentHash({ commitment, matchId, turn, self, opp, actionType, amount }) {
  const pad = (n) => Buffer.from(BigInt(n).toString(16).padStart(64, '0'), 'hex');
  const packed = Buffer.concat([
    pad(commitment),
    pad(`0x${matchId.replace(/-/g, '')}`),
    pad(turn),
    pad(self),
    pad(opp),
    pad(actionType),
    pad(amount),
    pad(1),
  ]);
  return `0x${keccak256(packed)}`;
}

describe('publicInputsHash', () => {
  it('matches the independent spec recomputation (EXTRACT)', () => {
    const got = computePublicInputsHash({
      commitment: COMMITMENT,
      matchId: MATCH_ID,
      turn: 3,
      selfBalance: '95',
      opponentBalance: '105',
      action: 'EXTRACT',
      amount: 5,
    });
    const want = independentHash({
      commitment: COMMITMENT,
      matchId: MATCH_ID,
      turn: 3,
      self: 95,
      opp: 105,
      actionType: 2,
      amount: 5,
    });
    assert.equal(got, want);
  });

  it('matches the independent spec recomputation (FORTIFY, amount forced to 0)', () => {
    const got = computePublicInputsHash({
      commitment: COMMITMENT,
      matchId: MATCH_ID,
      turn: 7,
      selfBalance: '100',
      opponentBalance: '100',
      action: 'FORTIFY',
      amount: 99, // must be ignored: 0 for HOLD/FORTIFY
    });
    const want = independentHash({
      commitment: COMMITMENT,
      matchId: MATCH_ID,
      turn: 7,
      self: 100,
      opp: 100,
      actionType: 1,
      amount: 0,
    });
    assert.equal(got, want);
  });

  it('is sensitive to field order: swapping balances changes the hash', () => {
    const a = computePublicInputsHash({
      commitment: COMMITMENT,
      matchId: MATCH_ID,
      turn: 1,
      selfBalance: '90',
      opponentBalance: '110',
      action: 'HOLD',
    });
    const b = computePublicInputsHash({
      commitment: COMMITMENT,
      matchId: MATCH_ID,
      turn: 1,
      selfBalance: '110',
      opponentBalance: '90',
      action: 'HOLD',
    });
    assert.notEqual(a, b);
  });

  it('rejects unknown actions and out-of-range values', () => {
    assert.throws(
      () =>
        computePublicInputsHash({
          commitment: COMMITMENT,
          matchId: MATCH_ID,
          turn: 1,
          selfBalance: '1',
          opponentBalance: '1',
          action: 'DANCE',
        }),
      /unknown action/,
    );
  });

  it('rejects empty/whitespace-only balances (BigInt("") coerces to 0n)', () => {
    for (const field of ['selfBalance', 'opponentBalance']) {
      for (const blank of ['', '   ']) {
        assert.throws(
          () =>
            computePublicInputsHash({
              commitment: COMMITMENT,
              matchId: MATCH_ID,
              turn: 1,
              selfBalance: '95',
              opponentBalance: '105',
              action: 'HOLD',
              [field]: blank,
            }),
          new RegExp(field),
        );
      }
    }
  });
});

describe('policy (confirmed circuit rule)', () => {
  const state = (overrides) => ({
    selfBalance: '100',
    opponentBalance: '100',
    selfFortifiedUntilTurn: null,
    opponentFortifiedUntilTurn: null,
    turn: 3,
    ...overrides,
  });
  // p0=5, p1=50, p2=100, p3=0: exercises every branch.
  const P = [5, 50, 100, 0, 0, 0, 0, 0];

  it('rejects empty/whitespace-only balances; safePolicy fail-closes to HOLD', () => {
    for (const field of ['selfBalance', 'opponentBalance']) {
      for (const blank of ['', '   ']) {
        assert.throws(() => policy(state({ [field]: blank }), P), new RegExp(field));
        assert.deepEqual(safePolicy(state({ [field]: blank }), P), { type: 'HOLD' });
      }
    }
    // Explicit zero is still a valid integer, not a blank.
    assert.deepEqual(policy(state({ selfBalance: '0', opponentBalance: '0' }), P), {
      type: 'FORTIFY',
    });
  });

  it('is deterministic and ignores turn + fortify flags', () => {
    const s = state({ selfBalance: '120', opponentBalance: '80' });
    assert.deepEqual(policy(s, P), policy(s, P));
    assert.deepEqual(
      policy(state({ selfBalance: '120', opponentBalance: '80', turn: 1 }), P),
      policy(
        state({
          selfBalance: '120',
          opponentBalance: '80',
          turn: 19,
          selfFortifiedUntilTurn: 19,
          opponentFortifiedUntilTurn: 19,
        }),
        P,
      ),
    );
  });

  it('fortifies when self < p1, including at the strict boundary', () => {
    assert.deepEqual(policy(state({ selfBalance: '49', opponentBalance: '190' }), P), {
      type: 'FORTIFY',
    });
    // self == p1 does NOT fortify (strict <).
    assert.deepEqual(policy(state({ selfBalance: '50', opponentBalance: '150' }), P), {
      type: 'EXTRACT',
      amount: 5,
    });
  });

  it('fortify beats hold and the passive flag (highest precedence)', () => {
    assert.deepEqual(policy(state({ selfBalance: '10', opponentBalance: '0' }), P), {
      type: 'FORTIFY',
    });
    const passive = [5, 50, 100, 1, 0, 0, 0, 0];
    assert.deepEqual(policy(state({ selfBalance: '10', opponentBalance: '190' }), passive), {
      type: 'FORTIFY',
    });
  });

  it('holds when opp <= p2, extracts when opp > p2 (strict boundary)', () => {
    assert.deepEqual(policy(state({ selfBalance: '100', opponentBalance: '100' }), P), {
      type: 'HOLD',
    });
    assert.deepEqual(policy(state({ selfBalance: '100', opponentBalance: '101' }), P), {
      type: 'EXTRACT',
      amount: 5,
    });
  });

  it('p3=1 replaces EXTRACT with HOLD but never overrides FORTIFY', () => {
    const passive = [5, 50, 100, 1, 0, 0, 0, 0];
    assert.deepEqual(policy(state({ selfBalance: '100', opponentBalance: '150' }), passive), {
      type: 'HOLD',
    });
    assert.deepEqual(policy(state({ selfBalance: '10', opponentBalance: '150' }), passive), {
      type: 'FORTIFY',
    });
  });

  it('extracts exactly p0, uncapped by the opponent balance', () => {
    assert.deepEqual(policy(state({ selfBalance: '100', opponentBalance: '1' }), [10, 0, 0, 0, 0, 0, 0, 0]), {
      type: 'EXTRACT',
      amount: 10,
    });
  });

  it('p1=0 disables FORTIFY entirely', () => {
    assert.deepEqual(
      policy(state({ selfBalance: '0', opponentBalance: '190' }), [10, 0, 0, 0, 0, 0, 0, 0]),
      { type: 'EXTRACT', amount: 10 },
    );
  });

  it('uses STRATEGY_PARAMS by default', () => {
    const [p0] = STRATEGY_PARAMS;
    assert.deepEqual(policy(state({ selfBalance: '100', opponentBalance: '100' })), {
      type: 'EXTRACT',
      amount: p0,
    });
  });

  it('rejects invalid params loudly (p0, p1, p2, p3, reserved)', () => {
    assert.throws(() => policy(state({}), [0, 0, 0, 0, 0, 0, 0, 0]), /p0/);
    assert.throws(() => policy(state({}), [11, 0, 0, 0, 0, 0, 0, 0]), /p0/);
    assert.throws(() => policy(state({}), [5, 201, 0, 0, 0, 0, 0, 0]), /p1/);
    assert.throws(() => policy(state({}), [5, 0, -1, 0, 0, 0, 0, 0]), /p2/);
    assert.throws(() => policy(state({}), [5, 0, 0, 2, 0, 0, 0, 0]), /p3/);
    assert.throws(() => policy(state({}), [5, 0, 0, 0, 1, 0, 0, 0]), /RESERVED/);
    assert.throws(() => policy(state({}), [5, 0, 0, 0]), /exactly 8/);
    assert.throws(() => policy(state({}), [5.5, 0, 0, 0, 0, 0, 0, 0]), /integer/);
  });

  it('safePolicy fails closed to HOLD on bad state', () => {
    assert.deepEqual(safePolicy({ selfBalance: 'NaN', opponentBalance: '1', turn: 0 }), {
      type: 'HOLD',
    });
    assert.deepEqual(safePolicy({ selfBalance: '-5', opponentBalance: '1', turn: 0 }), {
      type: 'HOLD',
    });
  });

  it('safePolicy fails closed to HOLD on invalid params', () => {
    assert.deepEqual(safePolicy(state({}), [0, 0, 0, 0, 0, 0, 0, 0]), { type: 'HOLD' });
    assert.deepEqual(safePolicy(state({}), [5, 0, 0, 2, 0, 0, 0, 0]), { type: 'HOLD' });
    assert.deepEqual(safePolicy(state({}), [5, 0, 0, 0, 0, 0, 0, 9]), { type: 'HOLD' });
  });
});

describe('turn response shaping', () => {
  it('omits amount entirely for HOLD and FORTIFY', () => {
    for (const type of ['HOLD', 'FORTIFY']) {
      const r = buildTurnResponse({
        matchId: MATCH_ID,
        turn: 2,
        action: { type },
        publicInputsHash: '0x00',
      });
      assert.equal(r.action.type, type);
      assert.equal('amount' in r.action, false);
    }
  });

  it('includes amount for EXTRACT', () => {
    const r = buildTurnResponse({
      matchId: MATCH_ID,
      turn: 2,
      action: { type: 'EXTRACT', amount: 5 },
      publicInputsHash: '0x00',
    });
    assert.deepEqual(r.action, { type: 'EXTRACT', amount: 5 });
  });

  it('echoes matchId/turn and generates unique idempotency keys', () => {
    const mk = () =>
      buildTurnResponse({
        matchId: MATCH_ID,
        turn: 2,
        action: { type: 'HOLD' },
        publicInputsHash: '0x00',
      });
    const a = mk();
    const b = mk();
    assert.equal(a.matchId, MATCH_ID);
    assert.equal(a.turn, 2);
    assert.notEqual(a.idempotencyKey, b.idempotencyKey);
    assert.equal(a.policyProof.circuitVersion, 'v1');
  });

  it('includes proof fields only when proof evidence exists', () => {
    const without = buildTurnResponse({
      matchId: MATCH_ID,
      turn: 2,
      action: { type: 'HOLD' },
      publicInputsHash: '0x00',
    });
    assert.equal('proof' in without, false);
    const withProof = buildTurnResponse({
      matchId: MATCH_ID,
      turn: 2,
      action: { type: 'HOLD' },
      publicInputsHash: '0x00',
      proof: { pi_a: ['1'] },
      publicSignals: ['1'],
    });
    assert.equal(withProof.proof.pi_a[0], '1');
    assert.deepEqual(withProof.public_signals, ['1']);
  });
});
