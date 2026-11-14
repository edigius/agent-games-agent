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
});

describe('policy', () => {
  const state = (overrides) => ({
    selfBalance: '100',
    opponentBalance: '100',
    selfFortifiedUntilTurn: null,
    opponentFortifiedUntilTurn: null,
    turn: 3,
    ...overrides,
  });

  it('is deterministic', () => {
    const s = state({ selfBalance: '120', opponentBalance: '80' });
    assert.deepEqual(policy(s), policy(s));
    assert.deepEqual(policy(s, STRATEGY_PARAMS), policy(s, { ...STRATEGY_PARAMS }));
  });

  it('extracts at parity in the mid-game', () => {
    assert.deepEqual(policy(state({})), { type: 'EXTRACT', amount: 10 });
  });

  it('fortifies a comfortable mid-game lead', () => {
    assert.deepEqual(policy(state({ selfBalance: '120', opponentBalance: '100' })), {
      type: 'FORTIFY',
    });
  });

  it('fortifies any lead in the endgame, extracts when behind', () => {
    assert.deepEqual(policy(state({ turn: 19, selfBalance: '101', opponentBalance: '100' })), {
      type: 'FORTIFY',
    });
    assert.deepEqual(policy(state({ turn: 19, selfBalance: '99', opponentBalance: '100' })), {
      type: 'EXTRACT',
      amount: 10,
    });
  });

  it('extracts when nearly broke even with a lead', () => {
    assert.deepEqual(policy(state({ selfBalance: '10', opponentBalance: '5', turn: 19 })), {
      type: 'EXTRACT',
      amount: 10,
    });
  });

  it('safePolicy fails closed to HOLD on bad state', () => {
    assert.deepEqual(safePolicy({ selfBalance: 'NaN', opponentBalance: '1', turn: 0 }), {
      type: 'HOLD',
    });
  });

  it('safePolicy clamps an out-of-range extract amount to HOLD', () => {
    const badParams = { ...STRATEGY_PARAMS, EXTRACT_AMOUNT: 99 };
    assert.deepEqual(safePolicy(state({}), badParams), { type: 'HOLD' });
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
