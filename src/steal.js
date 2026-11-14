/**
 * PEGASUS — Steal the VFY: policy, publicInputsHash, response shaping.
 *
 * Policy: a pure, deterministic function of the envelope state and
 * STRATEGY_PARAMS. It must match the vfy-policy circuit exactly — including
 * the extraction amount and the FORTIFY logic — so it is kept isolated,
 * dependency-free, and exhaustively tested. No history, no randomness, no
 * I/O inside the policy.
 *
 * publicInputsHash: keccak256 over 8 ABI-packed fields, each 32 bytes
 * big-endian, in the EXACT order published on /build:
 *   commitment, matchId, turn, selfBalance, opponentBalance, actionType,
 *   amount, circuitVersion
 * The platform recomputes this hash from the game state it knows and
 * rejects any proof where the hashes diverge. Field order and encoding
 * must never change without re-validating against practice mode.
 */
import { randomUUID } from 'node:crypto';
import { keccak256 } from 'js-sha3';
import { CIRCUIT_VERSION } from './config.js';
import { STRATEGY_PARAMS } from './strategyParams.js';

export const ACTION_TYPE = Object.freeze({
  HOLD: 0,
  FORTIFY: 1,
  EXTRACT: 2,
});

export const EXTRACT_MAX = 10;
export const FORTIFY_COST = 2;

function toBigInt(value, field) {
  try {
    return BigInt(value);
  } catch {
    throw new Error(`steal state field ${field} is not an integer: ${String(value)}`);
  }
}

/**
 * Pure policy: state + params -> action.
 * @param {object} state - envelope `state` object.
 * @param {object} params - STRATEGY_PARAMS (defaults to the module values).
 * @returns {{type: 'HOLD'|'FORTIFY'|'EXTRACT', amount?: number}}
 */
export function policy(state, params = STRATEGY_PARAMS) {
  const self = toBigInt(state.selfBalance, 'selfBalance');
  const opp = toBigInt(state.opponentBalance, 'opponentBalance');
  const turn = Number(state.turn);
  const lead = self - opp;
  const isEndgame = turn >= params.TOTAL_TURNS - params.ENDGAME_TURNS;

  // Broke: must extract, fortifying concedes the match.
  if (self <= BigInt(params.LOW_BALANCE_THRESHOLD)) {
    return { type: 'EXTRACT', amount: params.EXTRACT_AMOUNT };
  }
  // Endgame: protect any lead; behind -> extract.
  if (isEndgame) {
    if (lead > 0n) return { type: 'FORTIFY' };
    return { type: 'EXTRACT', amount: params.EXTRACT_AMOUNT };
  }
  // Mid-game: protect a comfortable lead, otherwise extract.
  if (lead >= BigInt(params.LEAD_FORTIFY_THRESHOLD)) {
    return { type: 'FORTIFY' };
  }
  return { type: 'EXTRACT', amount: params.EXTRACT_AMOUNT };
}

/** Fail-closed wrapper: any policy error degrades to HOLD, never a crash. */
export function safePolicy(state, params = STRATEGY_PARAMS) {
  try {
    const action = policy(state, params);
    if (action.type === 'EXTRACT') {
      const amount = Number(action.amount);
      if (!Number.isInteger(amount) || amount < 1 || amount > EXTRACT_MAX) {
        return { type: 'HOLD' };
      }
      return { type: 'EXTRACT', amount };
    }
    if (action.type === 'FORTIFY' || action.type === 'HOLD') {
      return { type: action.type };
    }
    return { type: 'HOLD' };
  } catch {
    return { type: 'HOLD' };
  }
}

function u256(value) {
  const n = typeof value === 'bigint' ? value : BigInt(value);
  if (n < 0n || n >= 1n << 256n) {
    throw new Error(`value out of uint256 range: ${String(value)}`);
  }
  const hex = n.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

/**
 * Compute policyProof.publicInputsHash per the published spec.
 * @param {object} args - { commitment, matchId, turn, selfBalance,
 *   opponentBalance, action, amount }
 * @returns {'0x' + string} keccak256 hex digest.
 */
export function computePublicInputsHash({
  commitment,
  matchId,
  turn,
  selfBalance,
  opponentBalance,
  action,
  amount,
}) {
  if (!(action in ACTION_TYPE)) {
    throw new Error(`unknown action type: ${String(action)}`);
  }
  const fields = [
    u256(commitment), // strategyCommitment.hash (Poseidon commitment)
    u256(BigInt(`0x${String(matchId).replace(/-/g, '')}`)), // UUID, hyphens stripped
    u256(BigInt(turn)),
    u256(toBigInt(selfBalance, 'selfBalance')),
    u256(toBigInt(opponentBalance, 'opponentBalance')),
    u256(BigInt(ACTION_TYPE[action])),
    // amount: EXTRACT amount, 0 for HOLD / FORTIFY.
    u256(action === 'EXTRACT' ? BigInt(amount ?? 0) : 0n),
    u256(1n), // circuitVersion "v1" -> 1
  ];
  return `0x${keccak256(Buffer.concat(fields))}`;
}

/**
 * Build the turn response. `amount` is OMITTED ENTIRELY for HOLD/FORTIFY
 * (sending it is a documented common mistake). proofReference is the Kurier
 * job id when a submission happened, else null. proof/public_signals are
 * included when available (superset response per the design decision in the
 * research note; validate in practice mode).
 */
export function buildTurnResponse({
  matchId,
  turn,
  action,
  publicInputsHash,
  proofReference = null,
  proof = null,
  publicSignals = null,
  idempotencyKey = randomUUID(),
  agentTimestamp = new Date().toISOString(),
}) {
  const actionOut =
    action.type === 'EXTRACT'
      ? { type: 'EXTRACT', amount: action.amount }
      : { type: action.type };
  const response = {
    matchId,
    turn,
    action: actionOut,
    policyProof: {
      circuitVersion: CIRCUIT_VERSION,
      proofReference,
      publicInputsHash,
    },
    agentTimestamp,
    idempotencyKey,
  };
  if (proof !== null && proof !== undefined) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  return response;
}
