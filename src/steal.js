/**
 * PEGASUS — Steal the VFY: policy, publicInputsHash, response shaping.
 *
 * Policy: the EXACT rule enforced by the vfy-policy circuit (confirmed
 * by local fullProve+verify experiments, 15 Nov 2026), parameterized by
 * the 8 values in STRATEGY_PARAMS (only p0..p3 are live knobs; p4..p7
 * are reserved 0). In precedence order:
 *   if selfBalance < p1:          FORTIFY, amount 0
 *   elif opponentBalance <= p2:   HOLD, amount 0
 *   elif p3 == 1:                 HOLD, amount 0
 *   else:                         EXTRACT, amount p0
 * Boundaries are strict as written. Turn number and fortification state
 * do NOT affect the policy: they are not policy inputs in the circuit,
 * so the policy function must never read them. The policy is pure and
 * deterministic: same balances + params -> same action, always. No
 * history, no randomness, no I/O inside the policy.
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
import { STRATEGY_PARAMS, validateStrategyParams } from './strategyParams.js';

export const ACTION_TYPE = Object.freeze({
  HOLD: 0,
  FORTIFY: 1,
  EXTRACT: 2,
});

export const EXTRACT_MAX = 10;
export const FORTIFY_COST = 2;

function toBigInt(value, field) {
  // BigInt('') and BigInt('   ') coerce to 0n in this runtime, so an
  // absent/blank balance would silently read as zero. Reject blank
  // strings loudly; policy() throws (safePolicy fail-closes to HOLD)
  // and computePublicInputsHash errors are caught by the server.
  if (typeof value === 'string' && value.trim() === '') {
    throw new Error(`steal state field ${field} is not an integer: (empty string)`);
  }
  try {
    return BigInt(value);
  } catch {
    throw new Error(`steal state field ${field} is not an integer: ${String(value)}`);
  }
}

/**
 * Pure policy: state + params -> action. Implements the circuit rule
 * exactly; any deviation means the turn proof fails in-circuit, so the
 * rule below must never drift from the confirmed mapping.
 * @param {object} state - envelope `state` object (balances only; turn
 *   and fortify fields are ignored by design).
 * @param {Array<number|bigint>} params - 8 strategy params (defaults to
 *   the module values). Validated on every call.
 * @returns {{type: 'HOLD'|'FORTIFY'|'EXTRACT', amount?: number}}
 */
export function policy(state, params = STRATEGY_PARAMS) {
  validateStrategyParams(params);
  const [p0, p1, p2, p3] = params.map((p) => BigInt(p));
  const self = toBigInt(state.selfBalance, 'selfBalance');
  const opp = toBigInt(state.opponentBalance, 'opponentBalance');
  if (self < 0n || opp < 0n) {
    throw new Error('steal state balances must be non-negative integers');
  }
  if (self < p1) return { type: 'FORTIFY' };
  if (opp <= p2) return { type: 'HOLD' };
  if (p3 === 1n) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: Number(p0) };
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
