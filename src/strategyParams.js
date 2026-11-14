/**
 * PEGASUS — Steal the VFY strategy parameters (CONFIRMED circuit format).
 *
 * The vfy-policy circuit's strategy is EXACTLY these 8 field elements.
 * The policy rule they parameterize (confirmed by local fullProve+verify
 * experiments, 15 Nov 2026) is, in precedence order:
 *   if selfBalance < p1:          FORTIFY, amount 0
 *   elif opponentBalance <= p2:   HOLD, amount 0
 *   elif p3 == 1:                 HOLD, amount 0
 *   else:                         EXTRACT, amount p0
 * Boundaries are strict as written: self == p1 does NOT fortify;
 * opponent == p2 HOLDS. Turn number and fortification state do NOT
 * affect the policy — they are not policy inputs in the circuit.
 *
 * Param roles and valid ranges (in-circuit gates; game values):
 *   p0  EXTRACT amount.            1..10 (0 or >=11 unprovable).
 *   p1  FORTIFY threshold on own balance. 0 disables FORTIFY; game 0..200.
 *   p2  HOLD threshold on opponent balance. Game 0..200.
 *   p3  Passive flag: 1 disables EXTRACT (HOLD instead). {0, 1} only.
 *   p4..p7  RESERVED. Must be 0 (any nonzero value is unprovable).
 *
 * This file is the ONLY place strategy values live. The commitment is
 * computed from exactly these values plus the secret salt via the shared
 * module src/commitment.js — the same code path the proof adapter uses,
 * so proofs always match the registered hash by construction.
 *
 * NEVER log these values, never put them in a prompt, never commit the
 * salt. The edge depends on them staying private until reveal.
 */

// Index names for readability at use sites (policy, simulator search).
export const PARAM_INDEX = Object.freeze({
  EXTRACT_AMOUNT: 0,
  FORTIFY_THRESHOLD: 1,
  HOLD_THRESHOLD: 2,
  PASSIVE_FLAG: 3,
});

const GAME_BALANCE_MAX = 200;

/**
 * Validate a candidate 8-param array against the circuit gates + game
 * ranges. Throws a specific Error on the first violation. Called at
 * startup (refuse to boot on invalid params), on every policy call, and
 * on every proof build — invalid params must never silently produce a
 * proof-less turn or a wrong commitment.
 */
export function validateStrategyParams(params) {
  if (!Array.isArray(params) || params.length !== 8) {
    throw new Error('strategy params must be an array of exactly 8 values');
  }
  const values = params.map((p, i) => {
    if (typeof p === 'number') {
      if (!Number.isInteger(p)) {
        throw new Error(`strategy param p${i} must be an integer, got ${String(p)}`);
      }
      return BigInt(p);
    }
    if (typeof p === 'bigint') return p;
    throw new Error(`strategy param p${i} must be an integer, got ${typeof p}`);
  });
  const [p0, p1, p2, p3, p4, p5, p6, p7] = values;
  if (p0 < 1n || p0 > 10n) {
    throw new Error(`strategy param p0 (EXTRACT amount) must be 1..10, got ${p0}`);
  }
  if (p1 < 0n || p1 > BigInt(GAME_BALANCE_MAX)) {
    throw new Error(`strategy param p1 (FORTIFY threshold) must be 0..200, got ${p1}`);
  }
  if (p2 < 0n || p2 > BigInt(GAME_BALANCE_MAX)) {
    throw new Error(`strategy param p2 (HOLD threshold) must be 0..200, got ${p2}`);
  }
  if (p3 !== 0n && p3 !== 1n) {
    throw new Error(`strategy param p3 (passive flag) must be 0 or 1, got ${p3}`);
  }
  for (const [i, p] of [[4, p4], [5, p5], [6, p6], [7, p7]]) {
    if (p !== 0n) {
      throw new Error(`strategy param p${i} is RESERVED and must be 0, got ${p}`);
    }
  }
}

// WINNER of the staged search (scripts/simulate.js --search, seed
// 20261115, 15 Nov 2026): coarse grid 360 configs x 50 matches, refine
// 52 configs x 200 matches, verify 6 candidates x 1000 matches per
// opponent. Verified result: W 4000 / D 1000 / L 0 across the 5-opponent
// battery (always-extract-10: 1000 draws; always-fortify, always-hold,
// random, tit-for-tat: 1000 wins each), total margin 565.2.
// NOTE: p1 is UNIDENTIFIABLE under this battery — p1 in {0,10,20,25,50}
// (and 100 in spot checks) tie EXACTLY, because self never drops into
// FORTIFY range against these opponents. The winner is the first-ranked
// by the deterministic tie-break (grid order). Do NOT hand-tune p1:
// any change needs a battery that actually reaches low-self states
// (e.g. threshold-policy opponents) and a fresh search.
export const STRATEGY_PARAMS = Object.freeze([10, 0, 0, 0, 0, 0, 0, 0]);
