/**
 * PEGASUS — Steal the VFY strategy parameters.
 *
 * PROVISIONAL — DO NOT COMMIT THESE VALUES TO THE PLATFORM YET.
 *
 * These numbers are a starting point for the local simulator only. They are
 * NOT a tuned strategy: no simulation-driven tuning has been done, and the
 * vfy-policy circuit's parameter format is unpublished, so it is not yet
 * known whether a strategy of this shape is even expressible in the
 * circuit. When the circuit parameter semantics are known, this file is the
 * ONLY place strategy values live, and the commitment must be computed from
 * exactly these values plus the secret salt.
 *
 * The policy is a pure function of the envelope state only
 * (selfBalance, opponentBalance, turn, fortify flags) — that is all the
 * circuit can see, so no match history or opponent modeling may leak into
 * the policy function. Opponent modeling belongs in the simulator, which
 * tests this policy against many opponent styles.
 *
 * NEVER log these values, never put them in a prompt, never commit the
 * salt. The edge depends on them staying private until reveal.
 */
export const STRATEGY_PARAMS = Object.freeze({
  // Total turns per match (documented: 20). Turn numbering (0- or 1-based)
  // is unpublished; the policy treats turn >= TOTAL_TURNS - 1 as the final
  // turn, which is safe under either convention.
  TOTAL_TURNS: 20,

  // EXTRACT amount used whenever the policy extracts (documented cap: 10).
  EXTRACT_AMOUNT: 10,

  // Protect a lead: FORTIFY when ahead by at least this much outside the
  // endgame window.
  LEAD_FORTIFY_THRESHOLD: 15,

  // Endgame window: in the last N turns, FORTIFY whenever ahead at all.
  ENDGAME_TURNS: 3,

  // Below this balance, always EXTRACT (must claw balance back; paying 2
  // for FORTIFY when nearly broke concedes the match).
  LOW_BALANCE_THRESHOLD: 10,
});
