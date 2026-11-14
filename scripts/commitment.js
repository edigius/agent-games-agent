#!/usr/bin/env node
/**
 * PEGASUS — strategy commitment helper.
 *
 * The platform requires a strategy COMMITMENT registered from the
 * dashboard (My Agents -> Edit agent -> Strategy Commitment) before
 * Swiss Round 1. This script computes and prints ONLY the hash — never
 * the params, never the salt.
 *
 * The commitment formula is CONFIRMED by local fullProve+verify
 * experiments against the vfy-policy circuit (15 Nov 2026):
 *   commitment = Poseidon([strategyParams[0..7], salt])
 * Poseidon arity 9, params first, salt LAST. The computation lives in
 * the shared module src/commitment.js — the SAME code the proof adapter
 * uses — so the registered hash always matches turn proofs by
 * construction. Never duplicate the formula here.
 *
 * Usage: STRATEGY_SALT=<secret> npm run commitment
 * The salt must come from the environment only. It is never printed.
 * The script refuses (non-zero exit) when STRATEGY_SALT is missing or
 * invalid, or when the strategy params are invalid.
 */
import { pathToFileURL } from 'node:url';
import { computeCommitment, parseStrategySalt } from '../src/commitment.js';
import { STRATEGY_PARAMS } from '../src/strategyParams.js';

// Re-exported so tests can verify the CLI and the proof adapter share
// one implementation (same function object, same hash for same inputs).
export { computeCommitment };

async function main() {
  let salt;
  try {
    salt = parseStrategySalt(process.env.STRATEGY_SALT);
  } catch (err) {
    // parseStrategySalt messages never echo the value.
    console.error(`commitment refused: ${err.message}`);
    process.exit(1);
  }
  try {
    const hash = await computeCommitment(STRATEGY_PARAMS, salt);
    // ONLY the hash is ever printed.
    console.log(hash);
    process.exit(0);
  } catch (err) {
    console.error(`commitment refused: ${err.message}`);
    process.exit(1);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
