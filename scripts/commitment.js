#!/usr/bin/env node
/**
 * PEGASUS — strategy commitment helper.
 *
 * The platform requires a strategy COMMITMENT (a Poseidon hash of the
 * strategy params + salt) registered from the dashboard before Swiss
 * Round 1. This script exists to compute and print ONLY the hash — never
 * the params, never the salt.
 *
 * BLOCKER: the Poseidon preimage layout is UNPUBLISHED. The docs say only
 * "a Poseidon hash of my strategy params + salt": no field order, no arity,
 * no encoding, no salt placement, and the circuit's parameter format is
 * unknown. Computing a hash from a guessed layout would register a
 * commitment the circuit can never match, silently breaking every turn
 * proof. This script therefore REFUSES to output a hash until the official
 * layout is known. When it is, implement computeCommitment() below, add a
 * test against an official worked example, and remove the refusal.
 *
 * Usage (once implemented): STRATEGY_SALT=<secret> npm run commitment
 * The salt must come from the environment only. It is never printed.
 */
import { pathToFileURL } from 'node:url';
import { STRATEGY_PARAMS } from '../src/strategyParams.js';

export function computeCommitment(_params, _salt) {
  throw new Error(
    'Commitment preimage layout is UNKNOWN: the official Poseidon input ' +
      'order/encoding for strategy params + salt is unpublished. Refusing ' +
      'to guess — a wrong commitment would invalidate every policy proof. ' +
      'See scripts/commitment.js header and README "Known unknowns".',
  );
}

function main() {
  const salt = process.env.STRATEGY_SALT ?? '';
  if (!salt) {
    console.error('STRATEGY_SALT is not set. Set it as an environment variable; never commit it.');
    process.exit(1);
  }
  try {
    const hash = computeCommitment(STRATEGY_PARAMS, salt);
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
