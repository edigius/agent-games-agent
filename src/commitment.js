/**
 * PEGASUS — shared Poseidon commitment module (Steal the VFY).
 *
 * SINGLE SOURCE OF TRUTH for the strategy commitment. Both users — the
 * proof adapter (src/proof.js) and the commitment CLI
 * (scripts/commitment.js) — compute through this module, so the salt +
 * params used for turn proofs always match the registered hash BY
 * CONSTRUCTION. Never duplicate this formula anywhere else.
 *
 * CONFIRMED by local fullProve+verify experiments against the downloaded
 * vfy-policy artifacts (15 Nov 2026, no platform contact; see the
 * discovery findings in the research notes):
 *   commitment = Poseidon([strategyParams[0..7], salt])
 * Poseidon arity 9, params first, salt LAST (circomlibjs buildPoseidon).
 * The dashboard-registered strategyCommitment.hash must equal this value.
 *
 * The circuit's second Poseidon hash binds a proof to one match + turn:
 *   sig[0] = Poseidon([matchId, turnNumber, circuitVersion]), arity 3.
 * It is NOT the keccak publicInputsHash (computed off-circuit in
 * src/steal.js). computeBindingHash() here exists so generateProof() can
 * echo-assert public signal[0] like every other signal.
 *
 * circomlibjs is imported LAZILY (dynamic import inside getPoseidon) and
 * the instance is cached, mirroring the snarkjs discipline in
 * src/proof.js: importing this module must stay cheap and side-effect
 * free, and nothing pays Poseidon init until a hash is actually needed.
 *
 * NEVER log params or salt. The commitment hash itself is public (it is
 * registered on the dashboard), but this module never prints anything.
 */
import { validateStrategyParams } from './strategyParams.js';

export const BN128_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidonInstance = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    const mod = await import('circomlibjs');
    const buildPoseidon = mod.buildPoseidon ?? mod.default?.buildPoseidon;
    if (typeof buildPoseidon !== 'function') {
      throw new Error('circomlibjs buildPoseidon not found: cannot compute Poseidon hashes');
    }
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

async function poseidonHash(fieldElements) {
  const poseidon = await getPoseidon();
  // Inputs MUST be BigInts; output is the canonical decimal string.
  const out = poseidon(fieldElements.map((v) => BigInt(v)));
  return poseidon.F.toObject(out).toString();
}

/**
 * Parse STRATEGY_SALT from its environment-string form.
 * The salt must be a non-negative integer below the BN128 field modulus
 * (any field element is valid in-circuit; out-of-field values are
 * refused rather than silently reduced, so a typo fails fast).
 * Error messages NEVER echo the value.
 * @returns {bigint}
 */
export function parseStrategySalt(value) {
  if (value === undefined || value === null || String(value).trim() === '') {
    throw new Error(
      'STRATEGY_SALT is not set. Set it as an environment variable; never commit it.',
    );
  }
  let salt;
  try {
    salt = BigInt(String(value).trim());
  } catch {
    throw new Error('STRATEGY_SALT is not a valid integer.');
  }
  if (salt < 0n || salt >= BN128_FIELD_MODULUS) {
    throw new Error('STRATEGY_SALT is out of BN128 field range.');
  }
  return salt;
}

/**
 * Compute the strategy commitment for one params array + salt.
 * @param {Array<number|bigint>} params - exactly 8 validated params.
 * @param {bigint} salt - parsed via parseStrategySalt().
 * @returns {Promise<string>} decimal-string commitment hash.
 */
export async function computeCommitment(params, salt) {
  validateStrategyParams(params);
  if (typeof salt !== 'bigint') {
    throw new Error('computeCommitment requires the salt as a BigInt (see parseStrategySalt).');
  }
  if (salt < 0n || salt >= BN128_FIELD_MODULUS) {
    throw new Error('computeCommitment: salt out of BN128 field range.');
  }
  return poseidonHash([...params, salt]);
}

/**
 * Compute the circuit's binding hash: Poseidon([matchId, turnNumber,
 * circuitVersion]), arity 3. Inputs are BigInt-convertible values
 * (decimal strings, numbers, or BigInts).
 * @returns {Promise<string>} decimal-string hash.
 */
export async function computeBindingHash(matchId, turnNumber, circuitVersion) {
  return poseidonHash([matchId, turnNumber, circuitVersion]);
}
