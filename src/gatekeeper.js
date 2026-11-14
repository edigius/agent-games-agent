/**
 * PEGASUS — Proof Gatekeeper decision logic. Pure and deterministic.
 *
 * Inputs: the envelope `input` object ONLY. No on-chain lookup is attempted
 * for the incoming proof: the public docs publish no lookup API for
 * proof_tx, and the envelope carries no proof bytes to verify. proof_tx is
 * treated as an audit pointer (echoed in the response) and as the seen-set
 * key for replay detection. This is a deliberate, documented design
 * revision — see README "Known unknowns".
 *
 * Check order (fixed priority; traps are documented as single-variety, so
 * order only matters for multi-anomaly envelopes, which should not occur):
 *   1. PROOF_REUSED     — proof_tx already decided (persistent seen-set).
 *      Checked FIRST: a replayed task must be answered with NO proof (valid
 *      facts + REJECT is unprovable in the circuit), so the replay branch
 *      short-circuits before any other check and before proof generation.
 *   2. VK_SUBSTITUTION  — proof_vk != registered_vk
 *   3. EXPIRED_CONDITION — current_block >= expiry_block (STRICT: equality
 *      is expired — confirmed by circuit experiments 15 Nov 2026)
 *   4. RECIPIENT_MISMATCH — recipient != condition_recipient
 *   5. THRESHOLD_MISMATCH — public_balance < minimum
 *   6. AMOUNT_OVERFLOW  — amount > max_transfer
 *   7. otherwise VALID_CONDITION → APPROVE
 *
 * Boundary semantics (CONFIRMED by local fullProve experiments against the
 * downloaded circuit, 15 Nov 2026):
 *   - balance == minimum PASSES (check is "meets or exceeds").
 *   - amount == max_transfer PASSES (overflow is strictly greater).
 *   - current_block == expiry_block IS EXPIRED (reject when current >=
 *     expiry). The circuit enforces the strict comparison: APPROVE at
 *     equality fails assertion, REJECT proves.
 *
 * Hex values (VK hashes, addresses) compare case-insensitively: checksummed
 * vs lowercase spellings of the same address/hash are the same value.
 */
import { REASON_CODE, TRAP, TRAP_TO_REASON_CODE } from './reasonCodes.js';

function normalizeHex(value) {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  return trimmed.startsWith('0x') || trimmed.startsWith('0X')
    ? trimmed.toLowerCase()
    : trimmed;
}

function toBigInt(value, field) {
  try {
    return BigInt(value);
  } catch {
    throw new Error(`gatekeeper input field ${field} is not an integer: ${String(value)}`);
  }
}

function toBlock(value, field) {
  const n = typeof value === 'bigint' ? value : toBigInt(value, field);
  return n;
}

/**
 * Decide a Gatekeeper task.
 * @param {object} input - envelope `input` object.
 * @param {object} ctx - { isReplay: boolean } — caller checks the seen-set.
 * @returns {{decision: 'APPROVE'|'REJECT', reasonCode: string, trap: string,
 *           checks: Array<{name: string, passed: boolean, detail: string}>}}
 */
export function decideGatekeeper(input, ctx = {}) {
  const checks = [];
  const fail = (trap, name, detail) => {
    checks.push({ name, passed: false, detail });
    return {
      decision: 'REJECT',
      reasonCode: TRAP_TO_REASON_CODE[trap],
      trap,
      checks,
    };
  };
  const pass = (name, detail) => checks.push({ name, passed: true, detail });

  const registeredVk = normalizeHex(input.registered_vk);
  const proofVk = normalizeHex(input.proof_vk);

  // 1. Replay — checked FIRST (see header). Caller owns the persistent
  // seen-set; the server short-circuits replay tasks before proving.
  if (ctx.isReplay) {
    return fail(
      TRAP.PROOF_REUSED,
      'proof_fresh',
      'proof_tx was already decided',
    );
  }
  pass('proof_fresh', 'proof_tx not seen before');

  // 2. VK substitution. NOTE: CIRCUIT_MISMATCH ("proof_vk belongs to an
  // unrelated circuit") cannot be distinguished from VK_SUBSTITUTION with
  // only two hashes in the envelope, so every mismatch uses VK_SUBSTITUTION.
  if (registeredVk !== proofVk) {
    return fail(
      TRAP.VK_SUBSTITUTION,
      'vk_match',
      'proof_vk does not match registered_vk',
    );
  }
  pass('vk_match', 'proof_vk matches registered_vk');

  // 3. Expiry. STRICT: current == expiry is expired (circuit-confirmed).
  const currentBlock = toBlock(input.current_block, 'current_block');
  const expiryBlock = toBlock(input.expiry_block, 'expiry_block');
  if (currentBlock >= expiryBlock) {
    return fail(
      TRAP.EXPIRED_CONDITION,
      'not_expired',
      `current_block ${currentBlock} has reached expiry_block ${expiryBlock}`,
    );
  }
  pass('not_expired', `current_block ${currentBlock} < expiry_block ${expiryBlock}`);

  // 4. Recipient.
  const recipient = normalizeHex(input.recipient);
  const conditionRecipient = normalizeHex(input.condition_recipient);
  if (recipient !== conditionRecipient) {
    return fail(
      TRAP.RECIPIENT_MISMATCH,
      'recipient_match',
      'recipient does not match condition_recipient',
    );
  }
  pass('recipient_match', 'recipient matches condition_recipient');

  // 5. Threshold. Boundary: balance == minimum passes.
  const balance = toBigInt(input.public_balance, 'public_balance');
  const minimum = toBigInt(input.minimum, 'minimum');
  if (balance < minimum) {
    return fail(
      TRAP.THRESHOLD_MISMATCH,
      'threshold',
      `public_balance ${balance} is below minimum ${minimum}`,
    );
  }
  pass('threshold', `public_balance ${balance} >= minimum ${minimum}`);

  // 6. Amount overflow. Boundary: amount == max_transfer passes.
  const amount = toBigInt(input.amount, 'amount');
  const maxTransfer = toBigInt(input.max_transfer, 'max_transfer');
  if (amount > maxTransfer) {
    return fail(
      TRAP.AMOUNT_OVERFLOW,
      'amount_cap',
      `amount ${amount} exceeds max_transfer ${maxTransfer}`,
    );
  }
  pass('amount_cap', `amount ${amount} <= max_transfer ${maxTransfer}`);

  return {
    decision: 'APPROVE',
    reasonCode: REASON_CODE.VALID_PROOF,
    trap: TRAP.VALID_CONDITION,
    checks,
  };
}
