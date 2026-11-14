/**
 * PEGASUS — proof adapter: snarkjs proving + Kurier submission.
 *
 * NOTE: snarkjs is imported LAZILY inside generateProof(). A static import
 * keeps the Node event loop alive (observed 15 Nov 2026: a process that
 * only exported a VK never exited), which hangs test runners and CLIs.
 * Nothing here needs snarkjs until a real proof is generated.
 *
 * GATEKEEPER MAPPING — CONFIRMED by local fullProve+verify experiments
 * against the downloaded artifacts (snarkjs 0.7.6, verify=true with the
 * exported VK), 15 Nov 2026. No platform contact was involved.
 *   Inputs (13): minimum, publicBalance, expiryBlock, currentBlock,
 *     recipient, conditionRecipient, amount, maxTransfer,
 *     registeredVkHash, proofVkHash, taskId, salt, decision.
 *   decision: 1 = APPROVE, 0 = REJECT. The circuit enforces APPROVE if
 *     and only if ALL checks pass: each single trap + decision 0 proves,
 *     each trap + decision 1 fails assertion, multi-trap + decision 0
 *     proves.
 *   Public signals (13, in order): [bindingHash, registeredVkHash,
 *     proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
 *     recipient, conditionRecipient, amount, maxTransfer, decision,
 *     taskId]. NOTE: decision is signal[11] and taskId is signal[12] —
 *     verified by direct inspection of generated proofs; an earlier
 *     briefing had these two swapped. salt is the ONLY private input.
 *     signal[0] depends only on (salt, taskId). generateProof() asserts
 *     the 12 echo positions match the inputs it was given, so a wiring
 *     bug fails loudly here instead of submitting a proof of the wrong
 *     statement.
 *   Salt: FIXED to 1 for all gatekeeper proofs. Any salt is
 *     cryptographically valid; a fixed salt avoids salt management and
 *     keeps the binding-hash public signal deterministic per task.
 *
 * ENCODINGS — PROVISIONAL, must be practice-validated (see README). The
 * circuit accepts any field element, so an encoding can prove+verify
 * locally and still mismatch what the PLATFORM recomputes from the
 * envelope. All value-to-field conversion goes through the single
 * isolated toField() below; if practice feedback shows a different
 * encoding, change ONLY that function.
 *
 * VFY-POLICY MAPPING — CONFIRMED by local fullProve+verify experiments
 * against the downloaded artifacts (snarkjs 0.7.6, verify=true with the
 * exported VK), 15 Nov 2026. No platform contact was involved.
 *   Inputs (17 slots): commitment, matchId, turnNumber, selfBalance,
 *     opponentBalance, action, amount, circuitVersion, salt (scalars) +
 *     strategyParams (array of exactly 8).
 *   commitment = Poseidon([strategyParams[0..7], salt]), arity 9, salt
 *     LAST — computed ONLY via the shared module src/commitment.js (the
 *     same code the commitment CLI uses), never duplicated here. The
 *     built input is cross-checked against the envelope's registered
 *     strategyCommitment.hash when present; a mismatch refuses to prove.
 *   matchId = UUID with hyphens stripped, as a decimal integer string.
 *   action: 0 = HOLD, 1 = FORTIFY, 2 = EXTRACT. amount is EXACTLY p0 for
 *     EXTRACT, 0 for HOLD/FORTIFY (the circuit enforces both). The
 *     policy rule itself lives in src/steal.js; this adapter only
 *     encodes the action it is given, and the circuit rejects any
 *     action the policy would not produce — so a proof can never be
 *     emitted for a non-policy action.
 *   circuitVersion = 1 ("v1"). salt comes from STRATEGY_SALT (BigInt,
 *     fail-fast at startup like the HMAC secret) and is passed in
 *     through the proof data — never read from the environment here.
 *   Public signals (9, in order): [bindingHash, commitment, matchId,
 *     turnNumber, selfBalance, opponentBalance, action, amount,
 *     circuitVersion], where bindingHash =
 *     Poseidon([matchId, turnNumber, circuitVersion]), arity 3. salt
 *     and strategyParams are PRIVATE. generateProof() echo-asserts ALL
 *     9 positions (recomputing the binding hash), failing loudly on
 *     wiring bugs instead of submitting a proof of the wrong statement.
 *   Proof generation failure (e.g. a fail-closed HOLD the circuit
 *   rejects) propagates as an error: the server degrades to a
 *   proof-less turn response and logs loudly. Evidence is never faked.
 *
 * Deadline discipline: proof generation + Kurier submission + opportunistic
 * polling must fit inside the caller's budget. The response is NEVER held
 * waiting for Finalized — the proof and public signals ride in the response
 * itself so the platform can verify independently. Proof generation
 * measured ~1s locally, comfortably inside the response budget.
 */
import { keccak256 } from 'js-sha3';
import { CIRCUIT } from './config.js';
import { KurierClient } from './kurier.js';
import { computeBindingHash, computeCommitment } from './commitment.js';
import { STRATEGY_PARAMS, validateStrategyParams } from './strategyParams.js';
import { ACTION_TYPE } from './steal.js';

export const BN128_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Fixed gatekeeper salt (see header). Any salt works; fixed keeps the
// binding hash deterministic per task and needs no salt management.
const GATEKEEPER_SALT = 1n;

function keccakToField(bytes) {
  return BigInt(`0x${keccak256(bytes)}`) % BN128_FIELD_MODULUS;
}

/**
 * PROVISIONAL ENCODING (practice-validation item). Convert an envelope
 * value to a BN128 field element:
 *  - hex strings (0x...) and decimal integers parse to BigInt and are used
 *    directly when below the field modulus;
 *  - values at/above the modulus (e.g. most 32-byte hashes) use
 *    keccak256 of the value bytes, mod the field modulus;
 *  - non-numeric strings (e.g. task_id "gk_...") use keccak256 of the
 *    UTF-8 bytes, mod the field modulus.
 * @returns {bigint} always < BN128_FIELD_MODULUS.
 */
export function toField(value) {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new Error('toField: negative values are not field elements');
    if (value < BN128_FIELD_MODULUS) return value;
    const hex = value.toString(16).padStart(64, '0');
    return keccakToField(Buffer.from(hex, 'hex'));
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`toField: expected a non-negative integer, got ${String(value)}`);
    }
    return toField(BigInt(value));
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) {
      let hex = s.slice(2);
      if (hex.length % 2 !== 0) hex = `0${hex}`;
      const bytes = Buffer.from(hex, 'hex');
      const n = BigInt(s);
      if (n < BN128_FIELD_MODULUS) return n;
      return keccakToField(bytes);
    }
    if (/^\d+$/.test(s)) {
      const n = BigInt(s);
      if (n < BN128_FIELD_MODULUS) return n;
      return keccakToField(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
    }
    return keccakToField(Buffer.from(s, 'utf8'));
  }
  throw new Error(`toField: unsupported value (type ${typeof value})`);
}

function buildGatekeeperInput(data) {
  const input = data?.input ?? {};
  const decision = data?.decision;
  if (decision !== 'APPROVE' && decision !== 'REJECT') {
    throw new Error(`gatekeeper proof requires decision APPROVE|REJECT, got ${String(decision)}`);
  }
  const taskId = data?.taskId ?? '';
  return {
    minimum: toField(input.minimum).toString(),
    publicBalance: toField(input.public_balance).toString(),
    expiryBlock: toField(input.expiry_block).toString(),
    currentBlock: toField(input.current_block).toString(),
    recipient: toField(input.recipient).toString(),
    conditionRecipient: toField(input.condition_recipient).toString(),
    amount: toField(input.amount).toString(),
    maxTransfer: toField(input.max_transfer).toString(),
    registeredVkHash: toField(input.registered_vk).toString(),
    proofVkHash: toField(input.proof_vk).toString(),
    taskId: toField(taskId).toString(),
    salt: GATEKEEPER_SALT.toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
  };
}

function parseNonNegativeInteger(value, field) {
  let n;
  try {
    n = BigInt(value);
  } catch {
    throw new Error(`vfyPolicy input ${field} is not an integer: ${String(value)}`);
  }
  if (n < 0n) {
    throw new Error(`vfyPolicy input ${field} must be non-negative, got ${String(value)}`);
  }
  return n;
}

// matchId: UUID with hyphens stripped, interpreted as hex, passed to the
// circuit as a decimal integer string (CONFIRMED encoding).
function parseMatchId(matchId) {
  const s = String(matchId ?? '').trim();
  const hex = s.replace(/^0x/i, '').replace(/-/g, '');
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('vfyPolicy input matchId is not a UUID (hex with hyphens)');
  }
  return BigInt(`0x${hex}`).toString();
}

async function buildVfyPolicyInput(data) {
  const envelope = data?.envelope ?? {};
  const action = data?.action ?? {};
  const params = data?.params ?? STRATEGY_PARAMS;
  validateStrategyParams(params);

  const salt = data?.salt;
  if (typeof salt !== 'bigint') {
    throw new Error(
      'vfyPolicy proof requires the strategy salt as a BigInt in data.salt ' +
        '(STRATEGY_SALT must be set; see src/config.js).',
    );
  }
  if (salt < 0n || salt >= BN128_FIELD_MODULUS) {
    throw new Error('vfyPolicy proof: strategy salt out of BN128 field range.');
  }

  // Commitment via the shared module ONLY — the same computation the
  // commitment CLI performs, so proofs match the registered hash.
  const commitment = await computeCommitment(params, salt);

  // Cross-check against the registered hash the platform sent, when
  // present. A mismatch means the salt/params do not match the dashboard
  // registration: proving would produce evidence the platform rejects,
  // so refuse loudly instead of emitting a useless proof.
  const envelopeHash = envelope.strategyCommitment?.hash;
  if (envelopeHash !== null && envelopeHash !== undefined && String(envelopeHash) !== '') {
    let registered;
    try {
      registered = BigInt(envelopeHash);
    } catch {
      throw new Error('strategyCommitment.hash is not parseable as an integer');
    }
    if (registered !== BigInt(commitment)) {
      throw new Error(
        'local commitment does not match the registered strategyCommitment.hash: ' +
          'check STRATEGY_SALT and strategy params against the dashboard registration.',
      );
    }
  }

  const actionCode = ACTION_TYPE[action.type];
  if (actionCode === undefined) {
    throw new Error(`vfyPolicy proof requires action HOLD|FORTIFY|EXTRACT, got ${String(action.type)}`);
  }
  // EXTRACT amount must come from the policy output; the circuit itself
  // enforces amount == p0, so a wrong amount fails proving (never a
  // proof for a non-policy action). HOLD/FORTIFY always carry 0.
  const amount =
    action.type === 'EXTRACT'
      ? parseNonNegativeInteger(action.amount, 'amount')
      : 0n;

  return {
    commitment,
    matchId: parseMatchId(envelope.matchId),
    turnNumber: parseNonNegativeInteger(envelope.turn, 'turn').toString(),
    selfBalance: parseNonNegativeInteger(envelope.state?.selfBalance, 'selfBalance').toString(),
    opponentBalance: parseNonNegativeInteger(
      envelope.state?.opponentBalance,
      'opponentBalance',
    ).toString(),
    action: String(actionCode),
    amount: amount.toString(),
    circuitVersion: '1',
    salt: salt.toString(),
    strategyParams: params.map((p) => BigInt(p).toString()),
  };
}

/**
 * Map task/turn data to the circuit's snarkjs input object. Async:
 * the vfyPolicy branch computes a Poseidon commitment.
 */
export async function buildCircuitInput(circuit, data) {
  if (circuit === 'gatekeeper') return buildGatekeeperInput(data);
  if (circuit === 'vfyPolicy') return buildVfyPolicyInput(data);
  throw new Error(`unknown circuit: ${String(circuit)}`);
}

function assertGatekeeperSignals(input, signals) {
  if (signals.length !== CIRCUIT.gatekeeper.nPublic) {
    throw new Error(
      `gatekeeper proof has ${signals.length} public signals, expected ${CIRCUIT.gatekeeper.nPublic}`,
    );
  }
  // signals[0] is the binding hash (salt, taskId) — not asserted here.
  // signals[1..12] must echo the inputs, in the confirmed order.
  const expected = [
    input.registeredVkHash,
    input.proofVkHash,
    input.minimum,
    input.publicBalance,
    input.expiryBlock,
    input.currentBlock,
    input.recipient,
    input.conditionRecipient,
    input.amount,
    input.maxTransfer,
    input.decision,
    input.taskId,
  ];
  const actual = signals.slice(1);
  for (let i = 0; i < expected.length; i += 1) {
    if (actual[i] !== expected[i]) {
      throw new Error(
        `gatekeeper public signal[${i + 1}] mismatch: expected ${expected[i]}, got ${actual[i]}. ` +
          'The proof would state different facts than the task — refusing to use it.',
      );
    }
  }
}

async function assertVfyPolicySignals(input, signals) {
  if (signals.length !== CIRCUIT.vfyPolicy.nPublic) {
    throw new Error(
      `vfyPolicy proof has ${signals.length} public signals, expected ${CIRCUIT.vfyPolicy.nPublic}`,
    );
  }
  // signals[0] is the binding hash Poseidon([matchId, turnNumber,
  // circuitVersion]) — recomputed here, not trusted from the prover.
  const expectedSig0 = await computeBindingHash(
    input.matchId,
    input.turnNumber,
    input.circuitVersion,
  );
  if (signals[0] !== expectedSig0) {
    throw new Error(
      'vfyPolicy public signal[0] (binding hash) mismatch: the proof is not ' +
        'bound to this match/turn/version — refusing to use it.',
    );
  }
  // signals[1..8] must echo the inputs, in the confirmed order.
  const expected = [
    input.commitment,
    input.matchId,
    input.turnNumber,
    input.selfBalance,
    input.opponentBalance,
    input.action,
    input.amount,
    input.circuitVersion,
  ];
  const actual = signals.slice(1);
  for (let i = 0; i < expected.length; i += 1) {
    if (actual[i] !== expected[i]) {
      throw new Error(
        `vfyPolicy public signal[${i + 1}] mismatch: expected ${expected[i]}, got ${actual[i]}. ` +
          'The proof would state different facts than the turn — refusing to use it.',
      );
    }
  }
}

/**
 * Generate a Groth16 proof with the downloaded artifacts.
 * @returns {{proof: object, publicSignals: string[]}}
 * @throws when the witness fails (e.g. the circuit rejects the action)
 *   or a public-signal echo check fails. Callers degrade loudly.
 */
export async function generateProof(circuit, data) {
  const input = await buildCircuitInput(circuit, data);
  const artifacts = CIRCUIT[circuit];
  const snarkjs = await import('snarkjs');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    artifacts.wasm,
    artifacts.zkey,
  );
  const signals = publicSignals.map(String);
  if (circuit === 'gatekeeper') assertGatekeeperSignals(input, signals);
  if (circuit === 'vfyPolicy') await assertVfyPolicySignals(input, signals);
  return { proof, publicSignals: signals };
}

/**
 * Full evidence pipeline for one task/turn:
 *   generate proof -> submit to Kurier (one attempt) -> poll opportunistically
 *   inside the remaining budget.
 * @param {object} opts - { circuit, data, kurier: KurierClient|null,
 *   deadlineMs, onEvent }
 * @returns {{proof, publicSignals, proofReference, kurierStatus,
 *   kurierFinalized}}
 * @throws when proof generation fails (witness rejection, bad input).
 *   Kurier failures never throw: the proof still rides in the response.
 */
export async function proveAndSubmit({
  circuit,
  data,
  kurier = null,
  deadlineMs,
  onEvent = null,
}) {
  const started = Date.now();
  const remaining = () => Math.max(0, deadlineMs - (Date.now() - started));

  const { proof, publicSignals } = await generateProof(circuit, data);
  if (onEvent) onEvent('proof_generated', { circuit });

  let proofReference = null;
  let kurierStatus = null;
  let kurierFinalized = false;

  if (kurier instanceof KurierClient) {
    try {
      const job = await kurier.submitProof({
        proof,
        publicSignals,
        vkHash: CIRCUIT[circuit].vkHash,
        timeoutMs: Math.min(20_000, remaining()),
      });
      proofReference = job?.jobId ?? null;
      kurierStatus = job?.status ?? 'Submitted';
      if (onEvent) onEvent('kurier_submitted', { jobId: proofReference });
      if (proofReference && remaining() > 0) {
        const waited = await kurier.waitForFinalized(proofReference, {
          deadlineMs: remaining(),
          onStatus: (status) => {
            kurierStatus = status;
            if (onEvent) onEvent('kurier_status', { status });
          },
        });
        kurierFinalized = waited.finalized;
        kurierStatus = waited.status ?? kurierStatus;
      }
    } catch (err) {
      // Kurier failure must never lose the decision: the proof still rides
      // in the response for independent platform verification.
      if (onEvent) onEvent('kurier_failed', { error: err.message });
    }
  }

  return { proof, publicSignals, proofReference, kurierStatus, kurierFinalized };
}

/**
 * Default proof provider used by the server. Swappable in tests.
 * Proof-generation failures propagate: the server catches them, logs
 * loudly, and degrades to a proof-less (but schema-valid) response.
 * Evidence is never faked or silently degraded here.
 */
export async function defaultProofProvider(opts) {
  return proveAndSubmit(opts);
}
