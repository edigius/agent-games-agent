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
 * VFY-POLICY MAPPING — STILL UNKNOWN (discovery running separately).
 * buildCircuitInput() throws CircuitMappingError for 'vfyPolicy', and the
 * server degrades to proof-less turn responses until it is implemented.
 * Do not guess the mapping.
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

export const BN128_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Fixed gatekeeper salt (see header). Any salt works; fixed keeps the
// binding hash deterministic per task and needs no salt management.
const GATEKEEPER_SALT = 1n;

export class CircuitMappingError extends Error {
  constructor(circuit) {
    super(
      `Circuit input mapping for "${circuit}" is NOT IMPLEMENTED: the ` +
        'official signal names/order are unpublished. See src/proof.js header. ' +
        'Refusing to guess — proof evidence unavailable in this mode.',
    );
    this.name = 'CircuitMappingError';
    this.circuit = circuit;
  }
}

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

/**
 * Map task/turn data to the circuit's snarkjs input object.
 * @throws {CircuitMappingError} for 'vfyPolicy' (mapping unknown).
 */
export function buildCircuitInput(circuit, data) {
  if (circuit === 'gatekeeper') return buildGatekeeperInput(data);
  if (circuit === 'vfyPolicy') throw new CircuitMappingError(circuit);
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

/**
 * Generate a Groth16 proof with the downloaded artifacts.
 * @returns {{proof: object, publicSignals: string[]}}
 */
export async function generateProof(circuit, data) {
  const input = buildCircuitInput(circuit, data);
  const artifacts = CIRCUIT[circuit];
  const snarkjs = await import('snarkjs');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    artifacts.wasm,
    artifacts.zkey,
  );
  const signals = publicSignals.map(String);
  if (circuit === 'gatekeeper') assertGatekeeperSignals(input, signals);
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
 * @throws {CircuitMappingError} when the mapping is unimplemented.
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
 * Returns null evidence on CircuitMappingError (degraded mode) instead of
 * throwing, so handlers stay simple. Other errors propagate.
 */
export async function defaultProofProvider(opts) {
  try {
    return await proveAndSubmit(opts);
  } catch (err) {
    if (err instanceof CircuitMappingError) {
      return {
        proof: null,
        publicSignals: null,
        proofReference: null,
        kurierStatus: 'mapping_unimplemented',
        kurierFinalized: false,
        degraded: true,
      };
    }
    throw err;
  }
}
