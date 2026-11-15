/**
 * PEGASUS — full startup warm-up (NEPTUN upgrade).
 *
 * Runs BEFORE the server starts listening, so the FIRST task never pays
 * cold-start costs inside its response budget and a broken proving
 * pipeline is visible at boot instead of on the first scored task:
 *   1. import snarkjs (cold import costs seconds; lazy per proof.js);
 *   2. verify all four circuit artifacts exist (both wasm + zkey files);
 *   3. parse both exported VK JSONs;
 *   4. generate ONE dummy gatekeeper REJECT proof with trap-failing
 *      inputs and verify it against the exported gatekeeper VK.
 *
 * The vfyPolicy circuit is NOT proven at boot: Steal the VFY entries
 * are locked for this tournament, so only its artifacts + VK are
 * checked. The warm-up never touches the seen-set or Kurier, and never
 * submits anything: the dummy proof is generated and verified locally
 * only, then discarded.
 *
 * Any failure logs loudly and returns ok:false — boot CONTINUES. A
 * failed warm-up means the first task falls back to exactly the old
 * behavior (lazy import, fail-closed on proof errors); staying online
 * beats refusing to start. The result is reported on GET /health as
 * `warmupOk` and in the `warmup` startup log line.
 */
import { access, readFile } from 'node:fs/promises';
import { CIRCUIT } from './config.js';
import { generateProof } from './proof.js';

export const WARMUP_TASK_ID = 'warmup';

/**
 * Dummy proof data: trap-failing facts + REJECT. The circuit proves
 * decision 0 for every trap combination (confirmed mapping), so a
 * threshold failure AND an amount overflow together still prove with
 * decision 0. VKs and recipients match, and the condition is not
 * expired, isolating exactly the two failing numeric checks.
 */
export function buildWarmupProofData() {
  const vk = `0x${'7d'.repeat(32)}`;
  const addr = '0xDe42aabbccddeeff001122334455667788990011';
  return {
    input: {
      registered_vk: vk,
      proof_vk: vk,
      minimum: '1',
      public_balance: '0',
      expiry_block: 100,
      current_block: 1,
      recipient: addr,
      condition_recipient: addr,
      amount: '2',
      max_transfer: '1',
    },
    decision: 'REJECT',
    taskId: WARMUP_TASK_ID,
  };
}

function defaultLog(event, fields = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

/**
 * Run the full warm-up. Never throws: every failure is caught, logged,
 * and reported as ok:false.
 * @param {object} deps - { log, circuits, prove, verifyProof }.
 *   `prove` defaults to generateProof and `verifyProof` to
 *   snarkjs.groth16.verify; both are injectable for tests.
 * @returns {{ok: boolean, durationMs: number, error?: string}}
 */
export async function runWarmup({
  log = defaultLog,
  circuits = CIRCUIT,
  prove = generateProof,
  verifyProof = null,
} = {}) {
  const started = Date.now();
  try {
    const snarkjs = await import('snarkjs');

    let gatekeeperVk = null;
    for (const [name, artifacts] of Object.entries(circuits)) {
      await access(artifacts.wasm);
      await access(artifacts.zkey);
      const vk = JSON.parse(await readFile(artifacts.vk, 'utf8'));
      if (name === 'gatekeeper') gatekeeperVk = vk;
    }
    if (!gatekeeperVk) {
      throw new Error('warm-up requires a gatekeeper circuit entry with a VK');
    }

    const { proof, publicSignals } = await prove('gatekeeper', buildWarmupProofData());
    const verify = verifyProof ?? ((vk, signals, p) => snarkjs.groth16.verify(vk, signals, p));
    const verified = await verify(gatekeeperVk, publicSignals, proof);
    if (!verified) {
      throw new Error('warm-up proof did not verify against the gatekeeper VK');
    }
    return { ok: true, durationMs: Date.now() - started };
  } catch (err) {
    log('warmup_failed', { error: err.message });
    return { ok: false, error: err.message, durationMs: Date.now() - started };
  }
}
