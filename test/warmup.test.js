import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildWarmupProofData, runWarmup, WARMUP_TASK_ID } from '../src/warmup.js';
import { CIRCUIT } from '../src/config.js';

const SILENT = () => {};

describe('startup warm-up', () => {
  it('builds trap-failing inputs with a REJECT decision', () => {
    const data = buildWarmupProofData();
    assert.equal(data.decision, 'REJECT');
    assert.equal(data.taskId, WARMUP_TASK_ID);
    assert.equal(data.input.registered_vk, data.input.proof_vk);
    assert.equal(data.input.recipient, data.input.condition_recipient);
    assert.ok(BigInt(data.input.public_balance) < BigInt(data.input.minimum));
    assert.ok(BigInt(data.input.amount) > BigInt(data.input.max_transfer));
    assert.ok(data.input.current_block < data.input.expiry_block);
  });

  it('succeeds end-to-end with the real prover and VK (dummy proof verifies)', async () => {
    const result = await runWarmup({ log: SILENT });
    assert.equal(result.ok, true);
    assert.equal(result.error, undefined);
    assert.ok(typeof result.durationMs === 'number' && result.durationMs >= 0);
  });

  it('reports failure (never throws) when a circuit artifact is missing', async () => {
    const broken = {
      gatekeeper: { ...CIRCUIT.gatekeeper, wasm: 'circuits/does-not-exist.wasm' },
      vfyPolicy: CIRCUIT.vfyPolicy,
    };
    let proveCalls = 0;
    const result = await runWarmup({
      log: SILENT,
      circuits: broken,
      prove: async () => {
        proveCalls += 1;
        throw new Error('must not prove with missing artifacts');
      },
    });
    assert.equal(result.ok, false);
    assert.match(result.error, /ENOENT|does-not-exist/);
    assert.equal(proveCalls, 0);
  });

  it('reports failure (never throws) when the dummy proof fails', async () => {
    const result = await runWarmup({
      log: SILENT,
      prove: async () => {
        throw new Error('simulated prover failure');
      },
    });
    assert.equal(result.ok, false);
    assert.match(result.error, /simulated prover failure/);
  });

  it('reports failure when the dummy proof does not verify', async () => {
    const result = await runWarmup({
      log: SILENT,
      prove: async () => ({ proof: {}, publicSignals: ['1'] }),
      verifyProof: async () => false,
    });
    assert.equal(result.ok, false);
    assert.match(result.error, /did not verify/);
  });

  it('succeeds with injected prove/verify seams (fast path, no snarkjs proving)', async () => {
    const seen = [];
    const result = await runWarmup({
      log: SILENT,
      prove: async (circuit, data) => {
        seen.push([circuit, data.taskId]);
        return { proof: { fake: true }, publicSignals: ['7'] };
      },
      verifyProof: async () => true,
    });
    assert.equal(result.ok, true);
    assert.deepEqual(seen, [['gatekeeper', WARMUP_TASK_ID]]);
  });
});
