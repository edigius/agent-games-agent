import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCircuitInput, generateProof } from '../src/proof.js';
import { computeBindingHash, computeCommitment } from '../src/commitment.js';
import { computeCommitment as cliComputeCommitment } from '../scripts/commitment.js';
import { policy } from '../src/steal.js';
import { stealEnvelope } from './helpers.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

async function loadVk() {
  return JSON.parse(await readFile(join(ROOT, 'circuits/vfyPolicy.vk.json'), 'utf8'));
}

// Confirming witness values from the discovery findings (probe5, case C1).
const WITNESS_PARAMS = [1, 0, 0, 0, 0, 0, 0, 0];
const WITNESS_SALT = 0n;
const WITNESS_COMMITMENT =
  '11299471465817035813941534680224295417418949445559228777402254279479107204147';
const WITNESS_MATCH_ID = '12345678901234567890123456789012345678';
const WITNESS_SIG0 =
  '10995411097053277183020857775826853537456303561713055208882563478534966732103';

const UUID = '9f4e1b2a-0000-4000-8000-000000000001';

async function vfyData({ params, salt, self, opp, turn = 1, matchId = UUID, action = null }) {
  const hash = await computeCommitment(params, salt);
  const policyAction =
    action ?? policy({ selfBalance: String(self), opponentBalance: String(opp) }, params);
  const envelope = stealEnvelope(
    { selfBalance: String(self), opponentBalance: String(opp) },
    { matchId, turn, strategyCommitment: { hash } },
  );
  return { envelope, action: policyAction, params, salt };
}

describe('vfy-policy circuit mapping (real artifacts)', () => {
  it('commitment + binding hash reproduce the discovery witness values exactly', async () => {
    assert.equal(await computeCommitment(WITNESS_PARAMS, WITNESS_SALT), WITNESS_COMMITMENT);
    assert.equal(
      await computeBindingHash(WITNESS_MATCH_ID, 1, 1),
      WITNESS_SIG0,
    );
  });

  it('the commitment CLI and the proof adapter share one implementation', async () => {
    assert.equal(cliComputeCommitment, computeCommitment);
    const params = [7, 33, 99, 0, 0, 0, 0, 0];
    const salt = 987654321n;
    assert.equal(
      await cliComputeCommitment(params, salt),
      await computeCommitment(params, salt),
    );
    // And the built circuit input carries that same commitment.
    const input = await buildCircuitInput(
      'vfyPolicy',
      await vfyData({ params, salt, self: 100, opp: 100 }),
    );
    assert.equal(input.commitment, await computeCommitment(params, salt));
  });

  it('a proof for the confirming witness params/salt verifies against the exported VK', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const data = await vfyData({
      params: WITNESS_PARAMS,
      salt: WITNESS_SALT,
      self: 100,
      opp: 100,
      turn: 1,
    });
    const { proof, publicSignals } = await generateProof('vfyPolicy', data);
    assert.equal(publicSignals.length, 9);
    assert.equal(publicSignals[1], WITNESS_COMMITMENT);
    assert.equal(publicSignals[2], BigInt(`0x${UUID.replace(/-/g, '')}`).toString());
    assert.equal(publicSignals[3], '1');
    assert.equal(publicSignals[4], '100');
    assert.equal(publicSignals[5], '100');
    assert.equal(publicSignals[6], '2'); // EXTRACT
    assert.equal(publicSignals[7], '1'); // amount == p0
    assert.equal(publicSignals[8], '1'); // circuitVersion
    assert.equal(
      publicSignals[0],
      await computeBindingHash(publicSignals[2], 1, 1),
    );
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  });

  it('policy precedence + boundary cases prove and verify', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const cases = [
      // [params, self, opp, expected action, expected amount, label]
      [[5, 50, 100, 0, 0, 0, 0, 0], 10, 190, '1', '0', 'FORTIFY: self < p1'],
      [[5, 50, 100, 0, 0, 0, 0, 0], 50, 150, '2', '5', 'boundary: self == p1 extracts'],
      [[5, 50, 100, 0, 0, 0, 0, 0], 100, 100, '0', '0', 'boundary: opp == p2 holds'],
      [[5, 50, 100, 1, 0, 0, 0, 0], 100, 150, '0', '0', 'passive flag holds'],
      [[5, 50, 100, 1, 0, 0, 0, 0], 10, 190, '1', '0', 'fortify beats passive flag'],
    ];
    for (const [params, self, opp, wantAction, wantAmount, label] of cases) {
      const data = await vfyData({ params, salt: 7n, self, opp });
      const { proof, publicSignals } = await generateProof('vfyPolicy', data);
      assert.equal(publicSignals[6], wantAction, label);
      assert.equal(publicSignals[7], wantAmount, label);
      assert.equal(
        await snarkjs.groth16.verify(vk, publicSignals, proof),
        true,
        label,
      );
    }
  });

  it('the same state proves at different turns with different binding hashes', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const params = [5, 50, 100, 0, 0, 0, 0, 0];
    const first = await generateProof(
      'vfyPolicy',
      await vfyData({ params, salt: 7n, self: 100, opp: 150, turn: 1 }),
    );
    const last = await generateProof(
      'vfyPolicy',
      await vfyData({ params, salt: 7n, self: 100, opp: 150, turn: 20 }),
    );
    assert.notEqual(first.publicSignals[0], last.publicSignals[0]);
    assert.equal(last.publicSignals[3], '20');
    // Every other signal is identical: turn enters ONLY the binding hash.
    for (const i of [1, 2, 4, 5, 6, 7, 8]) {
      assert.equal(last.publicSignals[i], first.publicSignals[i], `signal[${i}]`);
    }
    assert.equal(await snarkjs.groth16.verify(vk, last.publicSignals, last.proof), true);
  });

  it('wrong actions are unprovable: HOLD where the policy extracts', async () => {
    const data = await vfyData({
      params: [5, 50, 100, 0, 0, 0, 0, 0],
      salt: 7n,
      self: 100,
      opp: 150,
      action: { type: 'HOLD' },
    });
    await assert.rejects(generateProof('vfyPolicy', data), /Assert Failed/);
  });

  it('wrong amounts are unprovable: EXTRACT amount != p0', async () => {
    const wrongExtract = await vfyData({
      params: [5, 50, 100, 0, 0, 0, 0, 0],
      salt: 7n,
      self: 100,
      opp: 150,
      action: { type: 'EXTRACT', amount: 4 },
    });
    await assert.rejects(generateProof('vfyPolicy', wrongExtract), /Assert Failed/);
  });

  it('the adapter forces amount 0 for HOLD/FORTIFY (circuit requires it)', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const data = await vfyData({
      params: [5, 50, 100, 0, 0, 0, 0, 0],
      salt: 7n,
      self: 10,
      opp: 190,
      action: { type: 'FORTIFY', amount: 3 },
    });
    const { proof, publicSignals } = await generateProof('vfyPolicy', data);
    assert.equal(publicSignals[6], '1');
    assert.equal(publicSignals[7], '0');
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  });
});
