import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCircuitInput,
  defaultProofProvider,
  proveAndSubmit,
} from '../src/proof.js';
import { computeCommitment } from '../src/commitment.js';
import { KurierClient, KurierError } from '../src/kurier.js';
import { stealEnvelope } from './helpers.js';

describe('proof adapter: vfyPolicy input validation (no proving)', () => {
  const PARAMS = [5, 50, 100, 0, 0, 0, 0, 0];
  const SALT = 12345n;

  async function validData(overrides = {}) {
    const hash = await computeCommitment(PARAMS, SALT);
    return {
      envelope: stealEnvelope(
        {},
        { strategyCommitment: { hash } },
      ),
      action: { type: 'EXTRACT', amount: 5 },
      params: PARAMS,
      salt: SALT,
      ...overrides,
    };
  }

  it('builds the 17-slot input with the confirmed encodings', async () => {
    const input = await buildCircuitInput('vfyPolicy', await validData());
    assert.deepEqual(Object.keys(input), [
      'commitment',
      'matchId',
      'turnNumber',
      'selfBalance',
      'opponentBalance',
      'action',
      'amount',
      'circuitVersion',
      'salt',
      'strategyParams',
    ]);
    assert.equal(input.commitment, await computeCommitment(PARAMS, SALT));
    // matchId: UUID hyphens stripped, as a decimal integer string.
    assert.equal(input.matchId, BigInt(`0x${'9f4e1b2a000040008000000000000001'}`).toString());
    assert.equal(input.turnNumber, '3');
    assert.equal(input.selfBalance, '95');
    assert.equal(input.opponentBalance, '105');
    assert.equal(input.action, '2');
    assert.equal(input.amount, '5');
    assert.equal(input.circuitVersion, '1');
    assert.equal(input.salt, '12345');
    assert.deepEqual(input.strategyParams, ['5', '50', '100', '0', '0', '0', '0', '0']);
  });

  it('refuses when the envelope commitment does not match the local one', async () => {
    const data = await validData();
    data.envelope.strategyCommitment = { hash: '999' };
    await assert.rejects(buildCircuitInput('vfyPolicy', data), /does not match/);
  });

  it('refuses without a BigInt salt, and with invalid params', async () => {
    const noSalt = await validData({ salt: undefined });
    await assert.rejects(buildCircuitInput('vfyPolicy', noSalt), /salt/);
    const stringSalt = await validData({ salt: '12345' });
    await assert.rejects(buildCircuitInput('vfyPolicy', stringSalt), /salt/);
    const badParams = await validData({ params: [0, 0, 0, 0, 0, 0, 0, 0] });
    await assert.rejects(buildCircuitInput('vfyPolicy', badParams), /p0/);
  });

  it('refuses malformed matchId, turn, balances, and actions', async () => {
    const base = await validData();
    await assert.rejects(
      buildCircuitInput('vfyPolicy', {
        ...base,
        envelope: { ...base.envelope, matchId: 'not-a-uuid!' },
      }),
      /matchId/,
    );
    await assert.rejects(
      buildCircuitInput('vfyPolicy', { ...base, action: { type: 'DANCE' } }),
      /HOLD\|FORTIFY\|EXTRACT/,
    );
    await assert.rejects(
      buildCircuitInput('vfyPolicy', {
        ...base,
        action: { type: 'EXTRACT' }, // missing amount
      }),
      /amount/,
    );
    await assert.rejects(
      buildCircuitInput('vfyPolicy', {
        ...base,
        envelope: stealEnvelope({ selfBalance: '-1' }, {
          strategyCommitment: base.envelope.strategyCommitment,
        }),
      }),
      /non-negative/,
    );
  });

  it('proveAndSubmit surfaces input errors (never degrades silently)', async () => {
    await assert.rejects(
      proveAndSubmit({ circuit: 'vfyPolicy', data: {}, kurier: null, deadlineMs: 1000 }),
      /salt/,
    );
    await assert.rejects(
      defaultProofProvider({ circuit: 'vfyPolicy', data: {}, kurier: null, deadlineMs: 1000 }),
      /salt/,
    );
  });

  it('rejects unknown circuit names', async () => {
    await assert.rejects(buildCircuitInput('nope', {}), /unknown circuit/);
  });
});

describe('kurier client (mocked transport, no real network)', () => {
  const VK = `0x${'ab'.repeat(32)}`;

  it('submits the exact documented payload shape', async () => {
    const calls = [];
    const fakeFetch = async (url, opts) => {
      calls.push({ url, opts });
      return {
        ok: true,
        status: 200,
        json: async () => ({ jobId: 'job-1', optimisticVerify: 'success' }),
      };
    };
    const client = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      fetchImpl: fakeFetch,
    });
    const job = await client.submitProof({
      proof: { pi_a: ['1'] },
      publicSignals: ['2'],
      vkHash: VK,
    });
    assert.equal(job.jobId, 'job-1');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://api.kurier.xyz/api/v1/submit-proof/test-key');
    assert.equal(calls[0].opts.method, 'POST');
    const body = JSON.parse(calls[0].opts.body);
    assert.equal(body.proofType, 'groth16');
    assert.equal(body.vkRegistered, true);
    assert.deepEqual(body.proofOptions, { library: 'snarkjs', curve: 'bn128' });
    assert.deepEqual(body.proofData, {
      proof: { pi_a: ['1'] },
      publicSignals: ['2'],
      vk: VK,
    });
  });

  it('makes exactly ONE submit attempt when the POST fails (no blind resubmit)', async () => {
    let attempts = 0;
    const client = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      fetchImpl: async () => {
        attempts += 1;
        throw new Error('connection reset');
      },
    });
    await assert.rejects(
      client.submitProof({ proof: {}, publicSignals: [], vkHash: VK }),
      KurierError,
    );
    assert.equal(attempts, 1);
  });

  it('polls job status until Finalized', async () => {
    const statuses = ['Submitted', 'IncludedInBlock', 'Finalized'];
    let i = 0;
    const client = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      pollIntervalMs: 1,
      fetchImpl: async (url) => {
        assert.match(url, /\/job-status\/test-key\/job-9$/);
        const status = statuses[Math.min(i, statuses.length - 1)];
        i += 1;
        return { ok: true, status: 200, json: async () => ({ status, jobId: 'job-9' }) };
      },
    });
    const result = await client.waitForFinalized('job-9', { deadlineMs: 5000 });
    assert.equal(result.finalized, true);
    assert.equal(result.status, 'Finalized');
    assert.equal(result.timedOut, false);
  });

  it('stops polling on Failed and respects the deadline budget', async () => {
    const failing = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      pollIntervalMs: 1,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ status: 'Failed' }),
      }),
    });
    const failed = await failing.waitForFinalized('job-x', { deadlineMs: 5000 });
    assert.equal(failed.finalized, false);
    assert.equal(failed.status, 'Failed');

    const slow = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      pollIntervalMs: 50,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ status: 'Submitted' }),
      }),
    });
    const started = Date.now();
    const timedOut = await slow.waitForFinalized('job-y', { deadlineMs: 120 });
    assert.equal(timedOut.timedOut, true);
    assert.ok(Date.now() - started < 2000);
  });

  it('retries transient GET failures inside the budget', async () => {
    let calls = 0;
    const client = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      pollIntervalMs: 1,
      fetchImpl: async () => {
        calls += 1;
        if (calls < 3) throw new Error('flaky network');
        return { ok: true, status: 200, json: async () => ({ status: 'Finalized' }) };
      },
    });
    const result = await client.waitForFinalized('job-z', { deadlineMs: 5000 });
    assert.equal(result.finalized, true);
    assert.equal(calls, 3);
  });
});
