import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  CircuitMappingError,
  buildCircuitInput,
  defaultProofProvider,
  proveAndSubmit,
} from '../src/proof.js';
import { KurierClient, KurierError } from '../src/kurier.js';

describe('proof adapter (vfy-policy mapping still unknown)', () => {
  it('buildCircuitInput throws a clear NOT_IMPLEMENTED error for vfyPolicy', () => {
    assert.throws(() => buildCircuitInput('vfyPolicy', {}), CircuitMappingError);
    assert.throws(() => buildCircuitInput('vfyPolicy', {}), /NOT IMPLEMENTED/);
    assert.throws(() => buildCircuitInput('vfyPolicy', {}), /vfyPolicy/);
  });

  it('proveAndSubmit surfaces the mapping error for vfyPolicy (does not guess)', async () => {
    await assert.rejects(
      proveAndSubmit({ circuit: 'vfyPolicy', data: {}, kurier: null, deadlineMs: 1000 }),
      CircuitMappingError,
    );
  });

  it('defaultProofProvider degrades to null evidence for vfyPolicy instead of throwing', async () => {
    const evidence = await defaultProofProvider({
      circuit: 'vfyPolicy',
      data: {},
      kurier: null,
      deadlineMs: 1000,
    });
    assert.equal(evidence.proof, null);
    assert.equal(evidence.publicSignals, null);
    assert.equal(evidence.degraded, true);
    assert.equal(evidence.kurierStatus, 'mapping_unimplemented');
  });

  it('rejects unknown circuit names', () => {
    assert.throws(() => buildCircuitInput('nope', {}), /unknown circuit/);
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
