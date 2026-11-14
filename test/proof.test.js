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

describe('proveAndSubmit: never waits for Finalized (practice_b6662f40 regression)', () => {
  it('returns right after submit even when finalization never arrives', async () => {
    const events = [];
    const client = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      pollIntervalMs: 5,
      fetchImpl: async (url) => {
        if (url.includes('/submit-proof/')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({ jobId: 'job-1', status: 'Queued' }),
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: 'Queued', jobId: 'job-1' }),
        };
      },
    });
    // Exact input of practice task practice_b6662f40 (AMOUNT_OVERFLOW).
    const input = {
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
      condition_recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
      amount: '1800',
      max_transfer: '1000',
      proof_tx: '0xb6662f404bd7442a804fd211ca96dfd4',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    };
    const started = Date.now();
    const result = await proveAndSubmit({
      circuit: 'gatekeeper',
      data: {
        input,
        decision: 'REJECT',
        taskId: 'practice_b6662f40-4bd7-442a-804f-d211ca96dfd4',
      },
      kurier: client,
      deadlineMs: 30_000,
      finalizeBudgetMs: 200,
      onEvent: (event, fields) => events.push([event, fields]),
    });
    const elapsed = Date.now() - started;
    // The old code awaited submit + finalization and burned the whole 30s
    // budget; the fixed code returns after proving (a few seconds at most)
    // with the submission still pending in the background.
    assert.ok(elapsed < 10_000, `returned in ${elapsed}ms, must not wait out the budget`);
    assert.ok(result.proof, 'proof rides in the result');
    assert.equal(result.proofReference, null);
    assert.equal(result.kurierStatus, null);
    assert.equal(result.kurierFinalized, false);
    // The background chain still reports (without blocking): give it a
    // moment past its 200ms poll budget, then confirm the reports arrived.
    await new Promise((resolve) => setTimeout(resolve, 400));
    const submitted = events.find(([e]) => e === 'kurier_submitted');
    assert.ok(submitted, 'background submit reported');
    assert.equal(submitted[1].jobId, 'job-1');
    const fin = events.find(([e]) => e === 'kurier_finalized');
    assert.ok(fin, 'background poll reported finalization outcome');
    assert.equal(fin[1].finalized, false);
  });

  it('returns even when the Kurier submit itself never answers (practice_502f0b25)', async () => {
    const events = [];
    const client = new KurierClient({
      apiUrl: 'https://api.kurier.xyz/api/v1',
      apiKey: 'test-key',
      pollIntervalMs: 5,
      fetchImpl: async (_url, opts) => {
        // Hang until the client's abort signal fires, like a stalled API.
        await new Promise((_resolve, reject) => {
          opts.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
        });
        throw new Error('unreachable');
      },
    });
    const input = {
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
      condition_recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
      amount: '1800',
      max_transfer: '1000',
      proof_tx: '0xb6662f404bd7442a804fd211ca96dfd4',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    };
    const started = Date.now();
    const result = await proveAndSubmit({
      circuit: 'gatekeeper',
      data: {
        input,
        decision: 'REJECT',
        taskId: 'practice_502f0b25-slow-submit',
      },
      kurier: client,
      deadlineMs: 30_000,
      submitTimeoutMs: 150,
      finalizeBudgetMs: 200,
      onEvent: (event, fields) => events.push([event, fields]),
    });
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 10_000, `returned in ${elapsed}ms despite a stalled submit`);
    assert.ok(result.proof, 'proof rides in the result');
    await new Promise((resolve) => setTimeout(resolve, 400));
    assert.ok(events.some(([e]) => e === 'kurier_failed'), 'stalled submit reported as failed');
  });
});
