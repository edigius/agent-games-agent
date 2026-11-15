import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from '../src/server.js';
import { SeenSet } from '../src/seenSet.js';
import { SIGNATURE_HEADER, signBody, verifySignature } from '../src/hmac.js';
import { computeCommitment } from '../src/commitment.js';
import { safePolicy } from '../src/steal.js';
import { STRATEGY_PARAMS } from '../src/strategyParams.js';
import { gatekeeperEnvelope, stealEnvelope, VK_B, validGatekeeperInput } from './helpers.js';

const SECRET = 'test-only-server-secret';
let server;
let port;
let tmpDir;

const MOCK_EVIDENCE = {
  proof: { pi_a: ['1', '2'], pi_b: [['3', '4']], pi_c: ['5'], protocol: 'groth16', curve: 'bn128' },
  publicSignals: ['11', '22'],
  proofReference: 'job-mock-1',
  kurierStatus: 'Finalized',
  kurierFinalized: true,
};

// Records every proof-provider invocation so tests can assert the replay
// short-circuit never attempts proof generation.
const proofCalls = [];

function post(
  path,
  bodyObj,
  { sign = true, secret = SECRET, rawBody = null, targetPort = port } = {},
) {
  return new Promise((resolve, reject) => {
    const body = rawBody ?? Buffer.from(JSON.stringify(bodyObj));
    const req = request(
      { host: '127.0.0.1', port: targetPort, path, method: 'POST', headers: { 'content-type': 'application/json' } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            raw: Buffer.concat(chunks),
            json: JSON.parse(Buffer.concat(chunks).toString('utf8')),
          }),
        );
      },
    );
    req.on('error', reject);
    if (sign) req.setHeader(SIGNATURE_HEADER, signBody(secret, body));
    req.end(body);
  });
}

function get(path) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }),
      );
    });
    req.on('error', reject);
    req.end();
  });
}

before(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'pegasus-server-'));
  const seenSet = new SeenSet(join(tmpDir, 'seen-set.json'));
  await seenSet.load();
  server = createServer({
    config: { hmacSecret: SECRET, hasKurierKey: false },
    seenSet,
    kurier: null,
    proofProvider: async (opts) => {
      proofCalls.push(opts.circuit);
      return MOCK_EVIDENCE;
    },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
});

after(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  await rm(tmpDir, { recursive: true, force: true });
});

describe('server: auth + routing', () => {
  it('answers a signed preflight with the exact contract + valid signature', async () => {
    const envelope = {
      type: 'agent-games.preflight.v1',
      agent_id: 'agt_test',
      issued_at: new Date().toISOString(),
      nonce: 'abc123',
    };
    const res = await post('/agent', envelope);
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, { ok: true, protocolVersion: 'v1' });
    assert.equal(verifySignature(SECRET, res.raw, res.headers[SIGNATURE_HEADER]), true);
  });

  it('rejects unsigned requests with 401', async () => {
    const res = await post('/agent', { type: 'agent-games.preflight.v1' }, { sign: false });
    assert.equal(res.status, 401);
    assert.equal(res.json.error, 'invalid_signature');
  });

  it('rejects tampered bodies with 401', async () => {
    const body = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1' }));
    const sig = signBody(SECRET, body);
    const tampered = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1', x: 1 }));
    const res = await new Promise((resolve, reject) => {
      const req = request(
        { host: '127.0.0.1', port, path: '/agent', method: 'POST' },
        (r) => {
          const chunks = [];
          r.on('data', (c) => chunks.push(c));
          r.on('end', () =>
            resolve({ status: r.statusCode, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }),
          );
        },
      );
      req.on('error', reject);
      req.setHeader(SIGNATURE_HEADER, sig);
      req.end(tampered);
    });
    assert.equal(res.status, 401);
  });

  it('rejects unknown envelopes with 400 and unknown paths with 404', async () => {
    const res = await post('/agent', { hello: 'world' });
    assert.equal(res.status, 400);
    const res2 = await post('/nope', { type: 'agent-games.preflight.v1' });
    assert.equal(res2.status, 404);
  });

  it('serves a health endpoint reporting real readiness (no secrets)', async () => {
    const res = await get('/health');
    assert.equal(res.status, 200);
    assert.equal(res.json.name, 'PEGASUS');
    assert.equal(res.json.hmacConfigured, true);
    assert.equal(res.json.kurierKeyConfigured, false);
    assert.equal(typeof res.json.circuitsPresent, 'boolean');
    assert.ok(!JSON.stringify(res.json).includes(SECRET));
  });
});

describe('server: gatekeeper end-to-end (mock proof provider)', () => {
  it('approves a valid task with proof evidence echoed + signed', async () => {
    const res = await post('/agent', gatekeeperEnvelope(validGatekeeperInput()));
    assert.equal(res.status, 200);
    assert.equal(res.json.decision, 'APPROVE');
    assert.equal(res.json.reason_code, 'VALID_PROOF');
    assert.equal(res.json.proof_tx, validGatekeeperInput().proof_tx);
    assert.deepEqual(res.json.proof, MOCK_EVIDENCE.proof);
    assert.deepEqual(res.json.public_signals, MOCK_EVIDENCE.publicSignals);
    assert.equal(verifySignature(SECRET, res.raw, res.headers[SIGNATURE_HEADER]), true);
  });

  it('rejects a VK-substitution trap', async () => {
    const input = validGatekeeperInput({ proof_vk: VK_B, proof_tx: `0x${'bb'.repeat(32)}` });
    const res = await post('/agent', gatekeeperEnvelope(input, { task_id: 'gk_test_002' }));
    assert.equal(res.status, 200);
    assert.equal(res.json.decision, 'REJECT');
    assert.equal(res.json.reason_code, 'VK_SUBSTITUTION');
  });

  it('flags a replayed proof_tx as PROOF_REPLAY with NO proof fields and NO proof attempt', async () => {
    const tx = `0x${'cc'.repeat(32)}`;
    const first = await post(
      '/agent',
      gatekeeperEnvelope(validGatekeeperInput({ proof_tx: tx }), { task_id: 'gk_test_003' }),
    );
    assert.equal(first.json.decision, 'APPROVE');
    assert.ok('proof' in first.json);
    const callsBefore = proofCalls.length;
    const second = await post(
      '/agent',
      gatekeeperEnvelope(validGatekeeperInput({ proof_tx: tx }), { task_id: 'gk_test_004' }),
    );
    assert.equal(second.json.decision, 'REJECT');
    assert.equal(second.json.reason_code, 'PROOF_REPLAY');
    assert.equal(second.json.proof_tx, tx);
    assert.equal('proof' in second.json, false);
    assert.equal('public_signals' in second.json, false);
    // The replay short-circuit must not attempt proof generation at all.
    assert.equal(proofCalls.length, callsBefore);
  });
});

describe('server: steal end-to-end (mock proof provider)', () => {
  it('returns a schema-valid turn echoing matchId/turn with a policy proof', async () => {
    const envelope = stealEnvelope({});
    const res = await post('/agent', envelope);
    assert.equal(res.status, 200);
    assert.equal(res.json.matchId, envelope.matchId);
    assert.equal(res.json.turn, envelope.turn);
    assert.equal(res.json.policyProof.circuitVersion, 'v1');
    assert.equal(res.json.policyProof.proofReference, 'job-mock-1');
    assert.match(res.json.policyProof.publicInputsHash, /^0x[0-9a-f]{64}$/);
    assert.ok(typeof res.json.idempotencyKey === 'string' && res.json.idempotencyKey.length > 0);
    assert.ok(typeof res.json.agentTimestamp === 'string');
    assert.equal(verifySignature(SECRET, res.raw, res.headers[SIGNATURE_HEADER]), true);
  });

  it('turn action matches the policy module and amount shaping follows the action', async () => {
    const states = [
      { selfBalance: '95', opponentBalance: '105' },
      { selfBalance: '10', opponentBalance: '190' },
      { selfBalance: '100', opponentBalance: '0' },
    ];
    for (const [i, s] of states.entries()) {
      const envelope = stealEnvelope(s, { turn: 10 + i });
      const res = await post('/agent', envelope);
      assert.equal(res.status, 200);
      const expected = safePolicy({ ...s, turn: 10 + i });
      assert.equal(res.json.action.type, expected.type);
      if (expected.type === 'EXTRACT') {
        assert.equal(res.json.action.amount, expected.amount);
      } else {
        // HOLD/FORTIFY omit amount entirely.
        assert.equal('amount' in res.json.action, false);
      }
    }
  });

  it('produces distinct idempotency keys per turn', async () => {
    const a = await post('/agent', stealEnvelope({}, { turn: 4 }));
    const b = await post('/agent', stealEnvelope({}, { turn: 5 }));
    assert.notEqual(a.json.idempotencyKey, b.json.idempotencyKey);
  });
});

describe('server: health counters (NEPTUN observability)', () => {
  const servers = [];

  function getFrom(targetPort, path) {
    return new Promise((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port: targetPort, path, method: 'GET' }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }),
        );
      });
      req.on('error', reject);
      req.end();
    });
  }

  async function startServer(proofProvider, extra = {}) {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-counters-'));
    const seenSet = new SeenSet(join(dir, 'seen-set.json'));
    await seenSet.load();
    const srv = createServer({
      config: { hmacSecret: SECRET, hasKurierKey: false },
      seenSet,
      kurier: null,
      proofProvider,
      ...extra,
    });
    await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
    const entry = { server: srv, port: srv.address().port, dir };
    servers.push(entry);
    return entry;
  }

  after(async () => {
    for (const { server: srv, dir } of servers) {
      srv.closeAllConnections();
      await new Promise((resolve) => srv.close(resolve));
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reports zero counters before traffic and exact counts after', async () => {
    const { port: p } = await startServer(async () => MOCK_EVIDENCE, { warmupOk: true });
    const before = await getFrom(p, '/health');
    assert.equal(before.json.warmupOk, true);
    assert.equal(before.json.seenSetBackupRecovered, false);
    assert.equal(before.json.gatekeeperTasks, 0);
    assert.equal(before.json.gatekeeperReplays, 0);
    assert.equal(before.json.gatekeeperProofs, 0);
    assert.equal(before.json.gatekeeperProofDegraded, 0);
    assert.equal(before.json.gatekeeperBudgetExceeded, 0);
    assert.equal(before.json.stealTurns, 0);
    assert.equal(before.json.stealProofs, 0);
    assert.equal(before.json.lastGatekeeperDurationMs, null);
    assert.equal(before.json.lastStealDurationMs, null);

    const tx = `0x${'dd'.repeat(32)}`;
    const first = await post(
      '/agent',
      gatekeeperEnvelope(validGatekeeperInput({ proof_tx: tx }), { task_id: 'gk_cnt_001' }),
      { targetPort: p },
    );
    assert.equal(first.json.decision, 'APPROVE');
    const replay = await post(
      '/agent',
      gatekeeperEnvelope(validGatekeeperInput({ proof_tx: tx }), { task_id: 'gk_cnt_002' }),
      { targetPort: p },
    );
    assert.equal(replay.json.reason_code, 'PROOF_REPLAY');
    const turn = await post('/agent', stealEnvelope({}, { turn: 7 }), { targetPort: p });
    assert.equal(turn.status, 200);

    const after = await getFrom(p, '/health');
    assert.equal(after.json.gatekeeperTasks, 2);
    assert.equal(after.json.gatekeeperReplays, 1);
    assert.equal(after.json.gatekeeperProofs, 1);
    assert.equal(after.json.gatekeeperProofDegraded, 0);
    assert.equal(after.json.gatekeeperBudgetExceeded, 0);
    assert.equal(after.json.stealTurns, 1);
    assert.equal(after.json.stealProofs, 1);
    assert.ok(typeof after.json.lastGatekeeperDurationMs === 'number');
    assert.ok(after.json.lastGatekeeperDurationMs >= 0);
    assert.ok(typeof after.json.lastStealDurationMs === 'number');
    // Existing health fields keep their meaning.
    assert.equal(after.json.name, 'PEGASUS');
    assert.equal(after.json.buildId, 'neptun-1');
    assert.equal(after.json.seenSetSize, 1);
  });

  it('counts proof-less non-replay responses as degraded, warmupOk null by default', async () => {
    const { port: p } = await startServer(async () => {
      throw new Error('simulated proof failure');
    });
    const res = await post(
      '/agent',
      gatekeeperEnvelope(validGatekeeperInput({ proof_tx: `0x${'ee'.repeat(32)}` }), {
        task_id: 'gk_cnt_003',
      }),
      { targetPort: p },
    );
    assert.equal(res.status, 200);
    assert.equal('proof' in res.json, false);
    const health = await getFrom(p, '/health');
    assert.equal(health.json.warmupOk, null);
    assert.equal(health.json.gatekeeperTasks, 1);
    assert.equal(health.json.gatekeeperProofs, 0);
    assert.equal(health.json.gatekeeperProofDegraded, 1);
  });

  it('counts watchdog firings as budget-exceeded', async () => {
    const { port: p } = await startServer(
      async () =>
        new Promise((resolve) => setTimeout(() => resolve(MOCK_EVIDENCE), 1100)),
    );
    const res = await post(
      '/agent',
      gatekeeperEnvelope(validGatekeeperInput({ proof_tx: `0x${'ff'.repeat(32)}` }), {
        task_id: 'gk_cnt_004',
        // Past deadline: budget floors at 1000ms, provider answers at 1100ms.
        deadline_at: new Date(Date.now() - 1000).toISOString(),
      }),
      { targetPort: p },
    );
    assert.equal(res.status, 200);
    assert.equal(res.json.decision, 'REJECT');
    assert.equal(res.json.reason_code, 'MISSING_VERIFICATION');
    const health = await getFrom(p, '/health');
    assert.equal(health.json.gatekeeperTasks, 1);
    assert.equal(health.json.gatekeeperBudgetExceeded, 1);
    // Let the background handler settle before teardown.
    await new Promise((resolve) => setTimeout(resolve, 300));
  });
});

describe('server: steal end-to-end (REAL proof provider, real artifacts)', () => {
  const TEST_SALT = 777n;
  let realServer;
  let realPort;
  let realTmpDir;

  before(async () => {
    realTmpDir = await mkdtemp(join(tmpdir(), 'pegasus-server-real-'));
    const seenSet = new SeenSet(join(realTmpDir, 'seen-set.json'));
    await seenSet.load();
    realServer = createServer({
      config: { hmacSecret: SECRET, strategySalt: TEST_SALT, hasKurierKey: false },
      seenSet,
      kurier: null,
      // No mock proofProvider: defaultProofProvider generates a real proof.
    });
    await new Promise((resolve) => realServer.listen(0, '127.0.0.1', resolve));
    realPort = realServer.address().port;
  });

  after(async () => {
    realServer.closeAllConnections();
    await new Promise((resolve) => realServer.close(resolve));
    await rm(realTmpDir, { recursive: true, force: true });
  });

  it('returns a turn whose proof verifies against the exported VK', async () => {
    const hash = await computeCommitment(STRATEGY_PARAMS, TEST_SALT);
    const envelope = stealEnvelope(
      { selfBalance: '100', opponentBalance: '100' },
      { turn: 1, strategyCommitment: { hash } },
    );
    const res = await post('/agent', envelope, { targetPort: realPort });
    assert.equal(res.status, 200);
    assert.equal(res.json.matchId, envelope.matchId);
    assert.ok(res.json.proof, 'proof evidence present');
    assert.equal(res.json.public_signals.length, 9);
    assert.equal(verifySignature(SECRET, res.raw, res.headers[SIGNATURE_HEADER]), true);

    const snarkjs = await import('snarkjs');
    const vk = JSON.parse(
      await readFile(
        join(dirname(fileURLToPath(import.meta.url)), '..', 'circuits/vfyPolicy.vk.json'),
        'utf8',
      ),
    );
    assert.equal(
      await snarkjs.groth16.verify(vk, res.json.public_signals, res.json.proof),
      true,
    );
  });

  it('degrades to a proof-less but valid turn when the commitment mismatches', async () => {
    const envelope = stealEnvelope({}, { strategyCommitment: { hash: '999' } });
    const res = await post('/agent', envelope, { targetPort: realPort });
    assert.equal(res.status, 200);
    assert.equal('proof' in res.json, false);
    assert.equal('public_signals' in res.json, false);
    // The policy still answers; only the evidence is withheld.
    assert.equal(res.json.action.type, safePolicy(envelope.state).type);
    assert.equal(verifySignature(SECRET, res.raw, res.headers[SIGNATURE_HEADER]), true);
  });
});
