import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from '../src/server.js';
import { SeenSet } from '../src/seenSet.js';
import { SIGNATURE_HEADER, signBody, verifySignature } from '../src/hmac.js';
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

function post(path, bodyObj, { sign = true, secret = SECRET, rawBody = null } = {}) {
  return new Promise((resolve, reject) => {
    const body = rawBody ?? Buffer.from(JSON.stringify(bodyObj));
    const req = request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json' } },
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

  it('omits amount when the policy fortifies (comfortable lead)', async () => {
    const envelope = stealEnvelope({ selfBalance: '130', opponentBalance: '100' });
    const res = await post('/agent', envelope);
    assert.equal(res.json.action.type, 'FORTIFY');
    assert.equal('amount' in res.json.action, false);
  });

  it('produces distinct idempotency keys per turn', async () => {
    const a = await post('/agent', stealEnvelope({}, { turn: 4 }));
    const b = await post('/agent', stealEnvelope({}, { turn: 5 }));
    assert.notEqual(a.json.idempotencyKey, b.json.idempotencyKey);
  });
});
