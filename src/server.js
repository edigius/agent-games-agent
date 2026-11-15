/**
 * PEGASUS — HTTP transport. Single POST /agent endpoint, one router.
 *
 * The platform POSTs every envelope (preflight, Gatekeeper tasks, Steal
 * turns) to the exact URL registered — one path, distinguished by envelope
 * shape. GET /health and GET / exist for the operator's own monitoring
 * only; the platform's documented readiness check is the signed preflight,
 * and no health-check path is published.
 *
 * Invariants:
 *  - HMAC is verified over the RAW body BEFORE any JSON parsing.
 *  - Every response carries x-agent-games-signature over its raw body.
 *  - Handlers never throw to the socket: every failure degrades to a
 *    fail-closed, schema-valid response inside the deadline budget.
 *  - Logs are structured JSON and never contain secrets, strategy params,
 *    salts, or raw request bodies.
 */
import { createServer as createHttpServer } from 'node:http';
import { existsSync } from 'node:fs';
import {
  BUILD_ID,
  CIRCUIT,
  GATEKEEPER_DEADLINE_MS,
  GATEKEEPER_MARGIN_MS,
  MAX_BODY_BYTES,
  STEAL_DEADLINE_MS,
  STEAL_MARGIN_MS,
} from './config.js';
import { SIGNATURE_HEADER, signBody, verifySignature } from './hmac.js';
import { decideGatekeeper } from './gatekeeper.js';
import { REASON_CODE } from './reasonCodes.js';
import {
  buildTurnResponse,
  computePublicInputsHash,
  safePolicy,
} from './steal.js';
import { STRATEGY_PARAMS } from './strategyParams.js';
import { defaultProofProvider } from './proof.js';

const STARTED_AT = Date.now();

function log(event, fields = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

function budgetMs(envelopeDeadline, hardDeadlineMs, marginMs) {
  let budget = hardDeadlineMs - marginMs;
  if (typeof envelopeDeadline === 'string') {
    const parsed = Date.parse(envelopeDeadline);
    if (Number.isFinite(parsed)) {
      budget = Math.min(budget, parsed - Date.now() - marginMs);
    }
  }
  return Math.max(1_000, budget);
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      throw Object.assign(new Error('request body too large'), { code: 'BODY_TOO_LARGE' });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export function createServer({
  config,
  seenSet,
  kurier = null,
  proofProvider = defaultProofProvider,
  // Startup warm-up outcome from src/warmup.js. null = unknown (e.g.
  // tests that construct a server without running warm-up).
  warmupOk = null,
}) {
  // Lightweight observability for GET /health (NEPTUN): plain counters
  // in the server closure, no external stack. Counters reflect handler
  // completions: if the watchdog fires, the handler keeps running in
  // the background and its proof outcome still lands here, while
  // gatekeeperBudgetExceeded records the watchdog firing itself.
  const metrics = {
    gatekeeperTasks: 0,
    gatekeeperReplays: 0,
    gatekeeperProofs: 0,
    gatekeeperProofDegraded: 0,
    gatekeeperBudgetExceeded: 0,
    stealTurns: 0,
    stealProofs: 0,
    lastGatekeeperDurationMs: null,
    lastStealDurationMs: null,
  };
  const send = (res, status, payload) => {
    const body = Buffer.from(JSON.stringify(payload));
    res.writeHead(status, {
      'content-type': 'application/json',
      [SIGNATURE_HEADER]: signBody(config.hmacSecret, body),
    });
    res.end(body);
  };

  async function handlePreflight(envelope) {
    log('preflight', { agentId: envelope.agent_id ?? null });
    return { status: 200, payload: { ok: true, protocolVersion: 'v1' } };
  }

  async function handleGatekeeper(envelope, deadlineMs) {
    const started = Date.now();
    metrics.gatekeeperTasks += 1;
    const input = envelope.input ?? {};
    const taskId = envelope.task_id ?? null;
    const proofTx = typeof input.proof_tx === 'string' ? input.proof_tx : null;
    const inputSummary = {
      minimum: input.minimum,
      public_balance: input.public_balance,
      expiry_block: input.expiry_block,
      current_block: input.current_block,
      amount: input.amount,
      max_transfer: input.max_transfer,
    };

    // REPLAY CHECK FIRST: a replayed task is answered with NO proof and
    // NO proof generation attempt. Valid facts + REJECT is unprovable in
    // the circuit, and the docs state replay tasks carry no proof.
    if (proofTx && seenSet.has(proofTx)) {
      metrics.gatekeeperReplays += 1;
      metrics.lastGatekeeperDurationMs = Date.now() - started;
      log('gatekeeper_decision', {
        taskId,
        decision: 'REJECT',
        reasonCode: REASON_CODE.PROOF_REPLAY,
        trap: 'PROOF_REUSED',
        checks: 'proof_fresh:fail',
        proofTx,
        input: inputSummary,
        publicSignals: null,
        kurierStatus: null,
        kurierFinalized: false,
        proofDegraded: false,
        replay: true,
        durationMs: Date.now() - started,
      });
      return {
        status: 200,
        payload: {
          decision: 'REJECT',
          reason_code: REASON_CODE.PROOF_REPLAY,
          proof_tx: proofTx,
        },
      };
    }

    let decision;
    try {
      decision = decideGatekeeper(input, { isReplay: false });
    } catch (err) {
      // Malformed input fields: fail closed, never crash, never approve.
      log('gatekeeper_input_error', { taskId, error: err.message });
      decision = {
        decision: 'REJECT',
        reasonCode: REASON_CODE.MISSING_VERIFICATION,
        trap: 'MALFORMED_INPUT',
        checks: [],
      };
    }

    // Persist the proof reference BEFORE responding so a crash cannot
    // lose the replay record. First-seen record is kept for audit.
    if (proofTx && !seenSet.has(proofTx)) {
      try {
        await seenSet.add(proofTx, {
          taskId,
          decidedAt: new Date().toISOString(),
          decision: decision.decision,
        });
      } catch (err) {
        log('seen_set_write_failed', { taskId, error: err.message });
      }
    }

    const remaining = Math.max(0, deadlineMs - (Date.now() - started));
    let evidence = null;
    try {
      evidence = await proofProvider({
        circuit: 'gatekeeper',
        data: {
          input,
          decision: decision.decision,
          reasonCode: decision.reasonCode,
          taskId: taskId ?? '',
        },
        kurier,
        deadlineMs: remaining,
        onEvent: (event, fields) =>
          log(`gatekeeper_proof_${event}`, { taskId, ...fields }),
      });
    } catch (err) {
      log('gatekeeper_proof_error', { taskId, error: err.message });
    }

    const payload = {
      decision: decision.decision,
      reason_code: decision.reasonCode,
      proof_tx: proofTx,
    };
    if (evidence?.proof) {
      payload.proof = evidence.proof;
      payload.public_signals = evidence.publicSignals;
      metrics.gatekeeperProofs += 1;
    } else {
      // Non-replay response without proof evidence (proof generation
      // failed and degraded). Replay responses never reach this path.
      metrics.gatekeeperProofDegraded += 1;
    }
    metrics.lastGatekeeperDurationMs = Date.now() - started;
    log('gatekeeper_decision', {
      taskId,
      decision: decision.decision,
      reasonCode: decision.reasonCode,
      trap: decision.trap,
      checks: decision.checks.map((c) => `${c.name}:${c.passed ? 'pass' : 'fail'}`).join(','),
      proofTx,
      input: inputSummary,
      // Full public signals, every task: needed to correlate with
      // practice-mode teaching feedback (trap type, expected decision).
      publicSignals: evidence?.publicSignals ?? null,
      kurierStatus: evidence?.kurierStatus ?? null,
      kurierFinalized: evidence?.kurierFinalized ?? false,
      proofDegraded: !evidence?.proof,
      durationMs: Date.now() - started,
    });
    return { status: 200, payload };
  }

  async function handleSteal(envelope, deadlineMs) {
    const started = Date.now();
    metrics.stealTurns += 1;
    const { matchId, turn } = envelope;
    const state = envelope.state ?? {};
    const commitment = envelope.strategyCommitment?.hash ?? null;

    const action = safePolicy({ ...state, turn });
    let publicInputsHash = null;
    try {
      publicInputsHash = computePublicInputsHash({
        commitment,
        matchId,
        turn,
        selfBalance: state.selfBalance,
        opponentBalance: state.opponentBalance,
        action: action.type,
        amount: action.amount,
      });
    } catch (err) {
      log('steal_hash_error', { matchId, turn, error: err.message });
    }

    const remaining = Math.max(0, deadlineMs - (Date.now() - started));
    let evidence = null;
    try {
      evidence = await proofProvider({
        circuit: 'vfyPolicy',
        data: {
          envelope,
          action,
          publicInputsHash,
          params: STRATEGY_PARAMS,
          salt: config.strategySalt,
        },
        kurier,
        deadlineMs: remaining,
        onEvent: (event, fields) =>
          log(`steal_proof_${event}`, { matchId, turn, ...fields }),
      });
    } catch (err) {
      // Proof generation failed (e.g. the circuit rejected a fail-closed
      // HOLD, or the salt/params do not match the registered
      // commitment). Degrade LOUDLY to a proof-less turn response —
      // never emit a proof for an action the circuit rejects, never
      // fake evidence. The response below carries no proof fields.
      log('steal_proof_error', {
        matchId,
        turn,
        action: action.type,
        error: err.message,
        degraded: true,
      });
    }

    const payload = buildTurnResponse({
      matchId,
      turn,
      action,
      publicInputsHash,
      proofReference: evidence?.proofReference ?? null,
      proof: evidence?.proof ?? null,
      publicSignals: evidence?.publicSignals ?? null,
    });
    if (evidence?.proof) metrics.stealProofs += 1;
    metrics.lastStealDurationMs = Date.now() - started;
    log('steal_turn', {
      matchId,
      turn,
      action: action.type,
      amount: action.amount ?? null,
      selfBalance: state.selfBalance,
      opponentBalance: state.opponentBalance,
      publicSignals: evidence?.publicSignals ?? null,
      kurierStatus: evidence?.kurierStatus ?? null,
      kurierFinalized: evidence?.kurierFinalized ?? false,
      proofDegraded: !evidence?.proof,
      durationMs: Date.now() - started,
    });
    return { status: 200, payload };
  }

  function failClosedGatekeeper(envelope) {
    const input = envelope.input ?? {};
    return {
      status: 200,
      payload: {
        decision: 'REJECT',
        reason_code: REASON_CODE.MISSING_VERIFICATION,
        proof_tx: typeof input.proof_tx === 'string' ? input.proof_tx : null,
      },
    };
  }

  function failClosedSteal(envelope) {
    let publicInputsHash = null;
    try {
      publicInputsHash = computePublicInputsHash({
        commitment: envelope.strategyCommitment?.hash ?? null,
        matchId: envelope.matchId,
        turn: envelope.turn,
        selfBalance: envelope.state?.selfBalance,
        opponentBalance: envelope.state?.opponentBalance,
        action: 'HOLD',
        amount: 0,
      });
    } catch {
      publicInputsHash = null;
    }
    return {
      status: 200,
      payload: buildTurnResponse({
        matchId: envelope.matchId,
        turn: envelope.turn,
        action: { type: 'HOLD' },
        publicInputsHash,
      }),
    };
  }

  // Race a handler against its deadline budget. The watchdog timer is
  // unref'd (it must never keep the process alive on its own) and is
  // cleared as soon as the handler settles, so no stray timer fires after
  // the response is sent.
  async function withBudget(handlerPromise, budget, onTimeout) {
    let timer;
    const timeoutPromise = new Promise((resolve) => {
      timer = setTimeout(() => resolve(onTimeout()), budget);
      if (typeof timer.unref === 'function') timer.unref();
    });
    try {
      return await Promise.race([handlerPromise, timeoutPromise]);
    } finally {
      clearTimeout(timer);
    }
  }

  async function route(envelope) {
    if (envelope?.type === 'agent-games.preflight.v1') {
      return handlePreflight(envelope);
    }
    if (envelope?.type === 'agent-games.proof-gatekeeper.v1') {
      if (!envelope.input || typeof envelope.input !== 'object') {
        return { status: 400, payload: { error: 'missing_input' } };
      }
      const budget = budgetMs(
        envelope.deadline_at,
        GATEKEEPER_DEADLINE_MS,
        GATEKEEPER_MARGIN_MS,
      );
      return withBudget(handleGatekeeper(envelope, budget), budget, () => {
        metrics.gatekeeperBudgetExceeded += 1;
        log('gatekeeper_budget_exceeded', { taskId: envelope.task_id ?? null });
        return failClosedGatekeeper(envelope);
      });
    }
    if (envelope?.eventId === 'steal-the-vfy') {
      if (!envelope.matchId || !envelope.state || typeof envelope.state !== 'object') {
        return { status: 400, payload: { error: 'missing_match_state' } };
      }
      const budget = budgetMs(
        envelope.deadlineAt,
        STEAL_DEADLINE_MS,
        STEAL_MARGIN_MS,
      );
      return withBudget(handleSteal(envelope, budget), budget, () => {
        log('steal_budget_exceeded', {
          matchId: envelope.matchId,
          turn: envelope.turn,
        });
        return failClosedSteal(envelope);
      });
    }
    return { status: 400, payload: { error: 'unknown_envelope' } };
  }

  function health() {
    const circuitsPresent =
      existsSync(CIRCUIT.gatekeeper.wasm) &&
      existsSync(CIRCUIT.gatekeeper.zkey) &&
      existsSync(CIRCUIT.vfyPolicy.wasm) &&
      existsSync(CIRCUIT.vfyPolicy.zkey);
    const degraded = seenSet.degraded || !circuitsPresent;
    return {
      status: degraded ? 'degraded' : 'ok',
      name: 'PEGASUS',
      buildId: BUILD_ID,
      uptimeMs: Date.now() - STARTED_AT,
      hmacConfigured: Boolean(config.hmacSecret),
      strategySaltConfigured: typeof config.strategySalt === 'bigint',
      kurierKeyConfigured: config.hasKurierKey,
      circuitsPresent,
      seenSetSize: seenSet.size,
      seenSetDegraded: seenSet.degraded,
      // NEPTUN observability (additive; fields above unchanged).
      warmupOk,
      seenSetBackupRecovered: Boolean(seenSet.backupRecovered),
      gatekeeperTasks: metrics.gatekeeperTasks,
      gatekeeperReplays: metrics.gatekeeperReplays,
      gatekeeperProofs: metrics.gatekeeperProofs,
      gatekeeperProofDegraded: metrics.gatekeeperProofDegraded,
      gatekeeperBudgetExceeded: metrics.gatekeeperBudgetExceeded,
      stealTurns: metrics.stealTurns,
      stealProofs: metrics.stealProofs,
      lastGatekeeperDurationMs: metrics.lastGatekeeperDurationMs,
      lastStealDurationMs: metrics.lastStealDurationMs,
    };
  }

  const server = createHttpServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      if (req.method === 'GET' && url.pathname === '/health') {
        const body = health();
        send(res, 200, body);
        return;
      }
      if (req.method === 'GET' && url.pathname === '/') {
        send(res, 200, {
          name: 'PEGASUS',
          version: '0.1.0',
          tracks: ['proof-gatekeeper', 'steal-the-vfy'],
          endpoint: 'POST /agent',
        });
        return;
      }
      if (req.method !== 'POST' || url.pathname !== '/agent') {
        send(res, 404, { error: 'not_found' });
        return;
      }

      const rawBody = await readBody(req);

      // HMAC over the raw body, BEFORE parsing. Anything else is a
      // protocol violation and is rejected without further work.
      const signature = req.headers[SIGNATURE_HEADER];
      if (!verifySignature(config.hmacSecret, rawBody, signature)) {
        log('auth_rejected', { reason: 'invalid_signature' });
        send(res, 401, { error: 'invalid_signature' });
        return;
      }

      let envelope;
      try {
        envelope = JSON.parse(rawBody.toString('utf8'));
      } catch {
        send(res, 400, { error: 'invalid_json' });
        return;
      }

      // Timestamp sanity: warn, never reject on clock skew alone — the
      // platform enforces deadlines; PEGASUS must not drop a valid task
      // because two clocks disagree by seconds.
      const issuedAt = envelope.issued_at ?? envelope.issuedAt;
      if (issuedAt && Date.parse(issuedAt) > Date.now() + 5 * 60_000) {
        log('clock_warning', { reason: 'issued_at_in_future', issuedAt });
      }

      const { status, payload } = await route(envelope);
      send(res, status, payload);
    } catch (err) {
      if (err?.code === 'BODY_TOO_LARGE') {
        send(res, 413, { error: 'body_too_large' });
        return;
      }
      log('unhandled_error', { error: err?.message ?? String(err) });
      try {
        send(res, 500, { error: 'internal_error' });
      } catch {
        res.destroy();
      }
    }
  });

  return server;
}
