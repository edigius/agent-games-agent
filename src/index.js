/**
 * PEGASUS — entry point. Wires config, state, Kurier, and the HTTP server.
 * Fails fast when the HMAC secret or strategy salt is missing, or when the
 * strategy params are invalid; warns (and degrades proof submission) when
 * the Kurier key is missing.
 */
import { loadConfig } from './config.js';
import { STRATEGY_PARAMS, validateStrategyParams } from './strategyParams.js';
import { SeenSet } from './seenSet.js';
import { KurierClient } from './kurier.js';
import { createServer } from './server.js';
import { runWarmup } from './warmup.js';

function log(event, fields = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

async function main() {
  const config = loadConfig();

  // Refuse to boot on invalid strategy params: an unprovable policy
  // would degrade every Steal turn. Throws -> fatal exit below.
  validateStrategyParams(STRATEGY_PARAMS);

  const seenSet = new SeenSet(config.seenSetPath);
  await seenSet.load();

  let kurier = null;
  if (config.hasKurierKey) {
    kurier = new KurierClient({
      apiUrl: config.kurierApiUrl,
      apiKey: config.kurierApiKey,
    });
  } else {
    log('kurier_disabled', {
      reason: 'KURIER_API_KEY not set; proofs will not be submitted to zkVerify',
    });
  }

  // Full startup warm-up BEFORE listening (see src/warmup.js): snarkjs
  // import, artifact + VK checks, and one dummy REJECT proof that must
  // verify. A failure logs loudly but never blocks boot; Fly's
  // health-check grace period covers the warm-up time.
  const warmup = await runWarmup({ log });
  log('warmup', {
    ok: warmup.ok,
    durationMs: warmup.durationMs,
    ...(warmup.error ? { error: warmup.error } : {}),
  });

  const server = createServer({ config, seenSet, kurier, warmupOk: warmup.ok });
  await new Promise((resolve) => server.listen(config.port, resolve));

  log('started', {
    name: 'PEGASUS',
    port: config.port,
    kurierKeyConfigured: config.hasKurierKey,
    seenSetSize: seenSet.size,
    seenSetDegraded: seenSet.degraded,
    warmupOk: warmup.ok,
  });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log('shutdown', { signal });
    server.close();
    try {
      await seenSet.flush();
    } catch (err) {
      log('shutdown_flush_failed', { error: err.message });
    }
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  console.error(JSON.stringify({ level: 'fatal', error: err.message }));
  process.exit(1);
});
