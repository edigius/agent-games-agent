/**
 * PEGASUS — entry point. Wires config, state, Kurier, and the HTTP server.
 * Fails fast when the HMAC secret is missing; warns (and degrades proof
 * submission) when the Kurier key is missing.
 */
import { loadConfig } from './config.js';
import { SeenSet } from './seenSet.js';
import { KurierClient } from './kurier.js';
import { createServer } from './server.js';

function log(event, fields = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

async function main() {
  const config = loadConfig();

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

  const server = createServer({ config, seenSet, kurier });
  await new Promise((resolve) => server.listen(config.port, resolve));

  // Warm the snarkjs module cache now, so the FIRST task never pays the
  // ~4s cold-import cost inside its response budget (practice mode uses a
  // tighter deadline than competition). Fire-and-forget: a failure here
  // only means the first proof import happens lazily, as before.
  import('snarkjs').catch((err) => {
    log('snarkjs_warmup_failed', { error: err.message });
  });
  log('started', {
    name: 'PEGASUS',
    port: config.port,
    kurierKeyConfigured: config.hasKurierKey,
    seenSetSize: seenSet.size,
    seenSetDegraded: seenSet.degraded,
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
