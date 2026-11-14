/**
 * PEGASUS — configuration.
 *
 * All secrets come from environment variables only. Nothing in this file
 * (or anywhere in the repo) may contain a real secret or a placeholder that
 * looks like one. Booleans about secret presence are logged; values never are.
 */

// Registered verification-key hashes, published on zkVerify mainnet and
// served as JSON from https://agentgames.zkverify.io/api/circuit-info.
export const VK_HASH = Object.freeze({
  gatekeeper:
    '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
  vfyPolicy:
    '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047',
});

export const CIRCUIT_VERSION = 'v1';

// Verified circuit facts (snarkjs export, 15 Nov 2026). nPublic is known;
// signal names/order are NOT published — see src/proof.js.
export const CIRCUIT = Object.freeze({
  gatekeeper: Object.freeze({
    wasm: 'circuits/gatekeeper.wasm',
    zkey: 'circuits/gatekeeper_final.zkey',
    vk: 'circuits/gatekeeper.vk.json',
    vkHash: VK_HASH.gatekeeper,
    nPublic: 13,
  }),
  vfyPolicy: Object.freeze({
    wasm: 'circuits/vfy-policy.wasm',
    zkey: 'circuits/vfy-policy_final.zkey',
    vk: 'circuits/vfyPolicy.vk.json',
    vkHash: VK_HASH.vfyPolicy,
    nPublic: 9,
  }),
});

export const KURIER_API_URL =
  process.env.KURIER_API_URL ?? 'https://api.kurier.xyz/api/v1';

// Hard platform deadlines. Internal budgets subtract a safety margin so a
// slow proof/Kurier round-trip can never turn into a platform timeout.
export const GATEKEEPER_DEADLINE_MS = 60_000;
export const GATEKEEPER_MARGIN_MS = 5_000;
export const STEAL_DEADLINE_MS = 5 * 60_000;
export const STEAL_MARGIN_MS = 10_000;

export const MAX_BODY_BYTES = 1_048_576; // 1 MiB; envelopes are small JSON.

export function loadConfig(env = process.env) {
  const secret = env.AGENT_GAMES_HMAC_SECRET ?? '';
  if (!secret) {
    throw new Error(
      'AGENT_GAMES_HMAC_SECRET is not set. Reveal it once via Rotate Secret ' +
        'on the Agent Games dashboard and set it as an environment variable. ' +
        'Never commit it.',
    );
  }
  return Object.freeze({
    hmacSecret: secret,
    kurierApiKey: env.KURIER_API_KEY ?? '',
    kurierApiUrl: env.KURIER_API_URL ?? KURIER_API_URL,
    port: Number(env.PORT ?? 8080),
    seenSetPath: env.SEEN_SET_PATH ?? 'data/seen-set.json',
    // Presence flags only — safe to log.
    hasKurierKey: Boolean(env.KURIER_API_KEY),
  });
}
