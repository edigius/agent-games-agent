/** Shared fixtures for PEGASUS tests. Values are invented test data. */

// Deterministic PRNG (mulberry32) for property-style tests: no new
// dependencies (fast-check remains a user decision), same seed replays
// the exact same case sequence on every run.
export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function seededInt(rng, min, max) {
  return min + Math.floor(rng() * (max - min + 1));
}

export function seededHex(rng, bytes) {
  let s = '';
  for (let i = 0; i < bytes; i += 1) {
    s += seededInt(rng, 0, 255).toString(16).padStart(2, '0');
  }
  return s;
}

export const VK_A = `0x${'7d'.repeat(32)}`;
export const VK_B = `0x${'13'.repeat(32)}`;
export const ADDR_A = '0xDe42aabbccddeeff001122334455667788990011';
export const ADDR_B = '0xBeef00112233445566778899aabbccddeeff0011';
export const PROOF_TX = `0x${'a8'.repeat(32)}`;

export function validGatekeeperInput(overrides = {}) {
  return {
    registered_vk: VK_A,
    proof_vk: VK_A,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR_A,
    condition_recipient: ADDR_A,
    amount: '500',
    max_transfer: '1000',
    proof_tx: PROOF_TX,
    ...overrides,
  };
}

export function gatekeeperEnvelope(input, overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_001',
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input,
    ...overrides,
  };
}

export function stealEnvelope(state, overrides = {}) {
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId: '9f4e1b2a-0000-4000-8000-000000000001',
    turn: 3,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 300_000).toISOString(),
    state: {
      selfBalance: '95',
      opponentBalance: '105',
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
      ...state,
    },
    strategyCommitment: { hash: `0x${'7d'.repeat(32)}` },
    resolverVersion: 'v1',
    nonce: '3c2f1a00test',
    ...overrides,
  };
}
