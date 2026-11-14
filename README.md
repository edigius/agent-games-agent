# PEGASUS — zkVerify Agent Games agent

PEGASUS is a custom, hand-written agent for the zkVerify Agent Games
Season 01, covering both arena tracks with one HTTPS endpoint:

- **Proof Gatekeeper** — judges proof-backed payment tasks: APPROVE/REJECT
  with a reason code and a Groth16 proof, inside 60 seconds.
- **Steal the VFY** — head-to-head matches, 20 turns, each move backed by a
  policy proof that the move matches the agent's committed strategy.

It is deliberately NOT a starter-prompt scaffold: deterministic pure-logic
decisions, no LLM anywhere in the decision path, a persistent replay
memory, boundary-exact checks, and a simulation harness for the Steal
strategy. The platform re-verifies every proof against its own keys; there
is no shortcut and none is attempted.

## Status — read before deploying

PEGASUS is **pre-practice**: the transport, Gatekeeper decision logic,
Gatekeeper proof generation (confirmed mapping, verified against the
exported VK), signing, seen-set, Kurier client, and response shaping are
built and tested. **Steal the VFY proof generation is still blocked**:
the vfy-policy circuit mapping is unpublished and under separate
discovery — Steal turns are answered correctly but WITHOUT policy-proof
evidence until then. Do not enter scored rounds until practice mode
passes, including the encoding validation in
[Known unknowns](#known-unknowns).

## How it works

```
POST /agent  ── HMAC verify (raw body, before parsing)
   ├─ type = agent-games.preflight.v1        → { ok: true, protocolVersion: "v1" }
   ├─ type = agent-games.proof-gatekeeper.v1 → Gatekeeper decision + proof evidence
   └─ eventId = steal-the-vfy               → Steal turn + policy proof
```

Every response is signed with `x-agent-games-signature` (HMAC-SHA256 over
the raw response body). `GET /health` and `GET /` are operator monitoring
only — the platform's documented readiness check is the signed preflight;
no health-check path is published.

### Gatekeeper decisions

Pure checks over the envelope `input` fields, in fixed priority order:

1. `proof_tx` must not have been decided before (persistent seen-set)
   → else `PROOF_REPLAY` (canonical code; the event page calls the trap
   `PROOF_REUSED`). Checked FIRST: replay tasks are answered with NO
   proof fields and no proof generation attempt, because valid facts +
   REJECT is unprovable in the circuit.
2. `proof_vk` must equal `registered_vk` → else `VK_SUBSTITUTION`
3. `current_block` must be strictly below `expiry_block` → else expired
   trap (STRICT: equality is expired, confirmed by circuit experiments)
4. `recipient` must equal `condition_recipient` → else recipient trap
5. `public_balance` must be ≥ `minimum` → else `THRESHOLD_MISMATCH`
6. `amount` must be ≤ `max_transfer` → else amount-overflow trap
7. Otherwise APPROVE with `VALID_PROOF`

Boundary rules (confirmed by local fullProve experiments against the
downloaded circuit, 15 Nov 2026): balance == minimum passes; amount ==
max_transfer passes; current_block == expiry_block is EXPIRED. Hex
values compare case-insensitively. All comparisons use BigInt — no
float precision loss on large balances.

The gatekeeper proof covers the decision with 13 circuit inputs
(minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash,
taskId, salt, decision; decision 1 = APPROVE, 0 = REJECT) and 13 public
signals in the confirmed order. Salt is FIXED to 1: any salt is
cryptographically valid, and a fixed salt keeps the binding-hash public
signal deterministic per task with no salt management. Value encodings
are PROVISIONAL (single isolated `toField()` in `src/proof.js`) and must
be practice-validated — see Known unknowns. The full `publicSignals`
array is logged for every task so submissions can be correlated with
practice-mode teaching feedback.

No on-chain lookup is attempted for the incoming proof: the public docs
publish no lookup API for `proof_tx`, and the envelope carries no proof
bytes to verify. `proof_tx` is an audit pointer (echoed in the response)
and the seen-set key. The seen-set is a JSON file written atomically and
loaded at startup, so replay detection survives restarts — on Fly.io it
must live on the persistent volume (see `fly.toml`).

### Steal the VFY

The policy is a pure function of the envelope state
(`selfBalance`, `opponentBalance`, `turn`, fortify flags) and the
parameters in `src/strategyParams.js` — the ONLY file strategy values
live in. Current values are **PROVISIONAL** (starting point for the
simulator, not a tuned strategy) and must not be committed to the
platform until the circuit's parameter format is known.

`publicInputsHash` is keccak256 over 8 ABI-packed 32-byte big-endian
fields in the published order: commitment, matchId, turn, selfBalance,
opponentBalance, actionType (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount
(0 for HOLD/FORTIFY), circuitVersion ("v1" → 1). `amount` is omitted
entirely from HOLD/FORTIFY actions. Each turn gets a fresh
`idempotencyKey`. Any policy failure degrades to HOLD.

### Proofs and Kurier

Proofs are generated locally with snarkjs from the downloaded
circuit artifacts (`circuits/`, Groth16/BN128) and submitted to zkVerify
via Kurier REST (`POST /submit-proof/{key}`, poll `GET /job-status/`
to Finalized). The `.wasm`/`.zkey` binaries are not committed to the repo;
the Dockerfile downloads them from the official Agent Games site at build
time and verifies their SHA256 hashes (see `Dockerfile`). For local runs,
place the four artifacts in `circuits/` (URLs: `/api/circuit-info`). The response is NEVER held waiting for Finalized: the
proof and public signals ride in the response itself so the platform can
verify independently, and Kurier polling is opportunistic inside the
remaining deadline budget. Exactly one Kurier submission is attempted per
task/turn; only idempotent status polls are retried.

## Setup

Requires Node.js 20+.

```sh
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (and KURIER_API_KEY)
npm test               # full suite incl. real-circuit proofs; --test-force-exit
                       # because snarkjs leaves the event loop alive after proving
npm start              # serves POST /agent on $PORT (default 8080)
```

Environment variables (see `.env.example`):

| Variable | Required | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes | From dashboard "Rotate Secret", revealed once |
| `KURIER_API_KEY` | no* | From https://kurier.xyz signup |
| `KURIER_API_URL` | no | Defaults to mainnet |
| `STRATEGY_SALT` | CLI only | For `npm run commitment` |
| `PORT` | no | Default 8080 |
| `SEEN_SET_PATH` | no | Default `data/seen-set.json` |

\*Without a Kurier key the server still runs, but proofs are not
submitted to zkVerify and `proofReference` stays null.

## Deploy to Fly.io

```sh
fly launch --no-deploy          # pick a globally unique app name
fly volumes create pegasus_data --size 1 --region sin
fly secrets set AGENT_GAMES_HMAC_SECRET="..." KURIER_API_KEY="..."
fly deploy
```

Then, on the Agent Games dashboard: register the agent with the endpoint
URL `https://<app>.fly.dev/agent` (the FULL handler path — the platform
posts exactly to the registered URL), rotate the secret, set it via
`fly secrets set`, restart, and run the signed preflight. Preflight must
pass before the platform marks the agent active. After that, run practice
tasks/turns and validate every item in [Known unknowns](#known-unknowns)
before entering a scored round.

Single instance on purpose: two instances would split the seen-set.

## Simulator

```sh
npm run simulate [matches] [seed]   # default 1000 matches, seed 20261115
```

Plays the current policy against always-EXTRACT-10, always-FORTIFY,
always-HOLD, seeded-random, and tit-for-tat opponents, and reports
win/draw/loss plus average balances. Resolver assumptions are documented
in the script header. The harness validates; it does not tune — strategy
changes go in `src/strategyParams.js` only, and are re-simulated before
any commitment.

## Commitment CLI

```sh
STRATEGY_SALT="..." npm run commitment
```

Currently REFUSES to output a hash: the Poseidon preimage layout is
unpublished, and a guessed commitment would invalidate every policy
proof. When the official layout is known, implement
`computeCommitment()` in `scripts/commitment.js` and test it against an
official worked example. The CLI prints only the hash — never params,
never salt.

## Known unknowns (practice-validation items)

These are gaps in the PUBLIC documentation, not guesses. Each must be
resolved from the dashboard/practice view or official docs before scored
play. Nothing here is invented.

1. **Gatekeeper encodings (PROVISIONAL).** Signal names, order, and
   boundaries are CONFIRMED by local experiments, but the value-to-field
   encodings are provisional: the circuit accepts any field element, so a
   proof can verify locally and still mismatch what the platform
   recomputes from the envelope. All encodings live in the single
   isolated `toField()` in `src/proof.js` (hex/decimal direct when below
   the BN128 modulus, else keccak256-mod-modulus; non-numeric task ids
   hashed as UTF-8). Practice-mode teaching feedback must confirm them;
   if they differ, change ONLY `toField()`.
2. **Vfy-policy circuit mapping (BLOCKER for Steal proofs).** Signal
   names/order and the strategy-parameter format are unpublished;
   discovery is running separately. `src/proof.js` throws for
   `vfyPolicy` and Steal turns degrade to proof-less responses until it
   is implemented. Do not guess.
3. **Commitment preimage (BLOCKER for Steal).** "Poseidon hash of params
   + salt" with no field order, arity, encoding, or salt placement, and
   no published parameter format. `scripts/commitment.js` refuses.
4. **Reason-code mapping for 3 traps.** The canonical list has no
   expiry/recipient/overflow code. Provisional mapping (all three →
   `PUBLIC_INPUT_MISMATCH`) lives in `src/reasonCodes.js`; practice mode
   must confirm whether the platform expects the canonical codes or the
   event-page trap names (`EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`,
   `AMOUNT_OVERFLOW`).
5. **Finalized vs 60 seconds.** Docs demand Finalized "before approval"
   but also a hard 60s response deadline, with no published finalization
   time. PEGASUS never blocks on Finalized; practice (which uses a
   TIGHTER deadline than competition) must confirm the platform accepts
   proof evidence in the response without waiting. Proof generation
   measured ~1s locally, so the response path stays fast.
6. **Response superset.** The `/build` JSON examples show fewer fields
   than the prose/guide require. PEGASUS sends the union
   (`decision`/`reason_code`/`proof_tx`/`proof`/`public_signals`;
   Steal adds `proof`/`public_signals` beside `policyProof`), except
   replay tasks, which carry no proof fields by design. Practice must
   confirm extra fields are accepted.
7. **HMAC header encoding.** Docs say HMAC-SHA256 over the raw body
   without naming the encoding. PEGASUS emits lowercase hex and accepts
   hex or base64 inbound. Practice/preflight confirms.
8. **Incoming-proof verification.** No lookup API is published; PEGASUS
   does not attempt one. If practice reveals an expected check, add it
   in `src/gatekeeper.js` behind the same fail-closed discipline.
9. **Steal turn numbering and fortify duration.** Whether turns are
   0- or 1-based, and whether fortification lasts one turn or until
   `fortifiedUntilTurn`, is unstated. The policy/simulator assume the
   conservative readings documented in code; practice matches confirm.

## Rules compliance

- One agent, autonomous operation: no manual responses, no human in the
  decision loop (Rules 1.1–1.2).
- Proof integrity: fresh proof per task/turn, no reuse, no manipulation
  (Rule 1.3). The persistent seen-set enforces the replay rule.
- Fair play: no probing or attacking platform infrastructure (Rule 1.4).
  PEGASUS only answers signed requests sent to its own endpoint and
  submits its own proofs to Kurier.
- Secrets never appear in logs, prompts, or this repo (see `.gitignore`).

## Layout

```
src/
  index.js          entry point: config, state, shutdown
  server.js         HTTP transport, routing, budgets, fail-closed paths
  config.js         env config, vk hashes, circuit facts, deadlines
  hmac.js           sign/verify (raw body, constant-time compare)
  gatekeeper.js     pure decision logic
  reasonCodes.js    canonical codes + provisional trap mapping
  seenSet.js        persistent replay memory (atomic JSON file)
  steal.js          policy, publicInputsHash, response shaping
  strategyParams.js PROVISIONAL strategy values (single source)
  proof.js          snarkjs adapter + Kurier orchestration (gatekeeper
                    mapping confirmed; vfyPolicy stubbed, discovery pending)
  kurier.js         Kurier REST client (one submit, polled reads)
scripts/
  commitment.js     commitment CLI (refuses until layout is known)
  simulate.js       Steal match simulator + opponent battery
test/               node:test suite (no network, mocked proof/Kurier)
circuits/           downloaded artifacts (wasm, zkey, exported vk)
```
