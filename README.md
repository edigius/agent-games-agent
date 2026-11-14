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
exported VK), Steal policy + proof generation (confirmed vfy-policy
mapping, verified against the exported VK), signing, seen-set, Kurier
client, and response shaping are built and tested. Do not enter scored
rounds until practice mode passes, including the encoding validation in
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

The policy is the EXACT rule enforced by the vfy-policy circuit
(confirmed by local fullProve+verify experiments, 15 Nov 2026),
parameterized by the 8 values in `src/strategyParams.js` — the ONLY file
strategy values live in. In precedence order:

```
if selfBalance < p1:          FORTIFY, amount 0
elif opponentBalance <= p2:   HOLD, amount 0
elif p3 == 1:                 HOLD, amount 0
else:                         EXTRACT, amount p0
```

Only 4 knobs are live: p0 = EXTRACT amount (1..10), p1 = FORTIFY
threshold on own balance (0 disables), p2 = HOLD threshold on opponent
balance, p3 = passive flag {0,1}; p4..p7 are reserved and must be 0.
Boundaries are strict as written. Turn number and fortification state
do NOT affect the policy — the circuit's policy cannot see them. The
committed values were chosen ONLY by the staged simulator search (see
[Simulator](#simulator)); the search evidence is cited in
`src/strategyParams.js`.

The strategy commitment is `Poseidon([p0..p7, salt])`, arity 9, salt
last — computed by the shared module `src/commitment.js`, used by both
the proof adapter and the commitment CLI, so turn proofs always match
the registered hash by construction. The turn proof's public signals
are `[bindingHash, commitment, matchId, turnNumber, selfBalance,
opponentBalance, action, amount, circuitVersion]` with
`bindingHash = Poseidon([matchId, turnNumber, circuitVersion])`; salt
and params stay private. If proof generation fails for a turn (e.g.
the circuit rejects a fail-closed HOLD, or the salt/params do not match
the registered commitment), the server degrades to a proof-less turn
response and logs loudly — evidence is never faked.

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
place the four artifacts in `circuits/` (URLs: `/api/circuit-info`). The response is NEVER held waiting for Kurier at all: the
proof and public signals ride in the response itself so the platform can
verify independently, and the Kurier submission + finalization polling
run in the background after the response (awaiting either one burned
the whole deadline budget on practice tasks practice_b6662f40 and
practice_502f0b25). Exactly one Kurier submission is attempted per
task/turn; only idempotent status polls are retried. GET /health reports
a buildId (bumped in src/config.js on every push) so a deployment can be
verified as the intended code.

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
| `STRATEGY_SALT` | yes | Self-generated secret; server fails fast without it; same salt must be used for the commitment CLI |
| `KURIER_API_KEY` | no* | From https://kurier.xyz signup |
| `KURIER_API_URL` | no | Defaults to mainnet |
| `PORT` | no | Default 8080 |
| `SEEN_SET_PATH` | no | Default `data/seen-set.json` |

\*Without a Kurier key the server still runs, but proofs are not
submitted to zkVerify and `proofReference` stays null.

## Deploy to Fly.io

```sh
fly launch --no-deploy          # pick a globally unique app name
fly volumes create pegasus_data --size 1 --region sin
fly secrets set AGENT_GAMES_HMAC_SECRET="..." STRATEGY_SALT="..." KURIER_API_KEY="..."
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
node scripts/simulate.js --search [seed]   # staged parameter search
```

Plays the current policy against always-EXTRACT-10, always-FORTIFY,
always-HOLD, seeded-random, and tit-for-tat opponents, and reports
win/draw/loss plus average balances. Resolver assumptions are documented
in the script header. `--search` runs the staged search (coarse grid,
refine around the best, high-match verification) and reports the
winning params — the ONLY sanctioned source of tuned values for
`src/strategyParams.js`. Strategy changes go in `src/strategyParams.js`
only, are re-simulated before any commitment, and the commitment must
be re-registered whenever the params change.

## Commitment CLI

```sh
STRATEGY_SALT="..." npm run commitment
```

Prints ONLY the strategy commitment hash
(`Poseidon([p0..p7, salt])`), computed by the shared module
`src/commitment.js` — the same code the proof adapter uses. Register
the printed hash on the dashboard (My Agents → Edit agent → Strategy
Commitment) before Swiss Round 1, using the SAME salt the server runs
with. The CLI refuses (non-zero exit) when `STRATEGY_SALT` is missing
or invalid. It never prints params or salt.

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
2. **Reason-code mapping for 3 traps.** The canonical list has no
   expiry/recipient/overflow code. Provisional mapping (all three →
   `PUBLIC_INPUT_MISMATCH`) lives in `src/reasonCodes.js`; practice mode
   must confirm whether the platform expects the canonical codes or the
   event-page trap names (`EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`,
   `AMOUNT_OVERFLOW`).
3. **Finalized vs 60 seconds.** Docs demand Finalized "before approval"
   but also a hard 60s response deadline, with no published finalization
   time. PEGASUS never blocks on Finalized; practice (which uses a
   TIGHTER deadline than competition) must confirm the platform accepts
   proof evidence in the response without waiting. Proof generation
   measured ~1s locally, so the response path stays fast.
4. **Response superset.** The `/build` JSON examples show fewer fields
   than the prose/guide require. PEGASUS sends the union
   (`decision`/`reason_code`/`proof_tx`/`proof`/`public_signals`;
   Steal adds `proof`/`public_signals` beside `policyProof`), except
   replay tasks, which carry no proof fields by design. Practice must
   confirm extra fields are accepted.
5. **HMAC header encoding.** Docs say HMAC-SHA256 over the raw body
   without naming the encoding. PEGASUS emits lowercase hex and accepts
   hex or base64 inbound. Practice/preflight confirms.
6. **Incoming-proof verification.** No lookup API is published; PEGASUS
   does not attempt one. If practice reveals an expected check, add it
   in `src/gatekeeper.js` behind the same fail-closed discipline.
7. **Steal turn numbering and fortify duration.** Whether turns are
   0- or 1-based, and whether fortification lasts one turn or until
   `fortifiedUntilTurn`, is unstated. Turn numbering no longer affects
   the policy (the circuit ignores it; the turn value is passed through
   into the binding hash and `publicInputsHash` exactly as received),
   but fortify duration still affects the SIMULATOR's resolver
   assumptions (one turn, per the script header). Practice matches
   confirm.

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
  steal.js          policy (confirmed circuit rule), publicInputsHash,
                    response shaping
  strategyParams.js strategy values (single source) + validator
  commitment.js     shared Poseidon commitment + binding hash (used by
                    proof adapter and commitment CLI alike)
  proof.js          snarkjs adapter + Kurier orchestration (both circuit
                    mappings confirmed; public-signal echo assertions)
  kurier.js         Kurier REST client (one submit, polled reads)
scripts/
  commitment.js     commitment CLI (prints only the hash)
  simulate.js       Steal match simulator + opponent battery + staged
                    parameter search (--search)
test/               node:test suite (no network, mocked proof/Kurier,
                    plus real-artifact circuit suites)
circuits/           downloaded artifacts (wasm, zkey, exported vk)
```
