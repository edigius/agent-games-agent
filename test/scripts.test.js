import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeCommitment } from '../scripts/commitment.js';
import { resolveTurn, runSimulation, searchStrategies } from '../scripts/simulate.js';

const run = promisify(execFile);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('commitment CLI', () => {
  it('computes the confirmed Poseidon commitment (discovery witness)', async () => {
    assert.equal(
      await computeCommitment([1, 0, 0, 0, 0, 0, 0, 0], 0n),
      '11299471465817035813941534680224295417418949445559228777402254279479107204147',
    );
  });

  it('prints ONLY the hash and never the salt or params', async () => {
    const { stdout, stderr } = await run('node', ['scripts/commitment.js'], {
      cwd: ROOT,
      env: { ...process.env, STRATEGY_SALT: '424242' },
    });
    assert.match(stdout, /^\d+\n$/);
    assert.equal(stderr, '');
    assert.doesNotMatch(stdout, /424242/);
  });

  it('exits non-zero when STRATEGY_SALT is missing, without printing a hash', async () => {
    const env = { ...process.env };
    delete env.STRATEGY_SALT;
    await assert.rejects(
      run('node', ['scripts/commitment.js'], { cwd: ROOT, env }),
      (err) => {
        assert.match(err.stderr, /refused/);
        assert.match(err.stderr, /STRATEGY_SALT is not set/);
        assert.equal(err.stdout, '');
        return true;
      },
    );
  });

  it('refuses an invalid salt without echoing it', async () => {
    await assert.rejects(
      run('node', ['scripts/commitment.js'], {
        cwd: ROOT,
        env: { ...process.env, STRATEGY_SALT: 'super-secret-salt-value' },
      }),
      (err) => {
        assert.match(err.stderr, /refused/);
        assert.doesNotMatch(err.stderr, /super-secret-salt-value/);
        assert.doesNotMatch(err.stdout ?? '', /super-secret-salt-value/);
        return true;
      },
    );
  });
});

describe('simulator', () => {
  it('resolves fortify blocking: 10 extracted into a fortify lands 4, minus cost', () => {
    const [self, opp] = resolveTurn(
      100,
      100,
      { type: 'EXTRACT', amount: 10 },
      { type: 'FORTIFY' },
    );
    // Opponent pays 2 (98), loses max(0, 10-6)=4 -> 94; self gains 4 -> 104.
    assert.deepEqual([self, opp], [104, 94]);
  });

  it('resolves mutual extraction on prior state', () => {
    const [self, opp] = resolveTurn(
      100,
      100,
      { type: 'EXTRACT', amount: 10 },
      { type: 'EXTRACT', amount: 10 },
    );
    assert.deepEqual([self, opp], [100, 100]);
  });

  it('caps extraction at the opponent balance and floors at zero', () => {
    const [self, opp] = resolveTurn(5, 3, { type: 'EXTRACT', amount: 10 }, { type: 'HOLD' });
    assert.deepEqual([self, opp], [8, 0]);
  });

  it('runs a small reproducible simulation with totals summing to matches', () => {
    const a = runSimulation({ matches: 20, seed: 42 });
    const b = runSimulation({ matches: 20, seed: 42 });
    assert.deepEqual(a, b);
    for (const r of Object.values(a)) {
      assert.equal(r.wins + r.draws + r.losses, 20);
    }
    assert.deepEqual(Object.keys(a).sort(), [
      'always-extract-10',
      'always-fortify',
      'always-hold',
      'random',
      'tit-for-tat',
    ]);
  });

  it('passes explicit params through to the policy', () => {
    const baseline = runSimulation({ matches: 20, seed: 42 });
    const passive = runSimulation({
      matches: 20,
      seed: 42,
      params: [10, 0, 0, 1, 0, 0, 0, 0],
    });
    assert.notDeepEqual(passive, baseline);
    // Passive never extracts: vs always-hold every match draws 100-100.
    assert.deepEqual(
      [passive['always-hold'].wins, passive['always-hold'].draws, passive['always-hold'].losses],
      [0, 20, 0],
    );
  });

  it('staged search is deterministic and returns a valid ranked winner', () => {
    const opts = {
      seed: 7,
      coarseMatches: 5,
      refineMatches: 5,
      verifyMatches: 5,
      coarseGrid: { p0: [1, 10], p1: [0, 50], p2: [0, 50], p3: [0, 1] },
    };
    const a = searchStrategies(opts);
    const b = searchStrategies(opts);
    assert.deepEqual(a, b);
    assert.equal(a.coarse.length, 16);
    assert.ok(a.refined.length > 0);
    assert.ok(a.verified.length > 0 && a.verified.length <= 6);
    assert.equal(a.winner.params.length, 8);
    assert.deepEqual(a.winner.params.slice(4), [0, 0, 0, 0]);
    assert.equal(
      a.winner.totalWins + a.winner.totalDraws + a.winner.totalLosses,
      5 * 5,
    );
  });
});
