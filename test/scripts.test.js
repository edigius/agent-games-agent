import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeCommitment } from '../scripts/commitment.js';
import { resolveTurn, runSimulation } from '../scripts/simulate.js';

const run = promisify(execFile);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('commitment CLI', () => {
  it('refuses to compute a hash while the preimage layout is unknown', () => {
    assert.throws(() => computeCommitment({}, 'salt'), /preimage layout is UNKNOWN/);
  });

  it('exits non-zero with a refusal message (never prints params or salt)', async () => {
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
});
