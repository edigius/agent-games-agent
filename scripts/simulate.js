#!/usr/bin/env node
/**
 * PEGASUS — Steal the VFY match simulator.
 *
 * Plays the 4-knob threshold policy from src/steal.js (CONFIRMED circuit
 * rule: self<p1 FORTIFY; elif opp<=p2 HOLD; elif p3==1 HOLD; else
 * EXTRACT p0) against a battery of opponent styles over many matches
 * and reports win/draw/loss. Two modes:
 *   `npm run simulate [matches] [seed]` — report for STRATEGY_PARAMS.
 *   `node scripts/simulate.js --search [seed]` — staged parameter
 *   search (coarse grid, refine around the best, high-match
 *   verification). The search is the ONLY sanctioned source of tuned
 *   values for src/strategyParams.js: evidence, no hand-tuning.
 *
 * RESOLVER ASSUMPTIONS (from the published rules; validate in practice):
 *  - Simultaneous resolution on PRIOR public state only: both actions are
 *    chosen from the same pre-turn balances, then applied together.
 *  - FORTIFY costs 2 (deducted from the fortifier) and blocks up to 6 VFY
 *    of incoming extraction THAT turn. Fortification is assumed to last
 *    one turn (fortifiedUntilTurn == current turn); the docs do not state
 *    a longer duration.
 *  - EXTRACT N (max 10, free) steals min(N, opponent's post-cost balance),
 *    reduced by up to 6 when the opponent fortified that turn.
 *  - Balances floor at 0. Highest balance after 20 turns wins; equal
 *    balances draw. Both agents start at 100.
 *  - Turn numbering: turns run 0..19 in the simulator. The policy does
 *    not read the turn (the circuit's policy ignores it), so numbering
 *    cannot affect results here.
 *
 * Opponent styles: always-EXTRACT-10, always-FORTIFY, always-HOLD,
 * seeded-random, and tit-for-tat (extract iff the opponent extracted last
 * turn, HOLD on turn 0). The random policy uses a seeded PRNG so runs are
 * reproducible: same seed -> same results.
 */
import { pathToFileURL } from 'node:url';
import { policy } from '../src/steal.js';
import { STRATEGY_PARAMS } from '../src/strategyParams.js';

export const TOTAL_TURNS = 20;
export const START_BALANCE = 100;
export const FORTIFY_COST = 2;
export const FORTIFY_BLOCK = 6;

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const OPPONENTS = {
  'always-extract-10': () => ({ type: 'EXTRACT', amount: 10 }),
  'always-fortify': () => ({ type: 'FORTIFY' }),
  'always-hold': () => ({ type: 'HOLD' }),
  random: (rand) => {
    const r = rand();
    if (r < 0.33) return { type: 'HOLD' };
    if (r < 0.66) return { type: 'FORTIFY' };
    return { type: 'EXTRACT', amount: 1 + Math.floor(rand() * 10) };
  },
  'tit-for-tat': (_rand, history) => {
    const last = history[history.length - 1];
    if (!last) return { type: 'HOLD' };
    return last.selfAction.type === 'EXTRACT'
      ? { type: 'EXTRACT', amount: 10 }
      : { type: 'HOLD' };
  },
};

/**
 * Resolve one turn from prior-state balances.
 * @returns {[number, number]} post-turn balances [self, opponent].
 */
export function resolveTurn(selfBalance, oppBalance, selfAction, oppAction) {
  let self = selfBalance;
  let opp = oppBalance;
  const selfFort = selfAction.type === 'FORTIFY';
  const oppFort = oppAction.type === 'FORTIFY';
  if (selfFort) self -= FORTIFY_COST;
  if (oppFort) opp -= FORTIFY_COST;

  let selfSteal = 0;
  let oppSteal = 0;
  if (selfAction.type === 'EXTRACT') {
    selfSteal = Math.min(selfAction.amount, Math.max(0, opp));
    if (oppFort) selfSteal = Math.max(0, selfSteal - FORTIFY_BLOCK);
  }
  if (oppAction.type === 'EXTRACT') {
    oppSteal = Math.min(oppAction.amount, Math.max(0, self));
    if (selfFort) oppSteal = Math.max(0, oppSteal - FORTIFY_BLOCK);
  }
  self = Math.max(0, self + selfSteal - oppSteal);
  opp = Math.max(0, opp + oppSteal - selfSteal);
  return [self, opp];
}

export function playMatch(opponentFn, rand, params = STRATEGY_PARAMS) {
  let self = START_BALANCE;
  let opp = START_BALANCE;
  const history = [];
  for (let turn = 0; turn < TOTAL_TURNS; turn += 1) {
    const state = {
      selfBalance: String(self),
      opponentBalance: String(opp),
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
      turn,
    };
    const selfAction = policy(state, params);
    const oppAction = opponentFn(rand, history);
    history.push({ turn, selfAction, oppAction });
    [self, opp] = resolveTurn(self, opp, selfAction, oppAction);
  }
  return { self, opp, result: self > opp ? 'win' : self < opp ? 'loss' : 'draw' };
}

export function runSimulation({ matches = 1000, seed = 20261115, params = STRATEGY_PARAMS } = {}) {
  const report = {};
  for (const [name, fn] of Object.entries(OPPONENTS)) {
    const rand = mulberry32(seed);
    let wins = 0;
    let draws = 0;
    let losses = 0;
    let selfTotal = 0;
    let oppTotal = 0;
    for (let i = 0; i < matches; i += 1) {
      const { self, opp, result } = playMatch(fn, rand, params);
      selfTotal += self;
      oppTotal += opp;
      if (result === 'win') wins += 1;
      else if (result === 'draw') draws += 1;
      else losses += 1;
    }
    report[name] = {
      matches,
      wins,
      draws,
      losses,
      winRate: Number((wins / matches).toFixed(3)),
      avgSelfBalance: Number((selfTotal / matches).toFixed(1)),
      avgOppBalance: Number((oppTotal / matches).toFixed(1)),
    };
  }
  return report;
}

/**
 * Score one param set across the whole opponent battery at a fixed
 * match count and seed. Primary ranking: total wins. Tie-break: total
 * average-balance margin (self minus opponent, summed over opponents).
 */
export function scoreParams(params, { matches = 100, seed = 20261115 } = {}) {
  const perOpponent = runSimulation({ matches, seed, params });
  let totalWins = 0;
  let totalDraws = 0;
  let totalLosses = 0;
  let totalMargin = 0;
  for (const r of Object.values(perOpponent)) {
    totalWins += r.wins;
    totalDraws += r.draws;
    totalLosses += r.losses;
    totalMargin += r.avgSelfBalance - r.avgOppBalance;
  }
  return {
    params: [...params],
    matches,
    perOpponent,
    totalWins,
    totalDraws,
    totalLosses,
    totalMargin: Number(totalMargin.toFixed(1)),
  };
}

function compareScores(a, b) {
  if (b.totalWins !== a.totalWins) return b.totalWins - a.totalWins;
  return b.totalMargin - a.totalMargin;
}

export const DEFAULT_COARSE_GRID = Object.freeze({
  p0: Object.freeze([1, 3, 5, 7, 10]),
  p1: Object.freeze([0, 25, 50, 75, 100, 150]),
  p2: Object.freeze([0, 25, 50, 75, 100, 150]),
  p3: Object.freeze([0, 1]),
});

function neighborhood(value, step, lo, hi) {
  const values = new Set();
  for (let d = -2; d <= 2; d += 1) {
    const v = value + d * step;
    if (v >= lo && v <= hi) values.add(v);
  }
  return [...values].sort((a, b) => a - b);
}

/**
 * Staged parameter search (seeded, reproducible):
 *   1. coarse grid over p0 x p1 x p2 x p3 at `coarseMatches`;
 *   2. refine around the coarse winner (p0 +-2 step 1, p1/p2 +-20
 *      step 10, both p3 values) at `refineMatches`;
 *   3. verify the top 3 of each stage at `verifyMatches` and rank.
 * Deliberately NOT exhaustive: the full 10 x 201 x 201 x 2 space is
 * ~800k configs. Returns { coarse, refined, verified, winner } with
 * each stage ranked best-first.
 */
export function searchStrategies({
  seed = 20261115,
  coarseMatches = 50,
  refineMatches = 200,
  verifyMatches = 1000,
  coarseGrid = DEFAULT_COARSE_GRID,
} = {}) {
  const key = (p) => p.join(',');
  const seen = new Set();
  const coarse = [];
  for (const p0 of coarseGrid.p0) {
    for (const p1 of coarseGrid.p1) {
      for (const p2 of coarseGrid.p2) {
        for (const p3 of coarseGrid.p3) {
          const params = [p0, p1, p2, p3, 0, 0, 0, 0];
          seen.add(key(params));
          coarse.push(scoreParams(params, { matches: coarseMatches, seed }));
        }
      }
    }
  }
  coarse.sort(compareScores);

  const best = coarse[0].params;
  const refined = [];
  for (const p0 of neighborhood(best[0], 1, 1, 10)) {
    for (const p1 of neighborhood(best[1], 10, 0, 200)) {
      for (const p2 of neighborhood(best[2], 10, 0, 200)) {
        for (const p3 of [0, 1]) {
          const params = [p0, p1, p2, p3, 0, 0, 0, 0];
          if (seen.has(key(params))) continue;
          seen.add(key(params));
          refined.push(scoreParams(params, { matches: refineMatches, seed }));
        }
      }
    }
  }
  refined.sort(compareScores);

  // Final ranking at high match count; dedupe by params.
  const candidates = new Map();
  for (const s of [...coarse.slice(0, 3), ...refined.slice(0, 3)]) {
    candidates.set(key(s.params), s.params);
  }
  const verified = [...candidates.values()].map((params) =>
    scoreParams(params, { matches: verifyMatches, seed }),
  );
  verified.sort(compareScores);

  return { coarse, refined, verified, winner: verified[0] };
}

function printScore(score) {
  const p = score.params;
  console.log(
    `  [p0=${p[0]} p1=${p[1]} p2=${p[2]} p3=${p[3]}] ` +
      `W ${score.totalWins} D ${score.totalDraws} L ${score.totalLosses} ` +
      `margin ${score.totalMargin} (per ${score.matches} matches/opponent)`,
  );
}

function main() {
  if (process.argv[2] === '--search') {
    const seed = Number(process.argv[3] ?? 20261115);
    console.log(`PEGASUS staged strategy search, seed ${seed}`);
    const started = Date.now();
    const { coarse, refined, verified, winner } = searchStrategies({ seed });
    console.log(`Stage 1 coarse: ${coarse.length} configs. Top 3:`);
    coarse.slice(0, 3).forEach(printScore);
    console.log(`Stage 2 refine: ${refined.length} configs around the coarse winner. Top 3:`);
    refined.slice(0, 3).forEach(printScore);
    console.log(`Stage 3 verify: ${verified.length} candidates at 1000 matches/opponent.`);
    verified.forEach(printScore);
    console.log(`WINNER: [${winner.params.join(', ')}]`);
    for (const [name, r] of Object.entries(winner.perOpponent)) {
      console.log(
        `  ${name.padEnd(20)} W ${String(r.wins).padStart(5)}  D ${String(r.draws).padStart(5)}  ` +
          `L ${String(r.losses).padStart(5)}  winRate ${r.winRate}  avg ${r.avgSelfBalance} vs ${r.avgOppBalance}`,
      );
    }
    console.log(`Search took ${((Date.now() - started) / 1000).toFixed(1)}s.`);
    console.log('Set src/strategyParams.js to the winner ONLY from this evidence,');
    console.log('then re-run `npm run simulate` and commit the params before registering.');
    process.exit(0);
  }
  const matches = Number(process.argv[2] ?? 1000);
  const seed = Number(process.argv[3] ?? 20261115);
  const report = runSimulation({ matches, seed });
  console.log(`PEGASUS policy simulation — ${matches} matches per opponent, seed ${seed}`);
  console.log(`STRATEGY_PARAMS: [${STRATEGY_PARAMS.join(', ')}]`);
  for (const [name, r] of Object.entries(report)) {
    console.log(
      `${name.padEnd(20)} W ${String(r.wins).padStart(5)}  D ${String(r.draws).padStart(5)}  ` +
        `L ${String(r.losses).padStart(5)}  winRate ${r.winRate}  avg ${r.avgSelfBalance} vs ${r.avgOppBalance}`,
    );
  }
  process.exit(0);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
