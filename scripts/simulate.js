#!/usr/bin/env node
/**
 * PEGASUS — Steal the VFY match simulator.
 *
 * Plays the policy from src/steal.js against a battery of opponent styles
 * over many matches and reports win/draw/loss. This harness exists to
 * VALIDATE strategy changes before any commitment is registered; it does
 * not tune anything itself. Run: `npm run simulate [matches] [seed]`.
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
 *  - Turn numbering: turns run 0..19 in the simulator. The policy treats
 *    turn >= TOTAL_TURNS - ENDGAME_TURNS as endgame, which is safe under
 *    either 0- or 1-based platform numbering.
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

export function runSimulation({ matches = 1000, seed = 20261115 } = {}) {
  const report = {};
  for (const [name, fn] of Object.entries(OPPONENTS)) {
    const rand = mulberry32(seed);
    let wins = 0;
    let draws = 0;
    let losses = 0;
    let selfTotal = 0;
    let oppTotal = 0;
    for (let i = 0; i < matches; i += 1) {
      const { self, opp, result } = playMatch(fn, rand);
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

function main() {
  const matches = Number(process.argv[2] ?? 1000);
  const seed = Number(process.argv[3] ?? 20261115);
  const report = runSimulation({ matches, seed });
  console.log(`PEGASUS policy simulation — ${matches} matches per opponent, seed ${seed}`);
  console.log('NOTE: STRATEGY_PARAMS are PROVISIONAL; results validate the harness, not a tuned strategy.');
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
