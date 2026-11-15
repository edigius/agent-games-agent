import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak256 } from 'js-sha3';
import { decideGatekeeper } from '../src/gatekeeper.js';
import {
  BN128_FIELD_MODULUS,
  buildCircuitInput,
  generateProof,
  toField,
} from '../src/proof.js';
import { VK_B, validGatekeeperInput } from './helpers.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

async function loadVk() {
  return JSON.parse(await readFile(join(ROOT, 'circuits/gatekeeper.vk.json'), 'utf8'));
}

// FullProve against the real wasm/zkey takes ~1s per proof; these tests
// are the ground truth that the mapping matches the circuit. snarkjs is
// imported lazily here (as in src/proof.js) to avoid event-loop hangs.
describe('gatekeeper circuit mapping (real artifacts)', () => {
  it('input mapping uses the confirmed signal names, fixed salt 1, decision encoding', async () => {
    const input = validGatekeeperInput();
    const approve = await buildCircuitInput('gatekeeper', {
      input,
      decision: 'APPROVE',
      taskId: 'gk_test_001',
    });
    assert.deepEqual(Object.keys(approve), [
      'minimum',
      'publicBalance',
      'expiryBlock',
      'currentBlock',
      'recipient',
      'conditionRecipient',
      'amount',
      'maxTransfer',
      'registeredVkHash',
      'proofVkHash',
      'taskId',
      'salt',
      'decision',
    ]);
    assert.equal(approve.salt, '1');
    assert.equal(approve.decision, '1');
    assert.equal(approve.minimum, '1000');
    assert.equal(approve.publicBalance, '1460');
    const reject = await buildCircuitInput('gatekeeper', {
      input,
      decision: 'REJECT',
      taskId: 'gk_test_001',
    });
    assert.equal(reject.decision, '0');
    assert.equal(reject.salt, '1');
  });

  it('a proof for a valid envelope verifies against the exported VK', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const input = validGatekeeperInput();
    const { decision } = decideGatekeeper(input, { isReplay: false });
    assert.equal(decision, 'APPROVE');
    const { proof, publicSignals } = await generateProof('gatekeeper', {
      input,
      decision,
      taskId: 'gk_test_001',
    });
    assert.equal(publicSignals.length, 13);
    assert.equal(publicSignals[11], '1'); // decision signal: APPROVE
    assert.equal(publicSignals[12], toField('gk_test_001').toString()); // taskId
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    assert.equal(ok, true);
  });

  it('a proof for a trap task with REJECT verifies; decision signal is 0', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const input = validGatekeeperInput({ proof_vk: VK_B });
    const { decision } = decideGatekeeper(input, { isReplay: false });
    assert.equal(decision, 'REJECT');
    const { proof, publicSignals } = await generateProof('gatekeeper', {
      input,
      decision,
      taskId: 'gk_test_002',
    });
    assert.equal(publicSignals[11], '0'); // decision signal: REJECT
    assert.equal(publicSignals[12], toField('gk_test_002').toString()); // taskId
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  });

  it('boundary: balance == minimum with APPROVE proves and verifies', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const input = validGatekeeperInput({ public_balance: '1000' });
    assert.equal(decideGatekeeper(input, { isReplay: false }).decision, 'APPROVE');
    const { proof, publicSignals } = await generateProof('gatekeeper', {
      input,
      decision: 'APPROVE',
      taskId: 'gk_test_003',
    });
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  });

  it('boundary: amount == maxTransfer with APPROVE proves and verifies', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const input = validGatekeeperInput({ amount: '1000' });
    assert.equal(decideGatekeeper(input, { isReplay: false }).decision, 'APPROVE');
    const { proof, publicSignals } = await generateProof('gatekeeper', {
      input,
      decision: 'APPROVE',
      taskId: 'gk_test_004',
    });
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  });

  it('boundary: current == expiry with APPROVE FAILS (strict expiry); with REJECT proves', async () => {
    const snarkjs = await import('snarkjs');
    const vk = await loadVk();
    const input = validGatekeeperInput({ current_block: 8430000 });
    assert.equal(decideGatekeeper(input, { isReplay: false }).decision, 'REJECT');
    // The CIRCUIT rejects APPROVE at expiry (witness assertion failure),
    // not the echo check: fullProve itself must throw "Assert Failed".
    await assert.rejects(
      generateProof('gatekeeper', { input, decision: 'APPROVE', taskId: 'gk_test_005' }),
      /Assert Failed/,
    );
    const { proof, publicSignals } = await generateProof('gatekeeper', {
      input,
      decision: 'REJECT',
      taskId: 'gk_test_005',
    });
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  });

  it('valid facts + REJECT is unprovable (why replay tasks carry no proof)', async () => {
    const input = validGatekeeperInput();
    await assert.rejects(
      generateProof('gatekeeper', { input, decision: 'REJECT', taskId: 'gk_test_006' }),
      /Assert Failed/,
    );
  });
});

describe('toField encoding (provisional)', () => {
  it('passes small integers through unchanged', () => {
    assert.equal(toField('1000'), 1000n);
    assert.equal(toField(8430000), 8430000n);
    assert.equal(toField(0n), 0n);
  });

  it('converts 0x addresses to BigInt directly (fits the field)', () => {
    const addr = '0xDe42aabbccddeeff001122334455667788990011';
    assert.equal(toField(addr), BigInt(addr));
    assert.ok(toField(addr) < BN128_FIELD_MODULUS);
  });

  it('hashes 32-byte values at/above the modulus deterministically, always in-field', () => {
    const big = `0x${'ff'.repeat(32)}`;
    assert.ok(BigInt(big) >= BN128_FIELD_MODULUS);
    const a = toField(big);
    const b = toField(big);
    assert.equal(a, b);
    assert.ok(a < BN128_FIELD_MODULUS);
    assert.ok(a >= 0n);
  });

  it('hashes non-numeric strings (task ids) deterministically, always in-field', () => {
    const a = toField('gk_8d31_test');
    assert.equal(a, toField('gk_8d31_test'));
    assert.notEqual(a, toField('gk_8d31_other'));
    assert.ok(a < BN128_FIELD_MODULUS);
  });

  it('rejects negative and non-integer values loudly', () => {
    assert.throws(() => toField(-1n), /negative/);
    assert.throws(() => toField(1.5), /non-negative integer/);
    assert.throws(() => toField(undefined), /unsupported/);
  });

  it('hashes the FULL value bytes for >32-byte values (odd 65-hex-digit quirk)', () => {
    // 65 hex digits: padStart(64,'0') leaves it odd-length, and
    // Buffer.from(hex,'hex') silently drops the last nibble. toField
    // must hash all 33 big-endian bytes (leading zero nibble), in both
    // the bigint and the decimal-string branches. Envelopes cap at 32
    // bytes, so this pins behavior for values that never occur live.
    const value = BigInt(`0x1${'ab'.repeat(32)}`);
    assert.equal(value.toString(16).length, 65);
    assert.ok(value >= BN128_FIELD_MODULUS);
    const fullBytes = Buffer.from(`0${value.toString(16)}`, 'hex');
    assert.equal(fullBytes.length, 33);
    const expected = BigInt(`0x${keccak256(fullBytes)}`) % BN128_FIELD_MODULUS;
    assert.equal(toField(value), expected);
    assert.equal(toField(value.toString(10)), expected);
    // And it must differ from the old truncated-nibble hash.
    const truncated = BigInt(`0x${keccak256(Buffer.from(value.toString(16), 'hex'))}`) % BN128_FIELD_MODULUS;
    assert.notEqual(toField(value), truncated);
  });

  it('keeps the exact 32-byte hashing behavior unchanged (no drift)', () => {
    // 64 hex digits: the even-length fix must not alter the bytes
    // hashed for values that already worked.
    const value = BigInt(`0x${'ab'.repeat(32)}`);
    const expected = BigInt(`0x${keccak256(Buffer.from(value.toString(16), 'hex'))}`) % BN128_FIELD_MODULUS;
    assert.equal(toField(value), expected);
    assert.equal(toField(value.toString(10)), expected);
    assert.equal(toField(`0x${'ab'.repeat(32)}`), expected);
  });
});
