import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SeenSet } from '../src/seenSet.js';

describe('seen set', () => {
  it('persists across restarts (new instance, same file)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      const first = new SeenSet(path);
      await first.load();
      assert.equal(first.has('0xabc'), false);
      await first.add('0xabc', { taskId: 'gk_1', decidedAt: 't', decision: 'APPROVE' });

      const second = new SeenSet(path);
      await second.load();
      assert.equal(second.has('0xabc'), true);
      assert.equal(second.size, 1);
      assert.equal(second.degraded, false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('starts empty when the file does not exist', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const s = new SeenSet(join(dir, 'missing.json'));
      await s.load();
      assert.equal(s.size, 0);
      assert.equal(s.degraded, false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('degrades to empty (with flag) on a corrupt file instead of crashing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      await writeFile(path, '{not json', 'utf8');
      const s = new SeenSet(path);
      await s.load();
      assert.equal(s.degraded, true);
      assert.equal(s.size, 0);
      // Still usable afterwards.
      await s.add('0x1', { taskId: 'gk_2', decidedAt: 't', decision: 'REJECT' });
      assert.equal(s.has('0x1'), true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('writes atomically: no temp file left behind, valid JSON on disk', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      const s = new SeenSet(path);
      await s.load();
      await s.add('0xdead', { taskId: 'gk_3', decidedAt: 't', decision: 'APPROVE' });
      const parsed = JSON.parse(await readFile(path, 'utf8'));
      assert.equal(parsed.version, 1);
      assert.equal(parsed.entries['0xdead'].taskId, 'gk_3');
      await assert.rejects(readFile(`${path}.tmp`, 'utf8'));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('writes a second copy (.bak) identical to the primary on every save', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      const s = new SeenSet(path);
      await s.load();
      await s.add('0x1', { taskId: 'gk_4', decidedAt: 't', decision: 'APPROVE' });
      await s.add('0x2', { taskId: 'gk_5', decidedAt: 't', decision: 'REJECT' });
      const primary = JSON.parse(await readFile(path, 'utf8'));
      const backup = JSON.parse(await readFile(`${path}.bak`, 'utf8'));
      assert.deepEqual(backup, primary);
      assert.equal(backup.entries['0x2'].decision, 'REJECT');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('recovers from the backup when the primary is corrupt (degraded + flagged)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      const first = new SeenSet(path);
      await first.load();
      await first.add('0xabc', { taskId: 'gk_1', decidedAt: 't', decision: 'APPROVE' });
      await writeFile(path, '{corrupted', 'utf8');

      const second = new SeenSet(path);
      await second.load();
      assert.equal(second.has('0xabc'), true);
      assert.equal(second.size, 1);
      assert.equal(second.degraded, true);
      assert.equal(second.backupRecovered, true);
      // A later save repairs the primary from the recovered state.
      await second.add('0xdef', { taskId: 'gk_6', decidedAt: 't', decision: 'REJECT' });
      const repaired = JSON.parse(await readFile(path, 'utf8'));
      assert.equal(repaired.entries['0xabc'].taskId, 'gk_1');
      assert.equal(repaired.entries['0xdef'].taskId, 'gk_6');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('recovers from the backup when the primary is missing but the backup exists', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      const first = new SeenSet(path);
      await first.load();
      await first.add('0xabc', { taskId: 'gk_1', decidedAt: 't', decision: 'APPROVE' });
      await rm(path);

      const second = new SeenSet(path);
      await second.load();
      assert.equal(second.has('0xabc'), true);
      assert.equal(second.degraded, true);
      assert.equal(second.backupRecovered, true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('degrades to empty only when BOTH copies are unusable', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      await writeFile(path, '{bad primary', 'utf8');
      await writeFile(`${path}.bak`, '{bad backup', 'utf8');
      const s = new SeenSet(path);
      await s.load();
      assert.equal(s.degraded, true);
      assert.equal(s.backupRecovered, false);
      assert.equal(s.size, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('heals after a failed save: later adds still write (chain not poisoned)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      const s = new SeenSet(path);
      await s.load();
      // Block writes by making the target path a directory: the
      // atomic rename of the temp file onto a directory fails.
      const blocked = new SeenSet(join(dir, 'blocked'));
      await blocked.load();
      await mkdir(join(dir, 'blocked'));
      await assert.rejects(
        blocked.add('0x1', { taskId: 'gk_7', decidedAt: 't', decision: 'APPROVE' }),
      );
      // Remove the obstruction: the NEXT add must succeed, and its
      // write must persist BOTH records (the failed one included).
      await rm(join(dir, 'blocked'), { recursive: true, force: true });
      await blocked.add('0x2', { taskId: 'gk_8', decidedAt: 't', decision: 'REJECT' });
      const parsed = JSON.parse(await readFile(join(dir, 'blocked'), 'utf8'));
      assert.equal(parsed.entries['0x1'].taskId, 'gk_7');
      assert.equal(parsed.entries['0x2'].taskId, 'gk_8');
      assert.equal(blocked.has('0x1'), true);
      assert.equal(s.size, 0); // untouched instance unaffected
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('a backup write failure does not fail the save (primary is truth)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pegasus-seen-'));
    try {
      const path = join(dir, 'seen-set.json');
      // Make the backup path a directory so the backup rename fails.
      await mkdir(`${path}.bak`);
      const s = new SeenSet(path);
      await s.load();
      await s.add('0x1', { taskId: 'gk_9', decidedAt: 't', decision: 'APPROVE' });
      const parsed = JSON.parse(await readFile(path, 'utf8'));
      assert.equal(parsed.entries['0x1'].taskId, 'gk_9');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
