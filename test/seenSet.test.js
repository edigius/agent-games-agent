import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
});
