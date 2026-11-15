/**
 * PEGASUS — persistent seen-set for Gatekeeper proof references.
 *
 * PROOF_REUSED detection must survive restarts and redeploys: an in-memory
 * set forgets every proof it has seen, and a forgotten replay is a wrong
 * APPROVE (-6). State lives in a JSON file written atomically (temp file +
 * rename) so a crash mid-write never corrupts it. On Fly.io the file must
 * live on a persistent volume (see fly.toml / README) — the container
 * filesystem alone does not survive redeploys.
 *
 * SECOND COPY: every save also writes `${path}.bak` (same payload, same
 * atomic tmp+rename, after the primary). On load, a missing/unreadable or
 * corrupt primary falls back to the backup; a recovery from backup sets
 * the degraded flag (the backup can lag the primary by one save) and is
 * reported on the health endpoint via `backupRecovered`. A backup write
 * failure never fails the save itself — the primary is the source of
 * truth — but it is logged loudly. Only when BOTH copies are unusable
 * does the set degrade to empty.
 *
 * A corrupt or unreadable file degrades to an empty set with a loud error
 * log: staying online (risking a replay miss) beats refusing to start
 * (guaranteed timeouts). The health endpoint reports this degraded state.
 *
 * Save-chain healing: writes serialize through a promise chain, and the
 * chain CONTINUES after a failed save — one failed write must never
 * poison all later saves. add() still rejects for the failed save itself
 * so the caller logs it, but the next add() attempts a fresh write, and
 * that write persists the full in-memory map (including records from
 * failed saves), so the disk state self-heals.
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const FILE_VERSION = 1;

export class SeenSet {
  #path;
  #entries = new Map(); // proof_tx -> { taskId, decidedAt, decision }
  #degraded = false;
  #backupRecovered = false;
  #saveChain = Promise.resolve();

  constructor(path) {
    this.#path = path;
  }

  get size() {
    return this.#entries.size;
  }

  get degraded() {
    return this.#degraded;
  }

  get backupRecovered() {
    return this.#backupRecovered;
  }

  get #backupPath() {
    return `${this.#path}.bak`;
  }

  // Read + parse one copy. Returns { ok, entries?, missing?, kind?,
  // error? } — never throws, so load() can fall through to the backup
  // copy. kind is 'read' (unreadable file) or 'parse' (bad JSON/shape).
  async #readEntries(path) {
    let raw;
    try {
      raw = await readFile(path, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return { ok: false, missing: true, error: err };
      return { ok: false, missing: false, kind: 'read', error: err };
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed.version !== FILE_VERSION || typeof parsed.entries !== 'object') {
        throw new Error('unexpected seen-set file shape');
      }
      return { ok: true, entries: new Map(Object.entries(parsed.entries)) };
    } catch (err) {
      return { ok: false, missing: false, kind: 'parse', error: err };
    }
  }

  #logError(event, error) {
    console.error(JSON.stringify({ level: 'error', event, error: error.message }));
  }

  async load() {
    const primary = await this.#readEntries(this.#path);
    if (primary.ok) {
      this.#entries = primary.entries;
      return this;
    }
    // First run: neither copy exists. Empty set, NOT degraded.
    const backup = await this.#readEntries(this.#backupPath);
    if (primary.missing && backup.missing) return this;

    // A missing primary is not itself an error (first run with a stale
    // backup); unreadable/corrupt primaries keep their original events.
    if (!primary.missing) {
      this.#logError(
        primary.kind === 'read' ? 'seen_set_read_failed' : 'seen_set_corrupt',
        primary.error,
      );
    }
    if (backup.ok) {
      this.#entries = backup.entries;
      this.#degraded = true;
      this.#backupRecovered = true;
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'seen_set_recovered_from_backup',
          entries: this.#entries.size,
        }),
      );
      return this;
    }
    // Both copies unusable: degrade to empty, stay online.
    this.#degraded = true;
    this.#entries.clear();
    if (!backup.missing) this.#logError('seen_set_backup_unusable', backup.error);
    return this;
  }

  has(proofTx) {
    return this.#entries.has(proofTx);
  }

  /**
   * Record a decided task. Writes are serialized through a promise chain
   * and are atomic on disk. Callers SHOULD await this before responding so
   * a crash after the response cannot lose the record. A failed save
   * rejects this call (so the caller logs it) but does NOT poison the
   * chain: later adds still attempt their writes.
   */
  add(proofTx, record) {
    this.#entries.set(proofTx, record);
    const attempt = this.#saveChain.then(
      () => this.#save(),
      () => this.#save(),
    );
    // The stored chain always resolves, so a rejection can never wedge
    // later saves; the returned promise still rejects for THIS save.
    this.#saveChain = attempt.catch(() => {});
    return attempt;
  }

  async #writeAtomic(path, payload) {
    const tmpPath = `${path}.tmp`;
    await mkdir(dirname(path), { recursive: true });
    await writeFile(tmpPath, payload, 'utf8');
    await rename(tmpPath, path);
  }

  async #save() {
    const payload = JSON.stringify({
      version: FILE_VERSION,
      entries: Object.fromEntries(this.#entries),
    });
    await this.#writeAtomic(this.#path, payload);
    // Second copy. A backup failure must not fail the save: the primary
    // already holds the record. Loud log only.
    try {
      await this.#writeAtomic(this.#backupPath, payload);
    } catch (err) {
      this.#logError('seen_set_backup_failed', err);
    }
  }

  async flush() {
    await this.#saveChain;
  }
}
