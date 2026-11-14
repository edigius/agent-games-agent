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
 * A corrupt or unreadable file degrades to an empty set with a loud error
 * log: staying online (risking a replay miss) beats refusing to start
 * (guaranteed timeouts). The health endpoint reports this degraded state.
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const FILE_VERSION = 1;

export class SeenSet {
  #path;
  #entries = new Map(); // proof_tx -> { taskId, decidedAt, decision }
  #degraded = false;
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

  async load() {
    let raw;
    try {
      raw = await readFile(this.#path, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return this; // first run: nothing seen yet
      this.#degraded = true;
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'seen_set_read_failed',
          error: err.message,
        }),
      );
      return this;
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed.version !== FILE_VERSION || typeof parsed.entries !== 'object') {
        throw new Error('unexpected seen-set file shape');
      }
      for (const [key, value] of Object.entries(parsed.entries)) {
        this.#entries.set(key, value);
      }
    } catch (err) {
      this.#degraded = true;
      this.#entries.clear();
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'seen_set_corrupt',
          error: err.message,
        }),
      );
    }
    return this;
  }

  has(proofTx) {
    return this.#entries.has(proofTx);
  }

  /**
   * Record a decided task. Writes are serialized through a promise chain
   * and are atomic on disk. Callers SHOULD await this before responding so
   * a crash after the response cannot lose the record.
   */
  add(proofTx, record) {
    this.#entries.set(proofTx, record);
    this.#saveChain = this.#saveChain.then(() => this.#save());
    return this.#saveChain;
  }

  async #save() {
    const payload = JSON.stringify({
      version: FILE_VERSION,
      entries: Object.fromEntries(this.#entries),
    });
    const tmpPath = `${this.#path}.tmp`;
    await mkdir(dirname(this.#path), { recursive: true });
    await writeFile(tmpPath, payload, 'utf8');
    await rename(tmpPath, this.#path);
  }

  async flush() {
    await this.#saveChain;
  }
}
