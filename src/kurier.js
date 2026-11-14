/**
 * PEGASUS — Kurier REST client (zkVerify relayer).
 *
 * Flow (per /build + Kurier docs): the circuit VKs are ALREADY registered on
 * mainnet, so PEGASUS submits proofs directly with the registered vk hash
 * and polls the job to Finalized:
 *   POST /submit-proof/{API_KEY}
 *     { proofType: 'groth16', vkRegistered: true,
 *       proofOptions: { library: 'snarkjs', curve: 'bn128' },
 *       proofData: { proof, publicSignals, vk: vkHash } }
 *   GET /job-status/{API_KEY}/{jobId}
 *     statuses: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized
 *     (or Failed; aggregation variants exist when a chainId is provided,
 *     which PEGASUS does not do).
 *
 * Submission discipline: EXACTLY ONE submit attempt per task/turn. A timed-
 * out POST has an ambiguous outcome — the job may already exist — so a
 * blind resubmit could create a duplicate job. Retries apply ONLY to the
 * idempotent job-status GETs, inside the caller's deadline budget.
 *
 * The API key travels in the URL path (Kurier's design). It must never be
 * logged: this client logs job ids and statuses only.
 */
export const KURIER_TERMINAL = Object.freeze({
  FINALIZED: 'Finalized',
  FAILED: 'Failed',
});

export class KurierError extends Error {
  constructor(message, { status = null, retryable = false } = {}) {
    super(message);
    this.name = 'KurierError';
    this.status = status;
    this.retryable = retryable;
  }
}

function isRetryableStatus(status) {
  return status === 429 || status >= 500;
}

export class KurierClient {
  #apiUrl;
  #apiKey;
  #fetch;
  #pollIntervalMs;

  /**
   * @param {object} opts - { apiUrl, apiKey, fetchImpl?, pollIntervalMs? }
   * fetchImpl is injectable for tests; defaults to global fetch.
   */
  constructor({ apiUrl, apiKey, fetchImpl = globalThis.fetch, pollIntervalMs = 5000 }) {
    if (!apiKey) throw new Error('KurierClient requires an API key');
    this.#apiUrl = apiUrl.replace(/\/$/, '');
    this.#apiKey = apiKey;
    this.#fetch = fetchImpl;
    this.#pollIntervalMs = pollIntervalMs;
  }

  async #request(path, { method = 'GET', body = null, timeoutMs = 15_000 } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await this.#fetch(`${this.#apiUrl}${path}`, {
        method,
        headers: body ? { 'content-type': 'application/json' } : {},
        body: body ? JSON.stringify(body) : null,
        signal: controller.signal,
      });
      let data = null;
      try {
        data = await res.json();
      } catch {
        data = null;
      }
      if (!res.ok) {
        throw new KurierError(`Kurier ${method} ${path} failed: HTTP ${res.status}`, {
          status: res.status,
          retryable: isRetryableStatus(res.status),
        });
      }
      return data;
    } catch (err) {
      if (err instanceof KurierError) throw err;
      if (err.name === 'AbortError') {
        throw new KurierError(`Kurier ${method} ${path} timed out after ${timeoutMs}ms`, {
          retryable: true,
        });
      }
      throw new KurierError(`Kurier ${method} ${path} network error: ${err.message}`, {
        retryable: true,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Submit one proof. Single attempt — see module header. Returns the
   * parsed job object ({ jobId, optimisticVerify, ... }).
   */
  async submitProof({ proof, publicSignals, vkHash, timeoutMs = 20_000 }) {
    return this.#request(`/submit-proof/${this.#apiKey}`, {
      method: 'POST',
      timeoutMs,
      body: {
        proofType: 'groth16',
        vkRegistered: true,
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof, publicSignals, vk: vkHash },
      },
    });
  }

  async getJobStatus(jobId, { timeoutMs = 15_000 } = {}) {
    return this.#request(`/job-status/${this.#apiKey}/${jobId}`, { timeoutMs });
  }

  /**
   * Poll a job until it reaches a terminal status or the deadline passes.
   * Transient GET failures are retried inside the budget. Returns
   * { status, job, finalized: boolean, timedOut: boolean }.
   */
  async waitForFinalized(jobId, { deadlineMs, onStatus = null } = {}) {
    const started = Date.now();
    let lastJob = null;
    for (;;) {
      const remaining = deadlineMs - (Date.now() - started);
      if (remaining <= 0) {
        return { status: lastJob?.status ?? null, job: lastJob, finalized: false, timedOut: true };
      }
      try {
        const job = await this.getJobStatus(jobId, {
          timeoutMs: Math.min(15_000, remaining),
        });
        lastJob = job;
        if (onStatus) onStatus(job.status, job);
        if (job.status === KURIER_TERMINAL.FINALIZED) {
          return { status: job.status, job, finalized: true, timedOut: false };
        }
        if (job.status === KURIER_TERMINAL.FAILED) {
          return { status: job.status, job, finalized: false, timedOut: false };
        }
      } catch (err) {
        // Transient read failure: keep polling inside the budget.
        if (onStatus) onStatus('poll_error', { error: err.message });
      }
      const slept = Math.min(
        this.#pollIntervalMs,
        Math.max(0, deadlineMs - (Date.now() - started)),
      );
      if (slept <= 0) {
        return { status: lastJob?.status ?? null, job: lastJob, finalized: false, timedOut: true };
      }
      await new Promise((resolve) => setTimeout(resolve, slept));
    }
  }
}
