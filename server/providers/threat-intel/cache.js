import path from 'node:path';
import { promises as fsp } from 'node:fs';

const CACHE_DIR = path.join(process.cwd(), '.gev-cache', 'threat-intel');

/**
 * Memory + disk cache for one upstream feed. Concurrent callers share one
 * refresh, a fresh-enough disk entry prevents any upstream fetch across
 * dev-server restarts, and a failed refresh serves the previous entry as
 * stale rather than nothing. Pattern mirrors the FIRMS proxy.
 *
 * @template T
 * @param {{name: string, ttlMs: number, load: () => Promise<T>}} options
 * @returns {{get: () => Promise<{data: ?T, fetchedAt: ?number, stale: boolean, error: ?string}>}}
 */
export function createFeedCache({ name, ttlMs, load }) {
  const diskPath = path.join(CACHE_DIR, `${name}.json`);
  /** @type {?{at: number, data: T}} */
  let mem = null;
  let diskChecked = false;
  /** @type {?Promise<?{at: number, data: T}>} */
  let inflight = null;
  let lastError = null;

  async function readDiskOnce() {
    if (diskChecked) return;
    diskChecked = true;
    try {
      const parsed = JSON.parse(await fsp.readFile(diskPath, 'utf8'));
      if (Number.isFinite(parsed?.at) && parsed.data !== undefined)
        mem = parsed;
    } catch {
      /* no disk cache yet */
    }
  }

  async function writeDisk(entry) {
    try {
      await fsp.mkdir(CACHE_DIR, { recursive: true });
      await fsp.writeFile(diskPath, JSON.stringify(entry), 'utf8');
    } catch (err) {
      console.warn(
        `[threat-intel] ${name} cache write failed:`,
        err?.message || err,
      );
    }
  }

  async function get() {
    await readDiskOnce();
    const entry = mem;
    if (entry && Date.now() - entry.at < ttlMs) {
      return {
        data: entry.data,
        fetchedAt: entry.at,
        stale: false,
        error: null,
      };
    }
    if (!inflight) {
      inflight = load()
        .then(async (data) => {
          const fresh = { at: Date.now(), data };
          mem = fresh;
          lastError = null;
          await writeDisk(fresh);
          return fresh;
        })
        .catch((err) => {
          lastError = String(err?.message || err);
          console.warn(`[threat-intel] ${name} refresh failed: ${lastError}`);
          return null;
        })
        .finally(() => {
          inflight = null;
        });
    }
    const fresh = await inflight;
    if (fresh)
      return {
        data: fresh.data,
        fetchedAt: fresh.at,
        stale: false,
        error: null,
      };
    if (entry)
      return {
        data: entry.data,
        fetchedAt: entry.at,
        stale: true,
        error: lastError,
      };
    return { data: null, fetchedAt: null, stale: false, error: lastError };
  }

  return { get };
}

/**
 * Per-key in-memory cache with single-flight loading and a bounded size, for
 * lookups that vary by argument (a device's CPEs, a CPE's CVEs). A failed load
 * rejects and is not cached. Oldest entries are evicted past `max`.
 *
 * @template T
 * @param {{ ttlMs: number, max?: number, load: (key: string) => Promise<T> }} options
 * @returns {{ get: (key: string) => Promise<T> }}
 */
export function createKeyedCache({ ttlMs, max = 64, load }) {
  /** @type {Map<string, {at: number, data: T}>} */
  const entries = new Map();
  /** @type {Map<string, Promise<T>>} */
  const inflight = new Map();

  async function get(key) {
    const hit = entries.get(key);
    if (hit && Date.now() - hit.at < ttlMs) {
      // Refresh LRU order.
      entries.delete(key);
      entries.set(key, hit);
      return hit.data;
    }
    const pending = inflight.get(key);
    if (pending) return pending;
    const promise = Promise.resolve(load(key))
      .then((data) => {
        entries.set(key, { at: Date.now(), data });
        while (entries.size > max) {
          const oldest = entries.keys().next().value;
          entries.delete(oldest);
        }
        return data;
      })
      .finally(() => {
        inflight.delete(key);
      });
    inflight.set(key, promise);
    return promise;
  }

  return { get };
}
