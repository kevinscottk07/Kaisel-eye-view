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
