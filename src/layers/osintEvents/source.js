import { normalizeOsintGeo } from './records.js';

const DATA_URL = '/api/osint/data';

/**
 * Snapshot source for the OSINT events globe layer. Reads the same-origin
 * Crucix proxy. When Crucix is not running the proxy answers 503; the layer
 * then shows nothing rather than surfacing an error.
 */
export function createOsintEventsSource({
  fetchImpl = (...args) => globalThis.fetch(...args),
} = {}) {
  return {
    async getSnapshot({ signal } = {}) {
      signal?.throwIfAborted();
      const response = await fetchImpl(DATA_URL, {
        signal,
        headers: { Accept: 'application/json' },
      });
      if (response.status === 503) return [];
      if (!response.ok) throw new Error(`OSINT HTTP ${response.status}`);
      const payload = await response.json();
      signal?.throwIfAborted();
      return normalizeOsintGeo(payload);
    },
  };
}
