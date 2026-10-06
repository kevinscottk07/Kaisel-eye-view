/**
 * OSINT proxy: bridges the Kaisel-Crucix intelligence engine into God's Eye
 * View. Crucix runs as its own local service (default http://localhost:3117)
 * and sweeps ~29 open geopolitical, economic and conflict sources; this proxy
 * reads its snapshot server-side so the OSINT view and the globe can render it
 * same-origin, and reports clearly when Crucix is not running.
 *
 * Crucix is a separate (AGPL) service, deliberately not merged into this MIT
 * codebase — only its HTTP output is consumed here.
 *
 * Routes:
 *   GET /api/osint/status → {available, url, ...health} (never throws)
 *   GET /api/osint/data   → the Crucix snapshot, cached briefly; 503
 *                           {error:'crucix_unavailable'} when it is down.
 *
 * @returns {import('vite').Plugin}
 */
export function osintProxy() {
  const DATA_TTL_MS = 60_000;
  const baseUrl = () =>
    String(process.env.CRUCIX_URL || 'http://localhost:3117').replace(
      /\/$/,
      '',
    );

  /** @type {?{at: number, data: object}} */
  let dataCache = null;
  /** @type {?Promise<?object>} */
  let inflight = null;

  async function fetchCrucix(path, timeoutMs) {
    const res = await fetch(`${baseUrl()}${path}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function getData() {
    if (dataCache && Date.now() - dataCache.at < DATA_TTL_MS)
      return dataCache.data;
    if (!inflight) {
      inflight = fetchCrucix('/api/data', 12_000)
        .then((data) => {
          dataCache = { at: Date.now(), data };
          return data;
        })
        .catch((err) => {
          console.warn('[osint] Crucix fetch failed:', err?.message || err);
          return null;
        })
        .finally(() => {
          inflight = null;
        });
    }
    return inflight;
  }

  const sendJson = (res, status, body) => {
    if (res.headersSent) return;
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify(body));
  };

  const install = (middlewares) => {
    middlewares.use('/api/osint', async (req, res, next) => {
      const subPath = String(req.url || '').split('?')[0];
      try {
        if (subPath === '/status') {
          const health = await fetchCrucix('/api/health', 3000).catch(
            () => null,
          );
          sendJson(res, 200, {
            available: Boolean(health),
            url: baseUrl(),
            ...(health || {}),
          });
        } else if (subPath === '/data') {
          const data = await getData();
          if (!data) {
            sendJson(res, 503, { error: 'crucix_unavailable', url: baseUrl() });
            return;
          }
          sendJson(res, 200, data);
        } else {
          next();
        }
      } catch (err) {
        console.warn('[osint] error:', err?.message || err);
        sendJson(res, 500, { error: 'osint proxy error' });
      }
    });
  };

  return {
    name: 'osint-proxy',
    configureServer(server) {
      install(server.middlewares);
    },
    configurePreviewServer(server) {
      install(server.middlewares);
    },
  };
}
