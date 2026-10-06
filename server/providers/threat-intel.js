import { createFeedCache, createKeyedCache } from './threat-intel/cache.js';
import {
  loadAttack,
  loadEpss,
  loadFeodo,
  loadKev,
  loadRecentCves,
  loadThreatFox,
  loadUrlhaus,
} from './threat-intel/feeds.js';
import { searchCpes, cvesForCpe } from './threat-intel/nvd.js';
import { assembleExposure } from './threat-intel/exposure.js';
import { generateBrief, generateExposureBrief } from './threat-intel/brief.js';
import { sameSiteGated } from './common/same-site.js';
import { makeCostRateLimiter, clientKey } from './common/rate-limit.js';
import { readRequestBody } from './common/request.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const KEV_WINDOW_DAYS = 180;
const ASSEMBLY_TTL_MS = 5 * MINUTE;
const BRIEF_TTL_MS = 30 * MINUTE;
const ANTHROPIC_DEFAULT_PER_MIN = 10;

const FEEDS = [
  {
    id: 'kev',
    label: 'CISA KEV',
    about: 'Vulnerabilities known to be exploited in the wild',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  },
  {
    id: 'nvd',
    label: 'NVD',
    about: 'Critical and high CVEs published in the last 7 days',
    url: 'https://nvd.nist.gov/',
  },
  {
    id: 'epss',
    label: 'FIRST EPSS',
    about: 'Probability a CVE is exploited in the next 30 days',
    url: 'https://www.first.org/epss/',
  },
  {
    id: 'threatfox',
    label: 'ThreatFox',
    about: 'Recent indicators of compromise',
    url: 'https://threatfox.abuse.ch/',
  },
  {
    id: 'urlhaus',
    label: 'URLhaus',
    about: 'Recent malware-distribution URLs',
    url: 'https://urlhaus.abuse.ch/',
  },
  {
    id: 'feodo',
    label: 'Feodo Tracker',
    about: 'Botnet command-and-control servers',
    url: 'https://feodotracker.abuse.ch/',
  },
  {
    id: 'attack',
    label: 'MITRE ATT&CK',
    about: 'Threat groups, software and techniques',
    url: 'https://attack.mitre.org/',
  },
];

const normalizeName = (value) =>
  String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');

const countBy = (rows, keyOf) => {
  const counts = {};
  for (const row of rows) {
    const key = keyOf(row);
    if (key) counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
};

const topEntries = (counts, limit) =>
  Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([name, count]) => ({ name, count }));

/**
 * Threat-intelligence provider: public vulnerability, indicator and ATT&CK
 * feeds behind one cached API, plus a Claude-written analyst briefing.
 *
 * Routes:
 *   GET  /api/threat-intel/data   → feeds, stats, vulnerabilities, indicators, malware
 *   GET  /api/threat-intel/attack → reduced ATT&CK groups / software / techniques
 *   GET  /api/threat-intel/status → {hasKey}
 *   POST /api/threat-intel/brief  → {text, model, generatedAt} (ANTHROPIC_API_KEY)
 *
 * Every feed is keyless. Without ANTHROPIC_API_KEY the brief route answers
 * 503 {error:'no_key'} and never contacts Anthropic.
 *
 * @returns {import('vite').Plugin}
 */
export function threatIntelProxy() {
  const caches = {
    kev: createFeedCache({ name: 'kev', ttlMs: 6 * HOUR, load: loadKev }),
    nvd: createFeedCache({
      name: 'nvd',
      ttlMs: 3 * HOUR,
      load: () => loadRecentCves({ days: 7 }),
    }),
    threatfox: createFeedCache({
      name: 'threatfox',
      ttlMs: 30 * MINUTE,
      load: loadThreatFox,
    }),
    urlhaus: createFeedCache({
      name: 'urlhaus',
      ttlMs: 30 * MINUTE,
      load: loadUrlhaus,
    }),
    feodo: createFeedCache({ name: 'feodo', ttlMs: HOUR, load: loadFeodo }),
    attack: createFeedCache({
      name: 'attack',
      ttlMs: 7 * DAY,
      load: loadAttack,
    }),
  };
  // EPSS depends on which CVEs are in view, so its loader reads this list.
  let epssIds = [];
  caches.epss = createFeedCache({
    name: 'epss',
    ttlMs: 6 * HOUR,
    load: () => loadEpss(epssIds),
  });

  // Exposure-view lookups vary by device, so they use per-key caches that
  // respect NVD's keyless rate limit across repeated views of an asset.
  const cpeSearchCache = createKeyedCache({
    ttlMs: 6 * HOUR,
    max: 128,
    load: (query) => searchCpes(query, { limit: 20 }),
  });
  const cveByCpeCache = createKeyedCache({
    ttlMs: 6 * HOUR,
    max: 64,
    load: (cpeName) => cvesForCpe(cpeName, { limit: 500 }),
  });
  const exposureCache = createKeyedCache({
    ttlMs: 30 * MINUTE,
    max: 48,
    load: buildExposure,
  });
  /** @type {Map<string, {at: number, body: object}>} */
  const exposureBriefCache = new Map();

  /** @type {?{at: number, payload: object}} */
  let assembled = null;
  /** @type {?Promise<object>} */
  let assembling = null;
  /** @type {?{at: number, body: object}} */
  let briefCache = null;
  let limiter;

  const apiKey = () => String(process.env.ANTHROPIC_API_KEY || '').trim();

  async function assemble() {
    const [kev, nvd, threatfox, urlhaus, feodo, attack] = await Promise.all([
      caches.kev.get(),
      caches.nvd.get(),
      caches.threatfox.get(),
      caches.urlhaus.get(),
      caches.feodo.get(),
      caches.attack.get(),
    ]);
    const now = Date.now();
    const kevEntries = kev.data?.entries || [];
    const kevCutoff = new Date(now - KEV_WINDOW_DAYS * DAY)
      .toISOString()
      .slice(0, 10);

    /** @type {Map<string, object>} */
    const vulns = new Map();
    for (const entry of kevEntries) {
      if (!entry.dateAdded || entry.dateAdded < kevCutoff) continue;
      vulns.set(entry.id, {
        id: entry.id,
        title: entry.name,
        vendor: entry.vendor,
        product: entry.product,
        description: entry.description,
        action: entry.action,
        kev: true,
        kevAdded: entry.dateAdded,
        kevDue: entry.dueDate,
        ransomware: entry.ransomware,
        cwes: entry.cwes,
        published: null,
        cvss: null,
        severity: null,
        vector: null,
      });
    }
    const kevById = new Map(kevEntries.map((entry) => [entry.id, entry]));
    for (const cve of nvd.data || []) {
      const existing = vulns.get(cve.id);
      const inKev = kevById.get(cve.id);
      vulns.set(cve.id, {
        id: cve.id,
        title: existing?.title || inKev?.name || '',
        vendor: existing?.vendor || inKev?.vendor || '',
        product: existing?.product || inKev?.product || '',
        description: cve.description || existing?.description || '',
        action: existing?.action || inKev?.action || '',
        kev: Boolean(inKev),
        kevAdded: inKev?.dateAdded || null,
        kevDue: inKev?.dueDate || null,
        ransomware: Boolean(inKev?.ransomware),
        cwes: cve.cwes.length ? cve.cwes : existing?.cwes || [],
        published: cve.published,
        cvss: cve.cvss,
        severity: cve.severity,
        vector: cve.vector,
      });
    }

    epssIds = [...vulns.keys()].sort();
    const epss = epssIds.length
      ? await caches.epss.get()
      : { data: {}, fetchedAt: null, stale: false, error: null };
    const vulnerabilities = [...vulns.values()].map((vuln) => ({
      ...vuln,
      epss: epss.data?.[vuln.id]?.epss ?? null,
      epssPercentile: epss.data?.[vuln.id]?.percentile ?? null,
    }));
    // Exploited vulnerabilities lead, newest first; the rest follow by how
    // likely and how severe they are.
    const risk = (vuln) => (vuln.epss || 0) * 10 + (vuln.cvss || 0);
    vulnerabilities.sort((a, b) => {
      if (a.kev !== b.kev) return a.kev ? -1 : 1;
      if (a.kev)
        return String(b.kevAdded || '').localeCompare(String(a.kevAdded || ''));
      return risk(b) - risk(a);
    });

    const indicators = [
      ...(threatfox.data || []),
      ...(urlhaus.data || []),
      ...(feodo.data || []),
    ].sort((a, b) =>
      String(b.lastSeen || b.firstSeen || '').localeCompare(
        String(a.lastSeen || a.firstSeen || ''),
      ),
    );

    // Link malware families seen in indicators to ATT&CK software, and through
    // it to the groups known to use that software.
    const softwareByName = new Map();
    for (const item of attack.data?.software || []) {
      softwareByName.set(normalizeName(item.name), item);
      for (const alias of item.aliases) {
        const key = normalizeName(alias);
        if (!softwareByName.has(key)) softwareByName.set(key, item);
      }
    }
    const families = new Map();
    for (const row of indicators) {
      if (!row.malware) continue;
      let family = families.get(row.malware);
      if (!family) {
        const match = softwareByName.get(normalizeName(row.malware)) || null;
        family = {
          name: row.malware,
          count: 0,
          types: {},
          threats: {},
          lastSeen: null,
          attackId: match?.id || null,
          groups: match?.groups || [],
        };
        families.set(row.malware, family);
      }
      family.count += 1;
      family.types[row.type] = (family.types[row.type] || 0) + 1;
      if (row.threat)
        family.threats[row.threat] = (family.threats[row.threat] || 0) + 1;
      const seen = row.lastSeen || row.firstSeen;
      if (seen && (!family.lastSeen || seen > family.lastSeen))
        family.lastSeen = seen;
    }
    const malware = [...families.values()].sort((a, b) => b.count - a.count);

    const timeline = [];
    const kevByDay = countBy(kevEntries, (entry) => entry.dateAdded);
    for (let offset = 29; offset >= 0; offset -= 1) {
      const date = new Date(now - offset * DAY).toISOString().slice(0, 10);
      timeline.push({ date, count: kevByDay[date] || 0 });
    }
    const last30 = new Date(now - 30 * DAY).toISOString().slice(0, 10);
    const nvdRows = nvd.data || [];

    const results = { kev, nvd, epss, threatfox, urlhaus, feodo, attack };
    const counts = {
      kev: kevEntries.length,
      nvd: nvdRows.length,
      epss: Object.keys(epss.data || {}).length,
      threatfox: (threatfox.data || []).length,
      urlhaus: (urlhaus.data || []).length,
      feodo: (feodo.data || []).length,
      attack: attack.data
        ? attack.data.groups.length +
          attack.data.software.length +
          attack.data.techniques.length
        : 0,
    };

    return {
      generatedAt: now,
      feeds: FEEDS.map((feed) => ({
        ...feed,
        count: counts[feed.id],
        fetchedAt: results[feed.id].fetchedAt,
        stale: results[feed.id].stale,
        ok: results[feed.id].data !== null,
      })),
      stats: {
        kevTotal: kevEntries.length,
        kevLast30: kevEntries.filter((entry) => entry.dateAdded >= last30)
          .length,
        kevRansomware: kevEntries.filter((entry) => entry.ransomware).length,
        criticalCves: nvdRows.filter((cve) => cve.severity === 'CRITICAL')
          .length,
        highCves: nvdRows.filter((cve) => cve.severity === 'HIGH').length,
        indicators: indicators.length,
        malwareFamilies: malware.length,
        groups: attack.data?.groups.length || 0,
        techniques: attack.data?.techniques.length || 0,
        attackVersion: attack.data?.version || null,
      },
      kevTimeline: timeline,
      indicatorTypes: topEntries(
        countBy(indicators, (row) => row.type),
        12,
      ),
      threatTypes: topEntries(
        countBy(indicators, (row) => row.threat),
        12,
      ),
      topVendors: topEntries(
        countBy(
          kevEntries.filter((entry) => entry.dateAdded >= kevCutoff),
          (entry) => entry.vendor,
        ),
        10,
      ),
      vulnerabilities,
      indicators,
      malware,
    };
  }

  function getAssembled() {
    if (assembled && Date.now() - assembled.at < ASSEMBLY_TTL_MS)
      return Promise.resolve(assembled.payload);
    if (!assembling) {
      assembling = assemble()
        .then((payload) => {
          assembled = { at: Date.now(), payload };
          return payload;
        })
        .finally(() => {
          assembling = null;
        });
    }
    return assembling;
  }

  /** Compact view of the assembled data, sized for one model request. */
  async function buildSnapshot() {
    const data = await getAssembled();
    const attack = (await caches.attack.get()).data;
    const groupName = new Map(
      (attack?.groups || []).map((group) => [group.id, group.name]),
    );
    const risk = (vuln) =>
      (vuln.kev ? 2 : 0) + (vuln.epss || 0) + (vuln.cvss || 0) / 10;
    return {
      generatedAt: new Date(data.generatedAt).toISOString(),
      stats: data.stats,
      feedsUnavailable: data.feeds
        .filter((feed) => !feed.ok)
        .map((feed) => feed.label),
      recentlyExploited: data.vulnerabilities
        .filter((vuln) => vuln.kev)
        .slice(0, 30)
        .map((vuln) => ({
          id: vuln.id,
          vendor: vuln.vendor,
          product: vuln.product,
          name: vuln.title,
          addedToKev: vuln.kevAdded,
          patchDue: vuln.kevDue,
          ransomware: vuln.ransomware,
          cvss: vuln.cvss,
          epss: vuln.epss,
        })),
      highestRiskNewCves: data.vulnerabilities
        .filter((vuln) => vuln.published)
        .sort((a, b) => risk(b) - risk(a))
        .slice(0, 25)
        .map((vuln) => ({
          id: vuln.id,
          cvss: vuln.cvss,
          epss: vuln.epss,
          inKev: vuln.kev,
          published: vuln.published,
          description: vuln.description.slice(0, 240),
        })),
      activeMalware: data.malware.slice(0, 25).map((family) => ({
        name: family.name,
        indicators: family.count,
        activity: Object.keys(family.threats),
        attackSoftwareId: family.attackId,
        linkedGroups: family.groups
          .map((id) => `${groupName.get(id) || id} (${id})`)
          .slice(0, 8),
      })),
      indicatorTypes: data.indicatorTypes,
      threatTypes: data.threatTypes,
      botnetC2: data.indicators
        .filter((row) => row.source === 'Feodo Tracker')
        .map((row) => ({
          address: row.value,
          malware: row.malware,
          status: row.status,
          country: row.country,
          network: row.asName,
        })),
      mostTargetedVendors: data.topVendors,
    };
  }

  const sendJson = (res, status, body) => {
    if (res.headersSent) return;
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify(body));
  };

  async function handleBrief(req, res) {
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }
    const key = apiKey();
    if (!key) {
      sendJson(res, 503, { error: 'no_key' });
      return;
    }
    let question = null;
    try {
      const body = JSON.parse((await readRequestBody(req, 16 * 1024)) || '{}');
      if (typeof body.question === 'string' && body.question.trim())
        question = body.question.trim().slice(0, 2000);
    } catch {
      sendJson(res, 400, { error: 'Invalid request body' });
      return;
    }
    if (!question && briefCache && Date.now() - briefCache.at < BRIEF_TTL_MS) {
      sendJson(res, 200, { ...briefCache.body, cached: true });
      return;
    }
    // Per-IP throttle (GEV_RATELIMIT_ANTHROPIC_PER_MIN). 0 disables.
    if (limiter === undefined)
      limiter = makeCostRateLimiter(
        process.env.GEV_RATELIMIT_ANTHROPIC_PER_MIN,
        ANTHROPIC_DEFAULT_PER_MIN,
      );
    if (limiter && !limiter(clientKey(req))) {
      res.setHeader('Retry-After', '10');
      sendJson(res, 429, { error: 'Rate limit exceeded' });
      return;
    }
    const snapshot = await buildSnapshot();
    const result = await generateBrief({ apiKey: key, snapshot, question });
    if (!result.ok) {
      sendJson(res, result.status, { error: result.error });
      return;
    }
    const body = {
      text: result.text,
      model: result.model,
      generatedAt: Date.now(),
    };
    if (!question) briefCache = { at: Date.now(), body };
    sendJson(res, 200, body);
  }

  /**
   * Resolve one CPE to its exposure profile. The most severe CVEs (and every
   * exploited one) are analyzed, bounding the EPSS lookups and payload. Wrapped
   * by exposureCache.
   */
  async function buildExposure(cpeName) {
    const [{ total, cves }, kev] = await Promise.all([
      cveByCpeCache.get(cpeName),
      caches.kev.get(),
    ]);
    const kevIds = new Set((kev.data?.entries || []).map((entry) => entry.id));
    const exploited = cves.filter((cve) => kevIds.has(cve.id));
    const rest = cves
      .filter((cve) => !kevIds.has(cve.id))
      .sort(
        (a, b) =>
          (b.cvss || 0) - (a.cvss || 0) ||
          String(b.published || '').localeCompare(String(a.published || '')),
      );
    const analyzed = [...exploited, ...rest].slice(
      0,
      Math.max(300, exploited.length),
    );
    let epss = {};
    try {
      epss = await loadEpss(analyzed.map((cve) => cve.id));
    } catch {
      epss = {};
    }
    return assembleExposure({
      cpeName,
      cves: analyzed,
      epss,
      kevIds,
      totalCves: total,
    });
  }

  /** Compact an exposure profile for one model request. */
  function exposureSnapshot(exposure) {
    return {
      asset: exposure.asset,
      stats: exposure.stats,
      layers: exposure.layers.map((layer) => ({
        layer: layer.n,
        name: layer.name,
        cves: layer.count,
        exploited: layer.kev,
      })),
      topCves: exposure.cves.slice(0, 40).map((cve) => ({
        id: cve.id,
        cvss: cve.cvss,
        severity: cve.severity,
        epss: cve.epss,
        exploited: cve.kev,
        osiLayer: cve.osiLayer,
        cwes: cve.cwes,
        description: cve.description.slice(0, 200),
      })),
      attackPatterns: exposure.chain.patterns.slice(0, 24).map((pattern) => ({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        weaknesses: pattern.matchedCwes,
        techniques: pattern.attack,
      })),
      techniques: exposure.chain.techniqueIds,
      weaknessesWithoutMappedRoute: exposure.chain.uncoveredCwes,
    };
  }

  async function handleExposureBrief(req, res) {
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }
    const key = apiKey();
    if (!key) {
      sendJson(res, 503, { error: 'no_key' });
      return;
    }
    let cpe = '';
    let question = null;
    try {
      const body = JSON.parse((await readRequestBody(req, 16 * 1024)) || '{}');
      cpe = typeof body.cpe === 'string' ? body.cpe.trim() : '';
      if (typeof body.question === 'string' && body.question.trim())
        question = body.question.trim().slice(0, 2000);
    } catch {
      sendJson(res, 400, { error: 'Invalid request body' });
      return;
    }
    if (!cpe.startsWith('cpe:2.3:')) {
      sendJson(res, 400, { error: 'A cpe is required' });
      return;
    }
    const cacheKey = cpe;
    if (
      !question &&
      exposureBriefCache.has(cacheKey) &&
      Date.now() - exposureBriefCache.get(cacheKey).at < BRIEF_TTL_MS
    ) {
      sendJson(res, 200, {
        ...exposureBriefCache.get(cacheKey).body,
        cached: true,
      });
      return;
    }
    if (limiter === undefined)
      limiter = makeCostRateLimiter(
        process.env.GEV_RATELIMIT_ANTHROPIC_PER_MIN,
        ANTHROPIC_DEFAULT_PER_MIN,
      );
    if (limiter && !limiter(clientKey(req))) {
      res.setHeader('Retry-After', '10');
      sendJson(res, 429, { error: 'Rate limit exceeded' });
      return;
    }
    let exposure;
    try {
      exposure = await exposureCache.get(cpe);
    } catch (err) {
      console.warn(
        '[threat-intel] exposure build failed:',
        err?.message || err,
      );
      sendJson(res, 502, { error: 'Could not load this asset from NVD.' });
      return;
    }
    const result = await generateExposureBrief({
      apiKey: key,
      exposure: exposureSnapshot(exposure),
      question,
    });
    if (!result.ok) {
      sendJson(res, result.status, { error: result.error });
      return;
    }
    const body = {
      text: result.text,
      model: result.model,
      generatedAt: Date.now(),
    };
    if (!question) exposureBriefCache.set(cacheKey, { at: Date.now(), body });
    sendJson(res, 200, body);
  }

  const install = (middlewares) => {
    middlewares.use(
      '/api/threat-intel/exposure/brief',
      sameSiteGated(handleExposureBrief),
    );
    middlewares.use('/api/threat-intel/brief', sameSiteGated(handleBrief));
    middlewares.use('/api/threat-intel', async (req, res, next) => {
      try {
        const [subPath, rawQuery = ''] = String(req.url || '').split('?');
        const query = new URLSearchParams(rawQuery);
        if (subPath === '/data') {
          sendJson(res, 200, await getAssembled());
        } else if (subPath === '/exposure/search') {
          const q = (query.get('q') || '').trim();
          if (q.length < 2) {
            sendJson(res, 200, { query: q, results: [] });
            return;
          }
          try {
            const results = await cpeSearchCache.get(q.toLowerCase());
            sendJson(res, 200, { query: q, results });
          } catch (err) {
            console.warn(
              '[threat-intel] cpe search failed:',
              err?.message || err,
            );
            sendJson(res, 502, { error: 'NVD product search is unavailable.' });
          }
        } else if (subPath === '/exposure') {
          const cpe = (query.get('cpe') || '').trim();
          if (!cpe.startsWith('cpe:2.3:')) {
            sendJson(res, 400, { error: 'A cpe query parameter is required.' });
            return;
          }
          try {
            sendJson(res, 200, await exposureCache.get(cpe));
          } catch (err) {
            console.warn(
              '[threat-intel] exposure failed:',
              err?.message || err,
            );
            sendJson(res, 502, {
              error: 'Could not load this asset from NVD.',
            });
          }
        } else if (subPath === '/attack') {
          const attack = await caches.attack.get();
          if (!attack.data) {
            sendJson(res, 502, { error: 'ATT&CK data unavailable' });
            return;
          }
          sendJson(res, 200, {
            fetchedAt: attack.fetchedAt,
            stale: attack.stale,
            ...attack.data,
          });
        } else if (subPath === '/status') {
          sendJson(res, 200, { hasKey: Boolean(apiKey()) });
        } else {
          next();
        }
      } catch (err) {
        console.warn('[threat-intel] error:', err?.message || err);
        sendJson(res, 500, { error: 'threat intel provider error' });
      }
    });
  };

  return {
    name: 'threat-intel-proxy',
    configureServer(server) {
      install(server.middlewares);
    },
    configurePreviewServer(server) {
      install(server.middlewares);
    },
  };
}
