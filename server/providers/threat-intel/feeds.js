/**
 * Keyless public threat-intelligence feeds, normalized to small records.
 * Every loader throws on an upstream failure so the feed cache can serve the
 * previous entry instead.
 */

const USER_AGENT = 'gods-eye-view threat-intel (local dashboard)';

export async function fetchJson(
  url,
  { timeoutMs = 60_000, headers = {} } = {},
) {
  const res = await fetch(url, {
    headers: {
      'User-Agent': USER_AGENT,
      Accept: 'application/json',
      ...headers,
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const clip = (value, max) => {
  const text = String(value ?? '').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
};

/** ATT&CK prose → plain text: drop citations, unwrap markdown links and tags. */
function plainText(value) {
  return String(value ?? '')
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/<\/?[a-z][^>]*>/gi, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/ ([.,;])/g, '$1')
    .trim();
}

/** `2026-10-06 01:22:39 UTC` / `2026-10-06 01:22:39` → ISO, or null. */
function toIso(value) {
  if (!value) return null;
  const text = String(value).replace(' UTC', '').trim();
  const date = new Date(
    /T/.test(text)
      ? text
      : `${text.replace(' ', 'T')}${text.length > 10 ? 'Z' : ''}`,
  );
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** CISA Known Exploited Vulnerabilities — the full catalog (~1.8 MB). */
export async function loadKev() {
  const body = await fetchJson(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  );
  if (!Array.isArray(body?.vulnerabilities))
    throw new Error('unexpected KEV payload');
  return {
    catalogVersion: body.catalogVersion || null,
    entries: body.vulnerabilities.map((v) => ({
      id: v.cveID,
      vendor: v.vendorProject || '',
      product: v.product || '',
      name: v.vulnerabilityName || '',
      description: clip(v.shortDescription, 600),
      action: clip(v.requiredAction, 400),
      dateAdded: v.dateAdded || null,
      dueDate: v.dueDate || null,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
      cwes: Array.isArray(v.cwes) ? v.cwes : [],
    })),
  };
}

function nvdTimestamp(date) {
  return date.toISOString().replace('Z', '');
}

export function normalizeNvdCve(cve) {
  const metric =
    cve.metrics?.cvssMetricV31?.[0] ||
    cve.metrics?.cvssMetricV30?.[0] ||
    cve.metrics?.cvssMetricV40?.[0] ||
    null;
  const description =
    cve.descriptions?.find((d) => d.lang === 'en')?.value || '';
  const cwes = (cve.weaknesses || [])
    .flatMap((w) => w.description || [])
    .map((d) => d.value)
    .filter((value) => /^CWE-\d+$/.test(value));
  return {
    id: cve.id,
    published: cve.published ? `${cve.published}Z` : null,
    status: cve.vulnStatus || '',
    description: clip(description, 600),
    cvss: Number.isFinite(metric?.cvssData?.baseScore)
      ? metric.cvssData.baseScore
      : null,
    severity: metric?.cvssData?.baseSeverity || null,
    vector: metric?.cvssData?.vectorString || null,
    cwes: [...new Set(cwes)],
  };
}

/**
 * NVD: CRITICAL and HIGH CVEs published in the trailing `days`. Keyless NVD
 * allows 5 requests / 30 s, so the two severities are fetched sequentially.
 * NVD_API_KEY (optional) raises that allowance.
 */
export async function loadRecentCves({ days = 7 } = {}) {
  const end = new Date();
  const start = new Date(end.getTime() - days * 86_400_000);
  const key = String(process.env.NVD_API_KEY || '').trim();
  const out = [];
  for (const severity of ['CRITICAL', 'HIGH']) {
    const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    url.searchParams.set('resultsPerPage', '400');
    url.searchParams.set('cvssV3Severity', severity);
    url.searchParams.set('pubStartDate', nvdTimestamp(start));
    url.searchParams.set('pubEndDate', nvdTimestamp(end));
    const body = await fetchJson(url, {
      headers: key ? { apiKey: key } : {},
    });
    for (const item of body?.vulnerabilities || []) {
      if (item?.cve?.id) out.push(normalizeNvdCve(item.cve));
    }
  }
  return out;
}

/** FIRST EPSS exploit-probability scores for a list of CVE ids. */
export async function loadEpss(cveIds) {
  const scores = {};
  for (let i = 0; i < cveIds.length; i += 80) {
    const chunk = cveIds.slice(i, i + 80);
    const body = await fetchJson(
      `https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`,
      { timeoutMs: 30_000 },
    );
    for (const row of body?.data || []) {
      scores[row.cve] = {
        epss: Number(row.epss),
        percentile: Number(row.percentile),
      };
    }
  }
  return scores;
}

/** abuse.ch ThreatFox — recent indicators of compromise, newest first. */
export async function loadThreatFox({ limit = 1500 } = {}) {
  const body = await fetchJson(
    'https://threatfox.abuse.ch/export/json/recent/',
  );
  const rows = [];
  for (const [id, group] of Object.entries(body || {})) {
    for (const ioc of Array.isArray(group) ? group : []) {
      rows.push({
        id: `threatfox:${id}`,
        source: 'ThreatFox',
        type: ioc.ioc_type || 'unknown',
        value: ioc.ioc_value || '',
        threat: ioc.threat_type || '',
        malware: ioc.malware_printable || '',
        malwareKey: ioc.malware || '',
        confidence: Number.isFinite(ioc.confidence_level)
          ? ioc.confidence_level
          : null,
        firstSeen: toIso(ioc.first_seen_utc),
        lastSeen: toIso(ioc.last_seen_utc),
        tags: String(ioc.tags || '')
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean),
        reference: `https://threatfox.abuse.ch/ioc/${id}/`,
      });
    }
  }
  rows.sort((a, b) =>
    String(b.lastSeen || b.firstSeen).localeCompare(
      String(a.lastSeen || a.firstSeen),
    ),
  );
  return rows.slice(0, limit);
}

/** abuse.ch URLhaus — recent malware-distribution URLs, newest first. */
export async function loadUrlhaus({ limit = 1000 } = {}) {
  const body = await fetchJson(
    'https://urlhaus.abuse.ch/downloads/json_recent/',
  );
  const rows = [];
  for (const [id, group] of Object.entries(body || {})) {
    for (const entry of Array.isArray(group) ? group : []) {
      rows.push({
        id: `urlhaus:${id}`,
        source: 'URLhaus',
        type: 'url',
        value: entry.url || '',
        threat: entry.threat || '',
        malware: '',
        malwareKey: '',
        confidence: null,
        status: entry.url_status || '',
        firstSeen: toIso(entry.dateadded),
        lastSeen: toIso(entry.last_online),
        tags: Array.isArray(entry.tags) ? entry.tags : [],
        reference: entry.urlhaus_link || '',
      });
    }
  }
  rows.sort((a, b) => String(b.firstSeen).localeCompare(String(a.firstSeen)));
  return rows.slice(0, limit);
}

/** abuse.ch Feodo Tracker — botnet command-and-control servers. */
export async function loadFeodo() {
  const body = await fetchJson(
    'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  );
  if (!Array.isArray(body)) throw new Error('unexpected Feodo payload');
  return body.map((row) => ({
    id: `feodo:${row.ip_address}:${row.port}`,
    source: 'Feodo Tracker',
    type: 'ip:port',
    value: `${row.ip_address}:${row.port}`,
    threat: 'botnet_cc',
    malware: row.malware || '',
    malwareKey: '',
    confidence: null,
    status: row.status || '',
    country: row.country || null,
    asName: row.as_name || null,
    firstSeen: toIso(row.first_seen),
    lastSeen: toIso(row.last_online),
    tags: [],
    reference: `https://feodotracker.abuse.ch/browse/host/${row.ip_address}/`,
  }));
}

const externalId = (object, source = 'mitre-attack') =>
  object.external_references?.find((ref) => ref.source_name === source)
    ?.external_id || null;

const attackUrl = (object) =>
  object.external_references?.find((ref) => ref.source_name === 'mitre-attack')
    ?.url || null;

/**
 * MITRE ATT&CK Enterprise, reduced from the ~45 MB STIX bundle to the groups,
 * software and techniques plus the "uses" relationships between them.
 */
export async function loadAttack() {
  const bundle = await fetchJson(
    'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    { timeoutMs: 180_000 },
  );
  if (!Array.isArray(bundle?.objects))
    throw new Error('unexpected ATT&CK payload');
  const live = (object) => !object.revoked && !object.x_mitre_deprecated;
  const byStixId = new Map();
  // ATT&CK v17 detection model: a detection-strategy `detects` a technique and
  // points at analytics, each of which names concrete log sources.
  const detectionStrategies = new Map();
  const analytics = new Map();
  const groups = [];
  const software = [];
  const techniques = [];
  const tactics = [];
  let version = null;

  for (const object of bundle.objects) {
    if (object.type === 'x-mitre-collection') version = object.x_mitre_version;
    if (!live(object)) continue;
    if (object.type === 'intrusion-set') {
      const entry = {
        id: externalId(object),
        name: object.name,
        aliases: (object.aliases || []).filter(
          (alias) => alias !== object.name,
        ),
        description: clip(plainText(object.description), 900),
        url: attackUrl(object),
        modified: object.modified || null,
        techniques: [],
        software: [],
      };
      if (entry.id) {
        groups.push(entry);
        byStixId.set(object.id, { kind: 'group', entry });
      }
    } else if (object.type === 'malware' || object.type === 'tool') {
      const entry = {
        id: externalId(object),
        name: object.name,
        kind: object.type,
        aliases: (object.x_mitre_aliases || []).filter(
          (alias) => alias !== object.name,
        ),
        platforms: object.x_mitre_platforms || [],
        description: clip(plainText(object.description), 700),
        url: attackUrl(object),
        techniques: [],
        groups: [],
      };
      if (entry.id) {
        software.push(entry);
        byStixId.set(object.id, { kind: 'software', entry });
      }
    } else if (object.type === 'attack-pattern') {
      const entry = {
        id: externalId(object),
        name: object.name,
        tactics: (object.kill_chain_phases || [])
          .filter((phase) => phase.kill_chain_name === 'mitre-attack')
          .map((phase) => phase.phase_name),
        subtechnique: Boolean(object.x_mitre_is_subtechnique),
        platforms: object.x_mitre_platforms || [],
        description: clip(plainText(object.description), 500),
        detectionStrategies: [],
        telemetry: [],
        url: attackUrl(object),
        groups: [],
        software: [],
        mitigations: [],
      };
      if (entry.id) {
        techniques.push(entry);
        byStixId.set(object.id, { kind: 'technique', entry });
      }
    } else if (object.type === 'course-of-action') {
      // ATT&CK mitigations — the defensive counterpart to a technique.
      const entry = {
        id: externalId(object),
        name: object.name,
        description: clip(plainText(object.description), 300),
        url: attackUrl(object),
      };
      if (entry.id) byStixId.set(object.id, { kind: 'mitigation', entry });
    } else if (object.type === 'x-mitre-detection-strategy') {
      detectionStrategies.set(object.id, {
        name: object.name,
        analyticRefs: object.x_mitre_analytic_refs || [],
      });
    } else if (object.type === 'x-mitre-analytic') {
      analytics.set(
        object.id,
        (object.x_mitre_log_source_references || [])
          .map((ref) => ref.name)
          .filter(Boolean),
      );
    } else if (object.type === 'x-mitre-tactic') {
      tactics.push({
        id: externalId(object),
        key: object.x_mitre_shortname,
        name: object.name,
      });
    }
  }

  for (const object of bundle.objects) {
    if (object.type !== 'relationship' || !live(object)) continue;
    const source = byStixId.get(object.source_ref);
    const target = byStixId.get(object.target_ref);
    if (!source || !target) continue;
    if (object.relationship_type === 'uses') {
      if (source.kind === 'group' && target.kind === 'technique') {
        source.entry.techniques.push(target.entry.id);
        target.entry.groups.push(source.entry.id);
      } else if (source.kind === 'group' && target.kind === 'software') {
        source.entry.software.push(target.entry.id);
        target.entry.groups.push(source.entry.id);
      } else if (source.kind === 'software' && target.kind === 'technique') {
        source.entry.techniques.push(target.entry.id);
        target.entry.software.push(source.entry.id);
      }
    } else if (
      object.relationship_type === 'mitigates' &&
      source.kind === 'mitigation' &&
      target.kind === 'technique'
    ) {
      target.entry.mitigations.push({
        id: source.entry.id,
        name: source.entry.name,
      });
    }
  }

  // `detects` links a detection strategy to the technique it surfaces. Record
  // the strategy name and the concrete log sources from its analytics — what a
  // defender collects to catch the technique.
  for (const object of bundle.objects) {
    if (
      object.type !== 'relationship' ||
      object.relationship_type !== 'detects' ||
      !live(object)
    )
      continue;
    const strategy = detectionStrategies.get(object.source_ref);
    const target = byStixId.get(object.target_ref);
    if (!strategy || !target || target.kind !== 'technique') continue;
    if (
      strategy.name &&
      !target.entry.detectionStrategies.includes(strategy.name)
    )
      target.entry.detectionStrategies.push(strategy.name);
    for (const analyticRef of strategy.analyticRefs) {
      for (const logSource of analytics.get(analyticRef) || []) {
        if (
          target.entry.telemetry.length < 16 &&
          !target.entry.telemetry.includes(logSource)
        )
          target.entry.telemetry.push(logSource);
      }
    }
  }

  // Kill-chain order as published by ATT&CK Enterprise.
  const order = [
    'reconnaissance',
    'resource-development',
    'initial-access',
    'execution',
    'persistence',
    'privilege-escalation',
    'defense-evasion',
    'credential-access',
    'discovery',
    'lateral-movement',
    'collection',
    'command-and-control',
    'exfiltration',
    'impact',
  ];
  tactics.sort((a, b) => {
    const ia = order.indexOf(a.key);
    const ib = order.indexOf(b.key);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });
  const byName = (a, b) => a.name.localeCompare(b.name);
  return {
    version,
    tactics,
    groups: groups.sort(byName),
    software: software.sort(byName),
    techniques: techniques.sort((a, b) => a.id.localeCompare(b.id)),
  };
}
