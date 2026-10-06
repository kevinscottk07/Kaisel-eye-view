/**
 * Threat-intel data for the workspace: one fetch of the feed data and one of
 * the ATT&CK knowledge base, indexed so any entity can reach its neighbours.
 */

async function getJson(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const EMPTY_ATTACK = Object.freeze({
  version: null,
  tactics: [],
  groups: [],
  software: [],
  techniques: [],
});

/** Build lookup maps over the two payloads. */
export function buildIndex(data, attack) {
  const kb = attack || EMPTY_ATTACK;
  const index = {
    data,
    attack: kb,
    vulnById: new Map(data.vulnerabilities.map((v) => [v.id, v])),
    indicatorById: new Map(data.indicators.map((i) => [i.id, i])),
    malwareByName: new Map(data.malware.map((m) => [m.name, m])),
    groupById: new Map(kb.groups.map((g) => [g.id, g])),
    softwareById: new Map(kb.software.map((s) => [s.id, s])),
    techniqueById: new Map(kb.techniques.map((t) => [t.id, t])),
    /** Group id → malware families currently seen in indicators. */
    activeGroups: new Map(),
    /** ATT&CK software id → the malware family seen in indicators. */
    activeSoftware: new Map(),
  };
  for (const family of data.malware) {
    if (family.attackId) index.activeSoftware.set(family.attackId, family);
    for (const groupId of family.groups) {
      const list = index.activeGroups.get(groupId) || [];
      list.push(family.name);
      index.activeGroups.set(groupId, list);
    }
  }
  return index;
}

/** Load both payloads. ATT&CK is optional: the rest works without it. */
export async function loadThreatIntel() {
  const [data, attack] = await Promise.all([
    getJson('/api/threat-intel/data'),
    getJson('/api/threat-intel/attack').catch(() => null),
  ]);
  return buildIndex(data, attack);
}

export async function analystStatus() {
  try {
    return await getJson('/api/threat-intel/status');
  } catch {
    return { hasKey: false };
  }
}

/**
 * Ask the analyst. Resolves to {text, model, generatedAt} or throws an Error
 * whose `code` is `no_key` when no Anthropic key is configured.
 */
export async function askAnalyst(question) {
  const res = await fetch('/api/threat-intel/brief', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(question ? { question } : {}),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = new Error(
      body.error === 'no_key'
        ? 'No Anthropic API key is configured.'
        : body.error || `Request failed (HTTP ${res.status}).`,
    );
    error.code = body.error === 'no_key' ? 'no_key' : 'failed';
    throw error;
  }
  return body;
}

/** Resolve a free-text device/software query to candidate CPEs. */
export async function searchDevices(query) {
  const body = await getJson(
    `/api/threat-intel/exposure/search?q=${encodeURIComponent(query)}`,
  );
  return body.results || [];
}

/** Load one asset's exposure profile by CPE. */
export async function loadExposure(cpe) {
  return getJson(`/api/threat-intel/exposure?cpe=${encodeURIComponent(cpe)}`);
}

/**
 * Ask Claude to triage an asset's exposure. Resolves to
 * {text, model, generatedAt} or throws an Error whose `code` is `no_key`.
 */
export async function askExposureAnalyst(cpe, question) {
  const res = await fetch('/api/threat-intel/exposure/brief', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(question ? { cpe, question } : { cpe }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = new Error(
      body.error === 'no_key'
        ? 'No Anthropic API key is configured.'
        : body.error || `Request failed (HTTP ${res.status}).`,
    );
    error.code = body.error === 'no_key' ? 'no_key' : 'failed';
    throw error;
  }
  return body;
}

const matches = (needle, ...fields) =>
  fields.some((field) =>
    String(field || '')
      .toLowerCase()
      .includes(needle),
  );

/** Search every entity kind; returns at most `limit` hits per kind. */
export function searchAll(index, query, limit = 6) {
  const needle = String(query || '')
    .trim()
    .toLowerCase();
  if (needle.length < 2) return [];
  const hits = [];
  const take = (kind, rows, test, label, detail) => {
    let count = 0;
    for (const row of rows) {
      if (count >= limit) break;
      if (!test(row)) continue;
      hits.push({
        kind,
        id: row.id ?? row.name,
        label: label(row),
        detail: detail(row),
      });
      count += 1;
    }
  };
  take(
    'vuln',
    index.data.vulnerabilities,
    (v) => matches(needle, v.id, v.vendor, v.product, v.title),
    (v) => v.id,
    (v) =>
      [v.vendor, v.product].filter(Boolean).join(' ') ||
      v.description.slice(0, 80),
  );
  take(
    'group',
    index.attack.groups,
    (g) => matches(needle, g.id, g.name, ...g.aliases),
    (g) => g.name,
    (g) => g.aliases.slice(0, 3).join(', ') || g.id,
  );
  take(
    'malware',
    index.data.malware,
    (m) => matches(needle, m.name),
    (m) => m.name,
    (m) => `${m.count} indicators`,
  );
  take(
    'software',
    index.attack.software,
    (s) => matches(needle, s.id, s.name, ...s.aliases),
    (s) => s.name,
    (s) => `${s.kind} · ${s.id}`,
  );
  take(
    'technique',
    index.attack.techniques,
    (t) => matches(needle, t.id, t.name),
    (t) => `${t.id} ${t.name}`,
    (t) => t.tactics.join(', '),
  );
  take(
    'indicator',
    index.data.indicators,
    (i) => matches(needle, i.value, i.malware, ...i.tags),
    (i) => i.value,
    (i) => [i.type, i.malware].filter(Boolean).join(' · '),
  );
  return hits;
}
