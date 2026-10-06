import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * The bundled CWE→CAPEC→ATT&CK reference map (built by
 * scripts/build-capec-map.mjs). Loaded once, server-side, so the exposure
 * route is assembled without shipping the 400 KB map to the browser.
 */
let map = null;

function load() {
  if (map) return map;
  const url = new URL('./data/capecMap.json', import.meta.url);
  map = JSON.parse(readFileSync(fileURLToPath(url), 'utf8'));
  return map;
}

export function capecVersion() {
  return load().generatedAt || null;
}

/**
 * Walk a set of CWE ids to the attack patterns that abuse them and the ATT&CK
 * techniques those patterns map to — the CVE→CWE→CAPEC→ATT&CK exposure route.
 *
 * @param {string[]} cwes
 * @returns {{
 *   patterns: Array<object>,
 *   techniqueIds: string[],
 *   coveredCwes: string[],
 *   uncoveredCwes: string[],
 * }}
 */
export function chainForCwes(cwes) {
  const data = load();
  const wanted = [...new Set(cwes)].filter((cwe) => /^CWE-\d+$/.test(cwe));
  const patterns = new Map();
  const techniqueIds = new Set();
  const covered = new Set();

  for (const cwe of wanted) {
    const ids = data.cweToCapec[cwe];
    if (!ids || !ids.length) continue;
    covered.add(cwe);
    for (const capecId of ids) {
      const pattern = data.capec[capecId];
      if (!pattern) continue;
      let entry = patterns.get(capecId);
      if (!entry) {
        entry = { ...pattern, matchedCwes: [] };
        patterns.set(capecId, entry);
      }
      entry.matchedCwes.push(cwe);
      for (const technique of pattern.attack) techniqueIds.add(technique);
    }
  }

  const severityRank = {
    'Very High': 5,
    High: 4,
    Medium: 3,
    Low: 2,
    'Very Low': 1,
  };
  const ordered = [...patterns.values()].sort(
    (a, b) =>
      b.matchedCwes.length - a.matchedCwes.length ||
      (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0) ||
      b.attack.length - a.attack.length,
  );

  return {
    patterns: ordered,
    techniqueIds: [...techniqueIds],
    coveredCwes: [...covered],
    uncoveredCwes: wanted.filter((cwe) => !covered.has(cwe)),
  };
}
