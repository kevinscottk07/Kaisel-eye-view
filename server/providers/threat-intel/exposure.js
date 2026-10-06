import { parseCpe } from './nvd.js';
import { chainForCwes, capecVersion } from './capec.js';
import { OSI_LAYERS, osiLayerForCve } from './osi.js';

const MAX_CVES_RETURNED = 200;
const MAX_PATTERNS_RETURNED = 48;
const MAX_LAYER_CVES = 12;

/** Risk ordering for the exposure list: exploited first, then likelihood, then severity. */
function riskScore(cve) {
  return (cve.kev ? 100 : 0) + (cve.epss || 0) * 20 + (cve.cvss || 0);
}

/**
 * Assemble an asset's exposure from already-fetched data. Pure except for the
 * bundled CAPEC map read, so the aggregation, OSI placement and chain building
 * are unit-testable.
 *
 * @param {object} args
 * @param {string} args.cpeName - The CPE the CVEs were resolved for.
 * @param {Array<object>} args.cves - normalizeNvdCve rows.
 * @param {Record<string, {epss:number, percentile:number}>} [args.epss]
 * @param {Set<string>} [args.kevIds] - CVE ids known to be exploited.
 * @param {number} [args.totalCves] - NVD's total, when the fetch was capped.
 * @returns {object}
 */
export function assembleExposure({
  cpeName,
  cves,
  epss = {},
  kevIds = new Set(),
  totalCves,
}) {
  const asset = parseCpe(cpeName);

  const enriched = cves.map((cve) => {
    const layer = osiLayerForCve({ part: asset.part, cwes: cve.cwes });
    return {
      id: cve.id,
      cvss: cve.cvss,
      severity: cve.severity,
      description: cve.description,
      published: cve.published,
      cwes: cve.cwes,
      epss: epss[cve.id]?.epss ?? null,
      epssPercentile: epss[cve.id]?.percentile ?? null,
      kev: kevIds.has(cve.id),
      osiLayer: layer,
    };
  });
  enriched.sort((a, b) => riskScore(b) - riskScore(a));

  const allCwes = [...new Set(enriched.flatMap((cve) => cve.cwes))];
  const chain = chainForCwes(allCwes);

  // CVEs the attack-pattern chain actually covers, so the UI can be honest
  // about which exposure has a mapped route and which does not.
  const coveredCweSet = new Set(chain.coveredCwes);
  const mappedCves = enriched.filter((cve) =>
    cve.cwes.some((cwe) => coveredCweSet.has(cwe)),
  ).length;

  const layers = OSI_LAYERS.map((layer) => {
    const inLayer = enriched.filter((cve) => cve.osiLayer === layer.n);
    const kev = inLayer.filter((cve) => cve.kev).length;
    return {
      ...layer,
      count: inLayer.length,
      kev,
      topCves: inLayer.slice(0, MAX_LAYER_CVES).map((cve) => cve.id),
    };
  });

  const bySeverity = (name) =>
    enriched.filter((cve) => cve.severity === name).length;
  const maxEpss = enriched.reduce(
    (max, cve) => (cve.epss != null && cve.epss > max ? cve.epss : max),
    0,
  );

  return {
    asset,
    capecVersion: capecVersion(),
    stats: {
      total: totalCves ?? enriched.length,
      analyzed: enriched.length,
      exploited: enriched.filter((cve) => cve.kev).length,
      critical: bySeverity('CRITICAL'),
      high: bySeverity('HIGH'),
      maxEpss,
      weaknesses: allCwes.length,
      attackPatterns: chain.patterns.length,
      techniques: chain.techniqueIds.length,
      mappedCves,
    },
    layers,
    cves: enriched.slice(0, MAX_CVES_RETURNED),
    chain: {
      patterns: chain.patterns.slice(0, MAX_PATTERNS_RETURNED),
      techniqueIds: chain.techniqueIds,
      coveredCwes: chain.coveredCwes,
      uncoveredCwes: chain.uncoveredCwes,
    },
  };
}
