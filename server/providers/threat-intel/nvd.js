import { fetchJson, normalizeNvdCve } from './feeds.js';

/**
 * NVD device/software lookups for the exposure view: resolve a product to its
 * CPE names, and list the CVEs that apply to a chosen CPE. Keyless NVD allows
 * 5 requests / 30 s; NVD_API_KEY (optional) raises that. Callers cache.
 */

const CPE_API = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';
const CVE_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const PART_LABEL = { a: 'Application', o: 'Operating system', h: 'Hardware' };

const nvdHeaders = () => {
  const key = String(process.env.NVD_API_KEY || '').trim();
  return key ? { apiKey: key } : {};
};

/** Split a CPE 2.3 name into its labelled parts; unbrand `*`/`-` fields. */
export function parseCpe(cpeName) {
  const fields = String(cpeName || '').split(':');
  // cpe:2.3:part:vendor:product:version:update:edition:lang:...
  const clean = (value) =>
    value && value !== '*' && value !== '-'
      ? value.replace(/\\(.)/g, '$1').replace(/_/g, ' ')
      : '';
  const part = fields[2] || '';
  return {
    cpeName,
    part,
    partLabel: PART_LABEL[part] || 'Software',
    vendor: clean(fields[3]),
    product: clean(fields[4]),
    version: clean(fields[5]),
  };
}

/** Resolve a free-text product query to candidate CPE names, newest first. */
export async function searchCpes(query, { limit = 20 } = {}) {
  const url = new URL(CPE_API);
  url.searchParams.set('keywordSearch', String(query).slice(0, 120));
  url.searchParams.set('resultsPerPage', String(Math.min(limit * 3, 60)));
  const body = await fetchJson(url, {
    headers: nvdHeaders(),
    timeoutMs: 40_000,
  });
  const seen = new Set();
  const out = [];
  for (const entry of body?.products || []) {
    const cpe = entry?.cpe;
    if (!cpe?.cpeName || seen.has(cpe.cpeName)) continue;
    seen.add(cpe.cpeName);
    const parsed = parseCpe(cpe.cpeName);
    const title =
      (cpe.titles || []).find((t) => t.lang === 'en')?.title ||
      [parsed.vendor, parsed.product, parsed.version].filter(Boolean).join(' ');
    out.push({
      ...parsed,
      title,
      deprecated: Boolean(cpe.deprecated),
    });
  }
  // Live products before deprecated; otherwise keep NVD's relevance order.
  out.sort((a, b) => Number(a.deprecated) - Number(b.deprecated));
  return out.slice(0, limit);
}

/**
 * CVEs that apply to a specific CPE name. NVD resolves version ranges, so a
 * concrete CPE returns the vulnerabilities affecting that product/version.
 */
export async function cvesForCpe(cpeName, { limit = 500 } = {}) {
  const url = new URL(CVE_API);
  url.searchParams.set('cpeName', cpeName);
  url.searchParams.set('resultsPerPage', String(Math.min(limit, 2000)));
  const body = await fetchJson(url, {
    headers: nvdHeaders(),
    timeoutMs: 60_000,
  });
  const cves = [];
  for (const item of body?.vulnerabilities || []) {
    if (item?.cve?.id) cves.push(normalizeNvdCve(item.cve));
  }
  return { total: body?.totalResults ?? cves.length, cves };
}
