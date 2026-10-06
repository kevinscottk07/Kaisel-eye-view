/**
 * Place a vulnerability on the OSI stack for the exposure view's layer ladder.
 *
 * This is an APPROXIMATE framing, not a standard: OSI models network
 * communication, while a CVE's "layer" is a judgement. The classifier maps a
 * weakness to a layer when its class points clearly at one (cryptography →
 * Presentation, authentication/session → Session, transport/protocol →
 * Transport, hardware/firmware → Physical/Data Link), and otherwise falls back
 * to the affected component's CPE part (application → Application, OS →
 * Network, hardware → Physical). The ladder is a lens for triage, and the UI
 * labels it as approximate.
 */

export const OSI_LAYERS = Object.freeze([
  {
    n: 7,
    key: 'application',
    name: 'Application',
    blurb: 'Apps, APIs, services, logic',
  },
  {
    n: 6,
    key: 'presentation',
    name: 'Presentation',
    blurb: 'Encryption, encoding, serialization',
  },
  {
    n: 5,
    key: 'session',
    name: 'Session',
    blurb: 'Authentication, sessions, credentials',
  },
  {
    n: 4,
    key: 'transport',
    name: 'Transport',
    blurb: 'TCP/UDP, ports, TLS transport',
  },
  {
    n: 3,
    key: 'network',
    name: 'Network',
    blurb: 'IP, routing, the OS network stack',
  },
  {
    n: 2,
    key: 'datalink',
    name: 'Data Link',
    blurb: 'Drivers, firmware, local link',
  },
  {
    n: 1,
    key: 'physical',
    name: 'Physical',
    blurb: 'Hardware, debug interfaces, silicon',
  },
]);

// Weakness classes that point clearly at a layer. Checked in order; the first
// matching CWE set wins. CWE ids are bare numbers.
const CWE_LAYER_RULES = [
  {
    layer: 6,
    cwes: new Set([
      310, 311, 319, 321, 325, 326, 327, 328, 329, 330, 331, 347, 759, 760, 780,
      916,
    ]),
  },
  {
    layer: 5,
    cwes: new Set([
      255, 256, 287, 288, 290, 294, 295, 297, 300, 302, 303, 304, 306, 307, 308,
      384, 522, 521, 613, 620, 640, 798, 1392,
    ]),
  },
  { layer: 4, cwes: new Set([406, 441, 1385, 1386]) },
  { layer: 3, cwes: new Set([923, 940, 941]) },
  {
    layer: 1,
    cwes: new Set([
      1189, 1191, 1231, 1234, 1240, 1243, 1244, 1255, 1256, 1274, 1300, 1319,
      1332,
    ]),
  },
];

const PART_DEFAULT_LAYER = { a: 7, o: 3, h: 1 };

const cweNumber = (cwe) => Number(String(cwe).replace(/\D/g, ''));

/**
 * Primary OSI layer (1–7) for one vulnerability.
 * @param {{ part?: string, cwes?: string[] }} input
 * @returns {number}
 */
export function osiLayerForCve({ part = 'a', cwes = [] } = {}) {
  const numbers = cwes.map(cweNumber).filter(Boolean);
  for (const rule of CWE_LAYER_RULES) {
    if (numbers.some((n) => rule.cwes.has(n))) return rule.layer;
  }
  return PART_DEFAULT_LAYER[part] ?? 7;
}
