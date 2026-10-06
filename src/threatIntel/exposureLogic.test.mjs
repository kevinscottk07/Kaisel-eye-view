import test from 'node:test';
import assert from 'node:assert/strict';

import {
  osiLayerForCve,
  OSI_LAYERS,
} from '../../server/providers/threat-intel/osi.js';
import { chainForCwes } from '../../server/providers/threat-intel/capec.js';
import { assembleExposure } from '../../server/providers/threat-intel/exposure.js';

test('the OSI ladder runs application (7) down to physical (1)', () => {
  assert.deepEqual(
    OSI_LAYERS.map((l) => l.n),
    [7, 6, 5, 4, 3, 2, 1],
  );
});

test('OSI classification uses the weakness class, then the CPE part', () => {
  assert.equal(osiLayerForCve({ part: 'a', cwes: ['CWE-327'] }), 6); // crypto
  assert.equal(osiLayerForCve({ part: 'a', cwes: ['CWE-287'] }), 5); // auth
  assert.equal(osiLayerForCve({ part: 'o', cwes: ['CWE-406'] }), 4); // transport
  assert.equal(osiLayerForCve({ part: 'h', cwes: ['CWE-1300'] }), 1); // hardware
  // No decisive weakness → fall back to the component's part.
  assert.equal(osiLayerForCve({ part: 'a', cwes: ['CWE-787'] }), 7);
  assert.equal(osiLayerForCve({ part: 'o', cwes: ['CWE-787'] }), 3);
  assert.equal(osiLayerForCve({ part: 'h', cwes: [] }), 1);
  // The first matching rule (crypto) wins when several apply.
  assert.equal(osiLayerForCve({ part: 'a', cwes: ['CWE-327', 'CWE-287'] }), 6);
});

test('the CAPEC chain maps weaknesses to patterns and techniques', () => {
  const chain = chainForCwes(['CWE-287', 'CWE-9999999']);
  assert.ok(chain.patterns.length > 0, 'CWE-287 has mapped attack patterns');
  assert.ok(chain.coveredCwes.includes('CWE-287'));
  assert.ok(chain.uncoveredCwes.includes('CWE-9999999'));
  // Every returned pattern actually references one of the requested CWEs.
  for (const pattern of chain.patterns) {
    assert.ok(pattern.matchedCwes.includes('CWE-287'));
  }
  // Patterns are deduped and ordered by how many requested CWEs they match.
  const ids = chain.patterns.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('exposure assembly ranks, places and summarizes an asset', () => {
  const exposure = assembleExposure({
    cpeName: 'cpe:2.3:o:google:android:13.0:*:*:*:*:*:*:*',
    cves: [
      // Low CVSS but exploited → must rank first.
      { id: 'CVE-KEV', cvss: 5.0, severity: 'MEDIUM', description: 'auth', published: '2026-01-01Z', cwes: ['CWE-287'] },
      { id: 'CVE-CRIT', cvss: 9.8, severity: 'CRITICAL', description: 'oob', published: '2026-02-01Z', cwes: ['CWE-787'] },
    ],
    epss: { 'CVE-CRIT': { epss: 0.5, percentile: 0.9 } },
    kevIds: new Set(['CVE-KEV']),
    totalCves: 2,
  });

  assert.equal(exposure.asset.vendor, 'google');
  assert.equal(exposure.asset.partLabel, 'Operating system');
  assert.equal(exposure.cves[0].id, 'CVE-KEV', 'exploited ranks above higher CVSS');
  assert.equal(exposure.stats.exploited, 1);
  assert.equal(exposure.stats.critical, 1);
  assert.equal(exposure.stats.maxEpss, 0.5);

  // CVE-KEV (auth, CWE-287) → Session (5); CVE-CRIT (CWE-787, OS part) → Network (3).
  const session = exposure.layers.find((l) => l.n === 5);
  assert.equal(session.count, 1);
  assert.equal(session.kev, 1);
  assert.equal(exposure.layers.find((l) => l.n === 3).count, 1);

  // CWE-287 is mapped; CWE-787 is not, so only one CVE has a mapped route.
  assert.equal(exposure.stats.mappedCves, 1);
  assert.ok(exposure.chain.uncoveredCwes.includes('CWE-787'));
});
