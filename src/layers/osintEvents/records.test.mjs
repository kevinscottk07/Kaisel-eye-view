import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeOsintGeo } from './records.js';

test('chokepoints become validated geo points', () => {
  const rows = normalizeOsintGeo({
    chokepoints: [
      { label: 'Strait of Hormuz', note: '20% of world oil', lat: 26.5, lon: 56.5 },
      { label: 'Bad point', lat: 999, lon: 0 },
    ],
  });
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0], {
    stableId: 'chokepoint:Strait of Hormuz',
    kind: 'chokepoint',
    lon: 56.5,
    lat: 26.5,
    title: 'Strait of Hormuz',
    note: '20% of world oil',
  });
});

test('GDELT and ACLED points are mapped with tolerant field names', () => {
  const rows = normalizeOsintGeo({
    gdelt: { geoPoints: [{ latitude: 10, longitude: 20, title: 'Protest' }] },
    acled: { deadliestEvents: [{ lat: -5, lon: 30, event_type: 'Battle' }] },
  });
  const kinds = rows.map((r) => r.kind);
  assert.ok(kinds.includes('event'));
  assert.ok(kinds.includes('conflict'));
  assert.equal(rows.find((r) => r.kind === 'event').title, 'Protest');
  assert.equal(rows.find((r) => r.kind === 'conflict').title, 'Battle');
});

test('bad input and duplicates are dropped, never thrown', () => {
  assert.deepEqual(normalizeOsintGeo(null), []);
  assert.deepEqual(normalizeOsintGeo({}), []);
  const dup = normalizeOsintGeo({
    chokepoints: [
      { label: 'A', lat: 1, lon: 1 },
      { label: 'A', lat: 1, lon: 1 },
    ],
  });
  assert.equal(dup.length, 1);
});
