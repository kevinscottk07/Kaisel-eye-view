import test from 'node:test';
import assert from 'node:assert/strict';

import { buildIndex, searchAll } from './store.js';

const data = {
  vulnerabilities: [
    {
      id: 'CVE-2026-0001',
      vendor: 'Acme',
      product: 'Gateway',
      title: 'Acme Gateway overflow',
      description: 'Buffer overflow.',
    },
  ],
  indicators: [
    {
      id: 'threatfox:1',
      value: 'bad.example',
      type: 'domain',
      malware: 'Cobalt Strike',
      tags: ['c2'],
    },
  ],
  malware: [
    { name: 'Cobalt Strike', count: 1, attackId: 'S0154', groups: ['G0016'] },
    { name: 'Unmapped', count: 2, attackId: null, groups: [] },
  ],
};

const attack = {
  version: '19.2',
  tactics: [],
  groups: [
    { id: 'G0016', name: 'APT29', aliases: ['Cozy Bear'] },
    { id: 'G0007', name: 'APT28', aliases: [] },
  ],
  software: [{ id: 'S0154', name: 'Cobalt Strike', kind: 'tool', aliases: [] }],
  techniques: [{ id: 'T1566', name: 'Phishing', tactics: ['initial-access'] }],
};

test('the index links active malware to ATT&CK software and groups', () => {
  const index = buildIndex(data, attack);
  assert.deepEqual(index.activeGroups.get('G0016'), ['Cobalt Strike']);
  assert.equal(index.activeGroups.has('G0007'), false);
  assert.equal(index.activeSoftware.get('S0154').name, 'Cobalt Strike');
  assert.equal(index.vulnById.get('CVE-2026-0001').vendor, 'Acme');
});

test('the index works without the ATT&CK knowledge base', () => {
  const index = buildIndex(data, null);
  assert.equal(index.attack.groups.length, 0);
  assert.equal(index.malwareByName.get('Unmapped').count, 2);
});

test('search finds entities of every kind and ignores short queries', () => {
  const index = buildIndex(data, attack);
  assert.deepEqual(searchAll(index, 'c'), []);
  const kinds = (query) => searchAll(index, query).map((hit) => hit.kind);
  assert.deepEqual(kinds('cozy'), ['group']);
  assert.deepEqual(kinds('acme'), ['vuln']);
  assert.deepEqual(kinds('T1566'), ['technique']);
  assert.deepEqual(kinds('cobalt'), ['malware', 'software', 'indicator']);
  assert.equal(searchAll(index, 'bad.example')[0].id, 'threatfox:1');
});
