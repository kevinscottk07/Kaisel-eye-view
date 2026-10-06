/**
 * Reduce the MITRE CAPEC "Comprehensive" CSV to the mapping the Threat Intel
 * exposure view needs: each attack pattern with its related weaknesses (CWE)
 * and ATT&CK techniques, plus a CWE→CAPEC index. The result is bundled as
 * src/threatIntel/data/capecMap.json so the exposure route (CVE→CWE→CAPEC→
 * ATT&CK) is built from reference data without a runtime CAPEC fetch.
 *
 * CAPEC changes rarely, so this is run by hand when refreshing the dataset:
 *
 *   1. Download https://capec.mitre.org/data/csv/2000.csv.zip
 *   2. Unzip it (e.g. PowerShell `Expand-Archive`) to get 2000.csv
 *   3. node scripts/build-capec-map.mjs path/to/2000.csv
 *
 * The CWE↔CAPEC and CAPEC↔ATT&CK relationships are published by MITRE; this
 * script only re-shapes them.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Minimal RFC 4180 CSV parser (quoted fields, embedded commas/newlines). */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (c !== '\r') field += c;
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

const clip = (value, max) => {
  const text = String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
};

/** `::276::285::...::` → ['CWE-276', 'CWE-285', ...] */
function parseCwes(value) {
  return String(value || '')
    .split('::')
    .map((part) => part.trim())
    .filter((part) => /^\d+$/.test(part))
    .map((id) => `CWE-${id}`);
}

/** Pull ATT&CK technique ids from the Taxonomy Mappings column. */
function parseAttack(value) {
  const ids = new Set();
  const pattern = /TAXONOMY NAME:ATTACK:ENTRY ID:([0-9]+(?:\.[0-9]+)?)/g;
  let match;
  while ((match = pattern.exec(String(value || '')))) {
    ids.add(`T${match[1]}`);
  }
  return [...ids];
}

function main() {
  const csvPath = process.argv[2];
  if (!csvPath) {
    console.error('Usage: node scripts/build-capec-map.mjs path/to/2000.csv');
    process.exit(1);
  }
  const rows = parseCsv(readFileSync(csvPath, 'utf8'));
  const header = rows[0].map((h) => h.replace(/[^A-Za-z ]/g, '').trim());
  const col = (name) => header.indexOf(name);
  const ID = 0; // first column is the CAPEC id (may carry a spreadsheet quote)
  const cNameI = col('Name');
  const cAbsI = col('Abstraction');
  const cDescI = col('Description');
  const cLikeI = col('Likelihood Of Attack');
  const cSevI = col('Typical Severity');
  const cMitI = col('Mitigations');
  const cCweI = col('Related Weaknesses');
  const cTaxI = col('Taxonomy Mappings');

  const capec = {};
  const cweToCapec = {};
  for (const row of rows.slice(1)) {
    const id = String(row[ID] || '').replace(/\D/g, '');
    if (!id) continue;
    const capecId = `CAPEC-${id}`;
    const cwes = parseCwes(row[cCweI]);
    const attack = parseAttack(row[cTaxI]);
    capec[capecId] = {
      id: capecId,
      name: clip(row[cNameI], 140),
      abstraction: row[cAbsI] || '',
      severity: row[cSevI] || '',
      likelihood: row[cLikeI] || '',
      description: clip(row[cDescI], 320),
      mitigations: clip(row[cMitI], 320),
      cwes,
      attack,
    };
    for (const cwe of cwes) {
      (cweToCapec[cwe] ||= []).push(capecId);
    }
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const outDir = path.join(here, '..', 'server', 'providers', 'threat-intel', 'data');
  mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, 'capecMap.json');
  const payload = {
    source: 'MITRE CAPEC Comprehensive dictionary (CAPEC-2000)',
    generatedAt: new Date().toISOString().slice(0, 10),
    capecCount: Object.keys(capec).length,
    cweCount: Object.keys(cweToCapec).length,
    capec,
    cweToCapec,
  };
  writeFileSync(outPath, `${JSON.stringify(payload)}\n`, 'utf8');
  console.log(
    `Wrote ${outPath}: ${payload.capecCount} patterns, ${payload.cweCount} CWEs mapped.`,
  );
}

main();
