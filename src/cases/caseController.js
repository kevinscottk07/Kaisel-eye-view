import { getCase, saveCase } from '../threatIntel/store.js';

/**
 * The case controller owns one open case's graph and every mutation on it —
 * add an entity, expand a node to its related entities, link, remove, rename,
 * record an assessment. The Cases view's buttons and the voice agent both call
 * these same methods, so a spoken command and a click build the board
 * identically. Changes notify subscribers and autosave to the server.
 *
 * A "case" is threat entities and their relationships, drawn from the shared
 * Threat Intel index — threat actors, malware, ATT&CK software/techniques,
 * indicators and CVEs — never private individuals.
 */

const EXPAND_CAP = 14;

const keyOf = (kind, id) => `${kind}:${id}`;

export function createCaseController({ index }) {
  /** @type {?object} */
  let record = null;
  const listeners = new Set();
  let saveTimer = null;
  let saving = null;

  const nodeMap = () => new Map(record.nodes.map((n) => [n.key, n]));
  const hasNode = (key) => record.nodes.some((n) => n.key === key);
  const hasEdge = (a, b) =>
    record.edges.some(
      (e) =>
        (e.source === a && e.target === b) ||
        (e.source === b && e.target === a),
    );

  function emit() {
    for (const fn of listeners) fn(record);
    scheduleSave();
  }
  function scheduleSave() {
    if (!record) return;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saving = saveCase(record).catch((err) =>
        console.warn('[cases] save failed:', err?.message || err),
      );
    }, 700);
  }

  // ---- entity resolution + relationships (from the shared index) -----

  /** Resolve (kind,id) to a display label, or null if unknown. */
  function resolve(kind, id) {
    switch (kind) {
      case 'group': {
        const g = index.groupById.get(id);
        return g ? { label: g.name } : null;
      }
      case 'software': {
        const s = index.softwareById.get(id);
        return s ? { label: s.name } : null;
      }
      case 'technique': {
        const t = index.techniqueById.get(id);
        return t ? { label: `${t.id} ${t.name}` } : null;
      }
      case 'malware': {
        const m = index.malwareByName.get(id);
        return m ? { label: m.name } : null;
      }
      case 'indicator': {
        const i = index.indicatorById.get(id);
        return i ? { label: i.value } : null;
      }
      case 'vuln': {
        const v = index.vulnById.get(id);
        return v ? { label: v.id } : null;
      }
      case 'note':
        return { label: String(id).slice(0, 80) };
      default:
        return null;
    }
  }

  /** The entities one node relates to, as {kind,id} pairs. */
  function relatedOf(kind, id) {
    const out = [];
    const add = (k, i) => i && out.push({ kind: k, id: i });
    if (kind === 'group') {
      const g = index.groupById.get(id);
      if (g) {
        g.techniques.forEach((t) => add('technique', t));
        g.software.forEach((s) => add('software', s));
      }
    } else if (kind === 'software') {
      const s = index.softwareById.get(id);
      if (s) {
        s.techniques.forEach((t) => add('technique', t));
        s.groups.forEach((g) => add('group', g));
      }
    } else if (kind === 'technique') {
      const t = index.techniqueById.get(id);
      if (t) {
        t.groups.forEach((g) => add('group', g));
        t.software.forEach((s) => add('software', s));
      }
    } else if (kind === 'malware') {
      const m = index.malwareByName.get(id);
      if (m) {
        if (m.attackId) add('software', m.attackId);
        m.groups.forEach((g) => add('group', g));
      }
    } else if (kind === 'indicator') {
      const i = index.indicatorById.get(id);
      if (i && i.malware && index.malwareByName.has(i.malware))
        add('malware', i.malware);
    }
    return out;
  }

  const relatedKeySet = (kind, id) =>
    new Set(relatedOf(kind, id).map((r) => keyOf(r.kind, r.id)));

  function linkToExisting(node) {
    const rel = relatedKeySet(node.kind, node.id);
    for (const other of record.nodes) {
      if (other.key === node.key) continue;
      const connected =
        rel.has(other.key) || relatedKeySet(other.kind, other.id).has(node.key);
      if (connected && !hasEdge(node.key, other.key)) {
        record.edges.push({
          id: `${node.key}__${other.key}`,
          source: node.key,
          target: other.key,
          label: '',
        });
      }
    }
  }

  // ---- public operations --------------------------------------------

  const api = {
    get record() {
      return record;
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },

    async open(id) {
      record = await getCase(id);
      record.nodes ||= [];
      record.edges ||= [];
      emitOnly();
      return record;
    },
    load(rec) {
      record = rec;
      record.nodes ||= [];
      record.edges ||= [];
      emitOnly();
    },

    /** Add one entity by (kind,id). Returns {added, key, label}. */
    addEntity(kind, id) {
      if (!record) return { added: false };
      const key = keyOf(kind, id);
      if (hasNode(key))
        return { added: false, key, label: nodeMap().get(key)?.label };
      const resolved = resolve(kind, id);
      if (!resolved) return { added: false, reason: 'unknown' };
      const node = { key, kind, id, label: resolved.label };
      record.nodes.push(node);
      linkToExisting(node);
      emit();
      return { added: true, key, label: resolved.label };
    },

    /** Expand a node into its related entities (capped). Returns count added. */
    expand(key) {
      if (!record) return 0;
      const node = nodeMap().get(key);
      if (!node) return 0;
      const related = relatedOf(node.kind, node.id).slice(0, EXPAND_CAP);
      let added = 0;
      for (const r of related) {
        if (api.addEntity(r.kind, r.id).added) added += 1;
      }
      // Ensure the seed links to each related node even if capping changed order.
      emit();
      return added;
    },

    addEdge(sourceKey, targetKey, label = '') {
      if (!record || sourceKey === targetKey) return false;
      if (!hasNode(sourceKey) || !hasNode(targetKey)) return false;
      if (hasEdge(sourceKey, targetKey)) return false;
      record.edges.push({
        id: `${sourceKey}__${targetKey}`,
        source: sourceKey,
        target: targetKey,
        label: String(label).slice(0, 60),
      });
      emit();
      return true;
    },

    removeNode(key) {
      if (!record) return false;
      const before = record.nodes.length;
      record.nodes = record.nodes.filter((n) => n.key !== key);
      record.edges = record.edges.filter(
        (e) => e.source !== key && e.target !== key,
      );
      if (record.nodes.length !== before) {
        emit();
        return true;
      }
      return false;
    },

    clear() {
      if (!record) return;
      record.nodes = [];
      record.edges = [];
      emit();
    },

    rename(name) {
      if (!record) return;
      record.name = String(name).slice(0, 120);
      emit();
    },

    setAssessment(text, model) {
      if (!record) return;
      record.assessment = { text, model, generatedAt: Date.now() };
      emit();
    },

    /** Resolve a node's underlying entity for the detail panel. */
    entityFor(key) {
      const node = nodeMap().get(key);
      if (!node) return null;
      return { node, related: relatedOf(node.kind, node.id).length };
    },

    flush() {
      clearTimeout(saveTimer);
      if (record) saving = saveCase(record).catch(() => {});
      return saving;
    },
  };

  // Notify without triggering a save (used when loading from disk).
  function emitOnly() {
    for (const fn of listeners) fn(record);
  }

  return api;
}
