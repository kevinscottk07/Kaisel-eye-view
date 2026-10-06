import cytoscape from 'cytoscape';

import { h, replaceChildren } from '../threatIntel/dom.js';
import {
  sharedThreatIntelIndex,
  searchAll,
  listCases,
  createCase,
  deleteCase,
} from '../threatIntel/store.js';
import { createCaseController } from './caseController.js';

const KIND_COLOR = {
  group: '#ff9f43',
  malware: '#ff5d6c',
  technique: '#00d4ff',
  software: '#9b4cff',
  indicator: '#6fe3a0',
  vuln: '#ffcf5c',
  note: '#9fb4cc',
};
const KIND_LABEL = {
  group: 'Threat group',
  malware: 'Malware',
  technique: 'ATT&CK technique',
  software: 'ATT&CK software',
  indicator: 'Indicator',
  vuln: 'Vulnerability',
  note: 'Note',
};

// Exposed so the voice agent can drive the same operations the UI does.
let active = null;
/** @returns {?{controller: object, index: object, addBySearch: Function}} */
export function activeCaseApi() {
  return active;
}

export function mountCasesWorkspace() {
  const root = document.getElementById('cases-workspace');
  const switcher = document.getElementById('view-switch');
  if (!root || !switcher) return;
  const board = root.querySelector('#cases-board');
  const titleEl = root.querySelector('#cases-title');
  const searchInput = root.querySelector('#cases-search');
  const results = root.querySelector('#cases-search-results');
  const panel = root.querySelector('#cases-panel');
  const picker = root.querySelector('#cases-picker');
  const stateEl = root.querySelector('#cases-state');
  const countEl = root.querySelector('#cases-count');

  let index = null;
  let controller = null;
  let cy = null;
  let selectedKey = null;
  let loading = null;

  const kindColor = (k) => KIND_COLOR[k] || '#9fb4cc';

  function ensureIndex() {
    if (index) return Promise.resolve(index);
    if (!loading)
      loading = sharedThreatIntelIndex()
        .then((idx) => {
          index = idx;
          return idx;
        })
        .catch(() => null)
        .finally(() => {
          loading = null;
        });
    return loading;
  }

  // ---- Cytoscape board ----------------------------------------------

  function buildCy() {
    cy = cytoscape({
      container: board,
      minZoom: 0.2,
      maxZoom: 2.5,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (el) => kindColor(el.data('kind')),
            label: 'data(label)',
            color: '#e8f4ff',
            'font-family': 'IBM Plex Mono, monospace',
            'font-size': '9px',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            width: 22,
            height: 22,
            'border-width': 2,
            'border-color': (el) => kindColor(el.data('kind')),
            'border-opacity': 0.5,
            'overlay-opacity': 0,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#ffffff',
            'border-opacity': 1,
            width: 28,
            height: 28,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.4,
            'line-color': 'rgba(122,200,255,0.3)',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-family': 'IBM Plex Mono, monospace',
            'font-size': '7px',
            color: 'rgba(232,244,255,0.5)',
          },
        },
      ],
    });
    cy.on('tap', 'node', (evt) => selectNode(evt.target.id()));
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        selectedKey = null;
        renderPanel();
      }
    });
  }

  function syncBoard(previousCount) {
    if (!cy) buildCy();
    const rec = controller.record;
    const wantNodes = new Set(rec.nodes.map((n) => n.key));
    const wantEdges = new Set(rec.edges.map((e) => e.id));

    cy.batch(() => {
      for (const el of cy.nodes()) if (!wantNodes.has(el.id())) el.remove();
      for (const el of cy.edges()) if (!wantEdges.has(el.id())) el.remove();
      for (const n of rec.nodes) {
        if (cy.getElementById(n.key).empty())
          cy.add({
            group: 'nodes',
            data: { id: n.key, label: n.label, kind: n.kind },
          });
      }
      for (const e of rec.edges) {
        if (cy.getElementById(e.id).empty())
          cy.add({
            group: 'edges',
            data: {
              id: e.id,
              source: e.source,
              target: e.target,
              label: e.label || '',
            },
          });
      }
    });

    countEl.textContent = rec.nodes.length
      ? `${rec.nodes.length} nodes · ${rec.edges.length} links`
      : '';
    // Re-run layout when the node set changed, so the board visibly assembles.
    if (rec.nodes.length !== previousCount && rec.nodes.length > 0) {
      cy.layout({
        name: 'cose',
        animate: true,
        animationDuration: 500,
        nodeRepulsion: 9000,
        idealEdgeLength: 90,
        padding: 40,
      }).run();
    }
  }

  // ---- detail panel -------------------------------------------------

  function selectNode(key) {
    selectedKey = key;
    cy?.$(':selected').unselect();
    cy?.getElementById(key).select();
    renderPanel();
  }

  function renderPanel() {
    if (!controller?.record || !selectedKey) {
      replaceChildren(
        panel,
        h('p', {
          class: 'ti-dim cases-panel-empty',
          text: 'Select a node to inspect it, or add an entity to start the case.',
        }),
      );
      return;
    }
    const info = controller.entityFor(selectedKey);
    if (!info) {
      replaceChildren(
        panel,
        h('p', {
          class: 'ti-dim',
          text: 'This node is no longer in the case.',
        }),
      );
      return;
    }
    const { node, related } = info;
    replaceChildren(
      panel,
      h('span', {
        class: 'cases-kind',
        style: { color: kindColor(node.kind) },
        text: KIND_LABEL[node.kind] || node.kind,
      }),
      h('h3', { class: 'cases-node-title', text: node.label }),
      h('p', {
        class: 'ti-dim',
        text: `${related} related entit${related === 1 ? 'y' : 'ies'} available`,
      }),
      h(
        'div',
        { class: 'cases-actions' },
        related
          ? h(
              'button',
              {
                class: 'ti-button ti-button-accent',
                type: 'button',
                onClick: () => doExpand(selectedKey),
              },
              `Expand (+${Math.min(related, 14)})`,
            )
          : null,
        h(
          'button',
          {
            class: 'ti-button',
            type: 'button',
            onClick: () => {
              controller.removeNode(selectedKey);
              selectedKey = null;
            },
          },
          'Remove',
        ),
      ),
    );
  }

  function doExpand(key) {
    const before = controller.record.nodes.length;
    const added = controller.expand(key);
    stateEl.textContent = added
      ? `Expanded — ${added} new`
      : 'Nothing new to add';
    setTimeout(() => (stateEl.textContent = ''), 2500);
  }

  // ---- search to add -------------------------------------------------

  function addBySearch(query) {
    if (!index) return null;
    const hits = searchAll(index, query, 1);
    if (!hits.length) return null;
    const hit = hits[0];
    return controller.addEntity(hit.kind, hit.id);
  }

  searchInput.addEventListener('input', () => {
    const q = searchInput.value.trim();
    if (!index || q.length < 2) {
      results.hidden = true;
      return;
    }
    const hits = searchAll(index, q, 8);
    replaceChildren(
      results,
      hits.length
        ? hits.map((hit) =>
            h(
              'button',
              {
                class: 'ti-search-hit',
                type: 'button',
                onClick: () => {
                  controller.addEntity(hit.kind, hit.id);
                  searchInput.value = '';
                  results.hidden = true;
                  selectNode(`${hit.kind}:${hit.id}`);
                },
              },
              h('span', {
                class: 'ti-search-kind',
                text: KIND_LABEL[hit.kind] || hit.kind,
              }),
              h('span', { class: 'ti-search-label', text: hit.label }),
              h('span', { class: 'ti-dim', text: hit.detail }),
            ),
          )
        : h('p', {
            class: 'ti-dim ti-search-none',
            text: 'No matching entity.',
          }),
    );
    results.hidden = false;
  });
  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') results.hidden = true;
  });
  root.addEventListener('click', (e) => {
    if (!e.target.closest('.cases-search')) results.hidden = true;
  });

  // ---- case lifecycle ------------------------------------------------

  function onCaseChange() {
    const prev = cy ? cy.nodes().length : 0;
    titleEl.textContent = controller.record?.name || 'Case';
    syncBoard(prev);
    if (selectedKey) renderPanel();
  }

  async function openCase(id) {
    await ensureIndex();
    if (!controller) controller = createCaseController({ index });
    controller.subscribe(onCaseChange);
    active = { controller, index, addBySearch };
    await controller.open(id);
    selectedKey = null;
    renderPanel();
    renderPicker();
  }

  async function newCase() {
    const rec = await createCase('Untitled case');
    await refreshPicker();
    await openCase(rec.id);
    const name = prompt_fallback();
    if (name) controller.rename(name);
  }

  // prompt() is unavailable in some hosts; keep it optional.
  function prompt_fallback() {
    try {
      const v = window.prompt?.('Name this case', 'Untitled case');
      return v && v.trim() ? v.trim() : null;
    } catch {
      return null;
    }
  }

  let cases = [];
  async function refreshPicker() {
    cases = await listCases().catch(() => []);
    renderPicker();
  }
  function renderPicker() {
    replaceChildren(
      picker,
      h('option', {
        value: '',
        text: cases.length ? 'Open a case…' : 'No cases yet',
      }),
      cases.map((c) =>
        h('option', {
          value: c.id,
          text: `${c.name} (${c.nodeCount})`,
          selected: controller?.record?.id === c.id ? '' : null,
        }),
      ),
    );
  }
  picker.addEventListener('change', () => {
    if (picker.value) openCase(picker.value);
  });

  root.querySelector('#cases-new').addEventListener('click', newCase);
  root.querySelector('#cases-delete').addEventListener('click', async () => {
    if (!controller?.record) return;
    await deleteCase(controller.record.id);
    controller.load({ id: null, name: '', nodes: [], edges: [] });
    titleEl.textContent = 'Cases';
    countEl.textContent = '';
    if (cy) cy.elements().remove();
    await refreshPicker();
    renderState();
  });

  function renderState() {
    const empty = !controller?.record?.id;
    root.classList.toggle('cases-empty', empty);
  }

  // ---- view switch ---------------------------------------------------

  let shownOnce = false;
  function show(view) {
    const open = view === 'cases';
    root.hidden = !open;
    document.body.classList.toggle('cases-open', open);
    if (open) {
      if (!shownOnce) {
        shownOnce = true;
        ensureIndex();
        refreshPicker();
        renderState();
      }
      // Cytoscape needs a sized container; resize once visible.
      if (cy) setTimeout(() => cy.resize(), 50);
    }
  }
  for (const button of switcher.querySelectorAll('button[data-view]'))
    button.addEventListener('click', () => show(button.dataset.view));
  root.addEventListener('keydown', (e) => e.stopPropagation());

  renderPanel();
  renderState();
}
