import { h, replaceChildren, formatAgo, renderMarkdown } from './dom.js';
import {
  analystStatus,
  askAnalyst,
  loadThreatIntel,
  searchAll,
} from './store.js';
import {
  actorsView,
  indicatorsView,
  malwareView,
  matrixView,
  overviewView,
  vulnerabilitiesView,
} from './views.js';
import { describeEntity, kindLabel } from './detail.js';

const TABS = [
  ['overview', 'Overview'],
  ['vulnerabilities', 'Vulnerabilities'],
  ['indicators', 'Indicators'],
  ['malware', 'Malware'],
  ['actors', 'Threat groups'],
  ['matrix', 'ATT&CK'],
  ['analyst', 'Analyst'],
];

const SUGGESTED = [
  'Which vulnerabilities should I patch first, and why?',
  'What malware is most active right now and how do I detect it?',
  'Which threat groups are plausibly behind current activity?',
];

/**
 * Mount the threat-intelligence workspace: a full-screen view beside the
 * globe, opened from the view switch. Data loads on first open.
 */
export function mountThreatIntelWorkspace() {
  const root = document.getElementById('threat-intel-workspace');
  const switcher = document.getElementById('view-switch');
  if (!root || !switcher) return;
  const tabsHost = root.querySelector('#threat-intel-tabs');
  const main = root.querySelector('#threat-intel-main');
  const drawer = root.querySelector('#threat-intel-drawer');
  const drawerKind = root.querySelector('#threat-intel-drawer-kind');
  const drawerTitle = root.querySelector('#threat-intel-drawer-title');
  const drawerBody = root.querySelector('#threat-intel-drawer-body');
  const drawerBack = root.querySelector('#threat-intel-drawer-back');
  const searchInput = root.querySelector('#threat-intel-search');
  const searchResults = root.querySelector('#threat-intel-search-results');
  const refreshButton = root.querySelector('#threat-intel-refresh');
  const updated = root.querySelector('#threat-intel-updated');

  let index = null;
  let loading = null;
  let activeTab = 'overview';
  let tabPreset = {};
  /** Entities opened in the drawer, oldest first, for the back button. */
  let trail = [];
  /** @type {Array<{role: 'user'|'analyst'|'error', text: string, meta?: string}>} */
  const conversation = [];
  let analystBusy = false;
  let analystHasKey = null;

  const ctx = {
    get index() {
      return index;
    },
    open: (kind, id) => openEntity(kind, id),
    go: (tab, preset = {}) => {
      closeDrawer();
      showTab(tab, preset);
    },
  };

  const tabButtons = new Map(
    TABS.map(([id, label]) => [
      id,
      h('button', {
        class: 'ti-tab',
        type: 'button',
        role: 'tab',
        text: label,
        'aria-selected': 'false',
        onClick: () => ctx.go(id),
      }),
    ]),
  );
  replaceChildren(tabsHost, [...tabButtons.values()]);

  function setView(view) {
    const open = view === 'threat-intel';
    root.hidden = !open;
    document.body.classList.toggle('ti-open', open);
    for (const button of switcher.querySelectorAll('button[data-view]'))
      button.setAttribute('aria-pressed', String(button.dataset.view === view));
    if (open) {
      ensureLoaded();
      render();
    }
  }

  function ensureLoaded(force = false) {
    if (loading || (index && !force)) return loading;
    refreshButton.disabled = true;
    loading = loadThreatIntel()
      .then((next) => {
        index = next;
        updated.textContent = `Updated ${formatAgo(index.data.generatedAt)}`;
      })
      .catch((error) => {
        if (!index) main.dataset.error = String(error?.message || error);
      })
      .finally(() => {
        loading = null;
        refreshButton.disabled = false;
        render();
      });
    render();
    return loading;
  }

  function showTab(tab, preset = {}) {
    activeTab = tabButtons.has(tab) ? tab : 'overview';
    tabPreset = preset;
    render();
    main.scrollTop = 0;
  }

  function render() {
    for (const [id, button] of tabButtons)
      button.setAttribute('aria-selected', String(id === activeTab));
    if (activeTab === 'analyst') {
      replaceChildren(main, analystView());
      return;
    }
    if (!index) {
      replaceChildren(
        main,
        h(
          'div',
          { class: 'ti-state' },
          loading
            ? [
                h('div', { class: 'ti-spinner', 'aria-hidden': 'true' }),
                h('p', {
                  text: 'Collecting threat intelligence from public feeds…',
                }),
                h('p', {
                  class: 'ti-dim',
                  text: 'The first load downloads the ATT&CK knowledge base and can take up to a minute.',
                }),
              ]
            : [
                h('p', { text: 'The threat feeds could not be loaded.' }),
                h(
                  'button',
                  {
                    class: 'ti-button',
                    type: 'button',
                    onClick: () => ensureLoaded(true),
                  },
                  'Try again',
                ),
              ],
        ),
      );
      return;
    }
    const views = {
      overview: overviewView,
      vulnerabilities: vulnerabilitiesView,
      indicators: indicatorsView,
      malware: malwareView,
      actors: actorsView,
      matrix: matrixView,
    };
    replaceChildren(main, views[activeTab](ctx, tabPreset));
  }

  // ------------------------------------------------------------- drawer

  function openEntity(kind, id) {
    if (!index) return;
    const entity = describeEntity(ctx, kind, id);
    if (!entity) return;
    const last = trail[trail.length - 1];
    if (!last || last.kind !== kind || last.id !== id) trail.push({ kind, id });
    drawerKind.textContent = kindLabel(kind);
    drawerTitle.textContent = entity.title;
    replaceChildren(
      drawerBody,
      entity.body,
      h(
        'button',
        {
          class: 'ti-button ti-button-accent',
          type: 'button',
          onClick: () => {
            closeDrawer();
            showTab('analyst');
            submitQuestion(entity.question);
          },
        },
        'Ask the analyst about this',
      ),
    );
    drawerBack.hidden = trail.length < 2;
    drawer.hidden = false;
    drawerBody.scrollTop = 0;
    closeSearch();
  }

  function closeDrawer() {
    drawer.hidden = true;
    trail = [];
  }

  drawerBack.addEventListener('click', () => {
    trail.pop();
    const previous = trail.pop();
    if (previous) openEntity(previous.kind, previous.id);
  });
  root
    .querySelector('#threat-intel-drawer-close')
    .addEventListener('click', closeDrawer);

  // ------------------------------------------------------------- search

  function closeSearch() {
    searchResults.hidden = true;
  }

  searchInput.addEventListener('input', () => {
    if (!index) return;
    const hits = searchAll(index, searchInput.value);
    if (searchInput.value.trim().length < 2) {
      closeSearch();
      return;
    }
    replaceChildren(
      searchResults,
      hits.length
        ? hits.map((hit) =>
            h(
              'button',
              {
                class: 'ti-search-hit',
                type: 'button',
                onClick: () => {
                  searchInput.value = '';
                  openEntity(hit.kind, hit.id);
                },
              },
              h('span', { class: 'ti-search-kind', text: kindLabel(hit.kind) }),
              h('span', { class: 'ti-search-label', text: hit.label }),
              h('span', { class: 'ti-dim', text: hit.detail }),
            ),
          )
        : h('p', { class: 'ti-dim ti-search-none', text: 'Nothing found.' }),
    );
    searchResults.hidden = false;
  });
  searchInput.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      searchInput.value = '';
      closeSearch();
    }
  });
  document.addEventListener('click', (event) => {
    if (!event.target.closest?.('.ti-search')) closeSearch();
  });

  // ------------------------------------------------------------ analyst

  function analystView() {
    const log = h('div', { class: 'ti-chat-log', 'aria-live': 'polite' });
    if (!conversation.length && !analystBusy) {
      log.append(
        h(
          'div',
          { class: 'ti-chat-empty' },
          h('p', {
            class: 'ti-lead',
            text: 'An AI analyst that reads the same data you see here.',
          }),
          h('p', {
            class: 'ti-dim',
            text: 'Ask for a briefing, or ask a question about any vulnerability, malware family or group.',
          }),
        ),
      );
    }
    for (const message of conversation) {
      log.append(
        h(
          'article',
          { class: `ti-chat-msg ti-chat-${message.role}` },
          message.role === 'analyst'
            ? renderMarkdown(message.text)
            : h('p', { text: message.text }),
          message.meta
            ? h('p', { class: 'ti-dim ti-chat-meta', text: message.meta })
            : null,
        ),
      );
    }
    if (analystBusy)
      log.append(
        h(
          'article',
          { class: 'ti-chat-msg ti-chat-analyst ti-chat-pending' },
          h('div', { class: 'ti-spinner', 'aria-hidden': 'true' }),
          'Reading the feeds…',
        ),
      );

    const input = h('textarea', {
      class: 'ti-input ti-chat-input',
      rows: '2',
      placeholder: 'Ask the analyst…',
      'aria-label': 'Question for the analyst',
    });
    const send = () => {
      const question = input.value.trim();
      if (question) submitQuestion(question);
    };
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        send();
      }
    });
    const disabled = analystBusy || analystHasKey === false;
    input.disabled = disabled;

    queueMicrotask(() => {
      log.scrollTop = log.scrollHeight;
    });
    return h(
      'div',
      { class: 'ti-view ti-chat' },
      analystHasKey === false
        ? h(
            'div',
            { class: 'ti-callout' },
            h('strong', { text: 'The analyst needs an Anthropic API key. ' }),
            'Switch to the globe, open POWER UP (bottom right) and paste a key under ANTHROPIC. Everything else on this page works without it.',
          )
        : null,
      log,
      h(
        'div',
        { class: 'ti-chat-suggest' },
        h(
          'button',
          {
            class: 'ti-button ti-button-accent',
            type: 'button',
            disabled,
            onClick: () => submitQuestion(null),
          },
          "Today's briefing",
        ),
        SUGGESTED.map((question) =>
          h(
            'button',
            {
              class: 'ti-button',
              type: 'button',
              disabled,
              onClick: () => submitQuestion(question),
            },
            question,
          ),
        ),
      ),
      h(
        'div',
        { class: 'ti-chat-compose' },
        input,
        h(
          'button',
          {
            class: 'ti-button ti-button-accent',
            type: 'button',
            disabled,
            onClick: send,
          },
          'Ask',
        ),
      ),
    );
  }

  async function submitQuestion(question) {
    if (analystBusy) return;
    conversation.push({ role: 'user', text: question || "Today's briefing" });
    analystBusy = true;
    render();
    try {
      const answer = await askAnalyst(question);
      conversation.push({
        role: 'analyst',
        text: answer.text,
        meta: `${answer.model}${answer.cached ? ' · saved briefing from ' + formatAgo(answer.generatedAt) : ''}`,
      });
    } catch (error) {
      if (error.code === 'no_key') analystHasKey = false;
      conversation.push({ role: 'error', text: error.message });
    } finally {
      analystBusy = false;
      if (activeTab === 'analyst') render();
    }
  }

  // -------------------------------------------------------------- wiring

  for (const button of switcher.querySelectorAll('button[data-view]'))
    button.addEventListener('click', () => setView(button.dataset.view));
  refreshButton.addEventListener('click', () => ensureLoaded(true));

  // Cursor-following spotlight on the backdrop. Coalesced to one update per
  // frame; the backdrop reads --ti-spot-x/--ti-spot-y in the stylesheet.
  let spotPending = false;
  root.addEventListener('pointermove', (event) => {
    if (spotPending) return;
    spotPending = true;
    requestAnimationFrame(() => {
      spotPending = false;
      const rect = root.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      root.style.setProperty(
        '--ti-spot-x',
        `${((event.clientX - rect.left) / rect.width) * 100}%`,
      );
      root.style.setProperty(
        '--ti-spot-y',
        `${((event.clientY - rect.top) / rect.height) * 100}%`,
      );
    });
  });

  root.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !drawer.hidden) closeDrawer();
    // Keep the globe's keyboard shortcuts from firing while typing here.
    event.stopPropagation();
  });
  analystStatus().then((status) => {
    analystHasKey = Boolean(status.hasKey);
    if (activeTab === 'analyst' && !root.hidden) render();
  });
}
