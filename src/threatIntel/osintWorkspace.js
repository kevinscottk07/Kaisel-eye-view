import {
  h,
  replaceChildren,
  externalLink,
  formatAgo,
  formatNumber,
} from './dom.js';
import { badge } from './views.js';
import { loadOsint, osintStatus } from './store.js';

/** Decode HTML entities in RSS-sourced text, safely (read as text, not HTML). */
function decodeEntities(value) {
  const el = document.createElement('textarea');
  el.innerHTML = String(value || '');
  return el.value;
}

const nf = (value, digits = 2) =>
  Number.isFinite(value)
    ? value.toLocaleString('en-US', {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      })
    : '—';

/** Signed percentage, coloured green up / red down. */
function changeChip(pct) {
  if (!Number.isFinite(pct)) return h('span', { class: 'ti-dim', text: '—' });
  const sign = pct > 0 ? '+' : '';
  return h('span', {
    class: `ti-badge ${pct >= 0 ? 'ti-sev-low' : 'ti-sev-critical'}`,
    text: `${sign}${pct.toFixed(2)}%`,
  });
}

/** One market quote row: name, price, change. */
function quoteRow(q) {
  return h(
    'div',
    { class: 'osint-quote' },
    h('span', { class: 'osint-quote-name', text: q.name || q.symbol }),
    h('span', { class: 'osint-quote-price', text: nf(q.price) }),
    changeChip(q.changePct),
  );
}

function card(title, ...children) {
  return h(
    'section',
    { class: 'ti-card' },
    h('h3', { class: 'ti-card-title', text: title }),
    ...children.filter(Boolean),
  );
}

function sparkline(history, key = 'close') {
  const values = (history || [])
    .map((point) => (typeof point === 'number' ? point : point[key]))
    .filter(Number.isFinite);
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const up = values[values.length - 1] >= values[0];
  return h(
    'span',
    { class: `osint-spark ${up ? 'osint-spark-up' : 'osint-spark-down'}` },
    values.map((v) =>
      h('span', {
        class: 'osint-spark-bar',
        style: { height: `${10 + ((v - min) / span) * 90}%` },
      }),
    ),
  );
}

export function mountOsintWorkspace() {
  const root = document.getElementById('osint-workspace');
  const switcher = document.getElementById('view-switch');
  if (!root || !switcher) return;
  const main = root.querySelector('#osint-main');
  const posture = root.querySelector('#osint-posture');
  const updated = root.querySelector('#osint-updated');
  const refreshButton = root.querySelector('#osint-refresh');

  let data = null;
  let loading = null;
  let loaded = false;

  function show(view) {
    const open = view === 'osint';
    root.hidden = !open;
    document.body.classList.toggle('osint-open', open);
    if (open && !loaded) ensureLoaded();
  }

  function ensureLoaded(force = false) {
    if (loading || (loaded && !force)) return;
    refreshButton.disabled = true;
    render({ loading: true });
    loading = loadOsint()
      .then((snapshot) => {
        data = snapshot;
        loaded = true;
        render({});
      })
      .catch((error) => {
        render({ error });
      })
      .finally(() => {
        loading = null;
        refreshButton.disabled = false;
      });
  }

  // ---- panels --------------------------------------------------------

  function renderPosture() {
    const meta = data?.meta;
    if (!meta) {
      replaceChildren(posture);
      updated.textContent = '';
      return;
    }
    replaceChildren(
      posture,
      h('span', {
        class: 'ti-dot ti-dot-ok',
        title: 'Crucix reporting',
      }),
      h('span', {
        class: 'ti-dim',
        text: `${meta.sourcesOk}/${meta.sourcesQueried} sources`,
      }),
    );
    updated.textContent = `Swept ${formatAgo(Date.parse(meta.timestamp))}`;
  }

  function marketsCard() {
    const m = data.markets;
    if (!m) return null;
    const group = (label, rows) =>
      rows && rows.length
        ? h(
            'div',
            { class: 'osint-quote-group' },
            h('h4', { class: 'osint-group-title', text: label }),
            rows.map(quoteRow),
          )
        : null;
    const hasVix = Number.isFinite(m.vix?.value);
    const groups = ['indexes', 'commodities', 'crypto', 'rates'];
    // Crucix's market source (yfinance) can come back empty on a sweep; hide
    // the card entirely rather than show an empty shell.
    if (!hasVix && !groups.some((key) => (m[key] || []).length)) return null;
    const vix = hasVix
      ? h(
          'div',
          { class: 'osint-vix' },
          h('span', { class: 'ti-dim', text: 'VIX volatility' }),
          h('span', { class: 'osint-quote-price', text: nf(m.vix.value) }),
          changeChip(m.vix.changePct),
        )
      : null;
    return card(
      'Markets',
      vix,
      group('Indexes', m.indexes),
      group('Commodities', m.commodities),
      group('Crypto', m.crypto),
      group('Rates & credit', m.rates),
    );
  }

  function energyCard() {
    const e = data.energy;
    const metals = data.metals;
    const line = (label, value, recent) =>
      Number.isFinite(value)
        ? h(
            'div',
            { class: 'osint-stat-line' },
            h('span', { class: 'osint-stat-label', text: label }),
            h('span', { class: 'osint-quote-price', text: nf(value) }),
            recent ? sparkline(recent) : null,
          )
        : null;
    const lines = [
      line('WTI crude', e?.wti, e?.wtiRecent),
      line('Brent crude', e?.brent),
      line('Natural gas', e?.natgas),
      line('Gold', metals?.gold, metals?.goldRecent),
      line('Silver', metals?.silver, metals?.silverRecent),
    ].filter(Boolean);
    return lines.length ? card('Energy & metals', ...lines) : null;
  }

  function macroCard() {
    const parts = [];
    const debt = Number(data.treasury?.totalDebt);
    if (Number.isFinite(debt) && debt > 0)
      parts.push(
        h(
          'div',
          { class: 'osint-stat-line' },
          h('span', { class: 'osint-stat-label', text: 'US national debt' }),
          h('span', {
            class: 'osint-quote-price',
            text: `$${nf(debt / 1e12, 2)}T`,
          }),
        ),
      );
    for (const row of data.bls || [])
      parts.push(
        h(
          'div',
          { class: 'osint-stat-line' },
          h('span', { class: 'osint-stat-label', text: row.label }),
          h('span', { class: 'osint-quote-price', text: nf(row.value) }),
          changeChip(row.momChangePct),
        ),
      );
    if (data.gscpi?.value != null)
      parts.push(
        h(
          'div',
          { class: 'osint-stat-line' },
          h('span', {
            class: 'osint-stat-label',
            text: 'Global supply-chain pressure',
          }),
          h('span', { class: 'osint-quote-price', text: nf(data.gscpi.value) }),
          badge(data.gscpi.interpretation || '', 'ti-sev-medium'),
        ),
      );
    return parts.length ? card('Macro & supply chain', ...parts) : null;
  }

  function chokepointsCard() {
    const points = data.chokepoints || [];
    if (!points.length) return null;
    return card(
      'Strategic chokepoints',
      h(
        'ul',
        { class: 'ti-list' },
        points.map((p) =>
          h(
            'li',
            { class: 'osint-choke' },
            h('span', { class: 'osint-choke-name', text: p.label }),
            h('span', { class: 'ti-dim', text: p.note || '' }),
            h('span', {
              class: 'ti-dim ti-mono',
              text: `${p.lat.toFixed(1)}, ${p.lon.toFixed(1)}`,
            }),
          ),
        ),
      ),
      h('p', {
        class: 'ti-note',
        text: 'Globe plotting of these and of live conflict events is the next step.',
      }),
    );
  }

  function conflictCard() {
    const a = data.acled;
    if (!a) return null;
    if (!a.totalEvents)
      return card(
        'Armed conflict (ACLED)',
        h('p', {
          class: 'ti-dim',
          text: 'No events in the current window (ACLED needs credentials in Crucix for full coverage).',
        }),
      );
    const types = Object.entries(a.byType || {})
      .sort((x, y) => y[1] - x[1])
      .slice(0, 6);
    return card(
      'Armed conflict (ACLED)',
      h(
        'div',
        { class: 'ti-tiles osint-mini-tiles' },
        h(
          'div',
          { class: 'ti-tile ti-tile-alert' },
          h('span', {
            class: 'ti-tile-value',
            text: formatNumber(a.totalEvents),
          }),
          h('span', { class: 'ti-tile-label', text: 'Events' }),
        ),
        h(
          'div',
          { class: 'ti-tile' },
          h('span', {
            class: 'ti-tile-value',
            text: formatNumber(a.totalFatalities),
          }),
          h('span', { class: 'ti-tile-label', text: 'Fatalities' }),
        ),
      ),
      types.length
        ? h(
            'ul',
            { class: 'ti-bars' },
            types.map(([name, count]) =>
              h(
                'li',
                {},
                h(
                  'div',
                  { class: 'ti-bar-row' },
                  h('span', { class: 'ti-bar-label', text: name }),
                  h('span', {
                    class: 'ti-bar-value',
                    text: formatNumber(count),
                  }),
                ),
              ),
            ),
          )
        : null,
    );
  }

  function gdeltCard() {
    const g = data.gdelt;
    if (!g || !g.totalArticles) return null;
    return card(
      'Global events (GDELT)',
      h(
        'div',
        { class: 'ti-tiles osint-mini-tiles' },
        ['conflicts', 'economy', 'health', 'crisis'].map((key) =>
          h(
            'div',
            { class: 'ti-tile' },
            h('span', {
              class: 'ti-tile-value',
              text: formatNumber(g[key] || 0),
            }),
            h('span', { class: 'ti-tile-label', text: key }),
          ),
        ),
      ),
      g.topTitles && g.topTitles.length
        ? h(
            'ul',
            { class: 'ti-list' },
            g.topTitles.slice(0, 8).map((title) =>
              h('li', {
                class: 'osint-news-item',
                text: decodeEntities(title),
              }),
            ),
          )
        : null,
    );
  }

  function defenseCard() {
    const rows = data.defense || [];
    if (!rows.length) return null;
    return card(
      'Defense spending',
      h(
        'ul',
        { class: 'ti-list' },
        rows.slice(0, 8).map((row) =>
          h(
            'li',
            { class: 'osint-defense' },
            h('span', {
              class: 'osint-quote-price',
              text: `$${nf(row.amount / 1e9, 2)}B`,
            }),
            h('span', { class: 'osint-defense-name', text: row.recipient }),
          ),
        ),
      ),
    );
  }

  function newsCard() {
    const items = data.news || data.newsFeed || [];
    if (!items.length) return null;
    return card(
      'Geopolitical news',
      h(
        'div',
        { class: 'osint-news' },
        items
          .slice(0, 40)
          .map((item) =>
            h(
              'article',
              { class: 'osint-news-row' },
              h(
                'span',
                { class: 'osint-news-title' },
                externalLink(item.url, decodeEntities(item.title)) ||
                  decodeEntities(item.title),
              ),
              h(
                'span',
                { class: 'ti-dim osint-news-meta' },
                `${item.source || ''}${item.date ? ` · ${formatAgo(Date.parse(item.date))}` : ''}`,
              ),
            ),
          ),
      ),
    );
  }

  function deltaCard() {
    const delta = data.delta;
    const changes = Array.isArray(delta)
      ? delta
      : delta && Array.isArray(delta.changes)
        ? delta.changes
        : [];
    if (!changes.length) return null;
    return card(
      'What changed',
      h(
        'ul',
        { class: 'ti-list' },
        changes.slice(0, 12).map((c) =>
          h('li', {
            class: 'osint-news-item',
            text: typeof c === 'string' ? c : c.message || JSON.stringify(c),
          }),
        ),
      ),
    );
  }

  // ---- render --------------------------------------------------------

  function render({ loading: isLoading = false, error = null }) {
    renderPosture();
    if (error) {
      const starting = error.code === 'crucix_unavailable';
      replaceChildren(
        main,
        h(
          'div',
          { class: 'ti-state' },
          h('p', {
            class: 'ti-lead',
            text: starting
              ? 'The Crucix OSINT engine is not running.'
              : error.message,
          }),
          starting
            ? h(
                'div',
                { class: 'ti-callout osint-start' },
                h('p', { text: 'Start it in a terminal, then refresh:' }),
                h('pre', {
                  class: 'osint-cmd',
                  text: 'cd Kaisel-Crucix\nnpm install   # first time only\nnpm start',
                }),
                h('p', {
                  class: 'ti-dim',
                  text: `Expected at ${error.url || 'http://localhost:3117'}. Set CRUCIX_URL in .env to change it.`,
                }),
              )
            : null,
          h(
            'button',
            {
              class: 'ti-button',
              type: 'button',
              onClick: () => ensureLoaded(true),
            },
            'Retry',
          ),
        ),
      );
      return;
    }
    if (isLoading && !data) {
      replaceChildren(
        main,
        h(
          'div',
          { class: 'ti-state' },
          h('div', { class: 'ti-spinner', 'aria-hidden': 'true' }),
          h('p', { text: 'Reading the OSINT sweep from Crucix…' }),
        ),
      );
      return;
    }
    if (!data) return;
    replaceChildren(
      main,
      h(
        'div',
        { class: 'ti-view osint-grid' },
        marketsCard(),
        energyCard(),
        macroCard(),
        conflictCard(),
        gdeltCard(),
        chokepointsCard(),
        defenseCard(),
        deltaCard(),
        newsCard(),
      ),
    );
    main.scrollTop = 0;
  }

  // ---- wiring --------------------------------------------------------

  for (const button of switcher.querySelectorAll('button[data-view]'))
    button.addEventListener('click', () => show(button.dataset.view));
  refreshButton.addEventListener('click', () => ensureLoaded(true));
  root.addEventListener('keydown', (event) => event.stopPropagation());
  osintStatus();
}
