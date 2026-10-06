import {
  h,
  replaceChildren,
  externalLink,
  formatAgo,
  formatDate,
  formatNumber,
  formatPercent,
} from './dom.js';

const PAGE = 150;

const severityClass = (cvss) =>
  !Number.isFinite(cvss)
    ? 'ti-sev-none'
    : cvss >= 9
      ? 'ti-sev-critical'
      : cvss >= 7
        ? 'ti-sev-high'
        : cvss >= 4
          ? 'ti-sev-medium'
          : 'ti-sev-low';

export const badge = (text, tone = '') =>
  h('span', { class: `ti-badge ${tone}`.trim(), text });

const cvssBadge = (cvss) =>
  h('span', {
    class: `ti-badge ${severityClass(cvss)}`,
    text: Number.isFinite(cvss) ? cvss.toFixed(1) : '—',
  });

function section(title, ...children) {
  return h(
    'section',
    { class: 'ti-card' },
    h('h3', { class: 'ti-card-title', text: title }),
    ...children,
  );
}

function barList(rows, { onPick, total } = {}) {
  const max = total || Math.max(1, ...rows.map((row) => row.count));
  return h(
    'ul',
    { class: 'ti-bars' },
    rows.map((row) => {
      const label = h('span', { class: 'ti-bar-label', text: row.name });
      const inner = [
        label,
        h('span', { class: 'ti-bar-track' }, [
          h('span', {
            class: 'ti-bar-fill',
            style: { width: `${Math.max(2, (row.count / max) * 100)}%` },
          }),
        ]),
        h('span', { class: 'ti-bar-value', text: formatNumber(row.count) }),
      ];
      return h(
        'li',
        {},
        onPick
          ? h(
              'button',
              {
                class: 'ti-bar-row',
                type: 'button',
                onClick: () => onPick(row),
              },
              inner,
            )
          : h('div', { class: 'ti-bar-row' }, inner),
      );
    }),
  );
}

/**
 * A table whose rows open an entity. `columns` are {label, cell(row), sort?(row)}.
 * Rows render in pages so a few thousand indicators stay responsive.
 */
function entityTable({ columns, rows, onOpen, empty }) {
  let sortIndex = -1;
  let descending = true;
  let shown = PAGE;
  const body = h('tbody');
  const more = h('button', { class: 'ti-more', type: 'button' });
  const headers = columns.map((column, i) => {
    if (!column.sort) return h('th', { scope: 'col', text: column.label });
    const button = h('button', {
      class: 'ti-sort',
      type: 'button',
      text: column.label,
    });
    button.addEventListener('click', () => {
      descending = sortIndex === i ? !descending : true;
      sortIndex = i;
      shown = PAGE;
      render();
    });
    return h('th', { scope: 'col' }, button);
  });

  function sorted() {
    if (sortIndex < 0) return rows;
    const key = columns[sortIndex].sort;
    const direction = descending ? -1 : 1;
    return [...rows].sort((a, b) => {
      const av = key(a);
      const bv = key(b);
      if (av === bv) return 0;
      if (av === null || av === undefined || av === '') return 1;
      if (bv === null || bv === undefined || bv === '') return -1;
      return (av > bv ? 1 : -1) * direction;
    });
  }

  function render() {
    headers.forEach((th, i) => {
      if (i === sortIndex)
        th.setAttribute('aria-sort', descending ? 'descending' : 'ascending');
      else th.removeAttribute('aria-sort');
    });
    const list = sorted();
    replaceChildren(
      body,
      list.slice(0, shown).map((row) =>
        h(
          'tr',
          {
            tabindex: '0',
            onClick: () => onOpen(row),
            onKeydown: (event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                onOpen(row);
              }
            },
          },
          columns.map((column) =>
            h('td', { class: column.class || '' }, column.cell(row)),
          ),
        ),
      ),
    );
    if (!list.length)
      body.append(
        h(
          'tr',
          { class: 'ti-empty-row' },
          h('td', {
            colspan: columns.length,
            text: empty || 'Nothing matches.',
          }),
        ),
      );
    more.hidden = list.length <= shown;
    more.textContent = `Show more (${formatNumber(list.length - shown)} remaining)`;
  }
  more.addEventListener('click', () => {
    shown += PAGE * 2;
    render();
  });
  render();
  return h(
    'div',
    { class: 'ti-table-wrap' },
    h(
      'table',
      { class: 'ti-table' },
      h('thead', {}, h('tr', {}, headers)),
      body,
    ),
    more,
  );
}

function toolbar(...controls) {
  return h('div', { class: 'ti-toolbar' }, controls);
}

function searchInput(placeholder, onInput) {
  return h('input', {
    class: 'ti-input',
    type: 'search',
    placeholder,
    'aria-label': placeholder,
    onInput: (event) => onInput(event.target.value.trim().toLowerCase()),
  });
}

function select(label, options, onChange) {
  return h(
    'select',
    {
      class: 'ti-input',
      'aria-label': label,
      onChange: (event) => onChange(event.target.value),
    },
    options.map(([value, text]) => h('option', { value, text })),
  );
}

function toggle(label, onChange) {
  const input = h('input', {
    type: 'checkbox',
    onChange: (event) => onChange(event.target.checked),
  });
  return h('label', { class: 'ti-toggle' }, input, label);
}

/** A filtered list: rebuilds the table whenever a control changes. */
function filteredView(controls, build) {
  const host = h('div');
  const refresh = () => replaceChildren(host, build());
  const view = h('div', { class: 'ti-view' }, toolbar(controls(refresh)), host);
  refresh();
  return view;
}

// ---------------------------------------------------------------- overview

export function overviewView(ctx) {
  const { data, attack } = ctx.index;
  const { stats } = data;
  const tile = (value, label, tab, tone = '') =>
    h(
      'button',
      {
        class: `ti-tile ${tone}`.trim(),
        type: 'button',
        onClick: () => ctx.go(tab),
      },
      h('span', { class: 'ti-tile-value', text: formatNumber(value) }),
      h('span', { class: 'ti-tile-label', text: label }),
    );

  const peak = Math.max(1, ...data.kevTimeline.map((day) => day.count));
  const timeline = h(
    'div',
    {
      class: 'ti-spark',
      role: 'img',
      'aria-label':
        'Vulnerabilities added to the exploited list per day, last 30 days',
    },
    data.kevTimeline.map((day) =>
      h('span', {
        class: 'ti-spark-bar',
        title: `${day.date}: ${day.count}`,
        style: {
          height: `${day.count ? Math.max(8, (day.count / peak) * 100) : 2}%`,
        },
      }),
    ),
  );

  const exploited = data.vulnerabilities.filter((v) => v.kev).slice(0, 8);
  const activeGroups = [...ctx.index.activeGroups.entries()]
    .map(([id, families]) => ({ group: ctx.index.groupById.get(id), families }))
    .filter((row) => row.group)
    .sort(
      (a, b) =>
        b.families.length - a.families.length ||
        a.group.name.localeCompare(b.group.name),
    )
    .slice(0, 8);

  return h(
    'div',
    { class: 'ti-view' },
    h(
      'div',
      { class: 'ti-tiles' },
      tile(
        stats.kevLast30,
        'Newly exploited · 30 days',
        'vulnerabilities',
        'ti-tile-alert',
      ),
      tile(stats.criticalCves, 'Critical CVEs · 7 days', 'vulnerabilities'),
      tile(stats.indicators, 'Live indicators', 'indicators'),
      tile(stats.malwareFamilies, 'Active malware families', 'malware'),
      tile(ctx.index.activeGroups.size, 'Groups linked to activity', 'actors'),
      tile(stats.kevRansomware, 'Exploited by ransomware', 'vulnerabilities'),
    ),
    h(
      'div',
      { class: 'ti-grid' },
      section(
        'Latest exploited vulnerabilities',
        h(
          'ul',
          { class: 'ti-list' },
          exploited.map((v) =>
            h(
              'li',
              {},
              h(
                'button',
                {
                  class: 'ti-list-row',
                  type: 'button',
                  onClick: () => ctx.open('vuln', v.id),
                },
                h('span', { class: 'ti-mono', text: v.id }),
                h('span', {
                  class: 'ti-list-main',
                  text: `${v.vendor} ${v.product}`.trim() || v.title,
                }),
                v.ransomware ? badge('ransomware', 'ti-sev-critical') : null,
                h('span', { class: 'ti-dim', text: formatDate(v.kevAdded) }),
              ),
            ),
          ),
        ),
        h('div', {
          class: 'ti-card-sub',
          text: 'Added to the exploited list, last 30 days',
        }),
        timeline,
      ),
      section(
        'Most active malware',
        barList(
          data.malware
            .slice(0, 10)
            .map((m) => ({ name: m.name, count: m.count })),
          { onPick: (row) => ctx.open('malware', row.name) },
        ),
      ),
      section(
        'Threat groups linked to current activity',
        activeGroups.length
          ? h(
              'ul',
              { class: 'ti-list' },
              activeGroups.map(({ group, families }) =>
                h(
                  'li',
                  {},
                  h(
                    'button',
                    {
                      class: 'ti-list-row',
                      type: 'button',
                      onClick: () => ctx.open('group', group.id),
                    },
                    h('span', { class: 'ti-mono', text: group.id }),
                    h('span', { class: 'ti-list-main', text: group.name }),
                    h('span', {
                      class: 'ti-dim',
                      text: families.slice(0, 2).join(', '),
                    }),
                  ),
                ),
              ),
            )
          : h('p', {
              class: 'ti-dim',
              text: 'No current malware maps to a known group.',
            }),
        h('p', {
          class: 'ti-note',
          text: "A link means the group is known to use malware seen in today's indicators. Shared tools such as Cobalt Strike are used by many groups, so this is a lead, not attribution.",
        }),
      ),
      section(
        'What the indicators are doing',
        barList(
          data.threatTypes
            .slice(0, 6)
            .map((row) => ({ ...row, name: row.name.replace(/_/g, ' ') })),
        ),
      ),
      section('Indicator types', barList(data.indicatorTypes.slice(0, 6))),
      section(
        'Most targeted vendors · 180 days',
        barList(data.topVendors.slice(0, 8)),
      ),
      section(
        'Sources',
        h(
          'ul',
          { class: 'ti-feeds' },
          data.feeds.map((feed) =>
            h(
              'li',
              {},
              h('span', {
                class: `ti-dot ${feed.ok ? (feed.stale ? 'ti-dot-stale' : 'ti-dot-ok') : 'ti-dot-down'}`,
                title: feed.ok
                  ? feed.stale
                    ? 'Serving a saved copy'
                    : 'Live'
                  : 'Unavailable',
              }),
              h(
                'span',
                { class: 'ti-feed-name' },
                externalLink(feed.url, feed.label) || feed.label,
              ),
              h('span', { class: 'ti-dim ti-feed-about', text: feed.about }),
              h('span', {
                class: 'ti-dim',
                text: feed.ok
                  ? `${formatNumber(feed.count)} · ${formatAgo(feed.fetchedAt)}`
                  : 'unavailable',
              }),
            ),
          ),
        ),
        attack.version
          ? h('p', {
              class: 'ti-note',
              text: `ATT&CK Enterprise v${attack.version}. All sources are public and need no key.`,
            })
          : null,
      ),
    ),
  );
}

// --------------------------------------------------------- vulnerabilities

export function vulnerabilitiesView(ctx) {
  const state = { text: '', scope: 'all', ransomware: false };
  return filteredView(
    (refresh) => [
      searchInput('Filter by CVE, vendor or product', (value) => {
        state.text = value;
        refresh();
      }),
      select(
        'Scope',
        [
          ['all', 'All'],
          ['kev', 'Exploited in the wild'],
          ['critical', 'Critical (CVSS 9+)'],
          ['likely', 'Likely exploited (EPSS 10%+)'],
        ],
        (value) => {
          state.scope = value;
          refresh();
        },
      ),
      toggle('Ransomware only', (value) => {
        state.ransomware = value;
        refresh();
      }),
    ],
    () => {
      const rows = ctx.index.data.vulnerabilities.filter((v) => {
        if (state.ransomware && !v.ransomware) return false;
        if (state.scope === 'kev' && !v.kev) return false;
        if (state.scope === 'critical' && !(v.cvss >= 9)) return false;
        if (state.scope === 'likely' && !(v.epss >= 0.1)) return false;
        if (!state.text) return true;
        return `${v.id} ${v.vendor} ${v.product} ${v.title}`
          .toLowerCase()
          .includes(state.text);
      });
      return entityTable({
        rows,
        onOpen: (v) => ctx.open('vuln', v.id),
        empty: 'No vulnerabilities match these filters.',
        columns: [
          {
            label: 'CVE',
            class: 'ti-mono',
            cell: (v) => v.id,
            sort: (v) => v.id,
          },
          {
            label: 'Affected',
            cell: (v) =>
              `${v.vendor} ${v.product}`.trim() || v.description.slice(0, 90),
            sort: (v) => `${v.vendor} ${v.product}`.trim().toLowerCase(),
          },
          {
            label: 'CVSS',
            cell: (v) => cvssBadge(v.cvss),
            sort: (v) => v.cvss,
          },
          {
            label: 'EPSS',
            class: 'ti-num',
            cell: (v) => formatPercent(v.epss),
            sort: (v) => v.epss,
          },
          {
            label: 'Exploited',
            cell: (v) =>
              v.kev
                ? [
                    badge('exploited', 'ti-sev-high'),
                    v.ransomware
                      ? badge('ransomware', 'ti-sev-critical')
                      : null,
                  ]
                : h('span', { class: 'ti-dim', text: '—' }),
            sort: (v) => (v.kev ? 1 : 0) + (v.ransomware ? 1 : 0),
          },
          {
            label: 'Date',
            class: 'ti-dim',
            cell: (v) => formatDate(v.kevAdded || v.published),
            sort: (v) => v.kevAdded || v.published,
          },
          {
            label: 'Patch due',
            class: 'ti-dim',
            cell: (v) => formatDate(v.kevDue),
            sort: (v) => v.kevDue,
          },
        ],
      });
    },
  );
}

// -------------------------------------------------------------- indicators

export function indicatorsView(ctx, preset = {}) {
  const { indicators } = ctx.index.data;
  const state = { text: preset.text || '', type: 'all', source: 'all' };
  const types = [...new Set(indicators.map((i) => i.type))].sort();
  const sources = [...new Set(indicators.map((i) => i.source))].sort();
  return filteredView(
    (refresh) => {
      const input = searchInput('Filter by value, malware or tag', (value) => {
        state.text = value;
        refresh();
      });
      input.value = state.text;
      return [
        input,
        select(
          'Type',
          [['all', 'All types'], ...types.map((t) => [t, t])],
          (value) => {
            state.type = value;
            refresh();
          },
        ),
        select(
          'Source',
          [['all', 'All sources'], ...sources.map((s) => [s, s])],
          (value) => {
            state.source = value;
            refresh();
          },
        ),
      ];
    },
    () => {
      const needle = state.text.toLowerCase();
      const rows = indicators.filter((i) => {
        if (state.type !== 'all' && i.type !== state.type) return false;
        if (state.source !== 'all' && i.source !== state.source) return false;
        if (!needle) return true;
        return `${i.value} ${i.malware} ${i.tags.join(' ')}`
          .toLowerCase()
          .includes(needle);
      });
      return entityTable({
        rows,
        onOpen: (i) => ctx.open('indicator', i.id),
        empty: 'No indicators match these filters.',
        columns: [
          {
            label: 'Indicator',
            class: 'ti-mono ti-wrap',
            cell: (i) => i.value,
            sort: (i) => i.value,
          },
          { label: 'Type', cell: (i) => badge(i.type), sort: (i) => i.type },
          {
            label: 'Activity',
            cell: (i) => i.threat.replace(/_/g, ' ') || '—',
            sort: (i) => i.threat,
          },
          {
            label: 'Malware',
            cell: (i) => i.malware || '—',
            sort: (i) => i.malware.toLowerCase(),
          },
          {
            label: 'Confidence',
            class: 'ti-num',
            cell: (i) =>
              Number.isFinite(i.confidence) ? `${i.confidence}%` : '—',
            sort: (i) => i.confidence,
          },
          {
            label: 'Last seen',
            class: 'ti-dim',
            cell: (i) => formatAgo(i.lastSeen || i.firstSeen),
            sort: (i) => i.lastSeen || i.firstSeen,
          },
          {
            label: 'Source',
            class: 'ti-dim',
            cell: (i) => i.source,
            sort: (i) => i.source,
          },
        ],
      });
    },
  );
}

// ----------------------------------------------------------------- malware

export function malwareView(ctx) {
  const state = { text: '' };
  return filteredView(
    (refresh) => [
      searchInput('Filter malware families', (value) => {
        state.text = value;
        refresh();
      }),
    ],
    () =>
      entityTable({
        rows: ctx.index.data.malware.filter((m) =>
          m.name.toLowerCase().includes(state.text),
        ),
        onOpen: (m) => ctx.open('malware', m.name),
        empty: 'No malware families match.',
        columns: [
          {
            label: 'Family',
            cell: (m) => m.name,
            sort: (m) => m.name.toLowerCase(),
          },
          {
            label: 'Indicators',
            class: 'ti-num',
            cell: (m) => formatNumber(m.count),
            sort: (m) => m.count,
          },
          {
            label: 'Activity',
            cell: (m) =>
              Object.keys(m.threats)
                .map((t) => t.replace(/_/g, ' '))
                .join(', ') || '—',
          },
          {
            label: 'ATT&CK',
            class: 'ti-mono',
            cell: (m) =>
              m.attackId || h('span', { class: 'ti-dim', text: '—' }),
            sort: (m) => m.attackId,
          },
          {
            label: 'Linked groups',
            class: 'ti-num',
            cell: (m) => (m.groups.length ? m.groups.length : '—'),
            sort: (m) => m.groups.length,
          },
          {
            label: 'Last seen',
            class: 'ti-dim',
            cell: (m) => formatAgo(m.lastSeen),
            sort: (m) => m.lastSeen,
          },
        ],
      }),
  );
}

// ------------------------------------------------------------------ actors

export function actorsView(ctx) {
  const state = { text: '', active: false };
  const { activeGroups } = ctx.index;
  return filteredView(
    (refresh) => [
      searchInput('Filter by name, alias or ID', (value) => {
        state.text = value;
        refresh();
      }),
      toggle('Linked to current activity', (value) => {
        state.active = value;
        refresh();
      }),
    ],
    () =>
      entityTable({
        rows: ctx.index.attack.groups.filter((g) => {
          if (state.active && !activeGroups.has(g.id)) return false;
          if (!state.text) return true;
          return `${g.id} ${g.name} ${g.aliases.join(' ')}`
            .toLowerCase()
            .includes(state.text);
        }),
        onOpen: (g) => ctx.open('group', g.id),
        empty: ctx.index.attack.groups.length
          ? 'No groups match.'
          : 'The ATT&CK knowledge base could not be loaded.',
        columns: [
          {
            label: 'ID',
            class: 'ti-mono',
            cell: (g) => g.id,
            sort: (g) => g.id,
          },
          {
            label: 'Group',
            cell: (g) => g.name,
            sort: (g) => g.name.toLowerCase(),
          },
          {
            label: 'Also known as',
            class: 'ti-dim',
            cell: (g) => g.aliases.slice(0, 4).join(', ') || '—',
          },
          {
            label: 'Techniques',
            class: 'ti-num',
            cell: (g) => g.techniques.length,
            sort: (g) => g.techniques.length,
          },
          {
            label: 'Software',
            class: 'ti-num',
            cell: (g) => g.software.length,
            sort: (g) => g.software.length,
          },
          {
            label: 'Current activity',
            cell: (g) =>
              activeGroups.has(g.id)
                ? badge(
                    activeGroups.get(g.id).slice(0, 2).join(', '),
                    'ti-sev-high',
                  )
                : h('span', { class: 'ti-dim', text: '—' }),
            sort: (g) => (activeGroups.get(g.id) || []).length,
          },
        ],
      }),
  );
}

// ------------------------------------------------------------------ matrix

export function matrixView(ctx) {
  const { attack } = ctx.index;
  if (!attack.tactics.length)
    return h(
      'div',
      { class: 'ti-view' },
      h('p', {
        class: 'ti-dim',
        text: 'The ATT&CK knowledge base could not be loaded.',
      }),
    );
  const state = { scope: 'all' };
  const host = h('div', { class: 'ti-matrix-scroll' });

  function build() {
    // In "active" scope a technique counts only the groups linked to malware
    // seen in today's indicators.
    const weight = (technique) =>
      state.scope === 'active'
        ? technique.groups.filter((id) => ctx.index.activeGroups.has(id)).length
        : technique.groups.length;
    const parents = attack.techniques.filter((t) => !t.subtechnique);
    const peak = Math.max(1, ...parents.map(weight));
    replaceChildren(
      host,
      h(
        'div',
        {
          class: 'ti-matrix',
          style: {
            gridTemplateColumns: `repeat(${attack.tactics.length}, minmax(132px, 1fr))`,
          },
        },
        attack.tactics.map((tactic) => {
          const cells = parents
            .filter((t) => t.tactics.includes(tactic.key))
            .sort(
              (a, b) => weight(b) - weight(a) || a.name.localeCompare(b.name),
            );
          return h(
            'div',
            { class: 'ti-matrix-col' },
            h(
              'div',
              { class: 'ti-matrix-head' },
              h('strong', { text: tactic.name }),
              h('span', { class: 'ti-dim', text: `${cells.length}` }),
            ),
            cells.map((technique) => {
              const count = weight(technique);
              return h(
                'button',
                {
                  class: 'ti-matrix-cell',
                  type: 'button',
                  title: `${technique.id} · used by ${count} group${count === 1 ? '' : 's'}`,
                  style: {
                    '--ti-heat': String(
                      count ? 0.12 + 0.6 * (count / peak) : 0,
                    ),
                  },
                  onClick: () => ctx.open('technique', technique.id),
                },
                h('span', { text: technique.name }),
                count
                  ? h('span', { class: 'ti-matrix-count', text: String(count) })
                  : null,
              );
            }),
          );
        }),
      ),
    );
  }
  build();
  return h(
    'div',
    { class: 'ti-view' },
    toolbar(
      select(
        'Shading',
        [
          ['all', 'Shade by all known groups'],
          ['active', 'Shade by groups linked to current activity'],
        ],
        (value) => {
          state.scope = value;
          build();
        },
      ),
      h('span', {
        class: 'ti-dim',
        text: 'Brighter cells are used by more groups. Select a technique for detail.',
      }),
    ),
    host,
  );
}
