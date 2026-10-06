import {
  h,
  replaceChildren,
  externalLink,
  formatDate,
  formatNumber,
  formatPercent,
  renderMarkdown,
} from './dom.js';
import { badge } from './views.js';
import { searchDevices, loadExposure, askExposureAnalyst } from './store.js';

// Persist the last asset across tab switches so returning to Exposure keeps it.
const session = {
  query: '',
  cpe: null,
  exposure: null,
  activeLayer: null,
  brief: null,
  briefHasKey: null,
};

const EXAMPLES = [
  {
    label: 'OpenSSL 1.0.1',
    cpe: 'cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*',
  },
  {
    label: 'Apache Log4j 2.14.1',
    cpe: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
  },
  {
    label: 'Windows 10 22H2',
    cpe: 'cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:*:*',
  },
  { label: 'Android 13', cpe: 'cpe:2.3:o:google:android:13.0:*:*:*:*:*:*:*' },
];

const sevClass = (cvss) =>
  !Number.isFinite(cvss)
    ? 'ti-sev-none'
    : cvss >= 9
      ? 'ti-sev-critical'
      : cvss >= 7
        ? 'ti-sev-high'
        : cvss >= 4
          ? 'ti-sev-medium'
          : 'ti-sev-low';

const cvssBadge = (cvss) =>
  h('span', {
    class: `ti-badge ${sevClass(cvss)}`,
    text: Number.isFinite(cvss) ? cvss.toFixed(1) : '—',
  });

const nvdLink = (id) =>
  externalLink(`https://nvd.nist.gov/vuln/detail/${id}`, id) || id;

const cweLink = (cwe) =>
  externalLink(
    `https://cwe.mitre.org/data/definitions/${cwe.replace(/\D/g, '')}.html`,
    cwe,
  ) || cwe;

const titleCase = (value) =>
  String(value || '').replace(/\b\w/g, (ch) => ch.toUpperCase());

/** Vendor + product, but drop a vendor that just repeats the product. */
const assetName = (asset) => {
  const vendor = asset.vendor || '';
  const product = asset.product || '';
  if (!vendor || vendor === product || product.includes(vendor)) return product;
  return `${vendor} ${product}`;
};

const severityRank = {
  'Very High': 5,
  High: 4,
  Medium: 3,
  Low: 2,
  'Very Low': 1,
};
const patternSevClass = (severity) =>
  (severityRank[severity] || 0) >= 4
    ? 'ti-sev-high'
    : severity === 'Medium'
      ? 'ti-sev-medium'
      : 'ti-sev-low';

export function exposureView(ctx) {
  const root = h('div', { class: 'ti-view ti-exposure' });
  const content = h('div', { class: 'ti-exposure-content' });

  // ---- device search -------------------------------------------------
  const input = h('input', {
    class: 'ti-input',
    type: 'search',
    placeholder:
      'Name a device or software — e.g. OpenSSL 3.0, iPhone iOS 17, Cisco IOS',
    'aria-label': 'Search for a device or software',
    autocomplete: 'off',
  });
  input.value = session.query;
  const suggestions = h('div', { class: 'ti-search-results', hidden: true });

  let searchSeq = 0;
  let debounce = null;
  const runSearch = (value) => {
    const seq = ++searchSeq;
    searchDevices(value)
      .then((results) => {
        if (seq !== searchSeq) return;
        if (!results.length) {
          replaceChildren(
            suggestions,
            h('p', {
              class: 'ti-dim ti-search-none',
              text: 'No matching products in NVD.',
            }),
          );
        } else {
          replaceChildren(
            suggestions,
            results.map((r) =>
              h(
                'button',
                {
                  class: 'ti-search-hit',
                  type: 'button',
                  onClick: () => {
                    input.value = r.title;
                    session.query = r.title;
                    suggestions.hidden = true;
                    select(r.cpeName);
                  },
                },
                h('span', { class: 'ti-search-kind', text: r.partLabel }),
                h('span', { class: 'ti-search-label', text: r.title }),
                h('span', {
                  class: 'ti-dim',
                  text: r.deprecated ? 'deprecated CPE' : r.cpeName,
                }),
              ),
            ),
          );
        }
        suggestions.hidden = false;
      })
      .catch(() => {
        replaceChildren(
          suggestions,
          h('p', {
            class: 'ti-dim ti-search-none',
            text: 'NVD product search is unavailable right now.',
          }),
        );
        suggestions.hidden = false;
      });
  };
  input.addEventListener('input', () => {
    session.query = input.value.trim();
    clearTimeout(debounce);
    if (session.query.length < 2) {
      suggestions.hidden = true;
      return;
    }
    debounce = setTimeout(() => runSearch(session.query), 280);
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') suggestions.hidden = true;
  });
  root.addEventListener('click', (event) => {
    if (!event.target.closest('.ti-exposure-search')) suggestions.hidden = true;
  });

  const searchBar = h(
    'div',
    { class: 'ti-exposure-search' },
    input,
    suggestions,
  );

  // ---- load one asset ------------------------------------------------
  function select(cpe) {
    session.cpe = cpe;
    session.exposure = null;
    session.activeLayer = null;
    session.brief = null;
    renderContent({ loading: true });
    loadExposure(cpe)
      .then((exposure) => {
        if (session.cpe !== cpe) return;
        session.exposure = exposure;
        renderContent({});
      })
      .catch((error) => {
        if (session.cpe !== cpe) return;
        renderContent({ error: error.message || 'Could not load this asset.' });
      });
  }

  // ---- analyst triage ------------------------------------------------
  function runBrief() {
    if (!session.cpe || session.briefBusy) return;
    session.briefBusy = true;
    renderContent({});
    askExposureAnalyst(session.cpe, null)
      .then((answer) => {
        session.brief = { ...answer, error: null };
      })
      .catch((error) => {
        if (error.code === 'no_key') session.briefHasKey = false;
        session.brief = { error: error.message };
      })
      .finally(() => {
        session.briefBusy = false;
        renderContent({});
      });
  }

  // ---- render --------------------------------------------------------
  function statTile(value, label, tone = '') {
    return h(
      'div',
      { class: `ti-tile ${tone}`.trim() },
      h('span', { class: 'ti-tile-value', text: value }),
      h('span', { class: 'ti-tile-label', text: label }),
    );
  }

  function osiLadder(exposure) {
    const peak = Math.max(1, ...exposure.layers.map((l) => l.count));
    return h(
      'div',
      { class: 'ti-osi' },
      exposure.layers.map((layer) => {
        const active = session.activeLayer === layer.n;
        const empty = layer.count === 0;
        return h(
          'button',
          {
            class: `ti-osi-row${active ? ' ti-osi-active' : ''}${empty ? ' ti-osi-empty' : ''}`,
            type: 'button',
            disabled: empty,
            style: {
              '--ti-heat': String(
                empty ? 0 : 0.12 + 0.55 * (layer.count / peak),
              ),
            },
            onClick: () => {
              session.activeLayer = active ? null : layer.n;
              renderContent({});
            },
          },
          h('span', { class: 'ti-osi-n', text: `L${layer.n}` }),
          h(
            'span',
            { class: 'ti-osi-main' },
            h('span', { class: 'ti-osi-name', text: layer.name }),
            h('span', { class: 'ti-dim ti-osi-blurb', text: layer.blurb }),
          ),
          layer.kev ? badge(`${layer.kev} exploited`, 'ti-sev-critical') : null,
          h('span', { class: 'ti-osi-count', text: formatNumber(layer.count) }),
        );
      }),
    );
  }

  function cveRow(cve) {
    return h(
      'div',
      { class: 'ti-cve-row' },
      h(
        'div',
        { class: 'ti-cve-head' },
        cvssBadge(cve.cvss),
        h('span', { class: 'ti-mono ti-cve-id' }, nvdLink(cve.id)),
        cve.kev ? badge('exploited', 'ti-sev-critical') : null,
        Number.isFinite(cve.epss)
          ? h('span', {
              class: 'ti-dim',
              text: `EPSS ${formatPercent(cve.epss)}`,
            })
          : null,
        h('span', { class: 'ti-dim ti-cve-layer', text: `L${cve.osiLayer}` }),
      ),
      h('p', { class: 'ti-cve-desc', text: cve.description }),
      cve.cwes.length
        ? h(
            'div',
            { class: 'ti-chips' },
            cve.cwes.map((cwe) =>
              h('span', { class: 'ti-badge' }, cweLink(cwe)),
            ),
          )
        : null,
    );
  }

  function techniqueChip(id) {
    const byId = ctx.index?.techniqueById;
    // Open the technique in the drawer; if a sub-technique is not in the
    // loaded set, fall back to its parent, then to the ATT&CK site.
    const parent = id.split('.')[0];
    const target = byId?.has(id) ? id : byId?.has(parent) ? parent : null;
    if (target) {
      const technique = byId.get(target);
      return h('button', {
        class: 'ti-chip',
        type: 'button',
        text: `${id} ${technique.name}`,
        onClick: () => ctx.open('technique', target),
      });
    }
    const url = `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
    return externalLink(url, id);
  }

  function patternCard(pattern) {
    const body = h('div', { class: 'ti-pattern-body', hidden: true });
    let built = false;
    const toggle = h(
      'button',
      {
        class: 'ti-pattern-head',
        type: 'button',
        'aria-expanded': 'false',
        onClick: () => {
          const open = body.hidden;
          if (open && !built) {
            built = true;
            replaceChildren(
              body,
              pattern.description
                ? h('p', { text: pattern.description })
                : null,
              pattern.mitigations
                ? h(
                    'p',
                    { class: 'ti-pattern-mit' },
                    h('strong', { text: 'Mitigation: ' }),
                    pattern.mitigations,
                  )
                : null,
              pattern.attack.length
                ? h(
                    'div',
                    { class: 'ti-related' },
                    h('h4', { text: 'ATT&CK techniques' }),
                    h(
                      'div',
                      { class: 'ti-chips' },
                      pattern.attack.map(techniqueChip),
                    ),
                  )
                : h('p', {
                    class: 'ti-dim',
                    text: 'No ATT&CK technique mapped.',
                  }),
              externalLink(
                `https://capec.mitre.org/data/definitions/${pattern.id.replace(/\D/g, '')}.html`,
                'CAPEC reference',
              ),
            );
          }
          body.hidden = !open;
          toggle.setAttribute('aria-expanded', String(open));
        },
      },
      h('span', {
        class: `ti-badge ${patternSevClass(pattern.severity)}`,
        text: pattern.severity || '—',
      }),
      h('span', { class: 'ti-pattern-name', text: pattern.name }),
      h('span', { class: 'ti-dim', text: `${pattern.attack.length} ATT&CK` }),
    );
    return h('div', { class: 'ti-pattern' }, toggle, body);
  }

  function renderExposure(exposure) {
    const layerName = session.activeLayer
      ? exposure.layers.find((l) => l.n === session.activeLayer)?.name
      : null;
    const cves = session.activeLayer
      ? exposure.cves.filter((cve) => cve.osiLayer === session.activeLayer)
      : exposure.cves;

    const briefPanel = h('div', { class: 'ti-exposure-brief' });
    if (session.briefHasKey === false)
      briefPanel.append(
        h(
          'div',
          { class: 'ti-callout' },
          h('strong', { text: 'The analyst needs an Anthropic API key. ' }),
          'Switch to the globe, open POWER UP (bottom right) and paste a key under ANTHROPIC.',
        ),
      );
    else if (session.brief?.error)
      briefPanel.append(
        h(
          'div',
          { class: 'ti-chat-msg ti-chat-error' },
          h('p', { text: session.brief.error }),
        ),
      );
    else if (session.brief)
      briefPanel.append(
        h(
          'article',
          { class: 'ti-chat-msg ti-chat-analyst' },
          renderMarkdown(session.brief.text),
          h('p', { class: 'ti-dim ti-chat-meta', text: session.brief.model }),
        ),
      );

    return h(
      'div',
      { class: 'ti-exposure-report' },
      // Asset header
      h(
        'header',
        { class: 'ti-asset-head' },
        h(
          'div',
          {},
          h('h2', {
            class: 'ti-asset-title',
            text: titleCase(assetName(exposure.asset)) || 'Asset',
          }),
          h(
            'p',
            { class: 'ti-dim' },
            `${exposure.asset.partLabel}${exposure.asset.version ? ` · version ${exposure.asset.version}` : ''}`,
          ),
          h('p', {
            class: 'ti-mono ti-dim ti-asset-cpe',
            text: exposure.asset.cpeName,
          }),
        ),
        h(
          'button',
          {
            class: 'ti-button ti-button-accent',
            type: 'button',
            disabled: session.briefBusy,
            onClick: runBrief,
          },
          session.briefBusy
            ? 'Analyzing…'
            : 'Triage this asset with the analyst',
        ),
      ),
      briefPanel,
      // Stat tiles
      h(
        'div',
        { class: 'ti-tiles' },
        statTile(formatNumber(exposure.stats.total), 'Known CVEs'),
        statTile(
          formatNumber(exposure.stats.exploited),
          'Exploited in the wild',
          exposure.stats.exploited ? 'ti-tile-alert' : '',
        ),
        statTile(formatNumber(exposure.stats.critical), 'Critical'),
        statTile(
          exposure.stats.maxEpss ? formatPercent(exposure.stats.maxEpss) : '—',
          'Highest exploit probability',
        ),
        statTile(
          formatNumber(exposure.stats.attackPatterns),
          'Attack patterns',
        ),
        statTile(formatNumber(exposure.stats.techniques), 'ATT&CK techniques'),
      ),
      exposure.stats.analyzed < exposure.stats.total
        ? h('p', {
            class: 'ti-note',
            text: `Analyzing the ${formatNumber(exposure.stats.analyzed)} most severe of ${formatNumber(exposure.stats.total)} CVEs (every exploited one included).`,
          })
        : null,
      // Two columns: OSI + CVEs on the left, exposure route on the right
      h(
        'div',
        { class: 'ti-exposure-grid' },
        h(
          'section',
          { class: 'ti-card' },
          h('h3', {
            class: 'ti-card-title',
            text: 'Exposure across the stack',
          }),
          h('p', {
            class: 'ti-note',
            text: 'Approximate OSI placement. Select a layer to filter the CVEs.',
          }),
          osiLadder(exposure),
        ),
        h(
          'section',
          { class: 'ti-card' },
          h(
            'h3',
            { class: 'ti-card-title' },
            layerName ? `Vulnerabilities · ${layerName}` : 'Vulnerabilities',
          ),
          layerName
            ? h(
                'button',
                {
                  class: 'ti-button ti-clear-filter',
                  type: 'button',
                  onClick: () => {
                    session.activeLayer = null;
                    renderContent({});
                  },
                },
                'Clear layer filter',
              )
            : null,
          h(
            'div',
            { class: 'ti-cve-list' },
            cves.length
              ? cves.map(cveRow)
              : h('p', { class: 'ti-dim', text: 'No CVEs on this layer.' }),
          ),
        ),
      ),
      // Exposure route
      h(
        'section',
        { class: 'ti-card ti-route-card' },
        h('h3', {
          class: 'ti-card-title',
          text: 'Exposure route · CWE → CAPEC → ATT&CK',
        }),
        h('p', {
          class: 'ti-note',
          text: `${formatNumber(exposure.stats.mappedCves)} of ${formatNumber(exposure.stats.analyzed)} analyzed CVEs map to a published attack pattern. Expand a pattern for how it works, its mitigation, and the techniques to watch.`,
        }),
        exposure.chain.patterns.length
          ? h(
              'div',
              { class: 'ti-patterns' },
              exposure.chain.patterns.map(patternCard),
            )
          : h('p', {
              class: 'ti-dim',
              text: "No attack patterns are mapped to this asset's weaknesses.",
            }),
        exposure.chain.uncoveredCwes.length
          ? h(
              'div',
              { class: 'ti-uncovered' },
              h('h4', {
                text: `Weaknesses without a mapped pattern · ${exposure.chain.uncoveredCwes.length}`,
              }),
              h(
                'div',
                { class: 'ti-chips' },
                exposure.chain.uncoveredCwes.map((cwe) =>
                  h('span', { class: 'ti-badge' }, cweLink(cwe)),
                ),
              ),
            )
          : null,
      ),
      exposure.capecVersion
        ? h('p', {
            class: 'ti-note',
            text: `Attack-pattern mapping from MITRE CAPEC (${exposure.capecVersion}). CVE and EPSS data from NVD and FIRST. All sources public.`,
          })
        : null,
    );
  }

  function renderContent({ loading = false, error = null }) {
    if (loading) {
      replaceChildren(
        content,
        h(
          'div',
          { class: 'ti-state' },
          h('div', { class: 'ti-spinner', 'aria-hidden': 'true' }),
          h('p', { text: "Mapping this asset's exposure from NVD…" }),
          h('p', {
            class: 'ti-dim',
            text: 'Pulling its CVEs and walking the CWE → CAPEC → ATT&CK chain.',
          }),
        ),
      );
      return;
    }
    if (error) {
      replaceChildren(
        content,
        h(
          'div',
          { class: 'ti-state' },
          h('p', { text: error }),
          h(
            'button',
            {
              class: 'ti-button',
              type: 'button',
              onClick: () => select(session.cpe),
            },
            'Try again',
          ),
        ),
      );
      return;
    }
    if (session.exposure) {
      replaceChildren(content, renderExposure(session.exposure));
      return;
    }
    // Empty state
    replaceChildren(
      content,
      h(
        'div',
        { class: 'ti-exposure-empty' },
        h('p', {
          class: 'ti-lead',
          text: 'Profile a device or piece of software.',
        }),
        h('p', {
          class: 'ti-dim',
          text: 'Enter what you know — a product and version, or firmware — and see its known exposure: the CVEs against it, how severe and how likely to be exploited, and the weakness → attack-pattern → ATT&CK-technique route, laid across the OSI stack.',
        }),
        h('p', { class: 'ti-dim ti-examples-label', text: 'Try one:' }),
        h(
          'div',
          { class: 'ti-chips ti-examples' },
          EXAMPLES.map((ex) =>
            h('button', {
              class: 'ti-chip',
              type: 'button',
              text: ex.label,
              onClick: () => {
                input.value = ex.label;
                session.query = ex.label;
                suggestions.hidden = true;
                select(ex.cpe);
              },
            }),
          ),
        ),
      ),
    );
  }

  root.append(searchBar, content);
  renderContent({});
  return root;
}
