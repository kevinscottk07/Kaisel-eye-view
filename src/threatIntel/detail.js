import {
  h,
  externalLink,
  formatAgo,
  formatDate,
  formatPercent,
} from './dom.js';
import { badge } from './views.js';

const KIND_LABEL = {
  vuln: 'Vulnerability',
  indicator: 'Indicator',
  malware: 'Malware family',
  group: 'Threat group',
  software: 'ATT&CK software',
  technique: 'ATT&CK technique',
};

function field(label, value) {
  if (value === null || value === undefined || value === '' || value === false)
    return null;
  return h(
    'div',
    { class: 'ti-field' },
    h('dt', { text: label }),
    h('dd', {}, value),
  );
}

function related(title, items, render, limit = 40) {
  if (!items.length) return null;
  return h(
    'div',
    { class: 'ti-related' },
    h('h4', { text: `${title} · ${items.length}` }),
    h('div', { class: 'ti-chips' }, items.slice(0, limit).map(render)),
    items.length > limit
      ? h('p', { class: 'ti-dim', text: `and ${items.length - limit} more` })
      : null,
  );
}

/**
 * Detail for one entity: its own facts, then the entities it connects to.
 * Every related chip opens that entity, which is how an analyst pivots from an
 * indicator to its malware, to the groups using it, to their techniques.
 * @returns {?{kind: string, title: string, body: HTMLElement, question: string}}
 */
export function describeEntity(ctx, kind, id) {
  const { index } = ctx;
  const chip = (targetKind, targetId, label, tone = '') =>
    h('button', {
      class: `ti-chip ${tone}`.trim(),
      type: 'button',
      text: label,
      onClick: () => ctx.open(targetKind, targetId),
    });
  const groupChip = (groupId) => {
    const group = index.groupById.get(groupId);
    return group
      ? chip(
          'group',
          groupId,
          group.name,
          index.activeGroups.has(groupId) ? 'ti-chip-hot' : '',
        )
      : null;
  };
  const softwareChip = (softwareId) => {
    const item = index.softwareById.get(softwareId);
    return item
      ? chip(
          'software',
          softwareId,
          item.name,
          index.activeSoftware.has(softwareId) ? 'ti-chip-hot' : '',
        )
      : null;
  };
  const techniqueChip = (techniqueId) => {
    const technique = index.techniqueById.get(techniqueId);
    return technique
      ? chip('technique', techniqueId, `${techniqueId} ${technique.name}`)
      : null;
  };
  const body = h('div', { class: 'ti-detail' });
  const add = (...nodes) => body.append(...nodes.filter(Boolean));
  const facts = (...fields) =>
    h('dl', { class: 'ti-fields' }, fields.filter(Boolean));

  if (kind === 'vuln') {
    const v = index.vulnById.get(id);
    if (!v) return null;
    add(
      h('div', { class: 'ti-chips' }, [
        v.kev ? badge('exploited in the wild', 'ti-sev-high') : null,
        v.ransomware ? badge('used by ransomware', 'ti-sev-critical') : null,
        v.severity ? badge(v.severity.toLowerCase()) : null,
      ]),
      v.title ? h('p', { class: 'ti-lead', text: v.title }) : null,
      h('p', { text: v.description }),
      facts(
        field('Affected', `${v.vendor} ${v.product}`.trim()),
        field('CVSS', Number.isFinite(v.cvss) ? v.cvss.toFixed(1) : null),
        field('Vector', v.vector),
        field(
          'EPSS',
          Number.isFinite(v.epss)
            ? `${formatPercent(v.epss)} chance of exploitation in 30 days (higher than ${formatPercent(v.epssPercentile)} of CVEs)`
            : null,
        ),
        field('Published', v.published ? formatDate(v.published) : null),
        field('Added to exploited list', v.kevAdded),
        field('Patch due', v.kevDue),
        field('Weakness', v.cwes.join(', ')),
        field('Required action', v.action),
        field(
          'Reference',
          externalLink(`https://nvd.nist.gov/vuln/detail/${v.id}`, 'NVD entry'),
        ),
      ),
    );
    return {
      kind,
      title: v.id,
      body,
      question: `What should I know and do about ${v.id}?`,
    };
  }

  if (kind === 'indicator') {
    const i = index.indicatorById.get(id);
    if (!i) return null;
    const family = i.malware ? index.malwareByName.get(i.malware) : null;
    add(
      h('p', { class: 'ti-mono ti-wrap ti-lead', text: i.value }),
      facts(
        field('Type', i.type),
        field('Activity', i.threat.replace(/_/g, ' ')),
        field(
          'Confidence',
          Number.isFinite(i.confidence) ? `${i.confidence}%` : null,
        ),
        field('Status', i.status),
        field('Country', i.country),
        field('Network', i.asName),
        field('First seen', i.firstSeen ? formatDate(i.firstSeen) : null),
        field('Last seen', i.lastSeen ? formatAgo(i.lastSeen) : null),
        field('Tags', i.tags.join(', ')),
        field('Source', externalLink(i.reference, i.source) || i.source),
      ),
      family
        ? related('Malware', [family], (m) =>
            chip('malware', m.name, m.name, 'ti-chip-hot'),
          )
        : null,
      family
        ? related('Groups known to use it', family.groups, groupChip)
        : null,
    );
    return {
      kind,
      title: i.type,
      body,
      question: `What is the indicator ${i.value} (${i.malware || i.threat}) and how should I respond if I see it?`,
    };
  }

  if (kind === 'malware') {
    const m = index.malwareByName.get(id);
    if (!m) return null;
    const software = m.attackId ? index.softwareById.get(m.attackId) : null;
    add(
      software ? h('p', { text: software.description }) : null,
      facts(
        field('Indicators right now', String(m.count)),
        field(
          'Activity',
          Object.keys(m.threats)
            .map((t) => t.replace(/_/g, ' '))
            .join(', '),
        ),
        field(
          'Indicator types',
          Object.entries(m.types)
            .map(([type, count]) => `${type} (${count})`)
            .join(', '),
        ),
        field('Last seen', formatAgo(m.lastSeen)),
        field(
          'ATT&CK',
          software
            ? externalLink(software.url, software.id) || software.id
            : null,
        ),
      ),
      h(
        'button',
        {
          class: 'ti-button',
          type: 'button',
          onClick: () => ctx.go('indicators', { text: m.name }),
        },
        `View its ${m.count} indicators`,
      ),
      related('Groups known to use it', m.groups, groupChip),
      software
        ? related('Techniques', software.techniques, techniqueChip)
        : null,
    );
    return {
      kind,
      title: m.name,
      body,
      question: `Brief me on ${m.name}: what it does, who uses it, and how to detect it.`,
    };
  }

  if (kind === 'group') {
    const g = index.groupById.get(id);
    if (!g) return null;
    const active = index.activeGroups.get(id) || [];
    const byTactic = new Map();
    for (const techniqueId of g.techniques) {
      const technique = index.techniqueById.get(techniqueId);
      if (!technique || technique.subtechnique) continue;
      for (const tactic of technique.tactics) {
        const list = byTactic.get(tactic) || [];
        list.push(techniqueId);
        byTactic.set(tactic, list);
      }
    }
    add(
      active.length
        ? h('p', {
            class: 'ti-callout',
            text: `Linked to current activity through ${active.join(', ')}.`,
          })
        : null,
      h('p', { text: g.description }),
      facts(
        field('ATT&CK ID', externalLink(g.url, g.id) || g.id),
        field('Also known as', g.aliases.join(', ')),
        field('Profile updated', formatDate(g.modified)),
      ),
      related('Software', g.software, softwareChip),
      ...index.attack.tactics
        .filter((tactic) => byTactic.has(tactic.key))
        .map((tactic) =>
          related(tactic.name, byTactic.get(tactic.key), techniqueChip),
        ),
    );
    return {
      kind,
      title: g.name,
      body,
      question: `Profile ${g.name} (${g.id}): motivations, typical targets, and what in today's data relates to them.`,
    };
  }

  if (kind === 'software') {
    const s = index.softwareById.get(id);
    if (!s) return null;
    const family = index.activeSoftware.get(id);
    add(
      family
        ? h('p', {
            class: 'ti-callout',
            text: `Seen in ${family.count} current indicators.`,
          })
        : null,
      h('p', { text: s.description }),
      facts(
        field('ATT&CK ID', externalLink(s.url, s.id) || s.id),
        field('Kind', s.kind),
        field('Also known as', s.aliases.join(', ')),
        field('Platforms', s.platforms.join(', ')),
      ),
      family
        ? h(
            'button',
            {
              class: 'ti-button',
              type: 'button',
              onClick: () => ctx.open('malware', family.name),
            },
            'View current activity',
          )
        : null,
      related('Used by', s.groups, groupChip),
      related('Techniques', s.techniques, techniqueChip),
    );
    return {
      kind,
      title: s.name,
      body,
      question: `Brief me on ${s.name} (${s.id}): what it does, who uses it, and how to detect it.`,
    };
  }

  if (kind === 'technique') {
    const t = index.techniqueById.get(id);
    if (!t) return null;
    const active = t.groups.filter((groupId) =>
      index.activeGroups.has(groupId),
    );
    add(
      h('p', { text: t.description }),
      facts(
        field('ATT&CK ID', externalLink(t.url, t.id) || t.id),
        field(
          'Tactics',
          t.tactics.map((tactic) => tactic.replace(/-/g, ' ')).join(', '),
        ),
        field('Platforms', t.platforms.join(', ')),
      ),
      related('Groups linked to current activity', active, groupChip),
      related('All groups using it', t.groups, groupChip),
      related('Software using it', t.software, softwareChip),
    );
    return {
      kind,
      title: `${t.id} ${t.name}`,
      body,
      question: `Explain ATT&CK technique ${t.id} ${t.name} and how to detect and mitigate it.`,
    };
  }
  return null;
}

export const kindLabel = (kind) => KIND_LABEL[kind] || kind;
