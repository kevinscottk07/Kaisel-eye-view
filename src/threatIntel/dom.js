/**
 * Small DOM helpers for the threat-intel workspace. Feed text is third-party
 * content, so every string reaches the page as a text node, never as markup.
 */

/**
 * Create an element. `props` sets attributes; `class`, `text`, `dataset` and
 * `on<Event>` handlers are handled specially. Null/false children are skipped.
 */
export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else if (key === 'style') {
      for (const [name, styleValue] of Object.entries(value)) {
        if (name.startsWith('--')) el.style.setProperty(name, styleValue);
        else el.style[name] = styleValue;
      }
    } else if (key.startsWith('on') && typeof value === 'function')
      el.addEventListener(key.slice(2).toLowerCase(), value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(
      child instanceof Node ? child : document.createTextNode(String(child)),
    );
  }
}

export function replaceChildren(el, ...children) {
  el.textContent = '';
  append(el, children);
}

/** Only http(s) links from feeds are rendered as links. */
export function safeUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'https:' || url.protocol === 'http:'
      ? url.href
      : null;
  } catch {
    return null;
  }
}

export function externalLink(url, label) {
  const href = safeUrl(url);
  if (!href) return null;
  return h(
    'a',
    { class: 'ti-link', href, target: '_blank', rel: 'noopener noreferrer' },
    label,
  );
}

export function formatDate(value) {
  if (!value) return '—';
  const text = String(value);
  return text.length >= 10 ? text.slice(0, 10) : text;
}

export function formatAgo(value, now = Date.now()) {
  if (!value) return '—';
  const then = typeof value === 'number' ? value : Date.parse(value);
  if (!Number.isFinite(then)) return '—';
  const minutes = Math.max(0, Math.round((now - then) / 60_000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export const formatNumber = (value) =>
  Number.isFinite(value) ? value.toLocaleString('en-US') : '—';

export const formatPercent = (value) =>
  Number.isFinite(value)
    ? `${(value * 100).toFixed(value < 0.1 ? 1 : 0)}%`
    : '—';

/**
 * Render the analyst's short markdown (## headings, - bullets, **bold**,
 * `code`) as DOM nodes. Anything else stays literal text.
 */
export function renderMarkdown(text) {
  const root = h('div', { class: 'ti-prose' });
  let list = null;
  const inline = (line) => {
    const nodes = [];
    const pattern = /\*\*([^*]+)\*\*|`([^`]+)`/g;
    let last = 0;
    let match;
    while ((match = pattern.exec(line))) {
      if (match.index > last) nodes.push(line.slice(last, match.index));
      nodes.push(
        match[1] !== undefined
          ? h('strong', { text: match[1] })
          : h('code', { text: match[2] }),
      );
      last = pattern.lastIndex;
    }
    if (last < line.length) nodes.push(line.slice(last));
    return nodes;
  };
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) {
      list = null;
      continue;
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    const bullet = /^(?:[-*•]|\d+[.)])\s+(.*)$/.exec(line);
    if (heading) {
      list = null;
      root.append(
        h(heading[1].length <= 2 ? 'h3' : 'h4', {}, inline(heading[2])),
      );
    } else if (bullet) {
      if (!list) {
        list = h('ul');
        root.append(list);
      }
      list.append(h('li', {}, inline(bullet[1])));
    } else {
      list = null;
      root.append(h('p', {}, inline(line)));
    }
  }
  return root;
}
