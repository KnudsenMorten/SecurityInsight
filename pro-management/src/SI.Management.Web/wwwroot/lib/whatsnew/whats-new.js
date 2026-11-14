// WHATS-NEW-1 (framework/REQUIREMENTS.md "## WHATS-NEW-1"; owner 2026-11-13: "all solutions have a whats new which is human
// friendly info from release notes" / "agree upon layout format" / "all must have same"): the ONE browser renderer of a
// product's What's new. SecurityInsight, PIM Manager and Entra Policy Suite embed THIS file and whats-new.css unchanged in
// their GUI (Pro AND Community); invardia.com builds /products/<product>/whats-new from the same markup (whatsNewHtml), so
// every surface shows the same words in the same order. No dependencies, no network, no build step: an ES module.
//
//   <link rel="stylesheet" href="whats-new.css">
//   <div id="whats-new"></div>
//   <script type="module">
//     import { renderWhatsNew, shouldShowNewBadge, markWhatsNewSeen } from './whats-new.js';
//     renderWhatsNew(document.getElementById('whats-new'), files, { productName: 'PIM Manager', product: 'pim-manager', markSeen: true });
//     menuBadge.hidden = !shouldShowNewBadge(files, { product: 'pim-manager' });
//   </script>
//
// `files` = the parsed whats-new/<version>.json files (one per release, any order). The rules of a file are
// tools/whatsnew/whats-new.schema.json; checkWhatsNewFile / whatsNewConformance here and ConvertTo-WhatsNewMarkdown.ps1 -Check
// apply the same rules (tools/test/WhatsNew.Tests.ps1 and packages/core/test/whatsnew.test.ts keep them equal).

/** The 3a limits (owner 2026-11-13: "it must be easy to read xecutibe friendly"). The schema file carries the same numbers. */
export const WHATS_NEW_LIMITS = Object.freeze({ titleWords: 8, textWords: 40, itemsPerSection: 5 });
export const WHATS_NEW_TYPES = Object.freeze({ feature: 'Feature update', 'fix-only': 'Fix-only', security: 'Security' });
export const WHATS_NEW_NONE = 'None in this version.';
export const WHATS_NEW_EMPTY = 'Nothing is published yet.';
export const WHATS_NEW_VERSION = /^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]{1,30})?$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TOP_KEYS = ['$schema', 'version', 'date', 'type', 'summary', 'new', 'fixes'];
const ITEM_KEYS = ['title', 'text', 'action'];
// point 3 / point 5: no commit hash, no ticket number (a hash = 7-40 hex with at least one digit and one letter, so a plain
// word like "defaced" or a date like 20261113 is not one)
const COMMIT_HASH = /(?<![0-9A-Za-z])(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}(?![0-9A-Za-z])/i;
const TICKET = /(?<![0-9A-Za-z])SUP-\d{4}-\d+/i;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const filled = (v) => typeof v === 'string' && v.trim().length > 0;
const words = (s) => s.trim().split(/\s+/).filter(Boolean).length;
const oneLine = (s) => String(s).replace(/\s+/g, ' ').trim();

/** Release versions compared part by part (digits as numbers, any length; other parts as text). -1 / 0 / 1. The same
 *  order as tools/ops/InvardiaHandover.psm1 Compare-HandoverVersion and the PowerShell renderer. */
export function compareWhatsNewVersion(a, b) {
  const pa = String(a).split(/[.-]/), pb = String(b).split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (i >= pa.length) return -1;
    if (i >= pb.length) return 1;
    const x = pa[i], y = pb[i];
    let c;
    if (/^\d+$/.test(x) && /^\d+$/.test(y)) { const bx = BigInt(x), by = BigInt(y); c = bx === by ? 0 : bx < by ? -1 : 1; }
    else c = x === y ? 0 : x < y ? -1 : 1;
    if (c !== 0) return c;
  }
  return 0;
}

/** The SCHEMA problems of one parsed file (empty = it renders): the fields, their types, version / date / type, every item
 *  with a title and a text, no unknown field. The 3a limits and the word rules are whatsNewStyleProblems. */
export function checkWhatsNewFile(raw) {
  const p = [];
  if (!isObj(raw)) return ['the file is not a JSON object'];
  for (const k of Object.keys(raw)) if (!TOP_KEYS.includes(k)) p.push(`unknown field '${k}'`);
  if (!filled(raw.version)) p.push("'version' is missing");
  else if (!WHATS_NEW_VERSION.test(raw.version)) p.push(`'version' '${raw.version}' is not a release version (like 3.1.21)`);
  if (!filled(raw.date)) p.push("'date' is missing");
  else if (!DATE.test(raw.date) || Number.isNaN(Date.parse(`${raw.date}T00:00:00Z`)) || new Date(`${raw.date}T00:00:00Z`).toISOString().slice(0, 10) !== raw.date) p.push(`'date' '${raw.date}' is not a date (YYYY-MM-DD)`);
  if (!filled(raw.type)) p.push("'type' is missing");
  else if (!Object.hasOwn(WHATS_NEW_TYPES, raw.type)) p.push(`'type' '${raw.type}' is not fix-only, feature or security`);
  if (!filled(raw.summary)) p.push("'summary' is missing");
  for (const sec of ['new', 'fixes']) {
    const list = raw[sec];
    if (!Array.isArray(list)) { p.push(`'${sec}' is missing or not a list`); continue; }
    list.forEach((it, i) => {
      const at = `${sec}[${i}]`;
      if (!isObj(it)) { p.push(`${at} is not an object`); return; }
      for (const k of Object.keys(it)) if (!ITEM_KEYS.includes(k)) p.push(`${at}: unknown field '${k}'`);
      if (!filled(it.title)) p.push(`${at}: 'title' is missing`);
      if (!filled(it.text)) p.push(`${at}: 'text' is missing`);
      if (it.action !== undefined && !filled(it.action)) p.push(`${at}: 'action' is empty (leave the field out when there is nothing to do)`);
    });
  }
  return p;
}

/** The 3a / point 3 problems of a file that passes the schema: title at most 8 words, text at most 40 words, at most 5
 *  items per section, and no commit hash or ticket number anywhere in its text. */
export function whatsNewStyleProblems(raw) {
  const p = [];
  if (!isObj(raw)) return p;
  const L = WHATS_NEW_LIMITS;
  const scan = (where, s) => {
    if (typeof s !== 'string') return;
    if (COMMIT_HASH.test(s)) p.push(`${where}: names a commit hash ('${s.match(COMMIT_HASH)[0]}') - say the effect instead`);
    if (TICKET.test(s)) p.push(`${where}: names a ticket number ('${s.match(TICKET)[0]}')`);
  };
  scan('summary', raw.summary);
  for (const sec of ['new', 'fixes']) {
    const list = Array.isArray(raw[sec]) ? raw[sec] : [];
    if (list.length > L.itemsPerSection) p.push(`'${sec}' has ${list.length} items - at most ${L.itemsPerSection}; group the smaller ones ("Smaller fixes: ...")`);
    list.forEach((it, i) => {
      if (!isObj(it)) return;
      const at = `${sec}[${i}]`;
      if (filled(it.title) && words(it.title) > L.titleWords) p.push(`${at}: the title has ${words(it.title)} words - at most ${L.titleWords}`);
      if (filled(it.text) && words(it.text) > L.textWords) p.push(`${at}: the text has ${words(it.text)} words - at most ${L.textWords}`);
      scan(`${at}.title`, it.title); scan(`${at}.text`, it.text); scan(`${at}.action`, it.action);
    });
  }
  return p;
}

/** Everything a release gate checks on one file: the schema, then the 3a limits and word rules. */
export function whatsNewConformance(raw) {
  const s = checkWhatsNewFile(raw);
  return s.length ? s : whatsNewStyleProblems(raw);
}

/** The files newest first (copies; a file without a version sorts last). */
export function sortWhatsNew(files) {
  return [...(files ?? [])].filter(isObj).sort((a, b) => compareWhatsNewVersion(String(b.version ?? ''), String(a.version ?? '')));
}

/** One card's content in reading order (the GUI, the site, the Markdown and the owner's approval mail all follow it):
 *  header, summary, the Action needed lines first, then New features, then Fixes. */
export function whatsNewCard(f) {
  const items = (l) => (Array.isArray(l) ? l : []).filter(isObj).map((it) => ({ title: oneLine(it.title ?? ''), text: oneLine(it.text ?? ''), ...(filled(it.action) ? { action: oneLine(it.action) } : {}) }));
  const added = items(f.new), fixes = items(f.fixes);
  return {
    version: String(f.version), date: String(f.date), type: String(f.type), typeLabel: WHATS_NEW_TYPES[f.type] ?? String(f.type),
    summary: oneLine(f.summary ?? ''),
    actions: [...added, ...fixes].filter((it) => it.action).map((it) => it.action),
    new: added, fixes,
  };
}

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/** The What's new markup (a string; every product text escaped). The newest card is open, the older ones collapsed.
 *  opts.productName: the heading "What's new in <name>" (opts.heading: false leaves the heading to the host page). */
export function whatsNewHtml(files, opts = {}) {
  const sorted = sortWhatsNew(files);
  const head = opts.heading === false ? '' : `<h2 class="wn-heading">What's new${opts.productName ? ` in ${esc(opts.productName)}` : ''}</h2>`;
  if (!sorted.length) return `<div class="wn">${head}<p class="wn-empty">${WHATS_NEW_EMPTY}</p></div>`;
  const section = (title, list) => `<section class="wn-section"><h3>${title}</h3>${list.length
    ? `<ul>${list.map((it) => `<li><strong>${esc(it.title)}</strong> - ${esc(it.text)}</li>`).join('')}</ul>`
    : `<p class="wn-none">${WHATS_NEW_NONE}</p>`}</section>`;
  const cards = sorted.map((f, i) => {
    const c = whatsNewCard(f);
    return `<details class="wn-card"${i === 0 ? ' open' : ''}>`
      + `<summary class="wn-head"><span class="wn-line"><span class="wn-version">${esc(c.version)}</span> · <span class="wn-date">${esc(c.date)}</span> · <span class="wn-type wn-type-${esc(c.type)}">${esc(c.typeLabel)}</span></span>`
      + `<span class="wn-summary">${esc(c.summary)}</span></summary>`
      + `<div class="wn-body">${c.actions.map((a) => `<p class="wn-action"><strong>Action needed:</strong> ${esc(a)}</p>`).join('')}`
      + `${section('New features', c.new)}${section('Fixes', c.fixes)}</div></details>`;
  }).join('');
  return `<div class="wn">${head}${cards}</div>`;
}

const storageKey = (opts = {}) => opts.storageKey ?? `invardia-whatsnew-last-seen${opts.product ? `:${opts.product}` : ''}`;
const storageOf = (opts = {}) => opts.storage ?? (typeof localStorage !== 'undefined' ? localStorage : null);

/** The newest version among the files (null when there are none). */
export function newestWhatsNewVersion(files) {
  const s = sortWhatsNew(files).filter((f) => typeof f.version === 'string');
  return s.length ? s[0].version : null;
}

/** The "New" badge on the What's new menu entry: shown while the newest version is greater than the last one the admin
 *  opened (localStorage, per product). Never seen = shown. Storage that throws or is missing = no badge (it could never
 *  be cleared). `filesOrVersion`: the files or the newest version itself. */
export function shouldShowNewBadge(filesOrVersion, opts = {}) {
  const newest = typeof filesOrVersion === 'string' ? filesOrVersion : newestWhatsNewVersion(filesOrVersion);
  if (!newest) return false;
  let seen = null;
  try {
    const st = storageOf(opts);
    if (!st) return false;
    seen = st.getItem(storageKey(opts));
  } catch { return false; }
  return !seen || compareWhatsNewVersion(newest, seen) > 0;
}

/** Records that the admin opened the page at this version (the badge goes away). Never throws. */
export function markWhatsNewSeen(filesOrVersion, opts = {}) {
  const newest = typeof filesOrVersion === 'string' ? filesOrVersion : newestWhatsNewVersion(filesOrVersion);
  if (!newest) return false;
  try { const st = storageOf(opts); if (!st) return false; st.setItem(storageKey(opts), newest); return true; } catch { return false; }
}

/** Draws the What's new into `element` (its content is replaced). Files that fail the schema are left out (the GUI never
 *  shows half a card); opts.markSeen records the newest version as seen. Returns the cards drawn. */
export function renderWhatsNew(element, files, opts = {}) {
  const good = (files ?? []).filter((f) => checkWhatsNewFile(f).length === 0);
  element.innerHTML = whatsNewHtml(good, opts);
  if (opts.markSeen) markWhatsNewSeen(good, opts);
  return good.length;
}
