// Sorting + filtering for every small, bounded table: <table data-sortable> (BRAND-2.7). Big or unbounded data uses the
// server-side grid of the collection views and the Findings browser instead -- sorted, filtered and paged in SQL.
//   - click (or Enter / Space on) a column header to sort; again to reverse. aria-sort + a visible ▲ / ▼ show the state.
//     Numbers sort as numbers, ISO dates as dates, severities in rank order (Critical > Very High > High > Medium > Low
//     > Info), everything else as text (locale-aware, "item 2" before "item 10").
//   - a filter row under the headers: "any ▸" multi-select for a column with few distinct values, "from..to" for a
//     date column, "contains" for text; one search box over every column; the active filters shown as chips with one
//     "Clear all". A NUMBER column sorts only -- no min / max boxes (operator 2026-10-05: "nobody understands this
//     min/max"): its filter cell stays empty and the column stays narrow (th / td class "num", right-aligned).
// SORTING USES THE RAW VALUE: a cell's data-sort (or data-value) when present, else the displayed text parsed IN THE
// PAGE'S NUMBER LOCALE (<html data-number-locale>: the same locale the server wrote it in), so "2.254" on a Danish page
// is two thousand, never two point two (BRAND-2.6). A header with data-sort="off" (a checkbox / action column) is left
// alone; a row with data-sort-fixed (a total) stays last. Works without this file: the table is still all there.
// THE DEFAULT ORDER (#317): a table with a TIME column -- a date column headed When / Started / Time / Ran / Last run /
// Recorded -- opens NEWEST FIRST on it (▼ shown), so the latest event is on top; any header still sorts on click. A page
// says otherwise on the <table>: data-default-sort="off" keeps the server's order (a flow's step order, a precedence
// list), data-default-sort="<header text>" picks the column, data-default-dir="asc" the direction.
import { numberLocale, parseLocaleNumber, formatNumber } from "./numbers.js";

var SEVERITY = { "critical": 6, "very high": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2, "informational": 1, "info": 1, "none": 0 };
var ISO_DATE = /^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?( ?(UTC|Z))?$/;
var TIME_HEADER = /^(when|started|start|time|ran|last run|recorded)\b/i;
var CHOICE_MAX = 12;
var seq = 0;

function shown(td) { return td ? td.textContent.replace(/\s+/g, " ").trim() : ""; }
function raw(td) {
  if (!td) { return null; }
  var r = td.getAttribute("data-sort");
  if (r === null) { r = td.getAttribute("data-value"); }
  return r;
}
function cellNumber(td, locale) {
  if (!td) { return null; }
  var r = raw(td);
  if (r !== null && r !== "") { var n = Number(r); return isFinite(n) ? n : null; }
  return parseLocaleNumber(shown(td), locale);
}
// A <time datetime> cell (#313) sorts and filters on its LOCAL yyyy-MM-dd HH:mm -- the form the person reads and types --
// whatever zone label or tooltip it also carries.
function cellTime(td) {
  var tm = td && td.querySelector ? td.querySelector("time[datetime]") : null;
  return tm && window.siLocalTime ? window.siLocalTime.format(tm.getAttribute("datetime"), "datetime", tm.hasAttribute("data-seconds")) || null : null;
}
function cellDate(td) { var r = raw(td); var t = r !== null && r !== "" ? r : (cellTime(td) || shown(td)); return ISO_DATE.test(t) ? t : null; }

function headerRow(table) {
  var rows = table.tHead ? table.tHead.rows : null;
  return rows && rows.length ? rows[rows.length - 1] : null;
}
function bodyRows(table) {
  var out = [];
  Array.prototype.forEach.call(table.tBodies, function (b) { Array.prototype.forEach.call(b.rows, function (r) { out.push(r); }); });
  return out;
}
function isBlank(t) { return !t || t === "–" || t === "-"; }

function columnKind(rows, i, locale) {
  var seen = 0, nums = 0, sev = 0, dates = 0, distinct = {};
  rows.forEach(function (r) {
    var td = r.cells[i], t = shown(td);
    if (isBlank(t)) { return; }
    seen++;
    distinct[t] = true;
    if (cellNumber(td, locale) !== null) { nums++; }
    if (cellDate(td) !== null) { dates++; }
    if (SEVERITY.hasOwnProperty(t.toLowerCase())) { sev++; }
  });
  var values = Object.keys(distinct);
  var few = values.length <= CHOICE_MAX && values.length < rows.length;
  if (seen === 0) { return { kind: "text", distinct: [] }; }
  if (sev === seen) { return { kind: "severity", distinct: values.sort(function (a, b) { return SEVERITY[b.toLowerCase()] - SEVERITY[a.toLowerCase()]; }) }; }
  if (dates === seen) { return { kind: "date", distinct: [] }; }
  if (nums === seen) { return { kind: "number", distinct: [] }; }
  return { kind: "text", distinct: few ? values.sort(function (a, b) { return a.localeCompare(b, locale, { numeric: true }); }) : [] };
}

function compare(a, b, kind, locale) {
  if (kind === "number" || kind === "date") {
    var x = kind === "number" ? cellNumber(a, locale) : cellDate(a), y = kind === "number" ? cellNumber(b, locale) : cellDate(b);
    if (x === null && y === null) { return 0; }
    if (x === null) { return 1; }
    if (y === null) { return -1; }
    return kind === "number" ? x - y : (x < y ? -1 : x > y ? 1 : 0);
  }
  var s = shown(a), t = shown(b);
  if (kind === "severity") { return (SEVERITY[s.toLowerCase()] || -1) - (SEVERITY[t.toLowerCase()] || -1); }
  if (!s && t) { return 1; }
  if (s && !t) { return -1; }
  return s.localeCompare(t, locale, { numeric: true, sensitivity: "base" });
}

// #317: the column (and direction) a table opens sorted on, or null to keep the server's order. PURE over the header
// names, the column kinds and the table's data-default-sort / data-default-dir.
export function defaultSort(names, cols, want, dirAttr) {
  if (want && want.trim().toLowerCase() === "off") { return null; }
  var dir = dirAttr && dirAttr.trim().toLowerCase() === "asc" ? 1 : -1;
  var i, pick = -1;
  for (i = 0; i < names.length && pick < 0; i++) {
    if (!cols[i]) { continue; }
    if (want ? names[i].toLowerCase() === want.trim().toLowerCase() : (cols[i].kind === "date" && TIME_HEADER.test(names[i]))) { pick = i; }
  }
  return pick < 0 ? null : { col: pick, dir: dir };
}

function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }

export function enhanceTable(table) {
  if (table.getAttribute("data-sortable-ready") === "1") { return; }
  var head = headerRow(table);
  if (!head) { return; }
  table.setAttribute("data-sortable-ready", "1");
  var locale = numberLocale();
  var rows = bodyRows(table);
  var names = Array.prototype.map.call(head.cells, function (th) { return th.textContent.replace(/\s+/g, " ").trim(); });
  var cols = Array.prototype.map.call(head.cells, function (th, i) {
    return th.getAttribute("data-sort") === "off" || th.colSpan > 1 ? null : columnKind(rows, i, locale);
  });
  var state = { col: -1, dir: 1 };
  var id = "tbl" + (++seq);
  var filters = [];

  function active() {
    var out = [];
    if (search.value.trim()) { out.push({ text: "Search: " + search.value.trim(), clear: function () { search.value = ""; } }); }
    filters.forEach(function (f) {
      var n = names[f.col];
      if (f.min && (f.min.value.trim() || f.max.value.trim())) {
        out.push({ text: n + ": " + (f.min.value.trim() || "…") + ".." + (f.max.value.trim() || "…"), clear: function () { f.min.value = ""; f.max.value = ""; } });
      } else if (f.boxes) {
        var on = f.boxes.filter(function (b) { return b.checked; });
        if (on.length) { out.push({ text: n + ": " + on.map(function (b) { return b.value; }).join(" or "), clear: function () { on.forEach(function (b) { b.checked = false; }); } }); }
      } else if (f.input && f.input.value.trim()) {
        out.push({ text: n + " contains " + f.input.value.trim(), clear: function () { f.input.value = ""; } });
      }
    });
    return out;
  }

  // #287: every choice of a "any ▸" filter says how many rows it gives under the OTHER filters (and the search); a choice
  // with none is dimmed and listed after the others
  function countChoices(all, q) {
    filters.forEach(function (f) {
      if (!f.boxes) { return; }
      var n = {};
      all.forEach(function (r) {
        if (r.hasAttribute("data-sort-fixed") || !passes(r, q, f)) { return; }
        var t = shown(r.cells[f.col]);
        n[t] = (n[t] || 0) + 1;
      });
      var labels = f.boxes.map(function (b) { return b.parentNode; });
      f.boxes.forEach(function (b) {
        var c = n[b.value] || 0, lab = b.parentNode, span = lab.querySelector("[data-value-count]");
        if (!span) { span = el("span", "value-count"); span.setAttribute("data-value-count", ""); lab.appendChild(span); }
        span.textContent = " (" + formatNumber(c) + ")";
        lab.setAttribute("data-count", String(c));
        lab.classList.toggle("value-empty", c === 0);
      });
      var list = labels.length ? labels[0].parentNode : null;
      if (list) {
        labels.filter(function (l) { return !l.classList.contains("value-empty"); }).concat(labels.filter(function (l) { return l.classList.contains("value-empty"); }))
          .forEach(function (l) { list.appendChild(l); });
      }
    });
  }

  function passes(r, q, except) {
    var ok = !q || r.textContent.toLowerCase().indexOf(q) >= 0;
    filters.forEach(function (f) {
      if (!ok || f === except) { return; }
      ok = rowMatches(r, f);
    });
    return ok;
  }

  function rowMatches(r, f) {
    var td = r.cells[f.col];
    if (f.min) {
      var lo = f.min.value.trim(), hi = f.max.value.trim();
      if (!lo && !hi) { return true; }
      var d = cellDate(td);   // only a date column has a from..to (a number column sorts only)
      return !(d === null || (lo && d < lo) || (hi && d.slice(0, hi.length) > hi));
    }
    if (f.boxes) {
      var on = f.boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
      return !(on.length && on.indexOf(shown(td)) < 0);
    }
    if (f.input && f.input.value.trim()) { return shown(td).toLowerCase().indexOf(f.input.value.trim().toLowerCase()) >= 0; }
    return true;
  }

  function apply() {
    var all = bodyRows(table), q = search.value.trim().toLowerCase(), visible = 0, total = 0;
    countChoices(all, q);
    all.forEach(function (r) {
      if (r.hasAttribute("data-sort-fixed")) { return; }
      total++;
      var ok = !q || r.textContent.toLowerCase().indexOf(q) >= 0;
      filters.forEach(function (f) {
        if (!ok) { return; }
        var td = r.cells[f.col];
        if (f.min) {
          var lo = f.min.value.trim(), hi = f.max.value.trim();
          if (!lo && !hi) { return; }
          var d = cellDate(td);
          if (d === null || (lo && d < lo) || (hi && d.slice(0, hi.length) > hi)) { ok = false; }
        } else if (f.boxes) {
          var on = f.boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
          if (on.length && on.indexOf(shown(td)) < 0) { ok = false; }
        } else if (f.input && f.input.value.trim()) {
          if (shown(td).toLowerCase().indexOf(f.input.value.trim().toLowerCase()) < 0) { ok = false; }
        }
      });
      r.hidden = !ok;
      if (ok) { visible++; }
    });
    count.textContent = visible === total ? formatNumber(total) + " rows" : formatNumber(visible) + " of " + formatNumber(total) + " rows";
    // the active filters, each removable, and one action that clears them all
    chips.textContent = "";
    var act = active();
    act.forEach(function (a) {
      var li = el("li"), b = el("button", "chip", a.text + " ✕");
      b.type = "button"; b.setAttribute("aria-label", "Remove the filter " + a.text);
      b.addEventListener("click", function () { a.clear(); syncSummaries(); apply(); });
      li.appendChild(b); chips.appendChild(li);
    });
    chips.hidden = act.length === 0;
    clear.disabled = act.length === 0;
  }

  function syncSummaries() {
    filters.forEach(function (f) {
      if (!f.boxes) { return; }
      var n = f.boxes.filter(function (b) { return b.checked; }).length;
      f.summary.textContent = n ? n + " of " + f.boxes.length + " ▸" : "any ▸";
    });
  }

  function sortBy(i, dir) {
    if (!cols[i]) { return; }
    state.dir = dir ? dir : state.col === i ? -state.dir : (cols[i].kind === "text" ? 1 : -1);   // numbers, dates, severities: biggest / newest first
    state.col = i;
    Array.prototype.forEach.call(head.cells, function (th, j) {
      if (!cols[j]) { return; }
      th.setAttribute("aria-sort", j === i ? (state.dir > 0 ? "ascending" : "descending") : "none");
      var arrow = th.querySelector(".sort-arrow");
      if (arrow) { arrow.textContent = j === i ? (state.dir > 0 ? " ▲" : " ▼") : ""; }
    });
    Array.prototype.forEach.call(table.tBodies, function (b) {
      var list = Array.prototype.slice.call(b.rows);
      var fixed = list.filter(function (r) { return r.hasAttribute("data-sort-fixed"); });
      var moving = list.filter(function (r) { return !r.hasAttribute("data-sort-fixed"); });
      moving.sort(function (ra, rb) { return state.dir * compare(ra.cells[i], rb.cells[i], cols[i].kind, locale); });
      moving.concat(fixed).forEach(function (r) { b.appendChild(r); });
    });
  }

  // headers -> sort buttons (keyboard: real buttons)
  Array.prototype.forEach.call(head.cells, function (th, i) {
    if (!cols[i]) { return; }
    var b = el("button", "th-sort");
    b.type = "button";
    while (th.firstChild) { b.appendChild(th.firstChild); }
    b.appendChild(el("span", "sort-arrow"));
    b.setAttribute("aria-label", "Sort by " + names[i]);
    b.addEventListener("click", function () { sortBy(i); });
    th.appendChild(b);
    th.setAttribute("aria-sort", "none");
  });

  // the filter row
  var fr = el("tr", "colfilters");
  fr.setAttribute("data-filter-row", "");
  Array.prototype.forEach.call(head.cells, function (th, i) {
    var td = el("td"), c = cols[i], name = names[i];
    if (th.colSpan > 1) { td.colSpan = th.colSpan; }
    if (c && c.kind === "number") {
      // sort only: no filter box, and a narrow right-aligned column (#321)
      td.className = "num";
      th.classList.add("num", "col-num");
      rows.forEach(function (r) { var cell = r.cells[i]; if (cell && cell.colSpan === 1) { cell.classList.add("num"); } });
    } else if (c && c.kind === "date") {
      var min = el("input"), max = el("input");
      [min, max].forEach(function (x, k) {
        x.type = "text"; x.inputMode = "numeric";
        x.placeholder = k ? "to yyyy-mm-dd" : "from yyyy-mm-dd";
        x.setAttribute("aria-label", name + (k ? " at most" : " at least"));
        x.addEventListener("input", apply);
      });
      var w = el("div", "range-filter"); w.appendChild(min); w.appendChild(el("span", "muted", "..")); w.appendChild(max);
      td.appendChild(w);
      filters.push({ col: i, kind: c.kind, min: min, max: max });
    } else if (c && c.distinct.length) {
      var d = el("details", "colfilter"), s = el("summary", null, "any ▸"), list = el("div", "colfilter-list"), boxes = [];
      s.setAttribute("aria-label", "Show only some values of " + name);
      c.distinct.forEach(function (v) {
        var lab = el("label"), cb = el("input");
        cb.type = "checkbox"; cb.value = v;
        cb.addEventListener("change", function () { syncSummaries(); apply(); });
        lab.appendChild(cb); lab.appendChild(document.createTextNode(" " + v));
        list.appendChild(lab); boxes.push(cb);
      });
      d.appendChild(s); d.appendChild(list); td.appendChild(d);
      filters.push({ col: i, kind: "choice", boxes: boxes, summary: s });
    } else if (c) {
      var inp = el("input");
      inp.type = "search"; inp.placeholder = "contains"; inp.setAttribute("aria-label", name + " contains");
      inp.addEventListener("input", apply);
      td.appendChild(inp);
      filters.push({ col: i, kind: "text", input: inp });
    }
    fr.appendChild(td);
  });
  head.parentNode.insertBefore(fr, head.nextSibling);

  // the bar above: one search box over every column, the row count, the active filters, Clear all
  var bar = el("div", "gridbar table-tools");
  bar.setAttribute("data-table-tools", "");
  var lab = el("label", "sr-only", "Search this table"); lab.htmlFor = id + "-q";
  var search = el("input"); search.type = "search"; search.id = id + "-q"; search.placeholder = "Search this table";
  search.addEventListener("input", apply);
  var count = el("span", "muted"); count.setAttribute("aria-live", "polite");
  var clear = el("button", "secondary small", "Clear all"); clear.type = "button";
  clear.addEventListener("click", function () {
    search.value = "";
    filters.forEach(function (f) { if (f.min) { f.min.value = ""; f.max.value = ""; } if (f.boxes) { f.boxes.forEach(function (b) { b.checked = false; }); } if (f.input) { f.input.value = ""; } });
    syncSummaries(); apply();
  });
  var chips = el("ul", "filter-chips"); chips.setAttribute("aria-label", "Active table filters");
  bar.appendChild(lab); bar.appendChild(search); bar.appendChild(count); bar.appendChild(clear);
  var host = table.closest(".table-wrap") || table;
  // #282: the search box and the chips go ABOVE the grid toolbar (actions + pager) when the table has one
  var prev = host.previousElementSibling;
  if (prev && prev.hasAttribute("data-grid-toolbar")) { host = prev; }
  host.parentNode.insertBefore(bar, host);
  host.parentNode.insertBefore(chips, host);
  // #317: newest first on the time column unless the page says otherwise
  var first = defaultSort(names, cols, table.getAttribute("data-default-sort"), table.getAttribute("data-default-dir"));
  if (first) { sortBy(first.col, first.dir); table.setAttribute("data-default-sorted", names[first.col]); }
  apply();
}

// The sticky filter row sits right under the sticky header row: its offset is the header row's real height.
function measureHeads() {
  document.querySelectorAll("table").forEach(function (t) {
    if (!t.tHead || t.tHead.rows.length < 2) { return; }
    t.style.setProperty("--thead-h", t.tHead.rows[0].getBoundingClientRect().height + "px");
  });
  // #282: the grid toolbar sticks to the top of the window; the table under it is at most the window minus the
  // toolbar high, so its own sticky header row never slides under the toolbar (one offset, not two)
  document.querySelectorAll("[data-grid-toolbar]").forEach(function (bar) {
    if (bar.parentNode && bar.parentNode.style) { bar.parentNode.style.setProperty("--gt-h", Math.ceil(bar.getBoundingClientRect().height) + "px"); }
  });
}

export function initTables(root) {
  (root || document).querySelectorAll("table[data-sortable]").forEach(enhanceTable);
  measureHeads();
  window.addEventListener("resize", measureHeads);
  // a toolbar that wraps (a longer hint, a narrower window) re-measures itself
  if (typeof ResizeObserver === "function") {
    var ro = new ResizeObserver(measureHeads);
    (root || document).querySelectorAll("[data-grid-toolbar]").forEach(function (b) { ro.observe(b); });
  }
}
