// #1386 THE cells of every data view's table (owner 2026-11-25: "the column width in some views are wrong so it only shows
// one row in a view, fx due to compliance is added" -- chose "Auto width + 2-line cap"; and "it must be supported to adjust
// the width and then it must show more, like fx paths it is important we can see all info"). Loaded by view-tools.js for
// every table of a view, once:
//   - AUTO WIDTH: a column sizes to its content up to a maximum (css/app.css, table.cells-fit): a long-text column -- a list
//     (compliance tags, paths, affected software; th[data-col-kind=list]) or text that runs long -- gets a wider minimum, so
//     it no longer wraps into ten lines; a short one stays narrow. A width the person dragged (view-tools.js) always wins.
//   - TWO LINES AT MOST per cell, cut with "…" (line-clamp). Nothing is lost: the whole text is in the cell (the export and
//     the row's own page are not touched), on hover (its title), and one click away -- the row's "Show full text" button
//     (keyboard reachable, aria-expanded), or a click on a cut cell of a row without a drawer.
//   - FULL TEXT PER COLUMN: the header's "Full text" button (aria-pressed) shows every line of that column; it is kept with
//     the widths ("$full", Columns/ViewState.cs) -- for the person and in a saved layout.
//   - "a;b;c" lists read "a; b; c", so they wrap readably.
// Progressive: without this file every cell shows its whole text, as before. No inline style attribute is written.

var CLAMP = "cell-clamp";
var LONG_TEXT = 60;       // a text column whose longest value is longer than this reads as a long-text column

function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }

// a cell the cap applies to: a text cell of a row with one cell per header cell (never the tick box, never a number)
function clampable(td) {
  return td && td.tagName === "TD" && !td.classList.contains("sel") && !td.classList.contains("num") && td.colSpan === 1 && !td.querySelector("input, select, textarea, form");
}

// "a;b; c" -> "a; b; c" in the text the person reads (a link's address, an attribute and the export are not touched)
export function spaceLists(text) { return text.replace(/\s*;\s*(?=\S)/g, "; "); }

function spaceTextNodes(node) {
  node.childNodes.forEach(function (n) {
    if (n.nodeType === 3) { if (n.nodeValue.indexOf(";") >= 0) { n.nodeValue = spaceLists(n.nodeValue); } }
    else if (n.nodeType === 1) { spaceTextNodes(n); }
  });
}

function wrapCell(td) {
  if (td.firstElementChild && td.firstElementChild.classList.contains(CLAMP) && td.childNodes.length === 1) { return td.firstElementChild; }
  var box = el("div", CLAMP);
  while (td.firstChild) { box.appendChild(td.firstChild); }
  td.appendChild(box);
  spaceTextNodes(box);
  return box;
}

function cut(box) { return box.scrollHeight > box.clientHeight + 1; }

function setFull(table, index, on) {
  Array.prototype.forEach.call(table.rows, function (r) {
    var c = r.cells[index];
    if (c && c.colSpan === 1) { c.classList.toggle("col-full", on); }
  });
}

function rowButton(tr) {
  var host = tr.querySelector("td.sel") || tr.cells[0];
  if (!host || host.querySelector("[data-row-full]")) { return; }
  var b = el("button", "secondary small row-full-toggle", "⤢");
  b.type = "button";
  b.setAttribute("data-row-full", "");
  b.setAttribute("aria-expanded", "false");
  b.setAttribute("aria-label", "Show the full text of this row");
  b.title = "Show the full text of this row";
  b.addEventListener("click", function (e) { e.preventDefault(); e.stopPropagation(); toggleRow(tr); });
  host.appendChild(b);
}

export function toggleRow(tr, force) {
  var on = force === undefined ? !tr.classList.contains("row-full") : !!force;
  tr.classList.toggle("row-full", on);
  var b = tr.querySelector("[data-row-full]");
  if (b) {
    b.setAttribute("aria-expanded", on ? "true" : "false");
    var words = on ? "Show this row in two lines again" : "Show the full text of this row";
    b.setAttribute("aria-label", words); b.title = words;
  }
  return on;
}

// The cells of one table. opts: { full: [column keys shown in full], onFull: function (keys) -- the person changed them }
export function initGridCells(table, opts) {
  if (!table || table.getAttribute("data-cells-ready") === "1") { return null; }
  table.setAttribute("data-cells-ready", "1");
  opts = opts || {};
  var head = table.tHead && table.tHead.rows.length ? table.tHead.rows[0] : null;
  if (!head) { return null; }
  var n = head.cells.length;
  var full = (opts.full || []).slice();
  table.classList.add("cells-fit");
  var rows = Array.prototype.filter.call(table.tBodies.length ? table.tBodies[0].rows : [], function (r) { return r.cells.length === n; });

  // the cap on every text cell; the longest value per column says whether it is a long-text column
  var longest = [];
  rows.forEach(function (r) {
    Array.prototype.forEach.call(r.cells, function (td, i) {
      if (!clampable(td)) { return; }
      var box = wrapCell(td);
      var len = (box.textContent || "").trim().length;
      if (!longest[i] || len > longest[i]) { longest[i] = len; }
    });
  });
  Array.prototype.forEach.call(head.cells, function (th, i) {
    var key = th.getAttribute("data-col");
    if (!th.getAttribute("data-col-kind") && (longest[i] || 0) > LONG_TEXT) { th.setAttribute("data-col-kind", "long"); }
    var kind = th.getAttribute("data-col-kind");
    if (kind) { rows.forEach(function (r) { if (r.cells[i]) { r.cells[i].setAttribute("data-col-kind", kind); } }); }
    if (key && full.indexOf(key) >= 0) { setFull(table, i, true); }
    if (key && longest[i] !== undefined) { addFullButton(table, th, i, key); }
  });

  function addFullButton(t, th, i, key) {
    var box = th.querySelector("[data-th-tools]");
    if (!box) { box = el("span", "th-tools"); box.setAttribute("data-th-tools", ""); th.appendChild(box); }
    var name = th.getAttribute("data-col-label") || (th.textContent || "").trim();
    var b = el("button", "secondary small th-full", "⤢");
    b.type = "button";
    b.setAttribute("data-th-full", key);
    function words(on) {
      var w = on ? "Show the column " + name + " in two lines again" : "Show the full text of the column " + name;
      b.setAttribute("aria-label", w); b.title = w; b.setAttribute("aria-pressed", on ? "true" : "false");
    }
    words(full.indexOf(key) >= 0);
    b.addEventListener("click", function (e) {
      e.preventDefault(); e.stopPropagation();
      var at = full.indexOf(key), on = at < 0;
      if (on) { full.push(key); } else { full.splice(at, 1); }
      setFull(t, th.cellIndex, on);
      words(on);
      if (typeof opts.onFull === "function") { opts.onFull(full.slice()); }
    });
    box.appendChild(b);
  }

  // what is cut: its whole text on hover, and the row's "Show full text" button (after layout, one read per cell)
  window.requestAnimationFrame(function () { markCut(rows); });
  table.addEventListener("click", function (e) {
    var t = e.target;
    if (!(t instanceof Element) || t.closest("a, button, input, select, textarea, label, summary")) { return; }
    var box = t.closest("." + CLAMP), tr = box ? box.closest("tr") : null;
    if (!tr || tr.hasAttribute("data-row-drawer") || e.shiftKey || e.ctrlKey || e.metaKey) { return; }
    if (tr.classList.contains("row-full") || box.hasAttribute("data-cut")) { toggleRow(tr); }
  });
  // a folded list inside a cell ("12 paths") that is opened shows every item: its row is shown in full
  table.addEventListener("toggle", function (e) {
    var d = e.target;
    if (!(d instanceof Element) || d.tagName !== "DETAILS" || !d.closest("." + CLAMP)) { return; }
    if (d.open) { toggleRow(d.closest("tr"), true); }
  }, true);
  return { full: function () { return full.slice(); } };
}

export function markCut(rows) {
  rows.forEach(function (r) {
    var any = false;
    r.querySelectorAll("." + CLAMP).forEach(function (box) {
      if (!cut(box)) { box.removeAttribute("data-cut"); return; }
      any = true;
      box.setAttribute("data-cut", "");
      var td = box.parentElement;
      if (td && !td.getAttribute("title")) { td.setAttribute("title", (box.textContent || "").replace(/\s+/g, " ").trim()); }
    });
    if (any) { rowButton(r); }
  });
}
