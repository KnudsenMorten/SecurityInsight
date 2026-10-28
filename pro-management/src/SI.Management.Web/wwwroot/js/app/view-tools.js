// What each person fine-tunes on a data view's table itself (Pages/Shared/_ColumnChooser.cshtml renders the view bar
// [data-view-tools] next to every data view's column chooser; this file is loaded by column-chooser.js):
//   - MOVE A COLUMN on the table header: small "move left" / "move right" buttons in every column header (keyboard
//     reachable, aria-labelled) and drag-and-drop of a header. Saved at once for the signed-in person (the same save as
//     "Save for me"). A grid the server sorts is rearranged in place, without loading the page again; a table this app
//     sorts in the browser (table[data-sortable]) is loaded again, because its sorting and filter row know their columns
//     by position.
//   - COLUMN WIDTHS: drag a header's right edge (or focus it and use the left / right arrow keys); double-click (or
//     Enter) sets the column back to automatic. Saved per person per view.
//   - THE LAST SORT / FILTERS / SEARCH: after a change the person makes ON the page, the view's address parameters are
//     reported to the server, which shows them again the next time the view is opened FROM THE MENU (its links carry
//     nav=menu; a tile, a link of another page or a typed address shows the view's standard) without any (an address that names
//     a sort or filter always wins and is never stored by merely opening it). A table sorted in the browser has its sort,
//     search and filter row remembered and restored here -- EACH table of a view under its own name, so a view with
//     several tables remembers them all. A page whose filters are in its address and whose tables are sorted in the
//     browser (data-state-mode="address client") has both, stored as one state.
//   The move buttons sit on a line of their own under the header's text (css/app.css .th-tools): they never cover the
//   header's sort link, however narrow the column.
// Everything is progressive: without this file the Columns panel still chooses, orders and saves the columns, the Layout
// box still switches layouts and "Clear" still clears. No inline style attribute is written (the content security policy):
// widths are set through the style object.
import { toast } from "./ui.js";

var CHANGE_KEY = "si-view-change";
var MIN_WIDTH = 40, MAX_WIDTH = 2000, KEY_STEP = 16, LIVE_ROWS = 200;
var addressTools = [];
var listening = false;

function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }

// ---- talking to the shared /Columns page ---------------------------------------------------------------------------------

function post(tools, handler, fields) {
  var form = tools.querySelector("[data-view-post]");
  var token = form ? form.querySelector('input[name="__RequestVerificationToken"]') : null;
  if (!form || !token) { return Promise.resolve({ ok: false, message: "Not saved: reload the page and try again." }); }
  var url = (form.getAttribute("action") || "").replace(/handler=[A-Za-z]+/, "handler=" + handler);
  var body = new URLSearchParams();
  body.append("View", tools.getAttribute("data-view") || "");
  body.append("__RequestVerificationToken", token.value);
  fields.forEach(function (f) { body.append(f[0], f[1]); });
  return fetch(url, {
    method: "POST", credentials: "same-origin", keepalive: true,
    headers: { "X-Requested-With": "fetch", "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString()
  }).then(function (r) {
    if (r.ok) { return r.json(); }
    return { ok: false, message: r.status === 403 ? "Not saved: your account may not change this." : "Not saved: the server did not accept it. Reload the page and try again." };
  }).catch(function () { return { ok: false, message: "Not saved: the server could not be reached." }; });
}

function parse(json) {
  if (!json) { return {}; }
  try { var o = JSON.parse(json); return o && typeof o === "object" && !Array.isArray(o) ? o : {}; } catch (e) { return {}; }
}

// ---- the tables of a view ------------------------------------------------------------------------------------------------

// A page table carries its view key (div.dataview[data-view]); a grid is the table next to its chooser.
function tablesOf(tools) {
  var view = tools.getAttribute("data-view"), found = [];
  document.querySelectorAll(".dataview[data-view]").forEach(function (d) {
    if (d.getAttribute("data-view") !== view) { return; }
    d.querySelectorAll("table").forEach(function (t) { if (headOf(t)) { found.push(t); } });
  });
  if (found.length) { return found; }
  for (var p = tools.parentElement; p; p = p.parentElement) {
    var th = p.querySelector("table thead th[data-col]");
    if (th) { return [th.closest("table")]; }
  }
  return [];
}

function headOf(table) {
  var row = table.tHead && table.tHead.rows.length ? table.tHead.rows[0] : null;
  return row && row.querySelector("th[data-col]") ? row : null;
}
function columnHeads(table) { var h = headOf(table); return h ? Array.prototype.slice.call(h.querySelectorAll("th[data-col]")) : []; }
function keysOf(table) { return columnHeads(table).map(function (th) { return th.getAttribute("data-col"); }); }
function headByKey(table, key) { return columnHeads(table).filter(function (th) { return th.getAttribute("data-col") === key; })[0] || null; }

// The rows that have one cell per header cell (a "No row matches" row spans them all and is left alone).
function plainRows(table) {
  var head = headOf(table), n = head ? head.cells.length : 0, out = [];
  Array.prototype.forEach.call(table.rows, function (r) {
    if (r.cells.length !== n) { return; }
    for (var i = 0; i < r.cells.length; i++) { if (r.cells[i].colSpan > 1) { return; } }
    out.push(r);
  });
  return out;
}

// ---- move a column ---------------------------------------------------------------------------------------------------------

function moveCells(table, from, to) {
  plainRows(table).forEach(function (r) {
    var cell = r.cells[from], ref = r.cells[to];
    if (!cell || !ref || cell === ref) { return; }
    if (from < to) { ref.parentNode.insertBefore(cell, ref.nextSibling); } else { ref.parentNode.insertBefore(cell, ref); }
  });
}

// The Columns panel lists the shown columns in the same order, so a later "Save for me" keeps what the header did.
function syncPanel(chooser, keys) {
  var shown = chooser ? chooser.querySelector('[data-colgroup="shown"]') : null;
  if (!shown) { return; }
  // the shown columns are list items ([data-col-item]) of one ordered list
  var list = shown.querySelector("[data-colshown-list]") || shown;
  keys.forEach(function (k) {
    shown.querySelectorAll("[data-col-choice]").forEach(function (lab) {
      var input = lab.querySelector("input");
      if (input && input.value === k) { list.appendChild(lab.closest("[data-col-item]") || lab); }
    });
  });
  if (chooser && typeof chooser.dispatchEvent === "function") { chooser.dispatchEvent(new CustomEvent("si-columns-reordered")); }
}

function moveColumn(ctx, table, key, toKey, after) {
  var keys = keysOf(table), from = keys.indexOf(key), to = keys.indexOf(toKey);
  if (from < 0 || to < 0 || from === to) { return Promise.resolve(false); }
  var fromTh = headByKey(table, key);
  // the place the column ends at, counted without it: after a column to its left is one further, before one to its right one less
  if (after && to < from) { to++; } else if (!after && to > from) { to--; }
  if (to === from) { return Promise.resolve(false); }
  var target = columnHeads(table)[to];
  keys.splice(to, 0, keys.splice(from, 1)[0]);
  var fields = [["Scope", "user"]].concat(keys.map(function (k) { return ["Columns", k]; }));
  table.setAttribute("aria-busy", "true");
  return post(ctx.tools, "Save", fields).then(function (a) {
    table.removeAttribute("aria-busy");
    if (!a.ok) { toast(a.message || "Not saved.", "error"); return false; }
    if (ctx.inPlace) {
      moveCells(table, fromTh.cellIndex, target.cellIndex);
      syncPanel(ctx.chooser, keys);
      toast("Saved: this is your column order on this view.", "ok");
      return true;
    }
    // a table sorted in the browser knows its columns by position: show it again in the saved order
    window.location.reload();
    return true;
  });
}

function label(th) { return (th.getAttribute("data-col-label") || th.textContent || "").replace(/[▲▼]/g, "").replace(/\s+/g, " ").trim(); }

function addMoveButtons(ctx, table, th) {
  var key = th.getAttribute("data-col"), name = th.getAttribute("data-col-label");
  var box = el("span", "th-tools");
  box.setAttribute("data-th-tools", "");
  [["←", "Move the column " + name + " left", -1], ["→", "Move the column " + name + " right", 1]].forEach(function (d) {
    var b = el("button", "secondary small th-move", d[0]);
    b.type = "button";
    b.setAttribute("aria-label", d[1]);
    b.title = d[1];
    b.setAttribute("data-th-move", String(d[2]));
    b.addEventListener("click", function (e) {
      e.preventDefault(); e.stopPropagation();
      var keys = keysOf(table), i = keys.indexOf(key), j = i + d[2];
      if (i < 0 || j < 0 || j >= keys.length) { return; }
      moveColumn(ctx, table, key, keys[j], d[2] > 0).then(function (moved) { if (moved && ctx.inPlace) { b.focus(); } });
    });
    box.appendChild(b);
  });
  th.appendChild(box);
}

function addDrag(ctx, table, th) {
  var key = th.getAttribute("data-col");
  // a link or a sort button inside the header must not be what is dragged
  th.querySelectorAll("a").forEach(function (a) { a.setAttribute("draggable", "false"); });
  th.setAttribute("draggable", "true");
  th.addEventListener("dragstart", function (e) {
    if (th.getAttribute("draggable") !== "true") { e.preventDefault(); return; }
    ctx.dragKey = key; ctx.dragTable = table;
    th.classList.add("th-dragging");
    if (e.dataTransfer) { e.dataTransfer.effectAllowed = "move"; try { e.dataTransfer.setData("text/plain", key); } catch (x) { /* some browsers refuse; the key is kept above */ } }
  });
  th.addEventListener("dragend", function () {
    ctx.dragKey = null; ctx.dragTable = null;
    columnHeads(table).forEach(function (h) { h.classList.remove("th-dragging", "th-drop-before", "th-drop-after"); });
  });
  th.addEventListener("dragover", function (e) {
    if (!ctx.dragKey || ctx.dragTable !== table || ctx.dragKey === key) { return; }
    e.preventDefault();
    if (e.dataTransfer) { e.dataTransfer.dropEffect = "move"; }
    var r = th.getBoundingClientRect(), after = e.clientX > r.left + r.width / 2;
    th.classList.toggle("th-drop-after", after);
    th.classList.toggle("th-drop-before", !after);
  });
  th.addEventListener("dragleave", function () { th.classList.remove("th-drop-before", "th-drop-after"); });
  th.addEventListener("drop", function (e) {
    if (!ctx.dragKey || ctx.dragTable !== table || ctx.dragKey === key) { return; }
    e.preventDefault();
    var r = th.getBoundingClientRect(), after = e.clientX > r.left + r.width / 2;
    th.classList.remove("th-drop-before", "th-drop-after");
    moveColumn(ctx, table, ctx.dragKey, key, after);
  });
}

// ---- column widths ---------------------------------------------------------------------------------------------------------

function clamp(px) { return Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, Math.round(px))); }

function setWidth(table, th, px) {
  var i = th.cellIndex, w = px === null ? "" : px + "px";
  plainRows(table).forEach(function (r) {
    var c = r.cells[i];
    if (!c) { return; }
    c.style.width = w; c.style.minWidth = w; c.style.maxWidth = w;
    c.classList.toggle("col-sized", px !== null);
  });
}

function saveWidths(ctx) {
  window.clearTimeout(ctx.widthTimer);
  ctx.widthTimer = window.setTimeout(function () {
    post(ctx.tools, "Widths", [["Widths", JSON.stringify(ctx.widths)]]).then(function (a) {
      if (!a.ok && !ctx.widthWarned) { ctx.widthWarned = true; toast(a.message || "The column width was not saved.", "error"); }
    });
  }, 400);
}

function addGrip(ctx, table, th) {
  var key = th.getAttribute("data-col"), name = th.getAttribute("data-col-label");
  var grip = el("span", "th-grip");
  grip.setAttribute("role", "separator");
  grip.setAttribute("aria-orientation", "vertical");
  grip.setAttribute("tabindex", "0");
  grip.setAttribute("data-th-grip", "");
  var words = "Width of the column " + name + ": drag, or use the left and right arrow keys; double-click or Enter sets it back";
  grip.setAttribute("aria-label", words);
  grip.title = words;

  function commit(px) {
    if (px === null) { delete ctx.widths[key]; } else { ctx.widths[key] = px; }
    setWidth(table, th, px);
    saveWidths(ctx);
  }

  grip.addEventListener("pointerdown", function (e) {
    if (e.button !== 0) { return; }
    e.preventDefault(); e.stopPropagation();
    th.setAttribute("draggable", "false");
    var startX = e.clientX, startW = th.getBoundingClientRect().width, now = clamp(startW);
    var live = table.rows.length <= LIVE_ROWS, frame = 0;
    try { grip.setPointerCapture(e.pointerId); } catch (x) { /* an old browser: the drag still works while the pointer stays on the edge */ }
    grip.classList.add("th-grip-on");
    function onMove(ev) {
      now = clamp(startW + ev.clientX - startX);
      if (frame) { return; }
      frame = window.requestAnimationFrame(function () {
        frame = 0;
        // a long table is resized when the edge is let go; its header follows the pointer meanwhile
        if (live) { setWidth(table, th, now); } else { th.style.width = now + "px"; th.style.minWidth = now + "px"; th.style.maxWidth = now + "px"; }
      });
    }
    function onUp() {
      grip.removeEventListener("pointermove", onMove);
      grip.removeEventListener("pointerup", onUp);
      grip.removeEventListener("pointercancel", onUp);
      grip.classList.remove("th-grip-on");
      th.setAttribute("draggable", "true");
      if (Math.abs(now - clamp(startW)) >= 2) { commit(now); }
    }
    grip.addEventListener("pointermove", onMove);
    grip.addEventListener("pointerup", onUp);
    grip.addEventListener("pointercancel", onUp);
  });
  grip.addEventListener("click", function (e) { e.preventDefault(); e.stopPropagation(); });
  grip.addEventListener("dblclick", function (e) { e.preventDefault(); e.stopPropagation(); commit(null); });
  grip.addEventListener("keydown", function (e) {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      commit(clamp(th.getBoundingClientRect().width + (e.key === "ArrowLeft" ? -KEY_STEP : KEY_STEP)));
    } else if (e.key === "Enter" || e.key === "Delete") {
      e.preventDefault();
      commit(null);
    }
  });
  th.appendChild(grip);
}

// ---- the last sort / filters / search: a grid whose state is in the address -------------------------------------------------

function keySet(tools) {
  var set = {};
  (tools.getAttribute("data-state-keys") || "").split(" ").forEach(function (k) { if (k) { set[k.toLowerCase()] = true; } });
  return set;
}
function isStateKey(set, k) { k = k.toLowerCase(); return set[k] === true || k.indexOf("f.") === 0; }

// What an address names: has = it names a sort / filter / search at all (then it wins); state = the values it gives.
function addressState(set, search) {
  var out = { has: false, state: {} };
  new URLSearchParams(search).forEach(function (v, k) {
    if (!isStateKey(set, k)) { return; }
    out.has = true;
    if (v.trim() === "") { return; }
    (out.state[k] = out.state[k] || []).push(v);
  });
  return out;
}
function storedAddress(tools) {
  var all = parse(tools.getAttribute("data-state")), out = {};
  Object.keys(all).forEach(function (k) { if (k.toLowerCase().indexOf("t.") !== 0) { out[k] = all[k]; } });
  return out;
}
// The other half of what is stored: the state of the tables sorted in the browser (t.*), every table of the view.
function storedClient(tools) {
  var all = parse(tools.getAttribute("data-state")), out = {};
  Object.keys(all).forEach(function (k) { if (k.toLowerCase().indexOf("t.") === 0 && Array.isArray(all[k])) { out[k] = all[k]; } });
  return out;
}

// ONE state per person and view is stored: the address's sort / filters and every browser-sorted table's own. Each
// report sends the whole of it, so a table that reports its sort never drops the page's filters or another table's sort.
function sendState(ctx) {
  var p = new URLSearchParams(), all = {};
  [ctx.address, ctx.client].forEach(function (part) {
    Object.keys(part).forEach(function (k) {
      if (!Array.isArray(part[k]) || part[k].length === 0) { return; }
      all[k] = part[k];
      part[k].forEach(function (v) { p.append(k, v); });
    });
  });
  return post(ctx.tools, "State", [["State", p.toString()]]).then(function (a) {
    if (a.ok) { ctx.tools.setAttribute("data-state", JSON.stringify(all)); }
    return a;
  });
}
function sameState(a, b) {
  var ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
  if (ka.length !== kb.length) { return false; }
  for (var i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) { return false; }
    var x = a[ka[i]], y = b[kb[i]];
    if (!Array.isArray(x) || !Array.isArray(y) || x.length !== y.length) { return false; }
    for (var j = 0; j < x.length; j++) { if (x[j] !== y[j]) { return false; } }
  }
  return true;
}

function markChange() { try { window.sessionStorage.setItem(CHANGE_KEY, window.location.pathname); } catch (e) { /* no storage: nothing is remembered */ } }
function takeChange() {
  try {
    var v = window.sessionStorage.getItem(CHANGE_KEY);
    window.sessionStorage.removeItem(CHANGE_KEY);
    return v === window.location.pathname;
  } catch (e) { return false; }
}

function samePage(url) { return url.origin === window.location.origin && url.pathname === window.location.pathname && !url.searchParams.has("handler"); }

// A change made on the page is a link or a filter form of this page that leads to this page again. It is noted here and
// reported after the page has loaded with it; a link back to the bare view while something is remembered clears that first.
function listen() {
  if (listening) { return; }
  listening = true;
  document.addEventListener("click", function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { return; }
    var a = e.target instanceof Element ? e.target.closest("a[href]") : null;
    if (!a || a.target === "_blank" || a.hasAttribute("download") || (a.getAttribute("href") || "").charAt(0) === "#") { return; }
    var url;
    try { url = new URL(a.href, window.location.href); } catch (x) { return; }
    if (!samePage(url)) { return; }
    // the menu's own link to this view (it carries nav=menu) opens it with what is remembered: nothing changes, nothing is cleared
    if (url.searchParams.get("nav") === "menu") { return; }
    // paging or opening the same view again changes nothing: only a different sort / filter / search is a change
    if (differs(url.search)) { markChange(); }
    var remembered = addressTools.filter(function (t) { return Object.keys(storedAddress(t)).length > 0 && !addressState(keySet(t), url.search).has; });
    if (remembered.length === 0) { return; }
    e.preventDefault();
    Promise.all(remembered.map(function (t) { t.removeAttribute("data-state"); return post(t, "ClearState", []); }))
      .then(function () { window.location.href = a.href; });
  });
  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (!(f instanceof HTMLFormElement) || (f.getAttribute("method") || "get").toLowerCase() !== "get") { return; }
    var url;
    try { url = new URL(f.getAttribute("action") || window.location.href, window.location.href); } catch (x) { return; }
    if (url.origin !== window.location.origin || url.pathname !== window.location.pathname) { return; }
    var asked;
    try { asked = new URLSearchParams(new FormData(f)).toString(); } catch (x) { asked = null; }
    if (asked === null || differs(asked)) { markChange(); }
  });
}

// Whether an address (its query) asks for another sort / filter / search than the page shows now -- what the page shows
// is what its own address names, else what is remembered.
function differs(search) {
  var tools = addressTools[0];
  if (!tools) { return false; }
  var set = keySet(tools), here = addressState(set, window.location.search);
  var shown = here.has ? here.state : storedAddress(tools);
  return !sameState(addressState(set, search).state, shown);
}

function initAddressState(ctx, changed) {
  var tools = ctx.tools;
  addressTools.push(tools);
  listen();
  if (!changed) { return; }
  var now = addressState(keySet(tools), window.location.search);
  if (now.has && !sameState(now.state, ctx.address)) {
    ctx.address = now.state;
    sendState(ctx);
  }
}

// ---- the last sort / filters / search: a table sorted and filtered in the browser (tables.js) ---------------------------------

function fire(node, type) { node.dispatchEvent(new Event(type, { bubbles: true })); }

function tableBar(table) {
  var host = table.closest(".table-wrap") || table;
  for (var p = host.previousElementSibling, i = 0; p && i < 4; p = p.previousElementSibling, i++) {
    if (p.hasAttribute("data-table-tools")) { return p; }
  }
  return null;
}

// The filter row's cell of every column that has a key: its boxes ("any" multi-select) or its text boxes (contains; from..to).
function filterCells(table) {
  var head = headOf(table), row = table.tHead ? table.tHead.querySelector("tr[data-filter-row]") : null, out = [];
  if (!head || !row) { return out; }
  Array.prototype.forEach.call(head.cells, function (th, i) {
    var key = th.getAttribute("data-col"), td = row.cells[i];
    if (!key || !td) { return; }
    out.push({
      key: key,
      boxes: Array.prototype.slice.call(td.querySelectorAll('input[type="checkbox"]')),
      inputs: Array.prototype.slice.call(td.querySelectorAll('input:not([type="checkbox"])'))
    });
  });
  return out;
}

// A table's own state is kept under its own name -- "t.<table id>/sort", "t.<table id>/f.<column>" -- so a view that shows
// several tables (one per tier, one per section) remembers each. A table without an id keeps the plain "t.sort" names.
var TABLE_KEY = /^t\.[A-Za-z0-9_-]+\//;
function tableId(table) {
  var d = table.closest(".dataview[data-data-table]");
  var id = d ? d.getAttribute("data-data-table") || "" : "";
  return /^[A-Za-z0-9_-]+$/.test(id) ? id : "";
}
function clientPrefix(table) { var id = tableId(table); return id ? "t." + id + "/" : "t."; }
function hasPrefix(state, pre) { return Object.keys(state).some(function (k) { return k.indexOf(pre) === 0; }); }

// What the table shows now, as it is stored: { "<prefix>sort": [column], "<prefix>dir": [asc | desc], "<prefix>q": [text],
// "<prefix>f.<column>": [values] }.
function captureClient(table, pre) {
  var out = {};
  function add(k, v) { (out[pre + k] = out[pre + k] || []).push(v); }
  columnHeads(table).forEach(function (th) {
    var s = th.getAttribute("aria-sort");
    if (s === "ascending" || s === "descending") { add("sort", th.getAttribute("data-col")); add("dir", s === "ascending" ? "asc" : "desc"); }
  });
  var bar = tableBar(table), search = bar ? bar.querySelector('input[type="search"]') : null;
  if (search && search.value.trim()) { add("q", search.value.trim()); }
  filterCells(table).forEach(function (c) {
    c.boxes.forEach(function (b) { if (b.checked) { add("f." + c.key, b.value); } });
    var values = c.inputs.map(function (x) { return x.value.trim(); });
    if (values.some(function (v) { return v !== ""; })) { add("f." + c.key, values.join("..")); }
  });
  return out;
}

function restoreClient(table, stored, pre) {
  function one(k) { k = pre + k; return Array.isArray(stored[k]) && stored[k].length ? stored[k][0] : null; }
  var bar = tableBar(table), search = bar ? bar.querySelector('input[type="search"]') : null;
  if (search && one("q")) { search.value = one("q"); fire(search, "input"); }
  filterCells(table).forEach(function (c) {
    var values = stored[pre + "f." + c.key];
    if (!Array.isArray(values) || values.length === 0) { return; }
    if (c.boxes.length) {
      var any = null;
      c.boxes.forEach(function (b) { if (values.indexOf(b.value) >= 0) { b.checked = true; any = b; } });
      if (any) { fire(any, "change"); }
    } else if (c.inputs.length) {
      var parts = c.inputs.length > 1 ? values[0].split("..") : [values[0]];
      c.inputs.forEach(function (x, i) { x.value = parts[i] || ""; });
      fire(c.inputs[0], "input");
    }
  });
  var key = one("sort"), want = one("dir") === "desc" ? "descending" : "ascending";
  var th = key ? headByKey(table, key) : null, button = th ? th.querySelector("button.th-sort") : null;
  for (var i = 0; button && i < 2 && th.getAttribute("aria-sort") !== want; i++) { button.click(); }
}

// The menu's links to the data views carry nav=menu (Columns/ViewState.cs MenuMarker); it stays in the address, so a reload counts too.
function openedFromMenu() { return new URLSearchParams(window.location.search).get("nav") === "menu"; }

function isClientTable(table) { return table.hasAttribute("data-sortable") && table.getAttribute("data-sortable-ready") === "1"; }

// One table sorted in the browser: restored from what is stored under its own name, and reported after a change.
// only = the view shows this one table (then a state stored before tables had names is still read, once).
function initClientState(ctx, table, only) {
  var pre = clientPrefix(table);
  var plain = only && pre !== "t." && !hasPrefix(ctx.client, pre);
  // like the address's sort and filters: what is remembered comes back when the view was opened from the menu only
  if (openedFromMenu()) { restoreClient(table, ctx.client, plain ? "t." : pre); }
  var last = JSON.stringify(captureClient(table, pre)), timer = 0;
  function later() {
    window.clearTimeout(timer);
    timer = window.setTimeout(function () {
      var now = captureClient(table, pre), text = JSON.stringify(now);
      if (text === last) { return; }
      last = text;
      // this table's part is replaced (and, for the only table of a view, what was stored without a table's name)
      Object.keys(ctx.client).forEach(function (k) {
        if (k.indexOf(pre) === 0 || (only && !TABLE_KEY.test(k))) { delete ctx.client[k]; }
      });
      Object.keys(now).forEach(function (k) { ctx.client[k] = now[k]; });
      sendState(ctx);
    }, 900);
  }
  var bar = tableBar(table), chips = bar ? bar.nextElementSibling : null;
  [table.tHead, bar, chips && chips.classList.contains("filter-chips") ? chips : null].forEach(function (node) {
    if (!node) { return; }
    node.addEventListener("click", later);
    node.addEventListener("input", later);
    node.addEventListener("change", later);
  });
}

// ---- start ---------------------------------------------------------------------------------------------------------------

export function initViewTools(tools, chooser) {
  if (tools.getAttribute("data-view-tools-ready") === "1") { return; }
  tools.setAttribute("data-view-tools-ready", "1");
  var tables = tablesOf(tools);
  var canSave = tools.getAttribute("data-store-ready") === "1", more = tools.getAttribute("data-more-ready") === "1";
  var ctx = {
    tools: tools, chooser: chooser || null, widths: parse(tools.getAttribute("data-widths")), dragKey: null, dragTable: null, widthTimer: 0, widthWarned: false,
    // what is remembered: the address's sort / filters, and the state of each table sorted in the browser
    address: {}, client: {},
    // one grid the server sorts is rearranged in place; anything else is shown again in the saved order
    inPlace: tables.length === 1 && !tables[0].hasAttribute("data-sortable")
  };
  tables.forEach(function (table) {
    var heads = columnHeads(table);
    heads.forEach(function (th) { th.setAttribute("data-col-label", label(th)); });
    heads.forEach(function (th) {
      if (window.getComputedStyle(th).position === "static") { th.classList.add("th-rel"); }
      th.classList.add("th-has-tools");
      if (canSave && heads.length > 1) { addMoveButtons(ctx, table, th); addDrag(ctx, table, th); }
      if (more) { addGrip(ctx, table, th); }
    });
    if (more) {
      Object.keys(ctx.widths).forEach(function (key) {
        var th = headByKey(table, key), px = Number(ctx.widths[key]);
        if (th && isFinite(px)) { setWidth(table, th, clamp(px)); }
      });
    }
    table.setAttribute("data-view-tools-table", tools.getAttribute("data-view") || "");
  });
  if (more) {
    // "address" = a grid, or a page whose filters are in its address; "client" = tables sorted in the browser; a page
    // table under a page with filters of its own has both
    var modes = (tools.getAttribute("data-state-mode") || "address").split(" ");
    var client = modes.indexOf("client") >= 0, address = modes.indexOf("address") >= 0;
    ctx.address = storedAddress(tools);
    ctx.client = storedClient(tools);
    if (client) {
      // every table of the view keeps its own state, under its own name
      tables.forEach(function (table) {
        if (!isClientTable(table) || table.getAttribute("data-view-state-ready") === "1") { return; }
        table.setAttribute("data-view-state-ready", "1");
        initClientState(ctx, table, tables.length === 1);
      });
    }
    // a page with filters of its own remembers them even while they leave no row to show
    if (address && (tables.length > 0 || client)) { initAddressState(ctx, changedOnPage()); }
  }
  // Enter in the layout's name box saves the layout, never "Save for me"
  var name = chooser ? chooser.querySelector("[data-layout-name]") : null;
  if (name) {
    name.addEventListener("keydown", function (e) {
      if (e.key !== "Enter") { return; }
      e.preventDefault();
      var save = chooser.querySelector("[data-layout-save-new]");
      if (save && name.value.trim()) { save.click(); }
    });
  }
}

// Whether this page was reached by a change the person made on it (read once: several views may share a page).
var changeRead = false, changeValue = false;
function changedOnPage() {
  if (!changeRead) { changeRead = true; changeValue = takeChange(); }
  return changeValue;
}
