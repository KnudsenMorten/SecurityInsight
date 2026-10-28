// The column chooser of every data view (Pages/Shared/_ColumnChooser.cshtml): a search box over hundreds of columns.
// Typing narrows EVERY list at once -- the shown columns and each "Add" group (words, technical name or key) -- opens the
// groups that hold a match and hides the ones without. Without script the groups simply open and close by hand.
// The order of the shown columns (owner 2026-10-19: "how can i drag drop them up so I dont have to click 100 times"):
// drag a column by its handle (mouse and touch: pointer events), "Move to start" / "Move to end", "←" / "→" one place,
// type its position, or Alt + Up / Alt + Down on it. The form posts the ticked boxes in the order they stand on the page,
// so moving a column here is all it takes -- "Save for me" (or an Admin's "Save as the tenant default") keeps the order,
// and every export follows it.

function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }

function button(text, name, dir) {
  var b = el("button", "secondary small colmove", text);
  b.type = "button";
  b.setAttribute("aria-label", name);
  b.title = name;
  b.setAttribute("data-col-move", dir);
  return b;
}

function initColumnOrder(root) {
  var shown = root.querySelector('[data-colgroup="shown"]');
  if (!shown) { return; }
  var list = shown.querySelector("[data-colshown-list]") || shown;
  var live = el("p", "sr-only");
  live.setAttribute("aria-live", "polite");
  shown.appendChild(live);

  function items() { return Array.prototype.slice.call(list.querySelectorAll("[data-col-item]")); }
  function itemOf(node) { return node && node.closest ? node.closest("[data-col-item]") : null; }
  function nameOf(item) { var w = item.querySelector(".col-words"); return w ? w.textContent.trim() : ""; }

  // every item's position box shows its place (1-based)
  function renumber() {
    items().forEach(function (it, i) {
      var pos = it.querySelector("[data-col-pos]");
      if (pos) { pos.value = String(i + 1); pos.max = String(items().length); }
    });
  }
  function moveTo(item, index, focus) {
    var all = items(), from = all.indexOf(item);
    index = Math.max(0, Math.min(all.length - 1, index));
    if (from < 0 || from === index) { renumber(); return; }
    all.splice(from, 1);
    var ref = all[index] || null;
    list.insertBefore(item, ref);
    renumber();
    live.textContent = nameOf(item) + ": position " + (index + 1) + " of " + (all.length + 1);
    if (focus) { focus.focus(); }
  }

  items().forEach(function (it) {
    var lab = it.querySelector("[data-col-choice]");
    if (!lab) { return; }
    var name = nameOf(it);
    var handle = el("span", "colgrip", "⠿");
    handle.setAttribute("data-col-drag", "");
    handle.setAttribute("aria-hidden", "true");
    handle.title = "Drag to move " + name;
    it.insertBefore(handle, lab);
    var tools = el("span", "colmove-tools");
    tools.appendChild(button("⤒", "Move " + name + " to the start", "start"));
    lab.appendChild(button("←", "Move this column left", "-1"));
    lab.appendChild(button("→", "Move this column right", "1"));
    tools.appendChild(button("⤓", "Move " + name + " to the end", "end"));
    var pos = el("input", "colpos");
    pos.type = "number"; pos.min = "1"; pos.inputMode = "numeric";
    pos.setAttribute("data-col-pos", "");
    pos.setAttribute("aria-label", "Position of " + name);
    tools.appendChild(pos);
    it.appendChild(tools);
  });
  renumber();

  list.addEventListener("click", function (e) {
    var t = e.target;
    var b = t instanceof Element ? t.closest("[data-col-move]") : null;
    if (!b) { return; }
    e.preventDefault();
    var it = itemOf(b);
    if (!it) { return; }
    var all = items(), at = all.indexOf(it), d = b.getAttribute("data-col-move");
    moveTo(it, d === "start" ? 0 : d === "end" ? all.length - 1 : at + Number(d), b);
  });
  // type a position: Enter or leaving the box moves the column there
  function fromBox(box) {
    var it = itemOf(box), n = parseInt(box.value, 10);
    if (!it || !isFinite(n)) { renumber(); return; }
    moveTo(it, n - 1, box);
  }
  list.addEventListener("change", function (e) { if (e.target instanceof HTMLInputElement && e.target.hasAttribute("data-col-pos")) { fromBox(e.target); } });
  list.addEventListener("keydown", function (e) {
    var t = e.target;
    if (t instanceof HTMLInputElement && t.hasAttribute("data-col-pos") && e.key === "Enter") { e.preventDefault(); fromBox(t); return; }
    // Alt + Up / Down on a column (its checkbox or any of its controls) moves it one place
    if (!e.altKey || (e.key !== "ArrowUp" && e.key !== "ArrowDown")) { return; }
    var it = itemOf(t);
    if (!it) { return; }
    e.preventDefault();
    moveTo(it, items().indexOf(it) + (e.key === "ArrowUp" ? -1 : 1), t instanceof HTMLElement ? t : null);
  });

  // drag by the handle: pointer events, so a mouse, a pen and a finger all work; the item follows the pointer's place
  var drag = null;
  list.addEventListener("pointerdown", function (e) {
    var h = e.target instanceof Element ? e.target.closest("[data-col-drag]") : null;
    if (!h) { return; }
    var it = itemOf(h);
    if (!it) { return; }
    e.preventDefault();
    drag = { item: it, id: e.pointerId };
    it.classList.add("col-dragging");
    try { h.setPointerCapture(e.pointerId); } catch (err) { /* capture is a nicety */ }
  });
  list.addEventListener("pointermove", function (e) {
    if (!drag || e.pointerId !== drag.id) { return; }
    e.preventDefault();
    var over = items().filter(function (x) { return x !== drag.item; }).find(function (x) {
      var r = x.getBoundingClientRect();
      return e.clientY >= r.top && e.clientY <= r.bottom;
    });
    if (!over) { return; }
    var r = over.getBoundingClientRect();
    list.insertBefore(drag.item, e.clientY < r.top + r.height / 2 ? over : over.nextSibling);
  });
  function end(e) {
    if (!drag || (e && e.pointerId !== drag.id)) { return; }
    drag.item.classList.remove("col-dragging");
    var it = drag.item;
    drag = null;
    renumber();
    live.textContent = nameOf(it) + ": position " + (items().indexOf(it) + 1) + " of " + items().length;
  }
  list.addEventListener("pointerup", end);
  list.addEventListener("pointercancel", end);
  // a reorder from the table header (view-tools.js) renumbers the boxes
  root.addEventListener("si-columns-reordered", renumber);
}

// the view bar ([data-view-tools]) of this chooser: right after it (or, on an older page, right before it)
function toolsOf(root) {
  var view = root.getAttribute("data-view");
  var next = root.nextElementSibling, prev = root.previousElementSibling;
  if (next && next.hasAttribute("data-view-tools") && next.getAttribute("data-view") === view) { return next; }
  if (prev && prev.hasAttribute("data-view-tools") && prev.getAttribute("data-view") === view) { return prev; }
  return null;
}

export function initColumnChooser(root) {
  initColumnOrder(root);
  // the view bar beside the chooser: the header's move / resize controls and the remembered sort and filters (view-tools.js)
  var tools = toolsOf(root);
  if (tools) {
    import("./view-tools.js").then(function (m) { m.initViewTools(tools, root); });
  }
  var box = root.querySelector("[data-colchooser-search]");
  if (!box) { return; }
  var none = root.querySelector("[data-colchooser-none]");
  function apply() {
    var q = box.value.trim().toLowerCase();
    var any = false;
    root.querySelectorAll("[data-colgroup]").forEach(function (grp) {
      var hits = 0;
      grp.querySelectorAll("[data-col-choice]").forEach(function (lab) {
        var input = lab.querySelector("input");
        var text = (lab.textContent + " " + (input ? input.value : "")).toLowerCase();
        var hit = q.length === 0 || text.indexOf(q) >= 0;
        // a shown column is a list item: the whole item (its handle and buttons) goes with it
        var host = lab.closest("[data-col-item]") || lab;
        host.hidden = !hit;
        lab.hidden = !hit;
        if (hit) { hits++; }
      });
      grp.hidden = q.length > 0 && hits === 0;
      if (grp.tagName === "DETAILS" && q.length > 0 && hits > 0) { grp.open = true; }
      if (hits > 0) { any = true; }
    });
    if (none) { none.hidden = q.length === 0 || any; }
  }
  box.addEventListener("input", apply);
  // Enter in the search box filters; it never submits the form by accident
  box.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); apply(); } });
  // the panel closes with Escape and gives the focus back to the Columns button
  root.addEventListener("keydown", function (e) {
    if (e.key !== "Escape" || !root.open) { return; }
    root.open = false;
    var s = root.querySelector("summary");
    if (s) { s.focus(); }
  });
}
