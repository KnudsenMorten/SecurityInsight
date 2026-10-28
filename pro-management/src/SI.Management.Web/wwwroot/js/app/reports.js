// Reports (#274, #275 G7). The server renders and is the authority (validation, staging); this module keeps the
// drafts in the browser:
//   - the report templates builder: drag a report from the catalog into the template, reorder by dragging, Up / Down
//     buttons or Alt+Up / Alt+Down, take it out with Remove or Delete -- every change rewrites the hidden Draft (JSON list);
//   - the catalog search on the builder;
//   - the Exclusions list editor: each list as items with Remove, an Add field, and one search over every list; the
//     textarea it replaces stays the form field (one entry per line).

import { formatNumber } from "./numbers.js";

function readJson(el, fallback) { try { return JSON.parse(el ? el.value : "") || fallback; } catch (e) { return fallback; } }

function initBuilder(form) {
  const edit = form.dataset.templateBuilder === "edit";
  const draftEl = form.querySelector("[data-draft]");
  const list = form.querySelector("[data-included-list]");
  const count = form.querySelector("[data-included-count]");
  const search = form.querySelector("[data-catalog-search]");
  const hideAdded = form.querySelector("[data-hide-added]");
  let items = readJson(draftEl, []);

  // the catalog shows which reports are already in the template (#312): "Added ✓" (disabled) instead of Add, a muted row,
  // and the optional "hide added" filter; the search and that filter decide together what is visible
  function filterCatalog() {
    const q = search ? search.value.trim().toLowerCase() : "";
    const hide = !!(hideAdded && hideAdded.checked);
    form.querySelectorAll("[data-catalog-item]").forEach(function (li) {
      const hit = !q || li.dataset.catalogItem.toLowerCase().indexOf(q) >= 0 || (li.dataset.domain || "").toLowerCase().indexOf(q) >= 0;
      li.hidden = !hit || (hide && li.dataset.added === "true");
    });
  }
  function syncCatalog() {
    form.querySelectorAll("[data-catalog-item]").forEach(function (li) {
      const name = li.dataset.catalogItem;
      const added = items.indexOf(name) >= 0;
      li.dataset.added = added ? "true" : "false";
      li.classList.toggle("is-added", added);
      const b = li.querySelector("[data-add-report]");
      if (b) {
        b.disabled = added;
        b.textContent = added ? "Added ✓" : "Add";
        b.setAttribute("aria-label", added ? name + " is already in the template" : "Add " + name + " to the template");
      }
    });
    filterCatalog();
  }
  if (search) search.addEventListener("input", filterCatalog);
  if (hideAdded) hideAdded.addEventListener("change", filterCatalog);
  if (!edit || !list) return;

  function button(text, attr, label, title) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "small " + (attr === "data-remove" ? "quiet-danger" : "secondary icon");
    b.setAttribute(attr, ""); b.textContent = text; b.setAttribute("aria-label", label);
    if (title) b.title = title;
    return b;
  }

  function render(focusName) {
    draftEl.value = JSON.stringify(items);
    list.innerHTML = "";
    items.forEach(function (name) {
      const li = document.createElement("li");
      li.dataset.included = name; li.draggable = true; li.tabIndex = 0;
      const s = document.createElement("span"); s.textContent = name; li.appendChild(s);
      li.appendChild(document.createTextNode(" "));
      li.appendChild(button("↑", "data-move-up", "Move " + name + " up", "Move up"));
      li.appendChild(button("↓", "data-move-down", "Move " + name + " down", "Move down"));
      li.appendChild(button("Remove", "data-remove", "Remove " + name + " from the template"));
      list.appendChild(li);
    });
    if (count) count.textContent = formatNumber(items.length);
    syncCatalog();
    form.dataset.dirty = "1";
    if (focusName) { const f = list.querySelector('[data-included="' + CSS.escape(focusName) + '"]'); if (f) f.focus(); }
  }

  function add(name, at) {
    items = items.filter(function (x) { return x !== name; });
    const i = (typeof at === "number" && at >= 0 && at <= items.length) ? at : items.length;
    items.splice(i, 0, name);
    render(name);
  }
  function move(name, delta) {
    const i = items.indexOf(name); const j = i + delta;
    if (i < 0 || j < 0 || j >= items.length) return;
    items.splice(i, 1); items.splice(j, 0, name);
    render(name);
  }
  function remove(name) { items = items.filter(function (x) { return x !== name; }); render(); }

  form.addEventListener("click", function (e) {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.hasAttribute("data-add-report")) { add(t.getAttribute("data-add-report")); return; }
    const li = t.closest("[data-included]");
    if (!li) return;
    if (t.hasAttribute("data-move-up")) move(li.dataset.included, -1);
    else if (t.hasAttribute("data-move-down")) move(li.dataset.included, 1);
    else if (t.hasAttribute("data-remove")) remove(li.dataset.included);
  });
  list.addEventListener("keydown", function (e) {
    const li = e.target instanceof HTMLElement ? e.target.closest("[data-included]") : null;
    if (!li) return;
    if (e.altKey && e.key === "ArrowUp") { e.preventDefault(); move(li.dataset.included, -1); }
    else if (e.altKey && e.key === "ArrowDown") { e.preventDefault(); move(li.dataset.included, 1); }
    else if (e.key === "Delete" && e.target === li) { e.preventDefault(); remove(li.dataset.included); }
  });

  // drag: from the catalog (add) or within the template (reorder); dropped on an item = placed before it
  form.addEventListener("dragstart", function (e) {
    const t = e.target instanceof Element ? e.target.closest("[data-catalog-item], [data-included]") : null;
    if (!t) return;
    const name = t.dataset.catalogItem || t.dataset.included;
    if (!name) return;
    if (items.indexOf(name) < 0 && !t.dataset.catalogItem) return;
    e.dataTransfer.setData("text/plain", name);
    e.dataTransfer.effectAllowed = "copyMove";
  });
  list.addEventListener("dragover", function (e) { e.preventDefault(); list.classList.add("drop-target"); });
  list.addEventListener("dragleave", function () { list.classList.remove("drop-target"); });
  list.addEventListener("drop", function (e) {
    e.preventDefault(); list.classList.remove("drop-target");
    const name = e.dataTransfer.getData("text/plain");
    // only a report of the catalog can be dropped (text dragged from elsewhere is ignored)
    if (!name || !form.querySelector('[data-catalog-item="' + CSS.escape(name) + '"]')) return;
    const over = e.target instanceof HTMLElement ? e.target.closest("[data-included]") : null;
    let at = items.length;
    if (over) { at = items.indexOf(over.dataset.included); if (items.indexOf(name) >= 0 && items.indexOf(name) < at) at--; }
    add(name, at);
  });
  // the catalog's items are draggable once the module runs
  form.querySelectorAll("[data-catalog-item]").forEach(function (li) { li.draggable = true; });
}

function initListEditors(form) {
  const edit = form.dataset.exclusions === "edit";
  const search = form.querySelector("[data-list-search]");
  const editors = Array.prototype.slice.call(form.querySelectorAll("[data-list-editor]"));
  editors.forEach(function (box) {
    const src = box.querySelector("[data-list-source]");
    if (!src) return;
    src.hidden = true;
    const ul = document.createElement("ul"); ul.className = "list-items"; ul.setAttribute("data-list-items", box.dataset.listEditor);
    box.appendChild(ul);
    function values() { return src.value.split("\n").map(function (x) { return x.trim(); }).filter(function (x) { return x.length > 0; }); }
    function render() {
      ul.innerHTML = "";
      values().forEach(function (v) {
        const li = document.createElement("li"); li.dataset.item = v;
        const s = document.createElement("span"); s.textContent = v; li.appendChild(s);
        if (edit) {
          const b = document.createElement("button"); b.type = "button"; b.className = "small danger"; b.textContent = "Remove";
          b.setAttribute("aria-label", "Remove " + v); b.setAttribute("data-remove-item", "");
          b.addEventListener("click", function () { src.value = values().filter(function (x) { return x !== v; }).join("\n"); render(); form.dataset.dirty = "1"; });
          li.appendChild(document.createTextNode(" ")); li.appendChild(b);
        }
        ul.appendChild(li);
      });
      if (search) filter();
    }
    if (edit) {
      const row = document.createElement("div"); row.className = "list-add";
      const input = document.createElement("input"); input.type = "text"; input.placeholder = src.getAttribute("placeholder") || "";
      input.setAttribute("aria-label", "Add to " + (box.querySelector("label") ? box.querySelector("label").textContent : "the list"));
      input.setAttribute("data-add-input", box.dataset.listEditor);
      const b = document.createElement("button"); b.type = "button"; b.className = "small secondary"; b.textContent = "Add"; b.setAttribute("data-add-item", box.dataset.listEditor);
      function addIt() {
        const v = input.value.trim(); if (!v) return;
        const have = values(); if (have.indexOf(v) < 0) have.push(v);
        src.value = have.join("\n"); input.value = ""; render(); form.dataset.dirty = "1"; input.focus();
      }
      b.addEventListener("click", addIt);
      input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); addIt(); } });
      row.appendChild(input); row.appendChild(b); box.appendChild(row);
    }
    render();
  });
  function filter() {
    const q = search.value.trim().toLowerCase();
    form.querySelectorAll("[data-list-items] li").forEach(function (li) { li.hidden = !!q && li.dataset.item.toLowerCase().indexOf(q) < 0; });
  }
  if (search) search.addEventListener("input", filter);
}

export function initReports() {
  const b = document.querySelector("[data-template-builder]");
  if (b) initBuilder(b);
  const x = document.querySelector("[data-exclusions]");
  if (x) initListEditors(x);
}
