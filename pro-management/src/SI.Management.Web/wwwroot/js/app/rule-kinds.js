// #1351 (owner 2026-11-24: "a collapsed sorting per KIND (grouped)"): Configuration > Profiling rules -- the rules table in
// one section per condition kind, collapsed by default. The server writes the sections (a header <tbody data-kind-head>
// with its checkbox toggle, then the section's rows in <tbody data-kind-rows>; CSS shows the rows of a ticked section, so
// open / close needs no script); a rule with several kinds is in each of them.
// The table's own search box and filter row (tables.js) still work over every rule: while a search or a filter is set,
// the sections with matches open by themselves, a section with none disappears, and each count says "matches of total";
// when they are cleared, the sections are open or closed again as the person had them. Sorting stays per section.
import { formatNumber } from "./numbers.js";

// PURE. groups: [{ key, total, shown }]; filtering: a search or a filter is set; open: { key: true } as the person left
// them. Returns, per section, whether it is open, whether it is gone, and the numbers its count shows.
export function sectionState(groups, filtering, open) {
  return groups.map(function (g) {
    return {
      key: g.key,
      gone: !!filtering && g.shown === 0,
      open: filtering ? g.shown > 0 : !!(open && open[g.key]),
      shown: filtering ? g.shown : null,
      total: g.total
    };
  });
}

// the section's checkbox IS its open state: CSS shows the rows of a ticked section (it works with no script at all)
function setOpen(head, rows, on) {
  var b = head.querySelector("[data-kind-toggle]");
  if (b) { b.checked = !!on; }
}

export function initRuleKinds(table) {
  if (!table || table.getAttribute("data-kinds-ready") === "1") { return; }
  table.setAttribute("data-kinds-ready", "1");
  var card = table.closest("section") || table.parentNode;
  var sections = Array.prototype.map.call(table.querySelectorAll("tbody[data-kind-head]"), function (head) {
    var b = head.querySelector("[data-kind-toggle]");
    var rows = b ? document.getElementById(b.getAttribute("aria-controls")) : null;
    return { key: head.getAttribute("data-kind-head"), head: head, rows: rows, button: b };
  }).filter(function (s) { return s.rows && s.button; });
  var mine = {};          // the sections the person opened (the state a cleared search goes back to)
  var lastSig = null;

  function filterSignature() {
    var parts = [];
    card.querySelectorAll("[data-table-tools] input, [data-filter-row] input").forEach(function (i) {
      if (i.type === "checkbox") { if (i.checked) { parts.push("c:" + i.value); } }
      else if (i.value.trim()) { parts.push("t:" + i.value.trim()); }
    });
    return parts.join("\u0001");
  }

  function refresh() {
    var sig = filterSignature(), filtering = sig !== "";
    var changed = sig !== lastSig;
    lastSig = sig;
    var groups = sections.map(function (s) {
      var all = s.rows.rows, shown = 0;
      for (var i = 0; i < all.length; i++) { if (!all[i].hidden) { shown++; } }
      return { key: s.key, total: all.length, shown: shown };
    });
    sectionState(groups, filtering, mine).forEach(function (st, i) {
      var s = sections[i], count = s.head.querySelector("[data-kind-count]");
      s.head.hidden = st.gone;
      if (st.gone) { setOpen(s.head, s.rows, false); }
      // a person's own open / close stands until the search or a filter changes
      else if (changed) { setOpen(s.head, s.rows, st.open); }
      if (count) { count.textContent = st.shown === null ? formatNumber(st.total) : formatNumber(st.shown) + " of " + formatNumber(st.total); }
    });
    // the table's row count counts each rule once, as the Rules counter does (a rule is in every section of its kinds)
    var all = {}, seen = {}, nAll = 0, nSeen = 0;
    table.querySelectorAll("tbody[data-kind-rows] tr[data-rule]").forEach(function (r) {
      var k = r.getAttribute("data-rule");
      if (!all[k]) { all[k] = true; nAll++; }
      if (!r.hidden && !seen[k]) { seen[k] = true; nSeen++; }
    });
    var rc = card.querySelector("[data-table-tools] span[aria-live]");
    if (rc) { rc.textContent = nSeen === nAll ? formatNumber(nAll) + " rows" : formatNumber(nSeen) + " of " + formatNumber(nAll) + " rows"; }
  }

  // the checkbox opens and closes its section by itself (CSS); remembered here so a cleared search goes back to it
  sections.forEach(function (s) {
    s.button.addEventListener("change", function () {
      if (filterSignature() === "") { if (s.button.checked) { mine[s.key] = true; } else { delete mine[s.key]; } }
    });
  });
  // tables.js filters on input / change and its chips and Clear all on click: look again after it has
  function later(e) {
    if (e && e.target && e.target.closest && e.target.closest("[data-kind-toggle]")) { return; }
    window.setTimeout(refresh, 0);
  }
  card.addEventListener("input", later);
  card.addEventListener("change", later);
  card.addEventListener("click", later);
  refresh();   // a search the browser kept (back to the page) opens its sections at once
}
