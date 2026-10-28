// The row-click hook of the shared grid: a row with data-row-drawer="<url>" opens a side drawer AT ONCE (no page
// reload) with the HTML fragment that URL answers. A click on a link, a button, a checkbox or a form field in the row
// keeps its own meaning -- except the row's own link to that content (a[data-drawer-link]), which opens the drawer. The grid's page may put its own <aside data-drawer> in place (else one is added), and listens to
// the "si:row-open" event (detail: { key, url, row }) for anything more.
function drawerOf(doc) {
  var d = doc.querySelector("aside[data-drawer]");
  if (d) { return d; }
  d = doc.createElement("aside");
  d.setAttribute("data-drawer", "");
  d.className = "drawer";
  d.setAttribute("role", "dialog");
  d.setAttribute("aria-modal", "false");
  d.hidden = true;
  doc.body.appendChild(d);
  return d;
}

export function initRowDrawer(doc) {
  doc.addEventListener("click", function (e) {
    var t = e.target;
    if (!(t instanceof Element)) { return; }
    // a row's own link to the same content as a plain page (data-drawer-link: what works without this file, and what
    // the keyboard reaches) opens the drawer in place too -- unless it is opened in a new tab or window
    var link = t.closest("a[data-drawer-link]");
    if (link && (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey)) { return; }
    if (!link && t.closest("a, button, input, select, textarea, label, summary")) { return; }
    var row = t.closest("tr[data-row-drawer]");
    if (!row) { return; }
    var url = row.getAttribute("data-row-drawer");
    if (!url) { return; }
    if (link) { e.preventDefault(); }
    var drawer = drawerOf(doc);
    drawer.hidden = false;
    drawer.setAttribute("aria-busy", "true");
    drawer.textContent = "Loading...";
    doc.querySelectorAll("tr[data-row-open]").forEach(function (r) { r.removeAttribute("data-row-open"); });
    row.setAttribute("data-row-open", "");
    row.dispatchEvent(new CustomEvent("si:row-open", { bubbles: true, detail: { key: row.getAttribute("data-key"), url: url, row: row } }));
    fetch(url, { credentials: "same-origin", headers: { "Accept": "text/html" } })
      .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function (html) {
        drawer.innerHTML = '<button type="button" class="secondary small" data-drawer-close aria-label="Close">Close</button>' + html;
        // the keyboard continues in the drawer (its Close button first)
        var close = drawer.querySelector("[data-drawer-close]");
        if (link && close) { close.focus(); }
      })
      .catch(function () { drawer.textContent = "This row could not be opened."; })
      .finally(function () { drawer.removeAttribute("aria-busy"); });
  });
  doc.addEventListener("click", function (e) {
    var t = e.target;
    if (t instanceof Element && t.closest("[data-drawer-close]")) {
      var d = t.closest("aside[data-drawer]");
      if (d) { d.hidden = true; }
    }
  });
  doc.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { var d = doc.querySelector("aside[data-drawer]"); if (d) { d.hidden = true; } }
  });
}
