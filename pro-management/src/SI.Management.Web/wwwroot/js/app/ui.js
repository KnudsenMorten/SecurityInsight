// Shared page behaviour: toasts, the confirm modal (never window.confirm/alert), the theme toggle, filter forms that
// submit on change, and the row selection that drives the quick-change strip. Every page works without this file;
// it only makes the same forms nicer.

import { formatNumber } from "./numbers.js";

export function toast(text, kind) {
  var host = document.querySelector("[data-toasts]");
  if (!host) { return; }
  var t = document.createElement("div");
  t.className = "toast " + (kind || "ok");
  t.setAttribute("role", "status");
  t.textContent = text;
  host.appendChild(t);
  window.setTimeout(function () { t.remove(); }, 6000);
}

export function initToasts() {
  document.querySelectorAll("[data-toasts] .toast").forEach(function (t) {
    window.setTimeout(function () { t.remove(); }, 8000);
  });
}

// <form data-confirm="Text" data-confirm-title="Title"> asks first, in the shared <dialog>.
export function confirmDialog(title, text, okText) {
  var dlg = document.querySelector("[data-confirm-dialog]");
  if (!dlg || typeof dlg.showModal !== "function") { return Promise.resolve(true); }
  dlg.querySelector("[data-confirm-title]").textContent = title || "Are you sure?";
  dlg.querySelector("[data-confirm-text]").textContent = text || "";
  dlg.querySelector("[data-confirm-ok]").textContent = okText || "Continue";
  return new Promise(function (resolve) {
    dlg.addEventListener("close", function onClose() {
      dlg.removeEventListener("close", onClose);
      resolve(dlg.returnValue === "ok");
    });
    dlg.returnValue = "";
    dlg.showModal();
  });
}

export function initConfirm() {
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-confirm") || form.dataset.confirmed === "1") { return; }
    e.preventDefault();
    var submitter = e.submitter;
    confirmDialog(form.getAttribute("data-confirm-title"), form.getAttribute("data-confirm"), form.getAttribute("data-confirm-ok")).then(function (ok) {
      if (!ok) { return; }
      // Re-submit WITH the button that was pressed: its formaction (asp-page-handler on a button, e.g. Commit vs
      // Discard on Review & commit), formmethod and name/value travel only with the submitter. form.submit() drops
      // them, and the post then reaches the page with no handler at all.
      form.dataset.confirmed = "1";
      try {
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit(submitter && submitter.form === form ? submitter : undefined);
        } else {
          if (submitter) {
            var fa = submitter.getAttribute("formaction");
            if (fa) { form.setAttribute("action", fa); }
            if (submitter.name) {
              var h = document.createElement("input");
              h.type = "hidden"; h.name = submitter.name; h.value = submitter.value;
              form.appendChild(h);
            }
          }
          form.submit();
        }
      } finally {
        // a submit that does not leave the page (a download) asks again next time
        delete form.dataset.confirmed;
      }
    });
  });
}

// The header's Theme switch: Auto (the operating system decides) / Light / Dark, remembered per browser. theme.js applies
// it before first paint on the next page; here it applies at once, and the charts redraw in the new colours.
export function initTheme() {
  var root = document.documentElement;
  var stored = null;
  try { stored = window.localStorage.getItem("si-theme"); } catch (err) { stored = null; }
  var current = stored === "light" || stored === "dark" ? stored : "auto";
  function set(next) {
    if (next === "light" || next === "dark") { root.setAttribute("data-theme", next); } else { root.removeAttribute("data-theme"); }
    try {
      if (next === "light" || next === "dark") { window.localStorage.setItem("si-theme", next); } else { window.localStorage.removeItem("si-theme"); }
    } catch (err) { /* private window: the choice lasts this page */ }
    window.dispatchEvent(new CustomEvent("si-theme-change", { detail: next }));
  }
  document.querySelectorAll("select[data-theme-choice]").forEach(function (s) {
    s.value = current;
    s.addEventListener("change", function () { set(s.value); });
  });
  // the older one-click toggle, wherever a page still has one
  document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
    b.addEventListener("click", function () {
      var cur = root.getAttribute("data-theme");
      var dark = cur ? cur === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
      set(dark ? "light" : "dark");
    });
  });
  // Auto follows the operating system live
  var mq = window.matchMedia("(prefers-color-scheme: dark)");
  if (mq.addEventListener) { mq.addEventListener("change", function () { if (!root.getAttribute("data-theme")) { window.dispatchEvent(new CustomEvent("si-theme-change", { detail: "auto" })); } }); }
}

// <form data-autosubmit> submits when a select changes (the filter bars).
export function initAutosubmit() {
  document.querySelectorAll("form[data-autosubmit] select").forEach(function (s) {
    s.addEventListener("change", function () { s.form.requestSubmit ? s.form.requestSubmit() : s.form.submit(); });
  });
}

// The hint a grid toolbar's actions carry while nothing is ticked (#282).
export var SELECTION_HINT = "tick rows to act on them";

// The hint of the selected-rows export while nothing is ticked (ExportLabels.SelectedRowsNone).
var SELECTED_EXPORT_HINT = "Tick rows in the table first";

// The grid pager's page box (Pages/Shared/_GridToolbar.cshtml): type a page and press Enter (or leave the box) to go
// there. The box belongs to no form, so Enter never submits a page's own form; a number outside 1..last is brought in.
export function initPageBoxes() {
  document.querySelectorAll("input[data-gt-page-box]").forEach(function (box) {
    var href = box.getAttribute("data-href"), marker = box.getAttribute("data-marker");
    if (!href || !marker) { return; }
    function go() {
      var max = parseInt(box.getAttribute("max"), 10) || 1;
      var n = parseInt(String(box.value).replace(/\D/g, ""), 10);
      if (!isFinite(n)) { box.value = box.getAttribute("data-page"); return; }
      n = Math.min(Math.max(n, 1), max);
      if (String(n) === box.getAttribute("data-page")) { box.value = n; return; }
      window.location.href = href.split(marker).join(String(n));
    }
    box.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); go(); } });
    box.addEventListener("change", go);
  });
}

// The view toolbar's "Filters" button (a grid whose filters sit in its header row). The row is shown with the page, so a
// first click that hid it read as "nothing happens" (a customer 2026-10-20): the first click brings the filters to the
// person -- the row shown, scrolled into view, its first ACTIVE filter opened (else the first) -- and the button says
// "Hide filters"; that click hides the row and gives the button its own words back.
export function revealFilters(row) {
  row.hidden = false;
  if (row.scrollIntoView) { row.scrollIntoView({ block: "nearest" }); }
  var det = row.querySelector("details.is-chosen") || row.querySelector("details");
  if (det) {
    // after this click has bubbled: the filters close an open filter on a click outside it, and the button is outside
    setTimeout(function () {
      det.open = true;
      var s = det.querySelector("summary"); if (s) { s.focus(); }
    }, 0);
    return;
  }
  var first = row.querySelector("input, select");
  if (first) { first.focus(); }
}

export function initFilterToggles() {
  document.querySelectorAll("button[data-filters-toggle]").forEach(function (b) {
    var row = document.getElementById(b.getAttribute("aria-controls") || "");
    if (!row) { return; }
    var words = b.textContent;
    b.addEventListener("click", function () {
      if (!row.hidden && b.getAttribute("data-filters-shown") === "1") {
        row.hidden = true;
        b.removeAttribute("data-filters-shown");
        b.textContent = words;
        b.setAttribute("aria-expanded", "false");
        return;
      }
      revealFilters(row);
      b.setAttribute("data-filters-shown", "1");
      b.textContent = "Hide filters";
      b.setAttribute("aria-expanded", "true");
    });
  });
}

// A strip in the grid toolbar (#282) is ALWAYS shown, so people know the actions exist: with nothing ticked its
// controls are disabled and the hint says why; ticking a row enables them. (A strip elsewhere still shows only while
// rows are ticked.) Controls the page itself disabled (data-keep-disabled) stay disabled.
function syncToolbarStrip(strip, n) {
  var hint = strip.querySelector("[data-selection-hint]");
  if (!hint) {
    hint = document.createElement("span");
    hint.className = "bulk-hint";
    hint.setAttribute("data-selection-hint", "");
    hint.textContent = SELECTION_HINT;
    var count = strip.querySelector("[data-selected-count]");
    var after = count ? count.closest("strong") || count : null;
    if (after && after.parentNode === strip) { after.insertAdjacentElement("afterend", hint); } else { strip.insertBefore(hint, strip.firstChild); }
  }
  hint.hidden = n > 0;
  strip.toggleAttribute("data-empty", n === 0);
  strip.querySelectorAll("button, select, input:not([type=hidden]), textarea").forEach(function (el) {
    if (el.hasAttribute("data-keep-disabled")) { return; }
    el.disabled = n === 0;
  });
}

// Row selection: checkboxes [data-select-row] inside [data-selectable]; [data-select-all] toggles them; the
// [data-quickstrip] shows when 1..N rows are selected and carries the count -- or, in a grid toolbar, always shows
// and is enabled when 1..N rows are selected.
export function initSelection() {
  document.querySelectorAll("[data-selectable]").forEach(function (scope) {
    var strip = document.querySelector(scope.getAttribute("data-strip") || "[data-quickstrip]");
    var all = scope.querySelector("[data-select-all]");
    function rows() { return Array.prototype.slice.call(scope.querySelectorAll("[data-select-row]")); }
    function sync() {
      var n = rows().filter(function (r) { return r.checked; }).length;
      if (strip) {
        if (strip.closest("[data-grid-toolbar]")) { strip.hidden = false; syncToolbarStrip(strip, n); } else { strip.hidden = n === 0; }
        var c = strip.querySelector("[data-selected-count]");
        if (c) { c.textContent = formatNumber(n); }
      }
      if (all) { all.checked = n > 0 && n === rows().length; all.indeterminate = n > 0 && n < rows().length; }
      // the view's "Export: selected rows" (Pages/Shared/_ViewExports.cshtml) works while rows are ticked, and says why not
      var key = scope.getAttribute("data-strip");
      document.querySelectorAll("[data-export-selected]").forEach(function (b) {
        if (!key || b.getAttribute("data-strip") !== key) { return; }
        b.disabled = n === 0;
        if (!b.hasAttribute("data-title")) { b.setAttribute("data-title", b.title); }
        b.title = n === 0 ? SELECTED_EXPORT_HINT : b.getAttribute("data-title");
      });
    }
    if (all) { all.addEventListener("change", function () { rows().forEach(function (r) { r.checked = all.checked; }); sync(); }); }
    scope.addEventListener("change", function (e) { if (e.target && e.target.hasAttribute && e.target.hasAttribute("data-select-row")) { sync(); } });
    sync();
  });
}

// "/" focuses the page's search box (type-ahead search), unless the user is typing somewhere already.
export function initSearchKey() {
  document.addEventListener("keydown", function (e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) { return; }
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) { return; }
    var box = document.querySelector("[data-search]");
    if (box) { e.preventDefault(); box.focus(); box.select(); }
  });
}
