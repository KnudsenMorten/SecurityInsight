// THE shared action bar on every grid of findings (#272), in the grid toolbar above the table (#282). The bar sits inside the page's selection form; each action's
// form is a <dialog> kept in a <template> (no nested forms). A bar button opens its dialog, the dialog posts the action's
// fields PLUS the selection form's fields (the ticked keys and the filter) to /Actions/Apply, and the answer per finding
// is shown in the dialog. Without this module the same buttons post to /Actions/Prepare, a page with the same form.

import { toast } from "./ui.js";
import { formatNumber } from "./numbers.js";

function selected(form) {
  return Array.prototype.slice.call(form.elements).filter(function (el) {
    return el.hasAttribute && el.hasAttribute("data-select-row") && el.checked;
  });
}

// every field of the selection form except its own token and the bar's buttons / pickers
function selectionFields(form, data) {
  var skip = { "__RequestVerificationToken": 1, "action": 1, "allAction": 1, "handler": 1, "all": 1 };
  Array.prototype.forEach.call(form.elements, function (el) {
    if (!el.name || skip[el.name] || el.disabled) { return; }
    if ((el.type === "checkbox" || el.type === "radio") && !el.checked) { return; }
    if (el.type === "submit" || el.type === "button") { return; }
    data.append(el.name, el.value);
  });
}

// The most refused findings the expandable list names (the audit row keeps every id).
var REFUSALS_SHOWN = 200;

function counts(res) {
  return formatNumber(res.done || 0) + " done, " + formatNumber(res.refused || 0) + " refused";
}

// The answer in the dialog: one line with the counts (the viewer's number format) and, when some were refused, an
// expandable list naming each refused finding (asset + finding) with its reason.
function renderResults(box, res) {
  box.hidden = false;
  box.textContent = "";
  var h = document.createElement("p");
  h.className = "notice " + (res.ok ? (res.refused > 0 ? "warn" : "") : "error");
  h.setAttribute("data-action-summary", "");
  h.textContent = counts(res) + ". " + (res.message || "");
  box.appendChild(h);
  var refused = (res.results || []).filter(function (r) { return !r.done; });
  if (refused.length > 0) {
    var det = document.createElement("details");
    det.setAttribute("data-action-refusals", "");
    var sum = document.createElement("summary");
    sum.textContent = "Refused: " + formatNumber(refused.length) + " finding(s) -- show which and why";
    det.appendChild(sum);
    var ul = document.createElement("ul");
    refused.slice(0, REFUSALS_SHOWN).forEach(function (r) {
      var li = document.createElement("li");
      li.setAttribute("data-refused-finding", r.findingId);
      li.textContent = (r.asset || r.findingId) + " -- " + (r.title || r.findingId) + ": " + (r.why || "refused");
      ul.appendChild(li);
    });
    det.appendChild(ul);
    if (refused.length > REFUSALS_SHOWN) {
      var more = document.createElement("p");
      more.textContent = "... and " + formatNumber(refused.length - REFUSALS_SHOWN) + " more (all are in the audit log).";
      det.appendChild(more);
    }
    box.appendChild(det);
  }
}

// The grid keeps its viewport and its selection: nothing is unticked and the page does not reload. A refused finding
// stays selected and its row is marked, so it can be looked at or acted on again; marks of an earlier answer go.
function markRows(form, res) {
  var refused = {};
  (res.results || []).forEach(function (r) { if (!r.done) { refused[r.findingId] = r.why || "refused"; } });
  // form.elements: a grid's row boxes may sit outside the form (form="..."), as selected() reads them
  Array.prototype.forEach.call(form.elements, function (el) {
    if (!el.hasAttribute || !el.hasAttribute("data-select-row")) { return; }
    var row = el.closest("tr");
    if (!row) { return; }
    if (Object.prototype.hasOwnProperty.call(refused, el.value)) {
      row.setAttribute("data-action-refused", "");
      row.title = "Refused: " + refused[el.value];
    } else if (row.hasAttribute("data-action-refused")) {
      row.removeAttribute("data-action-refused");
      row.removeAttribute("title");
    }
  });
}

export function initFindingActions(bar) {
  var form = bar.closest("form");
  var tpl = bar.querySelector("template[data-action-dialogs]");
  if (!form || !tpl) { return; }
  // the dialogs live at the end of the body: a form may not sit inside the selection form
  var host = document.createElement("div");
  host.appendChild(tpl.content.cloneNode(true));
  document.body.appendChild(host);

  var clear = bar.querySelector("[data-selection-clear]");
  if (clear) {
    clear.addEventListener("click", function () {
      selected(form).forEach(function (el) { el.checked = false; el.dispatchEvent(new Event("change", { bubbles: true })); });
      var all = document.querySelector("[data-select-all]");
      if (all) { all.checked = false; all.indeterminate = false; }
      // #282: the strip stays in the grid toolbar; the row changes above let the selection code disable its actions
      // and show the hint again. A strip outside a toolbar hides, as before.
      var strip = bar.querySelector("[data-action-strip]");
      if (strip && !strip.closest("[data-grid-toolbar]")) { strip.hidden = true; }
    });
  }

  // #286 / #330: what the selection IS, from the server (the same resolver Apply uses; it writes nothing): the dialog's
  // title ("Exempt CVE-X on 3 assets"), "2 CVE row(s) = 5 finding(s)", and the action's preview (who approves, ...).
  // A count that fails or does not answer in time SAYS so -- it never stays at "counting..." (the ring-1 report).
  var COUNT_TIMEOUT_MS = 30000;
  var counting = 0;

  function countFindings(key, dlg, scope, title) {
    var ticket = ++counting;
    var data = new FormData();
    data.append("action", key);
    selectionFields(form, data);
    var ctl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) { ctl.abort(); } }, COUNT_TIMEOUT_MS);
    function fail(why) {
      if (ticket !== counting) { return; }
      scope.className = "notice error";
      scope.setAttribute("data-action-expansion", "0");
      scope.textContent = "The findings could not be counted: " + why + ". The action still checks each finding when you apply it.";
    }
    fetch("/Actions/Prepare?handler=Count", { method: "POST", body: data, headers: { "Accept": "application/json" }, credentials: "same-origin", signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        var type = r.headers.get("content-type") || "";
        if (!r.ok || type.indexOf("json") < 0) { throw new Error("the server answered " + r.status + (r.ok ? " without a count" : "")); }
        return r.json();
      })
      .then(function (res) {
        if (ticket !== counting) { return; }
        if (!res.ok) {
          scope.className = "notice error";
          scope.setAttribute("data-action-expansion", "0");
          scope.textContent = res.message || "The findings could not be counted.";
          return;
        }
        if (res.title) { title.textContent = res.title; }
        var parts = [];
        if (res.rows != null) { parts.push(res.message); } else if (res.findings != null) { parts.push(formatNumber(res.findings) + " selected finding(s)."); }
        if (res.refused > 0) { parts.push(formatNumber(res.refused) + " of the selected row(s) stand for no finding you may act on."); }
        scope.className = "notice";
        scope.textContent = parts.join(" ");
        scope.setAttribute("data-action-expansion", "1");
        applyPreview(dlg, res.preview || null);
      })
      .catch(function (err) { fail(err && err.name === "AbortError" ? "no answer within " + (COUNT_TIMEOUT_MS / 1000) + " seconds" : (err && err.message) || "no answer"); })
      .finally(function () { clearTimeout(timer); });
  }

  // #330: the selection-dependent parts of an action's form (the exemption's approvers, its one wider scope, "Approve now")
  function applyPreview(dlg, p) {
    var who = dlg.querySelector("[data-exempt-approvers]");
    if (who) { who.textContent = p && p.approvers ? p.approvers : ""; }
    var change = dlg.querySelector("[data-exempt-change]");
    var sel = dlg.querySelector("[data-exempt-approver]");
    if (change && sel) {
      while (sel.options.length > 1) { sel.remove(1); }
      (p && p.overrides ? p.overrides : []).forEach(function (a) { sel.add(new Option(a, a)); });
      sel.value = "";
      change.hidden = sel.options.length <= 1;
      change.open = false;
    }
    var more = dlg.querySelector("[data-exempt-more]");
    var alt = dlg.querySelector("[data-exempt-alt]");
    if (more && alt) {
      var a = p && p.alternatives && p.alternatives.length > 0 ? p.alternatives[0] : null;
      alt.checked = false;
      if (a) { alt.value = a.scope; dlg.querySelector("[data-exempt-alt-label]").textContent = a.label; }
      more.hidden = !a;
      more.open = false;
    }
    // the department dialog's "Assign by" opens on what the selection is
    var scopes = dlg.querySelectorAll("[data-assign-scope]");
    Array.prototype.forEach.call(scopes, function (r) { r.checked = r.value === ((p && p.defaultScope) || "asset"); });
    // #693 Link as one: the finding that stays (one choice per key of the selection) and why the selection cannot be linked
    var canon = dlg.querySelector("[data-link-canonical]");
    if (canon) {
      while (canon.options.length > 1) { canon.remove(1); }
      (p && p.linkFindings ? p.linkFindings : []).forEach(function (o) { canon.add(new Option(o.label, o.id)); });
      canon.value = (p && p.linkDefault) || "";
    }
    var lp = dlg.querySelector("[data-link-problem]");
    if (lp) { lp.textContent = (p && p.linkProblem) || ""; lp.hidden = !(p && p.linkProblem); }
    var now = dlg.querySelector("[data-exempt-approvenow]");
    if (now) {
      var box = now.querySelector("input");
      if (box) { box.checked = false; }
      now.hidden = !(p && p.canApproveAll);
    }
  }

  function open(key, allMatching) {
    var dlg = host.querySelector('dialog[data-action-dialog="' + key + '"]');
    if (!dlg || typeof dlg.showModal !== "function") { return false; }
    var dform = dlg.querySelector("form");
    var results = dlg.querySelector("[data-action-results]");
    results.hidden = true; results.textContent = "";
    var n = allMatching ? Number(bar.getAttribute("data-total") || "0") : selected(form).length;
    var scope = dlg.querySelector("[data-action-scope]");
    var title = dlg.querySelector("[data-action-title]");
    var noun = bar.getAttribute("data-row-noun");
    scope.className = "notice";
    title.textContent = title.getAttribute("data-label") || title.textContent;
    applyPreview(dlg, null);
    if (allMatching) {
      // "all matching" is resolved (and guarded) by Apply itself
      scope.textContent = noun
        ? "Every " + noun + " row matching the filter: " + formatNumber(n) + " -- each stands for its findings."
        : "Every finding matching the filter: " + formatNumber(n) + ".";
    } else {
      scope.textContent = formatNumber(n) + " " + (noun ? noun + " row(s)" : "finding(s)") + " selected -- reading what they stand for...";
      countFindings(key, dlg, scope, title);
    }
    dform.dataset.all = allMatching ? "1" : "0";
    dlg.showModal();
    var first = dform.querySelector("input:not([type=hidden]), select, textarea");
    if (first) { first.focus(); }
    return true;
  }

  // the bar's buttons: a dialog instead of the no-script page
  bar.addEventListener("click", function (e) {
    var b = e.target && e.target.closest ? e.target.closest("button[data-action], button[data-actions-all-apply]") : null;
    if (!b) { return; }
    var all = b.hasAttribute("data-actions-all-apply");
    var key = all ? (bar.querySelector("[data-actions-all-action]") || {}).value : b.getAttribute("data-action");
    if (key && open(key, all)) { e.preventDefault(); }
  });

  host.querySelectorAll("dialog[data-action-dialog]").forEach(function (dlg) {
    var dform = dlg.querySelector("form");
    dlg.querySelector("[data-action-cancel]").addEventListener("click", function () { dlg.close(); });
    dform.addEventListener("submit", function (e) {
      var data = new FormData(dform);
      selectionFields(form, data);
      if (dform.dataset.all === "1") { data.append("all", "1"); }
      // an export answers with a file: a plain post of the same fields lets the browser download it
      if (dlg.getAttribute("data-downloads") === "1") {
        e.preventDefault();
        var f = document.createElement("form");
        f.method = "post"; f.action = dform.getAttribute("action"); f.hidden = true;
        data.forEach(function (v, k) { var i = document.createElement("input"); i.type = "hidden"; i.name = k; i.value = v; f.appendChild(i); });
        document.body.appendChild(f); f.submit(); f.remove();
        dlg.close();
        return;
      }
      e.preventDefault();
      var submit = dform.querySelector("[data-action-submit]");
      if (submit) { submit.disabled = true; }
      fetch(dform.getAttribute("action"), { method: "POST", body: data, headers: { "Accept": "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (res) {
          renderResults(dlg.querySelector("[data-action-results]"), res);
          markRows(form, res);
          toast(counts(res) + ". " + (res.message || ""), res.ok ? (res.refused > 0 ? "warn" : "ok") : "error");
        })
        .catch(function (err) { toast("Nothing was done: " + err.message, "error"); })
        .finally(function () { if (submit) { submit.disabled = false; } });
    });
  });
}
