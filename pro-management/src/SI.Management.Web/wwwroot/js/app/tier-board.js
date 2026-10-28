// The tier board's staged changes. A form of a row's drawer (or of the panel on the plain page) that stages a pin, an
// exclusion or a rule change is posted in place: the button stays where it is, the answer is a toast, and the row, the
// panel and the tile say "staged" until the change is committed. Nothing is written by staging. Without this file the
// same form posts and the page comes back with the same message.
import { toast } from "./ui.js";

function badge(doc, text) {
  var b = doc.createElement("span");
  b.className = "badge warn";
  b.setAttribute("data-staged", "");
  b.textContent = text;
  return b;
}

// The row of the CI, its panel(s) and the tile the change is about say what is staged.
function markStaged(doc, panel, res) {
  var key = panel ? panel.getAttribute("data-tier-panel") : null;
  if (key) {
    doc.querySelectorAll("tr[data-key]").forEach(function (row) {
      if (row.getAttribute("data-key") !== key) { return; }
      var cell = row.querySelector("td[data-row-panel]");
      if (!cell) { return; }
      var old = cell.querySelector("[data-staged]");
      if (old) { old.remove(); }
      cell.appendChild(badge(doc, res.mark));
    });
    doc.querySelectorAll("[data-tier-panel]").forEach(function (p) {
      if (p.getAttribute("data-tier-panel") !== key) { return; }
      var head = p.querySelector("h2");
      if (!head) { return; }
      var old = head.querySelector("[data-staged]");
      if (old) { old.remove(); }
      head.appendChild(badge(doc, res.mark));
    });
  }
  // a pin is staged for the tier it moves the asset to; an exclusion for the tier the asset is in
  var staged = res.staged || {};
  var tier = staged.kind === "tier-pin" ? staged.tier : (panel ? panel.getAttribute("data-tier") : null);
  if (tier === null || tier === undefined) { return; }
  doc.querySelectorAll("[data-tier-tile]").forEach(function (tile) {
    if (tile.getAttribute("data-tier-tile") !== String(tier) || tile.querySelector("[data-tier-staged]")) { return; }
    var p = doc.createElement("p");
    p.className = "hint";
    p.setAttribute("data-tier-staged", "");
    p.appendChild(doc.createTextNode("Staged, not committed -- "));
    var a = doc.createElement("a");
    a.href = "/Changes";
    a.textContent = "review & commit";
    p.appendChild(a);
    tile.appendChild(p);
  });
}

// The buttons of the rule a claim was made by say what is staged for that rule (wherever its claim is shown).
function markRule(doc, key, text) {
  doc.querySelectorAll("form[data-rule-key]").forEach(function (f) {
    if (f.getAttribute("data-rule-key") !== key) { return; }
    var old = f.querySelector("[data-claim-staged]");
    if (old) { old.remove(); }
    var b = doc.createElement("span");
    b.className = "badge warn";
    b.setAttribute("data-claim-staged", "");
    b.textContent = text;
    f.appendChild(b);
  });
}

export function initTierBoard(doc) {
  doc.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-tier-stage")) { return; }
    e.preventDefault();
    var button = e.submitter || form.querySelector("button[type=submit]");
    // the fields of the form, and -- a claim's buttons each name their own change -- the button that was pressed
    var body = new URLSearchParams(new FormData(form));
    if (button && button.getAttribute("name")) { body.set(button.getAttribute("name"), button.value); }
    if (button) { button.disabled = true; }
    var status = 0;
    // the form's own address (an input of the form is named Action, so the attribute is read, not the property)
    fetch(form.getAttribute("action"), {
      method: "POST", body: body, credentials: "same-origin", headers: { Accept: "application/json" }
    })
      .then(function (r) { status = r.status; return r.json(); })
      .then(function (res) {
        toast(res.message || "Not staged.", res.ok ? "ok" : "error");
        if (res.ok && res.mark) { markStaged(doc, form.closest("[data-tier-panel]"), res); }
        if (res.ok && res.ruleMark && form.hasAttribute("data-rule-key")) { markRule(doc, form.getAttribute("data-rule-key"), res.ruleMark); }
        if (res.ok) { form.querySelectorAll("input[name=Reason]").forEach(function (i) { i.value = ""; }); }
      })
      .catch(function () {
        toast(status === 403 ? "Not allowed: your role cannot stage this change. Nothing was written." : "Not staged: the answer could not be read. Nothing was written.", "error");
      })
      .finally(function () { if (button) { button.disabled = false; } });
  });
}
