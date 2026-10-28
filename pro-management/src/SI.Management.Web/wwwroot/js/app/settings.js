// The Settings page (PIM Manager's settings page is the model): a category bar showing one category at a time
// (remembered per browser, ?cat= and #s-Name / #card-x deep links win), a filter over labels and help text, address
// chips for lists, and a Save per card that answers in place -- green when saved, red with the reason when not.
// Without this script every category is shown, a list is one item per line and Save reloads the page.
import { toast, confirmDialog } from "./ui.js";

var KEY = "siSettingsCat";
var MAIL = /^[^@\s<>,;"]+@[^@\s<>,;"]+\.[^@\s<>,;"]+$/;

function store(k, v) { try { if (v === undefined) { return window.localStorage.getItem(k); } window.localStorage.setItem(k, v); } catch (e) { return null; } return null; }

export function initSettings(root) {
  var bar = document.querySelector("[data-settings-catbar]");
  var cats = Array.prototype.slice.call(root.querySelectorAll(".set-cat"));
  var filterBox = document.querySelector("[data-settings-filter]");

  // ---- categories: one at a time ----
  function show(id, remember) {
    var all = id === "*" || !cats.some(function (c) { return c.getAttribute("data-cat") === id; });
    cats.forEach(function (c) { c.hidden = !all && c.getAttribute("data-cat") !== id; });
    if (bar) {
      bar.querySelectorAll("[data-cat]").forEach(function (b) { b.setAttribute("aria-current", b.getAttribute("data-cat") === (all ? "*" : id) ? "true" : "false"); });
    }
    if (remember) { store(KEY, all ? "*" : id); }
  }
  function categoryOf(el) { var c = el && el.closest ? el.closest(".set-cat") : null; return c ? c.getAttribute("data-cat") : null; }
  function reveal(el) {
    if (!el) { return; }
    var cat = categoryOf(el);
    if (cat) { show(cat, true); }
    var adv = el.closest("details.set-advanced");
    if (adv) { adv.open = true; }
    el.scrollIntoView({ block: "start" });
  }
  if (bar) {
    bar.addEventListener("click", function (e) {
      var b = e.target.closest("[data-cat]");
      if (!b) { return; }
      e.preventDefault();
      show(b.getAttribute("data-cat"), true);
      try { var u = new URL(window.location.href); u.searchParams.delete("cat"); u.hash = ""; window.history.replaceState(null, "", u); } catch (x) { /* old browser: the address stays */ }
    });
  }
  // a link to a field in another category (a "Needs X on" hint, the licence notices) opens that category
  root.addEventListener("click", function (e) {
    var a = e.target.closest('a[href^="#s-"], a[href^="#card-"]');
    if (!a) { return; }
    var el = document.getElementById(a.getAttribute("href").slice(1));
    if (el) { e.preventDefault(); reveal(el); }
  });
  var params = new URLSearchParams(window.location.search);
  var target = window.location.hash ? document.getElementById(window.location.hash.slice(1)) : null;
  var card = params.get("card") ? document.getElementById("card-" + params.get("card")) : null;
  if (root.getAttribute("data-filtered") === "true") { show("*", false); }
  else if (target && target.closest(".set-cat") && target.id.indexOf("cat-") !== 0) { reveal(target); }
  else if (card) { reveal(card); }
  else if (params.get("cat")) { show(params.get("cat"), true); }
  else { show(store(KEY) || root.getAttribute("data-open-cat") || "*", false); }

  // ---- the filter: labels, hints, internal names and help text, as you type ----
  if (filterBox) {
    filterBox.addEventListener("input", function () {
      var q = filterBox.value.trim().toLowerCase();
      root.querySelectorAll(".set-field").forEach(function (f) { f.hidden = q.length > 0 && (f.getAttribute("data-search") || "").indexOf(q) < 0; });
      root.querySelectorAll(".set-card[data-card]").forEach(function (c) {
        c.hidden = q.length > 0 && !c.querySelector(".set-field:not([hidden])");
      });
      if (q.length > 0) {
        show("*", false);
        root.querySelectorAll("details.set-advanced").forEach(function (d) { if (d.querySelector(".set-field:not([hidden])")) { d.open = true; } });
        cats.forEach(function (c) { if (!c.querySelector(".set-field:not([hidden])")) { c.hidden = true; } });
      } else {
        show(store(KEY) || root.getAttribute("data-open-cat") || "*", false);
      }
    });
  }

  // (switches say On / Off: main.js, for every page with a setting field)

  // ---- chips ----
  root.querySelectorAll("[data-chips]").forEach(initChips);

  // ---- Save per card ----
  root.querySelectorAll("form.set-card").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      save(form, e.submitter || null);
    });
  });
}

/// A list field as chips. The textarea stays the form field (one item per line); the chips only edit it.
export function initChips(host) {
  var area = host.querySelector("textarea");
  if (!area) { return; }
  var mail = host.getAttribute("data-mail") === "true";
  var disabled = area.disabled;
  var box = document.createElement("div");
  box.className = "set-chipbox";
  var input = document.createElement("input");
  input.type = mail ? "email" : "text";
  input.setAttribute("aria-label", (mail ? "Add an e-mail address to " : "Add an item to ") + (area.labels && area.labels[0] ? area.labels[0].textContent : "the list"));
  input.placeholder = mail ? "Type an address, press Enter" : "Type, press Enter";
  input.autocomplete = "off";
  input.spellcheck = false;
  var items = area.value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);

  function sync() { area.value = items.join("\n"); area.dispatchEvent(new Event("change", { bubbles: true })); }
  function render() {
    box.querySelectorAll(".set-chip").forEach(function (c) { c.remove(); });
    items.forEach(function (it, i) {
      var chip = document.createElement("span");
      chip.className = "set-chip" + (mail && !MAIL.test(it) ? " bad" : "");
      chip.setAttribute("data-chip", it);
      chip.appendChild(document.createTextNode(it));
      if (mail && !MAIL.test(it)) { chip.title = "Not an e-mail address"; }
      if (!disabled) {
        var x = document.createElement("button");
        x.type = "button";
        x.textContent = "×";
        x.setAttribute("aria-label", "Remove " + it);
        x.addEventListener("click", function () { items.splice(i, 1); sync(); render(); input.focus(); });
        chip.appendChild(x);
      }
      box.insertBefore(chip, disabled ? null : input);
    });
  }
  function add(text) {
    var added = false;
    text.split(mail ? /[\n\r,;\s]+/ : /[\n\r]+|,(?=\s)|;/).map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (s) {
      if (items.indexOf(s) < 0) { items.push(s); added = true; }
    });
    if (added) { sync(); render(); }
  }
  if (!disabled) {
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === "," || e.key === ";" || (e.key === "Tab" && input.value.trim())) {
        if (input.value.trim()) { e.preventDefault(); add(input.value); input.value = ""; }
        else if (e.key === "Enter") { e.preventDefault(); }
      } else if (e.key === "Backspace" && !input.value && items.length) {
        items.pop(); sync(); render();
      }
    });
    input.addEventListener("paste", function (e) {
      var t = (e.clipboardData || window.clipboardData).getData("text");
      if (t && /[\n,;]/.test(t)) { e.preventDefault(); add(t); }
    });
    // what is still typed when the card is saved counts too
    input.addEventListener("blur", function () { if (input.value.trim()) { add(input.value); input.value = ""; } });
    box.appendChild(input);
    box.addEventListener("click", function (e) { if (e.target === box) { input.focus(); } });
  }
  area.hidden = true;
  host.appendChild(box);
  host.setChips = function (list) { items = list.slice(); area.value = items.join("\n"); render(); };
  host.pending = function () { return input.value.trim(); };
  render();
}

function fieldOf(form, name) { return form.querySelector('.set-field[data-setting="' + (window.CSS && CSS.escape ? CSS.escape(name) : name) + '"]'); }

function save(form, submitter) {
  var msg = form.querySelector("[data-card-msg]");
  form.querySelectorAll("[data-field-error]").forEach(function (p) { p.hidden = true; p.textContent = ""; });
  // a mail list with an entry that is not an address is not sent at all
  var bad = null;
  form.querySelectorAll("[data-chips]").forEach(function (h) {
    if (h.pending && h.pending()) { var i = h.querySelector("input"); if (i) { i.blur(); } }
    if (h.getAttribute("data-mail") === "true" && h.querySelector(".set-chip.bad")) { bad = bad || h; }
  });
  if (bad) {
    var f = bad.closest(".set-field");
    var e = f && f.querySelector("[data-field-error]");
    var which = bad.querySelector(".set-chip.bad").getAttribute("data-chip");
    if (e) { e.textContent = "'" + which + "' is not an e-mail address -- remove it or correct it."; e.hidden = false; }
    say(msg, "Not saved: an address is not an e-mail address.", false);
    return;
  }
  // SETTING-INFO-1: a destructive or security-reducing value is confirmed first, with its consequence -- before anything
  // is staged. A reset is never risky by itself (it returns to the shipped default).
  var risky = (submitter && submitter.name && submitter.name.indexOf("reset:") === 0) ? [] : riskyChanges(form);
  if (risky.length && !form.dataset.riskConfirmed) {
    confirmDialog("Confirm this change", risky.map(function (r) { return r.title + ": " + r.text; }).join("\n\n"), "Save anyway").then(function (ok) {
      if (!ok) { say(msg, "Not saved.", null); return; }
      form.dataset.riskConfirmed = "1";
      try { save(form, submitter); } finally { delete form.dataset.riskConfirmed; }
    });
    return;
  }
  var body = new FormData(form);
  if (submitter && submitter.name) { body.append(submitter.name, submitter.value); }
  var buttons = form.querySelectorAll("button[type=submit]");
  buttons.forEach(function (b) { b.disabled = true; });
  say(msg, "Saving...", null);
  fetch(form.getAttribute("action") || window.location.pathname + "?handler=SaveCard", {
    method: "POST", body: new URLSearchParams(body), credentials: "same-origin", headers: { Accept: "application/json" },
  })
    .then(function (r) { if (!r.ok) { throw new Error(r.status === 403 ? "you may not change these settings" : "HTTP " + r.status); } return r.json(); })
    .then(function (res) {
      say(msg, res.message, res.ok);
      Object.keys(res.errors || {}).forEach(function (n) {
        var fld = fieldOf(form, n);
        var p = fld && fld.querySelector("[data-field-error]");
        if (p) { p.textContent = res.errors[n]; p.hidden = false; }
      });
      Object.keys(res.fields || {}).forEach(function (n) {
        applySaved(form, n, res.fields[n]);
        var sf = fieldOf(form, n); if (sf && sf.hasAttribute("data-confirm-when")) { markShown(sf); var v = nextValue(sf); if (v !== null) { sf.setAttribute("data-current", v); } }
      });
    })
    .catch(function (err) { say(msg, "Not saved: " + err.message, false); toast("Not saved: " + err.message, "error"); })
    .then(function () { buttons.forEach(function (b) { b.disabled = false; }); });
}

/// The value a field is about to save, as text: "true"/"false" for a switch, else the control's value.
function nextValue(fld) {
  var cb = fld.querySelector(".set-switch input[type=checkbox]");
  if (cb) { return cb.checked ? "true" : "false"; }
  var c = fld.querySelector("select[name^='v:'], input[type=number][name^='v:'], input[type=text][name^='v:']");
  return c ? String(c.value || "").trim() : null;
}

/// The value the field showed when the page was drawn (or last saved): the control's own default state -- so an
/// untouched field never asks, whatever text the row holds.
function shownValue(fld) {
  var cb = fld.querySelector(".set-switch input[type=checkbox]");
  if (cb) { return cb.defaultChecked ? "true" : "false"; }
  var sel = fld.querySelector("select[name^='v:']");
  if (sel) { var o = Array.prototype.find.call(sel.options, function (x) { return x.defaultSelected; }); return o ? o.value : ""; }
  var c = fld.querySelector("input[type=number][name^='v:'], input[type=text][name^='v:']");
  return c ? String(c.defaultValue || "").trim() : fld.getAttribute("data-current");
}

/// After a save the shown value is the saved one.
function markShown(fld) {
  var cb = fld.querySelector(".set-switch input[type=checkbox]");
  if (cb) { cb.defaultChecked = cb.checked; return; }
  var sel = fld.querySelector("select[name^='v:']");
  if (sel) { Array.prototype.forEach.call(sel.options, function (x) { x.defaultSelected = x.selected; }); return; }
  var c = fld.querySelector("input[type=number][name^='v:'], input[type=text][name^='v:']");
  if (c) { c.defaultValue = c.value; }
}

/// SETTING-INFO-1: the fields of this card whose new value moves INTO their risky value (on / off / lower) -- the same
/// rule as SettingInfo.NeedsConfirmation in the web app.
export function needsConfirmation(when, current, next) {
  current = String(current || "").trim().toLowerCase(); next = String(next || "").trim().toLowerCase();
  if (current === next) { return false; }
  if (when === "on") { return next === "true"; }
  if (when === "off") { return next === "false"; }
  if (when === "lower") {
    var n = parseFloat(next); if (isNaN(n)) { return false; }
    var c = parseFloat(current); if (isNaN(c)) { return true; }
    return n < c;
  }
  return false;
}

/// SETTING-INFO-1 outside the Settings cards (Get Started's setting steps post as plain forms): the same confirmation
/// before a form with a risky change is sent.
export function initRiskConfirm(root) {
  root.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement) || form.classList.contains("set-card") || form.dataset.riskConfirmed === "1") { return; }
    var risky = riskyChanges(form);
    if (!risky.length) { return; }
    e.preventDefault();
    var submitter = e.submitter;
    confirmDialog("Confirm this change", risky.map(function (r) { return r.title + ": " + r.text; }).join("\n\n"), "Save anyway").then(function (ok) {
      if (!ok) { return; }
      form.dataset.riskConfirmed = "1";
      if (typeof form.requestSubmit === "function") { form.requestSubmit(submitter && submitter.form === form ? submitter : undefined); } else { form.submit(); }
    });
  }, true);
}

function riskyChanges(form) {
  var out = [];
  form.querySelectorAll('.set-field[data-confirm-when]:not([data-confirm-when=""])').forEach(function (fld) {
    var next = nextValue(fld);
    if (next === null) { return; }
    if (needsConfirmation(fld.getAttribute("data-confirm-when"), shownValue(fld), next)) {
      out.push({ title: fld.getAttribute("data-title") || fld.getAttribute("data-setting"), text: fld.getAttribute("data-confirm") || "" });
    }
  });
  return out;
}

function say(el, text, ok) {
  if (!el) { return; }
  el.textContent = text || "";
  el.classList.toggle("ok", ok === true);
  el.classList.toggle("error", ok === false);
}

/// After a save: the field shows what is stored now, carries the new version, and says whether it differs from the default.
function applySaved(form, name, r) {
  var f = fieldOf(form, name);
  if (!f) { return; }
  var ver = f.querySelector('input[name="ver:' + name + '"]');
  if (ver) { ver.value = r.version || ""; }
  var cb = f.querySelector('input[type="checkbox"][name="v:' + name + '"]');
  var chips = f.querySelector("[data-chips]");
  if (cb) {
    cb.checked = r.text === "true";
    var t = f.querySelector(".set-switch-text"); if (t) { t.textContent = cb.checked ? "On" : "Off"; }
  } else if (chips && chips.setChips) {
    chips.setChips((r.text || "").split(/\r?\n/).filter(Boolean));
  } else {
    var el = f.querySelector('[name="v:' + name + '"]:not([type="hidden"])');
    if (el) { el.value = r.text || ""; }
  }
  var label = f.querySelector(".set-label");
  var dot = label && label.querySelector(".set-dot");
  if (r.set && !dot && label) { dot = document.createElement("span"); dot.className = "set-dot"; dot.title = "Changed from the default"; label.appendChild(dot); }
  if (!r.set && dot) { dot.remove(); }
  f.setAttribute("data-changed", r.set ? "true" : "false");
  var reset = f.querySelector("[data-reset]");
  var foot = f.querySelector(".set-foot");
  if (r.set && !reset && foot) {
    reset = document.createElement("button");
    reset.type = "submit"; reset.className = "link small"; reset.name = "reset:" + name; reset.value = "1";
    reset.setAttribute("data-reset", name); reset.formNoValidate = true; reset.textContent = "Reset to default";
    foot.insertBefore(reset, foot.firstChild);
  }
  if (!r.set && reset) { reset.remove(); }
}
