// "A new version is available" (#345, framework BRAND-2.11; operator 2026-10-05: "if a new version is released in pim i get a
// great message to reload the page. i need the same at invardia and si"). Same wording and placement as Invardia and PIM
// Manager: one bar at the top of the page, raised once, never stacked, and the page is NEVER reloaded by itself.
// How it knows: every signed-in page carries the build it was served from (<html data-app-build data-app-version>, the
// commit from BUILD.json, else the version). This script asks /about (signed-in, no data) every 5 minutes and at once when
// the tab is shown or focused; a hidden tab does not ask; errors (a deploy restarting the app, offline) ask less often.
//   * The server runs another build and still answers this page -> the calm bar: "A new version of SecurityInsight (vX) is
//     available. Reload when you are ready." with Reload / Later. A new revision keeps the page signed in and its forms
//     saving (the sign-in keys are shared, Auth/SqlKeyRing.cs), so there is no hurry. Typed-but-unsaved input on the page:
//     "finish or save it first".
//   * The server no longer accepts this page's sign-in (401, or a redirect to sign in) -> PIM's orange "session expired"
//     bar: "Reload to sign in again -- committed data is safe." That is the only case where the page really cannot save.
// The wall board shows the same bars; its own refresh tick (it reloads itself every few minutes by design) applies them.
(function () {
  "use strict";

  var root = document.documentElement;
  var mine = root.getAttribute("data-app-build") || "";
  if (!mine || !window.fetch) { return; }   // not signed in, or the build is unknown: nothing to compare

  var EVERY = 5 * 60000, MAX = 30 * 60000, MIN_GAP = 5000;
  var delay = EVERY, timer = null, busy = false, lastCheck = 0;
  var state = { kind: "", id: "", display: "" };   // kind: "" | "update" | "session"
  var later = "";         // the build the person said "Later" to (a later build shows the bar again)
  var bar = null;

  function idOf(b) { return b ? String(b.commit || b.display || b.version || "") : ""; }

  // typed-but-unsaved input: a POST form someone changed and has not submitted yet (filters and search are GET forms and
  // do not count); the report designer and risk index mark their own forms data-dirty
  function markUnsaved(e) {
    var f = e.target && e.target.form;
    if (!f || f.hasAttribute("data-no-unsaved")) { return; }
    if (String(f.getAttribute("method") || "get").toLowerCase() !== "post") { return; }
    if (!f.hasAttribute("data-unsaved")) { f.setAttribute("data-unsaved", "1"); render(); }
  }
  document.addEventListener("input", markUnsaved, true);
  document.addEventListener("change", markUnsaved, true);
  document.addEventListener("submit", function (e) { if (e.target && e.target.removeAttribute) { e.target.removeAttribute("data-unsaved"); render(); } }, true);
  function hasUnsaved() { return !!document.querySelector("form[data-unsaved], form[data-dirty='1']"); }

  function build() {
    bar = document.createElement("div");
    bar.className = "update-banner";
    bar.setAttribute("role", "alert");
    bar.setAttribute("data-update-banner", "");
    bar.innerHTML =
      '<span class="update-text"><b data-update-lead></b> <span data-update-sub></span>' +
      ' <span class="update-unsaved" data-update-unsaved hidden></span></span>' +
      '<span class="update-actions"><button type="button" class="update-reload" data-update-reload>Reload</button>' +
      '<button type="button" class="update-later" data-update-later>Later</button></span>';
    bar.querySelector("[data-update-reload]").addEventListener("click", function () { window.location.reload(); });
    bar.querySelector("[data-update-later]").addEventListener("click", function () { later = state.id; render(); });
    document.body.insertBefore(bar, document.body.firstChild);
  }

  function render() {
    var show = state.kind === "session" || (state.kind === "update" && state.id !== later);
    if (!show) { if (bar) { bar.hidden = true; } return; }
    try {
      if (!bar) { build(); }
      var session = state.kind === "session";
      bar.setAttribute("data-kind", state.kind);
      bar.querySelector("[data-update-lead]").textContent = session
        ? "Your sign-in session has expired."
        : "A new version of SecurityInsight" + (state.display ? " (v" + state.display + ")" : "") + " is available.";
      bar.querySelector("[data-update-sub]").textContent = session
        ? "This page can no longer save. Reload to sign in again — committed data is safe."
        : "Reload when you are ready.";
      var unsaved = bar.querySelector("[data-update-unsaved]");
      unsaved.textContent = session
        ? "What you typed on this page is not saved — copy it before you reload."
        : "You have typed something that is not saved yet — finish or save it first.";
      unsaved.hidden = !hasUnsaved();
      bar.querySelector("[data-update-reload]").textContent = session ? "Reload now" : "Reload";
      bar.querySelector("[data-update-later]").hidden = session;
      bar.hidden = false;
    } catch (_) { /* a bar must never be the thing that breaks the page */ }
  }

  function schedule() { if (timer) { clearTimeout(timer); } timer = setTimeout(check, delay); }

  function check() {
    if (busy) { return; }
    if (document.hidden) { schedule(); return; }   // a background tab asks again when it is shown
    busy = true; lastCheck = Date.now();
    fetch("/about", { credentials: "same-origin", cache: "no-store", redirect: "manual", headers: { "Accept": "application/json" } })
      .then(function (r) {
        // a redirect (to sign in) or a 401: this page's sign-in is no longer accepted -- it cannot save
        if (r.type === "opaqueredirect" || r.status === 401) { state = { kind: "session", id: "", display: "" }; render(); return null; }
        if (!r.ok) { throw new Error("HTTP " + r.status); }
        return r.json();
      })
      .then(function (b) {
        delay = EVERY;
        if (!b) { return; }
        var id = idOf(b);
        if (!id) { return; }
        state = id !== mine ? { kind: "update", id: id, display: String(b.display || b.version || "") }
                            : { kind: "", id: "", display: "" };   // same build again (signed in again, or a rollback)
        render();
      })
      .catch(function () { delay = Math.min(delay * 2, MAX); })   // restarting or offline: ask less often, say nothing
      .then(function () { busy = false; schedule(); });
  }

  function soon() { if (Date.now() - lastCheck >= MIN_GAP) { delay = EVERY; if (timer) { clearTimeout(timer); } check(); } }
  document.addEventListener("visibilitychange", function () { if (!document.hidden) { soon(); } });
  window.addEventListener("focus", soon);

  // a test hook (Playwright fixture mode): check now instead of waiting five minutes
  window.siVersionCheck = { now: function () { lastCheck = 0; soon(); } };

  schedule();
})();
