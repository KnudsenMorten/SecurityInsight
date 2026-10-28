// The service map (the tier board's pattern): lanes = the asset pool + one per CMDB service, cards loaded page by page
// from the server, MULTI-SELECT (a card's checkbox or Ctrl/Cmd-click, or "all matching the filter"), native HTML5
// drag-and-drop with lit legal targets. A drop NEVER writes: it asks for a reason, then STAGES one change through the
// page's Stage handler; Review & commit writes it.
import { toast } from "./ui.js";
import { formatNumber } from "./numbers.js";

var MAX_PER_LANE = 600;

export function initMap(wrap) {
  var token = wrap.getAttribute("data-token") || "";
  var query = wrap.getAttribute("data-query") || "";
  var edit = wrap.getAttribute("data-edit") === "1";
  var staged = [];
  try { staged = JSON.parse((wrap.querySelector("[data-staged]") || {}).textContent || "[]") || []; } catch (e) { staged = []; }
  var picked = {};          // lane -> { key: name }
  var matching = wrap.querySelector("[data-select-matching]");
  var dragging = null;

  function lanes() { return Array.prototype.slice.call(wrap.querySelectorAll("[data-lane]")); }
  function laneOf(el) { return el.closest("[data-lane]"); }
  function laneId(el) { return laneOf(el).getAttribute("data-lane"); }
  function isPool(name) { return name === "pool"; }

  // ---- staged markers ----
  function markStaged() {
    wrap.querySelectorAll(".map-card").forEach(function (c) {
      var key = c.getAttribute("data-asset");
      c.classList.toggle("staged", staged.some(function (s) { return s.assetKey === key; }));
    });
  }

  // ---- selection ----
  function setPicked(card, on) {
    var lane = laneId(card), key = card.getAttribute("data-asset");
    picked[lane] = picked[lane] || {};
    if (on) { picked[lane][key] = card.getAttribute("data-name"); } else { delete picked[lane][key]; }
    card.classList.toggle("picked", on);
    var box = card.querySelector("[data-pick]");
    if (box) { box.checked = on; }
    hint();
  }
  function count(lane) { return Object.keys(picked[lane] || {}).length; }
  function hint() {
    var h = wrap.querySelector("[data-selection-hint]");
    if (!h) { return; }
    var n = matching && matching.checked ? parseInt(matching.getAttribute("data-count") || "0", 10) : count("pool");
    h.textContent = n > 0 ? formatNumber(n) + " selected -- drag one of them onto a service." : "Select cards, then drag one onto a service.";
  }
  if (edit) {
    wrap.addEventListener("change", function (e) {
      if (e.target && e.target.hasAttribute && e.target.hasAttribute("data-pick")) { setPicked(e.target.closest(".map-card"), e.target.checked); }
    });
    wrap.addEventListener("click", function (e) {
      var card = e.target.closest && e.target.closest(".map-card");
      if (!card || e.target.hasAttribute("data-pick")) { return; }
      if (e.ctrlKey || e.metaKey) { e.preventDefault(); setPicked(card, !card.classList.contains("picked")); }
    });
    if (matching) { matching.addEventListener("change", hint); }
  }

  // ---- loading more cards ----
  function cardEl(c) {
    var d = document.createElement("div");
    d.className = "card-asset map-card";
    d.draggable = edit;
    d.setAttribute("data-asset", c.key);
    d.setAttribute("data-name", c.name);
    d.setAttribute("data-services", String(c.services || 0));
    var n = document.createElement("span"); n.className = "name";
    if (edit) { var b = document.createElement("input"); b.type = "checkbox"; b.setAttribute("data-pick", ""); b.setAttribute("aria-label", "Select " + c.name); n.appendChild(b); }
    n.appendChild(document.createTextNode(c.name));
    var m = document.createElement("span"); m.className = "meta";
    m.textContent = (c.kind || "asset") + " · " + (c.tier === "Unclassified" ? "Unclassified" : "Tier " + c.tier) + (c.risk ? " · weighted risk " + c.risk : "");
    d.appendChild(n); d.appendChild(m);
    if ((c.services || 0) > 1) { var s = document.createElement("span"); s.className = "badge multi"; s.title = c.numbers || ""; s.textContent = "in " + formatNumber(c.services) + " services"; d.appendChild(s); }
    return d;
  }
  function loadMore(lane, button) {
    var box = lane.querySelector("[data-cards]");
    var loaded = parseInt(box.getAttribute("data-loaded") || "0", 10);
    if (button.dataset.busy === "1") { return; }
    if (loaded >= MAX_PER_LANE) { button.disabled = true; button.textContent = "Showing " + formatNumber(loaded) + " -- refine the filter to see others"; return; }
    button.dataset.busy = "1";
    fetch("/Cmdb/Map?handler=Cards&lane=" + encodeURIComponent(lane.getAttribute("data-lane")) + "&skip=" + loaded + query, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.json(); })
      .then(function (d) {
        (d.items || []).forEach(function (c) { box.insertBefore(cardEl(c), button); });
        box.setAttribute("data-loaded", String(loaded + (d.items || []).length));
        if (!d.more) { button.remove(); }
        markStaged();
      })
      .catch(function (e) { toast("More assets could not be loaded: " + e.message, "error"); })
      .finally(function () { button.dataset.busy = "0"; });
  }
  lanes().forEach(function (lane) {
    var b = lane.querySelector("[data-load-more]");
    if (!b) { return; }
    b.addEventListener("click", function () { loadMore(lane, b); });
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (en) { en.forEach(function (x) { if (x.isIntersecting && b.isConnected) { loadMore(lane, b); } }); },
        { root: lane.querySelector("[data-cards]"), rootMargin: "200px" }).observe(b);
    }
  });

  if (!edit) { markStaged(); return; }

  // ---- drag and drop ----
  function legal(lane) {
    if (!dragging || lane.getAttribute("data-drop") !== "1") { return false; }
    var to = lane.getAttribute("data-lane");
    if (to === dragging.from) { return false; }
    return isPool(to) ? !isPool(dragging.from) : true;
  }
  function clearLit() { lanes().forEach(function (l) { l.classList.remove("drop-ok", "drop-over"); }); }

  wrap.addEventListener("dragstart", function (e) {
    var card = e.target.closest && e.target.closest(".map-card");
    if (!card) { return; }
    var from = laneId(card), key = card.getAttribute("data-asset");
    var all = isPool(from) && matching && matching.checked;
    var sel = picked[from] || {};
    var assets;
    if (!all && sel[key] === undefined) { assets = [{ key: key, name: card.getAttribute("data-name") }]; }
    else { assets = Object.keys(sel).map(function (k) { return { key: k, name: sel[k] }; }); }
    dragging = { from: from, assets: assets, all: all, count: all ? parseInt(matching.getAttribute("data-count") || "0", 10) : assets.length };
    e.dataTransfer.effectAllowed = "copyMove";
    e.dataTransfer.setData("text/plain", key);
    lanes().forEach(function (l) { if (legal(l)) { l.classList.add("drop-ok"); } });
  });
  document.addEventListener("dragend", function () { dragging = null; clearLit(); });
  lanes().forEach(function (lane) {
    lane.addEventListener("dragover", function (e) { if (legal(lane)) { e.preventDefault(); lane.classList.add("drop-over"); } });
    lane.addEventListener("dragleave", function () { lane.classList.remove("drop-over"); });
    lane.addEventListener("drop", function (e) {
      if (!legal(lane)) { return; }
      e.preventDefault();
      var d = dragging; dragging = null; clearLit();
      stage(d, lane);
    });
  });

  function serviceLabel(laneEl) { return laneEl.getAttribute("data-service-number") + " " + laneEl.getAttribute("data-service-name"); }
  function plural(n) { return n === 1 ? "1 asset" : formatNumber(n) + " assets"; }

  function askReason(title, text) {
    var dlg = document.querySelector("[data-reason-dialog]");
    if (!dlg || typeof dlg.showModal !== "function") { return Promise.resolve(null); }
    dlg.querySelector("[data-reason-title]").textContent = title;
    dlg.querySelector("[data-reason-text]").textContent = text + " Nothing is written until you review and commit.";
    var input = dlg.querySelector("[data-reason-input]");
    input.value = "";
    return new Promise(function (resolve) {
      dlg.addEventListener("close", function onClose() { dlg.removeEventListener("close", onClose); resolve(dlg.returnValue === "ok" ? input.value.trim() : null); });
      dlg.returnValue = "";
      dlg.showModal();
      input.focus();
    });
  }

  function stage(d, target) {
    var to = target.getAttribute("data-lane");
    var unlink = isPool(to);
    var svcLane = unlink ? wrap.querySelector('[data-lane="' + d.from + '"]') : target;
    var title = unlink ? "Unlink " + plural(d.count) + " from " + serviceLabel(svcLane) + "?" : "Link " + plural(d.count) + " to " + serviceLabel(svcLane) + "?";
    var text = unlink ? "Stages removing these assets from the service (the history stays)." : "Stages adding these assets to the service. An asset keeps every other service it is in.";
    askReason(title, text).then(function (reason) {
      if (reason === null) { return; }
      if (reason.length < 3) { toast("Not staged: give a reason (at least 3 characters).", "error"); return; }
      var body = new URLSearchParams();
      body.set("__RequestVerificationToken", token);
      body.set("Action", unlink ? "unlink" : "link");
      body.set("ServiceId", svcLane.getAttribute("data-lane"));
      body.set("Reason", reason);
      if (d.all) { body.set("AllMatching", "true"); } else { body.set("Assets", JSON.stringify(d.assets)); }
      fetch("/Cmdb/Map?handler=Stage" + query, { method: "POST", body: body, credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.json(); })
        .then(function (res) {
          toast(res.message, res.ok ? "ok" : "error");
          var badge = document.querySelector("[data-pending-count]");
          if (badge && typeof res.pending === "number") { badge.textContent = formatNumber(res.pending); badge.classList.toggle("warn", res.pending > 0); }
          if (res.ok) {
            d.assets.forEach(function (a) { staged.push({ assetKey: a.key, lane: unlink ? "pool" : to }); });
            Object.keys(picked).forEach(function (l) { wrap.querySelectorAll(".map-card.picked").forEach(function (c) { setPicked(c, false); }); delete picked[l]; });
            if (matching) { matching.checked = false; }
            hint(); markStaged();
          }
        })
        .catch(function (e) { toast("Not staged: " + e.message, "error"); });
    });
  }

  markStaged();
  hint();
}
