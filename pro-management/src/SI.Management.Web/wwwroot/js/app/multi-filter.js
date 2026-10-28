// THE filter of every view (Pages/Shared/_MultiFilter.cshtml): checkboxes, "All" = none ticked. "All" unticks every
// value; ticking a value unticks "All"; the closed filter says what is chosen ("All", the one value, "2 chosen"). Escape
// closes an open filter and gives the focus back to it; opening one closes the others. Without this file the filter is
// the plain checkbox list, and nothing ticked still means all.
import { formatNumber } from "./numbers.js";

function boxes(det) { return Array.prototype.slice.call(det.querySelectorAll('.colfilter-list input[type="checkbox"]')); }

function labelOf(box) {
  var lab = box.closest("label");
  if (!lab) { return box.value; }
  var copy = lab.cloneNode(true);
  copy.querySelectorAll("[data-value-count], input").forEach(function (x) { x.remove(); });
  return copy.textContent.replace(/\s+/g, " ").trim() || box.value;
}

function sync(det) {
  var ticked = boxes(det).filter(function (b) { return b.checked; });
  var all = det.querySelector("[data-mf-all]");
  if (all) { all.checked = ticked.length === 0; }
  var text = ticked.length === 0 ? "All" : ticked.length === 1 ? labelOf(ticked[0]) : formatNumber(ticked.length) + " chosen";
  var s = det.querySelector("[data-mf-summary]");
  if (s) { s.textContent = text; }
  var sum = det.querySelector("summary");
  var name = det.querySelector(".mf-name");
  if (sum) { sum.setAttribute("aria-label", "Filter " + (name ? name.textContent.trim() + ": " : "") + text); }
  det.classList.toggle("is-chosen", ticked.length > 0);
}

export function initMultiFilters(root) {
  var all = Array.prototype.slice.call((root || document).querySelectorAll("details[data-multifilter]"));
  all.forEach(function (det) {
    if (det.getAttribute("data-mf-ready") === "1") { return; }
    det.setAttribute("data-mf-ready", "1");
    det.addEventListener("change", function (e) {
      var t = e.target;
      if (!(t instanceof HTMLInputElement) || t.type !== "checkbox") { return; }
      if (t.hasAttribute("data-mf-all")) {
        if (t.checked) { boxes(det).forEach(function (b) { b.checked = false; }); }
        else if (!boxes(det).some(function (b) { return b.checked; })) { t.checked = true; }
      }
      sync(det);
    });
    det.addEventListener("toggle", function () {
      if (!det.open) { return; }
      all.forEach(function (o) { if (o !== det && o.open) { o.open = false; } });
    });
    // "Done" of a filter inside a larger form (MultiFilter.ApplyCloses): close the list, keep the ticks, submit nothing
    det.addEventListener("click", function (e) {
      var b = e.target instanceof Element ? e.target.closest("[data-mf-close]") : null;
      if (!b) { return; }
      e.preventDefault();
      sync(det);
      det.open = false;
      var s = det.querySelector("summary");
      if (s) { s.focus(); }
    });
    det.addEventListener("keydown", function (e) {
      if (e.key !== "Escape" || !det.open) { return; }
      det.open = false;
      var s = det.querySelector("summary");
      if (s) { s.focus(); }
    });
    sync(det);
  });
  // a page shown again (back / forward, a restored form) can carry ticks no change event announced: "All" is ALWAYS
  // "none ticked", never ticked beside a value (a customer 2026-10-20 saw All + Critical + High)
  window.addEventListener("pageshow", function () { all.forEach(sync); });
  // a click outside closes an open filter (its ticks stay until Apply)
  document.addEventListener("click", function (e) {
    var t = e.target instanceof Element ? e.target : null;
    all.forEach(function (det) { if (det.open && t && !det.contains(t)) { det.open = false; } });
  });
}
