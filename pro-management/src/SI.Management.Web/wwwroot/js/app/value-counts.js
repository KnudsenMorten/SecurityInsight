// #287: how many items each choice of a value filter holds -- "High (12)" -- counted on the server under the view's
// OTHER filters, so a count is exactly what picking that choice gives. Asked once, when the filter is first opened
// (a column filter <details data-counts-url>) or first focused (a <select data-counts-url>): the page itself never
// waits for counts. In the viewer's number format; a choice with none is dimmed (still selectable) and moves after the
// ones that have items. Without script (or when counting fails) the choices show as before, without counts.
import { formatNumber } from "./numbers.js";

function fetchCounts(url) {
  return fetch(url, { headers: { "Accept": "application/json" }, credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .catch(function () { return null; });
}

function byValue(res) {
  var m = {};
  ((res && res.values) || []).forEach(function (v) { m[String(v.value).toLowerCase()] = v.n; });
  return m;
}

// a column filter: <details data-counts-url> holding <label><input type=checkbox value=...> text</label>
function decorateList(det, res) {
  var counts = byValue(res);
  var list = det.querySelector(".colfilter-list");
  if (!list) { return; }
  // a filter whose choices are not drawn with the page ("+ Add filter"): the values the count read returned become its
  // choices -- a checkbox each, of the filter's own name and form
  if (det.hasAttribute("data-mf-fill")) {
    var have = {};
    Array.prototype.forEach.call(list.querySelectorAll("input[type=checkbox]"), function (b) { have[String(b.value).toLowerCase()] = 1; });
    ((res && res.values) || []).forEach(function (v) {
      var value = String(v.value);
      if (have[value.toLowerCase()]) { return; }
      var lab = document.createElement("label");
      var box = document.createElement("input");
      box.type = "checkbox"; box.name = det.getAttribute("data-filter") || ""; box.value = value;
      var form = det.getAttribute("data-mf-fill"); if (form) { box.setAttribute("form", form); }
      lab.appendChild(box);
      lab.appendChild(document.createTextNode(" " + (v.label ? String(v.label) : value)));
      list.appendChild(lab);
    });
  }
  var labels = Array.prototype.slice.call(list.querySelectorAll("label"));
  labels.forEach(function (lab) {
    var box = lab.querySelector("input[type=checkbox]");
    if (!box) { return; }
    var n = counts[String(box.value).toLowerCase()] || 0;
    var span = lab.querySelector("[data-value-count]");
    if (!span) { span = document.createElement("span"); span.className = "value-count"; span.setAttribute("data-value-count", ""); lab.appendChild(span); }
    span.textContent = " (" + formatNumber(n) + ")";
    lab.setAttribute("data-count", String(n));
    lab.classList.toggle("value-empty", n === 0);
  });
  // the choices with items first (their order kept), the empty ones after
  labels.filter(function (l) { return l.classList.contains("value-empty"); }).forEach(function (l) { list.appendChild(l); });
  // the shared filter's "All" (outside the list) carries the total when the server says it
  var all = det.querySelector("[data-mf-all]");
  var allLab = all ? all.closest("label") : null;
  if (allLab && res && typeof res.total === "number") {
    var t = allLab.querySelector("[data-value-count]");
    if (!t) { t = document.createElement("span"); t.className = "value-count"; t.setAttribute("data-value-count", ""); allLab.appendChild(t); }
    t.textContent = " (" + formatNumber(res.total) + ")";
  }
  det.setAttribute("data-counted", "1");
}

// a <select data-counts-url>: "All" carries the total, every option its count
function decorateSelect(sel, res) {
  var counts = byValue(res);
  var total = 0;
  Object.keys(counts).forEach(function (k) { total += counts[k]; });
  if (res && typeof res.total === "number") { total = res.total; }
  var opts = Array.prototype.slice.call(sel.options);
  opts.forEach(function (o) {
    // an option written without a value attribute takes its TEXT as its value: pin the value before the count is put
    // into the text, or the filter would be sent as "Very High (125)" and match nothing
    if (!o.hasAttribute("value")) { o.setAttribute("value", o.value); }
    var base = o.getAttribute("data-label") || o.textContent;
    o.setAttribute("data-label", base);
    var n = o.value === "" ? total : (counts[String(o.value).toLowerCase()] || 0);
    o.textContent = base + " (" + formatNumber(n) + ")";
    o.setAttribute("data-count", String(n));
    o.classList.toggle("value-empty", o.value !== "" && n === 0);
  });
  opts.filter(function (o) { return o.value !== "" && o.classList.contains("value-empty"); }).forEach(function (o) { sel.appendChild(o); });
  sel.setAttribute("data-counted", "1");
}

export function initValueCounts(root) {
  (root || document).querySelectorAll("details[data-counts-url]").forEach(function (det) {
    det.addEventListener("toggle", function () {
      if (!det.open || det.getAttribute("data-counted")) { return; }
      det.setAttribute("data-counted", "pending");
      fetchCounts(det.getAttribute("data-counts-url")).then(function (res) {
        if (res && res.ok) { decorateList(det, res); } else { det.removeAttribute("data-counted"); }
      });
    });
  });
  (root || document).querySelectorAll("select[data-counts-url]").forEach(function (sel) {
    function load() {
      if (sel.getAttribute("data-counted")) { return; }
      sel.setAttribute("data-counted", "pending");
      fetchCounts(sel.getAttribute("data-counts-url")).then(function (res) {
        if (res && res.ok) { decorateSelect(sel, res); } else { sel.removeAttribute("data-counted"); }
      });
    }
    sel.addEventListener("focus", load);
    sel.addEventListener("pointerdown", load);
  });
}
