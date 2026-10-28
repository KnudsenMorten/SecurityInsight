// Trend cards (#334): hover or focus on a card's sparkline reads one day -- "2026-10-04: 8,205" -- in the card's caption
// (aria-live), with a cursor line on the day. Arrow keys / Home / End move day by day when the sparkline has focus.
// The server drew the line and wrote the points (data-x / data-y on the card's own scale), the ISO days (data-days)
// and the raw values (data-values); this file only reads them. Numbers go through the ONE browser formatter
// (numbers.js, BRAND-2.6); a day is a calendar date (yyyy-MM-dd), shown as it is (BRAND-2.10: no time, no zone shift).
// Without this file the card is complete: the value, the changes and the low / high caption are server-rendered.
import { formatNumber } from "./numbers.js";

function list(svg, name) { return (svg.getAttribute(name) || "").split(","); }

export function initSparklines(root) {
  (root || document).querySelectorAll("svg[data-spark]").forEach(function (svg) {
    if (svg.getAttribute("data-spark-ready") === "1") { return; }
    svg.setAttribute("data-spark-ready", "1");
    var days = list(svg, "data-days"), vals = list(svg, "data-values"), xs = list(svg, "data-x"), ys = list(svg, "data-y");
    var score = svg.getAttribute("data-kind") === "score";
    var tip = svg.parentNode.querySelector("[data-spark-tip]");
    var cursor = svg.querySelector(".spark-cursor");
    var idle = tip ? tip.textContent : "";
    var have = [];
    for (var i = 0; i < xs.length; i++) { if (xs[i] !== "" && vals[i] !== "") { have.push(i); } }
    if (have.length === 0) { return; }
    var at = have.length - 1;

    function show(k) {
      at = Math.max(0, Math.min(have.length - 1, k));
      var i = have[at], v = Number(vals[i]);
      if (tip) { tip.textContent = days[i] + ": " + formatNumber(score ? Math.round(v) : v, 0); }
      if (cursor) { cursor.setAttribute("x1", xs[i]); cursor.setAttribute("x2", xs[i]); cursor.setAttribute("visibility", "visible"); }
    }
    function hide() {
      if (tip) { tip.textContent = idle; }
      if (cursor) { cursor.setAttribute("visibility", "hidden"); }
    }
    // the nearest day with a value to a pointer x (the svg is stretched: map the client x into the viewBox)
    function nearest(clientX) {
      var r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal;
      var x = r.width > 0 ? (clientX - r.left) / r.width * vb.width : 0, best = 0, dist = Infinity;
      have.forEach(function (i, k) { var d = Math.abs(Number(xs[i]) - x); if (d < dist) { dist = d; best = k; } });
      return best;
    }
    svg.addEventListener("pointermove", function (e) { show(nearest(e.clientX)); });
    svg.addEventListener("pointerleave", function () { if (document.activeElement !== svg) { hide(); } });
    svg.addEventListener("focus", function () { show(at); });
    svg.addEventListener("blur", hide);
    svg.addEventListener("keydown", function (e) {
      var k = { ArrowLeft: at - 1, ArrowRight: at + 1, Home: 0, End: have.length - 1 }[e.key];
      if (k === undefined) { return; }
      e.preventDefault();
      show(k);
    });
    // a click on the sparkline opens the card's findings, like the rest of the card
    svg.addEventListener("click", function () {
      var a = svg.closest("[data-tcard]") && svg.closest("[data-tcard]").querySelector(".tcard-h a");
      if (a) { a.click(); }
    });
  });
}
