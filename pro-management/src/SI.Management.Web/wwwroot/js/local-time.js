// ONE time formatter for the browser (BRAND-2.10, SI #313): every time a person reads is shown in THIS BROWSER's time
// zone (Intl resolvedOptions().timeZone, daylight saving included), as yyyy-MM-dd HH:mm (BRAND-2.6) -- never UTC.
// The server stores and writes UTC; it never converts, because it does not know the viewer's zone. Two shapes:
//   <time datetime="2026-10-04T18:54:00Z" data-fmt="datetime|date|time|relative" [data-zone] [data-seconds]>fallback</time>
//     -> the text becomes the local time. data-zone (audit / evidence views): a small zone label (CEST) and the UTC
//        value in the tooltip.
//   any element marked data-utc (an <option>, a <select>, a tooltip holder, a sentence built on the server)
//     -> every "yyyy-MM-dd HH:mm[:ss] UTC" (or "...Z") in its text and its title is rewritten in place.
// It runs once when the page is read and again for every element a script adds later (paging, live refresh, rows and
// cards fetched as HTML) -- a MutationObserver, so no other script has to remember to call it. Without script the
// page still reads correctly: the fallback text says UTC. Other scripts use window.siLocalTime.format(iso, fmt).
(function () {
  "use strict";

  var UTC_TEXT = /(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)? ?(?:UTC|Z)(?![A-Za-z])/g;

  function pad(n) { return (n < 10 ? "0" : "") + n; }

  function parse(iso) {
    if (!iso) { return null; }
    var d = new Date(iso);
    return isNaN(d.getTime()) ? null : d;
  }

  // yyyy-MM-dd HH:mm in the browser's zone (Date's local getters ARE the browser's zone, DST included)
  function format(value, fmt, seconds) {
    var d = value instanceof Date ? value : parse(value);
    if (!d) { return ""; }
    var day = d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
    var time = pad(d.getHours()) + ":" + pad(d.getMinutes()) + (seconds ? ":" + pad(d.getSeconds()) : "");
    if (fmt === "date") { return day; }
    if (fmt === "time") { return time; }
    if (fmt === "relative") { return relative(d); }
    return day + " " + time;
  }

  var rtf = null;
  function relative(d) {
    var s = Math.round((d.getTime() - Date.now()) / 1000), a = Math.abs(s);
    var unit = a < 60 ? ["second", s] : a < 3600 ? ["minute", Math.round(s / 60)] : a < 86400 ? ["hour", Math.round(s / 3600)] : ["day", Math.round(s / 86400)];
    try {
      if (!rtf) { rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" }); }
      return rtf.format(unit[1], unit[0]);
    } catch (e) { return format(d, "datetime"); }
  }

  // The short zone name for a moment (CEST / CET; another zone may read GMT+2) -- for the audit views' label.
  function zoneLabel(d) {
    try {
      var parts = new Intl.DateTimeFormat("en-GB", { timeZoneName: "short" }).formatToParts(d);
      for (var i = 0; i < parts.length; i++) { if (parts[i].type === "timeZoneName") { return parts[i].value; } }
    } catch (e) { /* an old browser: no label */ }
    return "";
  }

  function zoneName() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) { return ""; }
  }

  function utcText(d, seconds) {
    return d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " + pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) +
      (seconds ? ":" + pad(d.getUTCSeconds()) : "") + " UTC";
  }

  function rewriteText(s) {
    return s.replace(UTC_TEXT, function (m, y, mo, da, h, mi, se) {
      var d = new Date(Date.UTC(+y, +mo - 1, +da, +h, +mi, se ? +se : 0));
      return format(d, "datetime", !!se);
    });
  }

  function timeElement(t) {
    if (t.hasAttribute("data-local-done")) { return; }
    var d = parse(t.getAttribute("datetime"));
    if (!d) { return; }
    var fmt = t.getAttribute("data-fmt") || "datetime", seconds = t.hasAttribute("data-seconds");
    t.setAttribute("data-local-done", "");
    if (t.hasAttribute("data-local-time") && !t.hasAttribute("data-fmt")) {
      // the schedule editor's "= 07:30 your time" beside a UTC schedule slot (the date only when the day differs)
      var sameDay = d.getUTCFullYear() === d.getFullYear() && d.getUTCMonth() === d.getMonth() && d.getUTCDate() === d.getDate();
      t.textContent = (sameDay ? "" : format(d, "date") + " ") + format(d, "time") + " your time";
      return;
    }
    t.textContent = format(d, fmt, seconds);
    if (fmt === "relative") { t.title = format(d, "datetime"); }
    if (t.hasAttribute("data-zone")) {
      var z = zoneLabel(d);
      if (z) { var small = document.createElement("small"); small.className = "tz"; small.textContent = " " + z; t.appendChild(small); }
      t.title = utcText(d, true) + (zoneName() ? " · shown in " + zoneName() : "");
    }
  }

  function utcElement(el) {
    var walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null), n;
    while ((n = walker.nextNode())) {
      UTC_TEXT.lastIndex = 0;
      if (UTC_TEXT.test(n.nodeValue)) { n.nodeValue = rewriteText(n.nodeValue); }
    }
    var title = el.getAttribute("title");
    if (title) { UTC_TEXT.lastIndex = 0; if (UTC_TEXT.test(title)) { el.setAttribute("title", rewriteText(title)); } }
  }

  // Formats every time inside root (and root itself).
  function apply(root) {
    if (!root || root.nodeType !== 1 && root.nodeType !== 9) { return; }
    var self = root.nodeType === 1 ? root : null;
    if (self && self.matches("time[datetime]")) { timeElement(self); }
    if (self && self.hasAttribute("data-utc")) { utcElement(self); }
    Array.prototype.forEach.call(root.querySelectorAll("time[datetime]"), timeElement);
    Array.prototype.forEach.call(root.querySelectorAll("[data-utc]"), utcElement);
  }

  // A form with data-browser-tz inputs sends the browser's zone, so a date the person typed ("from 2026-10-01") is
  // read as THEIR day, not a UTC day.
  function fillZone(root) {
    Array.prototype.forEach.call((root || document).querySelectorAll("input[data-browser-tz]"), function (i) { if (!i.value) { i.value = zoneName(); } });
  }

  window.siLocalTime = { format: format, apply: apply, zone: zoneName, rewriteText: rewriteText };

  apply(document);
  fillZone(document);
  if (window.MutationObserver && document.body) {
    new MutationObserver(function (records) {
      records.forEach(function (r) {
        Array.prototype.forEach.call(r.addedNodes, function (n) { if (n.nodeType === 1) { apply(n); fillZone(n); } });
      });
    }).observe(document.body, { childList: true, subtree: true });
  }
})();
