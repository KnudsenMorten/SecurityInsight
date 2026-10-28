// Applies the viewer's theme choice BEFORE first paint (a classic script in <head>, no inline code: the CSP forbids it),
// so nothing flashes. "auto" (or nothing stored) = follow the operating system (prefers-color-scheme); "light" / "dark"
// = data-theme on <html>. The choice is a per-browser convenience only; the header's Theme switch changes it (ui.js).
(function () {
  "use strict";
  var choice = null;
  try { choice = window.localStorage.getItem("si-theme"); } catch (e) { choice = null; }
  if (choice === "light" || choice === "dark") { document.documentElement.setAttribute("data-theme", choice); }
})();
