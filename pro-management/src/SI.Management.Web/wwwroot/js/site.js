// SecurityInsight Pro management -- page behaviour. No inline script anywhere (the CSP forbids it): every chart is a
// <canvas data-chart="ID"> next to <script type="application/json" id="ID"> holding its spec, rendered here with the
// VENDORED Chart.js (wwwroot/lib, never a CDN -- the app runs on private ingress).
(function () {
  "use strict";

  // The grouped navigation (and the user menu): one menu open at a time; a click outside or Escape closes it and gives
  // the focus back to its group. Without this the <details> menus still open and close.
  var menus = document.querySelectorAll("details.nav-group, details.usermenu, details.hdr-env");
  function closeAll(except) {
    Array.prototype.forEach.call(menus, function (d) { if (d !== except) { d.open = false; } });
  }
  // A group's menu opens under its group, to the right. One that would stick out of the window there opens leftwards
  // instead (a class -- no inline style: the CSP); if it then stuck out at the left, it stays as it was. In the accordion
  // layout (a narrow window) a menu is part of the page's flow and never sticks out.
  function fitMenu(d) {
    var menu = d.querySelector(".nav-group-menu");
    if (!menu) { return; }
    menu.classList.remove("to-left");
    if (!d.open || menu.getBoundingClientRect().right <= document.documentElement.clientWidth) { return; }
    menu.classList.add("to-left");
    if (menu.getBoundingClientRect().left < 0) { menu.classList.remove("to-left"); }
  }
  Array.prototype.forEach.call(menus, function (d) {
    d.addEventListener("toggle", function () { if (d.open) { closeAll(d); } fitMenu(d); });
  });
  document.addEventListener("click", function (e) {
    if (!e.target.closest || !e.target.closest("details.nav-group, details.usermenu, details.hdr-env")) { closeAll(null); }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") { return; }
    var open = document.querySelector("details.nav-group[open], details.usermenu[open], details.hdr-env[open]");
    if (open) { open.open = false; var s = open.querySelector("summary"); if (s) { s.focus(); } }
  });
  // #909: the environment's details card also opens on hover with a mouse (click, Enter and Space open it everywhere); it
  // closes when the pointer leaves, after a short grace so the pointer can travel into the card -- unless it was clicked open.
  var hoverable = window.matchMedia && window.matchMedia("(hover: hover) and (pointer: fine)").matches;
  Array.prototype.forEach.call(document.querySelectorAll("details.hdr-env"), function (d) {
    if (!hoverable) { return; }
    var timer = null, byHover = false;
    d.addEventListener("mouseenter", function () { clearTimeout(timer); if (!d.open) { byHover = true; d.open = true; } });
    d.addEventListener("mouseleave", function () { if (byHover) { timer = setTimeout(function () { d.open = false; byHover = false; }, 250); } });
    d.querySelector("summary").addEventListener("click", function (e) { if (byHover && d.open) { e.preventDefault(); byHover = false; } });
  });

  // A MENU BAR on a desktop (operator 2026-10-04: "when i turn to next menu so it folders out automatically"): hovering a
  // group opens its menu; moving to the next group swaps menus at once; leaving closes after a short grace so the
  // pointer can travel into the menu. Arrow Left / Right move between groups (and keep a menu open if one was), Arrow
  // Down opens the group and focuses its first item. A phone (the accordion layout, <= 880px) or a touch screen keeps
  // tap-to-open.
  var groups = Array.prototype.slice.call(document.querySelectorAll("details.nav-group"));
  var desktop = window.matchMedia ? window.matchMedia("(min-width: 881px) and (hover: hover) and (pointer: fine)") : null;
  function isBar() { return !!(desktop && desktop.matches); }
  var leaveTimer = null;
  function cancelLeave() { if (leaveTimer) { clearTimeout(leaveTimer); leaveTimer = null; } }
  var hoverOpenedAt = 0;
  var usingKeys = false;
  document.addEventListener("keydown", function () { usingKeys = true; }, true);
  document.addEventListener("mousedown", function () { usingKeys = false; }, true);
  document.addEventListener("mousemove", function () { usingKeys = false; }, true);
  function openGroup(d) { cancelLeave(); if (!d.open) { d.open = true; hoverOpenedAt = Date.now(); } closeAll(d); fitMenu(d); }
  groups.forEach(function (d, i) {
    // the click that follows a hover-open must not fold the menu straight back in
    var sum = d.querySelector("summary");
    if (sum) {
      sum.addEventListener("click", function (e) {
        if (isBar() && d.open && Date.now() - hoverOpenedAt < 600) { e.preventDefault(); }
      });
    }
    d.addEventListener("mouseenter", function () { if (isBar()) { openGroup(d); } });
    d.addEventListener("mouseleave", function () {
      if (!isBar()) { return; }
      cancelLeave();
      // a keyboard user inside the menu keeps it; a mouse user leaving closes it (a click leaves focus on the summary)
      leaveTimer = setTimeout(function () { if (!(usingKeys && d.matches(":focus-within"))) { d.open = false; } }, 250);
    });
    var s = d.querySelector("summary");
    if (!s) { return; }
    s.addEventListener("keydown", function (e) {
      var next = null;
      if (e.key === "ArrowRight") { next = groups[(i + 1) % groups.length]; }
      else if (e.key === "ArrowLeft") { next = groups[(i - 1 + groups.length) % groups.length]; }
      else if (e.key === "ArrowDown") {
        e.preventDefault(); openGroup(d);
        var first = d.querySelector(".nav-group-item"); if (first) { first.focus(); }
        return;
      }
      if (!next) { return; }
      e.preventDefault();
      var wasOpen = groups.some(function (g) { return g.open; });
      closeAll(null);
      if (wasOpen) { next.open = true; }
      var ns = next.querySelector("summary"); if (ns) { ns.focus(); }
    });
  });
  // Arrow Up / Down inside an open menu move between its items.
  document.addEventListener("keydown", function (e) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") { return; }
    var item = e.target && e.target.closest ? e.target.closest(".nav-group-item") : null;
    if (!item) { return; }
    var items = Array.prototype.slice.call(item.closest("details.nav-group").querySelectorAll(".nav-group-item"));
    var k = items.indexOf(item) + (e.key === "ArrowDown" ? 1 : -1);
    if (k >= 0 && k < items.length) { e.preventDefault(); items[k].focus(); }
  });

  // Settings > Risk rating: the Low field follows the Moderate threshold while it is typed (Low = less than Moderate).
  var moderate = document.querySelector("input[data-threshold='Moderate']");
  var low = document.querySelector("input[data-threshold-low]");
  if (moderate && low) {
    moderate.addEventListener("input", function () { low.value = moderate.value; });
  }

  // Every <time datetime> (the old data-local-time ones included) is shown in the viewer's zone by local-time.js (#313).

  // The job schedule editor: show only the fields the chosen "How often" uses; show the start time in the viewer's clock.
  Array.prototype.forEach.call(document.querySelectorAll("form[data-schedule-editor]"), function (f) {
    var often = f.querySelector("[data-often]"), start = f.querySelector("[data-start-time]"), local = f.querySelector("[data-start-local]");
    function sync() {
      var v = often ? often.value : "";
      Array.prototype.forEach.call(f.querySelectorAll("[data-show]"), function (el) {
        el.hidden = (" " + el.getAttribute("data-show") + " ").indexOf(" " + v + " ") < 0;
      });
      if (start && local) {
        var m = /^(\d{1,2}):(\d{2})$/.exec(start.value || "");
        if (!m) { local.textContent = ""; return; }
        var d = new Date(); d.setUTCHours(+m[1], +m[2], 0, 0);
        local.textContent = window.siLocalTime ? "= " + window.siLocalTime.format(d, "time") + " your time" : "";
      }
    }
    if (often) { often.addEventListener("change", sync); }
    if (start) { start.addEventListener("input", sync); }
    sync();
  });

  // A Copy button beside a setting's internal name (data-copy holds the text). Without the clipboard API the name is
  // still selectable in one click.
  document.addEventListener("click", function (e) {
    var b = e.target && e.target.closest ? e.target.closest("button[data-copy]") : null;
    if (!b || !navigator.clipboard) { return; }
    navigator.clipboard.writeText(b.getAttribute("data-copy")).then(function () {
      var t = b.textContent; b.textContent = "Copied"; setTimeout(function () { b.textContent = t; }, 1500);
    });
  });

  // The audit trail's print view (#260): a Print button (no inline script under the CSP).
  document.addEventListener("click", function (e) {
    var b = e.target && e.target.closest ? e.target.closest("button[data-print]") : null;
    if (b) { window.print(); }
  });

  if (typeof Chart === "undefined") { return; }

  function token(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

  function build(canvas) {
    var specEl = document.getElementById(canvas.getAttribute("data-chart"));
    if (!specEl) { return; }
    var spec = JSON.parse(specEl.textContent || "{}");
    // time labels arrive as UTC moments: shown in the viewer's zone, like every other time (#313)
    if (spec.timeLabels && window.siLocalTime) {
      spec.labels = (spec.labels || []).map(function (l) { return window.siLocalTime.format(l, "datetime") || l; });
    }
    var text = token("--text-secondary"), grid = token("--grid"), surface = token("--surface-1");
    var datasets = (spec.series || []).map(function (s) {
      var c = token("--series-" + (s.slot || 1));
      return {
        label: s.name, data: s.data, borderColor: c, backgroundColor: c,
        borderWidth: 2, pointRadius: spec.type === "line" ? 0 : undefined, pointHoverRadius: 4,
        pointHoverBorderColor: surface, pointHoverBorderWidth: 2, tension: 0.2,
        borderRadius: spec.type === "bar" ? 4 : 0, borderSkipped: "start", maxBarThickness: 22,
        spanGaps: true
      };
    });
    new Chart(canvas, {
      type: spec.type || "line",
      data: { labels: spec.labels || [], datasets: datasets },
      options: {
        // axis labels, tooltips and data labels in the SAME locale the server wrote the tiles and tables in: the viewer's
        // Number format (<html data-number-locale>), never the browser's own language (BRAND-2.6)
        locale: document.documentElement.getAttribute("data-number-locale") || "en-US",
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },                    // the page renders an HTML legend (>= 2 series)
          tooltip: { mode: "index", intersect: false }
        },
        scales: {
          x: { ticks: { color: text, maxRotation: 0, autoSkip: true, maxTicksLimit: 6 }, grid: { display: false }, border: { color: grid } },
          y: {
            beginAtZero: spec.beginAtZero !== false,
            title: { display: !!spec.yLabel, text: spec.yLabel || "", color: text },
            ticks: { color: text, maxTicksLimit: 6 }, grid: { color: grid }, border: { display: false }
          }
        }
      }
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll("canvas[data-chart]"), build);

  // a theme switch re-reads the colour tokens: every chart is drawn again in the new colours
  window.addEventListener("si-theme-change", function () {
    Array.prototype.forEach.call(document.querySelectorAll("canvas[data-chart]"), function (c) {
      var old = Chart.getChart ? Chart.getChart(c) : null;
      if (old) { old.destroy(); }
      build(c);
    });
  });
})();
