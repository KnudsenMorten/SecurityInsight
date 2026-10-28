// Entry module: small modules, each one concern. A page's own module loads only on the page that has it.
import "./numbers.js";
import { initToasts, initConfirm, initTheme, initAutosubmit, initSelection, initSearchKey, initPageBoxes, initFilterToggles } from "./ui.js";
import { initTables } from "./tables.js";
import { initViewLoading } from "./view-loading.js";

initToasts();
initConfirm();
initTheme();
initAutosubmit();
initSelection();
initSearchKey();
initPageBoxes();
initFilterToggles();
// #284: a collection view that is loading says so
initViewLoading();
// every <table data-sortable>: header sorting + a filter row (the server-side grids sort and filter in SQL)
initTables();

// #287: a value filter shows how many items each choice holds, counted when it is first opened
if (document.querySelector("[data-counts-url]")) {
  import("./value-counts.js").then(function (m) { m.initValueCounts(document); });
}

// THE filter of every view: checkboxes, "All" = none ticked (owner 2026-10-19: every filter multi-select)
if (document.querySelector("details[data-multifilter]")) {
  import("./multi-filter.js").then(function (m) { m.initMultiFilters(document); });
}

// the output scope's quick choices ("Critical and High only", "Devices and Azure only"): one click ticks those values
if (document.querySelector("[data-scope-quick]")) {
  import("./scope-editor.js").then(function (m) { m.initScopeQuick(document); });
}
// a CMDB connector's asset kind it cannot send yet: ticking one shows the card's hint
if (document.querySelector("[data-scope-unsent-hint]")) {
  import("./scope-editor.js").then(function (m) { m.initUnsentKinds(document); });
}
// the column builder of an output (Fields sent / Workbook fields): the arrows move a column and renumber the places
if (document.querySelector("[data-builder-list]")) {
  import("./column-builder.js").then(function (m) { document.querySelectorAll("[data-builder-list]").forEach(m.initColumnBuilder); });
}
// every data view's column chooser: a search box over hundreds of columns
if (document.querySelector("[data-column-chooser]")) {
  import("./column-chooser.js").then(function (m) { document.querySelectorAll("[data-column-chooser]").forEach(m.initColumnChooser); });
}

// a grid row that opens a side drawer (data-row-drawer): the fragment is read and shown at once, no page reload
if (document.querySelector("[data-row-drawer]")) {
  import("./row-drawer.js").then(function (m) { m.initRowDrawer(document); });
}

// #334: trend cards -- hover / focus on a sparkline reads one day
if (document.querySelector("svg[data-spark]")) {
  import("./sparkline.js").then(function (m) { m.initSparklines(document); });
}

// Operations > Data quality: Re-run from here on a warning answers in place (a toast), the page stays where it is
if (document.querySelector("form[data-dq-rerun]")) {
  import("./data-quality.js").then(function (m) { m.initDataQuality(document); });
}

// the tier board: a pin, an exclusion or a rule change staged from a row's drawer answers in place (a toast)
if (document.querySelector("[data-tier-board], [data-tier-stage]")) {
  import("./tier-board.js").then(function (m) { m.initTierBoard(document); });
}

if (document.querySelector("[data-riskindex]")) {
  import("./riskindex.js").then(function (m) { m.initRiskIndex(document.querySelector("[data-riskindex]")); });
}

// #272: the shared action bar on every grid of findings (#282: in the grid toolbar above the table)
if (document.querySelector("[data-finding-actions]")) {
  import("./finding-actions.js").then(function (m) { document.querySelectorAll("[data-finding-actions]").forEach(m.initFindingActions); });
}

if (document.querySelector("[data-template-builder], [data-exclusions]")) {
  import("./reports.js").then(function (m) { m.initReports(); });
}

// #335: a department's people table (Admin > Departments)
if (document.querySelector("[data-people-table]")) {
  import("./people-table.js").then(function (m) { document.querySelectorAll("[data-people-table]").forEach(m.initPeopleTable); });
}

// A switch's On / Off words follow its box -- live, on every page with a setting field (Settings, Get Started, ...),
// and again when the browser restores a page with the boxes as they were left (operator 2026-10-09: "Off" next to a
// ticked box).
function syncSwitch(cb) {
  var sw = cb.closest(".set-switch");
  var t = sw && sw.querySelector(".set-switch-text");
  if (t) { t.textContent = cb.checked ? "On" : "Off"; }
}
function syncSwitches() { document.querySelectorAll('.set-switch input[type="checkbox"]').forEach(syncSwitch); }
syncSwitches();
window.addEventListener("pageshow", syncSwitches);
document.addEventListener("change", function (e) {
  var cb = e.target;
  if (cb && cb.type === "checkbox" && cb.closest && cb.closest(".set-switch")) { syncSwitch(cb); }
});

// Get Started's AI step: the status line follows the AI switch the moment it is ticked -- "On -- not saved yet" (and the
// reverse) -- and says the saved state again when the box is set back. data-gs-ai-status = the SAVED value.
function syncAiStatus() {
  var st = document.querySelector("[data-gs-ai-status]");
  var cb = document.getElementById("f-SI_EnableAI");
  if (!st || !cb) { return; }
  if (st.dataset.savedText === undefined) { st.dataset.savedText = st.textContent; }
  var savedOn = st.getAttribute("data-gs-ai-status") === "on";
  st.textContent = cb.checked === savedOn ? st.dataset.savedText : (cb.checked ? "On -- not saved yet (save to turn AI on)" : "Off -- not saved yet (save to turn AI off)");
}
syncAiStatus();
window.addEventListener("pageshow", syncAiStatus);
document.addEventListener("change", function (e) { if (e.target && e.target.id === "f-SI_EnableAI") { syncAiStatus(); } });

// #503: the shared mailbox in two steps -- the command is built as the name is typed
if (document.querySelector("[data-mailbox-step1]")) {
  import("./mailbox-steps.js").then(function (m) { m.initMailboxSteps(document); });
}

// #446: fields that belong to one choice (the SMTP relay's fields only with SMTP) -- Settings and Get Started
if (document.querySelector("[data-show-when]")) {
  import("./show-when.js").then(function (m) { m.initShowWhen(document); });
}

// #446: Admin > Access -- find the person or group by name
if (document.querySelector("[data-access-picker]")) {
  import("./access-picker.js").then(function (m) { document.querySelectorAll("[data-access-picker]").forEach(m.initAccessPicker); });
}
// #765: Admin > Access -- the scope only with Delegated, the mail forward only for a person
if (document.querySelector("[data-access-form]")) {
  import("./access-picker.js").then(function (m) { document.querySelectorAll("[data-access-form]").forEach(m.initAccessForm); });
}

// #360: the weighted risk page -- rows that expand in place, the pivot builder's drag and drop
if (document.querySelector("input[data-expand], [data-pivot-builder]")) {
  import("./weighted.js").then(function (m) { m.initExpanders(document); m.initPivot(document); });
}

if (document.querySelector("[data-map]")) {
  import("./cmdbmap.js").then(function (m) { m.initMap(document.querySelector("[data-map]")); });
}

// the Settings page: the category bar, the filter, address chips and a Save per card
if (document.querySelector("[data-settings]")) {
  import("./settings.js").then(function (m) { m.initSettings(document.querySelector("[data-settings]")); });
}

// SETTING-INFO-1: a setting with a risky value outside the Settings page (Get Started) asks before it is saved too
if (document.querySelector('.set-field[data-confirm-when]:not([data-confirm-when=""])') && !document.querySelector("[data-settings]")) {
  import("./settings.js").then(function (m) { m.initRiskConfirm(document); });
}
