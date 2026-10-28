// The Risk index editor (#266). The server renders the rows and is the authority (validation, dry run, staging); this
// module edits the draft in the browser: add, delete, duplicate, move (buttons and Alt+Up / Alt+Down), inline edit,
// reset a row to the vendor's, and show / hide columns. Every submit writes the draft back as JSON.
import { formatNumber } from "./numbers.js";

// the SI-keyed columns (#559) -> the draft's JSON property names (RiskIndexRow, camelCase)
const FIELDS = [
  ["si_finding_type", "findingType"], ["si_category", "category"], ["si_subcategory", "subCategory"], ["si_component", "component"],
  ["si_finding_key", "findingKey"], ["asset_class", "assetClass"], ["si_severity", "severity"], ["VulnerabilityBase", "vulnerabilityBase"],
  ["si_tier", "tier"], ["AssetBase", "assetBase"], ["Comments", "comments"],
];
const SCORES = ["VulnerabilityBase", "AssetBase"];
const LABEL = {
  si_finding_type: "Finding type", si_category: "Category", si_subcategory: "Subcategory", si_component: "Component", si_finding_key: "Finding key",
  asset_class: "Asset class", si_severity: "Severity", VulnerabilityBase: "Vulnerability base", si_tier: "Tier", AssetBase: "Asset base", Comments: "Comments",
};
const STORE = "si-riskindex-hidden-columns";

function prop(col) { for (const [c, p] of FIELDS) if (c === col) return p; return col; }

function emptyRow() { const r = { precedence: "" }; for (const [, p] of FIELDS) r[p] = ""; return r; }

function sameContent(a, b) { for (const [, p] of FIELDS) if ((a[p] || "") !== (b[p] || "")) return false; return true; }

function readJson(el, fallback) { try { return JSON.parse(el ? el.value : "") || fallback; } catch (e) { return fallback; } }

export function initRiskIndex(form) {
  if (!form) return;
  initColumns();
  if (form.dataset.riskindex !== "edit") return;

  const draftEl = form.querySelector("[data-draft]");
  const templates = readJson(form.querySelector("[data-templates]"), {});
  let rows = readJson(draftEl, []).map(function (d) { return { row: Object.assign(emptyRow(), d.row || {}), src: d.src || "" }; });
  const body = form.querySelector("[data-rows]");

  function origin(d) {
    const t = templates[d.src];
    if (!t) return "yours";
    return sameContent(d.row, t) ? "vendor" : "changed";
  }

  function markEdited() {
    form.dataset.dirty = "1";
    const h = document.querySelector("[data-edited]");
    if (!h) {
      const title = document.getElementById("h-rows");
      if (title) { const b = document.createElement("span"); b.className = "badge warn"; b.setAttribute("data-edited", ""); b.textContent = "edited, not staged"; title.appendChild(b); }
    }
    const n = document.querySelector("[data-row-count]");
    if (n) n.textContent = formatNumber(rows.length, 0);
  }

  function check(input) {
    const col = input.dataset.field;
    let msg = "";
    if (SCORES.indexOf(col) >= 0 && input.value.trim() !== "") {
      const v = Number(input.value);
      if (!isFinite(v)) msg = LABEL[col] + " must be a number";
      else if (v < 0 || v > 10) msg = LABEL[col] + " must be between 0 and 10";
    }
    if (/["\r\n]/.test(input.value)) msg = LABEL[col] + " may not hold quotes or line breaks";
    input.setCustomValidity(msg);
    if (msg) { input.setAttribute("aria-invalid", "true"); input.title = msg; } else { input.removeAttribute("aria-invalid"); input.removeAttribute("title"); }
  }

  function cellInput(col, value, i) {
    const inp = document.createElement("input");
    inp.dataset.field = col;
    inp.value = value || "";
    inp.setAttribute("aria-label", LABEL[col] + ", row " + (i + 1));
    if (SCORES.indexOf(col) >= 0) { inp.type = "number"; inp.step = "any"; inp.min = "0"; inp.max = "10"; inp.inputMode = "decimal"; }
    else {
      inp.type = "text"; inp.maxLength = 400;
      if (col !== "Comments") inp.placeholder = "any";
      if (col === "si_severity") inp.setAttribute("list", "ri-severities");
      if (col === "si_tier") inp.setAttribute("list", "ri-tiers");
      if (col === "asset_class") inp.setAttribute("list", "ri-classes");
    }
    return inp;
  }

  function button(label, attr, aria, cls) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "small " + (cls || "secondary"); b.setAttribute(attr, ""); b.setAttribute("aria-label", aria); b.textContent = label;
    return b;
  }

  function render(focus) {
    body.textContent = "";
    rows.forEach(function (d, i) {
      const tr = document.createElement("tr");
      tr.dataset.row = String(i); tr.dataset.src = d.src;
      const ord = document.createElement("td"); ord.className = "num"; ord.setAttribute("data-order", ""); ord.textContent = formatNumber(i + 1, 0); tr.appendChild(ord);
      const o = origin(d);
      const src = document.createElement("td"); const badge = document.createElement("span");
      badge.className = "badge " + (o === "vendor" ? "good" : o === "changed" ? "warn" : ""); badge.dataset.origin = o; badge.textContent = o;
      src.appendChild(badge); tr.appendChild(src);
      for (const [col, p] of FIELDS) {
        const td = document.createElement("td"); td.dataset.col = col;
        if (SCORES.indexOf(col) >= 0) td.className = "num";
        const inp = cellInput(col, d.row[p], i); td.appendChild(inp); check(inp);
        tr.appendChild(td);
      }
      const act = document.createElement("td"); act.setAttribute("data-actions", "");
      act.appendChild(button("Up", "data-up", "Move row " + (i + 1) + " up"));
      act.appendChild(button("Down", "data-down", "Move row " + (i + 1) + " down"));
      act.appendChild(button("Duplicate", "data-dup", "Duplicate row " + (i + 1)));
      const reset = button("Reset", "data-reset", "Reset row " + (i + 1) + " to the vendor's"); reset.disabled = !templates[d.src]; act.appendChild(reset);
      act.appendChild(button("Delete", "data-delete", "Delete row " + (i + 1), "danger"));
      tr.appendChild(act);
      body.appendChild(tr);
    });
    applyColumns();
    if (focus) {
      const el = body.querySelector('tr[data-row="' + focus.row + '"] ' + (focus.field ? '[data-field="' + focus.field + '"]' : "[" + focus.button + "]"));
      if (el) el.focus();
    }
    markEdited();
  }

  function indexOf(el) { const tr = el.closest("tr[data-row]"); return tr ? Number(tr.dataset.row) : -1; }

  function move(i, delta, focus) {
    const to = i + delta;
    if (i < 0 || to < 0 || to >= rows.length) return;
    const r = rows.splice(i, 1)[0]; rows.splice(to, 0, r);
    render(Object.assign({ row: to }, focus));
  }

  body.addEventListener("input", function (e) {
    const inp = e.target.closest("[data-field]"); if (!inp) return;
    const i = indexOf(inp); if (i < 0) return;
    rows[i].row[prop(inp.dataset.field)] = inp.value;
    check(inp);
    const badge = inp.closest("tr").querySelector("[data-origin]");
    if (badge) { const o = origin(rows[i]); badge.dataset.origin = o; badge.textContent = o; badge.className = "badge " + (o === "vendor" ? "good" : o === "changed" ? "warn" : ""); }
    markEdited();
  });

  body.addEventListener("keydown", function (e) {
    if (!e.altKey || (e.key !== "ArrowUp" && e.key !== "ArrowDown")) return;
    const el = e.target.closest("[data-field], button"); if (!el) return;
    const i = indexOf(el); if (i < 0) return;
    e.preventDefault();
    const focus = el.dataset.field ? { field: el.dataset.field } : { button: e.key === "ArrowUp" ? "data-up" : "data-down" };
    move(i, e.key === "ArrowUp" ? -1 : 1, focus);
  });

  body.addEventListener("click", function (e) {
    const b = e.target.closest("button"); if (!b) return;
    const i = indexOf(b); if (i < 0) return;
    if (b.hasAttribute("data-up")) move(i, -1, { button: "data-up" });
    else if (b.hasAttribute("data-down")) move(i, 1, { button: "data-down" });
    else if (b.hasAttribute("data-dup")) { rows.splice(i + 1, 0, { row: Object.assign({}, rows[i].row), src: "" }); render({ row: i + 1, field: "si_finding_key" }); }
    else if (b.hasAttribute("data-delete")) { rows.splice(i, 1); render(rows.length ? { row: Math.min(i, rows.length - 1), button: "data-delete" } : null); }
    else if (b.hasAttribute("data-reset")) {
      const t = templates[rows[i].src]; if (!t) return;
      const r = emptyRow(); for (const [, p] of FIELDS) r[p] = t[p] || ""; r.precedence = t.precedence || "";
      rows[i].row = r; render({ row: i, button: "data-reset" });
    }
  });

  const add = form.querySelector("[data-add]");
  if (add) add.addEventListener("click", function () { rows.push({ row: emptyRow(), src: "" }); render({ row: rows.length - 1, field: "si_finding_key" }); });

  form.addEventListener("submit", function () {
    draftEl.value = JSON.stringify(rows.map(function (d) { return { row: d.row, src: d.src }; }));
  });

  // the server-rendered rows (with the last check's notes under them) stay until the first add / move / delete
  body.querySelectorAll("[data-field]").forEach(check);
}

function hidden() { try { return JSON.parse(localStorage.getItem(STORE) || "[]"); } catch (e) { return []; } }
function saveHidden(list) { try { localStorage.setItem(STORE, JSON.stringify(list)); } catch (e) { /* per-viewer convenience only */ } }

function applyColumns() {
  const off = hidden();
  document.querySelectorAll("[data-ri-table] [data-col]").forEach(function (c) { c.hidden = off.indexOf(c.dataset.col) >= 0; });
  document.querySelectorAll("[data-col-toggle]").forEach(function (t) { t.checked = off.indexOf(t.dataset.colToggle) < 0; });
}

function initColumns() {
  document.querySelectorAll("[data-col-toggle]").forEach(function (t) {
    t.addEventListener("change", function () {
      let off = hidden().filter(function (c) { return c !== t.dataset.colToggle; });
      if (!t.checked) off.push(t.dataset.colToggle);
      saveHidden(off);
      applyColumns();
    });
  });
  applyColumns();
}
