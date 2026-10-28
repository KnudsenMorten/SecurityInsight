// #360: the weighted risk page. (1) A grid row with data-expand gets a button that opens its assets (or services) in
// place, read from the server as an HTML fragment. (2) The pivot builder: every move is a server-built link on the chip
// (keyboard: Tab to it, Enter); drag and drop only follows the link that matches the drop -- an illegal drop has no link
// and does nothing. Nothing here builds a query: the server does, from its own whitelist.
import { toast } from "./ui.js";

export function initExpanders(root) {
  // the expansion's address rides on the row's checkbox (the grid's row markup stays as every other view has it)
  root.querySelectorAll("input[data-expand]").forEach(function (box) {
    var tr = box.closest("tr");
    var url = box.getAttribute("data-expand");
    var cell = tr ? tr.querySelector("td[data-col]") : null;
    if (!url || !cell || cell.querySelector(".expander")) { return; }
    var label = (cell.textContent || "").trim();
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "expander small secondary";
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-label", "Show what " + label + " holds");
    btn.textContent = "▸";
    cell.insertBefore(btn, cell.firstChild);
    var detail = null;
    btn.addEventListener("click", function () {
      if (detail) {
        var open = btn.getAttribute("aria-expanded") === "true";
        detail.hidden = open;
        btn.setAttribute("aria-expanded", open ? "false" : "true");
        btn.textContent = open ? "▸" : "▾";
        return;
      }
      if (btn.dataset.busy === "1") { return; }
      btn.dataset.busy = "1";
      fetch(url, { credentials: "same-origin", headers: { Accept: "text/html" } })
        .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.text(); })
        .then(function (html) {
          detail = document.createElement("tr");
          detail.className = "expand-row";
          var td = document.createElement("td");
          td.colSpan = tr.children.length;
          td.innerHTML = html;    // the server's own fragment (Razor-encoded), same origin
          detail.appendChild(td);
          tr.parentNode.insertBefore(detail, tr.nextSibling);
          btn.setAttribute("aria-expanded", "true");
          btn.textContent = "▾";
        })
        .catch(function () { toast("Could not open it here -- open the row instead.", "error"); })
        .finally(function () { btn.dataset.busy = "0"; });
    });
  });
}

export function initPivot(root) {
  var builder = root.querySelector("[data-pivot-builder]");
  if (!builder) { return; }
  var dragged = null;

  function linkFor(chip, zone) {
    return chip ? chip.querySelector('a[data-move="' + zone + '"]') : null;
  }

  builder.querySelectorAll(".pivot-chip").forEach(function (chip) {
    chip.addEventListener("dragstart", function (e) {
      dragged = chip;
      chip.classList.add("dragging");
      if (e.dataTransfer) { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", chip.getAttribute("data-key") || ""); }
      builder.querySelectorAll("[data-zone]").forEach(function (z) {
        z.classList.toggle("drop-ok", !!linkFor(chip, z.getAttribute("data-zone")));
      });
    });
    chip.addEventListener("dragend", function () {
      chip.classList.remove("dragging");
      dragged = null;
      builder.querySelectorAll(".drop-ok, .drop-over").forEach(function (z) { z.classList.remove("drop-ok"); z.classList.remove("drop-over"); });
    });
  });

  builder.querySelectorAll("[data-zone]").forEach(function (zone) {
    zone.addEventListener("dragover", function (e) {
      if (dragged && linkFor(dragged, zone.getAttribute("data-zone"))) { e.preventDefault(); zone.classList.add("drop-over"); }
    });
    zone.addEventListener("dragleave", function () { zone.classList.remove("drop-over"); });
    zone.addEventListener("drop", function (e) {
      e.preventDefault();
      zone.classList.remove("drop-over");
      var a = linkFor(dragged, zone.getAttribute("data-zone"));
      if (!a) {
        if (dragged && dragged.getAttribute("data-zone-of") !== zone.getAttribute("data-zone")) {
          toast(dragged.getAttribute("data-kind") === "measure" ? "A measure goes to Values." : "That cannot go there.", "error");
        }
        return;
      }
      window.location.assign(a.getAttribute("href"));
    });
  });
}
