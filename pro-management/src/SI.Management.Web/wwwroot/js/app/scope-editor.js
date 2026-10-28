// THE output scope editor's quick choices (Pages/Reports/_OutputScopeBody.cshtml, owner 2026-10-19): a button names a
// filter (data-scope-quick = the checkboxes' name) and its values (data-values, '|'-separated); a click ticks exactly
// those values of that filter in the same form and unticks the others -- nothing is staged until the form is sent.
export function initScopeQuick(root) {
  (root || document).querySelectorAll("[data-scope-quick]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var form = btn.closest("form");
      if (!form) { return; }
      var name = btn.getAttribute("data-scope-quick");
      var want = (btn.getAttribute("data-values") || "").split("|").map(function (v) { return v.toLowerCase(); });
      var boxes = Array.prototype.filter.call(form.querySelectorAll("input[type=checkbox]"), function (b) { return b.name === name; });
      boxes.forEach(function (b) {
        b.checked = want.indexOf(String(b.value).toLowerCase()) >= 0;
        b.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });
  });
}

// #817 (main 2026-10-20): a CMDB connector offers every asset kind, but a kind it cannot send yet never fails silently --
// ticking one of the kinds the card's hint names (data-scope-unsent-hint, '|'-separated, on the AssetKinds checkboxes)
// shows the hint; unticking all of them hides it.
export function initUnsentKinds(root) {
  (root || document).querySelectorAll("[data-scope-unsent-hint]").forEach(function (hint) {
    var form = hint.closest("section") && hint.closest("section").querySelector("form");
    if (!form) { return; }
    var kinds = (hint.getAttribute("data-scope-unsent-hint") || "").split("|");
    function sync() {
      hint.hidden = !Array.prototype.some.call(form.querySelectorAll("input[type=checkbox][name=AssetKinds]"), function (b) {
        return b.checked && kinds.indexOf(String(b.value).toLowerCase()) >= 0;
      });
    }
    form.addEventListener("change", sync);
    sync();
  });
}
