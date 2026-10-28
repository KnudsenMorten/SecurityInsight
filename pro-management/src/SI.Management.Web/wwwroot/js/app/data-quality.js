// Operations > Data quality: "Re-run from here" on a warning answers IN PLACE -- the page does not reload and the
// viewport stays where it is; the answer (queued, already waiting, or why not) is a toast. The form asks first through
// the shared confirm dialog (ui.js); once confirmed, the same form fields (the step and the antiforgery token) are
// posted here. Without this file the form posts normally and the page comes back with the same words.
import { toast } from "./ui.js";

export function initDataQuality(root) {
  (root || document).querySelectorAll("form[data-dq-rerun]").forEach(function (form) {
    if (form.getAttribute("data-dq-ready") === "1") { return; }
    form.setAttribute("data-dq-ready", "1");
    form.addEventListener("submit", function (e) {
      // not confirmed yet: the shared confirm dialog takes this submit and sends it again once the person said yes
      if (form.hasAttribute("data-confirm") && form.dataset.confirmed !== "1") { return; }
      e.preventDefault();
      var button = form.querySelector("button[type=submit]");
      if (button) { button.disabled = true; }
      fetch(form.getAttribute("action"), { method: "POST", body: new FormData(form), headers: { "Accept": "application/json" }, credentials: "same-origin" })
        .then(function (r) {
          if (r.status === 403) { throw new Error("re-running the pipeline needs the Admin role"); }
          if (!r.ok) { throw new Error("the server answered " + r.status); }
          return r.json();
        })
        .then(function (res) { toast(res.message || "Done.", res.kind || (res.ok ? "ok" : "error")); })
        .catch(function (err) { toast("Re-run from here failed -- " + err.message, "error"); })
        .finally(function () { if (button) { button.disabled = false; } });
    });
  });
}
