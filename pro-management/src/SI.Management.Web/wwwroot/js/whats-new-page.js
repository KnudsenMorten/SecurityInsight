// Help > What's new (framework WHATS-NEW-1): the release files that ship with this version (/WhatsNew?handler=Files), drawn
// by Invardia's ONE renderer (../lib/whatsnew/whats-new.js, unchanged). Opening the page marks the newest version as seen,
// so the menu's "New" badge goes away.
import { renderWhatsNew } from "../lib/whatsnew/whats-new.js";

const host = document.querySelector("[data-whatsnew]");
if (host) {
  const opts = { productName: host.dataset.whatsnewName || "SecurityInsight", product: host.dataset.whatsnewProduct || "securityinsight", heading: false, markSeen: true };
  fetch(host.dataset.whatsnewSrc, { credentials: "same-origin", headers: { Accept: "application/json" } })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
    .then((files) => {
      renderWhatsNew(host, Array.isArray(files) ? files : [], opts);
      document.querySelectorAll("[data-whatsnew-badge]").forEach((b) => { b.hidden = true; });
    })
    .catch(() => {
      host.innerHTML = "";
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "What's new could not be loaded. Reload the page to try again.";
      host.appendChild(p);
    });
}
