// The "New" badge on Help > What's new (framework WHATS-NEW-1): shown after an update until the page is opened once.
// Invardia's renderer decides (shouldShowNewBadge: the newest shipped version against the last one opened in this browser);
// the server writes only the newest version on the badge. A browser that keeps nothing shows no badge.
import { shouldShowNewBadge } from "../lib/whatsnew/whats-new.js";

document.querySelectorAll("[data-whatsnew-badge]").forEach((badge) => {
  const newest = badge.getAttribute("data-whatsnew-newest");
  badge.hidden = !(newest && shouldShowNewBadge(newest, { product: badge.getAttribute("data-whatsnew-product") || "securityinsight" }));
});
