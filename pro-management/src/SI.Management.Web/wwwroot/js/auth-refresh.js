// Framework AUTH-MODERN-1: with Microsoft's built-in sign-in the web app checks the ID token's expiry strictly
// (Auth/BuiltInTokenVerifier.cs), so the page keeps the platform's token fresh itself through /.auth/refresh
// (offline_access is in the login parameters). Loaded once by the layout, ONLY when built-in sign-in is on, before every
// other script -- so every page and every script's fetch() has it:
//   * BEFORE expiry: /.auth/me tells the ID token's exp; less than 5 minutes left = refresh now, else a timer for then;
//   * ONCE on a 401: a same-origin fetch answered 401 refreshes once (one refresh in flight for all callers) and repeats
//     that fetch once; the refresh failing = one full navigation to the platform's sign-in -- at most once per 5 minutes
//     (never a loop), else the 401 is handed back as it came.
// It never adds or changes a request header: only the platform's own cookie goes out, so nothing that is not Entra's
// ever reaches the platform's token check (which would then drop its token headers).
(function () {
  "use strict";
  if (!window.fetch || window.__siAuthRefresh) return;
  // a magic-link session browses its own area with its own cookie (Auth/LinkArea.cs): nothing to refresh there
  if (location.pathname.toLowerCase().indexOf("/magiclink") === 0) return;
  window.__siAuthRefresh = true;

  var LEAD_MS = 5 * 60 * 1000;          // refresh when less than this is left
  var MIN_GAP_MS = 2 * 60 * 1000;       // never two proactive refreshes closer than this
  var RELOGIN_GAP_MS = 5 * 60 * 1000;   // never two sign-in navigations closer than this
  var RELOGIN_KEY = "si-auth-relogin-at";
  var origFetch = window.fetch;
  var inFlight = null;
  var lastProactive = 0;
  var timer = 0;

  function sameOrigin(input) {
    try {
      var u = typeof input === "string" ? input : (input && input.url) || String(input);
      return new URL(u, location.href).origin === location.origin;
    } catch (e) { return false; }
  }
  function isAuthPath(input) {
    try {
      var u = typeof input === "string" ? input : (input && input.url) || String(input);
      return new URL(u, location.href).pathname.toLowerCase().indexOf("/.auth/") === 0;
    } catch (e) { return false; }
  }

  // one refresh for every caller at a time; resolves true when the platform refreshed the session
  function refresh() {
    if (inFlight) return inFlight;
    inFlight = origFetch.call(window, "/.auth/refresh", { credentials: "same-origin", cache: "no-store", redirect: "manual" })
      .then(function (r) { return r.ok; }, function () { return false; })
      .then(function (ok) { inFlight = null; if (ok) schedule(); return ok; });
    return inFlight;
  }

  function relogin() {
    var last = 0;
    try { last = Number(sessionStorage.getItem(RELOGIN_KEY) || 0); } catch (e) { last = 0; }
    if (Date.now() - last < RELOGIN_GAP_MS) return false;   // already tried: no loop
    try { sessionStorage.setItem(RELOGIN_KEY, String(Date.now())); } catch (e) { /* storage off: still one per page */ }
    location.assign("/.auth/login/aad?post_login_redirect_uri=" + encodeURIComponent(location.pathname + location.search));
    return true;
  }

  // the ID token's exp (ms) from the platform's /.auth/me, or 0
  function readExpiry() {
    return origFetch.call(window, "/.auth/me", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        var e = Array.isArray(j) ? j[0] : null;
        if (!e) return 0;
        if (typeof e.id_token === "string") {
          var p = e.id_token.split(".")[1];
          if (p) {
            var claims = JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));
            if (claims && typeof claims.exp === "number") return claims.exp * 1000;
          }
        }
        var t = Date.parse(e.expires_on || "");
        return isNaN(t) ? 0 : t;
      })
      .catch(function () { return 0; });
  }

  function schedule() {
    if (timer) { clearTimeout(timer); timer = 0; }
    readExpiry().then(function (exp) {
      if (!exp) return;
      var wait = exp - LEAD_MS - Date.now();
      if (wait <= 0) {
        if (Date.now() - lastProactive < MIN_GAP_MS) return;   // the token did not move: the 401 path takes over
        lastProactive = Date.now();
        refresh();
        return;
      }
      timer = setTimeout(function () { lastProactive = Date.now(); refresh(); }, Math.min(wait, 2147483000));
    });
  }

  window.fetch = function (input, init) {
    var replay = (typeof Request !== "undefined" && input instanceof Request) ? input.clone() : null;
    var p = origFetch.call(this, input, init);
    if (!sameOrigin(input) || isAuthPath(input)) return p;
    var self = this;
    return p.then(function (r) {
      if (r.status !== 401) return r;
      // a streamed body cannot be sent twice: hand the 401 back as it came
      if (init && init.body && typeof ReadableStream !== "undefined" && init.body instanceof ReadableStream) return r;
      return refresh().then(function (ok) {
        if (!ok) { relogin(); return r; }
        return origFetch.call(self, replay || input, init);   // once: the repeat is not wrapped again
      });
    });
  };

  // a page that was opened again later (back/forward cache, a sleeping laptop): check the expiry again
  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") schedule(); });
  schedule();
})();
