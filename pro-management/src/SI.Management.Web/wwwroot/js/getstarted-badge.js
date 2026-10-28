// Get Started's red ! on the menu (Admins): shortly after a page has loaded, ask the server how many REQUIRED setup steps
// are still open (/Admin/GetStarted?handler=Badge -- computed from the install's data, cached there for a minute) and show
// the ! while any is. Nothing is stored in the browser: the ! is gone by itself once the steps are done.
(function () {
  'use strict';
  var DELAY_MS = 1500;
  function apply(badge, open) {
    if (open > 0) {
      badge.hidden = false;
      badge.title = open === 1 ? 'A required setup step is still open' : open + ' required setup steps are still open';
    } else {
      badge.hidden = true;
    }
  }
  function check() {
    var badge = document.querySelector('[data-getstarted-badge]');
    if (!badge || !window.fetch) return;
    fetch('/Admin/GetStarted?handler=Badge', { credentials: 'same-origin', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { if (j && typeof j.openRequired === 'number') apply(badge, j.openRequired); })
      .catch(function () { /* the badge is a hint: a failed check leaves it as it was */ });
  }
  function start() { window.setTimeout(check, DELAY_MS); }
  if (document.readyState === 'complete') start();
  else window.addEventListener('load', start);
})();
