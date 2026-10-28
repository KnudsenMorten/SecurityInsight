// #284: a collection view (its grid) is read on the server, so opening one, sorting, filtering or paging is a page load
// that can take a while on a large collection. While it loads, the page says so -- never a silent nothing. If the read
// runs out of time, the server answers with the view and a clear message (what happened, what to narrow, a reference);
// this file only covers the wait in between. Downloads (Export) do not leave the page and show nothing here.

var SLOW_MS = 10000;

function isViewUrl(url) {
  return url.origin === window.location.origin && url.pathname.indexOf("/Collection/") === 0 && !url.searchParams.has("handler");
}

function banner() {
  var b = document.querySelector("[data-view-loading]");
  if (b) { return b; }
  b = document.createElement("div");
  b.className = "view-loading";
  b.setAttribute("data-view-loading", "");
  b.setAttribute("role", "status");
  b.setAttribute("aria-live", "polite");
  b.hidden = true;
  document.body.appendChild(b);
  return b;
}

var slowTimer = 0;

export function showViewLoading() {
  var b = banner();
  b.textContent = "Loading the view…";
  b.hidden = false;
  document.body.setAttribute("aria-busy", "true");
  window.clearTimeout(slowTimer);
  slowTimer = window.setTimeout(function () {
    b.textContent = "Still loading. A large collection can take up to a minute and a half; if it runs out of time, the page says so and what to narrow.";
  }, SLOW_MS);
}

export function hideViewLoading() {
  window.clearTimeout(slowTimer);
  var b = document.querySelector("[data-view-loading]");
  if (b) { b.hidden = true; }
  document.body.removeAttribute("aria-busy");
}

export function initViewLoading() {
  document.addEventListener("click", function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { return; }
    var a = e.target instanceof Element ? e.target.closest("a[href]") : null;
    if (!a || a.hasAttribute("download") || a.hasAttribute("data-export") || (a.target && a.target !== "_self")) { return; }
    var url;
    try { url = new URL(a.href, window.location.href); } catch (err) { return; }
    if (isViewUrl(url)) { showViewLoading(); }
  });
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement) || e.defaultPrevented) { return; }
    if ((form.getAttribute("method") || "get").toLowerCase() !== "get") { return; }
    var s = e.submitter;
    if (s && s.name === "handler") { return; }   // an export of the selection: a download, the page stays
    var url;
    try { url = new URL(form.getAttribute("action") || window.location.href, window.location.href); } catch (err) { return; }
    if (isViewUrl(url)) { showViewLoading(); }
  });
  // back / forward from the page cache: nothing is loading
  window.addEventListener("pageshow", hideViewLoading);
}
