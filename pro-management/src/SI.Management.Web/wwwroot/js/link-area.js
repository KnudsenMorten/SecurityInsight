// CR7 Option A: a link session behind the shared sign-in front browses under /MagicLink/s/ (Auth/LinkArea.cs). The server
// keeps the page's links inside it; this keeps the scripts' own requests (fetch, XHR) inside it too. Outside the area: nothing.
(function () {
  "use strict";
  var P = "/MagicLink/s";
  if (location.pathname.toLowerCase().indexOf(P.toLowerCase() + "/") !== 0) return;
  function fix(u) {
    if (typeof u !== "string" || u.charAt(0) !== "/" || u.charAt(1) === "/" || u.charAt(1) === "\\") return u;
    if (u.toLowerCase().indexOf("/magiclink") === 0) return u;
    return P + u;
  }
  if (window.fetch) {
    var f = window.fetch;
    window.fetch = function (input, init) { return f.call(this, typeof input === "string" ? fix(input) : input, init); };
  }
  if (window.XMLHttpRequest) {
    var open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      var a = Array.prototype.slice.call(arguments);
      a[1] = fix(url);
      return open.apply(this, a);
    };
  }
})();
