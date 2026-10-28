// ONE number formatter for the browser (BRAND-2.6): the locale the server wrote the page in (<html
// data-number-locale>, from the viewer's Number format choice), through Intl.NumberFormat. Every number a script
// writes into the page -- counts in toasts and badges, chart axes and tooltips, the table row counts -- goes through
// formatNumber; nothing uses String(n) or toString() for a number a person reads. Dates stay ISO.

export function numberLocale() {
  var l = document.documentElement.getAttribute("data-number-locale");
  return l && l.length ? l : "en-US";
}

var cache = {};
function nf(locale, decimals) {
  var k = locale + "|" + decimals;
  if (!cache[k]) {
    cache[k] = new Intl.NumberFormat(locale, decimals === undefined
      ? { maximumFractionDigits: 1 }
      : { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
  }
  return cache[k];
}

export function formatNumber(n, decimals) {
  if (n === null || n === undefined || !isFinite(n)) { return "–"; }
  return nf(numberLocale(), decimals).format(n);
}

// The group and decimal separators of a locale ("." and "," for da-DK; a no-break space and "," for sv-SE).
export function separators(locale) {
  var parts = new Intl.NumberFormat(locale).formatToParts(12345.6);
  var g = parts.filter(function (p) { return p.type === "group"; })[0];
  var d = parts.filter(function (p) { return p.type === "decimal"; })[0];
  return { group: g ? g.value : ",", decimal: d ? d.value : "." };
}

// A number as the page wrote it, read back in the same locale: "2.254" (da-DK) = 2254, "1 234,5" (sv-SE) = 1234.5,
// "+12" = 12, "45 %" = 45, "12 min" = 12. Null when the text is not a number.
export function parseLocaleNumber(text, locale) {
  if (text === null || text === undefined) { return null; }
  var t = String(text).trim();
  if (!t) { return null; }
  var sep = separators(locale || numberLocale());
  var m = /^([+\-−]?)([0-9.,\s  ']+)\s*(%|[A-Za-zÀ-ɏ]{1,12})?$/.exec(t);
  if (!m) { return null; }
  var body = m[2].trim();
  // a space-like group separator (sv-SE, nb-NO): any space between digits is grouping
  if (sep.group.trim() === "") { body = body.replace(/[\s  ]/g, ""); }
  body = body.split(sep.group).join("");
  if (sep.decimal !== ".") { if (body.indexOf(".") >= 0) { return null; } body = body.split(sep.decimal).join("."); }
  else if (body.indexOf(",") >= 0) { return null; }
  body = body.replace(/\s/g, "");
  if (!/^\d*\.?\d+$|^\d+\.?$/.test(body)) { return null; }
  var n = Number(body);
  if (!isFinite(n)) { return null; }
  return m[1] === "-" || m[1] === "−" ? -n : n;
}

// for the classic scripts (site.js charts): the same formatter on window
window.SINumber = { locale: numberLocale, format: formatNumber, parse: parseLocaleNumber };
