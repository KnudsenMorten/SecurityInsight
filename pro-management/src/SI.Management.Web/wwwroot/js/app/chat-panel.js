// The chat panel beside a Security posture / Management page. It posts the question, the panel's conversation and the
// page's context (structured JSON from the data-chat-context attribute, plus the asset selected right now) to
// /Chat?handler=Ask, and renders the answer bubble exactly like the Chat page (Pages/Shared/_ChatAnswer.cshtml):
//  - the answer: the server's rendering (ChatAnswerRenderer: escaped text + whitelisted markup + highlights in the
//    viewer's number format), copied in through a second whitelist here (p, br, ul, li, strong, code, span, and a link
//    only to an asset page) -- never assigned as innerHTML, so a tampered response still cannot run anything;
//  - the tool calls, as TEXT: collapsed under the answer when SIWeb_Chat_ShowToolCalls is on, else on demand behind
//    "How was this answered?".

var MAX_TURNS = 20;
var ALLOWED = { P: 1, BR: 1, UL: 1, LI: 1, STRONG: 1, CODE: 1, SPAN: 1, A: 1 };
var DROPPED = { SCRIPT: 1, STYLE: 1, TEMPLATE: 1, IFRAME: 1, OBJECT: 1, EMBED: 1, SVG: 1, MATH: 1 };

function copySafe(src, dst) {
  Array.prototype.forEach.call(src.childNodes, function (n) {
    if (n.nodeType === 3) { dst.appendChild(document.createTextNode(n.nodeValue)); return; }
    if (n.nodeType !== 1 || DROPPED[n.tagName]) { return; }
    if (!ALLOWED[n.tagName]) { copySafe(n, dst); return; }      // an unknown element: its text only
    var e = document.createElement(n.tagName.toLowerCase());
    var cls = n.getAttribute("class");
    if (cls) { e.className = cls; }
    if (n.tagName === "A") {
      var href = n.getAttribute("href") || "";
      if (href.indexOf("/Collection/Asset?") === 0) { e.setAttribute("href", href); }
    }
    copySafe(n, e);
    dst.appendChild(e);
  });
}

function answerBody(html) {
  var body = el("div", "text chat-answer-body");
  // DOMParser builds an inert document: nothing in it runs or loads
  var doc = new DOMParser().parseFromString("<body>" + (html || "") + "</body>", "text/html");
  copySafe(doc.body, body);
  return body;
}

function toolList(into, calls) {
  calls.forEach(function (c) {
    var t = el("div", "tool");
    var head = el("div");
    head.appendChild(el("strong", "tool-name", c.tool));
    head.appendChild(document.createTextNode(" "));
    head.appendChild(el("span", "badge", c.source));
    t.appendChild(head);
    var a = el("p", "meta", "Arguments: ");
    a.appendChild(el("code", null, c.argumentsJson));
    t.appendChild(a);
    var pre = el("pre");
    pre.appendChild(el("code", null, c.query));
    t.appendChild(pre);
    into.appendChild(t);
  });
}

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) { e.className = cls; }
  if (text !== undefined && text !== null) { e.textContent = text; }
  return e;
}

function pageContext(panel) {
  var ctx = {};
  try { ctx = JSON.parse(panel.getAttribute("data-chat-context") || "{}"); } catch (e) { ctx = {}; }
  // the selection can change without a reload (the tier board selects in place)
  var url = new URLSearchParams(window.location.search);
  if (url.get("asset")) { ctx.selectedAsset = url.get("asset"); }
  var card = document.querySelector('[data-asset][aria-selected="true"]');
  if (card && card.getAttribute("data-asset")) { ctx.selectedAsset = card.getAttribute("data-asset"); }
  // the tier board: the asset whose details are open -- the drawer beside the table, or the panel on the page
  var open = document.querySelector('aside[data-drawer]:not([hidden]) [data-tier-panel], [data-tier-panel-plain] [data-tier-panel]');
  if (open && open.getAttribute("data-tier-panel")) { ctx.selectedAsset = open.getAttribute("data-tier-panel"); }
  return ctx;
}

function renderAnswer(log, answer) {
  var calls = answer.toolCalls || [];
  var m = el("div", "msg assistant chat-answer");
  m.setAttribute("data-chat-answer", "");
  m.setAttribute("data-tool-calls", calls.length === 0 ? "none" : answer.showToolCalls ? "shown" : "on-demand");
  var who = el("div", "who");
  var icon = el("img", "chat-icon");
  icon.setAttribute("src", "/brand/invardia-icon.svg");
  icon.setAttribute("alt", "");
  icon.setAttribute("width", "16");
  icon.setAttribute("height", "16");
  who.appendChild(icon);
  who.appendChild(document.createTextNode(" SecurityInsight"));
  m.appendChild(who);
  if (typeof answer.html === "string") { m.appendChild(answerBody(answer.html)); }
  else { m.appendChild(el("div", "text chat-answer-body", answer.text || "")); }
  var basis = answer.basis || "";
  if (calls.length === 0) {
    m.appendChild(el("p", "hint chat-basis", basis || "No estate data was queried for this answer."));
  } else if (answer.showToolCalls) {
    m.appendChild(el("p", "hint chat-basis", basis));
    var d = el("details", "query tool-calls");
    d.appendChild(el("summary", null, calls.length + " tool call" + (calls.length === 1 ? "" : "s") + " behind this answer"));
    toolList(d, calls);
    m.appendChild(d);
  } else {
    var how = el("details", "chat-how");
    how.appendChild(el("summary", null, "How was this answered?"));
    how.appendChild(el("p", "hint chat-basis", basis));
    toolList(how, calls);
    m.appendChild(how);
  }
  log.appendChild(m);
}

export function initChatPanel(panel) {
  var open = document.querySelector("[data-chat-open]");
  var close = panel.querySelector("[data-chat-close]");
  var form = panel.querySelector("[data-chat-form]");
  var log = panel.querySelector("[data-chat-log]");
  var box = form.querySelector("textarea");
  var ask = form.querySelector("[data-chat-ask]");
  var history = [];

  function show(on) {
    panel.hidden = !on;
    document.body.classList.toggle("chat-panel-open", on);
    if (open) { open.setAttribute("aria-expanded", on ? "true" : "false"); }
    if (on) { box.focus(); } else if (open) { open.focus(); }
  }
  if (open) { open.addEventListener("click", function () { show(panel.hidden); }); }
  close.addEventListener("click", function () { show(false); });
  panel.addEventListener("keydown", function (e) { if (e.key === "Escape") { show(false); } });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var q = box.value.trim();
    if (!q) { box.focus(); return; }
    var token = form.querySelector('input[name="__RequestVerificationToken"]');
    var mine = el("div", "msg user");
    mine.appendChild(el("div", "who", "You"));
    mine.appendChild(el("div", "text", q));
    log.appendChild(mine);
    var wait = el("p", "hint", "Looking it up...");
    wait.setAttribute("data-chat-wait", "");
    log.appendChild(wait);
    ask.disabled = true;
    fetch("/Chat?handler=Ask", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json", RequestVerificationToken: token ? token.value : "" },
      body: JSON.stringify({ question: q, history: history, context: pageContext(panel) })
    }).then(function (r) {
      if (!r.ok) { throw new Error("HTTP " + r.status); }
      return r.json();
    }).then(function (answer) {
      wait.remove();
      if (answer.error) {
        var err = el("div", "notice error", answer.error);
        err.setAttribute("role", "alert");
        log.appendChild(err);
        return;
      }
      renderAnswer(log, answer);
      history.push({ role: "user", content: q }, { role: "assistant", content: answer.text || "" });
      if (history.length > MAX_TURNS) { history = history.slice(history.length - MAX_TURNS); }
      box.value = "";
    }).catch(function () {
      wait.remove();
      var err = el("div", "notice error", "The question could not be sent. Reload the page and try again.");
      err.setAttribute("role", "alert");
      log.appendChild(err);
    }).finally(function () {
      ask.disabled = false;
      log.scrollTop = log.scrollHeight;
    });
  });
}

var panel = document.querySelector("[data-chat-panel]");
if (panel) { initChatPanel(panel); }
