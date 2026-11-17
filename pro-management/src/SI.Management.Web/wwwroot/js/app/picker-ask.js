// The people picker's "Search the tenant" (framework GRAPH-PICKER): a name the picker did not find in SecurityInsight's own
// names is asked of SecurityInsight's ENGINE (POST /Admin/DirectorySearch?handler=Ask -- the text and a reason; Admin; audited).
// The web app never reads the directory itself: the engine looks the name up and saves what it finds, and this block then
// polls the request (handler=Status, the asker's own request only) and says when the names are there. Works without this
// file: the object id field is always on the form.

export function initPickerAsk(root) {
  var url = root.getAttribute("data-ask-url") || "";
  var text = root.querySelector("[data-ask-text]");
  var reason = root.querySelector("[data-ask-reason]");
  var go = root.querySelector("[data-ask-go]");
  var state = root.querySelector("[data-ask-state]");
  if (!url || !text || !reason || !go || !state) { return; }
  var timer = null;

  function token() {
    var t = document.querySelector('input[name="__RequestVerificationToken"]');
    return t ? t.value : "";
  }

  function say(words) { state.textContent = words; }

  function poll(id, tries) {
    if (timer) { window.clearTimeout(timer); }
    if (tries <= 0) { say("Still waiting for SecurityInsight's engine -- type the name in the search box again in a few minutes."); return; }
    timer = window.setTimeout(function () {
      fetch(url + "?handler=Status&id=" + encodeURIComponent(id), { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : { state: "unknown" }; })
        .then(function (s) {
          if (!s || s.state === "waiting") { poll(id, tries - 1); return; }
          if (s.state === "done") { say("Done: " + (s.detail || "the names were saved") + ". Type the name in the search box above."); return; }
          say("Not found: " + (s.detail || s.state));
        })
        .catch(function () { poll(id, tries - 1); });
    }, 15000);
  }

  function ask() {
    var t = text.value.trim();
    var why = reason.value.trim();
    if (t.length < 2) { say("Type at least 2 characters of the name, sign-in name or mail."); text.focus(); return; }
    if (why.length < 3) { say("Give a reason -- it goes into the audit trail."); reason.focus(); return; }
    go.disabled = true;
    var body = new URLSearchParams();
    body.set("Text", t);
    body.set("Reason", why);
    body.set("__RequestVerificationToken", token());
    fetch(url + "?handler=Ask", { method: "POST", body: body, headers: { Accept: "application/json", RequestVerificationToken: token() }, credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : { ok: false, message: "Not asked (" + r.status + ")." }; })
      .then(function (a) {
        say(a && a.message ? a.message : "Not asked.");
        if (a && a.ok && a.id) { poll(a.id, 80); }
      })
      .catch(function () { say("Not asked: the page could not reach SecurityInsight."); })
      .then(function () { go.disabled = false; });
  }

  go.addEventListener("click", ask);
  // Enter in these fields asks -- it never submits the form they sit in
  [text, reason].forEach(function (box) {
    box.addEventListener("keydown", function (ev) { if (ev.key === "Enter") { ev.preventDefault(); ask(); } });
  });
}
