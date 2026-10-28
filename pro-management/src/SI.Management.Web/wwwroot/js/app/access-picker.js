// #446: Admin > Access -- find the person or group BY NAME. Typing searches the directory (users and groups whose name,
// mail or sign-in name starts with the text); picking one fills the object id, the type and the name of the form. The
// page works without this file: the object id field is always there.

export function initAccessPicker(root) {
  var input = root.querySelector("[data-picker-input]");
  var list = root.querySelector("[data-picker-list]");
  var chosen = root.querySelector("[data-picker-chosen]");
  var form = root.closest("form");
  var url = root.getAttribute("data-search-url") || "";
  if (!input || !list || !form || !url) { return; }
  var idBox = form.querySelector("[name=PrincipalId]");
  var typeBox = form.querySelector("[name=PrincipalType]");
  var nameBox = form.querySelector("[name=DisplayName]");
  var mailBox = form.querySelector("[name=AccountMail]");
  var items = [];
  var active = -1;
  var timer = null;
  var seq = 0;

  function close() { list.hidden = true; input.setAttribute("aria-expanded", "false"); input.removeAttribute("aria-activedescendant"); active = -1; }

  function mark(i) {
    var opts = list.querySelectorAll("[role=option]");
    opts.forEach(function (o, n) { o.setAttribute("aria-selected", n === i ? "true" : "false"); });
    active = i;
    if (i >= 0 && opts[i]) { input.setAttribute("aria-activedescendant", opts[i].id); opts[i].scrollIntoView({ block: "nearest" }); }
  }

  function pick(p) {
    if (idBox) { idBox.value = p.id; }
    if (typeBox) { typeBox.value = p.type; }
    if (nameBox) { nameBox.value = p.name; }
    if (mailBox) { mailBox.value = p.mail || ""; }
    if (typeBox) { typeBox.dispatchEvent(new Event("change", { bubbles: true })); }
    input.value = p.name;
    if (chosen) { chosen.hidden = false; chosen.textContent = (p.type === "Group" ? "Group" : p.guest ? "Guest" : "Person") + ": " + p.name + (p.mail ? " (" + p.mail + ")" : "") + " -- object id " + p.id; }
    close();
  }

  function render(found) {
    items = found;
    list.textContent = "";
    if (!found.length) {
      var none = document.createElement("li");
      none.className = "picker-none";
      none.textContent = "No person or group found";
      list.appendChild(none);
    }
    found.forEach(function (p, i) {
      var li = document.createElement("li");
      li.id = "a-find-opt-" + i;
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", "false");
      var b = document.createElement("strong"); b.textContent = p.name; li.appendChild(b);
      var s = document.createElement("span"); s.className = "picker-meta"; s.textContent = (p.type === "Group" ? "group" : p.guest ? "guest" : "person") + (p.mail ? " · " + p.mail : ""); li.appendChild(s);
      li.addEventListener("mousedown", function (ev) { ev.preventDefault(); pick(p); });
      list.appendChild(li);
    });
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
    active = -1;
  }

  input.addEventListener("input", function () {
    var q = input.value.trim();
    if (timer) { window.clearTimeout(timer); }
    if (q.length < 2) { close(); return; }
    timer = window.setTimeout(function () {
      var mine = ++seq;
      fetch(url + "&q=" + encodeURIComponent(q), { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (found) { if (mine === seq) { render(found || []); } })
        .catch(function () { if (mine === seq) { render([]); } });
    }, 250);
  });

  input.addEventListener("keydown", function (ev) {
    if (list.hidden) { return; }
    if (ev.key === "ArrowDown") { ev.preventDefault(); mark(Math.min(items.length - 1, active + 1)); }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); mark(Math.max(0, active - 1)); }
    else if (ev.key === "Enter") { if (active >= 0 && items[active]) { ev.preventDefault(); pick(items[active]); } }
    else if (ev.key === "Escape") { close(); }
  });

  input.addEventListener("blur", function () { window.setTimeout(close, 150); });
}

// #765: the Access form -- the scope only while the role is Delegated, the mail forward only for a person; after a save
// the saved row of the table is scrolled into view (it is highlighted by the page).
export function initAccessForm(form) {
  var role = form.querySelector("[data-access-role]");
  var type = form.querySelector("[data-access-type]");
  var scope = form.querySelector("[data-access-scope]");
  var fwd = form.querySelector("[data-access-forward]");
  function apply() {
    if (role && scope) { scope.hidden = role.value !== "Delegated"; }
    if (type && fwd) { fwd.hidden = type.value === "Group"; }
  }
  if (role) { role.addEventListener("change", apply); }
  if (type) { type.addEventListener("change", apply); }
  apply();
  var saved = document.querySelector("tr[data-saved=true]");
  if (saved) { saved.scrollIntoView({ block: "center" }); }
}