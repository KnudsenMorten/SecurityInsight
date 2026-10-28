// #335: a department's PEOPLE TABLE (Admin > Departments, new and existing). The page works without this file (one
// blank row, Remove is a tick box); here: "+ Add person" adds a row, the person field suggests people as you type
// (the directory's users and groups, and people already on a department), and an e-mail address nobody knows opens
// the outside-person fields (name, company).

var MAIL = /^[^@\s;,<>"]+@[^@\s;,<>"]+\.[A-Za-z]{2,}$/;

export function initPeopleTable(root) {
  var tbody = root.querySelector("[data-people-rows] tbody");
  var tpl = root.querySelector("template[data-person-template]");
  var add = root.querySelector("[data-add-person]");
  var list = root.querySelector("datalist");
  var url = root.getAttribute("data-search-url") || "";
  var known = {};
  var timer = null;
  if (!tbody) { return; }

  function outside(row, input) {
    var box = row.querySelector("[data-person-outside]");
    if (!box) { return; }
    var v = input.value.trim().toLowerCase();
    box.hidden = !(MAIL.test(v) && !known[v]);
  }

  function search(row, input) {
    var q = input.value.trim();
    if (timer) { window.clearTimeout(timer); }
    if (q.length < 2 || !url || !list) { return; }
    timer = window.setTimeout(function () {
      fetch(url + (url.indexOf("?") >= 0 ? "&" : "?") + "q=" + encodeURIComponent(q), { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (items) {
          list.textContent = "";
          items.forEach(function (s) {
            known[String(s.value).toLowerCase()] = s;
            var o = document.createElement("option");
            o.value = s.value;
            o.label = s.label;
            o.textContent = s.label;
            list.appendChild(o);
          });
          outside(row, input);
        })
        .catch(function () { /* no suggestions: an e-mail address still works */ });
    }, 250);
  }

  function wire(row) {
    var remove = row.querySelector("[data-person-remove]");
    if (remove) { remove.addEventListener("change", function () { row.classList.toggle("removing", remove.checked); }); }
    var input = row.querySelector("[data-person-input]");
    if (!input) { return; }
    input.addEventListener("input", function () { outside(row, input); search(row, input); });
    input.addEventListener("change", function () { outside(row, input); });
  }

  tbody.querySelectorAll("[data-person-row]").forEach(wire);

  if (add && tpl) {
    add.hidden = false;
    add.addEventListener("click", function () {
      var i = tbody.querySelectorAll("[data-person-row]").length;
      tbody.insertAdjacentHTML("beforeend", tpl.innerHTML.replace(/__i__/g, String(i)));
      var row = tbody.lastElementChild;
      wire(row);
      var input = row.querySelector("[data-person-input]");
      if (input) { input.focus(); }
    });
  }
}
