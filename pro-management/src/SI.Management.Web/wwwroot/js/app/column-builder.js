// THE column builder of an output (Pages/Reports/_OutputFieldsBody.cshtml, owner 2026-10-19): the arrows move a column one
// place up or down and every place box is renumbered to the order shown, so what is posted is the order on the screen.
// Without this file the place boxes are typed by hand (the server orders by them).
function renumber(list) {
  Array.prototype.forEach.call(list.querySelectorAll("[data-builder-item]"), function (li, i) {
    var box = li.querySelector("[data-builder-place]");
    if (box) { box.value = String(i + 1); }
  });
}

export function initColumnBuilder(list) {
  list.addEventListener("click", function (e) {
    var t = e.target instanceof Element ? e.target.closest("[data-builder-up], [data-builder-down]") : null;
    if (!t) { return; }
    var li = t.closest("[data-builder-item]");
    if (!li) { return; }
    if (t.hasAttribute("data-builder-up") && li.previousElementSibling) { list.insertBefore(li, li.previousElementSibling); }
    else if (t.hasAttribute("data-builder-down") && li.nextElementSibling) { list.insertBefore(li.nextElementSibling, li); }
    renumber(list);
    t.focus();
  });
  // a typed place moves the column there when the box is left
  list.addEventListener("change", function (e) {
    var box = e.target instanceof HTMLInputElement && e.target.hasAttribute("data-builder-place") ? e.target : null;
    if (!box) { return; }
    var li = box.closest("[data-builder-item]");
    var items = Array.prototype.slice.call(list.querySelectorAll("[data-builder-item]"));
    var to = Math.max(1, Math.min(items.length, parseInt(box.value, 10) || 1)) - 1;
    items.splice(items.indexOf(li), 1);
    items.splice(to, 0, li);
    items.forEach(function (x) { list.appendChild(x); });
    renumber(list);
    box.focus();
  });
}
