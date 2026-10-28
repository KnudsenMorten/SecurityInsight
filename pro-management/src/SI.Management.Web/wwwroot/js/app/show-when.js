// #446: a field that belongs to one choice ("the SMTP relay's fields only with SMTP") carries data-show-when="Name=value"
// and shows only while that setting's choice -- a radio or a dropdown in the same form -- has that value. A settings card
// whose fields are all hidden is hidden with them. A choice not made yet (nothing picked) hides nothing. The fields
// keep posting their values, so a hidden field is never changed by a save.

export function initShowWhen(root) {
  function choice(name) {
    var r = root.querySelector('input[type=radio][name="v:' + name + '"]:checked');
    if (r) { return r.value; }
    var s = root.querySelector('select[name="v:' + name + '"]');
    return s && s.value !== "" ? s.value : null;
  }

  function apply() {
    root.querySelectorAll("[data-show-when]").forEach(function (el) {
      var rule = (el.getAttribute("data-show-when") || "").split("=");
      if (rule.length !== 2) { return; }
      var v = choice(rule[0]);
      if (v === null) { el.hidden = false; return; }
      el.hidden = v.toLowerCase() !== rule[1].toLowerCase();
    });
    root.querySelectorAll(".set-card").forEach(function (card) {
      var fields = card.querySelectorAll("[data-setting]");
      if (!fields.length || !card.querySelector("[data-show-when]")) { return; }
      card.hidden = Array.prototype.every.call(fields, function (x) { return x.hidden; });
    });
  }

  root.addEventListener("change", function (e) {
    var t = e.target;
    if (t && t.name && t.name.indexOf("v:") === 0) { apply(); }
  });
  apply();
}
