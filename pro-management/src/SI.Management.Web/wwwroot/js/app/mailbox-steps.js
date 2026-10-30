// #503: the shared mailbox in two steps -- step 1 builds the Set-SIMail.ps1 command from the fields as they are typed,
// and shows it only once the mailbox name is filled in. The SAME string as SharedMailboxSteps.Command (Settings/SharedMailboxSteps.cs).
var NAME = /^[A-Za-z0-9._-]{1,64}$/;
var DOMAIN = /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

// line 1 downloads the script from invardia.com, line 2 runs it -- nothing else in the block (owner 2026-10-11)
var DOWNLOAD = "Invoke-WebRequest https://invardia.com/support/si/Set-SIMail.ps1 -OutFile Set-SIMail.ps1";

function q(s) { return "'" + String(s).trim().replace(/'/g, "''") + "'"; }

export function buildCommand(name, domain, display, exists, sub, rg) {
  name = (name || "").trim();
  if (!NAME.test(name)) { return null; }
  var d = (domain || "").trim().replace(/^@/, "");
  var parts = ["./Set-SIMail.ps1", "-MailboxName " + q(name)];
  if (DOMAIN.test(d)) { parts.push("-MailDomain " + q(d)); }
  if ((display || "").trim()) { parts.push("-DisplayName " + q(display)); }
  if (exists) { parts.push("-CreateMailbox $false"); }
  if ((sub || "").trim() && (rg || "").trim()) { parts.push("-SubscriptionId " + q(sub)); parts.push("-ResourceGroup " + q(rg)); }
  parts.push("-UseSignedInAccount");
  parts.push("-Apply");
  return DOWNLOAD + "\n" + parts.join(" ");
}

// #633: the address the name and the domain make -- the SAME rule as SharedMailboxSteps.AddressOf; null until both are valid
export function buildAddress(name, domain) {
  name = (name || "").trim();
  var d = (domain || "").trim().replace(/^@/, "");
  return NAME.test(name) && DOMAIN.test(d) ? name + "@" + d : null;
}

export function initMailboxSteps(root) {
  root.querySelectorAll("[data-mailbox-step1]").forEach(function (form) {
    var block = form.querySelector("[data-mb-command-block]");
    var pre = form.querySelector("[data-mail-command]");
    var pick = form.querySelector("[data-mb-domain-pick]");
    var other = form.querySelector("[data-mb-domain-other]");
    // a listed domain, or "Another domain..." and the one typed (SharedMailboxSteps.OtherDomain)
    function domain() {
      var p = pick ? pick.value : "";
      if (other) { other.hidden = p !== "__other"; }
      return p === "__other" ? (other ? other.value : "") : p;
    }
    function update() {
      var exists = form.querySelector('[data-mb-exists]:checked');
      var cmd = buildCommand(
        (form.querySelector("[data-mb-name]") || {}).value,
        domain(),
        (form.querySelector("[data-mb-display]") || {}).value,
        !!(exists && exists.value === "true"),
        form.getAttribute("data-sub"), form.getAttribute("data-rg"));
      if (block) { block.hidden = cmd === null; }
      if (pre && cmd !== null) { pre.textContent = cmd; }
      var addr = buildAddress((form.querySelector("[data-mb-name]") || {}).value, domain());
      var line = form.querySelector("[data-mb-address-line]");
      var out = form.querySelector("[data-mb-address]");
      if (line) { line.hidden = addr === null; }
      if (out && addr !== null) { out.textContent = addr; }
    }
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  });
}
