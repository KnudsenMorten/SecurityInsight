using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using SIAnalyzer.Core.Governance;

namespace SIAnalyzer.Web.Rendering;

/// <summary>
/// Renders the governance surface (Phase 6) - the exemption register + audit trail + the
/// risk-accept comments, PLUS the platform-exemption-sync controls rendered VISIBLE but
/// DIMMED/disabled with a "disabled until tested" note whenever the platform-sync capability
/// is locked off. The no-auto-revoke rule means the build never ships an enable-able platform
/// write: the toggle is shown (so the operator can see it exists) but cannot be switched on.
/// PIM-blue chrome (same theme as the exec surface) so it reads as a sibling of the Manager.
/// </summary>
public static class GovernanceRenderer
{
    /// <param name="nonce">Per-request CSP nonce (audit #13).</param>
    public static string Render(GovernanceStore store, string? nonce = null)
    {
        var caps = store.Capabilities;
        var h = HtmlEncoder.Default;
        var sb = new StringBuilder();

        sb.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurityInsight Analyzer - Governance</title>
""");
        // Reuse the exec theme + chrome for a consistent PIM-blue sibling look.
        sb.Append("<style>").Append(ExecHtmlRenderer.ThemeCss).Append(GovCss).Append("</style>");
        sb.Append("</head><body>");
        sb.Append(ExecHtmlRenderer.NavChrome("governance", standalone: false));
        sb.Append("<main class=\"wrap\" role=\"main\">");

        sb.Append("<h1 class=\"headline\">Governance &amp; exemptions</h1>");
        sb.Append("<div class=\"banner\" role=\"note\">The only place SIA can write. Everything else stays strictly read-only. ")
          .Append(caps.LocalRegisterEnabled
              ? "The local register accepts risk-accept comments and exemptions (SIA's own store; no platform is written)."
              : "The register is currently read-only (recording is off).")
          .Append("</div>");

        // --- Where the register LIVES (audit #7) -------------------------------------------
        // A volatile list must never be presented as a register of record. When storage is not
        // durable the page says so, in the same words the API does.
        sb.Append(store.StorageIsDurable
            ? "<p class=\"gov-store gov-store-ok\" role=\"status\"><strong>Durable register.</strong> Records are kept in "
            : "<p class=\"gov-store gov-store-warn\" role=\"status\"><strong>NOT a register of record.</strong> Records are kept ");
        sb.Append(h.Encode(store.StorageDescription));
        sb.Append(store.StorageIsDurable
            ? ", so they survive a restart, a redeploy and a second replica.</p>"
            : ", so they are LOST on restart or redeploy and are not shared between replicas. Set <code>SIAnalyzer:Governance:TableEndpoint</code> to make the register durable.</p>");

        // --- The GATED platform-sync control: visible, dimmed, disabled-until-tested ---
        var locked = !caps.PlatformSyncEnabled;
        sb.Append("<section class=\"card gov-sync").Append(locked ? " gov-disabled" : "").Append("\" aria-label=\"Platform exemption sync\">");
        sb.Append("<div class=\"gov-sync-head\"><h2>Sync exemptions to the security platforms</h2>");
        // The toggle is rendered but disabled while locked - it cannot be switched on.
        sb.Append("<label class=\"gov-toggle\" title=\"").Append(h.Encode(caps.PlatformSyncDisabledReason)).Append("\">")
          .Append("<input type=\"checkbox\" disabled")
          .Append(caps.PlatformSyncEnabled ? " checked" : "")
          .Append(" aria-describedby=\"gov-sync-note\">")
          .Append("<span class=\"gov-toggle-track\" aria-hidden=\"true\"></span>")
          .Append("<span class=\"gov-toggle-label\">").Append(caps.PlatformSyncEnabled ? "On" : "Off").Append("</span></label>");
        sb.Append("</div>");
        sb.Append("<p class=\"gov-targets\">Targets: Microsoft Defender for Cloud &middot; Azure Policy &middot; Microsoft Defender XDR. ")
          .Append("Syncing an exemption SUPPRESSES the finding on the platform - a write that removes a finding, so it is gated.</p>");
        if (locked)
        {
            sb.Append("<p id=\"gov-sync-note\" class=\"gov-note\" role=\"status\">")
              .Append("<span class=\"gov-badge-off\">Disabled until tested</span> ")
              .Append(h.Encode(caps.PlatformSyncDisabledReason))
              .Append("</p>");
            // Disabled action buttons so the surface is complete but inert.
            sb.Append("<div class=\"gov-actions\">")
              .Append("<button class=\"btn\" disabled aria-disabled=\"true\">Sync to Defender for Cloud</button> ")
              .Append("<button class=\"btn\" disabled aria-disabled=\"true\">Sync to Azure Policy</button> ")
              .Append("<button class=\"btn\" disabled aria-disabled=\"true\">Sync to Defender XDR</button>")
              .Append("</div>");
        }
        sb.Append("</section>");

        // --- Record a governance decision (audit #7/#8: the write path had no UI at all) ------
        // Both endpoints existed from the start; nothing in the app ever called them, so the
        // register could only ever be empty. These two forms are that missing half.
        sb.Append("<section class=\"card\" aria-label=\"Record a governance decision\">");
        sb.Append("<h2>Record a decision</h2>");
        if (!caps.LocalRegisterEnabled)
        {
            sb.Append("<p class=\"gov-note\" role=\"status\">Recording is off (<code>SIAnalyzer:Governance:LocalRegisterEnabled</code>). ")
              .Append("The register is read-only on this deployment.</p>");
        }
        var dis = caps.LocalRegisterEnabled ? "" : " disabled";
        sb.Append("<p class=\"muted\">A risk-acceptance says \"we know, and we accept it\" - the finding stays visible and keeps counting toward the score, marked with who accepted it and why. An exemption is scoped and MUST expire.</p>");

        sb.Append("<div class=\"gov-forms\">");

        // AUDIT #13: onsubmit="return recordAccept(event)" -> a submit listener bound in GovJs.
        sb.Append("<form class=\"gov-form\" id=\"racForm\">");
        sb.Append("<h3>Risk-accept a finding</h3>");
        sb.Append("<label for=\"racId\">Finding id <span class=\"muted\">(ConfigurationId)</span></label>")
          .Append("<input id=\"racId\" required").Append(dis).Append(">");
        sb.Append("<label for=\"racName\">Asset name</label><input id=\"racName\"").Append(dis).Append(">");
        sb.Append("<label for=\"racWhy\">Justification <span class=\"muted\">(required)</span></label>")
          .Append("<textarea id=\"racWhy\" required").Append(dis).Append("></textarea>");
        sb.Append("<label for=\"racExp\">Expires <span class=\"muted\">(optional - blank never lapses)</span></label>")
          .Append("<input id=\"racExp\" type=\"date\"").Append(dis).Append(">");
        sb.Append("<button class=\"btn\" type=\"submit\"").Append(dis).Append(">Record risk-acceptance</button>");
        sb.Append("<p class=\"gov-out\" id=\"racOut\" role=\"status\"></p>");
        sb.Append("</form>");

        sb.Append("<form class=\"gov-form\" id=\"exmForm\">");
        sb.Append("<h3>Record an exemption</h3>");
        sb.Append("<label for=\"exmId\">Finding id <span class=\"muted\">(ConfigurationId)</span></label>")
          .Append("<input id=\"exmId\" required").Append(dis).Append(">");
        sb.Append("<label for=\"exmName\">Asset name</label><input id=\"exmName\"").Append(dis).Append(">");
        sb.Append("<label for=\"exmScope\">Scope</label><input id=\"exmScope\" placeholder=\"e.g. subscription, resource group, asset\"").Append(dis).Append(">");
        sb.Append("<label for=\"exmWhy\">Reason <span class=\"muted\">(required)</span></label>")
          .Append("<textarea id=\"exmWhy\" required").Append(dis).Append("></textarea>");
        sb.Append("<label for=\"exmExp\">Expires <span class=\"muted\">(required - a future date)</span></label>")
          .Append("<input id=\"exmExp\" type=\"date\" required").Append(dis).Append(">");
        sb.Append("<p class=\"muted\">Platform sync stays off: the exemption is recorded in SIA only and nothing is suppressed on any security platform.</p>");
        sb.Append("<button class=\"btn\" type=\"submit\"").Append(dis).Append(">Record exemption</button>");
        sb.Append("<p class=\"gov-out\" id=\"exmOut\" role=\"status\"></p>");
        sb.Append("</form>");

        sb.Append("</div></section>");

        // --- Exemption register ---
        sb.Append("<section class=\"card\" aria-label=\"Exemption register\">");
        sb.Append("<h2>Exemption register</h2>");
        var exemptions = store.Exemptions;
        if (exemptions.Count == 0)
        {
            sb.Append("<p class=\"muted\">No exemptions recorded.</p>");
        }
        else
        {
            sb.Append("<div class=\"tbl-wrap\"><table class=\"qw\"><thead><tr><th>Asset</th><th>Scope</th><th>Owner</th><th>Reason</th><th>Expires</th><th>State</th><th>Platform</th><th>Renew</th></tr></thead><tbody>");
            foreach (var e in exemptions)
            {
                // An exemption past its expiry is DEAD even if the hourly sweep has not flipped
                // its state yet - so the row says so from the date, not from the stored state.
                var lapsed = e.State == GovernanceState.Expired || e.ExpiryUtc <= DateTimeOffset.UtcNow;
                sb.Append("<tr><td>").Append(h.Encode(e.ConfigurationName)).Append("</td>")
                  .Append("<td>").Append(h.Encode(e.Scope)).Append("</td>")
                  .Append("<td>").Append(h.Encode(e.Owner)).Append("</td>")
                  .Append("<td>").Append(h.Encode(e.Reason)).Append("</td>")
                  .Append("<td>").Append(e.ExpiryUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)).Append("</td>")
                  .Append("<td>").Append(lapsed ? "<span class=\"gov-badge-off\">Expired</span>" : h.Encode(e.State.ToString())).Append("</td>")
                  .Append("<td>").Append(e.Synced ? "synced" : "<span class=\"muted\">not synced</span>").Append("</td>")
                  // AUDIT #13 + the #19 class of defect: this was onclick="renew('<id>')" -- the id
                  // HTML-encoded but dropped raw into a JS STRING LITERAL. Now a data attribute read
                  // by a delegated listener, so the id is never parsed as code.
                  .Append("<td><button type=\"button\" class=\"btn btn-sm\" data-renew=\"").Append(h.Encode(e.Id)).Append("\"")
                  .Append(caps.LocalRegisterEnabled ? "" : " disabled").Append(">Renew 90d</button></td></tr>");
            }
            sb.Append("</tbody></table></div>");
            sb.Append("<p class=\"gov-out\" id=\"renewOut\" role=\"status\"></p>");
        }
        sb.Append("</section>");

        // --- Risk-accept comments (display is always a read concern) ---
        sb.Append("<section class=\"card\" aria-label=\"Risk-accepted findings\">");
        sb.Append("<h2>Risk-accepted findings</h2>");
        var comments = store.Comments;
        if (comments.Count == 0)
        {
            sb.Append("<p class=\"muted\">No findings have been risk-accepted.</p>");
        }
        else
        {
            sb.Append("<ul class=\"rlist\">");
            foreach (var c in comments)
            {
                var lapsed = c.State == GovernanceState.Expired
                             || (c.ExpiryUtc is { } ex && ex <= DateTimeOffset.UtcNow);
                sb.Append("<li><div class=\"rl-top\"><span class=\"rl-name\">").Append(h.Encode(c.ConfigurationName))
                  .Append("</span><span class=\"muted\">").Append(h.Encode(c.Owner)).Append("</span></div>")
                  .Append("<div class=\"rl-why\">").Append(h.Encode(c.Justification)).Append("</div>")
                  .Append("<div class=\"muted\">")
                  .Append(lapsed
                      ? "<span class=\"gov-badge-off\">Expired</span> no longer marks the finding as accepted"
                      : c.ExpiryUtc is { } until
                          ? "Accepted until " + until.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
                          : "No expiry set - this acceptance does not lapse")
                  .Append("</div></li>");
            }
            sb.Append("</ul>");
        }
        sb.Append("</section>");

        // --- Audit trail ---
        sb.Append("<section class=\"card\" aria-label=\"Audit trail\">");
        sb.Append("<h2>Audit trail</h2>");
        var audit = store.Audit;
        if (audit.Count == 0)
        {
            sb.Append("<p class=\"muted\">No governance actions yet.</p>");
        }
        else
        {
            sb.Append("<div class=\"tbl-wrap\"><table class=\"qw\"><thead><tr><th>When (UTC)</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>");
            foreach (var a in audit)
            {
                sb.Append("<tr><td>").Append(a.TimestampUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)).Append("</td>")
                  .Append("<td>").Append(h.Encode(a.Actor)).Append("</td>")
                  .Append("<td>").Append(h.Encode(a.Action)).Append("</td>")
                  .Append("<td>").Append(h.Encode(a.Detail)).Append("</td></tr>");
            }
            sb.Append("</tbody></table></div>");
        }
        sb.Append("</section>");

        sb.Append("</main>");
        sb.Append(ExecHtmlRenderer.ScriptTag(GovJs, nonce));
        sb.Append("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// The write half of the page. Posts to the same three endpoints the API exposes, then
    /// reloads so the register, the audit trail and the expiry states all re-render from the
    /// store rather than from a client-side guess about what was written.
    /// </summary>
    private const string GovJs = """
function govVal(id){var e=document.getElementById(id);return e?e.value.trim():'';}
function govSay(id,text,ok){var e=document.getElementById(id);if(!e)return;e.textContent=text;e.className='gov-out '+(ok?'gov-ok':'gov-bad');}
async function govPost(url,body){
  var r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.status===401){return {accepted:false,detail:'Not signed in - the governance write path requires an authenticated user.'};}
  try{return await r.json();}catch(e){return {accepted:false,detail:'Unexpected response ('+r.status+').'};}
}
async function recordAccept(ev){
  ev.preventDefault();
  var body={findingId:govVal('racId'),configurationName:govVal('racName')||govVal('racId'),justification:govVal('racWhy')};
  var exp=govVal('racExp'); if(exp){body.expiry=new Date(exp+'T00:00:00Z').toISOString();}
  govSay('racOut','Recording...',true);
  var d=await govPost('/api/governance/risk-accept',body);
  govSay('racOut',d.detail||'',!!d.accepted);
  if(d.accepted){setTimeout(function(){location.reload();},700);}
  return false;
}
async function recordExemption(ev){
  ev.preventDefault();
  var exp=govVal('exmExp');
  if(!exp){govSay('exmOut','An exemption must have a future expiry date.',false);return false;}
  var body={findingId:govVal('exmId'),configurationName:govVal('exmName')||govVal('exmId'),scope:govVal('exmScope'),
            reason:govVal('exmWhy'),expiry:new Date(exp+'T00:00:00Z').toISOString(),syncTargets:[]};
  govSay('exmOut','Recording...',true);
  var d=await govPost('/api/governance/exemption',body);
  govSay('exmOut',d.detail||'',!!d.accepted);
  if(d.accepted){setTimeout(function(){location.reload();},700);}
  return false;
}
async function renew(id){
  var when=new Date(Date.now()+90*24*3600*1000).toISOString();
  govSay('renewOut','Renewing...',true);
  var d=await govPost('/api/governance/renew',{exemptionId:id,expiry:when});
  govSay('renewOut',d.detail||'',!!d.accepted);
  if(d.accepted){setTimeout(function(){location.reload();},700);}
}
/* AUDIT #13: the three handlers that used to be inline attributes (onsubmit x2, onclick on every
   Renew button). Bound here so script-src can stay nonce-only -- a nonce does NOT whitelist inline
   handlers. The Renew binding is DELEGATED off the document so it covers rows regardless of when
   they were rendered, and reads the id from a data attribute rather than from generated code. */
(function(){
  var rac=document.getElementById('racForm');
  if(rac){rac.addEventListener('submit',recordAccept);}
  var exm=document.getElementById('exmForm');
  if(exm){exm.addEventListener('submit',recordExemption);}
  document.addEventListener('click',function(ev){
    var b=ev.target.closest?ev.target.closest('[data-renew]'):null;
    if(!b||b.disabled)return;
    ev.preventDefault();
    renew(b.getAttribute('data-renew'));
  });
})();
""";

    private const string GovCss = """
.gov-sync-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.gov-sync-head h2{margin:0}
.gov-disabled{opacity:.55;filter:grayscale(.3)}
.gov-toggle{display:inline-flex;align-items:center;gap:8px;cursor:not-allowed}
.gov-toggle input{position:absolute;opacity:0;width:0;height:0}
.gov-toggle-track{width:38px;height:20px;border-radius:20px;background:#d0d7de;position:relative;display:inline-block}
.gov-toggle-track::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:left .15s}
.gov-toggle input:checked + .gov-toggle-track{background:#0969da}
.gov-toggle input:checked + .gov-toggle-track::after{left:20px}
.gov-toggle-label{font-size:12px;font-weight:700;color:#57606a}
.gov-targets{font-size:13px;margin:6px 0 10px}
.gov-note{font-size:13px;color:#57606a;margin:0 0 12px;background:#fff8c5;border:1px solid #d4a72c;border-radius:8px;padding:10px 12px}
.gov-badge-off{display:inline-block;font-size:11px;font-weight:700;border-radius:12px;padding:2px 10px;background:rgba(207,34,46,.12);color:#cf222e;margin-right:6px}
.gov-actions .btn[disabled]{opacity:.5;cursor:not-allowed;background:#8c959f}
.gov-store{font-size:13px;border-radius:8px;padding:10px 12px;margin:0 0 16px;border:1px solid}
.gov-store-ok{background:#dafbe1;border-color:#2da44e;color:#116329}
.gov-store-warn{background:#fff8c5;border-color:#d4a72c;color:#7d4e00}
.gov-forms{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}
.gov-form h3{font-size:14px;margin:0 0 8px}
.gov-form label{display:block;font-size:12px;font-weight:600;color:#57606a;margin:10px 0 4px}
.gov-form input,.gov-form textarea{width:100%;border:1px solid #d0d7de;border-radius:8px;padding:8px;font-family:inherit;font-size:13px}
.gov-form textarea{min-height:56px;resize:vertical}
.gov-form input[disabled],.gov-form textarea[disabled]{background:#f6f8fa;cursor:not-allowed}
.gov-form .btn{margin-top:12px}
.btn-sm{padding:4px 10px;font-size:12px}
.gov-out{font-size:13px;margin:8px 0 0;min-height:1em}
.gov-ok{color:#116329}
.gov-bad{color:#cf222e}
""";
}
