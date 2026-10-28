using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Secrets;

/// <summary>
/// "SET VALUE" (#822, owner 2026-10-20: "i must have easy possibility to add things to keyvault and configue it" / "i will
/// provide servicenow user/password or api key and it must be stored into keyvault"). The ONE handler every "Set value" box
/// posts to (the view component SecretSet draws the box beside a secret-name field). SuperAdmin only (the page policy AND
/// here), anti-forgery checked (every Razor Pages POST), audited secret.value.set (the product's audit names are
/// domain.object.verb) with the secret's NAME -- never the value.
/// The value is handed to the updater ENCRYPTED (<see cref="SecretHandoverService"/>, owner 2026-10-10: "so the gui keeps
/// read only") -- the web app writes no secret and holds no Key Vault right; the updater stores it in the install's own
/// vault. Only the names <see cref="SecretAllowList"/> allows are accepted -- refused here, and again by the updater.
/// The value is never stored in SQL, logged, echoed back or sent anywhere else: it is read from its own form field
/// (<see cref="ValueField"/>, "Secret" in the name, which the audit trail and the request log always hide) and dropped.
/// </summary>
public sealed class SetModel(SecretHandoverService handover, ILogger<SetModel> log) : PageModel
{
    /// The pressed box's button: "target|secret name" (a setting name or connector:name/ref, and the Key Vault name).
    [BindProperty] public string? SecretPick { get; set; }
    /// Where to go back to (a local path only).
    [BindProperty] public string? ReturnUrl { get; set; }

    /// The form field holding the value for one target (one box per secret can sit in the same page form).
    public static string ValueField(string target) => "SecretValue:" + target;

    public IActionResult OnGet() => LocalRedirect(Back(ReturnUrl));

    [Audited("secret.value.set")]
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var back = Back(ReturnUrl);
        var pick = (SecretPick ?? "").Split('|', 2);
        var target = pick[0].Trim(); var name = pick.Length > 1 ? pick[1].Trim() : "";
        var value = Request.HasFormContentType ? Request.Form[ValueField(target)].ToString() : "";
        // the audit target: the route first (the trail's rule), then WHICH secret -- "SMTP password set 10:12 by X", never the value
        if (AuditScope.Current is { } audit) { audit.Target = "/Admin/Secrets/Set, secret=" + name + " (" + target + ")"; audit.Reason = "secret value set in the web app (the value is never recorded)"; }
        if (!User.IsSuperAdmin())
        {
            AuditScope.Current?.Refused("only a SuperAdmin can set a secret");
            return Forbid();
        }
        if (SecretAllowList.WhyNot(target, name) is { } why)
        {
            AuditScope.Current?.Refused(why);
            log.LogWarning("a secret was refused: {Secret} for {Target} -- {Why}", name, target, why);
            return Toast(back, "Nothing was stored: " + why + ".", "error");
        }
        if (string.IsNullOrWhiteSpace(value)) return Toast(back, "Nothing was stored: the value is empty.", "error");
        var r = await handover.HandOverAsync(target, name, value, User.ChangeName(), ct);
        value = "";
        log.LogInformation("secret {Secret} handed to the updater for {Target}: {Outcome}", name, target, r.Ok ? "ok" : "not stored");
        if (!r.Ok) AuditScope.Current?.Failed(r.Message);
        return Toast(back, (r.Ok ? name + ": " : "") + r.Message, r.Ok ? "ok" : "warn");
    }

    private IActionResult Toast(string back, string text, string kind)
    {
        TempData["toast"] = text; TempData["toastKind"] = kind;
        return LocalRedirect(back);
    }

    /// A local path to go back to; anything else = the settings page.
    public static string Back(string? url) =>
        !string.IsNullOrEmpty(url) && url.StartsWith('/') && !url.StartsWith("//", StringComparison.Ordinal) && !url.StartsWith("/\\", StringComparison.Ordinal) ? url : "/Admin/Settings";
}
