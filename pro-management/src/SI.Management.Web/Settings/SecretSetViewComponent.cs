using Microsoft.AspNetCore.Mvc;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Settings;

/// What the "Set value" box shows.
public sealed record SecretSetView(string Target, string SecretName, string Label, string ReturnUrl, bool CanSet, string? Refused, SecretStateView State, bool OwnForm = false);

/// <summary>
/// THE "SET VALUE" BOX (#822) beside a secret-name field: the secret's state (set at ... by ..., waiting for the updater, the
/// updater's reason, not set) and -- for a SuperAdmin -- a password box that posts to /Admin/Secrets/Set. One line on a page:
/// <c>&lt;vc:secret-set target="SMTPPassword" secret-name="SI-Smtp-Password" label="SMTP password" /&gt;</c>, or for a
/// connector secret target = SecretAllowList.ConnectorTarget(name, "password"). A name the allow-list refuses shows why, and
/// no box.
/// </summary>
public sealed class SecretSetViewComponent(SecretHandoverService handover, ISettingsStoreReader settings, ILogger<SecretSetViewComponent> log) : ViewComponent
{
    /// <paramref name="ownForm"/>: true where the box is NOT inside a page's form (it then brings its own, with the
    /// anti-forgery token); false (the default) inside one -- its button posts the page's form to the secret handler.
    public async Task<IViewComponentResult> InvokeAsync(string target, string secretName, string? label = null, bool ownForm = false)
    {
        var ct = HttpContext.RequestAborted;
        var why = SecretAllowList.WhyNot(target, secretName);
        SettingRow? row = null;
        if (!target.StartsWith(SecretAllowList.ConnectorTargetPrefix, StringComparison.Ordinal))
        {
            try { row = (await settings.ReadSettingsAsync(ct)).Rows.FirstOrDefault(r => r.Name == target && r.Scope == "solution"); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the setting {Setting} could not be read for its secret state", target); }
        }
        var state = await handover.StateOfAsync(target, row, DateTime.UtcNow, ct);
        var back = HttpContext.Request.Path + HttpContext.Request.QueryString;
        return View(new SecretSetView(target, secretName, string.IsNullOrWhiteSpace(label) ? secretName : label, back,
            HttpContext.User.IsSuperAdmin() && why is null, why, state, ownForm));
    }
}
