using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using SI.Management.Core;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages;

/// <summary>
/// What the header's context bar shows (framework BRAND-2, PIM Manager is the reference): in the dark brand bar
/// ENVIRONMENT (the install's own name), MODE (edition + hosting), UPDATE RING, TENANT and TENANT ID; in the light
/// sub-bar the data source (SQL: &lt;database&gt;). Every value comes from the install itself -- its settings, its
/// configuration, the update state the updater records, the tenant as setup read it from Entra -- never from a literal in
/// the code; a value that is not known is said to be "not recorded" (with how it gets filled), never guessed.
/// ENVIRONMENT and TENANT are ALWAYS shown (operator 2026-10-09: "in si i dont have the environment field ... and tenant
/// name is missing from header"): a value that was never set falls back to what the install itself knows.
/// </summary>
public sealed record HeaderInfo(string Environment, string EnvironmentDetail, bool EnvironmentNamed, string Mode, string ModeDetail, string? Ring, string RingDetail,
    string Tenant, string TenantDetail, bool TenantKnown, string? TenantId, string? DataSource)
{
    /// The name an admin gave this environment (the browser tab carries it); null while it has none.
    public string? EnvironmentName => EnvironmentNamed ? Environment : null;
}

public sealed class HeaderContext(ISettingsStoreReader settings, UpdateStateReader updates, InstallRingReader installRing, InstallTenantReader installTenant,
    IConfiguration config, IOptions<EstateOptions> estate, IMemoryCache cache, ILogger<HeaderContext> log)
{
    public const string EnvironmentNameSetting = "SIWeb_EnvironmentName";
    public const string TenantNameSetting = "SIWeb_TenantName";
    /// The Settings page's place for both (PIM Manager: "Environment name" is the first thing on its Settings page).
    public const string SettingsCategory = "Environment";
    public const string SettingsCard = "Environment and tenant";
    /// Where the "name it" link in the header goes: the Environment category, the field itself.
    public const string NameItUrl = "/Admin/Settings?cat=environment#s-" + EnvironmentNameSetting;
    /// #909: the header's details card (mode, licence, update ring, guard mode, tenant, tenant ID) ends with a link to where the
    /// same values are kept: Settings > Licence &amp; updates (the category id is the slug of its name).
    public const string LicenceUpdatesUrl = "/Admin/Settings?cat=licence-updates";
    /// The text shown when no tenant name is known at all.
    public const string NotRecorded = "not recorded";
    private const string Key = "si-header-context";

    private static CatalogSetting Text(string name, string label, string description, string purpose, string defaultText, string effect, string when, string hint) => new()
    {
        Name = name, Label = label, Group = SettingsCategory, Card = SettingsCard, Type = "text", Engines = new[] { "management-web" }, Edition = "pro", WebOnly = true,
        Default = JsonDocument.Parse("\"\"").RootElement.Clone(), Description = description, Purpose = purpose, DefaultText = defaultText, Effect = effect,
        WhenToChange = when, Hint = hint, Pattern = "^.{0,60}$", PatternHint = "at most 60 characters",
    };

    /// The two header settings, edited on the Settings page (category Environment) like every other web-app setting.
    public static readonly IReadOnlyList<CatalogSetting> Catalog =
    [
        Text(EnvironmentNameSetting, "Environment name",
            "This environment's own name, shown first in the header (ENVIRONMENT) and in the browser tab -- e.g. \"Production (EU)\" or \"Test\" -- so several open SecurityInsight windows are told apart at a glance.",
            "Names this environment in the header and the browser tab.", "Not set: the header shows the install's resource group (or its container app) and offers admins a link to name it",
            "Only the header and the browser tab change.", "Once, after the install; when you run more than one environment.",
            "Shown as Environment at the top of every page."),
        Text(TenantNameSetting, "Tenant name (override)",
            "The tenant name shown in the header (TENANT). Leave it empty: setup reads the tenant's own name from Entra ID when it installs. Set it only to show a different name.",
            "Overrides the tenant name the header shows.", "Not set: the tenant's name as setup read it from Entra ID, else its onmicrosoft.com domain",
            "Only the header changes.", "Rarely: only when the tenant's own name is not the one people know it by.",
            "Leave empty to show the tenant's own name from Entra ID."),
    ];

    /// The tooltip when no tenant name is known -- it says how it gets filled.
    public const string NoTenantDetail = "The tenant's name is not recorded for this install yet. Setup reads it from Entra ID when SecurityInsight is installed (the Set-SIInstallTenant script reads it again), or an admin sets \"Tenant name (override)\" on the Settings page (Environment).";

    /// ENVIRONMENT: the admin's name for it > the install's resource group (the web app's own configuration, else the
    /// install setting) > the container app it runs in. Named = false for every fallback (the header then offers admins a
    /// link to name it). Never empty: with nothing known it says "not named".
    public static (string Value, string Detail, bool Named) EnvironmentOf(string? setting, string? resourceGroup, string? settingResourceGroup, string? containerApp)
    {
        if (Clean(setting) is { } s) return (s, "This environment's name (Settings: Environment, \"Environment name\")", true);
        const string how = " An admin names it on the Settings page (Environment, \"Environment name\").";
        if ((Clean(resourceGroup) ?? Clean(settingResourceGroup)) is { } rg) return (rg, "Not named yet: this is the install's resource group." + how, false);
        if (Clean(containerApp) is { } ca) return (ca, "Not named yet: this is the container app the web app runs in." + how, false);
        return ("not named", "This environment has no name yet." + how, false);
    }

    /// TENANT: the admin's override > the name setup recorded from Entra ID > the tenant's initial (onmicrosoft.com)
    /// domain > "not recorded". A record made for ANOTHER tenant than the one this web app signs in to is ignored.
    public static (string Value, string Detail, bool Known) TenantOf(string? setting, InstallTenant? recorded, string? tenantId)
    {
        if (Clean(setting) is { } s) return (s, "Connected tenant (the name set on the Settings page: Environment, \"Tenant name (override)\")", true);
        if (recorded is not null && tenantId is not null && recorded.TenantId is { } rid
            && !string.Equals(rid, tenantId, StringComparison.OrdinalIgnoreCase)) recorded = null;
        var when = recorded?.SetAt is { } at ? " on " + Fmt.When(at) : "";
        if (Clean(recorded?.Name) is { } n)
            return (n, "Connected tenant: its name in Entra ID, as read" + when + (recorded!.InitialDomain is { } d ? " (" + d + ")" : ""), true);
        if (Clean(recorded?.InitialDomain) is { } dom)
            return (dom, "Connected tenant: its onmicrosoft.com domain (the tenant's name could not be read" + when + "). " + NoTenantDetail, true);
        return (NotRecorded, NoTenantDetail, false);
    }

    private static string? Clean(string? v) => string.IsNullOrWhiteSpace(v) ? null : v.Trim();

    /// "Pro" plus where it runs: Azure Container Apps sets CONTAINER_APP_NAME in every container it starts.
    public static (string Mode, string Detail) ModeOf(string? containerApp) =>
        string.IsNullOrWhiteSpace(containerApp)
            ? ("Pro (locally hosted)", "SecurityInsight Pro on a server or VM of your own")
            : ("Pro (Container Apps)", "SecurityInsight Pro in Azure Container Apps (" + containerApp.Trim() + ")");

    /// A tenant id from the sign-in configuration, never a placeholder.
    public static string? TenantIdOf(string? configured) =>
        Guid.TryParse(configured?.Trim(), out var g) && g != Guid.Empty ? g.ToString() : null;

    /// The tooltip when no ring is known at all -- it says how to set one.
    public const string NoRingDetail = "No update ring is recorded for this install. An admin sets it on the Settings page: \"Update ring\" (0 development, 1 internal, 2 early release, 3 broad). The updater also records it on its next run.";

    /// UPDATE RING (#308): the ring the updater last updated by (its state) > the ring recorded with the install
    /// (cfg.InstallState 'Ring', written at install time) > the admin's setting SI_UpdateRing. "not recorded" only when
    /// none of the three is known -- and then the tooltip says how to set it.
    public static (string? Ring, string Detail) RingOf(UpdateState? s, InstallRing? recorded = null, int? setting = null)
    {
        var ring = s?.Code?.Ring ?? s?.Templates?.Ring;
        if (s is not null && ring is not null)
        {
            var when = s.LastCheckUtc is { } t ? " (checked " + Fmt.When(t) + ")" : "";
            // CR3 (#657, framework 12.11e item 2): a pre-release wave -- "Ring 2 - Pre-release (<wave>)"
            if (s.Code?.Wave is { } wave)
            {
                var wr = s.Code.WaveRing ?? ring.Value;
                return (WaveText(wr, wave), "Pre-release: this install runs " + (s.Code.WaveVersion ?? "a version") + " early, in the wave \"" + wave
                    + "\" -- a version already released to a lower ring, served before ring " + wr + " gets it, with no ring move. It keeps that version and follows ring "
                    + wr + " again once the ring reaches it; it is never moved back. " + (s.Code.Summary) + when);
            }
            return (RingText(ring.Value), "Updates for ring " + ring + " -- " + (s.Code?.Summary ?? "no code update recorded") + when);
        }
        if (recorded is not null)
        {
            var how = recorded.Source switch
            {
                "setting" => " (from the Update ring setting)",
                "resource-group" => " (from the install's resource-group name)",
                "updater" => " (by the updater)",
                "parameter" => " (given to setup)",
                _ => "",
            };
            var by = string.IsNullOrWhiteSpace(recorded.SetBy) ? "" : " by " + recorded.SetBy;
            var at = recorded.SetAt is { } a ? " on " + Fmt.When(a) : "";
            var via = string.IsNullOrWhiteSpace(recorded.Channel) ? "" : "; updates come from " + recorded.Channel;
            return (RingText(recorded.Ring), "Ring " + recorded.Ring + " was recorded for this install" + by + at + how + via + ". The updater has not reported a check yet.");
        }
        if (setting is { } st and >= 0 and <= 3)
            return (RingText(st), "Ring " + st + " from the Update ring setting (SI_UpdateRing). The updater has not reported a check yet.");
        return (null, NoRingDetail);
    }

    private static string RingText(int ring) => "ring " + ring.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// The header's words in a pre-release wave (framework 12.11e: "Ring &lt;N&gt; - Pre-release (&lt;name&gt;)").
    public static string WaveText(int ring, string wave) => "Ring " + ring.ToString(System.Globalization.CultureInfo.InvariantCulture) + " - Pre-release (" + wave + ")";

    public async Task<HeaderInfo> ReadAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(Key, out HeaderInfo? hit) && hit is not null) return hit;
        string? env = null, tenantName = null, settingRg = null; int? ringSetting = null;
        try
        {
            var rows = (await settings.ReadSettingsAsync(ct).ConfigureAwait(false)).Rows;
            string? Value(string name, string scope)
            {
                var row = rows.FirstOrDefault(r => r.Scope == scope && r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (row?.ValueJson is not { } j) return null;
                try
                {
                    using var d = JsonDocument.Parse(j);
                    return d.RootElement.ValueKind == JsonValueKind.String && d.RootElement.GetString() is { } v && v.Trim().Length > 0 ? v.Trim() : null;
                }
                catch (JsonException) { return null; }
            }
            env = Value(EnvironmentNameSetting, CatalogSetting.WebScope);
            tenantName = Value(TenantNameSetting, CatalogSetting.WebScope);
            // the install's resource group as setup recorded it (Settings: Sign-in & Azure resources, Container hosting)
            settingRg = Value("SI_Bootstrap_ResourceGroupName", "solution");
            // #308: the admin's Update ring setting (engine catalog, solution scope) -- a number, or a number as text
            var rs = rows.FirstOrDefault(r => r.Scope == "solution" && r.Name.Equals(InstallRingReader.SettingName, StringComparison.OrdinalIgnoreCase));
            if (rs?.ValueJson is { } rj) ringSetting = InstallRingReader.RingOf(rj);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { log.LogDebug(ex, "header settings could not be read"); }

        UpdateState? state = null;
        try { state = await updates.ReadAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { log.LogDebug(ex, "update state could not be read for the header"); }

        InstallRing? recorded = null;
        try { recorded = await installRing.ReadAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { log.LogDebug(ex, "the recorded update ring could not be read for the header"); }

        InstallTenant? tenantRecord = null;
        try { tenantRecord = await installTenant.ReadAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { log.LogDebug(ex, "the recorded tenant could not be read for the header"); }

        var containerApp = System.Environment.GetEnvironmentVariable("CONTAINER_APP_NAME");
        var (mode, modeDetail) = ModeOf(containerApp);
        var (ring, ringDetail) = RingOf(state, recorded, ringSetting);
        var (envValue, envDetail, envNamed) = EnvironmentOf(env, config["Jobs:ResourceGroup"], settingRg, containerApp);
        var tenantId = TenantIdOf(config["AzureAd:TenantId"]);
        var (tenant, tenantDetail, tenantKnown) = TenantOf(tenantName, tenantRecord, tenantId);
        var db = estate.Value.SqlDatabase;
        var info = new HeaderInfo(envValue, envDetail, envNamed, mode, modeDetail, ring, ringDetail, tenant, tenantDetail, tenantKnown, tenantId,
            string.IsNullOrWhiteSpace(db) ? null : "SQL: " + db.Trim());
        cache.Set(Key, info, TimeSpan.FromMinutes(1));
        return info;
    }

    /// The cached header is dropped when a setting is saved (the next page shows the new name at once): the one settings
    /// write (Settings/SettingsStore.cs, SettingsWriter) calls this after every saved change.
    public void Forget() => Forget(cache);
    public static void Forget(IMemoryCache memory) => memory.Remove(Key);
}
