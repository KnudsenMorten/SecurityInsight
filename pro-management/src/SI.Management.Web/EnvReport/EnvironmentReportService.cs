using Microsoft.Extensions.Options;
using SI.Management.Core;
using SI.Management.Web.Changes;
using SI.Management.Web.ChangeJournal;
using SI.Management.Web.GetStarted;
using SI.Management.Web.Pages;
using SI.Management.Web.Settings;

namespace SI.Management.Web.EnvReport;

/// <summary>
/// Reads the environment report's facts NOW, each part on its own (one that cannot be read says so; the others still
/// show): Get Started's facts (licence, access, mail, the engines' runs and permission self-checks, ring, settings,
/// connectors -- the same reads its steps make), the header facts (tenant, environment, ring), the Azure resource group
/// through ARM, the permission list, the settings catalog and the configuration commits.
/// </summary>
public sealed class EnvironmentReportService(GetStartedService getStarted, HeaderContext header, InstallTenantReader tenant, IAzureFactsReader azure,
    SettingsCatalog catalog, IConfigJournalStore journal, IOptions<EstateOptions> estate, IConfiguration config, TimeProvider clock, ILogger<EnvironmentReportService> log)
{
    public async Task<EnvironmentReport> BuildAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        GetStartedResult? gs = null;
        try { gs = await getStarted.EvaluateAsync(fresh: false, ct); } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "environment report: Get Started facts"); }
        var f = gs?.Facts;
        HeaderInfo? h = null;
        try { h = await header.ReadAsync(ct); } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "environment report: header"); }
        InstallTenant? t = null;
        try { t = await tenant.ReadAsync(ct); } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "environment report: tenant"); }
        AzureFacts az;
        try { az = await azure.ReadAsync(ct); } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "environment report: Azure"); az = AzureFacts.NotConfigured with { Error = "the Azure part could not be read: " + ex.Message }; }
        IReadOnlyList<ConfigCommit> commits = Array.Empty<ConfigCommit>();
        string? changesNote = null;
        try
        {
            if (await journal.ExistsAsync(ct)) commits = (await journal.CommitsAsync(null, null, null, 0, 25, ct)).Rows;
            else changesNote = "the change journal is not in this database yet";
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "environment report: commits"); changesNote = "the configuration commits could not be read: " + ex.Message; }

        var settings = f?.Settings ?? Array.Empty<SettingRow>();
        var licence = f?.Licence;
        var perms = PermissionCatalog.Default is { } pc
            ? EnvironmentReportBuilder.Permissions(pc, f?.Permissions ?? Array.Empty<EnginePermissions>(), settings)
            : new[] { new PermissionLine("(all)", "-", "-", "not compared", "config\\permissions.locked.json is not next to the web app") };
        var summary = new ReportSummary(
            licence?.Customer ?? h?.Tenant ?? "not recorded", h?.Tenant ?? t?.Name ?? "not recorded", h?.TenantId ?? t?.TenantId, "SecurityInsight Pro",
            LicenceDimension.TextOrBeingChecked(licence, now), licence is null ? "no licence recorded" : InstalledLicence.Describe(licence.StateOn(now)).Text + (licence.ValidTo is { } to ? " (until " + InstalledLicence.Day(to) + ")" : ""),
            AppInfo.Version, h?.Ring, h?.Environment ?? "not named", t?.SetAt,
            gs is null ? "not read" : gs.Ready ? "every required setup step is done" : $"{gs.OpenRequired} required setup step(s) open",
            gs?.Done ?? 0, gs?.Total ?? 0, gs?.OpenRequired ?? 0);
        var identities = Identities(az, f, config["AzureAd:ClientId"]);
        var features = EnvironmentReportBuilder.Features(catalog, settings);
        var flows = EnvironmentReportBuilder.Flows(f, estate.Value.WorkspaceId, !string.IsNullOrWhiteSpace(estate.Value.SqlServer), settings);
        var findings = EnvironmentReportBuilder.Findings(perms, az, gs, now);
        return new EnvironmentReport(now, summary, az, identities, perms, features, flows, commits, changesNote, findings);
    }

    /// PURE. Every identity the install runs as or uses, by name, id and kind.
    public static IReadOnlyList<ReportIdentity> Identities(AzureFacts az, GetStartedFacts? f, string? webClientId)
    {
        var list = new List<ReportIdentity>();
        foreach (var r in az.Resources.Where(r => r.Type.Equals("Microsoft.ManagedIdentity/userAssignedIdentities", StringComparison.OrdinalIgnoreCase)))
        {
            var users = az.Resources.Where(x => x.UserAssigned?.Contains(r.Name, StringComparer.OrdinalIgnoreCase) == true).Select(x => x.Name).ToList();
            list.Add(new ReportIdentity(r.Name, r.PrincipalId ?? r.ClientId, "managed identity (user-assigned)", users.Count == 0 ? "not attached to a resource of this group" : "used by " + string.Join(", ", users)));
        }
        foreach (var r in az.Resources.Where(r => r.PrincipalId is not null && !r.Type.Equals("Microsoft.ManagedIdentity/userAssignedIdentities", StringComparison.OrdinalIgnoreCase)))
            list.Add(new ReportIdentity(r.Name + " (system-assigned)", r.PrincipalId, "managed identity (system-assigned)", "the " + r.Kind + "'s own identity"));
        if (!string.IsNullOrWhiteSpace(webClientId)) list.Add(new ReportIdentity("web app sign-in", webClientId, "app registration", "Entra sign-in to this web app; its app roles are the web app's roles"));
        foreach (var p in (f?.Permissions ?? Array.Empty<EnginePermissions>()).Where(p => p.Report is not null).GroupBy(p => p.Report!.Identity))
            if (!list.Any(i => string.Equals(i.Id, p.Key, StringComparison.OrdinalIgnoreCase)))
                list.Add(new ReportIdentity(p.First().Report!.Label, p.Key, "engine identity (client id)", "the engines " + string.Join(", ", p.Select(x => x.Engine))));
        if (f?.Mail is { } m && m.Mode.IsSharedMailbox && !string.IsNullOrWhiteSpace(m.From))
            list.Add(new ReportIdentity(m.From!, m.Identity, "mail sender (shared mailbox)", "every SecurityInsight mail is sent as this mailbox"));
        return list;
    }
}
