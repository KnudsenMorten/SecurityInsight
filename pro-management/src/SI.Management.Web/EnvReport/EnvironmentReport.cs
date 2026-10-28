using System.Text.Json;
using SI.Management.Web.Changes;
using SI.Management.Web.ChangeJournal;
using SI.Management.Web.GetStarted;
using SI.Management.Web.Settings;

namespace SI.Management.Web.EnvReport;

/// <summary>
/// THE ENVIRONMENT REPORT (framework ENV-REPORT-1, SI #482): the architecture and security facts of THIS install, read from
/// the live environment at report time -- never from design documents. Eight parts: summary, architecture (the Azure
/// resources + a diagram), identities (name, id, kind), permissions per identity (expected / missing / not checked against
/// config\permissions.locked.json, the list the engines check themselves against), features (the settings that change
/// security behaviour, with their More info), data flows (+ a diagram), change history (the configuration commits) and
/// findings (each deviation with its fix). No secret value appears anywhere: only names, ids and states.
/// </summary>
public sealed record EnvironmentReport(DateTime ReadUtc, ReportSummary Summary, AzureFacts Azure, IReadOnlyList<ReportIdentity> Identities,
    IReadOnlyList<PermissionLine> Permissions, IReadOnlyList<FeatureLine> Features, IReadOnlyList<FlowLine> Flows, IReadOnlyList<ConfigCommit> Changes,
    string? ChangesNote, IReadOnlyList<ReportFinding> Findings)
{
    public string ToJson() => JsonSerializer.Serialize(new
    {
        report = "SecurityInsight environment report", schema = 1, readUtc = ReadUtc, summary = Summary,
        architecture = new
        {
            Azure.SubscriptionId, Azure.ResourceGroup, error = Azure.Error,
            resources = Azure.Resources.Select(r => new { r.Name, r.Kind, r.Type, r.Location, network = r.Network.Select(n => new { fact = n.Fact, value = n.Value }), r.PrincipalId, r.UserAssigned, r.ClientId }),
            roleAssignments = Azure.Roles,
        },
        identities = Identities, permissions = Permissions, features = Features, flows = Flows,
        changes = Changes.Select(c => new { c.CommitId, c.CommittedUtc, c.InitiatedBy, c.ApprovedBy, c.Source, c.Records, c.Entities, c.Reason }), changesNote = ChangesNote,
        findings = Findings,
    }, new JsonSerializerOptions { WriteIndented = true });
}

public sealed record ReportSummary(string Customer, string Tenant, string? TenantId, string Product, string Edition, string Licence, string Version, string? Ring,
    string Environment, DateTime? InstalledUtc, string Health, int StepsDone, int StepsTotal, int RequiredOpen);

/// Kind: managed identity | app registration | service principal | mail sender | sign-in app.
public sealed record ReportIdentity(string Name, string? Id, string Kind, string Used);

/// One permission an identity is expected to hold: area (api / azure / database), the item, its state (present / missing /
/// not checked / not checked yet / granted) and why it is needed.
public sealed record PermissionLine(string Identity, string Area, string Item, string State, string Why, string? Fix = null);

public sealed record FeatureLine(string Setting, string Title, string Value, bool IsDefault, string What, string Consequence, bool SecurityRelevant);

public sealed record FlowLine(string From, string To, string Direction, string Protocol, string Auth, string Data, string State);

public sealed record ReportFinding(string Severity, string Area, string Text, string Fix);

/// <summary>PURE. Turns what was read into the report: the permission states, the features, the flows and the findings.</summary>
public static class EnvironmentReportBuilder
{
    /// The expected permissions of each identity in config\permissions.locked.json, against each engine's newest self-check.
    public static IReadOnlyList<PermissionLine> Permissions(PermissionCatalog catalog, IReadOnlyList<EnginePermissions> checks, IReadOnlyList<SettingRow> settings)
    {
        var lines = new List<PermissionLine>();
        foreach (var id in catalog.Identities)
        {
            var reports = checks.Where(c => c.Report is { } r && catalog.IdentityOfEngine(c.Engine) == id.Key).Select(c => c.Report!).ToList();
            foreach (var item in id.Items)
            {
                if (item.When is { } when && !IsOn(settings, when))
                {
                    lines.Add(new PermissionLine(id.Label, item.Area, item.Name, "not needed now", $"only while {when} is on"));
                    continue;
                }
                var gap = reports.SelectMany(r => r.Items).FirstOrDefault(g => g.Area.Equals(item.Area, StringComparison.OrdinalIgnoreCase) && g.Item.Contains(item.Name, StringComparison.OrdinalIgnoreCase));
                var state = reports.Count == 0 ? "not checked yet" : gap is null || gap.State.Equals("ok", StringComparison.OrdinalIgnoreCase) ? "present" : gap.Missing ? "missing" : "not checked";
                lines.Add(new PermissionLine(id.Label, item.Area, item.Name, state, item.Why, gap?.Fix ?? (state == "missing" ? id.Fix(item.Area) : null)));
            }
        }
        return lines;
    }

    private static bool IsOn(IReadOnlyList<SettingRow> rows, string name) =>
        rows.Any(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && (r.ValueJson ?? "").Trim().Equals("true", StringComparison.OrdinalIgnoreCase));

    /// The settings that change security behaviour (a More info confirmation), and every on/off switch set away from its default.
    public static IReadOnlyList<FeatureLine> Features(SettingsCatalog catalog, IReadOnlyList<SettingRow> rows)
    {
        var list = new List<FeatureLine>();
        foreach (var s in catalog.All.Where(s => s.Type == "bool"))
        {
            var info = s.MoreInfo;
            var row = rows.FirstOrDefault(r => r.Name.Equals(s.Name, StringComparison.OrdinalIgnoreCase) && r.ValueJson is not null);
            var def = s.Default is { } d && d.ValueKind == JsonValueKind.True;
            var on = row is null ? def : (row.ValueJson ?? "").Trim().Equals("true", StringComparison.OrdinalIgnoreCase);
            var security = !string.IsNullOrWhiteSpace(info.ConfirmWhen);
            if (!security && on == def) continue;
            list.Add(new FeatureLine(s.Name, s.Title, on ? "on" : "off", on == def, info.What ?? s.Title, (on ? info.WhenOn : info.WhenOff) ?? "", security));
        }
        return list.OrderByDescending(f => f.SecurityRelevant).ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// Every connection in and out, with its state in this install.
    public static IReadOnlyList<FlowLine> Flows(GetStartedFacts? f, string? workspaceId, bool sql, IReadOnlyList<SettingRow> rows)
    {
        string Setting(string n) => rows.FirstOrDefault(r => r.Name.Equals(n, StringComparison.OrdinalIgnoreCase))?.ValueJson?.Trim().Trim('"') ?? "";
        var mail = f?.Mail is { } m ? m.Mode.IsSharedMailbox ? "shared mailbox" + (m.From is { Length: > 0 } fr ? " " + fr : "") : m.Mode.IsSmtp ? "SMTP relay" : "off" : "not read";
        var telemetry = Setting("SI_Telemetry_Enabled") is { Length: > 0 } t ? t : "default";
        var connectors = f?.Connectors.Where(c => c.Enabled).Select(c => c.Name).ToList() ?? new List<string>();
        return
        [
            new("Microsoft Entra ID / Microsoft Graph", "collection jobs", "in", "HTTPS (REST)", "the collection identity (managed identity, application permissions)", "users, groups, roles, devices, applications, sign-in risk", "read-only"),
            new("Microsoft Defender XDR / Defender for Endpoint", "collection jobs", "in", "HTTPS (REST, advanced hunting)", "the collection identity", "devices, vulnerabilities, recommendations, exposure graph", "read-only"),
            new("Azure Resource Manager / Resource Graph", "collection jobs", "in", "HTTPS (REST)", "the collection identity (Reader)", "Azure resources and role assignments", "read-only"),
            new("collection jobs", "Pro database (Azure SQL)", "out", "TDS (encrypted)", "managed identity (Entra)", "provider records, CIs, links, risk factors", sql ? "configured" : "not configured"),
            new("CI build / jobs", "Log Analytics", "out", "HTTPS (Logs ingestion, DCR)", "managed identity", "profile tables, CIs (SI_CI_CL), run health, Risk Analysis output", string.IsNullOrWhiteSpace(workspaceId) ? "workspace not known to the web app" : "workspace " + workspaceId),
            new("Risk Analysis", "Log Analytics", "in", "HTTPS (KQL)", "managed identity", "the Kusto reports' data", "read-only"),
            new("browser", "web app", "in", "HTTPS", "Entra sign-in (OpenID Connect), app roles", "every page a signed-in person opens", "on"),
            new("web app", "Pro database (Azure SQL)", "out", "TDS (encrypted)", "the web app's managed identity", "configuration, views, audit trail", sql ? "configured" : "not configured"),
            new("web app", "Azure Resource Manager", "out", "HTTPS (REST)", "the web app's managed identity (Reader, job operator)", "jobs: list, start, schedule; this report's Azure part", "on"),
            new("mail job", "Exchange Online / SMTP relay", "out", "HTTPS (Graph sendMail) or SMTP", "the mail identity, scoped to the shared mailbox", "reports, alerts, reminders", mail),
            new("SecurityInsight", "Invardia (uplink)", "out", "HTTPS", "the install key", "status and run telemetry (no tenant data)", telemetry),
            new("Invardia", "updater job", "in", "HTTPS", "the install key; signed source", "new versions for the update ring", f?.Ring is { } r ? "ring " + r.Ring.ToString(System.Globalization.CultureInfo.InvariantCulture) : "ring not recorded"),
            new("Invardia", "updater job", "in", "HTTPS", "the install key", "the signed licence", f?.Licence is null ? "no licence recorded" : "licence " + f.Licence.Status),
            new("SecurityInsight", "connectors (ServiceNow / SQL CMDB / others)", "both", "HTTPS / TDS", "each connector's own secret reference (Key Vault)", "findings out, CMDB in", connectors.Count == 0 ? "none enabled" : string.Join(", ", connectors)),
        ];
    }

    /// Deviations, each with its fix.
    public static IReadOnlyList<ReportFinding> Findings(IReadOnlyList<PermissionLine> perms, AzureFacts azure, GetStartedResult? gs, DateTime nowUtc)
    {
        var list = new List<ReportFinding>();
        foreach (var p in perms.Where(p => p.State == "missing"))
            list.Add(new("high", "permissions", $"{p.Identity} is missing {p.Area} permission {p.Item}", p.Fix ?? "Grant it with the setup script, then let the engine run once."));
        foreach (var r in azure.Resources)
            foreach (var (fact, value) in r.Network)
            {
                if (fact == "public network access" && value.Equals("Enabled", StringComparison.OrdinalIgnoreCase))
                    list.Add(new("medium", "network", $"{r.Kind} {r.Name}: public network access is enabled", "Restrict it to the install's network (private endpoint or firewall rules) where your design allows."));
                if (fact == "default network rule" && value.Equals("Allow", StringComparison.OrdinalIgnoreCase))
                    list.Add(new("medium", "network", $"{r.Kind} {r.Name}: the default network rule allows every network", "Set the default rule to Deny and allow the install's network."));
                if (fact == "anonymous blob access" && value.Equals("true", StringComparison.OrdinalIgnoreCase))
                    list.Add(new("high", "network", $"{r.Kind} {r.Name}: anonymous blob access is allowed", "Turn anonymous blob access off."));
            }
        foreach (var r in azure.Resources.Where(r => r.Network.Any(n => n.Fact == "external ingress" && n.Value.Equals("true", StringComparison.OrdinalIgnoreCase)) && r.Network.Any(n => n.Fact == "IP restrictions" && n.Value == "0")))
            list.Add(new("low", "network", $"{r.Kind} {r.Name}: reachable from the internet without IP restrictions (sign-in still required)", "Add IP restrictions to the container app's ingress if only known networks should reach it."));
        if (azure.Error is not null) list.Add(new("info", "architecture", "The Azure part could not be read completely: " + azure.Error, "Give the web app's identity Reader on the install's resource group."));
        if (gs?.Facts?.Licence is { } l)
        {
            var st = l.StateOn(nowUtc);
            if (st is not (LicenceState.Valid)) list.Add(new(st == LicenceState.EndsSoon ? "medium" : "high", "licence", "Licence: " + InstalledLicence.Describe(st).Text, l.NextStep(st) ?? "Contact Invardia."));
        }
        foreach (var s in gs?.Steps.Where(s => s.OpenRequired) ?? Enumerable.Empty<StepState>())
            list.Add(new("medium", "setup", $"Get Started step open: {s.Step.Title} ({s.Note})", s.Step.Action + " -- " + s.Step.Href));
        var order = new[] { "high", "medium", "low", "info" };
        return list.OrderBy(f => Array.IndexOf(order, f.Severity)).ToList();
    }
}
