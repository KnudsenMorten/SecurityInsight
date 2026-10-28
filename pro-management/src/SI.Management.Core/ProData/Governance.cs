using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

/// <summary>
/// The GOVERNANCE LOG of a finding (#254, phase 2): the statuses a department gives a vulnerability. Validated in code (no
/// CHECK in cfg.GovernanceEntry, the list grows). The data sync never writes them and nothing here closes a finding:
/// "fixed-pending-verification" says the department believes it is fixed -- the next collections verify it.
/// </summary>
public static class GovernanceStatuses
{
    public const string Open = "open";
    public const string InProgress = "in-progress";
    public const string Planned = "planned";
    public const string FixedPendingVerification = "fixed-pending-verification";
    /// The risk is accepted through the exemption flow (#252): the entry carries the request; an approver decides.
    public const string Accepted = "accepted";
    /// Sent to the vendor for review (a remediation flow's "Escalate to vendor").
    public const string Escalated = "escalated";
    public const string NotApplicable = "not-applicable";

    public static readonly IReadOnlyList<string> All = [Open, InProgress, Planned, FixedPendingVerification, Accepted, Escalated, NotApplicable];

    /// The statuses a person sets directly with a comment. Accepted and Escalated are set by their actions (they raise an
    /// exemption request / a vendor mail), never by picking the word.
    public static readonly IReadOnlyList<string> Settable = [Open, InProgress, Planned, FixedPendingVerification, NotApplicable];

    public static string Label(string? s) => s switch
    {
        Open => "Open",
        InProgress => "In progress",
        Planned => "Planned",
        FixedPendingVerification => "Fixed, pending verification",
        Accepted => "Risk accepted (exemption requested)",
        Escalated => "Escalated to the vendor",
        NotApplicable => "Not applicable",
        null or "" => "No status",
        _ => s,
    };
}

/// <summary>
/// The REMEDIATION FLOW actions (#254, phase 3) -- what a department does with a category / subcategory of findings.
/// SecurityInsight stays read-only toward the platforms: <see cref="AutoWindow"/> schedules (records) the fix for the next
/// maintenance window and tells the technical owners; it never pushes a change to Defender, Intune, Entra or Azure.
/// </summary>
public static class RemediationActions
{
    public const string AutoWindow = "auto-window";
    public const string Manual = "manual";
    public const string EscalateVendor = "escalate-vendor";
    public const string AcceptRisk = "accept-risk";
    public const string NotApplicable = "not-applicable";
    public static readonly IReadOnlyList<string> All = [AutoWindow, Manual, EscalateVendor, AcceptRisk, NotApplicable];

    public static string Label(string? a) => a switch
    {
        AutoWindow => "Auto in the maintenance window",
        Manual => "Manual implementation",
        EscalateVendor => "Escalate to the vendor",
        AcceptRisk => "Accept the risk (exemption flow)",
        NotApplicable => "Not applicable",
        _ => a ?? "",
    };

    public static string Purpose(string? a) => a switch
    {
        AutoWindow => "SecurityInsight marks the finding as planned for the department's next maintenance window and tells its technical owners; the fix itself is made by the platform's own tooling",
        Manual => "the technical owners implement the fix by hand",
        EscalateVendor => "the finding is sent to the vendor contact for review; the mail is recorded in the governance log",
        AcceptRisk => "an exemption is requested; it applies only once an approver of the security domain approves it",
        NotApplicable => "recorded as not applicable for the department; the finding stays visible",
        _ => "",
    };

    /// The status an action records.
    public static string StatusOf(string action) => action switch
    {
        AutoWindow => GovernanceStatuses.Planned,
        EscalateVendor => GovernanceStatuses.Escalated,
        AcceptRisk => GovernanceStatuses.Accepted,
        NotApplicable => GovernanceStatuses.NotApplicable,
        _ => GovernanceStatuses.InProgress,
    };
}

/// One remediation flow (cfg.RemediationFlow). DepartmentId null = every department; Category / Subcategory "*" = any.
public sealed record RemediationFlowDef(int FlowId, int? DepartmentId, string Category, string Subcategory, string Action, string? VendorName, string? VendorMail,
    string? Note, int SortOrder, bool Retired = false);

public static class RemediationFlowResolver
{
    public const string Any = "*";

    /// <summary>
    /// The flow for a finding of a department: among the active flows that match (department or every department; the
    /// finding's security domain or "*"; its report or "*"), the MOST SPECIFIC wins -- a department's own flow over a
    /// flow for every department, then a named category over "*", then a named subcategory over "*" -- then the lowest
    /// SortOrder, then the lowest id. None = null (the department has no flow for it: handled by hand).
    /// </summary>
    public static RemediationFlowDef? Resolve(IEnumerable<RemediationFlowDef> flows, int? departmentId, string? category, string? subcategory)
    {
        static bool Eq(string a, string? b) => string.Equals(a.Trim(), (b ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
        return flows
            .Where(f => !f.Retired)
            .Where(f => f.DepartmentId is null || f.DepartmentId == departmentId)
            .Where(f => f.Category == Any || Eq(f.Category, category))
            .Where(f => f.Subcategory == Any || Eq(f.Subcategory, subcategory))
            .OrderByDescending(f => (f.DepartmentId is null ? 0 : 4) + (f.Category == Any ? 0 : 2) + (f.Subcategory == Any ? 0 : 1))
            .ThenBy(f => f.SortOrder).ThenBy(f => f.FlowId)
            .FirstOrDefault();
    }
}

/// One maintenance window: a day (Mon..Sun, or "daily") and a time span in UTC; a span whose end is not after its start
/// runs past midnight.
public sealed record MaintenanceWindow(DayOfWeek? Day, TimeSpan From, TimeSpan To)
{
    public TimeSpan Length => To > From ? To - From : TimeSpan.FromDays(1) - From + To;
}

/// <summary>
/// The department's maintenance windows (cfg.Department.MaintenanceWindowsJson, captured in phase 1):
/// <c>[{"day":"Sat","from":"22:00","to":"04:00"}]</c> -- times in UTC; "day" is Mon..Sun (or the full name) or "daily".
/// The PowerShell twin is Get-SIGovernanceNextWindow (engine\pro-data\_shared\SI-GovernanceMail.ps1): the same cases are
/// tested on both sides.
/// </summary>
public static class MaintenanceWindows
{
    private static readonly string[] DayNames = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

    public static (IReadOnlyList<MaintenanceWindow> Windows, IReadOnlyList<string> Problems) Parse(string? json)
    {
        var list = new List<MaintenanceWindow>();
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(json)) return (list, why);
        try
        {
            using var d = JsonDocument.Parse(json);
            var items = d.RootElement.ValueKind == JsonValueKind.Array ? d.RootElement.EnumerateArray().ToList() : [d.RootElement];
            var n = 0;
            foreach (var e in items)
            {
                n++;
                if (e.ValueKind != JsonValueKind.Object) { why.Add($"window {n} is not an object"); continue; }
                string? Get(string name) => e.EnumerateObject().FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)).Value is { ValueKind: JsonValueKind.String } v ? v.GetString() : null;
                var day = (Get("day") ?? "").Trim().ToLowerInvariant();
                DayOfWeek? dow = null;
                if (day is "daily" or "*" or "every day") dow = null;
                else if (day.Length >= 3 && Array.IndexOf(DayNames, day[..3]) is var i and >= 0) dow = (DayOfWeek)i;
                else { why.Add($"window {n}: '{day}' is not a day (Mon..Sun or daily)"); continue; }
                if (!TimeSpan.TryParseExact(Get("from") ?? "", @"hh\:mm", CultureInfo.InvariantCulture, out var from) || from >= TimeSpan.FromDays(1)) { why.Add($"window {n}: 'from' is not HH:mm"); continue; }
                if (!TimeSpan.TryParseExact(Get("to") ?? "", @"hh\:mm", CultureInfo.InvariantCulture, out var to) || to >= TimeSpan.FromDays(1)) { why.Add($"window {n}: 'to' is not HH:mm"); continue; }
                list.Add(new MaintenanceWindow(dow, from, to));
            }
        }
        catch (JsonException) { why.Add("the maintenance windows are not valid JSON"); }
        return (list, why);
    }

    /// <summary>
    /// The window a fix scheduled NOW goes into: the window running now (until it ends), else the earliest one to start
    /// after <paramref name="nowUtc"/>. Null = the department has no window.
    /// </summary>
    public static (DateTime Start, DateTime End)? Next(IReadOnlyList<MaintenanceWindow> windows, DateTime nowUtc)
    {
        if (windows.Count == 0) return null;
        var now = DateTime.SpecifyKind(nowUtc, DateTimeKind.Utc);
        (DateTime, DateTime)? best = null;
        // from yesterday (a window that started yesterday may still be running) to 8 days ahead covers every weekly window
        for (var day = now.Date.AddDays(-1); day <= now.Date.AddDays(8); day = day.AddDays(1))
        {
            foreach (var w in windows)
            {
                if (w.Day is { } dw && day.DayOfWeek != dw) continue;
                var start = DateTime.SpecifyKind(day + w.From, DateTimeKind.Utc);
                var end = start + w.Length;
                if (end <= now) continue;
                if (best is null || start < best.Value.Item1) best = (start, end);
            }
        }
        return best;
    }
}

/// The finding key the governance log uses across collections: the asset and the recommendation (ConfigurationId, else the CVE).
public static class GovernanceKeys
{
    public static string? Recommendation(string? configurationId, string? cve) =>
        !string.IsNullOrWhiteSpace(configurationId) ? configurationId.Trim() : string.IsNullOrWhiteSpace(cve) ? null : cve.Trim();
}
