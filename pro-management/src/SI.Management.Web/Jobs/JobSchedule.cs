using System.Globalization;

namespace SI.Management.Web.Jobs;

/// <summary>
/// A job's schedule in words people read (operator 2026-10-04, on the Jobs page: "nobody understands this as normal IT
/// people, when and cadence please"). The 5-field cron expression stays the source of truth -- it is what Container Apps
/// runs and what "Change schedule" writes -- and is shown as a tooltip; this turns the common shapes into "Daily at
/// 05:30 UTC", "Every 6 hours at :15", "Mondays at 02:00 UTC", "Monthly on day 1 at 03:00 UTC", and computes the next
/// run. Anything else reads "Custom schedule" with the expression.
/// </summary>
public static class JobSchedule
{
    public sealed record Described(string Cadence, DateTimeOffset? NextUtc, int? SortMinute);

    private static readonly string[] Days = ["Sundays", "Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays"];

    /// The readable name of an SI job, from its Container Apps name; an unknown job keeps its own name.
    public static string Label(string jobName)
    {
        var k = (jobName ?? "").Trim().ToLowerInvariant();
        if (k.StartsWith("caj-si-", StringComparison.Ordinal)) k = k["caj-si-".Length..];
        return k switch
        {
            "endpoint" => "Endpoint profiling",
            "identity" => "Identity profiling",
            "azure" => "Azure profiling",
            "publicip" => "Public IP profiling",
            "ptc" or "privilege-tier-classifier" => "Privilege tier classifier",
            "risk-analysis" => "Risk Analysis (summary report, optional)",
            "risk-analysis-detailed" => "Risk Analysis (detailed report)",
            "asset-trend" => "Risk trend",
            "asset-correlation" => "Asset correlation",
            "asset-properties" => "Asset properties (retired)",
            // #269: two jobs -- the SQL connector and the ServiceNow connector (operator: "one for sql connector and one for servicenow")
            "asset-vulnerabilities" => "Vulnerability connector -- SQL",
            "asset-vulns-servicenow" => "Vulnerability connector -- ServiceNow",
            "flow" => "Job flow (runner)",
            "asset-datasync" => "Data sync to the web app",
            "asset-cmdb" => "CMDB connector -- ServiceNow (creates / updates CIs)",
            "asset-cmdb-sql" => "CMDB connector -- SQL (Pro database)",
            "asset-tagging" => "Asset tagging",
            "templates" => "Template releases",
            "close-loop-mail" => "Mails (close-loop, exemptions, departments)",
            "verification" => "Verification (data-collection gaps)",
            "schema-discovery" => "Schema discovery",
            "updater" => "Updates",
            "config-backup" => "Configuration backup",
            "heartbeat" => "Status report to Invardia (hourly)",
            _ => jobName ?? "",
        };
    }

    /// What a job does and which jobs' output it reads (operator 2026-10-04: "explain also what the jobs do and
    /// dependencies they have to other jobs / data"). Needs are job keys (the name without "caj-si-").
    public sealed record JobRole(string Does, string[] Needs, string Produces);

    public static string Key(string jobName)
    {
        var k = (jobName ?? "").Trim().ToLowerInvariant();
        return k.StartsWith("caj-si-", StringComparison.Ordinal) ? k["caj-si-".Length..] : k;
    }

    public static JobRole? Role(string jobName) => Key(jobName) switch
    {
        "ptc" or "privilege-tier-classifier" => new("Classifies every Entra role, Graph permission and Azure role into tiers 0-3 -- the catalog the profilers use to tier identities.", [], "the privilege tier catalog"),
        "endpoint" => new("Collects every device from Defender for Endpoint and profiles it: role, criticality tier, exposure.", ["ptc"], "endpoint profiles (SI_Endpoint_Profile_CL); with full asset metadata on, every property of each device from the same read (SI_AssetProperties_CL)"),
        "identity" => new("Profiles users, groups and service principals from Entra ID: privileges, sign-in, tier.", ["ptc"], "identity profiles (SI_Identity_Profile_CL); with full asset metadata on, every property of each identity from the same read (SI_AssetProperties_CL)"),
        "azure" => new("Profiles Azure resources and Defender for Cloud recommendations per subscription.", ["ptc"], "Azure profiles (SI_Azure_Profile_CL); with full asset metadata on, every property of each resource from the same read (SI_AssetProperties_CL)"),
        "publicip" => new("Finds the public IP addresses of tier 0/1 assets and checks their exposure.", ["endpoint", "azure"], "public IP profiles (SI_PublicIP_Profile_CL)"),
        "asset-correlation" => new("Links the same machine or identity seen by several sources into one asset.", ["endpoint", "identity", "azure"], "the asset ledger (one asset, many sources)"),
        // #412: retired -- the profilers read each source once and publish the full asset metadata themselves
        "asset-properties" => new("Retired: with full asset metadata on, the endpoint, identity and azure profilers read each source once and publish every property themselves. This job reads nothing and can be removed.", [], "nothing (retired)"),
        "risk-analysis" => new("Optional, off by default: the older Summary report and its mail -- every Summary view of the web app is a grouping of the detailed findings, and the management mail is the detailed report's. Switch it on only when someone still reads the Summary workbook. Runs after the CIs are built and reads them.", ["endpoint", "identity", "azure", "publicip", "ptc", "asset-correlation"], "the summary risk report"),
        "risk-analysis-detailed" => new("The detailed per-finding report (Excel and mail). Runs after the CIs are built and reads them.", ["endpoint", "identity", "azure", "publicip", "ptc", "asset-correlation"], "the detailed risk report"),
        "asset-trend" => new("Stores the day's risk totals so trends can be drawn over time (from the detailed findings: every finding counts).", ["risk-analysis-detailed"], "the daily risk trend"),
        "asset-vulnerabilities" => new("The SQL vulnerability connector: writes every vulnerability into the vulnerability database (SQL) -- opens new ones, closes the fixed ones, reopens ones that come back. Other non-ServiceNow connectors (REST) run here too.", ["risk-analysis-detailed"], "the vulnerability database (SQL): open / closed / reopened"),
        "asset-vulns-servicenow" => new("The vulnerability connector's ServiceNow job. It sends nothing to ServiceNow: the ServiceNow data-out connector in the data sync step sends the vulnerable items. The step stays in the pipeline and ends at once.", ["risk-analysis-detailed", "asset-cmdb"], "nothing (the data-out connector sends the vulnerable items)"),
        "asset-datasync" => new("Copies the newest complete collection into the web app's database and pre-computes the views.", ["risk-analysis-detailed", "asset-vulnerabilities"], "the data the web app shows"),
        "close-loop-mail" => new("Sends the close-loop, exemption, department and task mails.", ["asset-datasync", "asset-vulnerabilities", "asset-vulns-servicenow"], "mails"),
        "verification" => new("Checks that the settings and plans SecurityInsight's data depends on are on: Defender for Cloud plans, Defender for Endpoint sensors on VMs and devices, supported operating systems, multicloud connectors, Advanced Hunting tables, sign-in logs in the security workspace and the collectors' last runs. Read-only: it never changes a setting.", ["ptc", "identity", "azure", "endpoint", "publicip"], "the data-collection gaps (" + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/Verification") + ")"),
        "flow" => new("Starts the jobs of the flow one after the other, each when the one before it has ended. Its timer only wakes it every 5 minutes; it starts the flow when the flow is due.", [], "the flow's run records"),
        "asset-cmdb" => new("The CMDB match report against ServiceNow: it plans and reports and sends nothing to ServiceNow -- the ServiceNow data-out connector in the data sync step sends the CIs.", ["asset-correlation"], "the match report (nothing is sent to ServiceNow)"),
        "asset-cmdb-sql" => new("The SQL CMDB connector: writes every asset SecurityInsight knows into the CI table of the Pro database -- creates new CIs, updates changed ones (with history) and retires CIs that have been gone for several complete runs; never from a partial snapshot, never deleting.", ["asset-correlation"], "the CI table in the Pro database (cmdbsync.ConfigurationItem)"),
        "asset-tagging" => new("Writes tier tags back to Defender devices (opt-in, its own write identity).", ["endpoint"], "device tags in Defender"),
        "templates" => new("Publishes an accepted template release. Started by the web app, not on a schedule.", [], "configuration templates"),
        "config-backup" => new("Backs up every configuration you made (settings, departments, access, exemptions, overrides, connectors, the CMDB service model, the pipeline, reports, saved views) once a day, records a day without changes as no change, and removes backups older than the retention (pinned ones stay). Never a step of the pipeline.", [], "configuration backups (" + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/Backups") + ")"),
        "heartbeat" => new("Sends the install's status report to Invardia once an hour, whether or not the pipeline runs -- so a long report or correlation never looks like a stopped install. It only reads; it never changes anything. Never a step of the pipeline.", [], "the hourly status report"),
        _ => null,
    };

    /// A job scheduled BEFORE a job it needs (on a daily schedule) reads yesterday's data -- the page warns.
    public static string[] RunsBeforeItsInputs(string jobName, IReadOnlyDictionary<string, int?> sortMinuteByKey)
    {
        var role = Role(jobName);
        if (role is null || !sortMinuteByKey.TryGetValue(Key(jobName), out var mine) || mine is not { } me || me < 0) return [];
        return role.Needs.Where(n => sortMinuteByKey.TryGetValue(n, out var t) && t is { } other && other >= 0 && other >= me).ToArray();
    }

    /// SCHED-1.1 / 1.4 (framework): a job on its own timer is started by the clock; the container's execution guard makes
    /// an execution that finds the previous one still running start nothing. So a time of day NEVER OVERLAPS -- but a
    /// clock interval is NOT "after it finishes" (only the flow counts from the finish), and the page says which it is.
    public const string NeverOverlaps = " (never overlaps the previous run)";
    public const string OnTheClock = ", on the clock -- skipped while the previous run is still running";

    public static Described Describe(string? cron, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(cron)) return new("Runs only when started", null, null);
        var f = cron.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (f.Length != 5) return new("Custom schedule (" + cron + ")", null, null);
        string mi = f[0], ho = f[1], dom = f[2], mon = f[3], dow = f[4];
        bool Int(string s, int lo, int hi, out int v) => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out v) && v >= lo && v <= hi;
        static string Hm(int h, int m) => h.ToString("00", CultureInfo.InvariantCulture) + ":" + m.ToString("00", CultureInfo.InvariantCulture);

        // every N minutes
        if (mi.StartsWith("*/", StringComparison.Ordinal) && Int(mi[2..], 1, 59, out var everyMin) && ho == "*" && dom == "*" && mon == "*" && dow == "*")
        {
            var t = new DateTimeOffset(nowUtc.Year, nowUtc.Month, nowUtc.Day, nowUtc.Hour, 0, 0, TimeSpan.Zero);
            while (t <= nowUtc) t = t.AddMinutes(everyMin);
            return new((everyMin == 1 ? "Every minute" : $"Every {everyMin} minutes") + OnTheClock, t, -1);
        }
        if (!Int(mi, 0, 59, out var m)) return new("Custom schedule (" + cron + ")", null, null);
        // hourly / every N hours
        if (ho == "*" && dom == "*" && mon == "*" && dow == "*")
        {
            var t = new DateTimeOffset(nowUtc.Year, nowUtc.Month, nowUtc.Day, nowUtc.Hour, m, 0, TimeSpan.Zero);
            if (t <= nowUtc) t = t.AddHours(1);
            return new($"Every hour at :{m:00}" + OnTheClock, t, -1);
        }
        if (ho.StartsWith("*/", StringComparison.Ordinal) && Int(ho[2..], 1, 23, out var everyH) && dom == "*" && mon == "*" && dow == "*")
        {
            var t = new DateTimeOffset(nowUtc.Year, nowUtc.Month, nowUtc.Day, 0, m, 0, TimeSpan.Zero);
            while (t <= nowUtc) t = t.AddHours(everyH);
            return new($"Every {everyH} hours at :{m:00} (from 00:{m:00} UTC)" + OnTheClock, t, m);
        }
        if (!Int(ho, 0, 23, out var h)) return new("Custom schedule (" + cron + ")", null, null);
        var today = new DateTimeOffset(nowUtc.Year, nowUtc.Month, nowUtc.Day, h, m, 0, TimeSpan.Zero);
        var sort = h * 60 + m;
        // daily
        if (dom == "*" && mon == "*" && dow == "*")
            return new($"Daily at {Hm(h, m)} UTC" + NeverOverlaps, today > nowUtc ? today : today.AddDays(1), sort);
        // weekly on one weekday (0 or 7 = Sunday)
        if (dom == "*" && mon == "*" && Int(dow, 0, 7, out var wd))
        {
            wd %= 7;
            var t = today;
            while ((int)t.DayOfWeek != wd || t <= nowUtc) t = t.AddDays(1);
            return new($"{Days[wd]} at {Hm(h, m)} UTC" + NeverOverlaps, t, sort);
        }
        // weekdays Monday-Friday
        if (dom == "*" && mon == "*" && dow == "1-5")
        {
            var t = today;
            while (t.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday || t <= nowUtc) t = t.AddDays(1);
            return new($"Weekdays at {Hm(h, m)} UTC" + NeverOverlaps, t, sort);
        }
        // monthly on a day of the month
        if (mon == "*" && dow == "*" && Int(dom, 1, 31, out var d))
        {
            var t = nowUtc;
            for (var i = 0; i < 400; i++)
            {
                var y = nowUtc.AddMonths(i);
                if (d > DateTime.DaysInMonth(y.Year, y.Month)) continue;
                var c = new DateTimeOffset(y.Year, y.Month, d, h, m, 0, TimeSpan.Zero);
                if (c > nowUtc) { t = c; break; }
            }
            return new($"Monthly on day {d} at {Hm(h, m)} UTC" + NeverOverlaps, t, sort);
        }
        return new("Custom schedule (" + cron + ")", null, sort);
    }

    /// The schedule editor's fields (operator 2026-10-04: "where is the edit button so i can control start time").
    public sealed record Editor(string Often, string Time, int Weekday, int DayOfMonth, int EveryHours, string Custom);

    public static readonly string[] OftenChoices = ["daily", "weekdays", "weekly", "monthly", "hours", "custom"];

    /// The fields that show an existing cron; a shape the editor does not know opens as "custom" with the expression.
    public static Editor ToEditor(string? cron)
    {
        var c = (cron ?? "").Trim();
        var f = c.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        bool Int(string s, int lo, int hi, out int v) => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out v) && v >= lo && v <= hi;
        static string Hm(int h, int m) => h.ToString("00", CultureInfo.InvariantCulture) + ":" + m.ToString("00", CultureInfo.InvariantCulture);
        if (f.Length == 5 && Int(f[0], 0, 59, out var m))
        {
            if (f[1].StartsWith("*/", StringComparison.Ordinal) && Int(f[1][2..], 1, 23, out var n) && f[2] == "*" && f[3] == "*" && f[4] == "*")
                return new("hours", Hm(0, m), 1, 1, n, c);
            if (Int(f[1], 0, 23, out var h) && f[3] == "*")
            {
                if (f[2] == "*" && f[4] == "*") return new("daily", Hm(h, m), 1, 1, 6, c);
                if (f[2] == "*" && f[4] == "1-5") return new("weekdays", Hm(h, m), 1, 1, 6, c);
                if (f[2] == "*" && Int(f[4], 0, 7, out var wd)) return new("weekly", Hm(h, m), wd % 7, 1, 6, c);
                if (f[4] == "*" && Int(f[2], 1, 28, out var d)) return new("monthly", Hm(h, m), 1, d, 6, c);
            }
        }
        return new("custom", "04:00", 1, 1, 6, c);
    }

    /// The cron for the editor's fields. Throws ArgumentException with a sentence a person can act on.
    public static string ToCron(string? often, string? time, int weekday, int dayOfMonth, int everyHours, string? custom)
    {
        var o = (often ?? "").Trim().ToLowerInvariant();
        if (o == "custom") return (custom ?? "").Trim();
        var t = (time ?? "").Trim();
        var mt = System.Text.RegularExpressions.Regex.Match(t, @"^([01]?\d|2[0-3]):([0-5]\d)$");
        if (!mt.Success) throw new ArgumentException("the start time must be HH:mm (00:00-23:59, UTC)");
        var h = int.Parse(mt.Groups[1].Value, CultureInfo.InvariantCulture);
        var m = int.Parse(mt.Groups[2].Value, CultureInfo.InvariantCulture);
        string I(int v) => v.ToString(CultureInfo.InvariantCulture);
        return o switch
        {
            "daily" => $"{I(m)} {I(h)} * * *",
            "weekdays" => $"{I(m)} {I(h)} * * 1-5",
            "weekly" => weekday is >= 0 and <= 6 ? $"{I(m)} {I(h)} * * {I(weekday)}" : throw new ArgumentException("choose a weekday"),
            // 1-28: every month has the day, so the job never silently skips a month
            "monthly" => dayOfMonth is >= 1 and <= 28 ? $"{I(m)} {I(h)} {I(dayOfMonth)} * *" : throw new ArgumentException("the day of the month must be 1-28 (every month has it)"),
            "hours" => everyHours is >= 1 and <= 12 ? $"{I(m)} */{I(everyHours)} * * *" : throw new ArgumentException("every 1-12 hours"),
            _ => throw new ArgumentException("choose how often the job runs"),
        };
    }

    /// A machine timestamp for a <time datetime> attribute (the browser shows it in the viewer's own clock).
    public static string Iso(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// "in 9 h 12 min" / "in 3 days" -- how far away the next run is.
    public static string Until(DateTimeOffset next, DateTimeOffset nowUtc)
    {
        var s = next - nowUtc;
        if (s.TotalMinutes < 1) return "in less than a minute";
        if (s.TotalHours < 1) return $"in {(int)s.TotalMinutes} min";
        if (s.TotalDays < 2) return $"in {(int)s.TotalHours} h {s.Minutes} min";
        return $"in {(int)s.TotalDays} days";
    }
}
