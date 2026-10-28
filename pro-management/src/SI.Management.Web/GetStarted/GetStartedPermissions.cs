using System.Text.Json;
using SI.Management.Core;
using SI.Management.Web.Pages.Admin;

namespace SI.Management.Web.GetStarted;

/// One permission an engine's own check could not confirm: Area ("Microsoft Graph", "Azure", "Pro database"), Item (the
/// permission or role), State ("missing" or "not-checked") and Fix (what to run -- plain words, from the catalog).
public sealed record PermissionGap(string Area, string Item, string State, string Fix)
{
    public bool Missing => State.Equals("missing", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// What one engine's run said about its own permissions -- the run-health END record's PermissionGaps (written by
/// engine/_shared/SI-PermissionCheck.ps1, catalog config/permissions.locked.json): the engine, the identity it ran as
/// (client id), the gaps and the items it could not check. <see cref="Error"/> set = the check itself could not run (or
/// the record could not be read): counted as open, never as done.
/// </summary>
public sealed record PermissionReport(string Engine, string Identity, string Label, IReadOnlyList<PermissionGap> Items, int More, string? Error)
{
    public IEnumerable<PermissionGap> Missing => Items.Where(i => i.Missing);
    public IEnumerable<PermissionGap> NotChecked => Items.Where(i => !i.Missing);
}

/// <summary>One engine's newest permission check in the window. <see cref="Report"/> null = the engine ran but none of its
/// End records carried a check (an older build); <see cref="When"/> null and no report = it did not run at all.</summary>
public sealed record EnginePermissions(string Engine, DateTimeOffset? When, PermissionReport? Report)
{
    public bool Checked => Report is { Error: null };
}

/// <summary>
/// GET STARTED > PERMISSIONS (operator 2026-10-08: "make sure to add permissions into the get started so we can verify we
/// have the needed permissions"). The web app cannot read other identities' grants; every engine checks its OWN at run
/// start and records the result on its run-health END record. This turns those records into the step: the newest check
/// of each engine in the last <see cref="GetStartedGuide.RunDays"/> days. Pure.
/// A gap of the area "Pro database" names what the engine met: no database user for its identity (the sign-in was
/// refused by a database that answered), or the database could not be reached at all (its server's firewall refused the
/// job) -- the engines tell the two apart (engine/_shared/SI-PermissionCheck.ps1), and the page shows the item and its fix.
/// </summary>
public static class GetStartedPermissions
{
    /// The engines whose check must be on record for the step to be done: the four sources and Risk Analysis.
    public static readonly IReadOnlyList<string> ExpectedEngines = [.. GetStartedGuide.SourceEngines, "risk-analysis"];

    /// The PermissionGaps JSON of one record; null when the record carries none (blank). A value that cannot be read is a
    /// report with <see cref="PermissionReport.Error"/> set -- never silently "no gaps".
    public static PermissionReport? Parse(string engine, string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object) return new(engine, "", "", Array.Empty<PermissionGap>(), 0, "the permission record could not be read");
            static string S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
            var items = new List<PermissionGap>();
            if (r.TryGetProperty("items", out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var i in arr.EnumerateArray())
                    if (i.ValueKind == JsonValueKind.Object)
                        items.Add(new PermissionGap(S(i, "area"), S(i, "item"), S(i, "state") is { Length: > 0 } st ? st : "missing", S(i, "fix")));
            var more = r.TryGetProperty("more", out var m) && m.ValueKind == JsonValueKind.Number && m.TryGetInt32(out var mv) ? mv : 0;
            var err = S(r, "error");
            var eng = S(r, "engine");
            return new(eng.Length > 0 ? eng : engine, S(r, "identity"), S(r, "label"), items, more, err.Length > 0 ? err : null);
        }
        catch (JsonException) { return new(engine, "", "", Array.Empty<PermissionGap>(), 0, "the permission record could not be read"); }
    }

    /// <summary>
    /// Per engine, the newest END record of the engine's OWN runs (never the job flow's step records 'flow:&lt;engine&gt;',
    /// which speak for the flow's identity) that carries a check; an engine whose records carry none is listed with no report.
    /// The expected engines are always listed (no run = no record). Ordered: expected engines first, then by name.
    /// </summary>
    public static IReadOnlyList<EnginePermissions> Latest(IEnumerable<RunHealthRow> rows)
    {
        var own = rows.Where(r => !RunHealthModel.IsStart(r.Phase) && !RunHealthModel.IsGuardEvent(r.Phase))
            .Select(r => (Row: r, Engine: RunHealthModel.EngineOf(r.Engine, out var viaFlow), ViaFlow: viaFlow))
            .Where(x => !x.ViaFlow && x.Engine.Length > 0)
            .GroupBy(x => x.Engine, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g =>
            {
                var withCheck = g.Where(x => !string.IsNullOrWhiteSpace(x.Row.PermissionGaps)).OrderByDescending(x => x.Row.When).FirstOrDefault();
                return withCheck.Row is { } row
                    ? new EnginePermissions(g.First().Engine, row.When, Parse(g.First().Engine, row.PermissionGaps))
                    : new EnginePermissions(g.First().Engine, g.Max(x => x.Row.When), null);
            }, StringComparer.OrdinalIgnoreCase);
        var list = new List<EnginePermissions>();
        foreach (var e in ExpectedEngines) list.Add(own.TryGetValue(e, out var p) ? p : new EnginePermissions(e, null, null));
        list.AddRange(own.Values.Where(p => !ExpectedEngines.Contains(p.Engine, StringComparer.OrdinalIgnoreCase)).OrderBy(p => p.Engine, StringComparer.OrdinalIgnoreCase));
        return list;
    }

    /// The engines as read, plus every expected engine that is not among them (no run = not checked).
    public static IReadOnlyList<EnginePermissions> WithExpected(IReadOnlyList<EnginePermissions>? engines)
    {
        var list = (engines ?? Array.Empty<EnginePermissions>()).ToList();
        foreach (var e in ExpectedEngines)
            if (!list.Any(p => p.Engine.Equals(e, StringComparison.OrdinalIgnoreCase))) list.Add(new EnginePermissions(e, null, null));
        return list;
    }

    /// Why an engine's check is not on record, in a few words. <paramref name="young"/> = an install on which "no run in
    /// 7 days" would be wrong (<see cref="GetStartedGuide.Young"/>): it then says "not run yet".
    public static string NotCheckedReason(EnginePermissions p, bool young = false) =>
        p.Report is { Error: { } err } ? "could not be checked (" + err + ")"
        : p.When is null ? (young ? "not checked yet (not run yet)" : "not checked yet (no run in " + GetStartedGuide.RunDays + " days)")
        : "not checked yet (its newest run did not record a check)";

    /// An engine that has not run at all in the window: nothing on record, and nothing wrong.
    public static bool NotRun(EnginePermissions p) => p.When is null && p.Report is null;

    public static string Label(string engine) => engine.Equals("risk-analysis", StringComparison.OrdinalIgnoreCase) ? "Risk Analysis" : GetStartedGuide.SourceLabel(engine);

    /// One identity and what its engines reported: the distinct gaps (each with the engines that reported it) and the
    /// distinct items that could not be checked.
    public sealed record IdentityGroup(string Identity, string Label, IReadOnlyList<string> Engines, IReadOnlyList<(PermissionGap Gap, IReadOnlyList<string> Engines)> Missing,
        IReadOnlyList<(PermissionGap Gap, IReadOnlyList<string> Engines)> NotChecked, int More);

    /// The checked engines grouped by the identity they ran as (several engines share the collection identity).
    public static IReadOnlyList<IdentityGroup> Groups(IEnumerable<EnginePermissions> engines)
    {
        static IReadOnlyList<(PermissionGap, IReadOnlyList<string>)> Collect(IEnumerable<(EnginePermissions P, PermissionGap G)> xs) =>
            xs.GroupBy(x => (x.G.Area.ToLowerInvariant(), x.G.Item.ToLowerInvariant()))
              .Select(g => (g.First().G, (IReadOnlyList<string>)g.Select(x => x.P.Engine).Distinct(StringComparer.OrdinalIgnoreCase).ToList()))
              .ToList();
        return engines.Where(p => p.Checked)
            .GroupBy(p => p.Report!.Identity.Length > 0 ? p.Report.Identity.ToLowerInvariant() : "?" + p.Engine)
            .Select(g =>
            {
                var first = g.First().Report!;
                return new IdentityGroup(first.Identity, first.Label, g.Select(p => p.Engine).ToList(),
                    Collect(g.SelectMany(p => p.Report!.Missing.Select(x => (p, x)))),
                    Collect(g.SelectMany(p => p.Report!.NotChecked.Select(x => (p, x)))),
                    g.Max(p => p.Report!.More));
            })
            .ToList();
    }

    /// <summary>
    /// The step: done when every expected engine's newest check is on record, no engine's check failed to run, and no
    /// engine reports a missing permission. Items that could not be checked are said, never counted as missing.
    /// </summary>
    public static StepCheck Check(GetStartedFacts f)
    {
        if (!f.Read("runs")) return new(false, "could not be read right now");
        var engines = WithExpected(f.Permissions);
        var groups = Groups(engines);
        var gaps = groups.Sum(g => g.Missing.Count);
        var gapEngines = engines.Count(p => p.Checked && p.Report!.Missing.Any());
        var notOnRecord = engines.Where(p => !p.Checked && (p.Report is not null || ExpectedEngines.Contains(p.Engine, StringComparer.OrdinalIgnoreCase))).ToList();
        // owner 2026-10-12: no gap, and the only engines without a check are the ones that have not run on an install
        // where no run has finished yet -- the step waits for the first run, it is not a list of five "not checked" lines
        if (gaps == 0 && notOnRecord.Count > 0 && notOnRecord.All(NotRun) && GetStartedGuide.FirstRun(f))
            return new(false, GetStartedGuide.WaitingForFirstRun(f), Waiting: true);
        var young = GetStartedGuide.Young(f);
        var parts = new List<string>();
        if (gaps > 0) parts.Add(Plural(gaps, "gap", "gaps") + " in " + Plural(gapEngines, "engine", "engines"));
        foreach (var p in notOnRecord) parts.Add(Label(p.Engine) + ": " + NotCheckedReason(p, young));
        if (parts.Count > 0) return new(false, string.Join("; ", parts));
        var checkedCount = engines.Count(p => p.Checked);
        var nc = groups.Sum(g => g.NotChecked.Count);
        return new(true, "no missing permissions in " + Plural(checkedCount, "engine", "engines") + (nc > 0 ? " (" + Plural(nc, "item", "items") + " could not be checked)" : ""));
    }

    private static string Plural(long n, string one, string many) => Pages.Fmt.Int(n) + " " + (n == 1 ? one : many);
}
