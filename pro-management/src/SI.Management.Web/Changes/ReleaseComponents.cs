using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>
/// One component of the installed code (CR3, #657; framework 12.11e item 3): a collection per source, the correlation,
/// Risk Analysis per report or data out per channel (config\release-scopes.locked.json). The updater records the
/// fingerprint of each after it installed a release; a component whose code changed is TESTING until it has had 3 good
/// daily runs (the engines count them at the end of each run), then STABLE again. Never changed since it was recorded =
/// Stable. Written by engine\_shared\SI-ReleaseControl.ps1 into cfg.ReleaseScope; this page only reads it.
/// </summary>
public sealed record ReleaseComponent(string Scope, DateTime? ChangedUtc, string? ChangedVersion, int GoodDays)
{
    public bool Testing => ChangedUtc is not null && GoodDays < ReleaseComponents.StableGoodDays;
}

public sealed record ReleaseComponents(IReadOnlyList<ReleaseComponent> Rows)
{
    /// The good daily runs after which a changed component is Stable again (the same number as SI-ReleaseControl.ps1).
    public const int StableGoodDays = 3;

    public IReadOnlyList<ReleaseComponent> Testing => Rows.Where(r => r.Testing).OrderBy(r => r.Scope, StringComparer.Ordinal).ToList();
    public int Stable => Rows.Count(r => !r.Testing);

    /// One plain line: "All 147 components are stable." or "3 of 147 components are testing after release 3.0.1 ...".
    public string Summary
    {
        get
        {
            if (Rows.Count == 0) return "No components recorded yet -- the updater records them with the next release it installs.";
            var t = Testing;
            if (t.Count == 0) return $"All {Rows.Count} components are stable.";
            var versions = t.Select(r => r.ChangedVersion).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct().ToList();
            var after = versions.Count == 1 ? " after release " + versions[0] : "";
            return $"{t.Count} of {Rows.Count} components are testing{after}: their code changed, and each is stable again after {StableGoodDays} good daily runs.";
        }
    }

    /// The testing components in words: "collection.identity (1 of 3 good days)".
    public static string Line(ReleaseComponent c) => $"{c.Scope} ({Math.Min(c.GoodDays, StableGoodDays)} of {StableGoodDays} good days)";
}

public sealed class ReleaseComponentsReader(ISqlExecutor sql)
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.ReleaseScope') IS NOT NULL SELECT Scope, ChangedUtc, ChangedVersion, GoodDays FROM cfg.ReleaseScope;
""";

    /// null = this install has no component table yet (a release before CR3).
    public async Task<ReleaseComponents?> ReadAsync(CancellationToken ct)
    {
        var rows = await sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct).ConfigureAwait(false);
        if (rows.Count == 0) return null;
        return new ReleaseComponents(rows.Where(r => r.Str("Scope") is { Length: > 0 })
            .Select(r => new ReleaseComponent(r.Str("Scope")!, r.Date("ChangedUtc"), r.Str("ChangedVersion"), (int)(r.Long("GoodDays") ?? 0))).ToList());
    }
}
