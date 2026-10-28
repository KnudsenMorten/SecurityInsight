using SI.Management.Core.ProData;

namespace SI.Management.Web.Outputs;

/// One column as the column builder posts it: sent or not, the name it is sent as (empty = its own), its place (1 = first).
public sealed record BuilderColumn(string Target, bool Send, string? Name, int? Place);

/// A column the builder adds: its key, the field it reads, the name it is sent as.
public sealed record BuilderAdd(string Target, string From, string? Name);

/// One change the builder stages (an <see cref="OutputMapChanges"/> action on one column).
public sealed record BuilderStep(string Action, string Target, string? From, string? Name, int? Position, bool SetPosition);

/// What a builder post comes to: the columns sent in their order (the preview), the changes to stage, and what is wrong.
public sealed record BuilderPlan(IReadOnlyList<OutputColumn> Sent, IReadOnlyList<BuilderStep> Steps, IReadOnlyList<string> Problems);

/// <summary>
/// THE COLUMN BUILDER of an output (owner 2026-10-19, Configuration &gt; Connectors &gt; Fields sent: "the column builder
/// (picker, order, rename, remove, add) + the 10-row preview, through Review &amp; commit"). PURE: from the map in force
/// and the builder's post to the columns sent (in order) and the changes, one staged change per column changed --
/// remove (stop sending), put back, change (a new name and / or place), add -- each through Review &amp; commit. A moved
/// column carries its place; the columns that keep their relative order carry none (<see cref="OutputMapRules.Places"/>),
/// so moving one column changes one column.
/// </summary>
public static class OutputColumnBuilder
{
    private static string? N(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    public static BuilderPlan Plan(OutputMapView map, IReadOnlyList<BuilderColumn> posted, IReadOnlyList<BuilderAdd> adds)
    {
        var problems = new List<string>();
        var byTarget = map.Columns.ToDictionary(c => c.InForce.Target, StringComparer.Ordinal);
        var known = posted.Where(p => byTarget.ContainsKey(p.Target)).ToList();
        foreach (var p in posted.Where(p => !byTarget.ContainsKey(p.Target))) problems.Add($"the output has no column '{p.Target}' -- reload the page");
        var newOnes = adds.Where(a => N(a.Target) is not null || N(a.From) is not null).Select(a => a with { Target = (a.Target ?? "").Trim(), From = (a.From ?? "").Trim() }).ToList();
        foreach (var a in newOnes)
        {
            if (a.Target.Length == 0) problems.Add("name the new column");
            else if (a.From.Length == 0) problems.Add($"choose the field the new column '{a.Target}' reads");
            else if (byTarget.ContainsKey(a.Target) || newOnes.Count(x => x.Target == a.Target) > 1) problems.Add($"the output already has a column '{a.Target}'");
        }
        // the order sent: the ticked columns by their place (equal places keep the list's order), then the new ones
        var sentPosted = known.Select((p, i) => (p, i)).Where(x => x.p.Send).OrderBy(x => x.p.Place ?? x.i + 1).ThenBy(x => x.i).Select(x => x.p).ToList();
        var wanted = sentPosted.Select(p => p.Target).Concat(newOnes.Select(a => a.Target)).ToList();
        var places = OutputMapRules.Places(map.MapOrder, wanted);
        var steps = new List<BuilderStep>();
        foreach (var p in known)
        {
            var row = byTarget[p.Target];
            var name = N(p.Name) is { } nm && nm != row.InForce.Target ? nm : null;
            if (!p.Send)
            {
                if (!row.Removed) steps.Add(new BuilderStep("remove", p.Target, null, null, null, false));
                continue;
            }
            var place = places.GetValueOrDefault(p.Target);
            if (row.Removed)
            {
                steps.Add(name is null && place is null && !row.Own ? new BuilderStep("restore", p.Target, null, null, null, false)
                    : new BuilderStep("change", p.Target, null, name, place, true));
                continue;
            }
            if (name != N(row.InForce.As) || place != row.InForce.Position) steps.Add(new BuilderStep("change", p.Target, null, name, place, true));
        }
        foreach (var a in newOnes.Where(a => a.Target.Length > 0 && a.From.Length > 0))
            steps.Add(new BuilderStep("add", a.Target, a.From, N(a.Name), places.GetValueOrDefault(a.Target), true));
        var sent = sentPosted.Select(p => byTarget[p.Target].InForce with { As = N(p.Name), Position = null })
            .Concat(newOnes.Select(a => new OutputColumn(a.Target, a.From, null, N(a.Name)))).ToList();
        return new BuilderPlan(sent, steps, problems);
    }
}
