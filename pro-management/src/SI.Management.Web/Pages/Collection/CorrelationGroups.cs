using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// How confident SecurityInsight is about a figure (or a record), shown the same way everywhere on the Correlation quality
/// page, in its asset list and in a CI's evidence: a coloured bar + a tinted background + a WORD (colour is never the only
/// signal). High = green, Good = teal, Check = amber, Act = red, Info = blue (neutral). A zero count is muted whatever its tone.
/// </summary>
public enum Tone { High, Good, Check, Act, Info }

public static class ToneText
{
    /// The CSS class (also the badge class): good / fair / warn / bad / info.
    public static string Css(this Tone t) => t switch { Tone.High => "good", Tone.Good => "fair", Tone.Check => "warn", Tone.Act => "bad", _ => "info" };
    /// The word next to the colour.
    public static string Word(this Tone t) => t switch { Tone.High => "High confidence", Tone.Good => "Good", Tone.Check => "Check", Tone.Act => "Act", _ => "Info" };
    /// The glyph next to the word (decoration; the word carries the meaning).
    public static string Glyph(this Tone t) => t switch { Tone.High or Tone.Good => "✓", Tone.Check => "!", Tone.Act => "✕", _ => "i" };
}

/// One figure box: what it counts, its tone, the filter that lists its assets (null = not a link) and what those assets
/// ARE in a sentence ("seen only by the Exposure Graph" -- the list's heading). <see cref="Marker"/> keeps the box's
/// data attribute for the tests and the docs screenshots.
public sealed record CorrelationTile(string Id, string Label, string? Sub, long Count, IReadOnlyList<(string Column, string Value)>? Filter, Tone Tone, string Title,
    (string Name, string Value)? Marker = null, string? Value = null)
{
    /// A zero is "nothing to do": muted, whatever the tone.
    public bool Zero => Value is null && Count == 0;
}

/// One group of figures: ONE plain question, what is good and bad, and (where something can be done) what to do.
public sealed record CorrelationGroup(string Id, string Question, string Hint, IReadOnlyList<CorrelationTile> Tiles, IReadOnlyList<string> Todo, string? Marker = null);

/// The page's figures, grouped and toned, from the pure <see cref="CorrelationReport"/>.
public static class CorrelationGroups
{
    /// exact = high confidence, strong = good, weak = check; anything else (a value a newer engine adds) = act.
    public static Tone ConfidenceTone(string confidence) => confidence.ToLowerInvariant() switch
    {
        "exact" => Tone.High, "strong" => Tone.Good, "weak" => Tone.Check, _ => Tone.Act,
    };

    /// "1 asset", "1.234 assets" (the viewer's number format).
    public static string Assets(long n) => Fmt.Int(n) + (n == 1 ? " asset" : " assets");

    private static string Named(string source) => source switch { "Exposure Graph" or "CMDB" => "the " + source, _ => source };

    private static (string, string)[] F(params (string, string)[] f) => f;

    public static IReadOnlyList<CorrelationGroup> Of(CorrelationReport r)
    {
        var groups = new List<CorrelationGroup>();
        string Pct(ReportFigure f) => Fmt.Pct(f.Share, 1);

        // 1) how many systems confirm each asset -- best first
        var b = r.SourceBuckets;
        groups.Add(new("sources", "How many systems confirm each asset?",
            "More is better: an asset seen by only one system may be a leftover or a gap.",
            new[]
            {
                new CorrelationTile("sources-3", "3 or more systems", Pct(b[2]), b[2].Count, b[2].Filter, Tone.High, "seen by 3 or more systems", ("data-bucket", b[2].Label)),
                new CorrelationTile("sources-2", "2 systems", Pct(b[1]), b[1].Count, b[1].Filter, Tone.Good, "seen by 2 systems", ("data-bucket", b[1].Label)),
                new CorrelationTile("sources-1", "1 system only", Pct(b[0]), b[0].Count, b[0].Filter, Tone.Check, "seen by one system only", ("data-bucket", b[0].Label)),
            }, Array.Empty<string>(), "data-buckets"));

        // 2) which system is the only one that knows them
        if (r.SingleSource.Count > 0)
            groups.Add(new("single", "Seen by one system only",
                "Check these: often stale cloud resources, or devices that are not in Defender.",
                r.SingleSource.Select(f => new CorrelationTile("single-" + f.Label, "only " + f.Label, null, f.Count, f.Filter, Tone.Check, "seen only by " + Named(f.Label), ("data-single", f.Label))).ToList(),
                new[]
                {
                    "Open each one. Gone? Remove it in the system that still lists it.",
                    "Real? Add it to the system that is missing (for example, onboard the device to Defender).",
                }, "data-single-source"));

        // 3) how the records were joined -- the confidence of each CI
        var joined = r.Confidence.Select(f => new CorrelationTile("confidence-" + f.Label, f.Label, Pct(f), f.Count, f.Filter, ConfidenceTone(f.Label),
            f.Label switch
            {
                "exact" => "joined on the same id in both systems (high confidence)",
                "strong" => "joined on a strong link (good)",
                "weak" => "joined on a weak match (check these)",
                _ => "joined as " + f.Label,
            }, ("data-confidence", f.Label))).ToList();
        joined.Add(new("conflicts", "conflict", "systems disagree", r.Conflicts.Count, r.Conflicts.Filter, Tone.Act, "where the systems disagree on a value", ("data-conflicts", r.Conflicts.Count.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        joined.Add(new("idchanged", "id change / merge", Fmt.Int(r.IdChanges) + " change(s)", r.IdChanged.Count, r.IdChanged.Filter, Tone.Info, "with an id change or merge", ("data-id-changes", r.IdChanges.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        joined.Add(new("duplicates", "possible duplicates", "same name, no shared id", r.PossibleDuplicates.Count, r.PossibleDuplicates.Filter, Tone.Check, "that may be duplicates (same name, no shared id)", ("data-duplicates", r.PossibleDuplicates.Count.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        groups.Add(new("joined", "How the records were joined",
            "exact = the same id in both systems (best) · strong = linked through the Exposure Graph or a CMDB rule · weak = by name only, worth a look · conflict = the systems disagree on a value · id change / merge = an asset got a new id · possible duplicates = the same name but no shared id.",
            joined,
            new[]
            {
                "Weak or possible duplicate: open the asset and compare its records under Evidence. The same machine? Give both records the same id in the source system or the CMDB; the next load joins them. Different machines: nothing to do.",
                "Conflict: correct the value in the system that reports it wrong.",
                "Id change / merge: for information; the asset kept its history.",
            }, "data-quality"));

        // 4) the CMDB
        if (r.Cmdb is { } cm)
        {
            var tiles = new List<CorrelationTile>
            {
                new("cmdb-rate", "match rate", "matched of matched + not in the CMDB", 0, null, cm.MatchRate is not { } mr ? Tone.Info : mr >= 90 ? Tone.High : mr >= 50 ? Tone.Check : Tone.Act,
                    "", ("data-match-rate", ""), cm.MatchRate is { } m ? Fmt.Pct(m, 1) : "-"),
                new("cmdb-matched", "in the CMDB", null, cm.Matched, F(("CmdbState", "matched")), Tone.High, "matched to a CMDB CI"),
                new("cmdb-si-only", "not in the CMDB", "seen by SecurityInsight only", cm.SiOnly, F(("CmdbState", "si-only")), Tone.Check, "seen by SecurityInsight but not in the CMDB"),
            };
            if (cm.Stale > 0) tiles.Add(new("cmdb-stale", "not judged", "the CMDB copy is too old", cm.Stale, F(("CmdbState", "stale")), Tone.Info, "not judged against the CMDB (its copy is too old)"));
            groups.Add(new("cmdb", "Against the CMDB", "Does your CMDB know the assets SecurityInsight found? A higher match rate is better.", tiles,
                new[] { "Not in the CMDB: add them to the CMDB, or check what its import leaves out." }, "data-cmdb-match"));
        }
        return groups;
    }

    /// The figure whose filter is exactly the URL's (order and case of the column names do not matter).
    public static CorrelationTile? Match(IEnumerable<CorrelationGroup> groups, IReadOnlyList<(string Column, string Value)> filter)
    {
        if (filter.Count == 0) return null;
        static string K((string Column, string Value) x) => x.Column.ToLowerInvariant() + "=" + x.Value;
        var want = filter.Select(K).ToHashSet(StringComparer.Ordinal);
        return groups.SelectMany(g => g.Tiles).FirstOrDefault(t => t.Filter is { Count: > 0 } f && f.Select(K).ToHashSet(StringComparer.Ordinal).SetEquals(want));
    }
}
