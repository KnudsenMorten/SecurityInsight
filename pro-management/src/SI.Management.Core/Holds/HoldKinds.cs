using System.Text.Json;

namespace SI.Management.Core.Holds;

/// One reason SecurityInsight holds a report back ON PURPOSE at its last complete result (#902): its kind (the stored
/// sidata.RaReportStatus.HoldKind), its catalogue code (information), its escalation code (the same report held
/// escalateAfterDetailedRuns Detailed runs in a row) and whether an Admin may accept its source as empty for good.
public sealed record HoldKind(string Kind, string Code, string EscalationCode, bool AcceptEmpty);

/// One code of the error catalogue as the web app shows it: its title and the customer's sentence.
public sealed record CatalogueEntry(string Code, string Title, string CustomerText);

/// <summary>
/// THE ONE LIST of hold kinds (#902) -- an embedded copy of data-model/hold-kinds.locked.json (ProData/DataModel, held to
/// the original by a test), the same file the engine reads (engine/_shared/SI-HoldKinds.ps1). With it the error catalogue
/// (data-model/errors.locked.json, also embedded), so the page shows the catalogue's own words for a code. The safe direction:
/// a kind that is not in the list is NOT a hold -- the report is shown as not complete, as a real failure.
/// </summary>
public sealed class HoldKindList
{
    public int EscalateAfterDetailedRuns { get; }
    public IReadOnlyList<HoldKind> Kinds { get; }
    private readonly IReadOnlyDictionary<string, CatalogueEntry> _catalogue;

    public HoldKindList(int escalateAfterDetailedRuns, IReadOnlyList<HoldKind> kinds, IReadOnlyDictionary<string, CatalogueEntry>? catalogue = null)
    {
        EscalateAfterDetailedRuns = escalateAfterDetailedRuns < 1 ? 3 : escalateAfterDetailedRuns;
        Kinds = kinds;
        _catalogue = catalogue ?? new Dictionary<string, CatalogueEntry>(StringComparer.OrdinalIgnoreCase);
    }

    /// The list entry of a stored kind; null for an empty or unknown kind.
    public HoldKind? Find(string? kind) =>
        string.IsNullOrWhiteSpace(kind) ? null : Kinds.FirstOrDefault(k => string.Equals(k.Kind, kind.Trim(), StringComparison.Ordinal));

    /// A hold is escalated (a real problem) only on a Detailed run, held this many runs in a row or more.
    public bool IsEscalated(int? heldRuns, string? grain) =>
        string.Equals(grain, "Detailed", StringComparison.Ordinal) && heldRuns is { } n && n >= EscalateAfterDetailedRuns;

    /// The code of a stored kind (its escalation code when escalated); null for an unknown kind.
    public string? CodeOf(string? kind, bool escalated) => Find(kind) is { } k ? (escalated ? k.EscalationCode : k.Code) : null;

    public CatalogueEntry? Entry(string? code) => code is not null && _catalogue.TryGetValue(code, out var e) ? e : null;

    public static string CodeUrl(string code) => "https://invardia.com/docs/si/errors/" + code.ToLowerInvariant() + "/";

    private static Stream Resource(string name) =>
        typeof(HoldKindList).Assembly.GetManifestResourceStream("DataModel/" + name)
        ?? throw new InvalidOperationException($"the embedded data model file {name} is missing from the build");

    /// PURE. The list from the two files' text.
    public static HoldKindList Load(string holdKindsJson, string? errorsJson)
    {
        using var doc = JsonDocument.Parse(holdKindsJson);
        var root = doc.RootElement;
        var n = root.TryGetProperty("escalateAfterDetailedRuns", out var e) && e.ValueKind == JsonValueKind.Number ? e.GetInt32() : 3;
        var kinds = new List<HoldKind>();
        if (root.TryGetProperty("kinds", out var ks) && ks.ValueKind == JsonValueKind.Array)
            foreach (var k in ks.EnumerateArray())
            {
                var kind = Str(k, "kind"); var code = Str(k, "code"); var esc = Str(k, "escalationCode");
                if (kind is null || code is null || esc is null) continue;
                kinds.Add(new HoldKind(kind, code.ToLowerInvariant(), esc.ToLowerInvariant(), k.TryGetProperty("acceptEmpty", out var a) && a.ValueKind == JsonValueKind.True));
            }
        var cat = new Dictionary<string, CatalogueEntry>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(errorsJson))
        {
            using var ed = JsonDocument.Parse(errorsJson);
            if (ed.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var x in ed.RootElement.EnumerateArray())
                    if (Str(x, "code") is { } c) cat[c] = new CatalogueEntry(c, Str(x, "title") ?? c, Str(x, "customerText") ?? "");
        }
        return new HoldKindList(n, kinds, cat);
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()) ? v.GetString()!.Trim() : null;

    private static readonly Lazy<HoldKindList> Lazy = new(() =>
    {
        try
        {
            using var h = new StreamReader(Resource("hold-kinds.locked.json"));
            using var c = new StreamReader(Resource("errors.locked.json"));
            return Load(h.ReadToEnd(), c.ReadToEnd());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            // nothing readable: no kinds, so every report is shown as it is stored (not complete) -- never hidden as held
            return new HoldKindList(3, Array.Empty<HoldKind>());
        }
    });

    /// The shipped list (embedded copies of the data-model files).
    public static HoldKindList Default => Lazy.Value;
}
