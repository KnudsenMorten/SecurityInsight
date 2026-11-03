using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Core;

/// <summary>
/// What is on the screen when a question is asked from a page's chat panel: the view, its collection, its filters
/// (from the page's URL, renamed to the tool argument names) and the selected asset or finding. It reaches the model
/// as JSON DATA in its own message -- never as page HTML and never inside the instructions. Everything is bounded and
/// sanitised here, because the browser posts it and a browser can post anything.
/// </summary>
public sealed partial record ChatPageContext
{
    public const int MaxFilters = 12;
    public const int MaxValueLength = 200;

    public string View { get; init; } = "";
    public string? Title { get; init; }
    public string? CollectionId { get; init; }
    public IReadOnlyDictionary<string, string> Filters { get; init; } = new Dictionary<string, string>();
    public string? SelectedAsset { get; init; }
    public string? SelectedFinding { get; init; }

    /// A page's URL key -> the name the tools use for it. Keys not listed keep their own name.
    public static readonly IReadOnlyDictionary<string, string> KeyNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["sev"] = "severity", ["dom"] = "domain", ["rep"] = "report", ["kind"] = "assetKind", ["q"] = "text", ["dim"] = "dimension",
    };

    /// URL keys that are paging, layout or plumbing -- not something the user is looking AT.
    private static readonly HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase) { "p", "page", "size", "cols", "handler", "skip", "returnUrl", "__RequestVerificationToken" };

    [GeneratedRegex(@"^[a-z0-9][a-z0-9\-/]{0,59}$", RegexOptions.CultureInvariant)]
    private static partial Regex ViewPattern();

    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9_]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyPattern();

    /// The context of one page from its view name, title and URL query: c / collection = the collection, asset = the
    /// selected asset, id = the selected finding; the rest are filters.
    public static ChatPageContext? FromQuery(string view, string? title, IEnumerable<KeyValuePair<string, string?>> query)
    {
        string? collection = null, asset = null, finding = null;
        var filters = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in query)
        {
            if (string.IsNullOrWhiteSpace(v) || Ignored.Contains(k)) continue;
            switch (k.ToLowerInvariant())
            {
                case "c": case "collection": case "collectionid": collection = v; break;
                case "asset": case "assetkey": asset = v; break;
                case "id": case "finding": case "findingid": finding = v; break;
                default: filters[KeyNames.TryGetValue(k, out var n) ? n : k] = v; break;
            }
        }
        return Sanitize(new ChatPageContext { View = view, Title = title, CollectionId = collection, SelectedAsset = asset, SelectedFinding = finding, Filters = filters });
    }

    /// Bounds every part; null when there is no usable view. Unknown shapes are dropped, never trimmed into something else.
    public static ChatPageContext? Sanitize(ChatPageContext? raw)
    {
        if (raw is null) return null;
        var view = (raw.View ?? "").Trim().ToLowerInvariant();
        if (!ViewPattern().IsMatch(view)) return null;
        var filters = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in raw.Filters ?? new Dictionary<string, string>())
        {
            if (filters.Count >= MaxFilters) break;
            if (k is null || !KeyPattern().IsMatch(k) || Ignored.Contains(k)) continue;
            // only a tool argument's name, with a value that argument takes: anything else on the URL is not passed on
            if (!ToolArguments.Contains(k)) continue;
            if (Clean(v) is { } c && ValueFits(k, c)) filters[k] = c;
        }
        return new ChatPageContext
        {
            View = view,
            Title = Clean(raw.Title, 80),
            CollectionId = Clean(raw.CollectionId, 64),
            SelectedAsset = Clean(raw.SelectedAsset, 400),
            SelectedFinding = Clean(raw.SelectedFinding, 64),
            Filters = filters,
        };
    }

    /// The argument names of the curated tools (collectionId has its own field): the only filter keys passed on.
    public static readonly IReadOnlySet<string> ToolArguments = EstateToolbox.All
        .SelectMany(t => { using var d = JsonDocument.Parse(t.ParametersJsonSchema); return d.RootElement.GetProperty("properties").EnumerateObject().Select(p => p.Name).ToList(); })
        .Where(n => n != "collectionId").ToHashSet(StringComparer.Ordinal);

    /// The fixed values of the arguments that take a list (severity, tier, domain, asset kind, sort, dimension, grain).
    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> Fixed = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
    {
        ["severity"] = ToolVocabulary.Severities.Concat(ToolVocabulary.SeverityWords.SelectMany(w => w.Item2.Append(w.Item1))).ToList(),
        ["tier"] = ProData.ProDataFilters.Tiers.Concat(ToolVocabulary.TierWords.SelectMany(w => w.Item2.Append(w.Item1))).ToList(),
        ["domain"] = ToolVocabulary.Domains.Concat(ToolVocabulary.DomainWords.SelectMany(w => w.Item2.Append(w.Item1))).ToList(),
        ["assetKind"] = ProData.ProDataFilters.AssetKinds.Concat(ToolVocabulary.AssetKindWords.SelectMany(w => w.Item2.Append(w.Item1))).ToList(),
        ["sort"] = ProData.FindingSorts.All.ToList(),
        ["dimension"] = ProData.TrendDimensions.All.ToList(),
        ["grain"] = ProData.Grains.All.ToList(),
    };

    /// A value the argument takes: each part of a list value (comma / pipe separated) is one of the argument's values; a
    /// number argument is a whole number; a free-text argument (text, report) passes as it is (bounded and cleaned).
    private static bool ValueFits(string key, string value)
    {
        if (Fixed.TryGetValue(key, out var allowed))
            return value.Split([',', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .All(p => allowed.Any(a => ToolVocabulary.Key(a) == ToolVocabulary.Key(p)));
        if (key is "days" or "weeks" or "top" or "skip" or "rows")
            return int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _);
        return true;
    }

    private static string? Clean(string? v, int max = MaxValueLength)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var t = v.Trim();
        if (t.Length > max || t.Any(char.IsControl)) return null;
        return t;
    }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = false };

    /// The context as the JSON the model receives.
    public string ToJson() => JsonSerializer.Serialize(new
    {
        view = View, title = Title, collectionId = CollectionId, filters = Filters, selectedAsset = SelectedAsset, selectedFinding = SelectedFinding,
    }, Json);
}
