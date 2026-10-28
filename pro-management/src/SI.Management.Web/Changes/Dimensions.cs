using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// Classification dimensions on findings and assets -- pure, no I/O. A dimension (the first is 'component': OS, SQL,
/// Network, Hardware, Browser, Office, Application, Other) is data: data-model/dimensions.locked.json, published into the
/// Pro database as one 'datamodel' row per dimension, keyed 'dimensions:&lt;dimension&gt;'. Its body carries the VALUES:
/// <code>
///   { "id": "component", "name": "Component", "default": "Other", "field": "si_component",
///     "values": [ { "value": "OS", "description": "..." } | "OS", ... ] }
/// </code>
/// WHICH value a finding or asset gets is decided by the ONE generic classification mapping (<see cref="ClassificationMapping"/>):
/// its rows that target the dimension's field (si_&lt;dimension&gt;). No match = the default (Other), never blank. A
/// dimension row that still carries 'rules' of its own is shown and validated, but the GUI writes classification rows.
/// </summary>
public static partial class Dimensions
{
    public const string Template = "dimensions";
    public const int MaxValues = 100;

    [GeneratedRegex(@"^[a-z][a-z0-9_]{0,40}$", RegexOptions.CultureInvariant)]
    private static partial Regex DimensionId();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._/&+\-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex PlainValue();

    [GeneratedRegex(@"^si_[a-z0-9_]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SiField();

    public sealed record ValueView(string Value, string Description);
    public sealed record DimensionView(DataModelRow Row, string Id, string Name, string Description, string Default, string Field, IReadOnlyList<ValueView> Values, int OwnRules);

    /// The dimensions of a row list, parsed for display (an unreadable body shows its key only).
    public static IReadOnlyList<DimensionView> Of(IEnumerable<DataModelRow> rows) =>
        rows.Where(r => r.Template == Template && r.Item.Length > 0).Select(View).ToList();

    private static string S(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    public static DimensionView View(DataModelRow r)
    {
        var body = r.Effective ?? r.TemplateBody ?? r.OverrideBody;
        try
        {
            using var d = JsonDocument.Parse(body ?? "{}");
            var o = d.RootElement;
            var values = Values(o);
            var id = S(o, "id") is { Length: > 0 } i ? i : r.Item;
            var def = S(o, "default") is { Length: > 0 } df ? df : values.Any(v => v.Value == "Other") ? "Other" : "";
            var field = S(o, "field") is { Length: > 0 } f && SiField().IsMatch(f) ? f : "si_" + id;
            var own = o.TryGetProperty("rules", out var rs) && rs.ValueKind == JsonValueKind.Array ? rs.GetArrayLength() : 0;
            return new DimensionView(r, id, S(o, "name") is { Length: > 0 } n ? n : id, S(o, "description"), def, field, values, own);
        }
        catch (JsonException) { return new DimensionView(r, r.Item, r.Item, "", "", "si_" + r.Item, Array.Empty<ValueView>(), 0); }
    }

    private static List<ValueView> Values(JsonElement o)
    {
        var list = new List<ValueView>();
        if (!(o.TryGetProperty("values", out var vs) && vs.ValueKind == JsonValueKind.Array)) return list;
        foreach (var v in vs.EnumerateArray())
        {
            if (v.ValueKind == JsonValueKind.String) list.Add(new ValueView(v.GetString() ?? "", ""));
            else if (v.ValueKind == JsonValueKind.Object) list.Add(new ValueView(S(v, "value") is { Length: > 0 } x ? x : S(v, "name"), S(v, "description")));
        }
        return list;
    }


    /// A dimension / classification value as the mechanism accepts it (Test-SIDimensionItem): one line of at most 64
    /// characters, without ';'.
    public static bool IsPlainValue(string? v) => !string.IsNullOrWhiteSpace(v) && v.Trim().Length <= 64 && v.IndexOfAny(new[] { '\r', '\n', '\t', ';' }) < 0;

    /// The reasons a dimension body is refused -- delegated to THE validator of the mechanism,
    /// ClassificationItemValidator.Dimension (the twin of Test-SIDimensionItem).
    public static IReadOnlyList<string> Validate(string item, JsonElement o) => ClassificationItemValidator.Dimension(item, o);
}
