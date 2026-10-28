using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SI.Management.Web.Settings;

/// The editor a field gets on the Settings page, chosen from the catalog type.
public enum EditorKind
{
    /// bool with a shipped default: a checkbox.
    Toggle,
    /// bool whose default is "not set" (an older name or another switch decides): Not set / On / Off.
    TriState,
    /// int / number: a number input with the catalog's min and max.
    Number,
    /// enum: a dropdown with the catalog's plain words.
    Select,
    /// text: a text input (the catalog's pattern, if any).
    Text,
    /// list: chips -- type, Enter / comma adds one, x removes it (a mail list checks each address).
    Chips,
    /// secret: the Key Vault secret NAME, never a value.
    Secret,
    /// a value this page cannot show in a field (JSON), or a setting changed on its own page: a link.
    Elsewhere,
}

/// The on/off setting a field only works with, and whether it is in the state the field needs now.
public sealed record NeedState(CatalogSetting Other, bool WantOn, bool Met);

/// One field: the setting, the scope this field edits, the row there (null = the default applies), what it shows now.
public sealed record SettingField(CatalogSetting Setting, string Scope, SettingRow? Row, IReadOnlyList<SettingRow> OtherRows, EditorKind Editor,
    string Text, IReadOnlyList<string> Items, bool Changed, string? ElsewhereUrl, NeedState? Needs)
{
    public string Version => Row is null ? "" : Row.Version.ToString(CultureInfo.InvariantCulture);
    /// The value stored for this field's scope, in words (the default when none is).
    public string Status => Row is null ? "Default" : "Set here";
}

/// One card: one topic, its fields, one Save.
public sealed record SettingsCard(string Name, string Id, string? Description, IReadOnlyList<SettingField> Fields);

/// One category: its common cards, and the advanced ones shown on request.
public sealed record SettingsCategory(string Name, string Id, string? Description, IReadOnlyList<SettingsCard> Common, IReadOnlyList<SettingsCard> Advanced)
{
    public int Count => Common.Sum(c => c.Fields.Count) + Advanced.Sum(c => c.Fields.Count);
    public bool AllAdvanced => Common.Count == 0 && Advanced.Count > 0;
}

/// <summary>
/// The Settings page layout, driven by the catalog (PIM Manager's settings page is the model): categories shown one at a
/// time, one card per topic with one Save, a field per setting with the editor its type calls for. A setting without a
/// card sits on its category's "General" card (advanced: "More settings"); a setting whose group no category lists sits
/// in "Other" -- so nothing can disappear.
/// </summary>
public static class SettingsLayout
{
    public const string GeneralCard = "General";
    public const string MoreCard = "More settings";
    public const string OtherCategory = "Other";

    /// The category a setting is shown in: its card's category, else the category listing its group, else a category
    /// named like its group, else Other.
    public static string CategoryOf(SettingsCatalog catalog, CatalogSetting s)
    {
        if (!string.IsNullOrWhiteSpace(s.Card)
            && catalog.Cards.FirstOrDefault(c => string.Equals(c.Name, s.Card, StringComparison.OrdinalIgnoreCase)) is { } card
            && catalog.Categories.Any(c => string.Equals(c.Name, card.Category, StringComparison.OrdinalIgnoreCase)))
            return card.Category;
        foreach (var c in catalog.Categories)
            if (c.Groups.Contains(s.Group, StringComparer.OrdinalIgnoreCase)) return c.Name;
        foreach (var c in catalog.Categories)
            if (string.Equals(c.Name, s.Group, StringComparison.OrdinalIgnoreCase)) return c.Name;
        return OtherCategory;
    }

    /// The card a setting is shown on: its own, else General (common) or More settings (advanced).
    public static string CardOf(SettingsCatalog catalog, CatalogSetting s) =>
        !string.IsNullOrWhiteSpace(s.Card) && catalog.Cards.Any(c => string.Equals(c.Name, s.Card, StringComparison.OrdinalIgnoreCase)) ? s.Card!
        : s.Advanced ? MoreCard : GeneralCard;

    public static IReadOnlyList<SettingsCategory> Build(SettingsCatalog catalog, IEnumerable<CatalogSetting> settings, IReadOnlyList<SettingRow> rows)
    {
        var byName = rows.ToLookup(r => r.Name, StringComparer.OrdinalIgnoreCase);
        var catOrder = catalog.Categories.Select(c => c.Name).ToList();
        int CatRank(string n) { var i = catOrder.FindIndex(x => string.Equals(x, n, StringComparison.OrdinalIgnoreCase)); return i < 0 ? catOrder.Count : i; }
        var cardOrder = catalog.Cards.Select(c => c.Name).ToList();
        int CardRank(string n)
        {
            if (string.Equals(n, GeneralCard, StringComparison.Ordinal)) return int.MaxValue - 1;
            if (string.Equals(n, MoreCard, StringComparison.Ordinal)) return int.MaxValue;
            var i = cardOrder.FindIndex(x => string.Equals(x, n, StringComparison.OrdinalIgnoreCase)); return i < 0 ? cardOrder.Count : i;
        }
        var list = settings.ToList();
        var result = new List<SettingsCategory>();
        foreach (var cat in list.GroupBy(s => CategoryOf(catalog, s), StringComparer.OrdinalIgnoreCase).OrderBy(g => CatRank(g.Key)).ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            var diag = cat.All(s => s.Advanced);
            SettingsCard MakeCard(IGrouping<string, CatalogSetting> g, bool advanced)
            {
                var def = catalog.Cards.FirstOrDefault(c => string.Equals(c.Name, g.Key, StringComparison.OrdinalIgnoreCase));
                var fields = g.OrderBy(s => s.Advanced).ThenBy(s => FieldRank(catalog, s)).ThenBy(s => s.Title, StringComparer.OrdinalIgnoreCase)
                    .Select(s => Field(s, byName[s.Name].ToList(), catalog, byName)).ToList();
                var id = Slug(cat.Key) + "--" + Slug(g.Key) + (advanced ? "--adv" : "");
                return new SettingsCard(def?.Name ?? g.Key, id, def?.Description, fields);
            }
            var common = cat.Where(s => !s.Advanced).GroupBy(s => CardOf(catalog, s), StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => CardRank(g.Key)).Select(g => MakeCard(g, false)).ToList();
            var advanced = cat.Where(s => s.Advanced).GroupBy(s => CardOf(catalog, s), StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => CardRank(g.Key)).Select(g => MakeCard(g, true)).ToList();
            var desc = catalog.Categories.FirstOrDefault(c => string.Equals(c.Name, cat.Key, StringComparison.OrdinalIgnoreCase))?.Description
                ?? catalog.Groups.FirstOrDefault(c => string.Equals(c.Name, cat.Key, StringComparison.OrdinalIgnoreCase))?.Description;
            result.Add(new SettingsCategory(cat.Key, Slug(cat.Key), desc, common, advanced));
        }
        return result;
    }

    /// A setting's place on its card: where the card lists it; one the card does not list (a web-app setting naming its
    /// card itself) follows in catalog order.
    private static int FieldRank(SettingsCatalog catalog, CatalogSetting s)
    {
        var card = catalog.Cards.FirstOrDefault(c => string.Equals(c.Name, s.Card, StringComparison.OrdinalIgnoreCase));
        var i = card is null ? -1 : card.Settings.ToList().FindIndex(n => string.Equals(n, s.Name, StringComparison.OrdinalIgnoreCase));
        if (i >= 0) return i;
        var j = catalog.All.ToList().IndexOf(s);
        return 10_000 + (j < 0 ? 0 : j);
    }

    /// The scope a field edits: the one row's scope when the setting has exactly one, else its default scope (the Edit
    /// page's rule). Other rows are shown as "also set for ..." with a link to the Edit page.
    public static string EditScope(CatalogSetting s, IReadOnlyList<SettingRow> rows) => rows.Count == 1 ? rows[0].Scope : s.DefaultScope;

    public static SettingField Field(CatalogSetting s, IReadOnlyList<SettingRow> rows, SettingsCatalog catalog, ILookup<string, SettingRow> all)
    {
        var scope = EditScope(s, rows);
        var row = rows.FirstOrDefault(r => r.Scope == scope);
        var others = rows.Where(r => !ReferenceEquals(r, row)).ToList();
        var editor = EditorOf(s, row);
        string? elsewhere = editor == EditorKind.Elsewhere
            ? string.Equals(s.Name, SI.Management.Web.Cmdb.CmdbSources.Setting, StringComparison.OrdinalIgnoreCase) ? "/Cmdb/Source" : "/Admin/Settings/Edit?name=" + Uri.EscapeDataString(s.Name)
            : null;
        var text = s.Secret ? row?.KeyVaultSecretName ?? "" : row is not null ? SettingJson.ToFormText(row.ValueJson) : DefaultText(s);
        var items = editor == EditorKind.Chips ? Items(row is not null ? row.ValueJson : DefaultRaw(s)) : Array.Empty<string>();
        var changed = row is not null && (s.Secret || !SameAsDefault(s, row.ValueJson));
        NeedState? needs = null;
        if (!string.IsNullOrWhiteSpace(s.Needs))
        {
            var wantOn = !s.Needs!.StartsWith('!');
            var other = catalog.Find(s.Needs.TrimStart('!'));
            if (other is not null) needs = new NeedState(other, wantOn, IsOn(other, all[other.Name].ToList()) == wantOn);
        }
        return new SettingField(s, scope, row, others, editor, text, items, changed, elsewhere, needs);
    }

    public static EditorKind EditorOf(CatalogSetting s, SettingRow? row)
    {
        if (string.Equals(s.Name, SI.Management.Web.Cmdb.CmdbSources.Setting, StringComparison.OrdinalIgnoreCase)) return EditorKind.Elsewhere;
        if (s.Secret) return EditorKind.Secret;
        var kind = Kind(row?.ValueJson);
        if (s.Type == "list") return kind is JsonValueKind.Object && !IsEmptyObject(row!.ValueJson) ? EditorKind.Elsewhere : EditorKind.Chips;
        // a stored list or object on a scalar setting is not something a field can show -- the Edit page can
        if (kind is JsonValueKind.Array or JsonValueKind.Object) return EditorKind.Elsewhere;
        return s.Type switch
        {
            "bool" => DefaultRaw(s) is not null ? EditorKind.Toggle : EditorKind.TriState,
            "int" or "number" => EditorKind.Number,
            "enum" => EditorKind.Select,
            _ => EditorKind.Text,
        };
    }

    /// What an empty field shows in grey: the default value, or its words when they are short -- else "Not set" (the
    /// whole default text is in the (i)).
    public static string Placeholder(CatalogSetting s)
    {
        var t = DefaultText(s);
        if (t.Length > 0 && t.Length <= 40 && !t.Contains('\n')) return t;
        var p = s.DefaultPlain;
        if (p.StartsWith("Not set", StringComparison.OrdinalIgnoreCase)) return "Not set";
        if (p.Length <= 28) return p;
        // the first clause of a long default ("24 MB (fits a 25 MB limit)" -> "24 MB")
        var cut = p.IndexOfAny(new[] { '(', ':', ';' });
        var head = (cut > 0 ? p[..cut] : p.Split(" -- ")[0]).Trim();
        return head.Length is > 0 and <= 40 ? head : "Not set";
    }

    /// The default as the text a field shows ("" when the catalog has no default value).
    public static string DefaultText(CatalogSetting s) => DefaultRaw(s) is { } raw ? SettingJson.ToFormText(raw) : "";

    /// The default as JSON. A switch whose default the configuration files set in code (so the catalog has no literal)
    /// but whose default text says plainly "On ..." / "Off ..." has that default -- it is a switch, not a three-way choice.
    public static string? DefaultRaw(CatalogSetting s)
    {
        if (s.Default is { } d && d.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)) return d.GetRawText();
        if (s.Type == "bool" && DefaultWord.Match(s.DefaultText ?? "") is { Success: true } m)
            return m.Groups[1].Value.Equals("on", StringComparison.OrdinalIgnoreCase) ? "true" : "false";
        return null;
    }

    private static readonly System.Text.RegularExpressions.Regex DefaultWord =
        new(@"^\s*(on|off)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// The items of a stored list ("PROD" -> one item; {} -- an empty list as PowerShell 5.1 writes it -- -> none).
    public static IReadOnlyList<string> Items(string? valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson)) return Array.Empty<string>();
        try
        {
            using var doc = JsonDocument.Parse(valueJson);
            var e = doc.RootElement;
            return e.ValueKind switch
            {
                JsonValueKind.Array => e.EnumerateArray().Select(x => SettingValidator.PsString(x)).Where(x => x.Length > 0).ToList(),
                JsonValueKind.String => string.IsNullOrEmpty(e.GetString()) ? Array.Empty<string>() : new[] { e.GetString()! },
                JsonValueKind.Null or JsonValueKind.Object => Array.Empty<string>(),
                _ => new[] { e.GetRawText() },
            };
        }
        catch (JsonException) { return new[] { valueJson }; }
    }

    /// True when a stored value is the shipped default (formatting aside; lists by their items).
    public static bool SameAsDefault(CatalogSetting s, string? valueJson)
    {
        var raw = DefaultRaw(s);
        if (s.Type == "list") return Items(valueJson).SequenceEqual(Items(raw), StringComparer.Ordinal);
        return raw is not null && SettingsDiff.JsonEquals(valueJson, raw);
    }

    /// Whether an on/off setting is on now: its solution row (else its one row), else its default.
    public static bool IsOn(CatalogSetting s, IReadOnlyList<SettingRow> rows)
    {
        var row = rows.FirstOrDefault(r => r.Scope == EditScope(s, rows));
        var json = row is not null ? row.ValueJson : DefaultRaw(s);
        if (json is null) return false;
        try
        {
            using var d = JsonDocument.Parse(json);
            return d.RootElement.ValueKind == JsonValueKind.True
                || (d.RootElement.ValueKind == JsonValueKind.String && string.Equals(d.RootElement.GetString(), "true", StringComparison.OrdinalIgnoreCase));
        }
        catch (JsonException) { return false; }
    }

    private static JsonValueKind? Kind(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { using var d = JsonDocument.Parse(json); return d.RootElement.ValueKind; }
        catch (JsonException) { return null; }
    }

    private static bool IsEmptyObject(string? json)
    {
        try { using var d = JsonDocument.Parse(json ?? ""); return d.RootElement.ValueKind == JsonValueKind.Object && !d.RootElement.EnumerateObject().Any(); }
        catch (JsonException) { return false; }
    }

    /// An id for a category or card: lower-case letters and digits, words joined by '-'.
    public static string Slug(string s)
    {
        var sb = new StringBuilder();
        foreach (var ch in s.ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(ch)) sb.Append(ch);
            else if (sb.Length > 0 && sb[^1] != '-') sb.Append('-');
        }
        return sb.ToString().Trim('-');
    }
}
