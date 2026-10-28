using System.Text.Json;
using System.Text.Json.Serialization;

namespace SI.Management.Web.Settings;

/// One setting from config\settings.catalog.locked.json -- the same catalog the Community Settings page and the Pro
/// PowerShell reader/writer (engine\pro-settings\SI-ProSettings.ps1) validate against. min / max / values / pattern are
/// optional: Test-SISettingValue honours them when present, so this port does too.
public sealed class CatalogSetting
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("label")] public string? Label { get; init; }
    [JsonPropertyName("group")] public string Group { get; init; } = "Other settings";
    [JsonPropertyName("type")] public string Type { get; init; } = "text";
    [JsonPropertyName("engines")] public IReadOnlyList<string> Engines { get; init; } = Array.Empty<string>();
    [JsonPropertyName("edition")] public string Edition { get; init; } = "community";
    [JsonPropertyName("secret")] public bool Secret { get; init; }
    [JsonPropertyName("advanced")] public bool Advanced { get; init; }
    [JsonPropertyName("default")] public JsonElement? Default { get; init; }
    [JsonPropertyName("defaultText")] public string? DefaultText { get; init; }
    [JsonPropertyName("description")] public string? Description { get; init; }
    /// What the setting is for, in one plain sentence (catalog help text).
    [JsonPropertyName("purpose")] public string? Purpose { get; init; }
    /// What changing it does -- run time, cost, data, risk.
    [JsonPropertyName("effect")] public string? Effect { get; init; }
    /// When someone would change it (most installs never should).
    [JsonPropertyName("whenToChange")] public string? WhenToChange { get; init; }
    /// The unit a number is in (days, minutes, rows, ...), shown beside every value.
    [JsonPropertyName("unit")] public string? Unit { get; init; }
    [JsonPropertyName("min")] public double? Min { get; init; }
    [JsonPropertyName("max")] public double? Max { get; init; }
    [JsonPropertyName("values")] public IReadOnlyList<string>? Values { get; init; }
    /// The plain words a dropdown shows for each allowed value (type enum); a value without one shows as itself.
    [JsonPropertyName("valueLabels")] public IReadOnlyDictionary<string, string>? ValueLabels { get; init; }
    /// #446: "radio" = show the choice as radio buttons (every option visible) instead of a dropdown -- e.g. how mail is sent.
    [JsonPropertyName("editor")] public string? Editor { get; init; }
    /// The words a person reads for one allowed value: its label when the catalog has one, else the value itself.
    public string ChoiceLabel(string value) =>
        ValueLabels is not null && ValueLabels.TryGetValue(value, out var l) && !string.IsNullOrWhiteSpace(l) ? l : value;
    [JsonPropertyName("pattern")] public string? Pattern { get; init; }
    [JsonPropertyName("patternHint")] public string? PatternHint { get; init; }

    /// The card (one topic, one Save) the Settings page shows this setting on; null = its category's general card.
    [JsonPropertyName("card")] public string? Card { get; init; }
    /// The one short line under the field, only where the label is not enough.
    [JsonPropertyName("hint")] public string? Hint { get; init; }
    /// The on/off setting this one only works with; "!Name" = only while that setting is off.
    [JsonPropertyName("needs")] public string? Needs { get; init; }
    /// "email": a list of mail addresses -- edited as address chips, and an entry that is not an address is refused.
    [JsonPropertyName("itemFormat")] public string? ItemFormat { get; init; }
    [JsonIgnore] public bool IsMailList => Type == "list" && string.Equals(ItemFormat, "email", StringComparison.OrdinalIgnoreCase);
    /// Read ONLY by setup (container setup, the auth bootstrap, the licence request): a value stored here changes nothing
    /// until setup runs again, so the page shows it read-only with <see cref="SetupOnlyNote"/> and the save refuses it.
    [JsonPropertyName("setupOnly")] public bool SetupOnly { get; init; }
    public const string SetupOnlyNote = "Changed by running setup";

    /// "More info" (framework SETTING-INFO-1) as the catalog carries it; null for the web app's own settings, which get it
    /// from <see cref="SettingInfoComposer"/> -- read <see cref="MoreInfo"/>.
    [JsonPropertyName("info")] public SettingInfo? Info { get; init; }
    /// The setting's More info, whichever way it is defined.
    [JsonIgnore] public SettingInfo MoreInfo => SettingInfoComposer.For(this);

    /// Who may change it: the licence settings are the install's lifecycle and need SuperAdmin (#253); every other
    /// setting is Admin. The page disables the field and the save refuses it by this same rule.
    [JsonIgnore] public bool NeedsSuperAdmin => SI.Management.Web.Auth.AccessLifecycle.IsLicenceSetting(Name);

    /// The scopes a value may be written at: 'solution', and 'engine:&lt;folder&gt;' for every engine the catalog names.
    public IEnumerable<string> AllowedScopes() => WebOnly ? new[] { WebScope } : new[] { "solution" }.Concat(Engines.Select(e => "engine:" + e));

    /// A setting of the management web app itself (not in the engines' catalog). It lives ONLY at scope
    /// 'engine:management-web': every engine skips another engine's rows before its catalog check, so such a row can
    /// never stop a run -- whereas at 'solution' scope an unknown name is refused and the run fails.
    [JsonIgnore] public bool WebOnly { get; init; }
    public const string WebScope = "engine:management-web";

    /// The scope a new value goes to by default -- the Community page's own rule: one engine -> that engine's file, else the solution file.
    public string DefaultScope => Engines.Count == 1 ? "engine:" + Engines[0] : "solution";

    /// The shipped default VALUE as JSON text when there is one, else the default in words. DefaultPlain is what a
    /// person reads; this is the machine form.
    public string DefaultDisplay => Default is { } d && d.ValueKind != JsonValueKind.Null ? d.GetRawText() : (DefaultText ?? "(none)");

    /// The name a person reads: the catalog label, else the internal name.
    [JsonIgnore] public string Title => string.IsNullOrWhiteSpace(Label) ? Name : Label!;

    /// What it is for: the purpose, else the comment from the configuration files.
    [JsonIgnore] public string? PurposeText => !string.IsNullOrWhiteSpace(Purpose) ? Purpose : Description;

    /// The real default in words. A plain value gets its unit ("90 days"); with neither text nor value: "Not set".
    [JsonIgnore] public string DefaultPlain =>
        !string.IsNullOrWhiteSpace(DefaultText) ? DefaultText!
        : Default is { } d && d.ValueKind != JsonValueKind.Null ? WithUnit(d.ValueKind == JsonValueKind.String ? d.GetString() ?? "" : d.GetRawText())
        : "Not set";

    /// A value with this setting's unit after it when the value is a plain number ("30" -> "30 days").
    public string WithUnit(string value) =>
        !string.IsNullOrWhiteSpace(Unit) && double.TryParse(value.Trim('"'), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out _)
            ? value.Trim('"') + " " + Unit : value;

    /// True when the query matches the label, the internal name or any of the explaining text (case-insensitive).
    public bool Matches(string q) =>
        new[] { Name, Label, Description, Purpose, Effect, WhenToChange, DefaultText, Group, Card, Hint }
            .Any(t => !string.IsNullOrEmpty(t) && t.Contains(q, StringComparison.OrdinalIgnoreCase));
}

/// One area of the Settings page: grouped by what an admin wants to do, with a one-line description.
public sealed class CatalogGroup
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("description")] public string? Description { get; init; }
}

/// One category of the Settings page (one shown at a time). Groups: the catalog groups whose settings it shows when
/// they name no card of their own.
public sealed class CatalogCategory
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("description")] public string? Description { get; init; }
    [JsonPropertyName("groups")] public IReadOnlyList<string> Groups { get; init; } = Array.Empty<string>();
}

/// One card of the Settings page: one topic, its fields, one Save.
public sealed class CatalogCard
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("category")] public string Category { get; init; } = "";
    [JsonPropertyName("description")] public string? Description { get; init; }
    /// Its settings in the order the card shows them (the web app's own settings name their card themselves).
    [JsonPropertyName("settings")] public IReadOnlyList<string> Settings { get; init; } = Array.Empty<string>();
}

public sealed class SettingsCatalog
{
    private readonly Dictionary<string, CatalogSetting> _byName;

    public SettingsCatalog(IEnumerable<CatalogSetting> settings, IEnumerable<CatalogGroup>? groups = null,
        IEnumerable<CatalogCategory>? categories = null, IEnumerable<CatalogCard>? cards = null)
    {
        All = settings.ToList();
        Groups = (groups ?? Array.Empty<CatalogGroup>()).ToList();
        Categories = (categories ?? Array.Empty<CatalogCategory>()).ToList();
        Cards = (cards ?? Array.Empty<CatalogCard>()).ToList();
        _byName = All.GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Last(), StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<CatalogSetting> All { get; }

    /// The areas in the order the Settings page shows them (the catalog's "groups"); empty for an older catalog.
    public IReadOnlyList<CatalogGroup> Groups { get; }

    /// The Settings page's categories and cards, in order (the catalog's "categories" / "cards"); empty for an older catalog.
    public IReadOnlyList<CatalogCategory> Categories { get; }
    public IReadOnlyList<CatalogCard> Cards { get; }

    /// This catalog plus the web app's own settings (scope engine:management-web only).
    public SettingsCatalog WithWebSettings() =>
        new(All.Concat(SI.Management.Web.Links.WebSettings.Catalog.Concat(SI.Management.Web.Exemptions.ExemptionSettings.Catalog).Append(SI.Management.Web.Cmdb.CmdbSources.Catalog).Append(SI.Management.Web.Pages.DisplayCulture.Catalog).Append(SI.Management.Web.ChatView.ChatDisplay.Catalog).Concat(SI.Management.Web.Pages.HeaderContext.Catalog).Concat(SI.Management.Web.ChangeJournal.ConfigSettings.Catalog).Concat(SI.Management.Web.GetStarted.GetStartedSettings.Catalog).Concat(SI.Management.Web.Notify.NotifySettings.Catalog).Where(w => Find(w.Name) is null)), Groups, Categories, Cards);

    /// PowerShell hashtable lookup ($byName[$name]) is case-insensitive -- so is this.
    public CatalogSetting? Find(string name) => _byName.TryGetValue(name, out var s) ? s : null;

    public static SettingsCatalog Load(string path)
    {
        using var fs = File.OpenRead(path);
        using var doc = JsonDocument.Parse(fs);
        var list = doc.RootElement.GetProperty("settings").Deserialize<List<CatalogSetting>>() ?? new();
        List<T> Read<T>(string prop) => doc.RootElement.TryGetProperty(prop, out var e) && e.ValueKind == JsonValueKind.Array
            ? e.Deserialize<List<T>>() ?? new() : new List<T>();
        return new SettingsCatalog(list, Read<CatalogGroup>("groups"), Read<CatalogCategory>("categories"), Read<CatalogCard>("cards"));
    }

    /// The catalog shipped beside the app (linked from config\ in the csproj); Settings:CatalogPath overrides it.
    public static string DefaultPath(string contentRoot) => Path.Combine(AppContext.BaseDirectory, "catalog", "settings.catalog.locked.json");
}
