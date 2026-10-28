using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// <summary>One asset tag rule as the next tagging run applies it (Origin as for rules: vendor / changed / off / yours).</summary>
public sealed record TagEntry(string Key, RuleOrigin Origin, string? Body, string? VendorBody, long? Version, DateTime? UpdatedAt, string? UpdatedBy)
{
    public string? EditBody => Body ?? VendorBody;
    private JsonObject? Obj => TaggingStore.Parse(EditBody);
    public string Name => TaggingStore.Str(Obj, "AssetTagName") ?? Key[4..];
    public int? Tier => ItemValidator.TagTier(Name);
    public bool Excluded => Name.EndsWith("--excluded--SI", StringComparison.OrdinalIgnoreCase);
    public string Mode => TaggingStore.Str(Obj, "Mode") is { Length: > 0 } m ? m : "Prod";
    public string QueryEngine => TaggingStore.Str(Obj, "QueryEngine") is { Length: > 0 } q ? q : "DefenderGraph";
    public string? Gate => TaggingStore.Str(Obj, "EnabledByConfigFlag");
}

/// <summary>The asset tagging configuration as a run gets it: the tag rules and the gates (asset-tagging.config.json).</summary>
public sealed record TaggingCatalog(bool Schema, bool TemplatesPublished, IReadOnlyList<TagEntry> Tags, string? ConfigBody, long? ConfigVersion,
    DateTime? ConfigUpdatedAt, string? ConfigUpdatedBy, IReadOnlyList<string> Notes)
{
    public TagEntry? Find(string key) => Tags.FirstOrDefault(t => string.Equals(t.Key, key, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Asset tagging (v2.2's AssetTagging.locked.yaml + AssetTagging.custom.yaml + config\asset-tagging.config.json) as the
/// Pro run serves it: the vendor's 'assettagging' templates (one per tag, keyed 'tag/&lt;STEM&gt;--SI' -- the engine's own
/// merge key, so a custom tag of the same stem replaces the vendor's), the customer's overrides (override / disable)
/// and own tags, and the ONE configuration item 'config' (the AutoExclude gates and the device-name patterns). The
/// materialiser writes the tags as AssetTagging.locked.yaml under SI_ProAssetTaggingPath and the gates as
/// asset-tagging.config.json under SI_ProConfigRoot -- exactly where AssetTagging.ps1 reads them.
/// </summary>
public sealed class TaggingStore
{
    public const string Kind = ItemValidator.AssetTagging;
    public const string ConfigKey = "config";
    public static readonly JsonSerializerOptions Write = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private readonly IItemSource _src;
    public TaggingStore(IItemSource src) => _src = src;

    /// A body as stored: indented JSON with LF line ends on every OS (the same bytes from a Windows or a Linux host).
    public static string Json(JsonNode node) => node.ToJsonString(Write).Replace("\r\n", "\n");

    public static JsonObject? Parse(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try { return JsonNode.Parse(body) as JsonObject; } catch (JsonException) { return null; }
    }

    public static string? Str(JsonObject? o, string name)
    {
        if (o is null) return null;
        foreach (var (k, v) in o) if (string.Equals(k, name, StringComparison.OrdinalIgnoreCase)) return v is JsonValue jv && jv.TryGetValue<string>(out var s) ? s : v?.ToJsonString();
        return null;
    }

    public async Task<TaggingCatalog> LoadAsync(CancellationToken ct) => Build(await _src.LoadAsync(Kind, ct));

    /// PURE. Merge-SIProItems for the 'assettagging' kind.
    public static TaggingCatalog Build(ItemSet set)
    {
        if (!set.Schema) return new TaggingCatalog(false, false, Array.Empty<TagEntry>(), null, null, null, null, new[] { SqlItemSource.MissingSchemaMessage });
        var notes = new List<string>();
        var list = new List<TagEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in set.Templates.Where(t => t.Key.StartsWith("tag/", StringComparison.OrdinalIgnoreCase)))
        {
            seen.Add(t.Key);
            var o = set.Override(t.Key);
            if (o is { State: "override" }) { list.Add(new TagEntry(t.Key, RuleOrigin.Changed, o.Body, t.Retired ? null : t.Body, o.Version, o.UpdatedAt, o.UpdatedBy)); continue; }
            if (o is { State: "disable" }) { list.Add(new TagEntry(t.Key, RuleOrigin.Off, null, t.Body, o.Version, o.UpdatedAt, o.UpdatedBy)); continue; }
            if (t.Retired) continue;
            list.Add(new TagEntry(t.Key, RuleOrigin.Vendor, null, t.Body, o?.Version, null, null));
        }
        foreach (var o in set.Overrides.Where(o => o.Key.StartsWith("tag/", StringComparison.OrdinalIgnoreCase) && !seen.Contains(o.Key) && o.State == "override"))
            list.Add(new TagEntry(o.Key, RuleOrigin.Yours, o.Body, null, o.Version, o.UpdatedAt, o.UpdatedBy));
        var published = set.Templates.Any(t => t.Key.StartsWith("tag/", StringComparison.OrdinalIgnoreCase));
        if (!published && list.Count > 0)
            notes.Add($"{list.Count} tag rule(s) of yours are NOT applied yet: no vendor tag templates are published in this database, so the tagging run still reads its rules from the installation. Publish the templates (Templates > Releases) to apply them.");
        else if (!published)
            notes.Add("no vendor tag templates are published in this database yet: the tagging run reads its rules from the installation until they are (Templates > Releases). The gates below apply either way.");
        var cfg = set.Override(ConfigKey);
        var cfgBody = cfg is { State: "override" } ? cfg.Body : null;
        return new TaggingCatalog(true, published, list.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase).ToList(), cfgBody, cfg?.Version, cfg?.UpdatedAt, cfg?.UpdatedBy, notes);
    }

    /// save / off / reset / remove for a tag; save / reset for the gates ('config'). Null + why when it does not apply.
    public static (ItemWrite? Write, string? Why) WriteFor(TaggingCatalog cat, string key, string action, string? body)
    {
        if (string.Equals(key, ConfigKey, StringComparison.OrdinalIgnoreCase))
            return action switch
            {
                "save" => (new ItemWrite(Kind, ConfigKey, "override", "override", body, cat.ConfigVersion), null),
                "reset" when cat.ConfigVersion is not null => (new ItemWrite(Kind, ConfigKey, "override", "inherit", null, cat.ConfigVersion), null),
                "reset" => (null, "no gates are stored -- nothing to reset"),
                _ => (null, $"unknown action '{action}' for the gates"),
            };
        var e = cat.Find(key);
        var isVendor = e?.VendorBody is not null;
        switch (action)
        {
            case "save":
                return (new ItemWrite(Kind, e?.Key ?? key, "override", "override", body, e?.Version), null);
            case "off":
                if (e is null || !isVendor) return (null, "only a vendor tag can be turned off -- remove your own tag instead");
                if (e.Origin == RuleOrigin.Off) return (null, "this tag is already turned off");
                return (new ItemWrite(Kind, e.Key, "override", "disable", null, e.Version), null);
            case "reset":
            case "remove":
                if (action == "reset" && e is not null && !isVendor) return (null, "this is your own tag -- remove it instead");
                if (action == "remove" && isVendor) return (null, "a vendor tag cannot be removed -- turn it off, or reset it to the vendor's");
                if (e is null || e.Version is null) return (null, action == "reset" ? "this tag is the vendor's as it is -- nothing to reset" : "there is nothing of yours to remove");
                return (new ItemWrite(Kind, e.Key, "override", "inherit", null, e.Version), null);
            default:
                return (null, $"unknown action '{action}'");
        }
    }

    /// The reasons a body cannot be stored for this key: Test-SIProItem's rules, plus the engine's: a tag runs a query.
    public static IReadOnlyList<string> Problems(string key, string body)
    {
        var why = new List<string>(ItemValidator.Validate(Kind, key, body));
        if (why.Count == 0 && !string.Equals(key, ConfigKey, StringComparison.OrdinalIgnoreCase))
        {
            var o = Parse(body);
            var q = o is null ? null : o.FirstOrDefault(kv => string.Equals(kv.Key, "Query", StringComparison.OrdinalIgnoreCase)).Value;
            var any = q switch
            {
                JsonArray a => a.Any(x => x is JsonValue v && v.TryGetValue<string>(out var s) && !string.IsNullOrWhiteSpace(s)),
                JsonValue v => v.TryGetValue<string>(out var s) && !string.IsNullOrWhiteSpace(s),
                _ => false,
            };
            if (!any) why.Add("a tag needs a query (the tagging run skips a tag without one)");
        }
        return why;
    }
}

/// <summary>The asset tagging editor's change through THE staging: one tag, or the gates, per staged change.</summary>
public sealed class TaggingChanges : IStagedChangeHandler
{
    public const string ChangeKind = "tagging-edit";
    private readonly TaggingStore _store;
    private readonly IItemSource _src;
    public TaggingChanges(TaggingStore store, IItemSource src) { _store = store; _src = src; }

    public bool Handles(string kind) => kind == ChangeKind;

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewAsync(string key, string action, string? body, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        var cat = await _store.LoadAsync(ct);
        if (!cat.Schema) return (null, new[] { SqlItemSource.MissingSchemaMessage });
        var (w, why) = TaggingStore.WriteFor(cat, key, action, body);
        if (w is null) return (null, new[] { why! });
        var isConfig = w.Key == TaggingStore.ConfigKey;
        if (w.State == "override")
        {
            var p = TaggingStore.Problems(w.Key, w.Body ?? "");
            if (p.Count > 0) return (null, p);
            var now = isConfig ? cat.ConfigBody : cat.Find(w.Key)?.EditBody;
            if (now is not null && Same(now, w.Body)) return (null, new[] { "nothing changed -- this is what is in force" });
        }
        var e = cat.Find(w.Key);
        var title = isConfig
            ? (action == "reset" ? "Remove the asset tagging gates (every gated tag off)" : "Save the asset tagging gates")
            : action switch
            {
                "off" => $"Turn off the asset tag {e?.Name ?? w.Key}",
                "reset" => $"Reset the asset tag {e?.Name ?? w.Key} to the vendor's",
                "remove" => $"Remove your asset tag {e?.Name ?? w.Key}",
                _ => e is null ? $"Add the asset tag {TaggingStore.Str(TaggingStore.Parse(w.Body), "AssetTagName")}" : $"Change the asset tag {TaggingStore.Str(TaggingStore.Parse(w.Body), "AssetTagName")}",
            };
        return (new StagedChange
        {
            Kind = ChangeKind, Title = title,
            Data = new(StringComparer.Ordinal)
            {
                ["key"] = w.Key, ["action"] = action, ["state"] = w.State, ["body"] = w.Body, ["reason"] = reason.Trim(),
                ["expectedVersion"] = w.ExpectedVersion?.ToString(CultureInfo.InvariantCulture),
            },
        }, Array.Empty<string>());
    }

    /// Two JSON bodies that say the same (key order and spacing do not count).
    public static bool Same(string? a, string? b)
    {
        try { return JsonNode.DeepEquals(JsonNode.Parse(a ?? "null"), JsonNode.Parse(b ?? "null")); }
        catch (JsonException) { return string.Equals(a, b, StringComparison.Ordinal); }
    }

    private static ItemWrite WriteOf(StagedChange c) => new(TaggingStore.Kind, c.Get("key") ?? "", "override", c.Get("state") ?? "", c.Get("body"),
        long.TryParse(c.Get("expectedVersion"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null);

    private static long? VersionNow(TaggingCatalog cat, string key) => key == TaggingStore.ConfigKey ? cat.ConfigVersion : cat.Find(key)?.Version;

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var w = WriteOf(c);
        var cat = await _store.LoadAsync(ct);
        var why = new List<string>();
        if (!cat.Schema) why.Add(SqlItemSource.MissingSchemaMessage);
        if (VersionNow(cat, w.Key) != w.ExpectedVersion) why.Add("asset tagging changed since this was staged -- discard this change and stage it again from the Asset tagging page");
        if (w.State == "override") why.AddRange(TaggingStore.Problems(w.Key, w.Body ?? ""));
        var e = cat.Find(w.Key);
        var old = w.Key == TaggingStore.ConfigKey ? cat.ConfigBody ?? "(no gates stored: every gated tag is off)"
            : e is null ? "(no such tag yet)" : e.Origin switch { RuleOrigin.Off => "(turned off)\n" + e.VendorBody, RuleOrigin.Vendor => "(the vendor's tag)\n" + e.VendorBody, _ => e.Body ?? "" };
        var now = w.State switch
        {
            "disable" => "(turned off)",
            "inherit" => w.Key == TaggingStore.ConfigKey ? "(no gates stored: every gated tag is off)" : e?.VendorBody is { } v ? "(the vendor's tag)\n" + v : "(removed)",
            _ => w.Body ?? "",
        };
        var warnings = new List<string>();
        if (!cat.TemplatesPublished && w.Key != TaggingStore.ConfigKey) warnings.Add("no vendor tag templates are published yet: this tag is stored but not applied until they are");
        return new ChangePreview(c, old, now, why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        var w = WriteOf(c);
        var cat = await _store.LoadAsync(ct);
        if (!cat.Schema) return new WriteResult(WriteStatus.Refused, SqlItemSource.MissingSchemaMessage);
        if (VersionNow(cat, w.Key) != w.ExpectedVersion) return new WriteResult(WriteStatus.Stale, "asset tagging changed since this was staged -- nothing was written; open it again and stage it again");
        if (w.State == "override")
        {
            var why = TaggingStore.Problems(w.Key, w.Body ?? "");
            if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        }
        return await _src.WriteAsync(w, by, c.Get("reason") ?? c.Title, ct);
    }
}
