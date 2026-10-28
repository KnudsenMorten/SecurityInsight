using System.Globalization;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One engine's schema overlay as the next run reads it (null Body = none: the shipped schema as it is).
public sealed record SchemaOverlayEntry(string Engine, string? Body, long? Version, DateTime? UpdatedAt, string? UpdatedBy)
{
    /// The v2.2 file this overlay is (asset-profiling-schema\&lt;engine&gt;.schema.custom.json).
    public string FileName => (Engine == "publicip" ? "public-ip" : Engine) + ".schema.custom.json";
}

/// <summary>
/// Schema overlays (v2.2's asset-profiling-schema\&lt;engine&gt;.schema.custom.json): per profiling engine, the customer's
/// extra or replaced profile columns, aggregator contributors and raw-payload include paths -- ONE configuration item per
/// engine (cfg.ItemOverride Kind 'schemaoverlay', no vendor template). The materialiser writes it as
/// asset-profiling-schema\&lt;engine&gt;.schema.custom.json under SI_ProConfigRoot, where Get-SISchemaWithCustomMerge reads it
/// first, and merges it over the shipped schema by its own rules (same name / id replaces, new appends, include paths
/// union).
/// </summary>
public sealed class SchemaOverlayStore
{
    public const string Kind = ItemValidator.SchemaOverlay;
    public static readonly string[] Engines = ["endpoint", "identity", "azure", "publicip"];
    private readonly IItemSource _src;
    public SchemaOverlayStore(IItemSource src) => _src = src;

    public async Task<(bool Schema, IReadOnlyList<SchemaOverlayEntry> Overlays)> LoadAsync(CancellationToken ct)
    {
        var set = await _src.LoadAsync(Kind, ct);
        if (!set.Schema) return (false, Array.Empty<SchemaOverlayEntry>());
        return (true, Engines.Select(e => set.Override(e) is { State: "override" } o ? new SchemaOverlayEntry(e, o.Body, o.Version, o.UpdatedAt, o.UpdatedBy)
            : new SchemaOverlayEntry(e, null, set.Override(e)?.Version, null, null)).ToList());
    }
}

/// <summary>The schema overlay editor's change through THE staging: one engine's overlay (save, or remove) per change.</summary>
public sealed class SchemaOverlayChanges : IStagedChangeHandler
{
    public const string ChangeKind = "schema-overlay-edit";
    private readonly SchemaOverlayStore _store;
    private readonly IItemSource _src;
    public SchemaOverlayChanges(SchemaOverlayStore store, IItemSource src) { _store = store; _src = src; }

    public bool Handles(string kind) => kind == ChangeKind;

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewAsync(string engine, string action, string? body, string? reason, CancellationToken ct)
    {
        if (!SchemaOverlayStore.Engines.Contains(engine)) return (null, new[] { $"'{engine}' is not a profiling engine (endpoint, identity, azure, publicip)" });
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        var (schema, list) = await _store.LoadAsync(ct);
        if (!schema) return (null, new[] { SqlItemSource.MissingSchemaMessage });
        var e = list.Single(x => x.Engine == engine);
        if (action == "remove")
        {
            if (e.Body is null) return (null, new[] { "there is no overlay to remove" });
            return (Change(e, "inherit", null, reason, $"Remove the {engine} schema overlay"), Array.Empty<string>());
        }
        if (action != "save") return (null, new[] { $"unknown action '{action}'" });
        var why = ItemValidator.Validate(SchemaOverlayStore.Kind, engine, body);
        if (why.Count > 0) return (null, why);
        if (e.Body is not null && TaggingChanges.Same(e.Body, body)) return (null, new[] { "nothing changed -- this is the overlay in force" });
        return (Change(e, "override", body, reason, $"Save the {engine} schema overlay"), Array.Empty<string>());
    }

    private static StagedChange Change(SchemaOverlayEntry e, string state, string? body, string reason, string title) => new()
    {
        Kind = ChangeKind, Title = title,
        Data = new(StringComparer.Ordinal)
        {
            ["key"] = e.Engine, ["state"] = state, ["body"] = body, ["reason"] = reason.Trim(), ["expectedVersion"] = e.Version?.ToString(CultureInfo.InvariantCulture),
        },
    };

    private static ItemWrite WriteOf(StagedChange c) => new(SchemaOverlayStore.Kind, c.Get("key") ?? "", "override", c.Get("state") ?? "", c.Get("body"),
        long.TryParse(c.Get("expectedVersion"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null);

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var w = WriteOf(c);
        var (schema, list) = await _store.LoadAsync(ct);
        var why = new List<string>();
        if (!schema) why.Add(SqlItemSource.MissingSchemaMessage);
        var e = list.FirstOrDefault(x => x.Engine == w.Key);
        if (e?.Version != w.ExpectedVersion) why.Add("the overlay changed since this was staged -- discard this change and stage it again from the Schema overlays page");
        if (w.State == "override") why.AddRange(ItemValidator.Validate(SchemaOverlayStore.Kind, w.Key, w.Body));
        return new ChangePreview(c, e?.Body ?? "(no overlay: the shipped schema as it is)", w.State == "inherit" ? "(no overlay: the shipped schema as it is)" : w.Body ?? "", why,
            new[] { "a column added here reaches the profile table on the next profiling run of that engine (new columns can take a while to appear in Log Analytics)" });
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        var w = WriteOf(c);
        var (schema, list) = await _store.LoadAsync(ct);
        if (!schema) return new WriteResult(WriteStatus.Refused, SqlItemSource.MissingSchemaMessage);
        if (list.FirstOrDefault(x => x.Engine == w.Key)?.Version != w.ExpectedVersion) return new WriteResult(WriteStatus.Stale, "the overlay changed since this was staged -- nothing was written; open it again and stage it again");
        if (w.State == "override" && ItemValidator.Validate(SchemaOverlayStore.Kind, w.Key, w.Body) is { Count: > 0 } why) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        return await _src.WriteAsync(w, by, c.Get("reason") ?? c.Title, ct);
    }
}
