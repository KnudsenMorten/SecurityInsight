using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Cmdb;

/// <summary>
/// The service map's changes, through THE staging (Review &amp; commit) like the tier board's: a drop builds ONE staged
/// change -- link (or unlink) every selected asset to one service -- validated at once (an external CMDB, a retired
/// service, an empty selection are refused before anything is staged), previewed on Review &amp; commit and written by
/// <see cref="ICmdbStore.LinkAsync"/> in one transaction with its cfg.ChangeLog row. Nothing is written when staging.
/// </summary>
public sealed class CmdbChanges : IStagedChangeHandler
{
    public const int MaxPerChange = SqlCmdbStore.MaxLinkBatch;
    private const int Listed = 25;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly ICmdbStore _store;
    public CmdbChanges(ICmdbStore store) => _store = store;

    public bool Handles(string kind) => kind == ChangeKinds.CmdbLink;

    public sealed record Asset(string Key, string? Name);

    public static IReadOnlyList<Asset> AssetsOf(StagedChange c)
    {
        try { return JsonSerializer.Deserialize<List<Asset>>(c.Get("assets") ?? "[]", Json) ?? new List<Asset>(); }
        catch (JsonException) { return Array.Empty<Asset>(); }
    }

    // read on Review & commit and in the toast: the viewer's number format (never invariant)
    private static string Plural(int n, string one) => n == 1 ? "1 " + one : SI.Management.Core.ProData.ScoreFormat.Count(n) + " " + one + "s";

    private static string Names(IReadOnlyList<Asset> a) =>
        string.Join("\n", a.Take(Listed).Select(x => "  " + (x.Name ?? x.Key))) + (a.Count > Listed ? $"\n  ... and {SI.Management.Core.ProData.ScoreFormat.Count(a.Count - Listed)} more" : "");

    /// Build (never write) a link / unlink of the given assets. The reasons it is refused, or the change to stage.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewLinkAsync(int serviceId, IReadOnlyList<Asset> assets, bool link, string? reason, CancellationToken ct)
    {
        if (!(await _store.SchemaAsync(ct)).HasCmdb) return (null, new[] { SqlCmdbStore.MissingSchemaMessage });
        var (source, _) = await _store.ActiveSourceAsync(ct);
        if (CmdbSources.IsReadOnly(source)) return (null, new[] { $"the CMDB source is {CmdbSources.Label(source)}: links are made in that source, not here" });
        var svc = await _store.ServiceAsync(serviceId, ct);
        if (svc is null) return (null, new[] { "the service does not exist" });
        if (svc.Source != CmdbSources.SI) return (null, new[] { $"{svc.Number} {svc.Name} belongs to {CmdbSources.Label(svc.Source)} and is read-only here" });
        if (svc.Retired) return (null, new[] { $"{svc.Number} {svc.Name} is retired" });
        var list = assets.Where(a => !string.IsNullOrWhiteSpace(a.Key)).GroupBy(a => a.Key, StringComparer.Ordinal).Select(g => g.First()).ToList();
        if (list.Count == 0) return (null, new[] { "no asset was selected" });
        if (list.Count > MaxPerChange) return (null, new[] { $"at most {SI.Management.Core.ProData.ScoreFormat.Count(MaxPerChange)} assets are linked in one change -- narrow the filter" });
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        var title = link
            ? $"Link {Plural(list.Count, "asset")} to {svc.Number} {svc.Name}"
            : $"Unlink {Plural(list.Count, "asset")} from {svc.Number} {svc.Name}";
        return (new StagedChange
        {
            Kind = ChangeKinds.CmdbLink, Title = title,
            Data = new(StringComparer.Ordinal)
            {
                ["serviceId"] = serviceId.ToString(CultureInfo.InvariantCulture), ["serviceNumber"] = svc.Number, ["serviceName"] = svc.Name,
                ["action"] = link ? "link" : "unlink", ["assets"] = JsonSerializer.Serialize(list, Json), ["reason"] = reason.Trim(),
            },
        }, Array.Empty<string>());
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var why = new List<string>(); var warnings = new List<string>();
        var link = c.Get("action") != "unlink";
        var assets = AssetsOf(c);
        if (!(await _store.SchemaAsync(ct)).HasCmdb) return new ChangePreview(c, "", "", new[] { SqlCmdbStore.MissingSchemaMessage }, warnings);
        var (source, _) = await _store.ActiveSourceAsync(ct);
        if (CmdbSources.IsReadOnly(source)) why.Add($"the CMDB source is now {CmdbSources.Label(source)} -- links are made in that source; discard this change");
        var svc = int.TryParse(c.Get("serviceId"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) ? await _store.ServiceAsync(id, ct) : null;
        if (svc is null) return new ChangePreview(c, "", "", why.Append("the service no longer exists -- discard this change").ToList(), warnings);
        if (svc.Retired) why.Add($"{svc.Number} {svc.Name} was retired since this was staged -- discard this change");
        if (assets.Count == 0) why.Add("the change names no asset");
        var linked = (await _store.LinksOfAsync(assets.Select(a => a.Key).ToList(), ct)).Where(l => l.ServiceId == svc.ServiceId).Select(l => l.AssetKey).ToHashSet(StringComparer.Ordinal);
        var affected = assets.Where(a => link ? !linked.Contains(a.Key) : linked.Contains(a.Key)).ToList();
        var unaffected = assets.Count - affected.Count;
        if (unaffected > 0) warnings.Add(link ? $"{SI.Management.Core.ProData.ScoreFormat.Count(unaffected)} of the selected assets are already linked to {svc.Number} -- left as they are" : $"{SI.Management.Core.ProData.ScoreFormat.Count(unaffected)} of the selected assets are not linked to {svc.Number} -- nothing to unlink for them");
        if (link && (await _store.LinksOfAsync(affected.Select(a => a.Key).ToList(), ct)).Any(l => l.ServiceId != svc.ServiceId))
            warnings.Add("Some of these assets already belong to another service; they will belong to both.");
        var now = $"{svc.Number} {svc.Name}: {Plural((int)svc.Assets, "linked asset")}";
        var after = link
            ? $"{svc.Number} {svc.Name}: {Plural((int)svc.Assets + affected.Count, "linked asset")} -- adds {Plural(affected.Count, "asset")}:\n{Names(affected)}"
            : $"{svc.Number} {svc.Name}: {Plural(Math.Max(0, (int)svc.Assets - affected.Count), "linked asset")} -- removes {Plural(affected.Count, "asset")} (the history stays):\n{Names(affected)}";
        return new ChangePreview(c, now, after, why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        if (!int.TryParse(c.Get("serviceId"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)) return new WriteResult(WriteStatus.Refused, "the change names no service");
        var link = c.Get("action") != "unlink";
        var (r, n) = await _store.LinkAsync(id, AssetsOf(c).Select(a => (a.Key, a.Name)).ToList(), link, by, c.Get("reason") ?? c.Title, ct);
        return r.Status == WriteStatus.Saved
            ? r with { Message = (link ? "linked " : "unlinked ") + Plural(n, "asset") + (link ? " to " : " from ") + c.Get("serviceNumber") }
            : r;
    }
}
