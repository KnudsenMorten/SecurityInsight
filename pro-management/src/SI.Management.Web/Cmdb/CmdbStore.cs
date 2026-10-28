using System.Globalization;
using System.Text.Json;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Cmdb;

public sealed record CmdbSchema(bool HasCmdb, bool HasData);

/// <summary>
/// THE one seam to the CMDB tables (sql\si-pro-settings.sql, #256). Every write is ONE batch, ONE transaction with its
/// cfg.ChangeLog row; every write to the CMDB model re-checks, INSIDE that transaction, that the authoritative source is
/// SecurityInsight's own (an external CMDB is read-only here, whatever the page showed). Imports go through the
/// procedure cfg.CmdbImportSnapshot, the same one the PowerShell import calls.
/// </summary>
public interface ICmdbStore
{
    Task<CmdbSchema> SchemaAsync(CancellationToken ct);
    /// The authoritative source (the setting; SI when unset) and the row version of that setting (null = no row).
    Task<(string Source, long? Version)> ActiveSourceAsync(CancellationToken ct);
    Task<IReadOnlyList<CmdbService>> ServicesAsync(string source, bool includeRetired, CancellationToken ct);
    Task<CmdbService?> ServiceAsync(int serviceId, CancellationToken ct);
    Task<CmdbService?> ServiceByNumberAsync(string source, string number, CancellationToken ct);
    Task<(WriteResult Result, CmdbService? Service)> CreateAsync(CmdbServiceInput input, string by, string? reason, CancellationToken ct);
    Task<WriteResult> UpdateAsync(int serviceId, CmdbServiceInput input, long expectedVersion, string by, string? reason, CancellationToken ct);
    Task<WriteResult> RetireAsync(int serviceId, long expectedVersion, string by, string reason, CancellationToken ct);
    /// Link (link = true) or unlink a set of assets to / from one SI-homed service. Already linked / not linked = no-op.
    Task<(WriteResult Result, int Changed)> LinkAsync(int serviceId, IReadOnlyList<(string Key, string? Name)> assets, bool link, string by, string? reason, CancellationToken ct);
    Task<CmdbImportResult> ImportAsync(string source, string kind, string? origin, string? sha256, string payload, string by, string? reason, CancellationToken ct);
    Task<IReadOnlyList<CmdbImportRow>> ImportsAsync(int top, CancellationToken ct);
    /// The service map's asset pool, one page (most weighted risk first).
    Task<(IReadOnlyList<MapAsset> Assets, long Total)> AssetsAsync(MapFilter filter, int skip, int take, CancellationToken ct);
    /// Every asset key the filter matches, at most max (the map's "all matching the filter").
    Task<IReadOnlyList<(string Key, string Name)>> AssetKeysAsync(MapFilter filter, int max, CancellationToken ct);
    /// One service lane: its linked assets, one page.
    Task<(IReadOnlyList<MapAsset> Assets, long Total)> ServiceAssetsAsync(int serviceId, MapFilter filter, int skip, int take, CancellationToken ct);
    /// The CURRENT services of a set of assets (one row per membership) -- the keys already linked, for a review.
    Task<IReadOnlyList<(string AssetKey, int ServiceId)>> LinksOfAsync(IReadOnlyList<string> assetKeys, CancellationToken ct);
    /// After a membership change: the next data sync derives the newest collection's services again (the Services view's
    /// resolver contract: ServicesDerivedAt NULL). Older collections keep the membership they were derived with.
    Task RecomputeAsync(CancellationToken ct);
}

public sealed class SqlCmdbStore : ICmdbStore
{
    public const int MaxLinkBatch = 5000;
    private readonly ISqlExecutor _sql;
    private readonly ISettingsStoreReader _settings;
    public SqlCmdbStore(ISqlExecutor sql, ISettingsStoreReader settings) { _sql = sql; _settings = settings; }

    public const string MissingSchemaMessage = "this database has no CMDB tables yet -- run the Pro settings schema (sql\\si-pro-settings.sql) first";

    public const string SchemaSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.CmdbService') IS NOT NULL AND OBJECT_ID(N'cfg.CmdbServiceAsset') IS NOT NULL AND OBJECT_ID(N'cfg.vCmdbAssetService') IS NOT NULL
                 AND OBJECT_ID(N'cfg.CmdbImportSnapshot') IS NOT NULL THEN 1 ELSE 0 END AS HasCmdb,
       CASE WHEN OBJECT_ID(N'sidata.Asset') IS NOT NULL AND OBJECT_ID(N'sidata.Finding') IS NOT NULL THEN 1 ELSE 0 END AS HasData;
""";

    private const string Cols = """
s.ServiceId, s.Source, s.ServiceNumber, s.ExternalId, s.Name, s.Description, s.Owner, s.OwnerMail, s.Criticality, s.DataSensitivity, s.Environment,
       s.Department, s.ExtraJson, s.CreatedAt, s.CreatedBy, s.UpdatedAt, s.UpdatedBy, s.RetiredAt, s.RetiredBy, s.RetireReason, CONVERT(bigint, s.RowVersion) AS Version,
       (SELECT COUNT_BIG(*) FROM cfg.CmdbServiceAsset AS m WHERE m.ServiceId = s.ServiceId AND m.UnlinkedAt IS NULL) AS Assets
""";

    public const string ServicesSql = $"""
SELECT {Cols}
FROM cfg.CmdbService AS s
WHERE s.Source = @Source AND (@IncludeRetired = 1 OR s.RetiredAt IS NULL)
ORDER BY CASE WHEN s.RetiredAt IS NULL THEN 0 ELSE 1 END, LEN(s.ServiceNumber), s.ServiceNumber;
""";

    public const string ServiceSql = $"""
SELECT {Cols}
FROM cfg.CmdbService AS s
WHERE s.ServiceId = @ServiceId;
""";

    public const string ServiceByNumberSql = $"""
SELECT {Cols}
FROM cfg.CmdbService AS s
WHERE s.Source = @Source AND s.ServiceNumber = @Number;
""";

    /// The guard every write starts with, inside its transaction: the CMDB tables exist and SecurityInsight's own CMDB is
    /// the authoritative one. @active is left for the caller's message.
    private const string Guard = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.CmdbService') IS NULL OR OBJECT_ID(N'cfg.vCmdbSource') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @active nvarchar(24) = (SELECT ActiveSource FROM cfg.vCmdbSource);
IF @active <> N'SI'
BEGIN
    COMMIT;
    SELECT N'ReadOnly' AS Outcome, @active AS ActiveSource;
    RETURN;
END;
""";

    public const string CreateSql = Guard + """
IF EXISTS (SELECT 1 FROM cfg.CmdbService WITH (UPDLOCK, HOLDLOCK) WHERE Source = N'SI' AND RetiredAt IS NULL AND Name = @Name)
BEGIN
    COMMIT;
    SELECT N'Duplicate' AS Outcome;
    RETURN;
END;
DECLARE @seq int = NEXT VALUE FOR cfg.CmdbServiceNumber;
DECLARE @num nvarchar(64) = N'SVC-' + CASE WHEN @seq < 10000 THEN RIGHT(N'0000' + CONVERT(nvarchar(12), @seq), 4) ELSE CONVERT(nvarchar(12), @seq) END;
INSERT cfg.CmdbService (Source, ServiceNumber, Name, Description, Owner, OwnerMail, Criticality, DataSensitivity, Environment, Department, CreatedBy, UpdatedBy)
VALUES (N'SI', @num, @Name, @Description, @Owner, @OwnerMail, @Criticality, @DataSensitivity, @Environment, @Department, @By, @By);
DECLARE @id int = CONVERT(int, SCOPE_IDENTITY());
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'cmdb/' + @num, N'cmdb', N'cmdb-service', N'Set', NULL, @Json, @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome, @id AS ServiceId, @num AS ServiceNumber;
""";

    private const string LockService = """
DECLARE @cur bigint, @num nvarchar(64), @src nvarchar(24), @retired datetime2(0), @old nvarchar(max);
SELECT @cur = CONVERT(bigint, RowVersion), @num = ServiceNumber, @src = Source, @retired = RetiredAt,
       @old = (SELECT s2.Name AS name, s2.Description AS description, s2.Owner AS owner, s2.OwnerMail AS ownerMail, s2.Criticality AS criticality,
                      s2.DataSensitivity AS dataSensitivity, s2.Environment AS environment, s2.Department AS department
               FROM cfg.CmdbService AS s2 WHERE s2.ServiceId = @ServiceId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM cfg.CmdbService WITH (UPDLOCK, HOLDLOCK) WHERE ServiceId = @ServiceId;
IF @num IS NULL BEGIN COMMIT; SELECT N'NotFound' AS Outcome; RETURN; END;
IF @src <> N'SI' BEGIN COMMIT; SELECT N'ReadOnly' AS Outcome, @src AS ActiveSource; RETURN; END;
IF @retired IS NOT NULL BEGIN COMMIT; SELECT N'Retired' AS Outcome; RETURN; END;
""";

    public const string UpdateSql = Guard + LockService + """
IF @cur <> @Expected BEGIN COMMIT; SELECT N'Stale' AS Outcome, @cur AS Version; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.CmdbService WHERE Source = N'SI' AND RetiredAt IS NULL AND Name = @Name AND ServiceId <> @ServiceId)
BEGIN COMMIT; SELECT N'Duplicate' AS Outcome; RETURN; END;
UPDATE cfg.CmdbService SET Name = @Name, Description = @Description, Owner = @Owner, OwnerMail = @OwnerMail, Criticality = @Criticality,
       DataSensitivity = @DataSensitivity, Environment = @Environment, Department = @Department, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE ServiceId = @ServiceId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'cmdb/' + @num, N'cmdb', N'cmdb-service', N'Set', @old, @Json, @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome, (SELECT CONVERT(bigint, RowVersion) FROM cfg.CmdbService WHERE ServiceId = @ServiceId) AS Version;
""";

    public const string RetireSql = Guard + LockService + """
IF @cur <> @Expected BEGIN COMMIT; SELECT N'Stale' AS Outcome, @cur AS Version; RETURN; END;
UPDATE cfg.CmdbService SET RetiredAt = SYSUTCDATETIME(), RetiredBy = @By, RetireReason = @Reason, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE ServiceId = @ServiceId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'cmdb/' + @num, N'cmdb', N'cmdb-service', N'Reset', @old, N'retired', @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// Link or unlink many assets in one transaction. @Assets = [{"key":"...","name":"..."}]. History stays: an unlink sets
    /// UnlinkedAt, a link adds a row. One cfg.ChangeLog row names every asset that changed.
    public const string LinkSql = Guard + LockService + """
DECLARE @k TABLE (AssetKey nvarchar(400) NOT NULL PRIMARY KEY, AssetName nvarchar(400) NULL);
INSERT @k (AssetKey, AssetName)
SELECT j.[key], MAX(j.[name]) FROM OPENJSON(@Assets) WITH ([key] nvarchar(400) N'$.key', [name] nvarchar(400) N'$.name') AS j
WHERE NULLIF(j.[key], N'') IS NOT NULL GROUP BY j.[key];
DECLARE @done TABLE (AssetKey nvarchar(400) NOT NULL);
IF @Link = 1
    INSERT cfg.CmdbServiceAsset (ServiceId, AssetKey, AssetName, LinkedBy)
    OUTPUT inserted.AssetKey INTO @done (AssetKey)
    SELECT @ServiceId, k.AssetKey, k.AssetName, @By FROM @k AS k
    WHERE NOT EXISTS (SELECT 1 FROM cfg.CmdbServiceAsset AS m WITH (UPDLOCK, HOLDLOCK) WHERE m.ServiceId = @ServiceId AND m.AssetKey = k.AssetKey AND m.UnlinkedAt IS NULL);
ELSE
    UPDATE m SET UnlinkedAt = SYSUTCDATETIME(), UnlinkedBy = @By
    OUTPUT inserted.AssetKey INTO @done (AssetKey)
    FROM cfg.CmdbServiceAsset AS m JOIN @k AS k ON k.AssetKey = m.AssetKey
    WHERE m.ServiceId = @ServiceId AND m.UnlinkedAt IS NULL;
DECLARE @n int = (SELECT COUNT(*) FROM @done);
IF @n > 0
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (N'cmdb/' + @num, N'cmdb', N'cmdb-link', CASE WHEN @Link = 1 THEN N'Set' ELSE N'Reset' END, NULL,
            (SELECT CASE WHEN @Link = 1 THEN N'link' ELSE N'unlink' END AS action, (SELECT d.AssetKey AS [key] FROM @done AS d FOR JSON PATH) AS assets FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
            @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome, @n AS Changed;
""";

    public const string ImportSql = "EXEC cfg.CmdbImportSnapshot @Source, @Kind, @Origin, @Sha256, @Payload, @By, @Reason;";

    /// After a membership change: the services of the collection the views show (the published run's) and of the newest
    /// complete one are derived again by the next data sync (the resolver's contract -- ServicesDerivedAt NULL). Older
    /// collections keep the membership they were derived with.
    public const string RecomputeSql = """
IF COL_LENGTH(N'sidata.Collection', N'ServicesDerivedAt') IS NOT NULL
    EXEC (N'UPDATE sidata.Collection SET ServicesDerivedAt = NULL WHERE CollectionId = (SELECT TOP (1) x.CollectionId FROM sidata.Collection AS x WHERE x.Kind = N''Detailed'' AND x.Status = N''Complete'' ORDER BY x.CollectionTime DESC)
       OR CollectionId = (SELECT TOP (1) pc.CollectionId FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N''Detailed'')');
SELECT N'Saved' AS Outcome;
""";

    public async Task RecomputeAsync(CancellationToken ct) => await _sql.QueryAsync(RecomputeSql, new Dictionary<string, object?>(), ct);

    private async Task<WriteResult> AfterAsync(WriteResult r, CancellationToken ct)
    {
        if (r.Status == WriteStatus.Saved) await RecomputeAsync(ct);
        return r;
    }

    public const string ImportsSql = """
IF OBJECT_ID(N'cfg.CmdbImport') IS NOT NULL
SELECT TOP (@Top) ImportId, Source, Kind, Origin, ImportedAt, ImportedBy, Outcome, Message, ServicesAdded, ServicesUpdated, ServicesRetired, ServicesSkipped,
       LinksAdded, LinksRemoved, LinksRejected, RejectedJson
FROM cfg.CmdbImport ORDER BY ImportId DESC;
""";

    /// #855 M18: the CI lifecycle of an asset key (<paramref name="key"/>, an SQL expression): the CI of that id, else the CI that
    /// carries it as a linked object (the primary and newest link first); none, or a CI without a lifecycle = active.
    private const string LifecycleOfPool = "COALESCE((SELECT NULLIF(c.Lifecycle, N'') FROM sidata.Ci AS c WHERE c.CiId = a.AssetKey), (SELECT TOP (1) NULLIF(c2.Lifecycle, N'') FROM sidata.CiLink AS l JOIN sidata.Ci AS c2 ON c2.CiId = l.CiId WHERE l.NativeId = LOWER(a.AssetKey) ORDER BY l.IsPrimary DESC, l.LastSeen DESC), N'active')";
    private const string LifecycleOfLane = "COALESCE((SELECT NULLIF(c.Lifecycle, N'') FROM sidata.Ci AS c WHERE c.CiId = m.AssetKey), (SELECT TOP (1) NULLIF(c2.Lifecycle, N'') FROM sidata.CiLink AS l JOIN sidata.Ci AS c2 ON c2.CiId = l.CiId WHERE l.NativeId = LOWER(m.AssetKey) ORDER BY l.IsPrimary DESC, l.LastSeen DESC), N'active')";

    /// The asset pool: sidata.Asset, the weighted risk of the published run's collection, the asset's current services.
    private const string PoolFrom = $"""
WITH latest AS (SELECT {SI.Management.Core.ProData.PublishedRun.DetailedId} AS CollectionId),
risk AS (SELECT s.AssetKey, s.TotalWeightedOrRisk AS Weighted FROM sidata.AssetRiskSummary AS s JOIN latest AS l ON l.CollectionId = s.CollectionId),
pool AS (
    SELECT a.AssetKey, a.AssetName, a.AssetKind, a.Tier, r.Weighted,
           (SELECT COUNT(*) FROM cfg.vCmdbAssetService AS v WHERE v.AssetKey = a.AssetKey) AS Services,
           (SELECT STRING_AGG(v.ServiceNumber, N'; ') FROM cfg.vCmdbAssetService AS v WHERE v.AssetKey = a.AssetKey) AS ServiceNumbers
    FROM sidata.Asset AS a LEFT JOIN risk AS r ON r.AssetKey = a.AssetKey
    WHERE (@Kind IS NULL OR EXISTS (SELECT 1 FROM OPENJSON(@Kind) AS kv WHERE N';' + COALESCE(NULLIF(a.AssetKinds, N''), a.AssetKind) + N';' LIKE N'%;' + kv.[value] + N';%'))
      AND (@Text IS NULL OR a.AssetName LIKE @Text OR a.AssetKey LIKE @Text)
      AND (@Tier IS NULL OR (CASE WHEN a.Tier IS NULL OR a.Tier > 3 THEN N'Unclassified' ELSE CONVERT(nvarchar(4), a.Tier) END) IN (SELECT tv.[value] FROM OPENJSON(@Tier) AS tv))
      AND (@Unlinked = 0 OR NOT EXISTS (SELECT 1 FROM cfg.vCmdbAssetService AS v WHERE v.AssetKey = a.AssetKey))
      AND (@Department IS NULL OR EXISTS (SELECT 1 FROM cfg.vCmdbAssetService AS v WHERE v.AssetKey = a.AssetKey AND v.Department IN (SELECT dv.[value] FROM OPENJSON(@Department) AS dv)))
      AND (@Lifecycle IS NULL OR {LifecycleOfPool} IN (SELECT lv.[value] FROM OPENJSON(@Lifecycle) AS lv))
)
""";

    public const string PoolSql = PoolFrom + """
SELECT p.AssetKey, p.AssetName, p.AssetKind, p.Tier, p.Weighted, p.Services, p.ServiceNumbers, COUNT_BIG(*) OVER () AS Total
FROM pool AS p
ORDER BY CASE WHEN p.Weighted IS NULL THEN 1 ELSE 0 END, p.Weighted DESC, p.AssetName, p.AssetKey
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
OPTION (RECOMPILE);
""";

    public const string PoolKeysSql = PoolFrom + """
SELECT TOP (@Max) p.AssetKey, p.AssetName FROM pool AS p ORDER BY p.AssetName, p.AssetKey
OPTION (RECOMPILE);
""";

    /// One lane: the service's current links; an asset the data no longer holds still shows (by the name it was linked with).
    public const string LaneSql = $"""
WITH latest AS (SELECT {SI.Management.Core.ProData.PublishedRun.DetailedId} AS CollectionId),
risk AS (SELECT s.AssetKey, s.TotalWeightedOrRisk AS Weighted FROM sidata.AssetRiskSummary AS s JOIN latest AS l ON l.CollectionId = s.CollectionId),
lane AS (
    SELECT m.AssetKey, COALESCE(a.AssetName, m.AssetName, m.AssetKey) AS AssetName, a.AssetKind, a.Tier, r.Weighted,
           (SELECT COUNT(*) FROM cfg.CmdbServiceAsset AS o JOIN cfg.CmdbService AS os ON os.ServiceId = o.ServiceId
             WHERE o.AssetKey = m.AssetKey AND o.UnlinkedAt IS NULL AND os.RetiredAt IS NULL AND os.Source = s.Source) AS Services,
           (SELECT STRING_AGG(os.ServiceNumber, N'; ') FROM cfg.CmdbServiceAsset AS o JOIN cfg.CmdbService AS os ON os.ServiceId = o.ServiceId
             WHERE o.AssetKey = m.AssetKey AND o.UnlinkedAt IS NULL AND os.RetiredAt IS NULL AND os.Source = s.Source) AS ServiceNumbers
    FROM cfg.CmdbServiceAsset AS m
    JOIN cfg.CmdbService AS s ON s.ServiceId = m.ServiceId
    LEFT JOIN sidata.Asset AS a ON a.AssetKey = m.AssetKey
    LEFT JOIN risk AS r ON r.AssetKey = m.AssetKey
    WHERE m.ServiceId = @ServiceId AND m.UnlinkedAt IS NULL
      AND (@Kind IS NULL OR EXISTS (SELECT 1 FROM OPENJSON(@Kind) AS kv WHERE N';' + COALESCE(NULLIF(a.AssetKinds, N''), a.AssetKind) + N';' LIKE N'%;' + kv.[value] + N';%'))
      AND (@Text IS NULL OR a.AssetName LIKE @Text OR m.AssetKey LIKE @Text OR m.AssetName LIKE @Text)
      AND (@Tier IS NULL OR (CASE WHEN a.Tier IS NULL OR a.Tier > 3 THEN N'Unclassified' ELSE CONVERT(nvarchar(4), a.Tier) END) IN (SELECT tv.[value] FROM OPENJSON(@Tier) AS tv))
      AND (@Lifecycle IS NULL OR {LifecycleOfLane} IN (SELECT lv.[value] FROM OPENJSON(@Lifecycle) AS lv))
)
SELECT l.AssetKey, l.AssetName, l.AssetKind, l.Tier, l.Weighted, l.Services, l.ServiceNumbers, COUNT_BIG(*) OVER () AS Total
FROM lane AS l
ORDER BY CASE WHEN l.Weighted IS NULL THEN 1 ELSE 0 END, l.Weighted DESC, l.AssetName, l.AssetKey
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
OPTION (RECOMPILE);
""";

    public const string LinksOfSql = """
SELECT m.AssetKey, m.ServiceId
FROM cfg.CmdbServiceAsset AS m
JOIN OPENJSON(@Keys) WITH ([key] nvarchar(400) N'$') AS k ON k.[key] = m.AssetKey
WHERE m.UnlinkedAt IS NULL;
""";

    // ------------------------------------------------------------------------------------------------- reads

    public async Task<CmdbSchema> SchemaAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(SchemaSql, new Dictionary<string, object?>(), ct);
        return rows.Count == 0 ? new CmdbSchema(false, false) : new CmdbSchema(rows[0].Long("HasCmdb") == 1, rows[0].Long("HasData") == 1);
    }

    public async Task<(string Source, long? Version)> ActiveSourceAsync(CancellationToken ct)
    {
        var (rows, _) = await _settings.ReadSettingsAsync(ct);
        var row = rows.FirstOrDefault(r => r.Name.Equals(CmdbSources.Setting, StringComparison.OrdinalIgnoreCase) && r.Scope == CatalogSetting.WebScope);
        return (CmdbSources.FromSettingValue(row?.ValueJson), row?.Version);
    }

    internal static CmdbService Map(SqlRow r) => new(
        (int)(r.Long("ServiceId") ?? 0), r.Str("Source") ?? "", r.Str("ServiceNumber") ?? "", r.Str("ExternalId"), r.Str("Name") ?? "", r.Str("Description"),
        r.Str("Owner"), r.Str("OwnerMail"), r.Str("Criticality"), r.Str("DataSensitivity"), r.Str("Environment"), r.Str("Department"), r.Str("ExtraJson"),
        r.Date("CreatedAt"), r.Str("CreatedBy"), r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Date("RetiredAt"), r.Str("RetiredBy"), r.Str("RetireReason"),
        r.Long("Version") ?? 0, r.Long("Assets") ?? 0);

    public async Task<IReadOnlyList<CmdbService>> ServicesAsync(string source, bool includeRetired, CancellationToken ct) =>
        (await _sql.QueryAsync(ServicesSql, new Dictionary<string, object?> { ["Source"] = source, ["IncludeRetired"] = includeRetired ? 1 : 0 }, ct)).Select(Map).ToList();

    public async Task<CmdbService?> ServiceAsync(int serviceId, CancellationToken ct) =>
        (await _sql.QueryAsync(ServiceSql, new Dictionary<string, object?> { ["ServiceId"] = serviceId }, ct)).Select(Map).FirstOrDefault();

    public async Task<CmdbService?> ServiceByNumberAsync(string source, string number, CancellationToken ct) =>
        (await _sql.QueryAsync(ServiceByNumberSql, new Dictionary<string, object?> { ["Source"] = source, ["Number"] = number }, ct)).Select(Map).FirstOrDefault();

    public async Task<IReadOnlyList<CmdbImportRow>> ImportsAsync(int top, CancellationToken ct) =>
        (await _sql.QueryAsync(ImportsSql, new Dictionary<string, object?> { ["Top"] = Math.Clamp(top, 1, 200) }, ct)).Select(r => new CmdbImportRow(
            r.Long("ImportId") ?? 0, r.Str("Source") ?? "", r.Str("Kind") ?? "", r.Str("Origin"), r.Date("ImportedAt"), r.Str("ImportedBy") ?? "", r.Str("Outcome") ?? "",
            r.Str("Message"), I(r, "ServicesAdded"), I(r, "ServicesUpdated"), I(r, "ServicesRetired"), I(r, "ServicesSkipped"), I(r, "LinksAdded"), I(r, "LinksRemoved"),
            I(r, "LinksRejected"), r.Str("RejectedJson"))).ToList();

    private static int I(SqlRow r, string c) => (int)(r.Long(c) ?? 0);

    /// The map's filters: kind, tier and department may each hold several values ('|'-joined; owner 2026-10-19), each sent
    /// as a JSON array its IN-list reads.
    private static Dictionary<string, object?> FilterParams(MapFilter f) => new()
    {
        ["Kind"] = ProDataFilters.Json(ProDataFilters.Many(f.Kind, ProDataFilters.Kind)),
        ["Text"] = ProDataFilters.Like(ProDataFilters.Text(f.Text)),
        ["Tier"] = ProDataFilters.Json(ProDataFilters.Many(f.Tier, t => string.IsNullOrWhiteSpace(t) ? null : ProDataFilters.Tiers.Contains(t.Trim()) ? t.Trim() : throw new ArgumentException($"'{t}' is not a tier"))),
        ["Unlinked"] = f.UnlinkedOnly ? 1 : 0,
        ["Department"] = ProDataFilters.Json(ProDataFilters.Many(f.Department, d => ProDataFilters.Label(d, "department"))),
        // #855 M18: the lifecycle states as a JSON list from the FIXED names (null = every state)
        ["Lifecycle"] = SI.Management.Core.ProData.LifecycleFilter.Parse(new[] { f.Lifecycle }).States is { } ls ? JsonSerializer.Serialize(ls) : null,
    };

    private static MapAsset MapAssetRow(SqlRow r) => new(r.Str("AssetKey") ?? "", r.Str("AssetName") ?? r.Str("AssetKey") ?? "", r.Str("AssetKind"),
        r.Long("Tier") is { } t && t is >= 0 and <= 3 ? t.ToString(CultureInfo.InvariantCulture) : ProDataFilters.Unclassified,
        r.TryGetValue("Weighted", out var w) && w is not null ? Convert.ToDouble(w, CultureInfo.InvariantCulture) : null, (int)(r.Long("Services") ?? 0), r.Str("ServiceNumbers"));

    public async Task<(IReadOnlyList<MapAsset> Assets, long Total)> AssetsAsync(MapFilter filter, int skip, int take, CancellationToken ct)
    {
        var p = FilterParams(filter);
        p["Skip"] = Math.Max(0, skip); p["Take"] = Math.Clamp(take, 1, ProDataFilters.MaxTake);
        // #264: the weighted risk follows the page's exempted scope (the shared rewrite)
        var rows = await _sql.QueryAsync(SI.Management.Core.ProData.Exempted.Apply(PoolSql), p, ct);
        return (rows.Select(MapAssetRow).ToList(), rows.Count > 0 ? rows[0].Long("Total") ?? rows.Count : 0);
    }

    public async Task<IReadOnlyList<(string Key, string Name)>> AssetKeysAsync(MapFilter filter, int max, CancellationToken ct)
    {
        var p = FilterParams(filter);
        p["Max"] = Math.Clamp(max, 1, MaxLinkBatch);
        return (await _sql.QueryAsync(PoolKeysSql, p, ct)).Select(r => (r.Str("AssetKey") ?? "", r.Str("AssetName") ?? r.Str("AssetKey") ?? "")).Where(x => x.Item1.Length > 0).ToList();
    }

    public async Task<(IReadOnlyList<MapAsset> Assets, long Total)> ServiceAssetsAsync(int serviceId, MapFilter filter, int skip, int take, CancellationToken ct)
    {
        var p = FilterParams(filter);
        p.Remove("Unlinked"); p.Remove("Department");
        p["ServiceId"] = serviceId; p["Skip"] = Math.Max(0, skip); p["Take"] = Math.Clamp(take, 1, ProDataFilters.MaxTake);
        var rows = await _sql.QueryAsync(SI.Management.Core.ProData.Exempted.Apply(LaneSql), p, ct);
        return (rows.Select(MapAssetRow).ToList(), rows.Count > 0 ? rows[0].Long("Total") ?? rows.Count : 0);
    }

    public async Task<IReadOnlyList<(string AssetKey, int ServiceId)>> LinksOfAsync(IReadOnlyList<string> assetKeys, CancellationToken ct)
    {
        if (assetKeys.Count == 0) return Array.Empty<(string, int)>();
        var rows = await _sql.QueryAsync(LinksOfSql, new Dictionary<string, object?> { ["Keys"] = JsonSerializer.Serialize(assetKeys) }, ct);
        return rows.Select(r => (r.Str("AssetKey") ?? "", (int)(r.Long("ServiceId") ?? 0))).ToList();
    }

    // ------------------------------------------------------------------------------------------------- writes

    private static string Who(string by) => by.Length > 256 ? by[..256] : by;
    private static string? Why(string? reason) => string.IsNullOrWhiteSpace(reason) ? null : reason.Trim().Length > 400 ? reason.Trim()[..400] : reason.Trim();

    public static string ServiceJson(CmdbServiceInput i) => JsonSerializer.Serialize(new
    {
        name = i.Name, description = i.Description, owner = i.Owner, ownerMail = i.OwnerMail, criticality = i.Criticality,
        dataSensitivity = i.DataSensitivity, environment = i.Environment, department = i.Department,
    });

    private static Dictionary<string, object?> InputParams(CmdbServiceInput n, string by, string? reason) => new()
    {
        ["Name"] = n.Name, ["Description"] = n.Description, ["Owner"] = n.Owner, ["OwnerMail"] = n.OwnerMail, ["Criticality"] = n.Criticality,
        ["DataSensitivity"] = n.DataSensitivity, ["Environment"] = n.Environment, ["Department"] = n.Department, ["Json"] = ServiceJson(n),
        ["By"] = Who(by), ["Reason"] = Why(reason),
    };

    /// The outcome words every write answers with, in the page's language.
    public static WriteResult Outcome(SqlRow? row, string what)
    {
        var o = row?.Str("Outcome");
        return o switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, what + " saved", row?.Long("Version")),
            "Missing" => new WriteResult(WriteStatus.Refused, MissingSchemaMessage + " -- nothing was written"),
            "ReadOnly" => new WriteResult(WriteStatus.Refused, $"the CMDB source is {CmdbSources.Label(row?.Str("ActiveSource") ?? "external")}: services and links are changed in that source, not here -- nothing was written"),
            "NotFound" => new WriteResult(WriteStatus.Refused, "the service does not exist -- nothing was written"),
            "Retired" => new WriteResult(WriteStatus.Refused, "the service is retired; a retired service is kept as history and cannot be changed -- nothing was written"),
            "Duplicate" => new WriteResult(WriteStatus.Refused, "a service with this name already exists -- nothing was written"),
            "Stale" => new WriteResult(WriteStatus.Stale, "the service changed since you opened it -- reload and make the change again", row?.Long("Version")),
            _ => throw new InvalidOperationException("the CMDB write returned no outcome"),
        };
    }

    public async Task<(WriteResult Result, CmdbService? Service)> CreateAsync(CmdbServiceInput input, string by, string? reason, CancellationToken ct)
    {
        var why = input.Validate();
        if (why.Count > 0) return (new WriteResult(WriteStatus.Refused, string.Join("; ", why)), null);
        if (string.IsNullOrWhiteSpace(by)) return (new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record"), null);
        var n = input.Normalized();
        var rows = await _sql.QueryAsync(CreateSql, InputParams(n, by, reason), ct);
        var r = Outcome(rows.FirstOrDefault(), "the service " + n.Name);
        if (r.Status != WriteStatus.Saved) return (r, null);
        var id = (int)(rows[0].Long("ServiceId") ?? 0);
        return (r with { Message = $"{rows[0].Str("ServiceNumber")} {n.Name} added" }, await ServiceAsync(id, ct));
    }

    public async Task<WriteResult> UpdateAsync(int serviceId, CmdbServiceInput input, long expectedVersion, string by, string? reason, CancellationToken ct)
    {
        var why = input.Validate();
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        var p = InputParams(input.Normalized(), by, reason);
        p["ServiceId"] = serviceId; p["Expected"] = expectedVersion;
        return await AfterAsync(Outcome((await _sql.QueryAsync(UpdateSql, p, ct)).FirstOrDefault(), "the service"), ct);
    }

    public async Task<WriteResult> RetireAsync(int serviceId, long expectedVersion, string by, string reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason for retiring the service (at least 3 characters)");
        return await AfterAsync(Outcome((await _sql.QueryAsync(RetireSql, new Dictionary<string, object?>
        {
            ["ServiceId"] = serviceId, ["Expected"] = expectedVersion, ["By"] = Who(by), ["Reason"] = Why(reason),
        }, ct)).FirstOrDefault(), "the retirement"), ct);
    }

    public async Task<(WriteResult Result, int Changed)> LinkAsync(int serviceId, IReadOnlyList<(string Key, string? Name)> assets, bool link, string by, string? reason, CancellationToken ct)
    {
        if (assets.Count == 0) return (new WriteResult(WriteStatus.Refused, "no asset was selected"), 0);
        if (assets.Count > MaxLinkBatch) return (new WriteResult(WriteStatus.Refused, $"at most {MaxLinkBatch} assets are linked in one change"), 0);
        var json = JsonSerializer.Serialize(assets.Select(a => new { key = a.Key, name = a.Name }));
        var rows = await _sql.QueryAsync(LinkSql, new Dictionary<string, object?>
        {
            ["ServiceId"] = serviceId, ["Assets"] = json, ["Link"] = link ? 1 : 0, ["By"] = Who(by), ["Reason"] = Why(reason),
        }, ct);
        var r = await AfterAsync(Outcome(rows.FirstOrDefault(), link ? "the links" : "the unlinks"), ct);
        return (r, r.Status == WriteStatus.Saved ? (int)(rows[0].Long("Changed") ?? 0) : 0);
    }

    public async Task<CmdbImportResult> ImportAsync(string source, string kind, string? origin, string? sha256, string payload, string by, string? reason, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ImportSql, new Dictionary<string, object?>
        {
            ["Source"] = source, ["Kind"] = kind, ["Origin"] = origin is { Length: > 400 } ? origin[..400] : origin, ["Sha256"] = sha256, ["Payload"] = payload,
            ["By"] = Who(by), ["Reason"] = Why(reason),
        }, ct);
        var r = rows.FirstOrDefault() ?? throw new InvalidOperationException("the CMDB import returned no outcome");
        if (r.Str("Outcome") == "Imported") await RecomputeAsync(ct);
        return new CmdbImportResult(r.Str("Outcome") ?? "", r.Str("Message"), r.Long("ImportId"), I(r, "ServicesAdded"), I(r, "ServicesUpdated"), I(r, "ServicesRetired"),
            I(r, "ServicesSkipped"), I(r, "ServicesUnchanged"), I(r, "LinksAdded"), I(r, "LinksRemoved"), I(r, "LinksRejected"), r.Str("RejectedJson"));
    }
}
