using System.Text.Json;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// ACTIVE DEVICES NOT ONBOARDED IN DEFENDER (#858, owner 2026-10-21: "including NotOnboarded MDE devices makes sense as it is
// active devices somewhere but not secure enough. but of course they must be active but in not onboarded state. it would
// make sense to have a view to show them - Active devices not onboarded in Defender (both MDC/MDE)").
// THE INCLUSION RULE (decided): a device Defender only DISCOVERED on the network IS an asset and counts -- a real device
// that is not protected -- but ONLY while it is ACTIVE (seen within the device window); a not seen / retired discovered
// device never counts, and a customer excludes one by tag (si_is_excluded, asset tagging).
// The view: the ACTIVE device CIs whose Defender for Endpoint onboarding is not "onboarded" (MDE device discovery), and the
// Azure machines without the Defender agent (Defender for Cloud: no Defender for Endpoint device, no onboarding state),
// split by status. Read from sidata.Ci, lifecycle active only (its columns; the document only for the page's own fields
// and the exclusion tag).
// =====================================================================================================================

/// One status of the view: its stored value, its words, what it means, and whether a person can act on it (onboard it).
public sealed record NotOnboardedStatus(string Value, string Label, string Meaning, bool Actionable);

/// The devices of one status: how many are listed, and how many more a customer excluded by tag (not listed, not counted).
public sealed record NotOnboardedCount(string Status, long Devices, long Excluded);

/// One device of the view.
public sealed record NotOnboardedRow(string CiId, string? Name, string Status, string? OnboardingStatus, string? IpAddress, IReadOnlyList<string> IpAddresses,
    IReadOnlyList<string> MacAddresses, string? OsName, string? OsPlatform, string? AssetType, DateTime? FirstSeen, DateTime? LastSeen, IReadOnlyList<string> Sources)
{
    /// #856 a nameless device's fallback (its IP, MAC or source id) -- shown marked; null when it has a name.
    public CiNameFallback? NameFallback => CiDisplayName.Of(Name, IpAddress ?? CiDisplayName.BestIp(IpAddresses) ?? MacAddresses.FirstOrDefault() ?? CiId);
    /// The address the view shows (the IpAddress column, else the best of the device's addresses).
    public string? Ip => IpAddress ?? CiDisplayName.BestIp(IpAddresses);
}

/// The view's page: the counts per status (the whole set), the rows of the chosen status, paged.
/// <paramref name="Ready"/>: false while the database has no CI columns yet (the data sync adds them).
public sealed record NotOnboardedPage(bool Ready, IReadOnlyList<NotOnboardedCount> Counts, IReadOnlyList<NotOnboardedRow> Rows, long Total, string? Status, int Page, int Size)
{
    public static NotOnboardedPage NotReady(string? status, int page, int size) => new(false, [], [], 0, status, page, size);
    /// Every listed device (every status).
    public long Devices => Counts.Sum(c => c.Devices);
    /// Every device a customer excluded by tag.
    public long Excluded => Counts.Sum(c => c.Excluded);
    public long Of(string status) => Counts.Where(c => c.Status == status).Sum(c => c.Devices);
}

public interface INotOnboardedViews
{
    /// The counts per status and one page of devices (<paramref name="status"/> null = every status).
    Task<QueryResult<NotOnboardedPage>> ReadAsync(string? status, int page, int size, CancellationToken ct);
}

public static class NotOnboarded
{
    public const string CanBeOnboarded = "can_be_onboarded";
    public const string Unsupported = "unsupported";
    public const string InsufficientInfo = "insufficient_info";
    /// An Azure machine without the Defender agent (Defender for Cloud) -- no Defender for Endpoint onboarding state at all.
    public const string NoAgent = "no_agent";
    /// Any other state that is not onboarded (e.g. offboarded).
    public const string Other = "other";

    /// The statuses in the order the view lists them: the actionable one first.
    public static readonly IReadOnlyList<NotOnboardedStatus> Statuses =
    [
        new(CanBeOnboarded, "Can be onboarded", "Defender found it on the network and it can run Defender for Endpoint: onboard it. This is the actionable group.", true),
        new(NoAgent, "Azure machine without the agent", "Defender for Cloud lists the Azure virtual machine, but it has no Defender for Endpoint device: deploy the agent (the MDE extension) or onboard it.", true),
        new(Unsupported, "Unsupported", "Defender saw it, but Defender for Endpoint cannot run on it (a printer, a network device, an unsupported operating system): protect it another way, or exclude it by tag.", false),
        new(InsufficientInfo, "Insufficient info", "Defender saw it on the network but not enough to tell what it is. It stays listed while it is active; exclude it by tag if it is not yours.", false),
        new(Other, "Other state", "Any other state that is not onboarded (for example offboarded).", false),
    ];

    public static NotOnboardedStatus Of(string? value) =>
        Statuses.FirstOrDefault(s => string.Equals(s.Value, value, StringComparison.OrdinalIgnoreCase)) ?? new(value ?? "", value ?? "", "", false);

    /// The page sizes the view offers.
    public static readonly IReadOnlyList<int> Sizes = [50, 100, 250, 500];

    /// The status a request names, or null (every status; an unknown value is every status too).
    public static string? Status(string? value) => Statuses.FirstOrDefault(s => string.Equals(s.Value, value, StringComparison.OrdinalIgnoreCase))?.Value;
}

/// <summary>The statements: fixed text, parameters only, read-only.</summary>
public static class NotOnboardedSql
{
    /// The status of a device CI (sidata.Ci AS c).
    public const string Bucket =
        "CASE WHEN NULLIF(c.OnboardingStatus, N'') IS NULL THEN N'no_agent' "
        + "WHEN LOWER(c.OnboardingStatus) IN (N'can_be_onboarded', N'unsupported', N'insufficient_info') THEN LOWER(c.OnboardingStatus) ELSE N'other' END";

    /// The document fields the view reads (one parse per row; j).
    private const string Doc = """
OUTER APPLY OPENJSON(CASE WHEN ISJSON(c.DocJson) = 1 THEN c.DocJson END) WITH (
    Excluded NVARCHAR(8) '$.si_is_excluded', FirstSeen NVARCHAR(40) '$.si_first_seen',
    IpList NVARCHAR(MAX) '$.si_ip_addresses' AS JSON, IpOne NVARCHAR(400) '$.si_ip_addresses',
    MacList NVARCHAR(MAX) '$.si_mac_addresses' AS JSON, MacOne NVARCHAR(400) '$.si_mac_addresses',
    LinkMde NVARCHAR(400) '$.si_link_mde', LinkAzure NVARCHAR(400) '$.si_link_azure', LinkEg NVARCHAR(400) '$.si_link_eg') AS j
""";

    /// <summary>
    /// The devices of the view, part 1: device CIs of the lifecycle @Lifecycle (active; a CI written before the lifecycle
    /// counts as active). Named in each statement itself, so the lifecycle reader guard sees it there.
    /// </summary>
    public const string DeviceOfLifecycle = "c.Class = N'device' AND ISNULL(c.Lifecycle, N'active') = @Lifecycle";

    /// <summary>
    /// The devices of the view, part 2: the onboarding state is set and not onboarded -- or an Azure machine with no
    /// onboarding state and no Defender for Endpoint device. <paramref name="ctx"/>: the database has the CI's Defender
    /// device id as a column (MdeDeviceId); else the document's MDE link decides.
    /// </summary>
    public static string NotOnboardedState(bool ctx) =>
        "("
        + "(NULLIF(c.OnboardingStatus, N'') IS NOT NULL AND LOWER(c.OnboardingStatus) <> N'onboarded') "
        + "OR (NULLIF(c.OnboardingStatus, N'') IS NULL AND LOWER(c.AzureResourceType) = N'microsoft.compute/virtualmachines' AND "
        + (ctx ? "(NULLIF(c.MdeDeviceId, N'') IS NULL OR c.MdeDeviceId = N'[]')" : "NULLIF(j.LinkMde, N'') IS NULL") + "))";

    /// The whole device test (both parts).
    public static string Where(bool ctx) => DeviceOfLifecycle + " AND " + NotOnboardedState(ctx);

    /// The excluded-by-tag test (the asset tagging exclusion).
    public const string ExcludedSql = "LOWER(ISNULL(j.Excluded, N'')) IN (N'true', N'1')";

    /// The devices per status, and how many of them a customer excluded by tag.
    public static string Counts(bool ctx) => $"""
SELECT b.Status, SUM(1 - b.Excluded) AS Devices, SUM(b.Excluded) AS Excluded
FROM (
    SELECT {Bucket} AS Status, CASE WHEN {ExcludedSql} THEN 1 ELSE 0 END AS Excluded
    FROM sidata.Ci AS c
{Doc}
    WHERE {DeviceOfLifecycle} AND {NotOnboardedState(ctx)}
) AS b
GROUP BY b.Status
""";

    /// One page of the devices (@Status NULL = every status), the newest seen first; never the excluded ones.
    public static string Rows(bool ctx) => $"""
SELECT c.CiId, c.Name, {Bucket} AS Status, c.OnboardingStatus, c.IpAddress, c.OsName, c.OsPlatform, c.AssetType, c.LastSeen,
       j.FirstSeen, j.IpList, j.IpOne, j.MacList, j.MacOne, j.LinkMde, j.LinkAzure, j.LinkEg, COUNT_BIG(*) OVER () AS TotalRows
FROM sidata.Ci AS c
{Doc}
WHERE {DeviceOfLifecycle} AND {NotOnboardedState(ctx)} AND NOT ({ExcludedSql}) AND (@Status IS NULL OR {Bucket} = @Status)
ORDER BY c.LastSeen DESC, c.CiId
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
""";
}

/// <summary>The SQL implementation over <see cref="IProSql"/>; the schema probe is the CI views' own.</summary>
public sealed class NotOnboardedViews(IProSql sql, ICiViews cis, TimeProvider? clock = null) : INotOnboardedViews
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(q.Text);
        var rows = await ViewTimeout.Run(t => sql.QueryAsync(q, t), Timeout, ct).ConfigureAwait(false);
        return (rows, EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    public async Task<QueryResult<NotOnboardedPage>> ReadAsync(string? status, int page, int size, CancellationToken ct)
    {
        status = NotOnboarded.Status(status);
        size = NotOnboarded.Sizes.Contains(size) ? size : NotOnboarded.Sizes[0];
        page = Math.Max(1, page);
        var schema = (await cis.SchemaAsync(ct).ConfigureAwait(false)).Data;
        if (!schema.Ci || !schema.DocFields) return new(NotOnboardedPage.NotReady(status, page, size), "", sql.SourceName, _clock.GetUtcNow());
        var ctx = schema.CtxFields;
        var life = CiLifecycleDefinitions.DefaultFilter;
        var (cr, ctext) = await Run(new SqlQuery(NotOnboardedSql.Counts(ctx), new Dictionary<string, object?> { ["Lifecycle"] = life }), ct).ConfigureAwait(false);
        var counts = cr.Select(r => new NotOnboardedCount(ProDataQueries.S(r, "Status"), ProDataQueries.L(r, "Devices"), ProDataQueries.L(r, "Excluded")))
            .OrderBy(c => Rank(c.Status)).ToList();
        var (rr, rtext) = await Run(new SqlQuery(NotOnboardedSql.Rows(ctx), new Dictionary<string, object?>
        {
            ["Lifecycle"] = life, ["Status"] = status, ["Skip"] = (page - 1) * size, ["Take"] = size,
        }), ct).ConfigureAwait(false);
        var rows = rr.Select(Map).ToList();
        var total = rr.Count > 0 ? ProDataQueries.L(rr[0], "TotalRows") : status is null ? counts.Sum(c => c.Devices) : counts.Where(c => c.Status == status).Sum(c => c.Devices);
        return new(new NotOnboardedPage(true, counts, rows, total, status, page, size), ctext + "\n\n" + rtext, sql.SourceName, _clock.GetUtcNow());
    }

    private static int Rank(string status)
    {
        for (var i = 0; i < NotOnboarded.Statuses.Count; i++) if (NotOnboarded.Statuses[i].Value == status) return i;
        return NotOnboarded.Statuses.Count;
    }

    internal static NotOnboardedRow Map(IReadOnlyDictionary<string, object?> r)
    {
        var sources = new List<string>();
        if (ProDataQueries.SN(r, "LinkMde") is not null || ProDataQueries.SN(r, "OnboardingStatus") is not null) sources.Add("Defender for Endpoint (device discovery)");
        if (ProDataQueries.SN(r, "LinkAzure") is not null) sources.Add("Defender for Cloud (Azure)");
        if (ProDataQueries.SN(r, "LinkEg") is not null) sources.Add("Exposure Management");
        return new NotOnboardedRow(ProDataQueries.S(r, "CiId"), ProDataQueries.SN(r, "Name"), ProDataQueries.S(r, "Status"), ProDataQueries.SN(r, "OnboardingStatus"),
            ProDataQueries.SN(r, "IpAddress"), List(ProDataQueries.SN(r, "IpList"), ProDataQueries.SN(r, "IpOne")), List(ProDataQueries.SN(r, "MacList"), ProDataQueries.SN(r, "MacOne")),
            ProDataQueries.SN(r, "OsName"), ProDataQueries.SN(r, "OsPlatform"), ProDataQueries.SN(r, "AssetType"),
            CiDoc.UtcOrNull(ProDataQueries.SN(r, "FirstSeen")), ProDataQueries.T(r, "LastSeen"), sources);
    }

    /// A list kept as JSON (the document's list), else the one text.
    private static IReadOnlyList<string> List(string? json, string? one)
    {
        if (json is { Length: > 0 })
        {
            try
            {
                using var d = JsonDocument.Parse(json);
                if (d.RootElement.ValueKind == JsonValueKind.Array)
                    return d.RootElement.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).Where(s => s.Length > 0).ToList();
            }
            catch (JsonException) { }
        }
        return one is { Length: > 0 } ? [one] : [];
    }
}
