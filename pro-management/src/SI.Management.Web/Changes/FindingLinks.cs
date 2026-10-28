using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One finding of a link: its finding key (the report's ConfigurationId / CVE), its title and report as they were when linked.
public sealed record FindingLinkMember(string Id, string Title, string Report);

/// <summary>
/// #693 one operator's LINK: two or more findings of ONE CI that are one finding. It is one item of the data-model template
/// recommendation-equivalence ('recommendation-equivalence:&lt;id&gt;', match "link") -- the SAME store and the SAME mechanism
/// as the same recommendation across providers and the meaning rules (engine\data-model\SI-RecommendationEquivalence.ps1):
/// Risk Analysis keys every member on the canonical finding (its key, its lifecycle: the members' history carries over),
/// the findings outputs send it once, the vulnerability close-loop keeps one record (a member's record closes as Linked).
/// Unlinked = stage not_used; the item stays (history, reversible).
/// </summary>
public sealed record FindingLink(string Id, string Owner, string CanonicalId, string CanonicalTitle, IReadOnlyList<FindingLinkMember> Members,
    string LinkedBy, string Reason, DateTime? LinkedAt, string Stage)
{
    public string? UnlinkedBy { get; init; }
    public string? UnlinkReason { get; init; }
    public DateTime? UnlinkedAt { get; init; }
    /// The cfg.ItemOverride row's last writer and time (the change log has every write).
    public string? UpdatedBy { get; init; }
    public DateTime? UpdatedAt { get; init; }
    public bool Active => Stage is "" or "production";
    public string ItemKey => FindingLinks.Prefix + Id;
    public bool Has(string key) => Members.Any(m => string.Equals(m.Id, key, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// #693 THE MANUAL LINK SCREEN's store: reads the links (cfg.ItemOverride, kind datamodel) and writes one through the ONE
/// writer of that table (<see cref="ItemOverrideRepository.WriteAsync"/>: one transaction with its cfg.ChangeLog row -- who,
/// when, the reason, before and after). The owner a link is made on is the finding's own (sidata.Finding.RaFindingKey,
/// '&lt;CI id or asset:&lt;id&gt;&gt;|&lt;key&gt;' -- what Risk Analysis keys the finding on). Effective from the next Risk
/// Analysis run.
/// </summary>
public sealed class FindingLinks
{
    public const string Template = "recommendation-equivalence";
    public const string Prefix = Template + ":";
    public const string IdPrefix = "link-";
    public const int MaxMembers = 50;
    public const string MissingKeyMessage = "this database does not record which CI a finding is keyed on yet (sidata.Finding.RaFindingKey) -- findings can be linked after the next update and Risk Analysis run";

    private readonly ISqlExecutor _sql;
    private readonly ItemOverrideRepository _overrides;
    public FindingLinks(ISqlExecutor sql, ItemOverrideRepository overrides) { _sql = sql; _overrides = overrides; }

    // ---------------------------------------------------------------- pure

    /// PURE. The owner of a Risk Analysis finding key ('&lt;owner&gt;|&lt;key&gt;'), or null.
    public static string? OwnerOf(string? raFindingKey)
    {
        if (string.IsNullOrWhiteSpace(raFindingKey)) return null;
        var i = raFindingKey.IndexOf('|');
        return i > 0 ? raFindingKey[..i] : null;
    }

    /// PURE. The finding key the link names a finding by: the report's own key (its configuration id, else its CVE).
    public static string? KeyOf(string? configurationId, string? cve) =>
        !string.IsNullOrWhiteSpace(configurationId) ? configurationId.Trim() : !string.IsNullOrWhiteSpace(cve) ? cve.Trim() : null;

    /// PURE. A stable id for a link of these keys on this owner: 'link-' + 16 hex characters (the group id rule
    /// ^[a-z0-9][a-z0-9_\-\.]{0,99}$). The same keys on the same owner give the same id (linking them again updates it).
    public static string IdFor(string owner, IEnumerable<string> keys)
    {
        var text = owner.Trim().ToLowerInvariant() + "|" + string.Join("|", keys.Select(k => k.Trim().ToLowerInvariant()).OrderBy(k => k, StringComparer.Ordinal));
        var h = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return IdPrefix + Convert.ToHexString(h, 0, 8).ToLowerInvariant();
    }

    /// PURE. The link's item body (what the engine reads: id, match link, owner, members, canonicalId, canonicalTitle,
    /// linkedBy, reason, linkedAt; unlinkedBy / unlinkReason / unlinkedAt once unlinked).
    public static string Body(FindingLink l)
    {
        var o = new JsonObject
        {
            ["id"] = l.Id, ["match"] = "link", ["stage"] = l.Active ? "production" : "not_used", ["owner"] = l.Owner,
            ["canonicalId"] = l.CanonicalId, ["canonicalTitle"] = l.CanonicalTitle,
            ["members"] = new JsonArray(l.Members.Select(m => (JsonNode)new JsonObject { ["id"] = m.Id, ["title"] = m.Title, ["report"] = m.Report }).ToArray()),
            ["linkedBy"] = l.LinkedBy, ["reason"] = l.Reason,
            ["linkedAt"] = (l.LinkedAt ?? DateTime.UtcNow).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
        };
        if (!l.Active)
        {
            o["unlinkedBy"] = l.UnlinkedBy ?? "";
            o["unlinkReason"] = l.UnlinkReason ?? "";
            o["unlinkedAt"] = (l.UnlinkedAt ?? DateTime.UtcNow).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }
        return o.ToJsonString();
    }

    /// PURE. A link item's body -> the link; null for any other group (key, fold) or a body that cannot be read.
    public static FindingLink? Parse(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var d = JsonDocument.Parse(body);
            var o = d.RootElement;
            if (o.ValueKind != JsonValueKind.Object || !string.Equals(S(o, "match"), "link", StringComparison.OrdinalIgnoreCase)) return null;
            var members = o.TryGetProperty("members", out var m) && m.ValueKind == JsonValueKind.Array
                ? m.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object).Select(x => new FindingLinkMember(S(x, "id"), S(x, "title"), S(x, "report"))).ToList()
                : new List<FindingLinkMember>();
            return new FindingLink(S(o, "id"), S(o, "owner"), S(o, "canonicalId"), S(o, "canonicalTitle"), members, S(o, "linkedBy"), S(o, "reason"), When(S(o, "linkedAt")), S(o, "stage"))
            {
                UnlinkedBy = NullIfEmpty(S(o, "unlinkedBy")), UnlinkReason = NullIfEmpty(S(o, "unlinkReason")), UnlinkedAt = When(S(o, "unlinkedAt")),
            };
        }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// PURE. The link for a selection, or the reasons it is refused: two to <see cref="MaxMembers"/> findings, every one
    /// keyed on the SAME owner (one CI), at least two different finding keys, a reason of three characters or more, and
    /// none already in an ACTIVE link on that owner (unlink it first). -Canonical: the finding id that stays (default: the
    /// most severe, then the highest risk score, then the first key). Members = the distinct keys.
    /// </summary>
    public static (FindingLink? Link, IReadOnlyList<string> Problems) Build(IReadOnlyList<LinkCandidate> findings, string? canonicalFindingId, string reason, string by,
        IReadOnlyList<FindingLink> existing, DateTime now)
    {
        var why = new List<string>();
        if (findings.Count < 2) why.Add("select two or more findings to link into one");
        var withKey = findings.Where(f => f.Key is not null && f.Owner is not null).ToList();
        foreach (var f in findings.Where(f => f.Key is null)) why.Add($"{f.Title}: the finding has no key (configuration id or CVE) to link it by");
        foreach (var f in findings.Where(f => f.Key is not null && f.Owner is null)) why.Add($"{f.Title}: SecurityInsight does not know which CI this finding is on yet (it is keyed after the next Risk Analysis run)");
        var owners = withKey.Select(f => f.Owner!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (owners.Count > 1) why.Add($"the findings are on {owners.Count} different CIs ({string.Join(", ", withKey.Select(f => f.AssetName).Distinct(StringComparer.OrdinalIgnoreCase).Take(4))}) -- a link joins findings of ONE CI");
        var keys = withKey.Select(f => f.Key!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (withKey.Count >= 2 && keys.Count < 2) why.Add("the selected rows are the same finding (one key) -- nothing to link");
        if (keys.Count > MaxMembers) why.Add($"at most {MaxMembers} findings in one link");
        if ((reason ?? "").Trim().Length < 3) why.Add("write why these findings are one (at least 3 characters) -- it is what the link and the change log show");
        if (string.IsNullOrWhiteSpace(by)) why.Add("the signed-in user has no name to record");
        if (why.Count > 0 || owners.Count != 1) return (null, why);
        var owner = owners[0];
        foreach (var l in existing.Where(l => l.Active && string.Equals(l.Owner, owner, StringComparison.OrdinalIgnoreCase)))
            foreach (var k in keys.Where(l.Has))
                why.Add($"{k} is already linked (link {l.Id}, into {l.CanonicalId}) -- unlink that first on the finding's page");
        if (why.Count > 0) return (null, why);
        var pick = canonicalFindingId is { Length: > 0 } cid ? withKey.FirstOrDefault(f => f.FindingId == cid) : null;
        if (canonicalFindingId is { Length: > 0 } && pick is null) return (null, new[] { "the finding chosen to stay is not one of the selection" });
        pick ??= withKey.OrderByDescending(f => SeverityRank(f.Severity)).ThenByDescending(f => f.RiskScore).ThenBy(f => f.Key, StringComparer.OrdinalIgnoreCase).First();
        var members = keys.Select(k => withKey.First(f => string.Equals(f.Key, k, StringComparison.OrdinalIgnoreCase)))
            .Select(f => new FindingLinkMember(f.Key!, Cut(f.Title, 400), Cut(f.ReportName, 256))).ToList();
        var r = reason!.Trim(); if (r.Length > 400) r = r[..400];
        return (new FindingLink(IdFor(owner, keys), owner, pick.Key!, Cut(pick.Title, 400), members, by, r, now, "production"), Array.Empty<string>());
    }

    /// PURE. The severity words as a rank (Very High / Critical highest).
    public static int SeverityRank(string? s) => (s ?? "").Trim().ToLowerInvariant() switch
    {
        "very high" or "critical" => 5, "high" => 4, "medium-high" => 3, "medium" or "moderate" => 2, "low" => 1, _ => 0,
    };

    private static string Cut(string? s, int n) { s ??= ""; return s.Length > n ? s[..n] : s; }
    private static string S(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;
    private static DateTime? When(string s) => DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    // ---------------------------------------------------------------- reads

    public const string ListSql = """
IF OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL
SELECT ItemKey, State, BodyJson, UpdatedAt, UpdatedBy
FROM cfg.ItemOverride
WHERE Kind = N'datamodel' AND ItemKey LIKE N'recommendation-equivalence:link-%' AND State = N'override'
ORDER BY ItemKey;
""";

    /// The finding keys Risk Analysis gave the findings of one collection (@c, @ids = a JSON array of finding ids).
    public const string KeysSql = """
IF COL_LENGTH(N'sidata.Finding', N'RaFindingKey') IS NULL
    SELECT CAST(NULL AS nvarchar(64)) AS FindingId, CAST(N'missing' AS nvarchar(900)) AS RaFindingKey WHERE 1 = 0;
ELSE
    EXEC sp_executesql N'SELECT CONVERT(nvarchar(64), f.FindingId) AS FindingId, f.RaFindingKey
FROM sidata.Finding AS f
WHERE f.CollectionId = TRY_CONVERT(int, @c) AND f.FindingId IN (SELECT TRY_CONVERT(bigint, value) FROM OPENJSON(@ids));', N'@c nvarchar(32), @ids nvarchar(max)', @c = @c, @ids = @ids;
""";

    public const string HasKeySql = "SELECT CASE WHEN COL_LENGTH(N'sidata.Finding', N'RaFindingKey') IS NULL THEN 0 ELSE 1 END AS Ready;";

    /// Every link (active and unlinked), newest write first; empty when the table does not exist yet.
    public async Task<IReadOnlyList<FindingLink>> ListAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct);
        return rows.Select(r => Parse(r.Str("BodyJson")) is { } l ? l with { UpdatedBy = r.Str("UpdatedBy"), UpdatedAt = r.Date("UpdatedAt") } : null)
            .Where(l => l is not null).Select(l => l!).OrderByDescending(l => l.UpdatedAt ?? l.LinkedAt ?? DateTime.MinValue).ToList();
    }

    /// The links one finding is in (its owner + key), active first.
    public async Task<IReadOnlyList<FindingLink>> ForFindingAsync(string? owner, string? key, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(key)) return Array.Empty<FindingLink>();
        return (await ListAsync(ct)).Where(l => string.Equals(l.Owner, owner, StringComparison.OrdinalIgnoreCase) && l.Has(key))
            .OrderByDescending(l => l.Active).ToList();
    }

    /// The owner (CI) Risk Analysis keyed each finding of one collection on: finding id -> owner. Null when the database has
    /// no such column yet.
    public async Task<IReadOnlyDictionary<string, string?>?> OwnersAsync(string collectionId, IEnumerable<string> findingIds, CancellationToken ct)
    {
        var ready = await _sql.QueryAsync(HasKeySql, new Dictionary<string, object?>(), ct);
        if (ready.Count == 0 || ready[0].Long("Ready") != 1) return null;
        var ids = findingIds.Where(i => !string.IsNullOrWhiteSpace(i)).Distinct(StringComparer.Ordinal).ToList();
        var map = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (ids.Count == 0) return map;
        var rows = await _sql.QueryAsync(KeysSql, new Dictionary<string, object?> { ["c"] = collectionId, ["ids"] = JsonSerializer.Serialize(ids) }, ct);
        foreach (var r in rows) if (r.Str("FindingId") is { } id) map[id] = OwnerOf(r.Str("RaFindingKey"));
        return map;
    }

    // ---------------------------------------------------------------- writes (through the ONE writer of cfg.ItemOverride)

    public async Task<WriteResult> SaveAsync(FindingLink link, string by, CancellationToken ct) =>
        await _overrides.WriteAsync(new ItemOverrideWrite(DataModelItemValidator.Kind, link.ItemKey, ItemOverrideRepository.StateOverride, Body(link), link.Active ? link.Reason : link.UnlinkReason), by, ct);

    /// Unlink: the item stays (stage not_used, who / when / why recorded) -- reversible by linking the findings again.
    public async Task<WriteResult> UnlinkAsync(string id, string reason, string by, CancellationToken ct)
    {
        if ((reason ?? "").Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "write why the findings are no longer one (at least 3 characters)");
        var cur = (await ListAsync(ct)).FirstOrDefault(l => string.Equals(l.Id, id, StringComparison.Ordinal));
        if (cur is null) return new WriteResult(WriteStatus.Refused, $"there is no link {id}");
        if (!cur.Active) return new WriteResult(WriteStatus.Refused, $"link {id} is already undone");
        var r = reason!.Trim(); if (r.Length > 400) r = r[..400];
        return await SaveAsync(cur with { Stage = "not_used", UnlinkedBy = by, UnlinkReason = r, UnlinkedAt = DateTime.UtcNow }, by, ct);
    }
}

/// One selected finding as the link sees it: its id, its key, the owner (CI) Risk Analysis keyed it on, and what is shown.
public sealed record LinkCandidate(string FindingId, string? Key, string? Owner, string Title, string AssetName, string ReportName, string Severity, double RiskScore);
