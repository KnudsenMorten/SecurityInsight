using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One exemption as the GUI writes it. Domain = the finding's security domain (#252: whose owners review it); null = unknown.
public sealed record ExemptionRequest(string Scope, string? ReportName, string? ConfigurationId, string? Cve, string? AssetKey, string? AssetName, string Reason, DateTime? ExpiresAt,
    string? Domain = null);

public sealed record ExemptionRow(string ExemptionId, string Scope, string? ReportName, string? ConfigurationId, string? Cve, string? AssetKey,
    string Reason, DateTime? ExpiresAt, string CreatedBy, DateTime? CreatedAt, DateTime? RevokedAt);

/// <summary>
/// THE one class that knows the shape of cfg.Exemption (L-CONFIG lane: ExemptionId, Scope, ReportName, ConfigurationId,
/// Cve, AssetKey, Reason, ExpiresAt, CreatedBy, CreatedAt, RevokedAt). A column rename is a change here only.
/// Writes are one transaction each, with their cfg.ChangeLog row (Name 'exemption/&lt;id&gt;', Scope 'exemption',
/// Kind 'exemption'; Action Set = created, Reset = revoked). Nothing is ever deleted: a revoke stamps RevokedAt.
/// </summary>
public sealed partial class ExemptionRepository
{
    /// The scopes the GUI writes: one finding (asset + issue), one issue on every asset, or a whole asset.
    public const string ScopeFinding = "finding";
    public const string ScopeIssue = "issue";
    public const string ScopeAsset = "asset";
    public static readonly IReadOnlyList<string> Scopes = [ScopeFinding, ScopeIssue, ScopeAsset];
    public const int MaxExpiryDays = 3 * 366;

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,7}$", RegexOptions.CultureInvariant)] private static partial Regex CvePattern();
    [GeneratedRegex(@"^[A-Za-z0-9._:\-]{1,128}$", RegexOptions.CultureInvariant)] private static partial Regex ConfigIdPattern();
    [GeneratedRegex(@"^[A-Za-z0-9_]{1,128}$", RegexOptions.CultureInvariant)] private static partial Regex ReportPattern();

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.Exemption') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    public const string CreateSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.Exemption WITH (UPDLOCK, HOLDLOCK)
           WHERE Scope = @Scope AND RevokedAt IS NULL AND (ExpiresAt IS NULL OR ExpiresAt > SYSUTCDATETIME())
             AND ISNULL(ReportName, N'') = ISNULL(@ReportName, N'') AND ISNULL(ConfigurationId, N'') = ISNULL(@ConfigurationId, N'')
             AND ISNULL(Cve, N'') = ISNULL(@Cve, N'') AND ISNULL(AssetKey, N'') = ISNULL(@AssetKey, N''))
BEGIN
    COMMIT;
    SELECT N'Exists' AS Outcome, CAST(NULL AS nvarchar(64)) AS ExemptionId;
    RETURN;
END;
DECLARE @ids TABLE (ExemptionId nvarchar(64));
INSERT cfg.Exemption (Scope, ReportName, ConfigurationId, Cve, AssetKey, Reason, ExpiresAt, CreatedBy, CreatedAt)
OUTPUT CONVERT(nvarchar(64), inserted.ExemptionId) INTO @ids
VALUES (@Scope, @ReportName, @ConfigurationId, @Cve, @AssetKey, @Reason, @ExpiresAt, @By, SYSUTCDATETIME());
DECLARE @id nvarchar(64) = (SELECT TOP (1) ExemptionId FROM @ids);
-- #252: the direct path is an approval in one step -- recorded as approved by the one who committed it. Through
-- sp_executesql, so a database without the #252 columns yet still takes the exemption.
IF COL_LENGTH(N'cfg.Exemption', N'ApprovedBy') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.Exemption SET ApprovedBy = @By, ApprovedAt = SYSUTCDATETIME(), Domain = @Domain WHERE CONVERT(nvarchar(64), ExemptionId) = @id',
        N'@By nvarchar(256), @Domain nvarchar(64), @id nvarchar(64)', @By = @By, @Domain = @Domain, @id = @id;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption/' + @id, 128), N'exemption', N'exemption', N'Set', NULL, @Body, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome, @id AS ExemptionId;
""";

    public const string RevokeSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) CONCAT(Scope, N' ', ISNULL(ReportName, N''), N' ', ISNULL(ConfigurationId, N''), N' ', ISNULL(Cve, N''), N' ', ISNULL(AssetKey, N''))
                              FROM cfg.Exemption WITH (UPDLOCK, HOLDLOCK)
                              WHERE CONVERT(nvarchar(64), ExemptionId) = @ExemptionId AND RevokedAt IS NULL);
IF @old IS NULL
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome;
    RETURN;
END;
UPDATE cfg.Exemption SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By WHERE CONVERT(nvarchar(64), ExemptionId) = @ExemptionId AND RevokedAt IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption/' + @ExemptionId, 128), N'exemption', N'exemption', N'Reset', @old, NULL, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// Active exemptions (not revoked, not expired); when the table does not exist yet, no rows (not an error).
    public const string ActiveSql = """
IF OBJECT_ID(N'cfg.Exemption') IS NOT NULL
SELECT TOP (@Top) CONVERT(nvarchar(64), e.ExemptionId) AS ExemptionId, e.Scope, e.ReportName, e.ConfigurationId, e.Cve, e.AssetKey,
       e.Reason, e.ExpiresAt, e.CreatedBy, e.CreatedAt, e.RevokedAt
FROM cfg.Exemption AS e
WHERE e.RevokedAt IS NULL AND (e.ExpiresAt IS NULL OR e.ExpiresAt > SYSUTCDATETIME())
  AND (@AssetKey IS NULL OR e.AssetKey = @AssetKey OR e.AssetKey IS NULL)
ORDER BY e.CreatedAt DESC;
""";

    private readonly ISqlExecutor _sql;
    private readonly TimeProvider _clock;

    private readonly SI.Management.Web.Exemptions.ExemptionSettings? _settings;

    public ExemptionRepository(ISqlExecutor sql, TimeProvider? clock = null, SI.Management.Web.Exemptions.ExemptionSettings? settings = null)
    { _sql = sql; _clock = clock ?? TimeProvider.System; _settings = settings; }

    /// <summary>
    /// #252: no open-ended exemption unless the setting allows it. An exemption given without an end date gets the
    /// default period (from today); with open-ended exemptions allowed it stays without one.
    /// </summary>
    public async Task<ExemptionRequest> WithDefaultPeriodAsync(ExemptionRequest r, CancellationToken ct)
    {
        if (r.ExpiresAt is not null) return r;
        var s = _settings is null ? SI.Management.Web.Exemptions.ExemptionSettings.Values.Defaults : await _settings.ReadAsync(ct);
        if (s.AllowOpenEnded) return r;
        return r with { ExpiresAt = SI.Management.Web.Exemptions.ExemptionPeriods.EndOfDay(_clock.GetUtcNow().UtcDateTime.Date.AddMonths(s.DefaultMonths)) };
    }

    /// <summary>The reasons an exemption is refused (empty = accepted). Sends nothing.</summary>
    public IReadOnlyList<string> Validate(ExemptionRequest r)
    {
        var why = new List<string>();
        if (!Scopes.Contains(r.Scope)) why.Add($"'{r.Scope}' is not an exemption scope (finding, issue, asset)");
        if (r.Cve is not null && !CvePattern().IsMatch(r.Cve)) why.Add($"'{r.Cve}' is not a CVE id (CVE-YYYY-NNNN)");
        if (r.ConfigurationId is not null && !ConfigIdPattern().IsMatch(r.ConfigurationId)) why.Add($"'{r.ConfigurationId}' is not a configuration id (letters, digits, . _ : -)");
        if (r.ReportName is not null && !ReportPattern().IsMatch(r.ReportName)) why.Add($"'{r.ReportName}' is not a report name");
        if (r.AssetKey is not null && (r.AssetKey.Length > 400 || r.AssetKey.Any(char.IsControl))) why.Add("the asset key is not valid");
        switch (r.Scope)
        {
            case ScopeFinding:
                if (r.AssetKey is null) why.Add("a finding exemption needs the asset");
                if (r.Cve is null && r.ConfigurationId is null) why.Add("a finding exemption needs the CVE or the configuration id");
                break;
            case ScopeIssue:
                if (r.Cve is null && r.ConfigurationId is null) why.Add("an issue exemption needs the CVE or the configuration id");
                if (r.AssetKey is not null) why.Add("an issue exemption applies to every asset -- it names no asset");
                break;
            case ScopeAsset:
                if (r.AssetKey is null) why.Add("an asset exemption needs the asset");
                break;
        }
        var reason = r.Reason?.Trim() ?? "";
        if (reason.Length < 3) why.Add("give a reason (at least 3 characters) -- it is what the audit shows");
        if (reason.Length > 400) why.Add("the reason is longer than 400 characters");
        if (r.ExpiresAt is { } e)
        {
            var now = _clock.GetUtcNow().UtcDateTime;
            if (e <= now) why.Add("the expiry is in the past");
            else if (e > now.AddDays(MaxExpiryDays)) why.Add($"the expiry is more than {MaxExpiryDays} days away");
        }
        return why;
    }

    public static string Describe(ExemptionRequest r) => r.Scope switch
    {
        ScopeAsset => $"every finding on {r.AssetName ?? r.AssetKey}",
        ScopeIssue => $"{r.Cve ?? r.ConfigurationId} on every asset" + (r.ReportName is null ? "" : $" ({r.ReportName})"),
        _ => $"{r.Cve ?? r.ConfigurationId} on {r.AssetName ?? r.AssetKey}" + (r.ReportName is null ? "" : $" ({r.ReportName})"),
    } + (r.ExpiresAt is { } x ? $", until {x.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}" : ", no expiry");

    public async Task<bool> TableExistsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    public async Task<WriteResult> CreateAsync(ExemptionRequest r, string by, CancellationToken ct)
    {
        r = await WithDefaultPeriodAsync(r, ct);
        var why = Validate(r);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var body = JsonSerializer.Serialize(new { r.Scope, r.ReportName, r.ConfigurationId, r.Cve, r.AssetKey, ExpiresAt = r.ExpiresAt?.ToString("o", CultureInfo.InvariantCulture) });
        var rows = await _sql.QueryAsync(CreateSql, new Dictionary<string, object?>
        {
            ["Scope"] = r.Scope, ["ReportName"] = r.ReportName, ["ConfigurationId"] = r.ConfigurationId, ["Cve"] = r.Cve, ["AssetKey"] = r.AssetKey,
            ["Reason"] = r.Reason.Trim(), ["ExpiresAt"] = r.ExpiresAt, ["By"] = Trim256(by), ["Body"] = body,
            ["Domain"] = string.IsNullOrWhiteSpace(r.Domain) ? null : r.Domain.Trim(),
        }, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"exemption {rows[0].Str("ExemptionId")} saved: {Describe(r)}"),
            "Exists" => new WriteResult(WriteStatus.Stale, $"an active exemption for {Describe(r)} already exists -- nothing was written"),
            _ => throw new InvalidOperationException("the exemption write returned no outcome"),
        };
    }

    public async Task<WriteResult> RevokeAsync(string exemptionId, string reason, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(exemptionId) || exemptionId.Length > 64) return new WriteResult(WriteStatus.Refused, "no exemption id");
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        var rows = await _sql.QueryAsync(RevokeSql, new Dictionary<string, object?>
        {
            ["ExemptionId"] = exemptionId.Trim(), ["Reason"] = reason.Trim(), ["By"] = Trim256(by),
        }, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"exemption {exemptionId} revoked"),
            "Gone" => new WriteResult(WriteStatus.Stale, $"exemption {exemptionId} is not active any more -- nothing was written"),
            _ => throw new InvalidOperationException("the exemption revoke returned no outcome"),
        };
    }

    public async Task<(IReadOnlyList<ExemptionRow> Rows, string Query)> ActiveAsync(string? assetKey, int top, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ActiveSql, new Dictionary<string, object?> { ["Top"] = Math.Clamp(top, 1, 2000), ["AssetKey"] = assetKey }, ct);
        return (rows.Select(r => new ExemptionRow(r.Str("ExemptionId") ?? "", r.Str("Scope") ?? "", r.Str("ReportName"), r.Str("ConfigurationId"), r.Str("Cve"),
            r.Str("AssetKey"), r.Str("Reason") ?? "", r.Date("ExpiresAt"), r.Str("CreatedBy") ?? "", r.Date("CreatedAt"), r.Date("RevokedAt"))).ToList(), ActiveSql);
    }

    /// Whether an active exemption covers a finding (for the "exempted" marker in the browser).
    public static bool Covers(ExemptionRow e, string assetKey, string? reportName, string? configurationId, string? cve) => e.Scope switch
    {
        ScopeAsset => string.Equals(e.AssetKey, assetKey, StringComparison.OrdinalIgnoreCase),
        ScopeIssue => IssueMatch(e, reportName, configurationId, cve),
        ScopeFinding => string.Equals(e.AssetKey, assetKey, StringComparison.OrdinalIgnoreCase) && IssueMatch(e, reportName, configurationId, cve),
        _ => false,
    };

    private static bool IssueMatch(ExemptionRow e, string? report, string? cfg, string? cve) =>
        (e.ReportName is null || string.Equals(e.ReportName, report, StringComparison.OrdinalIgnoreCase))
        && ((e.Cve is not null && string.Equals(e.Cve, cve, StringComparison.OrdinalIgnoreCase))
            || (e.ConfigurationId is not null && string.Equals(e.ConfigurationId, cfg, StringComparison.OrdinalIgnoreCase)));

    private static string Trim256(string s) => s.Length > 256 ? s[..256] : s;
}
