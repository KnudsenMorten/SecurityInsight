using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One per-server exception (sidata.CiSoftwareException): ONE rule's match of ONE software on ONE CI marked a false positive
/// by an Admin, with who, when, why -- and, once undone, who undid it, when and why.
public sealed record CiSoftwareExceptionRow(long Id, string CiId, string RuleId, string Vendor, string Product, string Reason, string SetBy, DateTime? SetAt,
    bool Removed, string? RemovedBy, DateTime? RemovedAt, string? RemovedReason)
{
    /// The software as the software lists carry it: "vendor/product", lower-case.
    public string Software => SoftwareKey.Of(Vendor, Product);
    public string StateText => Removed ? "undone" : "in force";
}

/// One path of a software copy on one of the CI's Defender devices (sidata.SoftwareEvidence, the newest run only).
public sealed record SoftwareEvidencePath(string DeviceId, string Vendor, string Product, string Version, string PathType, string FullPath, string InstallKind,
    string? Application, string? ApplicationVendor, string? ApplicationVersion, string? ApplicationSource, DateTime? CollectionTime)
{
    public string Software => SoftwareKey.Of(Vendor, Product);
    /// The application the path lies in, as the engine says it (Format-SIEvidenceApplication): from the device's own software
    /// inventory "vendor/name version", else the folder name.
    public string ApplicationText => ApplicationSource == "inventory"
        ? ((string.IsNullOrEmpty(ApplicationVendor) ? "" : ApplicationVendor + "/") + Application + (string.IsNullOrEmpty(ApplicationVersion) ? "" : " " + ApplicationVersion))
        : Application ?? "";
}

/// Whether a Defender device's evidence was read in its newest run (read), could not be read (unknown), is being written
/// (writing -- shown as unknown) or was never read (none).
public sealed record SoftwareEvidenceDeviceState(string DeviceId, string State, DateTime? CollectionTime, int? Rows)
{
    public bool Read => State == "read";
}

/// A tier detection that matched through installed software: the rule's claim on the CI and the software it matched.
public sealed record SoftwareDetection(string Rule, string RuleId, string Label, int? Tier, bool Winner, bool Admissible, string Software);

/// A candidate for an exception (never applied by itself): a software tier detection on a CI whose every disk path is in a
/// user profile or a data folder, or whose every disk path is a copy bundled in another product.
/// Where a suggestion page starts: after this (CI, vendor, product) key; Start = before the first.
public sealed record SuggestionKey(string CiId, string Vendor, string Product)
{
    public static readonly SuggestionKey Start = new("", "", "");
}

public sealed record SoftwareExceptionSuggestion(string CiId, string? CiName, SoftwareDetection Detection, string Why, long Paths, string? SamplePath);

public static class SoftwareKey
{
    public static string Of(string? vendor, string? product) => ((vendor ?? "").Trim() + "/" + (product ?? "").Trim()).ToLowerInvariant();

    /// "vendor/product" -> (vendor, product); null when it is not one.
    public static (string Vendor, string Product)? Split(string? software)
    {
        var s = (software ?? "").Trim().ToLowerInvariant();
        var i = s.IndexOf('/');
        if (i <= 0 || i == s.Length - 1 || s.IndexOf('/', i + 1) >= 0) return null;
        return (s[..i], s[(i + 1)..]);
    }
}

/// <summary>
/// #1219 (4) the tier detections of a CI that matched through installed software, read from the CI document the CI build
/// wrote (si_tier_claims): a claim on a tier whose evidence is si_installed_software, one entry per software it matched ("installed
/// software vendor/product", ConvertTo-SICiEvidenceText). PURE.
/// </summary>
public static class SoftwareDetections
{
    public const string Prefix = "installed software ";

    public static IReadOnlyList<SoftwareDetection> From(CiDocument doc) =>
        doc.Claims.Where(c => c.Tier is not null && (c.Kind is null or "rule") && c.Evidence.Contains("si_installed_software", StringComparer.Ordinal))
            .SelectMany(c => c.Matched.Where(m => m.StartsWith(Prefix, StringComparison.Ordinal) && !m.EndsWith("...", StringComparison.Ordinal))
                .Select(m => m[Prefix.Length..].Trim().ToLowerInvariant()).Where(s => SoftwareKey.Split(s) is not null).Distinct(StringComparer.Ordinal)
                .Select(s => new SoftwareDetection(c.Rule, RuleIdOf(c.Rule), c.Label ?? c.Name ?? c.Rule, c.Tier, c.Winner, c.Admissible, s)))
            .ToList();

    /// The rule id of a CI rule ("&lt;rule id&gt;/&lt;detection id&gt;" -> "&lt;rule id&gt;"), the engine's Get-SICiRuleIdOf.
    public static string RuleIdOf(string rule)
    {
        var s = (rule ?? "").Trim();
        var i = s.IndexOf('/');
        return i > 0 ? s[..i] : s;
    }
}

/// The C# twin of what the engine accepts (engine\_shared\SI-SoftwareException.ps1): which exceptions can be set. Sends nothing.
public static partial class SoftwareExceptionValidator
{
    public const int MaxCiId = 64, MaxRule = 200, MaxPart = 256, MaxReason = 1000;

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_\-]{0,199}$", RegexOptions.CultureInvariant)]
    public static partial Regex RulePattern();

    public static IReadOnlyList<string> Validate(string? ciId, string? ruleId, string? vendor, string? product, string? reason)
    {
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(ciId) || ciId.Trim().Length > MaxCiId) why.Add("name the CI (its id, at most 64 characters)");
        if (!RulePattern().IsMatch((ruleId ?? "").Trim())) why.Add("name the rule (its id, as the tier claim shows it)");
        if (string.IsNullOrWhiteSpace(product) || product.Trim().Length > MaxPart || (vendor ?? "").Trim().Length > MaxPart || (vendor ?? "").Contains('/') || product.Contains('/'))
            why.Add("name the software (vendor and product, as the detection matched it)");
        var r = (reason ?? "").Trim();
        if (r.Length < 3) why.Add("give a reason (at least 3 characters) -- it is shown on the CI and kept in the change log");
        else if (r.Length > MaxReason) why.Add($"the reason is longer than {MaxReason} characters");
        return why;
    }
}

/// <summary>
/// #1219 (4) PER-SERVER EXCEPTIONS of a software detection (owner 2026-11-16: "fine tune on a per server so i can exempt a
/// wrong detection of wordpress"). Reads and writes sidata.CiSoftwareException the way the manual CI overrides do
/// (<see cref="CiOverrideStore"/>): every write is ONE transaction with its cfg.ChangeLog row (Name '&lt;ci&gt;|&lt;rule&gt;|&lt;software&gt;',
/// Scope 'ci', Kind 'cisoftwareexception'); an undo is SOFT (Removed, RemovedBy, RemovedAt, RemovedReason). The CI build and the
/// profiler apply the exceptions in force (engine\_shared\SI-SoftwareException.ps1). Also reads the software evidence of a CI
/// (sidata.SoftwareEvidence -- Community: the CI page shows it in both editions) and the candidates for an exception.
/// Nothing here is written except through Review &amp; commit (<see cref="SoftwareExceptionChanges"/>).
/// </summary>
public sealed class SoftwareExceptionStore
{
    public const string Kind = "cisoftwareexception";
    public const string MissingTableMessage = "This database has no table for per-server software exceptions yet (sidata.CiSoftwareException) -- it arrives with the next update of the database schema.";
    public const int UndoneListDays = 90;
    public const int SuggestionPage = 200;

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'sidata.CiSoftwareException') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    public const string ListSql = """
IF OBJECT_ID(N'sidata.CiSoftwareException') IS NOT NULL
SELECT TOP (2000) ExceptionId, CiId, RuleId, Vendor, Product, Reason, SetBy, SetAt, CONVERT(int, Removed) AS Removed, RemovedBy, RemovedAt, RemovedReason
FROM sidata.CiSoftwareException
WHERE (@CiId IS NULL OR CiId = @CiId)
  AND (Removed = 0 OR RemovedAt >= DATEADD(day, -@UndoneDays, SYSUTCDATETIME()))
ORDER BY Removed, CiId, RuleId, Vendor, Product, SetAt DESC;
""";

    public const string ReadSql = """
IF OBJECT_ID(N'sidata.CiSoftwareException') IS NOT NULL
SELECT ExceptionId, CiId, RuleId, Vendor, Product, Reason, SetBy, SetAt, CONVERT(int, Removed) AS Removed, RemovedBy, RemovedAt, RemovedReason
FROM sidata.CiSoftwareException WHERE ExceptionId = @Id;
""";

    /// The exception in force for one CI, rule and software (one at most).
    public const string CurrentSql = """
IF OBJECT_ID(N'sidata.CiSoftwareException') IS NOT NULL
SELECT TOP (1) ExceptionId, CiId, RuleId, Vendor, Product, Reason, SetBy, SetAt, CONVERT(int, Removed) AS Removed, RemovedBy, RemovedAt, RemovedReason
FROM sidata.CiSoftwareException WHERE CiId = @CiId AND RuleId = @RuleId AND Vendor = @Vendor AND Product = @Product AND Removed = 0 ORDER BY SetAt DESC, ExceptionId DESC;
""";

    public const string SetSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.CiSoftwareException') IS NULL OR OBJECT_ID(N'cfg.ChangeLog') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM sidata.CiSoftwareException WITH (UPDLOCK, HOLDLOCK) WHERE CiId = @CiId AND RuleId = @RuleId AND Vendor = @Vendor AND Product = @Product AND Removed = 0)
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
INSERT sidata.CiSoftwareException (CiId, RuleId, Vendor, Product, Reason, SetBy) VALUES (@CiId, @RuleId, @Vendor, @Product, @Reason, @By);
DECLARE @new bigint = SCOPE_IDENTITY();
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(@CiId + N'|' + @RuleId + N'|' + @Vendor + N'/' + @Product, 128), N'ci', N'cisoftwareexception', N'Set', N'(the rule uses this software on this server)',
        N'false positive on this server: rule ' + @RuleId + N' does not use ' + @Vendor + N'/' + @Product, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome, @new AS ExceptionId;
""";

    public const string RemoveSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.CiSoftwareException') IS NULL OR OBJECT_ID(N'cfg.ChangeLog') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @ci nvarchar(64) = NULL, @rule nvarchar(200) = NULL, @sw nvarchar(600) = NULL, @old nvarchar(max) = NULL;
SELECT @ci = CiId, @rule = RuleId, @sw = Vendor + N'/' + Product, @old = N'false positive on this server (' + Reason + N')'
FROM sidata.CiSoftwareException WITH (UPDLOCK, HOLDLOCK) WHERE ExceptionId = @Id AND Removed = 0;
IF @ci IS NULL
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
UPDATE sidata.CiSoftwareException SET Removed = 1, RemovedBy = @By, RemovedAt = SYSUTCDATETIME(), RemovedReason = @Reason WHERE ExceptionId = @Id;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(@ci + N'|' + @rule + N'|' + @sw, 128), N'ci', N'cisoftwareexception', N'Reset', @old, N'(undone -- the rule uses this software on this server again)', @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// The CI's Defender devices and whether each one's evidence was read in its newest run.
    public const string EvidenceStateSql = """
IF OBJECT_ID(N'sidata.CiLink') IS NOT NULL AND OBJECT_ID(N'sidata.SoftwareEvidenceDevice') IS NOT NULL
    EXEC sp_executesql N'SELECT DISTINCT LOWER(l.NativeId) AS DeviceId, ISNULL(s.State, N''none'') AS State, s.CollectionTime, s.[Rows]
FROM sidata.CiLink l LEFT JOIN sidata.SoftwareEvidenceDevice s ON s.DeviceId = LOWER(l.NativeId)
WHERE l.CiId = @CiId AND l.Provider = N''mde''', N'@CiId nvarchar(64)', @CiId = @CiId;
""";

    /// Every path of the named software ("vendor/product" JSON list) on the CI's Defender devices whose evidence was READ.
    public const string EvidenceRowsSql = """
IF OBJECT_ID(N'sidata.CiLink') IS NOT NULL AND OBJECT_ID(N'sidata.SoftwareEvidenceDevice') IS NOT NULL AND OBJECT_ID(N'sidata.SoftwareEvidence') IS NOT NULL
    EXEC sp_executesql N'SELECT e.DeviceId, e.Vendor, e.Product, e.Version, e.PathType, e.FullPath, e.InstallKind, e.Application, e.ApplicationVendor, e.ApplicationVersion,
       e.ApplicationSource, e.CollectionTime
FROM (SELECT DISTINCT LOWER(NativeId) AS DeviceId FROM sidata.CiLink WHERE CiId = @CiId AND Provider = N''mde'') d
JOIN sidata.SoftwareEvidenceDevice s ON s.DeviceId = d.DeviceId AND s.State = N''read''
JOIN sidata.SoftwareEvidence e ON e.DeviceId = s.DeviceId
WHERE LOWER(e.Vendor + N''/'' + e.Product) IN (SELECT LOWER(j.[value]) FROM OPENJSON(@Software) j)
ORDER BY e.Vendor, e.Product, e.Version, e.PathType, e.FullPath', N'@CiId nvarchar(64), @Software nvarchar(max)', @CiId = @CiId, @Software = @Software;
""";

    /// The candidates for an exception, a page at a time: per CI and software (the newest run's evidence of its READ Defender
    /// devices), every DISK path in a user profile / data folder ('data'), or every disk path a copy bundled in another product
    /// ('bundled') -- only where the CI's tier claims matched that software ("installed software vendor/product" in the CI
    /// document; the page checks it exactly) and no exception is in force for it on that CI.
    public const string SuggestionsSql = """
IF OBJECT_ID(N'sidata.SoftwareEvidence') IS NOT NULL AND OBJECT_ID(N'sidata.SoftwareEvidenceDevice') IS NOT NULL AND OBJECT_ID(N'sidata.CiLink') IS NOT NULL
   AND OBJECT_ID(N'sidata.Ci') IS NOT NULL AND OBJECT_ID(N'sidata.CiSoftwareException') IS NOT NULL
    EXEC sp_executesql N'WITH c AS (
    SELECT l.CiId, e.Vendor, e.Product, COUNT(*) AS Paths,
           SUM(CASE WHEN e.PathType = N''disk'' THEN 1 ELSE 0 END) AS Disk,
           SUM(CASE WHEN e.PathType = N''disk'' AND e.InstallKind IN (N''user-profile'', N''data-folder'') THEN 1 ELSE 0 END) AS DataDisk,
           SUM(CASE WHEN e.PathType = N''disk'' AND e.InstallKind = N''bundled'' THEN 1 ELSE 0 END) AS BundledDisk,
           MIN(CASE WHEN e.PathType = N''disk'' THEN LEFT(e.FullPath, 400) END) AS SamplePath
    FROM sidata.SoftwareEvidence e
    JOIN sidata.SoftwareEvidenceDevice s ON s.DeviceId = e.DeviceId AND s.State = N''read''
    JOIN sidata.CiLink l ON l.Provider = N''mde'' AND LOWER(l.NativeId) = e.DeviceId
    GROUP BY l.CiId, e.Vendor, e.Product)
SELECT c.CiId, ci.Name, c.Vendor, c.Product, c.Paths, c.SamplePath, CASE WHEN c.DataDisk = c.Disk THEN N''data'' ELSE N''bundled'' END AS Why, ci.DocJson
FROM c JOIN sidata.Ci ci ON ci.CiId = c.CiId
WHERE c.Disk > 0 AND (c.DataDisk = c.Disk OR c.BundledDisk = c.Disk)
  AND ci.DocJson LIKE N''%installed software '' + c.Vendor + N''/'' + c.Product + N''%''
  AND NOT EXISTS (SELECT 1 FROM sidata.CiSoftwareException x WHERE x.CiId = c.CiId AND x.Vendor = c.Vendor AND x.Product = c.Product AND x.Removed = 0)
  AND (c.CiId > @AfterCi OR (c.CiId = @AfterCi AND (c.Vendor > @AfterVendor OR (c.Vendor = @AfterVendor AND c.Product > @AfterProduct))))
ORDER BY c.CiId, c.Vendor, c.Product
OFFSET 0 ROWS FETCH NEXT @Take ROWS ONLY', N'@AfterCi nvarchar(64), @AfterVendor nvarchar(256), @AfterProduct nvarchar(256), @Take int',
    @AfterCi = @AfterCi, @AfterVendor = @AfterVendor, @AfterProduct = @AfterProduct, @Take = @Take;
""";

    private readonly ISqlExecutor _sql;
    public SoftwareExceptionStore(ISqlExecutor sql) => _sql = sql;

    public static CiSoftwareExceptionRow Map(SqlRow r) => new(r.Long("ExceptionId") ?? 0, r.Str("CiId") ?? "", r.Str("RuleId") ?? "", r.Str("Vendor") ?? "", r.Str("Product") ?? "",
        r.Str("Reason") ?? "", r.Str("SetBy") ?? "", r.Date("SetAt"), (r.Long("Removed") ?? 0) != 0, r.Str("RemovedBy"), r.Date("RemovedAt"), r.Str("RemovedReason"));

    /// The evidence path IN FULL, a person's folder name included (owner 2026-11-17: an Admin needs the whole path as evidence
    /// to correct a wrong conclusion); who sees it follows the department scoping.
    public static SoftwareEvidencePath MapPath(SqlRow r) => new(r.Str("DeviceId") ?? "", r.Str("Vendor") ?? "", r.Str("Product") ?? "", r.Str("Version") ?? "", r.Str("PathType") ?? "",
        r.Str("FullPath") ?? "", r.Str("InstallKind") ?? "", r.Str("Application"), r.Str("ApplicationVendor"), r.Str("ApplicationVersion"), r.Str("ApplicationSource"), r.Date("CollectionTime"));

    public async Task<bool> TableExistsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    /// Every exception (of one CI when ciId is given): those in force, plus those undone in the last 90 days.
    public async Task<IReadOnlyList<CiSoftwareExceptionRow>> ListAsync(string? ciId, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["CiId"] = string.IsNullOrWhiteSpace(ciId) ? null : ciId.Trim(), ["UndoneDays"] = UndoneListDays }, ct)).Select(Map).ToList();

    public async Task<CiSoftwareExceptionRow?> ReadAsync(long id, CancellationToken ct) =>
        (await _sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["Id"] = id }, ct)).Select(Map).FirstOrDefault();

    public async Task<CiSoftwareExceptionRow?> CurrentAsync(string ciId, string ruleId, string vendor, string product, CancellationToken ct) =>
        (await _sql.QueryAsync(CurrentSql, new Dictionary<string, object?> { ["CiId"] = ciId, ["RuleId"] = ruleId, ["Vendor"] = vendor, ["Product"] = product }, ct)).Select(Map).FirstOrDefault();

    public async Task<IReadOnlyList<SoftwareEvidenceDeviceState>> EvidenceStatesAsync(string ciId, CancellationToken ct) =>
        (await _sql.QueryAsync(EvidenceStateSql, new Dictionary<string, object?> { ["CiId"] = ciId }, ct))
            .Select(r => new SoftwareEvidenceDeviceState(r.Str("DeviceId") ?? "", r.Str("State") ?? "none", r.Date("CollectionTime"), r.Long("Rows") is { } n ? (int)n : null)).ToList();

    /// The paths of the named software on the CI (none named = none read).
    public async Task<IReadOnlyList<SoftwareEvidencePath>> EvidenceAsync(string ciId, IEnumerable<string> software, CancellationToken ct)
    {
        var list = software.Select(s => (s ?? "").Trim().ToLowerInvariant()).Where(s => s.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        if (list.Count == 0) return Array.Empty<SoftwareEvidencePath>();
        return (await _sql.QueryAsync(EvidenceRowsSql, new Dictionary<string, object?> { ["CiId"] = ciId, ["Software"] = JsonSerializer.Serialize(list) }, ct)).Select(MapPath).ToList();
    }

    /// One page of candidates (SuggestionPage keys READ after the key -after, in key order), checked against the CI's own
    /// tier claims (the SQL text match is only the narrowing) -- so a page may show fewer; the next page continues after the
    /// last key READ (Next), never after the last row shown, so paging is stable. Next = null on the last page.
    public async Task<(IReadOnlyList<SoftwareExceptionSuggestion> Rows, SuggestionKey? Next)> SuggestionsAsync(SuggestionKey? after, CancellationToken ct)
    {
        var a = after ?? SuggestionKey.Start;
        var rows = await _sql.QueryAsync(SuggestionsSql, new Dictionary<string, object?>
        {
            ["AfterCi"] = a.CiId, ["AfterVendor"] = a.Vendor, ["AfterProduct"] = a.Product, ["Take"] = SuggestionPage + 1,
        }, ct);
        var page = rows.Take(SuggestionPage).ToList();
        SuggestionKey? next = rows.Count > SuggestionPage && page.Count > 0 ? new SuggestionKey(page[^1].Str("CiId") ?? "", page[^1].Str("Vendor") ?? "", page[^1].Str("Product") ?? "") : null;
        var list = new List<SoftwareExceptionSuggestion>();
        foreach (var r in page)
        {
            var sw = SoftwareKey.Of(r.Str("Vendor"), r.Str("Product"));
            foreach (var d in SoftwareDetections.From(CiDoc.Parse(r.Str("DocJson"))).Where(d => d.Software == sw))
                list.Add(new SoftwareExceptionSuggestion(r.Str("CiId") ?? "", r.Str("Name"), d, r.Str("Why") ?? "data", r.Long("Paths") ?? 0, r.Str("SamplePath")));
        }
        return (list, next);
    }

    private static string Clip(string s, int n) => s.Length > n ? s[..n] : s;

    /// Set an exception (none in force for the same CI, rule and software).
    public async Task<WriteResult> SetAsync(string ciId, string ruleId, string vendor, string product, string reason, string by, CancellationToken ct)
    {
        var why = SoftwareExceptionValidator.Validate(ciId, ruleId, vendor, product, reason);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(SetSql, new Dictionary<string, object?>
        {
            ["CiId"] = ciId.Trim(), ["RuleId"] = ruleId.Trim(), ["Vendor"] = (vendor ?? "").Trim().ToLowerInvariant(), ["Product"] = product.Trim().ToLowerInvariant(),
            ["Reason"] = reason.Trim(), ["By"] = Clip(by, 256),
        }, ct);
        return Outcome(rows, $"the exception of {SoftwareKey.Of(vendor, product)} for rule {ruleId} on {ciId}", "is already in force -- nothing was written");
    }

    /// Undo (soft) one exception: the rule uses the software on that server again from the next CI build and profiler run.
    public async Task<WriteResult> RemoveAsync(long id, string reason, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(RemoveSql, new Dictionary<string, object?> { ["Id"] = id, ["Reason"] = Clip(reason.Trim(), 1000), ["By"] = Clip(by, 256) }, ct);
        return Outcome(rows, "the exception", "is already undone -- nothing was written");
    }

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string what, string stale) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, what + " saved -- the next CI build and endpoint run apply it"),
        "Stale" => new WriteResult(WriteStatus.Stale, what + " " + stale),
        "Missing" => new WriteResult(WriteStatus.Refused, MissingTableMessage + " Nothing was written."),
        _ => throw new InvalidOperationException("the software exception write returned no outcome"),
    };

    /// The install kind in words.
    public static string KindText(string? kind) => kind switch
    {
        "installed" => "installed",
        "bundled" => "bundled in another product",
        "user-profile" => "in a user profile",
        "data-folder" => "in a data folder",
        "registry-only" => "registry only",
        _ => "unknown",
    };

    /// Why a candidate is listed, in words.
    public static string WhyText(string why) => why == "bundled"
        ? "every path is a copy bundled inside another product"
        : "every path is in a user profile or a data folder";
}

/// <summary>
/// #1219 (4) the per-server software exceptions through THE staging (Review &amp; commit): set one (mark a detection a false
/// positive on one server) or undo one. Validated when staged, previewed before -> after, written by
/// <see cref="SoftwareExceptionStore"/> in one transaction with its cfg.ChangeLog row, in the signed-in name. Admin only
/// (ChangeAccess: Administer -- the default for a kind it does not name).
/// </summary>
public sealed class SoftwareExceptionChanges : IStagedChangeHandler
{
    public const string ChangeKind = "ci-software-exception";
    private readonly SoftwareExceptionStore _store;
    public SoftwareExceptionChanges(SoftwareExceptionStore store) => _store = store;

    public bool Handles(string kind) => kind == ChangeKind;

    public static string Describe(CiSoftwareExceptionRow r) =>
        $"false positive on {r.CiId}: rule {r.RuleId} does not use {r.Software} -- set by {r.SetBy}\nReason: {r.Reason}";

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewSetAsync(string? ciId, string? ruleId, string? vendor, string? product, string? reason, CancellationToken ct)
    {
        var why = SoftwareExceptionValidator.Validate(ciId, ruleId, vendor, product, reason);
        if (why.Count > 0) return (null, why);
        if (!await _store.TableExistsAsync(ct)) return (null, new[] { SoftwareExceptionStore.MissingTableMessage });
        var ci = ciId!.Trim(); var rule = ruleId!.Trim(); var v = (vendor ?? "").Trim().ToLowerInvariant(); var p = product!.Trim().ToLowerInvariant();
        if (await _store.CurrentAsync(ci, rule, v, p, ct) is not null) return (null, new[] { "nothing changed -- this exception is already in force" });
        return (new StagedChange
        {
            Kind = ChangeKind,
            Title = $"Mark rule {rule} on {ci} a false positive for {SoftwareKey.Of(v, p)}",
            Data = new(StringComparer.Ordinal) { ["action"] = "set", ["key"] = $"{ci}|{rule}|{v}/{p}", ["ciId"] = ci, ["ruleId"] = rule, ["vendor"] = v, ["product"] = p, ["reason"] = reason!.Trim() },
        }, Array.Empty<string>());
    }

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewRemoveAsync(long id, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        if (!await _store.TableExistsAsync(ct)) return (null, new[] { SoftwareExceptionStore.MissingTableMessage });
        var cur = await _store.ReadAsync(id, ct);
        if (cur is null || cur.Removed) return (null, new[] { "that exception does not exist or is already undone" });
        return (new StagedChange
        {
            Kind = ChangeKind, Title = $"Undo the false positive of rule {cur.RuleId} on {cur.CiId} for {cur.Software}",
            Data = new(StringComparer.Ordinal) { ["action"] = "remove", ["key"] = $"{cur.CiId}|{cur.RuleId}|{cur.Software}", ["id"] = id.ToString(CultureInfo.InvariantCulture), ["ciId"] = cur.CiId, ["reason"] = reason.Trim() },
        }, Array.Empty<string>());
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var why = new List<string>(); var warnings = new List<string>();
        if (!await _store.TableExistsAsync(ct)) return new ChangePreview(c, "", "", new[] { SoftwareExceptionStore.MissingTableMessage }, warnings);
        if (c.Get("action") == "remove")
        {
            var cur = long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) ? await _store.ReadAsync(id, ct) : null;
            if (cur is null || cur.Removed) why.Add("the exception is already undone -- discard this change");
            return new ChangePreview(c, cur is null ? "(none)" : Describe(cur), "(undone -- the rule uses this software on this server again from the next CI build)", why, warnings);
        }
        var ci = c.Get("ciId") ?? ""; var rule = c.Get("ruleId") ?? ""; var v = c.Get("vendor") ?? ""; var p = c.Get("product") ?? "";
        why.AddRange(SoftwareExceptionValidator.Validate(ci, rule, v, p, c.Get("reason")));
        if (await _store.CurrentAsync(ci, rule, v, p, ct) is not null) why.Add("this exception is already in force -- discard this change");
        warnings.Add("Only this rule stops using this software, and only on this server: its other evidence, every other rule and every other server are unchanged. The findings of the software stay; the CI says the detection is excepted.");
        return new ChangePreview(c, $"rule {rule} uses {SoftwareKey.Of(v, p)} on {ci}",
            $"false positive on {ci}: rule {rule} does not use {SoftwareKey.Of(v, p)}\nReason: {c.Get("reason")}", why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        if (c.Get("action") == "remove")
            return long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)
                ? await _store.RemoveAsync(id, c.Get("reason") ?? "", by, ct)
                : new WriteResult(WriteStatus.Refused, "the change names no exception");
        return await _store.SetAsync(c.Get("ciId") ?? "", c.Get("ruleId") ?? "", c.Get("vendor") ?? "", c.Get("product") ?? "", c.Get("reason") ?? "", by, ct);
    }
}
