namespace SI.Management.Core;

/// THE fixed query templates. Nothing else is ever sent to Log Analytics or SQL.
///
/// A template holds placeholders of the form {{NAME}}; <see cref="Fill"/> replaces each with a value that
/// <see cref="QueryParameters"/> already validated (a bounded integer, the configured edition marker, or an
/// escaped KQL string literal). SQL templates take real @parameters instead and contain no placeholder at all.
///
/// Table and column names, with the code that writes them:
///   SI_RiskAnalysis_Summary_CL                 engine/risk-analysis/Invoke-RiskAnalysis.ps1 (TraceCols, fill plan);
///       Summary: ImpactedAssetsList + ImpactedAssetIds (aligned arrays, canonicalised by RA-RiskScore.ps1),
///       CriticalityTier, RiskScoreTotal_Weighted, SecurityDomain, SolutionVersion ("+v3" edition marker);
///       Detailed: AssetName, AssetId, AssetDetectedInReportName (the report), ConfigurationName, SecuritySeverity.
///   SI_Endpoint/Azure/Identity_Profile_CL      the identity map: engine/risk-analysis/_shared/RA-AssetIdentityMap.ps1
///       (SI_AssetId, SI_AssetName, AssetType, Tier, AzureResourceId, ExposureGraphNodeId, vendor ids).
///   sidata.Finding / FindingDaily / AssetDaily  the Detailed result and its day totals (#830: never SI_RiskAnalysis_Detailed_CL
///       or SI_Trend_CL -- optional outputs, off by default): engine/_shared/data-sql/SI-DataSql.ps1.
///   SI_RunHealth_CL                            engine/asset-profiling/shared/Send-SIRunHealthRow.ps1.
///   vuln.VulnerabilityItem / VulnerabilityEvent sql/si-vulnerability-target.sql (+ SI-VulnTarget.ps1 actions).
///   cfg.Setting / cfg.ChangeLog                sql/si-pro-settings.sql.
public static class QueryTemplates
{
    /// Replaces each {{KEY}} with its (already validated) value; every placeholder must be supplied and used.
    public static string Fill(string template, IReadOnlyDictionary<string, string> values)
    {
        var text = template;
        foreach (var (k, v) in values)
        {
            var token = "{{" + k + "}}";
            if (!text.Contains(token, StringComparison.Ordinal)) throw new InvalidOperationException($"Template has no placeholder {token}.");
            text = text.Replace(token, v, StringComparison.Ordinal);
        }
        if (text.Contains("{{", StringComparison.Ordinal)) throw new InvalidOperationException("Template has an unfilled placeholder.");
        return text;
    }

    // ------------------------------------------------------------------------------------------------
    // The asset-identity map, as KQL. Same sources and the same priority as RA-AssetIdentityMap.ps1:
    //   * profile rows that carry a v3 identity (SI_AssetId + SI_AssetName), last {{ID_DAYS}} days;
    //   * id -> name/type/tier: the newest row per table, then FIRST TABLE WINS (endpoint > azure > identity);
    //   * device claims: an Azure VM resource id or a 32-hex ExposureGraph node carried by an ENDPOINT row
    //     belongs to that device; the newest claim wins, and two devices claiming it in the same snapshot
    //     link to nothing (no fusion) -- Add-SIIdentityClaim.
    // Each table is projected to the same typed columns INSIDE its own union leg: the tables disagree on
    // types (Tier int vs long, AssetType string vs dynamic), and a union over raw columns would split them.
    // ------------------------------------------------------------------------------------------------
    private const string ProfileLeg = """
    ({{T}}
        | where TimeGenerated > ago({{ID_DAYS}}d)
        | project CollectionTime, _p = {{P}},
            _i = tostring(column_ifexists("SI_AssetId", "")), _n = tostring(column_ifexists("SI_AssetName", "")),
            _t = tostring(column_ifexists("AssetType", "")), _tier = tostring(column_ifexists("Tier", "")),
            _arm = tolower(tostring(column_ifexists("AzureResourceId", ""))),
            _eg = tolower(tostring(column_ifexists("ExposureGraphNodeId", ""))),
            _rel = pack_array(tostring(column_ifexists("MdeDeviceId", "")), tostring(column_ifexists("AadDeviceId", "")),
                              tostring(column_ifexists("AzureResourceId", "")), tostring(column_ifexists("EntraAccountObjectId", "")),
                              tostring(column_ifexists("PrimaryEntityId", "")), tostring(column_ifexists("ExposureGraphNodeId", ""))))
""";

    private static readonly string IdentityMap =
        "let _looksId = (s:string) { isempty(s) or s matches regex @\"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|(az:)?/subscriptions/.*)$\" };\n" +
        "let _profiles = union isfuzzy=true\n" +
        ProfileLeg.Replace("{{T}}", "SI_Endpoint_Profile_CL").Replace("{{P}}", "1") + ",\n" +
        ProfileLeg.Replace("{{T}}", "SI_Azure_Profile_CL").Replace("{{P}}", "2") + ",\n" +
        ProfileLeg.Replace("{{T}}", "SI_Identity_Profile_CL").Replace("{{P}}", "3") + "\n" +
        """
    | where isnotempty(_i) and isnotempty(_n);
let _claimRows = _profiles
    | where _p == 1
    | mv-expand _k = pack_array(_arm, _eg) to typeof(string)
    | where _k startswith "/subscriptions/" or _k matches regex "^[0-9a-f]{32}$"
    | summarize Seen = max(CollectionTime) by _k, _i;
let _claims = _claimRows
    | join kind=inner (_claimRows | summarize MaxSeen = max(Seen) by _k) on _k
    | where Seen == MaxSeen
    | summarize _ids = dcount(_i), ClaimId = take_any(_i) by _k
    | where _ids == 1
    | project _k, ClaimId;
let _names = _profiles
    | summarize arg_max(CollectionTime, _i, _n, _t, _tier) by _il = tolower(_i), _p
    | summarize arg_min(_p, _i, _n, _t, _tier) by _il
    | project _il, CanonId = _i, CanonName = _n, CanonType = _t, CanonTier = _tier;

""";

    /// top_risks. The newest v3 Summary snapshot, one row per (finding row, impacted asset), each asset
    /// resolved to its canonical id through the identity map, then aggregated ON THE ID (name only when no id
    /// exists) -- Get-RARowAssetKeys / Add-AssetAgg. Ranked like the engine: tier ascending, then weighted score.
    public static readonly string TopRisks = IdentityMap + """
let _src = SI_RiskAnalysis_Summary_CL
    | where TimeGenerated > ago({{SNAP_DAYS}}d)
    | where tostring(column_ifexists("SolutionVersion", "")) endswith {{EDITION}};
let _snap = toscalar(_src | summarize max(CollectionTime));
_src
| where CollectionTime == _snap
| where {{COUNTED}}
| serialize _row = row_number()
| extend _an = todynamic(column_ifexists("ImpactedAssetsList", dynamic([]))), _ai = todynamic(column_ifexists("ImpactedAssetIds", dynamic([])))
| extend _aligned = array_length(_ai) == array_length(_an)
| mv-expand with_itemindex = _ix _name = _an to typeof(string)
| where isnotempty(_name)
| extend _raw = iff(_aligned, trim(@"\s+", tostring(_ai[_ix])), "")
| extend _arm = tolower(replace_regex(_raw, @"^az:", "")), _egk = tolower(extract(@"^(?:eg:az:)?([0-9a-fA-F]{32})$", 1, _raw))
| extend _k = case(_arm startswith "/subscriptions/", _arm, isnotempty(_egk), _egk, "-")
| join kind=leftouter (_claims) on _k
| extend _id = iff(isnotempty(ClaimId), ClaimId, _raw)
| extend _il = iff(isempty(_id), "-", tolower(_id))
| join kind=leftouter (_names) on _il
| extend AssetName = iff(isnotempty(CanonId) and not(_looksId(CanonName) and not(_looksId(_name))), CanonName, _name),
         AssetId = iff(isnotempty(CanonId), CanonId, _id)
| extend _key = iff(isempty(AssetId), strcat("name:", tolower(AssetName)), strcat("id:", tolower(AssetId)))
// one finding row counts ONCE per asset, even when two of its names resolve to the same machine
| summarize _w = max(todouble(RiskScoreTotal_Weighted)), _rt = min(toint(CriticalityTier)), _dom = take_any(tostring(SecurityDomain)),
            _nm = take_anyif(AssetName, not(_looksId(AssetName))), _nm2 = take_any(AssetName), _aid = take_any(AssetId), _ct = take_any(CanonTier)
            by _row, _key
| summarize WeightedRiskScore = sum(_w), Findings = count(), _rowTier = min(_rt), Domains = make_set(_dom),
            _nm = take_any(_nm), _nm2 = take_any(_nm2), AssetId = take_any(_aid), _profileTier = take_any(_ct)
            by _key
| extend AssetName = iff(isnotempty(_nm), _nm, _nm2),
         Tier = iff(isnotempty(_profileTier), _profileTier, iff(isnull(_rowTier), "", tostring(_rowTier)))
| extend _tierSort = iff(Tier matches regex "^[0-9]+$", toint(Tier), 99)
| sort by _tierSort asc, WeightedRiskScore desc, AssetName asc
| take {{TOP}}
| extend Rank = row_number()
| project Rank, AssetName, AssetId, Tier, WeightedRiskScore, Findings, Domains, SnapshotTime = _snap
""";

    /// asset_lookup. Name or id -> the ONE canonical asset (same resolution order as Resolve-SIAssetIdentity /
    /// Resolve-SICanonicalAsset: VM/graph claim, SI id, exact name, short name, then any vendor id it carries),
    /// plus its top findings from the newest v3 Detailed snapshot under any of its ids.
    public static readonly string AssetLookup = IdentityMap + """
let _q = {{NAME}};
let _ql = tolower(_q);
let _qs = tolower(tostring(split(_q, ".")[0]));
let _qarm = tolower(replace_regex(_q, @"^az:", ""));
let _qeg = tolower(extract(@"^(?:eg:az:)?([0-9a-fA-F]{32})$", 1, _q));
let _shortHits = _profiles
    | extend _s = tolower(tostring(split(_n, ".")[0]))
    | where _s == _qs
    | summarize _ids = dcount(tolower(_i)), Id = take_any(_i)
    | where _ids == 1
    | project Id, P = 4;
let _hit0 = toscalar(
    union
        (_claims | where _k == _qarm or (isnotempty(_qeg) and _k == _qeg) | project Id = ClaimId, P = 1),
        (_names | where _il == _ql | project Id = CanonId, P = 2),
        (_profiles | where tolower(_n) == _ql | summarize arg_min(_p, _i) | project Id = _i, P = 3),
        (_shortHits),
        (_profiles | mv-expand _r = _rel to typeof(string) | where isnotempty(_r) and (tolower(_r) == _ql or tolower(_r) == _qarm) | summarize arg_min(_p, _i) | project Id = _i, P = 5)
    | where isnotempty(Id)
    | summarize arg_min(P, Id)
    | project Id);
// THE asset, not just a match: an Azure VM (or graph node) that a device claims IS that device (Resolve-SICanonicalAsset).
let _hitKey = tolower(replace_regex(tostring(_hit0), @"^(az:|eg:az:)", ""));
let _claimed = toscalar(_claims | where _k == _hitKey | project ClaimId);
let _hit = iff(isnotempty(_claimed), _claimed, tostring(_hit0));
let _asset = _profiles
    | where tolower(_i) == tolower(_hit)
    | mv-expand _r = _rel to typeof(string)
    | summarize _rels = make_set_if(_r, isnotempty(_r) and tolower(_r) != tolower(_i), 50) by _il = tolower(_i)
    | join kind=inner (_names) on _il
    | project Kind = "asset", AssetId = CanonId, AssetName = CanonName, AssetType = CanonType, Tier = CanonTier, RelatedIds = _rels;
_asset
""";

    /// asset_lookup, its findings (SQL; #830, owner 2026-10-20: Pro reads Risk Analysis Detailed from the database only --
    /// the report-row copy SI_RiskAnalysis_Detailed_CL is an optional output, off by default). The asset's top 10 findings
    /// in the newest complete Detailed collection (not past the published run, not removed by the retention) under any of
    /// its ids (@i0 .. @i&lt;n-1&gt;: the asset's id and its related ids, each with and without "az:"), on its CI key or the
    /// id Risk Analysis gave the row: per report, title and severity the highest weighted risk score. {{COUNTED}} is the
    /// request's exempted scope (the findings without an exemption mark, or every finding).
    public static string AssetTopFindings(int ids, string counted)
    {
        if (ids < 1) throw new ArgumentOutOfRangeException(nameof(ids));
        var list = string.Join(", ", Enumerable.Range(0, ids).Select(i => "@i" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return $"""
WITH c AS (
    SELECT TOP (1) col.CollectionId FROM sidata.Collection AS col
    WHERE col.Kind = N'Detailed' AND col.Status = N'Complete' AND col.RetiredAt IS NULL AND {SI.Management.Core.ProData.PublishedRun.NotAfter("col.CollectionTime")}
    ORDER BY col.CollectionTime DESC
)
SELECT TOP (10) COALESCE(f.ReportName, N'') AS Report, COALESCE(f.Title, N'') AS Title, COALESCE(f.Severity, N'') AS Severity, MAX(f.RiskScoreWeighted) AS RiskScore
FROM sidata.Finding AS f
JOIN c ON c.CollectionId = f.CollectionId
WHERE (f.AssetKey IN ({list}) OR f.RaAssetId IN ({list})) AND {counted}
GROUP BY f.ReportName, f.Title, f.Severity
ORDER BY RiskScore DESC
""";
    }

    // #830 (owner 2026-10-20): risk_trend and domain_trend read the trend from the database (sidata.FindingDaily /
    // AssetDaily, ProDataSql.Trend through EstateQueries) -- SI_Trend_CL is part of the optional report-row copy, off by default.

    /// run_health. Every Start/End heartbeat in the window, newest RECORD first, at most 500 rows. A run's Start and End
    /// carry the same CollectionTime (the run's start), so the order is by when each record was written (TimeGenerated):
    /// by CollectionTime alone a run's Start and End were tied, in no particular order.
    public const string RunHealth = """
SI_RunHealth_CL
| where TimeGenerated > ago({{DAYS}}d)
| project TimeGenerated, CollectionTime, Engine = tostring(Engine), Phase = tostring(Phase), DurationSec = todouble(DurationSec),
          ExitReason = tostring(ExitReason), RunId = tostring(RunId), PermissionGaps = tostring(column_ifexists('PermissionGaps', ''))
| order by TimeGenerated desc, CollectionTime desc
| take 500
""";

    /// vulnerability_state (SQL, parameters @source, @firstWeek, @weeks). Per week (Sunday start, UTC, like
    /// KQL startofweek): New = Open events; Fixed = SI closes with reason Remediated (SI saw the asset and the
    /// CVE gone) -- the close event stores "&lt;reason&gt;: &lt;why&gt;", so the reason is matched as a prefix; Reopened = Reopen events; Open = records whose last state change before the week's end left
    /// them open. Median days to fix over records closed as Remediated inside the window.
    public const string VulnerabilityState = """
WITH N AS (
    SELECT 0 AS k
    UNION ALL
    SELECT k + 1 FROM N WHERE k + 1 < @weeks
),
W AS (
    SELECT DATEADD(DAY, 7 * k, @firstWeek) AS WeekStart, DATEADD(DAY, 7 * (k + 1), @firstWeek) AS WeekEnd FROM N
),
E AS (
    SELECT e.EventId, e.SysId, e.Action, e.ToState, e.Reason, e.At
    FROM vuln.VulnerabilityEvent e
    JOIN vuln.VulnerabilityItem i ON i.SysId = e.SysId
    WHERE i.Source = @source AND e.Action <> 'Seen'
)
SELECT
    W.WeekStart,
    (SELECT COUNT(*) FROM E WHERE E.Action = 'Open' AND E.At >= W.WeekStart AND E.At < W.WeekEnd) AS NewCount,
    (SELECT COUNT(*) FROM E WHERE E.Action = 'Close' AND (E.Reason = 'Remediated' OR E.Reason LIKE 'Remediated:%') AND E.At >= W.WeekStart AND E.At < W.WeekEnd) AS FixedCount,
    (SELECT COUNT(*) FROM E WHERE E.Action = 'Reopen' AND E.At >= W.WeekStart AND E.At < W.WeekEnd) AS ReopenedCount,
    o.OpenCount,
    m.MedianDaysToFix
FROM W
OUTER APPLY (
    SELECT COUNT(*) AS OpenCount
    FROM (
        SELECT E.ToState, ROW_NUMBER() OVER (PARTITION BY E.SysId ORDER BY E.At DESC, E.EventId DESC) AS rn
        FROM E WHERE E.At < W.WeekEnd
    ) x
    WHERE x.rn = 1 AND x.ToState = 'Open'
) o
OUTER APPLY (
    SELECT TOP (1) PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY DATEDIFF(SECOND, i.FirstSeen, i.ClosedAt) / 86400.0) OVER () AS MedianDaysToFix
    FROM vuln.VulnerabilityItem i
    WHERE i.Source = @source AND i.State = 'Closed' AND i.CloseReason = 'Remediated' AND i.ClosedAt >= @firstWeek
) m
ORDER BY W.WeekStart
OPTION (MAXRECURSION 200)
""";

    /// settings_read, current values (SQL, parameter @name: NULL = all). A secret's value never enters SQL;
    /// even its Key Vault secret NAME is not returned -- only that it is a secret.
    public const string SettingsCurrent = """
SELECT s.Name, s.Scope,
       CASE WHEN s.KeyVaultSecretName IS NULL THEN s.ValueJson ELSE NULL END AS ValueJson,
       CASE WHEN s.KeyVaultSecretName IS NULL THEN 0 ELSE 1 END AS IsSecret,
       s.UpdatedAt, s.UpdatedBy
FROM cfg.Setting s
WHERE (@name IS NULL OR s.Name = @name)
ORDER BY s.Name, s.Scope
""";

    /// settings_read, history (SQL, parameters @name, @since, @limit). Newest first. A Key Vault reference in a
    /// value ('keyvault:<name>') is redacted in SQL before it leaves the database.
    public const string SettingsHistory = """
SELECT TOP (@limit) c.ChangeId, c.Name, c.Scope, c.Action,
       CASE WHEN c.OldValue LIKE 'keyvault:%' THEN '(Key Vault reference)' ELSE c.OldValue END AS OldValue,
       CASE WHEN c.NewValue LIKE 'keyvault:%' THEN '(Key Vault reference)' ELSE c.NewValue END AS NewValue,
       c.ChangedAt, c.ChangedBy, c.Reason
FROM cfg.ChangeLog c
WHERE (@name IS NULL OR c.Name = @name) AND c.ChangedAt >= @since
ORDER BY c.ChangeId DESC
""";
}
