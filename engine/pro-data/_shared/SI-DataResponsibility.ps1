#Requires -Version 5.1
<#
    SecurityInsight Pro -- ASSET RESPONSIBILITY in the data sync (REQUIREMENTS #254, phase 1).

    Every finding of every loaded collection is stamped with the department responsible for it and the SOURCE of that
    answer, so the department pages, the Unassigned triage view and the business owners' monthly report read a
    precomputed result: no resolution per request, never Log Analytics.

    PRECEDENCE (highest first)
      1. recommendation override   cfg.ResponsibilityOverride Scope 'recommendation' -- one ConfigurationId (a CVE id on a
                                   CVE finding) on EVERY asset; it wins over the asset override
      2. asset override            cfg.ResponsibilityOverride Scope 'asset'
      3. the policy                its sources in the order SI_Pro_Responsibility_Sources names (default: tags, rules);
                                   a source left out is off
                                     tags   the platform tags named in SI_Pro_Responsibility_TagNames (earlier name wins;
                                            on one name an Azure resource tag wins over Defender, then Entra, then the
                                            subscription's tag). A tag value matches a department by its name or one of
                                            its MatchValues
                                     rules  the SI definitions in cfg.ResponsibilityRule, first match by SortOrder
      4. SI_Pro_Responsibility_DefaultDepartment, else Unassigned (DepartmentId NULL)

    THE STEPS (Invoke-SIDataResponsibility, after the collection views' data)
      a. the tags of the CIs just loaded are stored in sidata.AssetTag (Write-SIDataAssetTags, during the load)
      b. every CI in sidata.Asset gets its own resolution (overrides on assets, policy, default)
      c. the policy's FINGERPRINT (settings + departments + rules + active overrides) is computed in SQL
      d. every complete collection resolved with another fingerprint (or never) is resolved again, NEWEST FIRST, in
         FindingId ranges sized from their measured time, then its per-department aggregate (sidata.DepartmentFacet)
         is replaced and the fingerprint stamped -- one transaction.
    COST DECISION: a POLICY change (an Admin edits a department, a rule, an override or a responsibility setting)
       re-resolves EVERY retained collection on the next sync, so a department's trend always reads by today's rules.
       A TAG that changes on an asset does not rewrite history: the asset's own resolution follows the newest tags, and
       the next loaded collection carries it. The work per collection is one set-based UPDATE per measured range and one
       aggregate -- the same shape as the collection views' derive step.

    A database without the responsibility tables (cfg.Department ..., sidata.Finding.DepartmentId ...) is said once and
    the rest of the sync is not affected. PS 5.1 safe.
#>

# ------------------------------------------------------------------------------------------------------------------
#  SETTINGS (pure)
# ------------------------------------------------------------------------------------------------------------------

function Resolve-SIDataResponsibilitySettings {
    <#
        PURE. The responsibility policy's settings from the globals (name -> value). Unknown sources are a problem (never
        silently dropped); an empty source list means "no policy source" (overrides and the default still apply).
        Returns @{ Sources; TagNames; DefaultDepartment; Problems; Text } -- Text is the canonical form the fingerprint uses.
    #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $problems = New-Object System.Collections.Generic.List[string]

    # read directly: a scriptblock would turn an EMPTY list (the policy switched off) into $null
    $rawSources = $null; if ($Globals.ContainsKey('SI_Pro_Responsibility_Sources')) { $rawSources = $Globals['SI_Pro_Responsibility_Sources'] }
    $sources = New-Object System.Collections.Generic.List[string]
    if ($null -eq $rawSources) { $sources.Add('tags'); $sources.Add('rules') }
    else {
        foreach ($s in @($rawSources)) {
            foreach ($part in ("$s" -split '[,;]')) {
                $v = $part.Trim().ToLowerInvariant()
                if (-not $v) { continue }
                if ($v -notin 'tags', 'rules') { $problems.Add(("SI_Pro_Responsibility_Sources: '{0}' is not a source (tags, rules)" -f $part.Trim())); continue }
                if (-not $sources.Contains($v)) { $sources.Add($v) }
            }
        }
    }

    $rawTags = $null; if ($Globals.ContainsKey('SI_Pro_Responsibility_TagNames')) { $rawTags = $Globals['SI_Pro_Responsibility_TagNames'] }
    $tags = New-Object System.Collections.Generic.List[string]
    if ($null -eq $rawTags) { foreach ($t in 'Department', 'Owner', 'CostCenter') { $tags.Add($t) } }
    else {
        foreach ($t in @($rawTags)) {
            foreach ($part in ("$t" -split '[,;]')) {
                $v = $part.Trim()
                if (-not $v) { continue }
                if ($v.Length -gt 128) { $problems.Add(("SI_Pro_Responsibility_TagNames: '{0}...' is longer than 128 characters" -f $v.Substring(0, 20))); continue }
                if (-not @($tags | Where-Object { $_ -ieq $v }).Count) { $tags.Add($v) }
            }
        }
    }
    if ($tags.Count -gt 20) { $problems.Add('SI_Pro_Responsibility_TagNames: at most 20 tag names') }

    $def = "$(& $g 'SI_Pro_Responsibility_DefaultDepartment')".Trim()
    if ($def.Length -gt 128) { $problems.Add('SI_Pro_Responsibility_DefaultDepartment is longer than 128 characters') }

    $srcArr = @($sources.ToArray()); $tagArr = @($tags.ToArray())
    [pscustomobject]@{
        Sources = $srcArr; TagNames = $tagArr; DefaultDepartment = $def; Problems = @($problems.ToArray())
        Text = ('sources=' + ($srcArr -join ',') + '|tags=' + ($tagArr -join ',') + '|default=' + $def)
    }
}

function ConvertTo-SIDataJsonArrayText {
    <# PURE. A string array as JSON text, always an array (PS 5.1 makes a 1-item list a scalar). #>
    param([AllowEmptyCollection()][string[]]$Items = @())
    '[' + ((@($Items) | ForEach-Object { ConvertTo-SIDataJsonString -Value $_ }) -join ',') + ']'
}

# ------------------------------------------------------------------------------------------------------------------
#  TAGS: read from the profile tables, parsed here (pure), stored per CI
# ------------------------------------------------------------------------------------------------------------------

# What each profile table carries that says who an asset belongs to (checked against asset-profiling-schema):
#   endpoint  MachineTags (Defender), DeviceManualTags / DeviceDynamicTags (Exposure Graph) -- lists of tags;
#             ServiceName (the business / CMDB service); MachineGroup, RbacGroupName (Defender device groups)
#   identity  Department (the Entra attribute), Tags (list); ServiceName
#   azure     Properties.azure.tags (the resource's tags), Properties.azure.parentTags.subscription (inherited);
#             ServiceName; AzResourceGroup, AzSubscriptionId
$script:SIDataTagColumns = @{
    endpoint = [ordered]@{ MachineTags = 'list'; DeviceManualTags = 'list'; DeviceDynamicTags = 'list'; ServiceName = 'service'; MachineGroup = 'group'; RbacGroupName = 'group' }
    identity = [ordered]@{ Department = 'attribute'; Tags = 'list'; ServiceName = 'service' }
    azure    = [ordered]@{ AzTags = 'bag'; AzSubscriptionTags = 'bag-subscription'; ServiceName = 'service'; AzResourceGroup = 'group'; AzSubscriptionId = 'group' }
}

function Get-SIDataAssetTagKql {
    <#
        PURE. Each v3 asset's newest profile row's responsibility columns, as text (parsed by ConvertFrom-SIDataTagRow).
        Columns a table does not have read as empty (column_ifexists). Filtered to v3 rows BEFORE arg_max (#83).
    #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure')][string]$Kind,
          [Parameter(Mandatory)][string]$TableName, [int]$LookbackDays = 8)
    $cols = @($script:SIDataTagColumns[$Kind].Keys)
    $proj = foreach ($c in $cols) {
        switch ($c) {
            'AzTags'             { 'AzTags = tostring(parse_json(tostring(column_ifexists("Properties", ""))).azure.tags)' }
            'AzSubscriptionTags' { 'AzSubscriptionTags = tostring(parse_json(tostring(column_ifexists("Properties", ""))).azure.parentTags.subscription)' }
            default              { '{0} = tostring(column_ifexists("{0}", ""))' -f $c }
        }
    }
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
| extend SI_AssetId = tostring(column_ifexists("SI_AssetId", ""))
| where isnotempty(SI_AssetId)
| project SI_AssetId, CollectionTime, $($proj -join ', ')
| summarize arg_max(CollectionTime, $($cols -join ', ')) by SI_AssetId
"@
}

function Split-SIDataTag {
    <# PURE. "Department:Finance" / "Department=Finance" -> Name + Value; a bare tag -> Name '' + the tag. #>
    param([string]$Tag)
    $t = "$Tag".Trim()
    if (-not $t) { return $null }
    $i = $t.IndexOfAny([char[]]@(':', '='))
    if ($i -gt 0 -and $i -lt $t.Length - 1) { return [pscustomobject]@{ Name = $t.Substring(0, $i).Trim(); Value = $t.Substring($i + 1).Trim() } }
    [pscustomobject]@{ Name = ''; Value = $t }
}

function ConvertFrom-SIDataTagRow {
    <#
        PURE. One profile row (Get-SIDataAssetTagKql) -> its tags: @{ Source; TagName; TagValue }. A list column holds a
        JSON array (or a ';'-separated text), a bag a JSON object; anything unreadable is skipped, never guessed.
        Values longer than the column (256) are skipped; names longer than 128 too.
    #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure')][string]$Kind, [Parameter(Mandatory)]$Row)
    $out = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$src, [string]$name, [string]$value)
        $n = "$name".Trim(); $v = "$value".Trim()
        if (-not $v -or $v.Length -gt 256 -or $n.Length -gt 128) { return }
        $out.Add([pscustomobject]@{ Source = $src; TagName = $n; TagValue = $v })
    }
    foreach ($c in @($script:SIDataTagColumns[$Kind].Keys)) {
        $how = $script:SIDataTagColumns[$Kind][$c]
        $raw = $null
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($c)) { $raw = $Row[$c] } }
        elseif ($Row.PSObject.Properties[$c]) { $raw = $Row.$c }
        $text = "$raw".Trim()
        if (-not $text -or $text -eq '[]' -or $text -eq '{}' -or $text -eq 'null') { continue }
        switch ($how) {
            'list' {
                $items = @()
                if ($text.StartsWith('[')) { try { $o = ConvertFrom-Json -InputObject $text; $items = @(foreach ($x in @($o)) { "$x" }) } catch { $items = @() } }
                else { $items = @($text -split ';') }
                foreach ($it in $items) { $p = Split-SIDataTag -Tag $it; if ($p) { & $add $Kind $p.Name $p.Value } }
            }
            'attribute' { & $add $Kind $c $text }
            'service'   { & $add 'service' 'Service' $text }
            'group'     {
                $name = switch ($c) { 'RbacGroupName' { 'RbacGroup' } 'AzResourceGroup' { 'ResourceGroup' } 'AzSubscriptionId' { 'Subscription' } default { $c } }
                & $add 'group' $name $text
            }
            default {
                # 'bag' / 'bag-subscription': a JSON object of tag name -> value
                if (-not $text.StartsWith('{')) { continue }
                $src = if ($how -eq 'bag-subscription') { 'azure-subscription' } else { 'azure' }
                try { $o = ConvertFrom-Json -InputObject $text } catch { continue }
                foreach ($p in $o.PSObject.Properties) { & $add $src $p.Name ([string]$p.Value) }
            }
        }
    }
    # returned plainly: every caller wraps in @() (a comma-wrapped return would make @() count ONE)
    $out.ToArray()
}

function Get-SIDataAssetTagItems {
    <#
        PURE. Tags of profile rows -> one JSON item PER CI ({ AssetKey, SeenAt, Tags: [...] }), the members of one CI
        merged, each tag once. A CI whose profile carries no tag still gets an item (its old tags are replaced by none).
        -Rows: @{ Kind; Row } pairs. Returns string[].
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Index = @{}, [Parameter(Mandatory)][datetime]$SeenAt)
    $byKey = @{}
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $aid = "$($r.Row.SI_AssetId)".Trim()
        if (-not $aid) { continue }
        $key = (Get-SIDataAssetKey -SIAssetId $aid -Index $Index).Key
        if (-not $byKey.ContainsKey($key)) { $byKey[$key] = @{ Seen = @{}; Tags = (New-Object System.Collections.Generic.List[object]) }; $order.Add($key) }
        foreach ($t in @(ConvertFrom-SIDataTagRow -Kind $r.Kind -Row $r.Row)) {
            if ($null -eq $t) { continue }
            $sig = ('{0}|{1}|{2}' -f $t.Source, $t.TagName, $t.TagValue).ToLowerInvariant()
            if ($byKey[$key].Seen.ContainsKey($sig)) { continue }
            $byKey[$key].Seen[$sig] = $true
            $byKey[$key].Tags.Add($t)
        }
    }
    $seen = Format-SIDataSqlTime -Time $SeenAt
    $items = foreach ($k in $order) {
        $tags = @($byKey[$k].Tags | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ Source = $_.Source; TagName = $_.TagName; TagValue = $_.TagValue }) })
        '{"AssetKey":' + (ConvertTo-SIDataJsonString -Value $k) + ',"SeenAt":' + (ConvertTo-SIDataJsonString -Value $seen) + ',"Tags":[' + ($tags -join ',') + ']}'
    }
    @($items)
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STATEMENTS (pure text)
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataResponsibilitySchemaCheckSql {
    <# 1 when the database carries every responsibility table and column, else 0 (checked BEFORE any statement names them). #>
    "SELECT CASE WHEN OBJECT_ID('cfg.Department') IS NOT NULL AND OBJECT_ID('cfg.ResponsibilityRule') IS NOT NULL AND OBJECT_ID('cfg.ResponsibilityOverride') IS NOT NULL AND OBJECT_ID('sidata.AssetTag') IS NOT NULL AND OBJECT_ID('sidata.DepartmentFacet') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'DepartmentId') IS NOT NULL AND COL_LENGTH('sidata.Asset', 'DepartmentId') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ResolvedVersion') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RiskScoreWeighted') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataAssetTagSchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.AssetTag') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataUpsertAssetTagSql {
    <# One chunk of CIs: each CI's tags REPLACED by the ones it carries now. Returns the CIs written (one per item). #>
    @'
SET XACT_ABORT ON;
DECLARE @a TABLE (AssetKey nvarchar(400) PRIMARY KEY, SeenAt datetime2(3), Tags nvarchar(max));
INSERT @a SELECT j.AssetKey, CONVERT(datetime2(3), j.SeenAt, 126), j.Tags
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), SeenAt nvarchar(40), Tags nvarchar(max) AS JSON) j;
BEGIN TRAN;
DELETE t FROM sidata.AssetTag AS t WHERE t.AssetKey IN (SELECT a.AssetKey FROM @a AS a);
INSERT sidata.AssetTag (AssetKey, Source, TagName, TagValue, SeenAt)
SELECT DISTINCT a.AssetKey, LEFT(x.Source, 24), LEFT(ISNULL(x.TagName, N''), 128), LEFT(x.TagValue, 256), a.SeenAt
FROM @a AS a CROSS APPLY OPENJSON(a.Tags) WITH (Source nvarchar(24), TagName nvarchar(128), TagValue nvarchar(256)) x
WHERE x.Source IS NOT NULL AND x.TagValue IS NOT NULL AND x.TagValue <> N'';
COMMIT;
SELECT COUNT(*) FROM @a;
'@
}

function Get-SIDataResolveAssetsSql {
    <#
        Every CI's own department: its asset override, else the policy's sources in their order (@Sources, a JSON array:
        "tags" / "rules"), else the default department (@DefaultDepartment, a name), else Unassigned. Only rows whose
        answer changed are written. Returns one row per source with its CI count.
    #>
    @'
SET XACT_ABORT ON;
DECLARE @tagRank int = (SELECT TOP (1) CONVERT(int, j.[key]) FROM OPENJSON(@Sources) AS j WHERE j.[value] = N'tags');
DECLARE @ruleRank int = (SELECT TOP (1) CONVERT(int, j.[key]) FROM OPENJSON(@Sources) AS j WHERE j.[value] = N'rules');
DECLARE @default int = (SELECT TOP (1) d.DepartmentId FROM cfg.Department AS d WHERE d.RetiredAt IS NULL AND d.Name = NULLIF(LTRIM(RTRIM(@DefaultDepartment)), N''));
CREATE TABLE #tn (Name nvarchar(128) NOT NULL PRIMARY KEY, Rnk int NOT NULL);
INSERT #tn (Name, Rnk)
SELECT LEFT(LTRIM(RTRIM(j.[value])), 128), MIN(CONVERT(int, j.[key])) FROM OPENJSON(@TagNames) AS j
WHERE LTRIM(RTRIM(j.[value])) <> N'' GROUP BY LEFT(LTRIM(RTRIM(j.[value])), 128);
CREATE TABLE #d (DepartmentId int NOT NULL PRIMARY KEY);
INSERT #d SELECT d.DepartmentId FROM cfg.Department AS d WHERE d.RetiredAt IS NULL;
-- the values a tag may carry for a department: its name and its MatchValues (case-insensitive by the database collation)
CREATE TABLE #dv (Value nvarchar(256) NOT NULL PRIMARY KEY, DepartmentId int NOT NULL);
INSERT #dv (Value, DepartmentId)
SELECT v.Value, MIN(v.DepartmentId) FROM (
    SELECT LEFT(LTRIM(RTRIM(d.Name)), 256) AS Value, d.DepartmentId FROM cfg.Department AS d WHERE d.RetiredAt IS NULL
    UNION ALL
    SELECT LEFT(LTRIM(RTRIM(s.[value])), 256), d.DepartmentId FROM cfg.Department AS d CROSS APPLY STRING_SPLIT(d.MatchValues, N';') AS s
    WHERE d.RetiredAt IS NULL AND d.MatchValues IS NOT NULL
) AS v WHERE v.Value <> N'' GROUP BY v.Value;
CREATE TABLE #c (AssetKey nvarchar(400) NOT NULL, R1 int NOT NULL, R2 int NOT NULL, DepartmentId int NOT NULL, Src nvarchar(24) NOT NULL, Detail nvarchar(256) NULL);
-- (2) the asset override: above every policy source
INSERT #c SELECT o.AssetKey, -1, 0, o.DepartmentId, N'asset-override', LEFT(CONCAT(N'override ', o.OverrideId, N': ', o.Reason), 256)
FROM cfg.ResponsibilityOverride AS o JOIN #d ON #d.DepartmentId = o.DepartmentId
WHERE o.Scope = N'asset' AND o.RevokedAt IS NULL;
-- (3a) platform tags: the earlier tag name wins; on one name an Azure resource tag, then Defender, then Entra, then the subscription
IF @tagRank IS NOT NULL
INSERT #c SELECT t.AssetKey, @tagRank,
       tn.Rnk * 10 + CASE t.Source WHEN N'azure' THEN 0 WHEN N'endpoint' THEN 1 WHEN N'identity' THEN 2 WHEN N'azure-subscription' THEN 5 ELSE 9 END,
       dv.DepartmentId, N'tag', LEFT(CONCAT(t.TagName, N' = ', t.TagValue, N' (', t.Source, N')'), 256)
FROM sidata.AssetTag AS t
JOIN #tn AS tn ON tn.Name = t.TagName
JOIN #dv AS dv ON dv.Value = t.TagValue
WHERE t.Source IN (N'azure', N'azure-subscription', N'endpoint', N'identity');
-- (3b) the SI definitions, first match by SortOrder; * and ? are the wildcards, everything else literal
CREATE TABLE #r (RuleId int NOT NULL, Kind nvarchar(16) NOT NULL, Pattern nvarchar(400) NOT NULL, LikePattern nvarchar(1600) NOT NULL, DepartmentId int NOT NULL, SortOrder int NOT NULL);
IF @ruleRank IS NOT NULL
INSERT #r SELECT r.RuleId, LOWER(r.Kind), r.Pattern,
       REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(r.Pattern, N'[', N'[[]'), N'%', N'[%]'), N'_', N'[_]'), N'*', N'%'), N'?', N'_'),
       r.DepartmentId, r.SortOrder
FROM cfg.ResponsibilityRule AS r JOIN #d ON #d.DepartmentId = r.DepartmentId WHERE r.Enabled = 1;
INSERT #c SELECT a.AssetKey, @ruleRank, r.SortOrder, r.DepartmentId, N'rule', LEFT(CONCAT(N'rule ', r.RuleId, N': ', r.Kind, N' ', r.Pattern), 256)
FROM sidata.Asset AS a JOIN #r AS r ON r.Kind = N'name' AND a.AssetName LIKE r.LikePattern;
INSERT #c SELECT a.AssetKey, @ruleRank, r.SortOrder, r.DepartmentId, N'rule', LEFT(CONCAT(N'rule ', r.RuleId, N': ', r.Kind, N' ', r.Pattern), 256)
FROM sidata.Asset AS a JOIN #r AS r ON r.Kind = N'kind' AND a.AssetKind = r.Pattern;
INSERT #c SELECT DISTINCT t.AssetKey, @ruleRank, r.SortOrder, r.DepartmentId, N'rule', LEFT(CONCAT(N'rule ', r.RuleId, N': ', r.Kind, N' ', r.Pattern), 256)
FROM sidata.AssetTag AS t JOIN #r AS r ON r.Kind = N'service' AND t.Source = N'service' AND t.TagValue LIKE r.LikePattern;
-- the CMDB services of the newest collection, from the ONE service-membership resolver the Services view uses (#255)
IF OBJECT_ID('sidata.ServiceMember') IS NOT NULL
INSERT #c SELECT DISTINCT sm.AssetKey, @ruleRank, r.SortOrder, r.DepartmentId, N'rule', LEFT(CONCAT(N'rule ', r.RuleId, N': ', r.Kind, N' ', r.Pattern), 256)
FROM sidata.ServiceMember AS sm JOIN #r AS r ON r.Kind = N'service' AND (sm.ServiceName LIKE r.LikePattern OR sm.ServiceKey LIKE r.LikePattern)
WHERE sm.CollectionId = (SELECT MAX(c.CollectionId) FROM sidata.Collection AS c WHERE c.Status = N'Complete' AND c.Kind = N'Detailed');
INSERT #c SELECT DISTINCT t.AssetKey, @ruleRank, r.SortOrder, r.DepartmentId, N'rule', LEFT(CONCAT(N'rule ', r.RuleId, N': ', r.Kind, N' ', r.Pattern), 256)
FROM sidata.AssetTag AS t JOIN #r AS r ON r.Kind = N'group' AND t.Source = N'group' AND t.TagValue LIKE r.LikePattern;
INSERT #c SELECT DISTINCT t.AssetKey, @ruleRank, r.SortOrder, r.DepartmentId, N'rule', LEFT(CONCAT(N'rule ', r.RuleId, N': ', r.Kind, N' ', r.Pattern), 256)
FROM sidata.AssetTag AS t JOIN #r AS r ON r.Kind = N'tag' AND t.Source IN (N'azure', N'azure-subscription', N'endpoint', N'identity')
 AND (t.TagValue LIKE r.LikePattern OR CONCAT(t.TagName, N'=', t.TagValue) LIKE r.LikePattern);
CREATE TABLE #best (AssetKey nvarchar(400) NOT NULL PRIMARY KEY, DepartmentId int NOT NULL, Src nvarchar(24) NOT NULL, Detail nvarchar(256) NULL);
INSERT #best SELECT b.AssetKey, b.DepartmentId, b.Src, b.Detail FROM (
    SELECT c.AssetKey, c.DepartmentId, c.Src, c.Detail, ROW_NUMBER() OVER (PARTITION BY c.AssetKey ORDER BY c.R1, c.R2, c.DepartmentId) AS n FROM #c AS c
) AS b WHERE b.n = 1;
BEGIN TRAN;
WITH n AS (
    SELECT a.AssetKey, a.DepartmentId, a.ResponsibilitySource, a.ResponsibilityDetail,
           COALESCE(b.DepartmentId, @default) AS NewDepartmentId,
           CASE WHEN b.AssetKey IS NOT NULL THEN b.Src WHEN @default IS NOT NULL THEN N'default' ELSE N'unassigned' END AS NewSource,
           CASE WHEN b.AssetKey IS NOT NULL THEN b.Detail WHEN @default IS NOT NULL THEN N'the default department' ELSE NULL END AS NewDetail
    FROM sidata.Asset AS a LEFT JOIN #best AS b ON b.AssetKey = a.AssetKey
)
UPDATE n SET DepartmentId = NewDepartmentId, ResponsibilitySource = NewSource, ResponsibilityDetail = NewDetail
WHERE EXISTS (SELECT n.DepartmentId, n.ResponsibilitySource, n.ResponsibilityDetail EXCEPT SELECT n.NewDepartmentId, n.NewSource, n.NewDetail);
COMMIT;
SELECT ISNULL(a.ResponsibilitySource, N'unassigned') AS Source, COUNT_BIG(*) AS N FROM sidata.Asset AS a GROUP BY ISNULL(a.ResponsibilitySource, N'unassigned');
'@
}

function Get-SIDataResponsibilityFingerprintSql {
    <# The policy's fingerprint: the settings text + every department, rule and ACTIVE override, hashed (SHA-256, hex). #>
    @'
SELECT CONVERT(char(64), HASHBYTES('SHA2_256', CONCAT(CONVERT(nvarchar(max), @Settings), N'|',
    (SELECT d.DepartmentId, d.Name, d.MatchValues, d.RetiredAt FROM cfg.Department AS d ORDER BY d.DepartmentId FOR JSON PATH), N'|',
    (SELECT r.RuleId, r.Kind, r.Pattern, r.DepartmentId, r.SortOrder, r.Enabled FROM cfg.ResponsibilityRule AS r ORDER BY r.RuleId FOR JSON PATH), N'|',
    (SELECT o.OverrideId, o.Scope, o.AssetKey, o.RecommendationKey, o.DepartmentId FROM cfg.ResponsibilityOverride AS o WHERE o.RevokedAt IS NULL ORDER BY o.OverrideId FOR JSON PATH))), 2) AS Fingerprint;
'@
}

function Get-SIDataUnresolvedSql {
    <# Complete collections resolved with another policy (or never), NEWEST first. #>
    # #717: never a collection whose finding rows the retention removed -- its department totals are what is left of it
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter }
    "SELECT CollectionId, CollectionTime FROM sidata.Collection WHERE Status = 'Complete' AND (ResolvedVersion IS NULL OR ResolvedVersion <> @Fingerprint)$live ORDER BY CollectionTime DESC"
}

function Get-SIDataResolveFindingSql {
    <#
        One FindingId range of one collection: recommendation override > the CI's own resolution (asset override, policy,
        default) > the default department > Unassigned. The recommendation key is the finding's ConfigurationId (a CVE id on
        a CVE finding), else its CVE. Overrides are a key set built once and joined -- no per-row lookup.
        -WithName (#636): also the department's NAME (sidata.Finding.DepartmentName, the Detailed page's filter column).
    #>
    param([switch]$WithName)
    $name = ''; $nameJoin = ''
    if ($WithName) {
        $name = ',' + [Environment]::NewLine + '    DepartmentName       = LEFT(dn.Name, 128)'
        $nameJoin = [Environment]::NewLine + 'LEFT JOIN cfg.Department AS dn ON dn.DepartmentId = COALESCE(ro.DepartmentId, a.DepartmentId, @default)'
    }
    (@'
DECLARE @default int = (SELECT TOP (1) d.DepartmentId FROM cfg.Department AS d WHERE d.RetiredAt IS NULL AND d.Name = NULLIF(LTRIM(RTRIM(@DefaultDepartment)), N''));
WITH ro AS (
    SELECT o.RecommendationKey AS K, o.OverrideId, o.DepartmentId, o.Reason
    FROM cfg.ResponsibilityOverride AS o
    JOIN cfg.Department AS d ON d.DepartmentId = o.DepartmentId AND d.RetiredAt IS NULL
    WHERE o.Scope = N'recommendation' AND o.RevokedAt IS NULL
)
UPDATE f SET
    DepartmentId         = COALESCE(ro.DepartmentId, a.DepartmentId, @default),
    ResponsibilitySource = CASE WHEN ro.DepartmentId IS NOT NULL THEN N'recommendation-override'
                                WHEN a.DepartmentId IS NOT NULL THEN a.ResponsibilitySource
                                WHEN @default IS NOT NULL THEN N'default' ELSE N'unassigned' END,
    ResponsibilityDetail = CASE WHEN ro.DepartmentId IS NOT NULL THEN LEFT(CONCAT(N'override ', ro.OverrideId, N': ', ro.Reason), 256)
                                WHEN a.DepartmentId IS NOT NULL THEN a.ResponsibilityDetail
                                WHEN @default IS NOT NULL THEN N'the default department' ELSE NULL END{NAME}
FROM sidata.Finding AS f
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
LEFT JOIN ro ON ro.K = COALESCE(f.ConfigurationId, f.Cve){NAMEJOIN}
WHERE f.CollectionId = @CollectionId AND f.FindingId > @After AND f.FindingId <= @Upto;
SELECT @@ROWCOUNT;
'@).Replace('{NAME}', $name).Replace('{NAMEJOIN}', $nameJoin)
}

function Get-SIDataDepartmentNameCheckSql {
    <# 1 = sidata.Finding has the DepartmentName column (#636). #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'DepartmentName') IS NOT NULL THEN 1 ELSE 0 END;"
}

function Get-SIDataDepartmentNameBackfillSql {
    <#
        #636: ONE batch of finding rows resolved before the DepartmentName column existed (a department, no name yet): the
        name written from cfg.Department. Answers the rows written; the caller repeats until 0 (or its budget is spent).
    #>
    @'
UPDATE TOP (50000) f SET DepartmentName = LEFT(d.Name, 128)
FROM sidata.Finding AS f
JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId
WHERE f.CollectionId = @CollectionId AND f.DepartmentName IS NULL AND f.DepartmentId IS NOT NULL;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataDepartmentFacetSql {
    <#
        The collection's per-department aggregate (DepartmentId 0 = Unassigned) -- per severity, per tier and the total --
        replacing what it held, and the policy fingerprint stamped: ONE transaction, so a reader sees the old set or the new.
        -Counted (#264): the same aggregate over the findings WITHOUT an exemption mark, into sidata.DepartmentFacetCounted
        (no fingerprint stamp). A ResolvedAt newer than the collection's ExemptedDerivedAt makes its twins stale.
    #>
    param([switch]$Counted)
    $table = 'DepartmentFacet'; $mark = ''
    $stamp = "UPDATE sidata.Collection SET ResolvedAt = SYSUTCDATETIME(), ResolvedVersion = @Fingerprint WHERE CollectionId = @CollectionId;"
    if ($Counted) { $table = 'DepartmentFacetCounted'; $mark = ' AND x.ExemptionId IS NULL'; $stamp = '' }
    (@'
SET XACT_ABORT ON;
CREATE TABLE #df (DepartmentId int NOT NULL, Severity nvarchar(30) NOT NULL, Tier nvarchar(12) NOT NULL, Findings int NOT NULL, Assets int NOT NULL,
                  ScoreTotal float NOT NULL, WeightedTotal float NULL);
WITH f AS (
    SELECT ISNULL(x.DepartmentId, 0) AS Dept, COALESCE(NULLIF(x.Severity, N''), N'(none)') AS Sev,
           CASE WHEN x.Tier BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), x.Tier) ELSE N'Unclassified' END AS TierV,
           x.AssetKey, x.RiskScore, x.RiskScoreWeighted
    -- #855: the departments' counts are of ACTIVE CIs only (their key cannot take the lifecycle in an additive schema; the
    -- Departments page says so)
    FROM sidata.Finding AS x WHERE x.CollectionId = @CollectionId{MARK} AND (x.CiLifecycle IS NULL OR x.CiLifecycle = N'active')
)
INSERT #df (DepartmentId, Severity, Tier, Findings, Assets, ScoreTotal, WeightedTotal)
SELECT f.Dept, CASE WHEN GROUPING(f.Sev) = 1 THEN N'*' ELSE f.Sev END, CASE WHEN GROUPING(f.TierV) = 1 THEN N'*' ELSE f.TierV END,
       COUNT(*), COUNT(DISTINCT f.AssetKey), ISNULL(SUM(f.RiskScore), 0), SUM(f.RiskScoreWeighted)
FROM f
GROUP BY GROUPING SETS ((f.Dept, f.Sev), (f.Dept, f.TierV), (f.Dept));
BEGIN TRAN;
DELETE FROM sidata.{TABLE} WHERE CollectionId = @CollectionId;
INSERT sidata.{TABLE} (CollectionId, DepartmentId, Severity, Tier, Findings, Assets, ScoreTotal, WeightedTotal)
SELECT @CollectionId, DepartmentId, Severity, Tier, Findings, Assets, ScoreTotal, WeightedTotal FROM #df;
DECLARE @n int = @@ROWCOUNT;
{STAMP}
COMMIT;
SELECT @n;
'@).Replace('{TABLE}', $table).Replace('{MARK}', $mark).Replace('{STAMP}', $stamp)
}

# ------------------------------------------------------------------------------------------------------------------
#  THE WRITES / ORCHESTRATION
# ------------------------------------------------------------------------------------------------------------------

function Invoke-SIDataDepartmentFacet {
    <#
        2026-10-29 The collection's per-department aggregate (Get-SIDataDepartmentFacetSql; -Counted: its counted twin) -- on a
        real database's seam in ranges (SI-DataSql.ps1 "THE COLLECTION'S AGGREGATES IN RANGES"): the findings a FindingId range
        at a time into partial counts per department, severity, tier and asset, folded a range of assets at a time, and the
        aggregate (and, not counted, the policy fingerprint) replaced in one short transaction. Any other seam: the one
        statement. Answers the aggregate's rows written.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [string]$Fingerprint = '', [switch]$Counted,
          [scriptblock]$Log, [long]$FirstSize = 50000, [long]$TargetMs = 5000)
    $p0 = @{ CollectionId = $CollectionId }; if (-not $Counted) { $p0['Fingerprint'] = $Fingerprint }
    if (-not ((Get-Command -Name Test-SIDataSessionRangedSeam -ErrorAction SilentlyContinue) -and (Test-SIDataSessionRangedSeam $Invoke))) {
        return [int](& $Invoke (Get-SIDataDepartmentFacetSql -Counted:$Counted) $p0 'scalar')
    }
    if ($Invoke.PSObject.Properties['SIRangeFirstTake'] -and [long]$Invoke.SIRangeFirstTake -gt 0) { $FirstSize = [long]$Invoke.SIRangeFirstTake }
    $table = 'DepartmentFacet'; $mark = ''
    $stamp = "UPDATE sidata.Collection SET ResolvedAt = SYSUTCDATETIME(), ResolvedVersion = $(ConvertTo-SIDataSqlText $Fingerprint) WHERE CollectionId = $CollectionId;"
    if ($Counted) { $table = 'DepartmentFacetCounted'; $mark = ' AND x.ExemptionId IS NULL'; $stamp = '' }
    $what = $(if ($Counted) { 'v3 model    : the departments without exempted findings' } else { 'v3 model    : the departments' })
    $cid = $CollectionId
    $onSession = {
        param($Run)
        & $Run @'
SELECT TOP (0) ISNULL(x.DepartmentId, 0) AS Dept, COALESCE(NULLIF(x.Severity, N''), N'(none)') AS Sev,
       CASE WHEN x.Tier BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), x.Tier) ELSE N'Unclassified' END AS TierV, x.AssetKey,
       COUNT_BIG(*) AS Findings, SUM(x.RiskScore) AS ScoreSum, SUM(x.RiskScoreWeighted) AS WSum
INTO #fp FROM sidata.Finding AS x
GROUP BY ISNULL(x.DepartmentId, 0), COALESCE(NULLIF(x.Severity, N''), N'(none)'), CASE WHEN x.Tier BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), x.Tier) ELSE N'Unclassified' END, x.AssetKey;
CREATE CLUSTERED INDEX CX_fp ON #fp (AssetKey);
CREATE TABLE #fr (DepartmentId int NOT NULL, Severity nvarchar(30) COLLATE DATABASE_DEFAULT NOT NULL, Tier nvarchar(12) COLLATE DATABASE_DEFAULT NOT NULL, Findings bigint NOT NULL, Assets bigint NOT NULL, ScoreSum float NULL, WSum float NULL);
'@ 'none'
        $null = Invoke-SIDataSessionIdRanges -Run $Run -CollectionId $cid -What $what -Log $Log -FirstSize $FirstSize -TargetMs $TargetMs -Text @"
INSERT #fp (Dept, Sev, TierV, AssetKey, Findings, ScoreSum, WSum)
SELECT ISNULL(x.DepartmentId, 0), COALESCE(NULLIF(x.Severity, N''), N'(none)'), CASE WHEN x.Tier BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), x.Tier) ELSE N'Unclassified' END, x.AssetKey,
       COUNT_BIG(*), SUM(x.RiskScore), SUM(x.RiskScoreWeighted)
FROM sidata.Finding AS x
WHERE x.CollectionId = $cid AND x.FindingId > {AFTER} AND x.FindingId <= {UPTO}$mark AND (x.CiLifecycle IS NULL OR x.CiLifecycle = N'active')
GROUP BY ISNULL(x.DepartmentId, 0), COALESCE(NULLIF(x.Severity, N''), N'(none)'), CASE WHEN x.Tier BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), x.Tier) ELSE N'Unclassified' END, x.AssetKey;
"@
        $null = Invoke-SIDataSessionKeyRanges -Run $Run -Table '#fp' -Column 'AssetKey' -What $what -Log $Log -TargetMs $TargetMs -Text @'
INSERT #fr (DepartmentId, Severity, Tier, Findings, Assets, ScoreSum, WSum)
SELECT Dept, CASE WHEN GROUPING(Sev) = 1 THEN N'*' ELSE Sev END, CASE WHEN GROUPING(TierV) = 1 THEN N'*' ELSE TierV END,
       SUM(Findings), COUNT(DISTINCT AssetKey), SUM(ScoreSum), SUM(WSum)
FROM #fp WHERE 1 = 1{PRED}
GROUP BY GROUPING SETS ((Dept, Sev), (Dept, TierV), (Dept));
'@
        [int](& $Run @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
BEGIN TRAN;
DELETE FROM sidata.$table WHERE CollectionId = $cid;
INSERT sidata.$table (CollectionId, DepartmentId, Severity, Tier, Findings, Assets, ScoreTotal, WeightedTotal)
SELECT $cid, DepartmentId, Severity, Tier, SUM(Findings), SUM(Assets), ISNULL(SUM(ScoreSum), 0), SUM(WSum) FROM #fr GROUP BY DepartmentId, Severity, Tier;
DECLARE @n int = @@ROWCOUNT;
$stamp
COMMIT;
DROP TABLE #fp; DROP TABLE #fr;
SELECT @n;
"@ 'scalar')
    }
    [int](& $Invoke $null $null 'session' $onSession)
}

function Read-SIDataAssetTagRows {
    <#
        Reads the responsibility columns of every profile table (one query each). A table that does not exist yet is
        skipped (-ReadOrSkip). Returns @{ Kind; Row } pairs.
    #>
    param([Parameter(Mandatory)][scriptblock]$ReadOrSkip)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($pair in @(@('endpoint', 'SI_Endpoint_Profile_CL'), @('identity', 'SI_Identity_Profile_CL'), @('azure', 'SI_Azure_Profile_CL'))) {
        $rows = & $ReadOrSkip (Get-SIDataAssetTagKql -Kind $pair[0] -TableName $pair[1]) $pair[1]
        foreach ($r in @($rows)) { if ($r) { $out.Add([pscustomobject]@{ Kind = $pair[0]; Row = $r }) } }
    }
    , $out.ToArray()
}

function Write-SIDataAssetTags {
    <# Stores the CIs' tags (Get-SIDataAssetTagItems). A database without sidata.AssetTag writes nothing and says so. Returns the CIs written, or -1. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyCollection()][string[]]$Items = @(), [ref]$ChunkChars)
    if ([int](& $Invoke (Get-SIDataAssetTagSchemaCheckSql) @{} 'scalar') -ne 1) { return -1 }
    if (@($Items).Count -eq 0) { return 0 }
    Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataUpsertAssetTagSql) -Items $Items -ChunkChars $ChunkChars -What 'asset tags'
}

function Invoke-SIDataResolveCollection {
    <# Resolves ONE collection in FindingId ranges sized from their measured time, then its per-department aggregate + stamp. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [Parameter(Mandatory)][string]$Fingerprint,
          [string]$DefaultDepartment = '', [ref]$BatchSize, [long]$TargetMs = 5000, [switch]$WithName)
    $bRaw = & $Invoke (Get-SIDataFindingBoundsSql) @{ CollectionId = $CollectionId } 'reader'
    $b = @($bRaw) | Select-Object -First 1
    $done = 0L
    if ($b -and $null -ne $b['Lo'] -and -not ($b['Lo'] -is [System.DBNull])) {
        $lo = [long]$b['Lo']; $hi = [long]$b['Hi']
        $size = [long]20000; if ($BatchSize -and $BatchSize.Value -gt 0) { $size = [long]$BatchSize.Value }
        $after = $lo - 1
        while ($after -lt $hi) {
            $upto = [Math]::Min($hi, $after + $size)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $done += [long](& $Invoke (Get-SIDataResolveFindingSql -WithName:$WithName) @{ CollectionId = $CollectionId; After = $after; Upto = $upto; DefaultDepartment = $DefaultDepartment } 'scalar')
            $sw.Stop()
            $after = $upto
            $size = Get-SIDataNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 500
        }
        if ($BatchSize) { $BatchSize.Value = $size }
    }
    $facets = [int](Invoke-SIDataDepartmentFacet -Invoke $Invoke -CollectionId $CollectionId -Fingerprint $Fingerprint)
    [pscustomobject]@{ CollectionId = $CollectionId; Findings = $done; Facets = $facets }
}

function Invoke-SIDataResponsibility {
    <#
        Steps b-d of the file header. Returns @{ Ready; Assets (source -> CIs); Fingerprint; Resolved (per collection) }.
        -Settings: Resolve-SIDataResponsibilitySettings output.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Settings, [switch]$DryRun, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $res = [ordered]@{ Ready = $false; Assets = @{}; Fingerprint = ''; Pending = 0; Resolved = @() }
    if ([int](& $Invoke (Get-SIDataResponsibilitySchemaCheckSql) @{} 'scalar') -ne 1) {
        & $Log 'WARN' 'departments : the database does not have the asset responsibility tables yet -- run setup\Initialize-SIDataSql.ps1 and the Pro settings schema again to add them; the department views stay empty until then.'
        return [pscustomobject]$res
    }
    $res.Ready = $true
    $p = @{ Sources = (ConvertTo-SIDataJsonArrayText -Items $Settings.Sources); TagNames = (ConvertTo-SIDataJsonArrayText -Items $Settings.TagNames); DefaultDepartment = [string]$Settings.DefaultDepartment }
    $fp = [string](& $Invoke (Get-SIDataResponsibilityFingerprintSql) @{ Settings = [string]$Settings.Text } 'scalar')
    $res.Fingerprint = $fp.Trim()
    $pendRaw = & $Invoke (Get-SIDataUnresolvedSql) @{ Fingerprint = $res.Fingerprint } 'reader'
    $pending = @(@($pendRaw) | Where-Object { $_ })
    $res.Pending = $pending.Count
    if ($DryRun) {
        & $Log 'INFO' ("departments : {0} collection(s) would be resolved to departments; nothing is written." -f $pending.Count)
        return [pscustomobject]$res
    }
    $counts = @{}
    # a reader answer is ONE array object: assigned first, then enumerated
    $aRaw = & $Invoke (Get-SIDataResolveAssetsSql) $p 'reader'
    foreach ($r in @($aRaw)) { if ($r) { $counts[[string]$r['Source']] = [long]$r['N'] } }
    $res.Assets = $counts
    & $Log 'OK' ("departments : CIs by source -- {0}" -f ((@($counts.Keys | Sort-Object) | ForEach-Object { '{0} {1}' -f $_, $counts[$_] }) -join ', '))
    $batch = [long]0
    $withName = $false
    try { $withName = ([int](& $Invoke (Get-SIDataDepartmentNameCheckSql) @{} 'scalar')) -eq 1 } catch { $withName = $false }
    foreach ($c in $pending) {
        $res.Resolved += (Invoke-SIDataResolveCollection -Invoke $Invoke -CollectionId ([int]$c['CollectionId']) -Fingerprint $res.Fingerprint -DefaultDepartment $p.DefaultDepartment -BatchSize ([ref]$batch) -WithName:$withName)
    }
    if ($withName) { $null = Invoke-SIDataDepartmentNameBackfill -Invoke $Invoke -Log $Log }
    if ($pending.Count) {
        & $Log 'OK' ("departments : {0} collection(s) resolved ({1} finding row(s))" -f $pending.Count, (@($res.Resolved | ForEach-Object { $_.Findings }) | Measure-Object -Sum).Sum)
    } else { & $Log 'INFO' 'departments : every collection is resolved with the current policy.' }
    [pscustomobject]$res
}

function Invoke-SIDataDepartmentNameBackfill {
    <#
        #636: the finding rows resolved before sidata.Finding.DepartmentName existed get the name once, newest complete
        collection first, in batches of 50,000 within -BudgetSeconds (the rest follows on the next run). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log, [int]$BudgetSeconds = 300)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    try {
        $sql = "SELECT DISTINCT f.CollectionId FROM sidata.Finding AS f WHERE f.DepartmentName IS NULL AND f.DepartmentId IS NOT NULL ORDER BY f.CollectionId DESC;"
        $cols = @(@(& $Invoke $sql @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if ($cols.Count -eq 0) { return 0 }
        $clock = [Diagnostics.Stopwatch]::StartNew(); $rows = [long]0
        foreach ($c in $cols) {
            $cid = $(if ($c -is [System.Collections.IDictionary]) { $c['CollectionId'] } else { $c.CollectionId })
            while ($true) {
                $n = [long](& $Invoke (Get-SIDataDepartmentNameBackfillSql) @{ CollectionId = [int]$cid } 'scalar')
                $rows += $n
                if ($n -eq 0 -or $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            }
            if ($clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
        }
        & $Log 'OK' ("departments : department names written on {0} earlier finding row(s)" -f $rows)
        return $rows
    } catch {
        & $Log 'WARN' ("departments : the department names of earlier findings were not all written this run -- {0}. Tried again on the next run." -f $_.Exception.Message)
        return 0
    }
}