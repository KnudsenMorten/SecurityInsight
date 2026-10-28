#Requires -Version 5.1
<#
    RISK ANALYSIS ON CIs (V3-DATA-MODEL part 2, P4 / M4) -- the CI context of every finding row, BEFORE it is scored.

    Operator, 2026-10-08: "risk analyzes needs refinement, but that is all about switching to more static si fields whre
    appropriate". The reports keep their queries; what changes is that every row is tied to its CI and takes the CI's
    SI fields, so one asset has ONE tier, ONE set of CMDB values, ONE criticality factor and ONE set of asset risk factors
    in every report:

      * si_ci_id                     the row's CI (SI_CI_CL), found through any id the row carries -- the provider's own id
                                     (Defender device, Entra object, Azure resource, Exposure Graph node), SI_AssetId with
                                     its prefix removed -- and, only when no id is known, a name that exactly one CI has
      * CriticalityTier / -Level     the CI's tier (the enrichment rules' MIN, with its trace on the CI)
      * cmdbId / cmdbName / cmdbCriticality / cmdbDataSensitivity   the owning CMDB's values, where the row has none
      * RiskFactor_Weight            the CI's criticality factor (x100), unless the report's own weighting set one
      * RiskFactor_*_Detailed        the CI's asset risk factors (risk-factors.json) are added as tokens -- a factor the
                                     report already computed (same name, any spelling) is not added twice

    SI_RA_CiContext = off switches it off (the rows are then scored as before). No SI_CI_CL yet = nothing changes.
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

function Get-RADataModelMode {
    <#
        PURE. Which data model Risk Analysis scores on: 'ci' (M4 -- the CI decides tier, asset risk factors and the
        criticality factor) or 'legacy' (today: the CI context is added on top of the report's own values). Set by
        SI_DataModel; ring customers move to 'ci' at M6 (operator: the current v3 keeps releasing until the new model is
        complete).
    #>
    param($Setting = $global:SI_DataModel)
    if (([string]$Setting).Trim().ToLowerInvariant() -eq 'ci') { return 'ci' }
    return 'legacy'
}

function Get-RAStaleDays {
    <# PURE. SI_ActiveStaleDays (default 30): a CI not seen in any source for this many days is stale, and the CI's
       latest FULL row is looked for within the same days (operator: "device must look back 30 days before being stale"). #>
    param($Setting = $global:SI_ActiveStaleDays)
    $d = 0
    if ([int]::TryParse(([string]$Setting).Trim(), [ref]$d) -and $d -gt 0) { return $d }
    return 30
}

function Get-RACiIndexKql {
    <#
        The current CIs and their properties (#501, V3-DATA-MODEL 2.21) -- ONE query for both data models (the SQL CI
        build's SI_CI_CL contract). The CI build posts a SLIM 'seen' row for every CI every build and a FULL row only when
        a CI's content changed (plus a weekly full refresh), so:
          * the SET of CIs = the rows of the newest build (si_collection_time == its max; a full row also counts as seen)
          * a CI's PROPERTIES = its latest full row within SI_ActiveStaleDays (default 30) -- operator 2026-10-09: "a device
            can be off for 1 week, how do we find its latest data if you filter per day"
          * si_stale_ = the CI's lifecycle says not seen (#855 W10: the CI build's lifecycle, from the install's windows --
            Risk Analysis' own day count only decides for a CI whose row carries no lifecycle: the newest seen row says no
            source saw it within the same days)
        Rows written before the row kinds (no si_row_kind) count as both. One setting, never a second number. -Mode is
        kept for the callers; the data model changes what a finding TAKES from its CI (Add-RACiContext), not which CIs exist.
    #>
    param([ValidateSet('legacy', 'ci')][string]$Mode = 'legacy', [Alias('LookbackDays')][int]$StaleDays = 0)
    $LookbackDays = $StaleDays
    if ($LookbackDays -le 0) { $LookbackDays = 30; if ($global:SI_ActiveStaleDays -and [int]$global:SI_ActiveStaleDays -gt 0) { $LookbackDays = [int]$global:SI_ActiveStaleDays } }
    @"
let ci_ = SI_CI_CL
| where TimeGenerated > ago($($LookbackDays)d)
| extend si_k_ = tostring(si_ci_id), si_t_ = todatetime(si_collection_time), si_kind_ = tostring(column_ifexists('si_row_kind', ''))
| where isnotempty(si_k_);
let build_ = toscalar(ci_ | summarize max(si_t_));
let set_ = ci_ | where si_t_ == build_ | summarize si_seen_ = max(todatetime(column_ifexists('si_last_seen', datetime(null)))) by si_k_;
ci_
| where si_kind_ in ('full', '')
| summarize arg_max(si_t_, *) by si_k_
| join kind=inner set_ on si_k_
| extend si_ci_id = si_k_, si_last_seen = si_seen_
| extend si_lc_ = tostring(column_ifexists('si_lifecycle', ''))
| extend si_stale_ = iff(isnotempty(si_lc_), si_lc_ == 'not_seen', isnotnull(si_seen_) and si_seen_ < ago($($LookbackDays)d))
| project si_ci_id, si_class, si_asset_name, si_asset_type = tostring(column_ifexists('si_asset_type', '')), si_tier, si_tier_set_by, si_tier_reason = column_ifexists('si_tier_reason', ''),
          si_cmdb_id = column_ifexists('si_cmdb_id', ''), si_cmdb_name = column_ifexists('si_cmdb_name', ''),
          si_cmdb_criticality = column_ifexists('si_cmdb_criticality', ''), si_cmdb_data_sensitivity = column_ifexists('si_cmdb_data_sensitivity', ''),
          si_criticality_factor = column_ifexists('si_criticality_factor', real(null)),
          si_criticality_source = column_ifexists('si_criticality_source', dynamic(null)), si_risk_factors = column_ifexists('si_risk_factors', dynamic(null)),
          si_linked_objects = column_ifexists('si_linked_objects', dynamic(null)),
          si_link_mde = column_ifexists('si_link_mde', ''), si_link_entra = column_ifexists('si_link_entra', ''), si_link_azure = column_ifexists('si_link_azure', ''),
          si_link_eg = column_ifexists('si_link_eg', ''), si_link_ad = column_ifexists('si_link_ad', ''), si_link_intune = column_ifexists('si_link_intune', ''),
          si_last_seen, si_stale_,
          si_identity_origin = tostring(column_ifexists('si_identity_origin', '')), si_rf_unknown = column_ifexists('si_rf_unknown', dynamic(null)),
          si_unknown_fields = column_ifexists('si_unknown_fields', dynamic(null)),
          si_device_category = tostring(column_ifexists('si_device_category', '')), si_os_platform = tostring(column_ifexists('si_os_platform', '')),
          si_os_name = tostring(column_ifexists('si_os_name', ''))$(Get-RACiContextProjectionKql)
"@
}

# RICH CONTEXT ON EVERY REPORT ROW (owner 2026-10-11: "rich context, single overview through si, ability to prioritize"):
# the context a finding row takes from its CI besides tier and CMDB id -- ids AND names side by side, who owns and
# supports the asset, where it runs, and the facts a person prioritises on. name -> the type SI_CI_CL stores it as.
# A row keeps a value its own report already set; a CI without the value adds no column.
function Get-RACiContextFieldTypes {
    return [ordered]@{
    si_azure_subscription_id = 'string'; si_azure_subscription_name = 'string'; si_azure_resource_group = 'string'
    si_azure_tenant_id = 'string'; si_azure_tenant_name = 'string'
    si_management_group_id = 'string'; si_management_group_name = 'string'; si_management_group_path = 'string'
    # #772 the asset's OS family (Windows, Linux, ...): every finding carries its asset's value
    si_os_family = 'string'
    si_owner = 'string'; si_environment = 'string'; si_cost_center = 'string'; si_app_name = 'string'
    si_cmdb_owner = 'string'; si_cmdb_environment = 'string'; si_cmdb_support_group = 'string'; si_cmdb_support_group_id = 'string'
    si_service_owner = 'string'; si_service_department = 'string'; si_service_environment = 'string'
    si_service_support_group = 'string'; si_service_support_group_id = 'string'
    si_service_assignment_group = 'string'; si_service_assignment_group_id = 'string'
    si_backup_protected = 'bool'; si_pending_critical_patches = 'long'; si_defender_plan_tier = 'string'; si_mde_extension = 'bool'
    si_attached_resource_id = 'string'; si_attached_resource_name = 'string'
    si_is_encrypted = 'bool'; si_primary_user_upn = 'string'; si_intune_last_sync = 'datetime'
    # #636: the first Shodan banner of a public IP -- the source first-seen of its findings (RA-SourceFirstSeen.ps1)
    si_banner_first_seen = 'datetime'
    }
}

function Get-RACiContextProjectionKql {
    <# PURE. The context fields as the tail of the CI index query's projection: each read with column_ifexists, so a
       workspace whose SI_CI_CL does not hold a column yet (a build from before it) still answers. No comment lines. #>
    $cols = [System.Collections.Generic.List[string]]::new()
    $types = Get-RACiContextFieldTypes
    foreach ($k in $types.Keys) {
        $t = [string]$types[$k]
        if ($t -eq 'string') { $cols.Add(("{0} = tostring(column_ifexists('{0}', ''))" -f $k)) }
        else { $cols.Add(("{0} = column_ifexists('{0}', {1}(null))" -f $k, $t)) }
    }
    return (",`n          " + ($cols.ToArray() -join ",`n          "))
}

function Add-RACiContextFields {
    <# PURE. The CI's context fields onto one finding row: only a value the CI has, only where the row has none of its own. #>
    param($Row, $Ci)
    if ($null -eq $Row -or $null -eq $Ci) { return }
    # the field names are the same for every row: listed once per process
    if ($null -eq $script:RACiContextFieldNames) { $script:RACiContextFieldNames = [string[]]@((Get-RACiContextFieldTypes).Keys) }
    foreach ($k in $script:RACiContextFieldNames) {
        $v = $Ci.PSObject.Properties[$k]
        if (-not $v -or $null -eq $v.Value) { continue }
        $val = $v.Value
        if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) { continue }
        if ($val -is [System.DBNull]) { continue }
        $cur = $Row.PSObject.Properties[$k]
        if ($cur -and $null -ne $cur.Value -and -not ($cur.Value -is [string] -and [string]::IsNullOrWhiteSpace([string]$cur.Value))) { continue }
        Set-RARowValue $Row $k $val
    }
}
$script:RACiContextFieldNames = $null

function ConvertTo-RACiIdKey {
    <# PURE. An id as the CI index keys it: lower-case, SI's own prefixes removed (az:, eg:az:, eg:dev:, mde:, entra-user: ...). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $s = ([string]$Value).Trim().ToLowerInvariant()
    if (-not $s) { return '' }
    $s = $s -replace '^(eg:az:|eg:dev:|eg:|az:|mde:|entra-user:|entra-sp:|entra-device:|aad:)', ''
    return $s
}

function New-RACiIndex {
    <# PURE. CI rows -> @{ ById = id -> CI; ByName = unique name -> CI; Count }. #>
    param([AllowEmptyCollection()][object[]]$Cis = @())
    $byId = @{}; $nameCount = @{}; $byName = @{}
    foreach ($c in $Cis) {
        if ($null -eq $c -or -not $c.si_ci_id) { continue }
        $ids = [System.Collections.Generic.List[string]]::new()
        foreach ($f in 'si_ci_id', 'si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune') {
            $v = $c.PSObject.Properties[$f]; if ($v -and $v.Value) { $ids.Add([string]$v.Value) }
        }
        $lo = $c.PSObject.Properties['si_linked_objects']
        if ($lo -and $lo.Value) {
            $arr = $lo.Value
            if ($arr -is [string]) { try { $arr = $arr | ConvertFrom-Json } catch { $arr = @() } }
            foreach ($l in @($arr)) { if ($l -and $l.id) { $ids.Add([string]$l.id) } }
        }
        foreach ($i in $ids) { $k = ConvertTo-RACiIdKey $i; if ($k -and -not $byId.ContainsKey($k)) { $byId[$k] = $c } }
        $n = ([string]$c.si_asset_name).Trim().ToLowerInvariant()
        if ($n) { if ($nameCount.ContainsKey($n)) { $nameCount[$n]++ } else { $nameCount[$n] = 1; $byName[$n] = $c } }
    }
    foreach ($n in @($nameCount.Keys)) { if ($nameCount[$n] -gt 1) { $byName.Remove($n) } }   # a shared name identifies nothing
    return @{ ById = $byId; ByName = $byName; Count = @($Cis).Count }
}

function Test-RACiBuildHere {
    <#
        Does THIS Risk Analysis run build the CIs? (D2, operator 2026-10-08: CIs in both editions.) In Pro the correlation
        job builds them before Risk Analysis runs; where that job does not run (Community -- the 'correlation' feature is
        not available) Risk Analysis builds them at its start. SI_RA_BuildCis = on | off overrides; default auto.
    #>
    param([scriptblock]$FeatureAvailable)
    $s = ([string]$global:SI_RA_BuildCis).Trim().ToLowerInvariant()
    if ($s -in 'on', 'true', '1') { return $true }
    if ($s -in 'off', 'false', '0') { return $false }
    try {
        if (-not $FeatureAvailable) {
            if (-not (Get-Command -Name Test-SIFeatureAvailable -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'SI-FeatureCatalog.ps1') }
            $FeatureAvailable = { param($f) [bool](Test-SIFeatureAvailable -Feature $f).Allowed }
        }
        return (-not (& $FeatureAvailable 'correlation'))
    } catch { return $true }      # cannot tell: build -- the ledger keeps the ids stable either way
}

# ---------------------------------------------------------------------------------------------------------------------
# #639 THE RUN'S CI INDEX AT MILLIONS OF CIs (owner 2026-10-21: "env must work in millions of assets env"). The run never
# holds an index of every CI: the whole SI_CI_CL index was one answer (refused above the service's answer limit -- the
# findings were then scored WITHOUT their CI context) and held whole (~3 GB at 2 M CIs). Now Get-RACiIndex answers a KEYED
# index -- the same shape (ById / ByName / Count) -- that holds only the CIs of the rows in hand: Add-RACiContext looks the
# CIs of each query slice up (Use-RACiIndexSlice) by the ids and names the slice's rows carry, in the install database
# (sidata.Ci + sidata.CiLink, the CI build's tables) or, without one, in SI_CI_CL (keyed KQL, in id chunks). A caller that
# needs EVERY CI (the protection score's assets, the unknown counts) walks them a PAGE at a time: ById.Values of a keyed
# index reads the CIs page by page (keyset on the CI id) -- one page held, never the set. Get-RACiIndex never builds CIs:
# the run builds them where it decides (Invoke-RiskAnalysis, Community) -- it no longer asks the build for every CI.
# ---------------------------------------------------------------------------------------------------------------------
$script:RACiKeyedTableSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Management.Automation;
namespace SecurityInsight.RaCi {
    // ById of a keyed CI index: the current slice's CIs by key, and .Values = EVERY CI, read a page at a time.
    public class KeyedCiTable : Hashtable {
        public KeyedCiTable() : base(StringComparer.OrdinalIgnoreCase) { }
        public ScriptBlock AllPages;
        public object Owner;
        public long Total;
        // set from PowerShell through this method: a property assigned on a dictionary there becomes a KEY of it
        public void Bind(ScriptBlock pages, object owner, long total) { AllPages = pages; Owner = owner; Total = total; }
        public override ICollection Values {
            get { if (AllPages == null) { return base.Values; } return new PagedCiValues(AllPages, Owner, Total); }
        }
    }
    public class PagedCiValues : ICollection {
        private readonly ScriptBlock pages; private readonly object owner; private readonly long total;
        public PagedCiValues(ScriptBlock p, object o, long t) { pages = p; owner = o; total = t; }
        public int Count { get { return (int)Math.Min(total, int.MaxValue); } }
        public bool IsSynchronized { get { return false; } }
        public object SyncRoot { get { return this; } }
        public void CopyTo(Array array, int index) { foreach (object o in this) { array.SetValue(o, index++); } }
        public IEnumerator GetEnumerator() { return Walk().GetEnumerator(); }
        private IEnumerable<object> Walk() {
            string after = "";
            while (true) {
                Collection<PSObject> got = pages.Invoke(owner, after);
                if (got == null || got.Count == 0) { yield break; }
                string last = null;
                foreach (PSObject o in got) {
                    if (o == null) { continue; }
                    PSPropertyInfo p = o.Properties["si_ci_id"];
                    if (p != null && p.Value != null) { last = p.Value.ToString(); }
                    yield return o;
                }
                // (the store orders the ids in its own collation: only "no progress" ends the walk early)
                if (last == null || String.Equals(last, after, StringComparison.Ordinal)) { yield break; }
                after = last;
            }
        }
    }
}
'@
function Get-RACiKeyedTableType {
    <# The keyed index's ById type (compiled once per process; both PowerShell editions). #>
    if (-not ('SecurityInsight.RaCi.KeyedCiTable' -as [type])) { Add-Type -TypeDefinition $script:RACiKeyedTableSource -Language CSharp }
    [SecurityInsight.RaCi.KeyedCiTable]
}

function Get-RACiPageSize {
    <# Rows per page of the CI index (SI_RA_CiIndexPageRows, default 5,000 from the database, 50,000 from Log Analytics). It
       paces the reads; it never limits how many CIs are read. #>
    param([ValidateSet('sql', 'la')][string]$Source = 'sql')
    $n = 0
    if ($global:SI_RA_CiIndexPageRows -and [int]::TryParse(([string]$global:SI_RA_CiIndexPageRows).Trim(), [ref]$n) -and $n -gt 0) { return $n }
    if ($Source -eq 'la') { return 50000 }
    return 5000
}

function Get-RACiRowValue {
    <# A column of a database row (a dictionary from the 'reader' mode, or an object from 'rows'); DBNull is $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    else { $p = $Row.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function Get-RACiSqlCountSql {
    <# The current CIs of the install database: Count. #>
    "SET NOCOUNT ON; SELECT COUNT_BIG(*) AS N FROM sidata.Ci c WHERE ISNULL(c.Lifecycle, '') <> 'retired' AND c.DocJson IS NOT NULL;"
}

function Get-RACiSqlKeyedSql {
    <#
        The CIs one slice's rows can be matched to (@Ids = [ "id" ] lower case, each with and without SI's prefixes;
        @Names = [ "name" ]): by an id the CI carries (its own, or a linked object's), or by a name -- every current CI with
        one of the names is answered, so a name more than one CI has is dropped by New-RACiIndex as before. Retired CIs are
        not current. In CI id order (the first CI of a shared id wins, the same every run).
    #>
    @'
SET NOCOUNT ON;
DECLARE @idList TABLE (v nvarchar(450) PRIMARY KEY);
INSERT @idList SELECT DISTINCT LEFT(value, 450) FROM OPENJSON(@Ids) WHERE value IS NOT NULL AND value <> '';
DECLARE @nameList TABLE (v nvarchar(400) PRIMARY KEY);
INSERT @nameList SELECT DISTINCT LEFT(value, 400) FROM OPENJSON(@Names) WHERE value IS NOT NULL AND value <> '';
SELECT c.CiId, c.DocJson, CASE WHEN c.LastSeen IS NOT NULL AND c.LastSeen < DATEADD(day, -CONVERT(int, @StaleDays), SYSUTCDATETIME()) THEN 1 ELSE 0 END AS Stale
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, '') <> 'retired' AND c.DocJson IS NOT NULL
  AND (c.CiId IN (SELECT v FROM @idList)
       OR c.CiId IN (SELECT l.CiId FROM sidata.CiLink l WHERE l.NativeId IN (SELECT v FROM @idList))
       OR c.Name IN (SELECT v FROM @nameList))
ORDER BY c.CiId;
'@
}

function Get-RACiSqlPageSql {
    <# One page of every current CI (keyset on the CI id): after @After, @N of them, in id order. #>
    @'
SET NOCOUNT ON;
SELECT TOP (CONVERT(int, @N)) c.CiId, c.DocJson, CASE WHEN c.LastSeen IS NOT NULL AND c.LastSeen < DATEADD(day, -CONVERT(int, @StaleDays), SYSUTCDATETIME()) THEN 1 ELSE 0 END AS Stale
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, '') <> 'retired' AND c.DocJson IS NOT NULL AND c.CiId > @After
ORDER BY c.CiId;
'@
}

function Get-RACiFlatRows {
    <# The rows of a database answer, one level unrolled: the 'reader' mode answers its row list as ONE object (, $list). #>
    param([AllowEmptyCollection()][object[]]$Answer = @())
    foreach ($x in $Answer) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IDictionary] -or $x -is [System.Management.Automation.PSCustomObject] -or $x -isnot [System.Collections.IEnumerable] -or $x -is [string]) { $x; continue }
        foreach ($h in $x) { if ($null -ne $h) { $h } }
    }
}

function ConvertFrom-RACiSqlRows {
    <# Database rows (CiId, DocJson, Stale) -> CI objects as the index holds them (si_ci_id always set, si_stale_ 'true' / 'false'). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    foreach ($h in @(Get-RACiFlatRows -Answer $Rows)) {
        if ($null -eq $h) { continue }
        $js = [string](Get-RACiRowValue $h 'DocJson'); if (-not $js) { continue }
        $c = $null; try { $c = ConvertFrom-Json -InputObject $js } catch { continue }
        if ($null -eq $c) { continue }
        if (-not $c.PSObject.Properties['si_ci_id'] -or -not $c.si_ci_id) { Add-Member -InputObject $c -NotePropertyName 'si_ci_id' -NotePropertyValue ([string](Get-RACiRowValue $h 'CiId')) -Force }
        $st = Get-RACiRowValue $h 'Stale'
        Add-Member -InputObject $c -NotePropertyName 'si_stale_' -NotePropertyValue $(if ($null -ne $st -and [int]$st -eq 1) { 'true' } else { 'false' }) -Force
        $c
    }
}

function Get-RACiLaKeyedKql {
    <# The CI index query (Get-RACiIndexKql) narrowed to the CIs that carry one of -Ids (lower case: the CI id, a link id or a
       linked object's id) or one of -Names -- every CI with such a name, so a shared name is dropped by New-RACiIndex. #>
    param([AllowEmptyCollection()][string[]]$Ids = @(), [AllowEmptyCollection()][string[]]$Names = @(), [int]$StaleDays = 0)
    $q = { param($a) '"' + (([string]$a) -replace '\\', '\\' -replace '"', '\"') + '"' }
    $idList = (@($Ids | ForEach-Object { & $q $_ }) -join ', ')
    $nameList = (@($Names | ForEach-Object { & $q ([string]$_).ToLowerInvariant() }) -join ', ')
    (Get-RACiIndexKql -Mode (Get-RADataModelMode) -StaleDays $StaleDays) + @"

| extend k_ids_ = pack_array(tolower(si_ci_id), tolower(si_link_mde), tolower(si_link_entra), tolower(si_link_azure), tolower(si_link_eg), tolower(si_link_ad), tolower(si_link_intune))
| mv-apply lo_ = iff(isnull(si_linked_objects), dynamic([]), todynamic(si_linked_objects)) to typeof(dynamic) on (summarize k_lo_ = make_set(tolower(tostring(lo_.id))))
| where array_length(set_intersect(array_concat(k_ids_, k_lo_), dynamic([$idList]))) > 0 or tolower(si_asset_name) in (dynamic([$nameList]))
| project-away k_ids_, k_lo_
"@
}

function Get-RACiLaPageKql {
    <# One page of every CI from SI_CI_CL (keyset on the CI id): after -After, -Take of them, in id order. #>
    param([string]$After = '', [int]$Take = 50000, [int]$StaleDays = 0)
    $a = ([string]$After) -replace '\\', '\\' -replace '"', '\"'
    (Get-RACiIndexKql -Mode (Get-RADataModelMode) -StaleDays $StaleDays) + @"

| where si_ci_id > "$a"
| top $Take by si_ci_id asc
"@
}

function Get-RACiSliceKeys {
    <# PURE. The ids (lower case, each with and without SI's id prefixes) and names one slice's rows can be matched to their
       CI by -- the columns Find-RACiForRow reads. @{ Ids; Names }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $prefixes = @('', 'az:', 'eg:az:', 'eg:dev:', 'eg:', 'mde:', 'entra-user:', 'entra-sp:', 'entra-device:', 'aad:')
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        foreach ($col in 'si_ci_id', 'SI_CorrelationId', 'SI_AssetId', 'MdeDeviceId', 'DeviceId', 'AadDeviceId', 'AzureResourceId', 'ResourceId', 'EntraObjectId', 'EntraAccountObjectId', 'AccountObjectId', 'ObjectId', 'EgNodeId', 'NodeId', 'PrimaryEntityId', 'AssetId') {
            $p = $r.PSObject.Properties[$col]
            if (-not $p -or -not $p.Value) { continue }
            $k = ConvertTo-RACiIdKey ([string]$p.Value)
            if ($k) { foreach ($px in $prefixes) { [void]$ids.Add($px + $k) } }
        }
        foreach ($col in 'SI_AssetName', 'AssetName', 'DeviceName') {
            $p = $r.PSObject.Properties[$col]
            if ($p -and $p.Value) { $n = ([string]$p.Value).Trim(); if ($n) { [void]$names.Add($n) } }
        }
    }
    $i = New-Object 'string[]' $ids.Count; $ids.CopyTo($i)
    $n = New-Object 'string[]' $names.Count; $names.CopyTo($n)
    @{ Ids = $i; Names = $n }
}

function Read-RACiIndexPage {
    <# One page of EVERY current CI of a keyed index (-After = the last CI id of the page before; '' = the first page), in id
       order -- what ById.Values of a keyed index walks. Never more than one page is read at a time. #>
    param([Parameter(Mandatory)]$Index, [string]$After = '')
    if ($Index.Source -eq 'sql') {
        $rows = @(& $Index.Invoke (Get-RACiSqlPageSql) @{ After = $After; N = [string](Get-RACiPageSize -Source sql); StaleDays = [string]$Index.StaleDays } 'reader')
        return @(ConvertFrom-RACiSqlRows -Rows $rows)
    }
    if (-not (Get-Command -Name Invoke-LogAnalyticsKqlQuery -ErrorAction SilentlyContinue)) { return @() }
    @(Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -Query (Get-RACiLaPageKql -After $After -Take (Get-RACiPageSize -Source la) -StaleDays $Index.StaleDays) -TimeoutSec 300)
}

function Use-RACiIndexSlice {
    <#
        Fills a keyed index (Get-RACiIndex) with the CIs ONE slice's rows can be matched to -- the CIs of the slice before are
        let go. The database (sidata.Ci) when there is one, else SI_CI_CL in chunks of ids (SI_RA_CiIndexKeyChunk, default
        2,000 ids per query: the query text stays within the service's size). A lookup that fails is said once per run, as a
        WARNING of the run (the slice is scored without its CI context). Answers the CIs found.
    #>
    param([Parameter(Mandatory)]$Index, [AllowEmptyCollection()][object[]]$Rows = @())
    $Index.ById.Clear(); $Index.ByName.Clear()
    $keys = Get-RACiSliceKeys -Rows $Rows
    if (@($keys.Ids).Count -eq 0 -and @($keys.Names).Count -eq 0) { return 0 }
    $cis = New-Object System.Collections.Generic.List[object]
    try {
        if ($Index.Source -eq 'sql') {
            $res = @(& $Index.Invoke (Get-RACiSqlKeyedSql) @{ Ids = (ConvertTo-Json -InputObject @($keys.Ids) -Compress); Names = (ConvertTo-Json -InputObject @($keys.Names) -Compress); StaleDays = [string]$Index.StaleDays } 'reader')
            foreach ($c in @(ConvertFrom-RACiSqlRows -Rows $res)) { $cis.Add($c) }
        } elseif ($global:SI_WorkspaceResourceId -and (Get-Command -Name Invoke-LogAnalyticsKqlQuery -ErrorAction SilentlyContinue)) {
            $chunk = 2000; $x = 0; if ($global:SI_RA_CiIndexKeyChunk -and [int]::TryParse(([string]$global:SI_RA_CiIndexKeyChunk).Trim(), [ref]$x) -and $x -gt 0) { $chunk = $x }
            $ids = @($keys.Ids); $names = @($keys.Names)
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $n = [Math]::Max([Math]::Ceiling($ids.Count / $chunk), [Math]::Ceiling($names.Count / $chunk))
            for ($i = 0; $i -lt $n; $i++) {
                $iPart = @(); if ($i * $chunk -lt $ids.Count) { $iPart = @($ids[($i * $chunk)..([Math]::Min(($i + 1) * $chunk, $ids.Count) - 1)]) }
                $nPart = @(); if ($i * $chunk -lt $names.Count) { $nPart = @($names[($i * $chunk)..([Math]::Min(($i + 1) * $chunk, $names.Count) - 1)]) }
                foreach ($c in @(Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -Query (Get-RACiLaKeyedKql -Ids $iPart -Names $nPart -StaleDays $Index.StaleDays) -TimeoutSec 300)) {
                    if ($c -and $c.si_ci_id -and $seen.Add([string]$c.si_ci_id)) { $cis.Add($c) }
                }
            }
        }
    } catch {
        if (-not $Index.Said) {
            $Index.Said = $true
            $why = ('CI context: the CIs of a query slice could not be looked up ({0}) -- those findings are scored WITHOUT their CI context (tier, criticality, exposure)' -f $_.Exception.Message)
            Write-Warning $why
            $pf = Get-Variable -Name _RAPublishFailures -Scope Script -ValueOnly -ErrorAction SilentlyContinue
            if ($null -ne $pf) { try { [void]$pf.Add($why) } catch { } }
            $global:RA_CiIndexProblem = $why
        }
        return 0
    }
    $ix = New-RACiIndex -Cis $cis.ToArray()
    foreach ($k in $ix.ById.Keys) { $Index.ById[$k] = $ix.ById[$k] }
    foreach ($k in $ix.ByName.Keys) { $Index.ByName[$k] = $ix.ByName[$k] }
    $Index.SliceCis = $cis.Count
    $cis.Count
}

function Get-RACiIndex {
    <#
        The run's CI index (cached for every report of the run): a KEYED index (#639 -- see the block above) over the install
        database (sidata.Ci) when it is configured, else over SI_CI_CL. It holds no CI until a slice is looked up
        (Use-RACiIndexSlice, which Add-RACiContext calls); Count = the number of current CIs (0 = no CIs yet, nothing changes);
        ById.Values walks every CI a page at a time. Get-RACiIndex never builds CIs and never reads every CI at once.
        -Invoke: the install database seam { param($Sql, $Params, $Mode) } (tests); default the run's database (the stream's
        connection, else SI_ProSqlServer / SI_ProSqlDatabase), none = SI_CI_CL.
    #>
    param([scriptblock]$Invoke, [switch]$LogAnalytics)
    if ($null -ne $global:RA_CiIndex) { return $global:RA_CiIndex }
    $global:RA_CiIndexProblem = $null
    $staleDays = Get-RAStaleDays
    if (-not $Invoke -and -not $LogAnalytics) {
        try {
            $st = Get-Variable -Name RAStream -Scope Script -ValueOnly -ErrorAction SilentlyContinue
            if ($st -and $st.Invoke) { $Invoke = $st.Invoke }
            elseif ((Get-Command -Name Test-RAStreamWanted -ErrorAction SilentlyContinue) -and (Test-RAStreamWanted) -and (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue) -and (Get-Command -Name Resolve-SIDataSettings -ErrorAction SilentlyContinue)) {
                $g = @{}; foreach ($n in 'SI_ProSqlServer', 'SI_ProSqlDatabase', 'SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase') { $g[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
                $set = Resolve-SIDataSettings -Globals $g
                $Invoke = New-SIDataSqlInvoke -Server $set.Server -Database $set.Database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
            }
        } catch { $Invoke = $null }
    }
    $type = Get-RACiKeyedTableType
    $byId = New-Object $type
    $idx = @{ Keyed = $true; ById = $byId; ByName = @{}; Count = 0; Source = $(if ($Invoke) { 'sql' } else { 'la' }); Invoke = $Invoke; StaleDays = $staleDays; Said = $false; SliceCis = 0 }
    $n = 0L
    try {
        if ($Invoke) {
            $r = @(Get-RACiFlatRows -Answer @(& $Invoke (Get-RACiSqlCountSql) @{} 'reader')) | Select-Object -First 1
            if ($r) { $n = [long](Get-RACiRowValue $r 'N') }
        } elseif ($global:SI_WorkspaceResourceId -and (Get-Command -Name Invoke-LogAnalyticsKqlQuery -ErrorAction SilentlyContinue)) {
            $c = @(Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -Query ((Get-RACiIndexKql -Mode (Get-RADataModelMode) -StaleDays (Get-RAStaleDays)) + "`n| count") -TimeoutSec 300) | Select-Object -First 1
            if ($c) { $p = $c.PSObject.Properties['Count']; if ($p) { $n = [long]$p.Value } }
        }
    } catch {
        # #639 (working rule 4): never only verbose -- every finding of this run is scored WITHOUT its CI's context (tier,
        # criticality, exposure), so the run is a WARNING: said in the log and on the run's END record (a partial run --
        # the data sync marks its collection and the close-loop closes nothing on it)
        $src = if ($Invoke) { 'the CIs in the database' } else { 'SI_CI_CL' }
        $why = ('CI context: {0} could not be read ({1}) -- the findings of this run are scored WITHOUT their CI context (tier, criticality, exposure)' -f $src, $_.Exception.Message)
        Write-Warning $why
        $pf = Get-Variable -Name _RAPublishFailures -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $pf) { try { [void]$pf.Add($why) } catch { } }
        $global:RA_CiIndexProblem = $why
        $n = 0L
    }
    $idx.Count = $n
    # (through a method: a property assigned on a dictionary from PowerShell becomes a KEY of it)
    $byId.Bind({ param($Index, $After) Read-RACiIndexPage -Index $Index -After $After }, $idx, [long]$n)
    $global:RA_CiIndex = $idx
    return $global:RA_CiIndex
}

function Find-RACiForRow {
    <# PURE. The CI of one finding row: by any id it carries, else by a name exactly one CI has. @{ Ci; By } or $null. #>
    param($Row, [Parameter(Mandatory)][hashtable]$Index)
    foreach ($col in 'si_ci_id', 'SI_CorrelationId', 'SI_AssetId', 'MdeDeviceId', 'DeviceId', 'AadDeviceId', 'AzureResourceId', 'ResourceId', 'EntraObjectId', 'EntraAccountObjectId', 'AccountObjectId', 'ObjectId', 'EgNodeId', 'NodeId', 'PrimaryEntityId', 'AssetId') {
        $p = $Row.PSObject.Properties[$col]
        if (-not $p -or -not $p.Value) { continue }
        $k = ConvertTo-RACiIdKey ([string]$p.Value)
        if ($k -and $Index.ById.ContainsKey($k)) { return @{ Ci = $Index.ById[$k]; By = $col } }
    }
    foreach ($col in 'SI_AssetName', 'AssetName', 'DeviceName') {
        $p = $Row.PSObject.Properties[$col]
        if (-not $p -or -not $p.Value) { continue }
        $n = ([string]$p.Value).Trim().ToLowerInvariant()
        if ($Index.ByName.ContainsKey($n)) { return @{ Ci = $Index.ByName[$n]; By = 'name' } }
    }
    return $null
}

function ConvertTo-RATokenKey {
    <#
        A risk-factor token compared by the FACTOR it names: RF_P_InternetExposed == Internet-Exposed == internet_exposed,
        and -- through the catalog's legacy tokens (RA-FactorKeys.ps1) -- LegacyEndOfSupport == unsupported_os. Letters
        only when the catalog keys are not loaded. One factor is counted once.
    #>
    param([string]$Token)
    if ($null -eq $script:RACiHasFactorKeys) { $script:RACiHasFactorKeys = [bool](Get-Command -Name ConvertTo-RAFactorKey -ErrorAction SilentlyContinue) }
    if ($script:RACiHasFactorKeys) { return (ConvertTo-RAFactorKey -Token $Token) }
    (([string]$Token) -replace '^(?i)RF_[PC]_', '' -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
}

function New-RAFactorCatalog {
    <#
        PURE. The risk-factor catalog as Risk Analysis needs it: @{ AssetKeys = token key -> factor id (every factor the
        catalog evaluates on the ASSET -- its id, its catalog name and its legacyTokens); Display = factor id -> the token a
        report shows: the catalog's display NAME (owner 2026-10-10 -- a customer renames a factor once, in the catalog), else
        its first legacy token, else the id }. Finding factors and
        report-scoped factors are NOT asset keys -- they stay the report's.
    #>
    param([AllowEmptyCollection()][object[]]$Factors = @())
    $keys = @{}; $display = @{}; $axis = @{}
    foreach ($f in $Factors) {
        if ($null -eq $f -or -not $f.id) { continue }
        $id = [string]$f.id
        $axis[$id] = [string]$f.axis
        $first = @(@($f.legacyTokens) | Where-Object { $_ })
        $name = ''; if ($f.PSObject.Properties['name']) { $name = ([string]$f.name).Trim() }
        # #558 / #559: reports show the SHORT name (InternetExposed); the description (name) is the GUI's
        $short = ''; if ($f.PSObject.Properties['shortName']) { $short = ([string]$f.shortName).Trim() }
        if ($short) { $display[$id] = $short } elseif ($name) { $display[$id] = $name } elseif ($first.Count -gt 0) { $display[$id] = [string]$first[0] } else { $display[$id] = $id }
        if ([string]$f.appliesTo -ne 'asset' -or ([string]$f.evaluatedBy -and [string]$f.evaluatedBy -ne 'catalog')) { continue }
        $alias = @(@($id) + $first); if ($name) { $alias += $name }; if ($short) { $alias += $short }
        foreach ($t in $alias) { $k = ConvertTo-RATokenKey ([string]$t); if ($k -and -not $keys.ContainsKey($k)) { $keys[$k] = $id } }
    }
    return @{ AssetKeys = $keys; Display = $display; Axis = $axis }
}

function Get-RAFactorCatalog {
    <# The run's factor catalog (cached): the data model's risk-factors (with the customer's overlay) when it loads, else
       the shipped data-model/risk-factors.locked.json. #>
    if ($null -ne $global:RA_FactorCatalog) { return $global:RA_FactorCatalog }
    $factors = @()
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    try {
        if (-not (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\data-model\SI-DataModelTemplates.ps1') }
        $m = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot
        $factors = @($m['risk-factors'].factors)
    } catch {
        try { $factors = @((Get-Content -LiteralPath (Join-Path $siRoot 'data-model\risk-factors.locked.json') -Raw | ConvertFrom-Json).factors) } catch { $factors = @() }
    }
    $global:RA_FactorCatalog = New-RAFactorCatalog -Factors $factors
    return $global:RA_FactorCatalog
}

function Select-RACiModeTokens {
    <#
        PURE. Data model 'ci': a row's tokens with every ASSET-catalog token removed except those the CI set (the CI
        decides the asset factors -- one definition, never the report's provider columns, never counted twice). Finding
        and report-scoped tokens stay. One factor is kept once: a second token naming the same factor (InternetExposureSignal
        after RF_P_InternetExposed) is dropped. Returns the kept tokens (input order).
    #>
    param([AllowEmptyCollection()][string[]]$Tokens = @(), [Parameter(Mandatory)][hashtable]$Catalog, [AllowEmptyCollection()][string[]]$CiTokens = @())
    $ci = @{}; foreach ($t in $CiTokens) { $k = ConvertTo-RATokenKey $t; if ($k) { $ci[$k] = $true } }
    $out = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($t in $Tokens) {
        if (-not $t) { continue }
        $k = ConvertTo-RATokenKey $t
        if ($k -and $Catalog.AssetKeys.ContainsKey($k) -and -not $ci.ContainsKey($k)) { continue }
        if ($k) { if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true }
        $out.Add($t)
    }
    return $out.ToArray()      # unrolled: callers wrap in @()
}

function Set-RARowValue {
    param($Row, [string]$Name, $Value)
    # (a new column through the row's own property list, not the Add-Member command: this runs several times per row)
    if ($Row.PSObject.Properties[$Name]) { $Row.$Name = $Value } else { $Row.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($Name, $Value)) }
}

function Add-RACiContext {
    <#
    .SYNOPSIS  Ties every finding row to its CI and takes the CI's SI fields (see the header). Returns the rows.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Index,
          # 'legacy' (default: the CI context on top of the report's own values) or 'ci' (M4: the CI decides) -- SI_DataModel
          [ValidateSet('legacy', 'ci')][string]$Mode = (Get-RADataModelMode),
          # the risk-factor catalog (test seam); default the run's (Get-RAFactorCatalog)
          [hashtable]$Catalog,
          # #541: the report's factor set (RA-ScopePreamble.ps1, Get-RAReportFactorSet) -- a CI factor outside it never
          # reaches this report (no network factor on an identity report). Empty = every factor.
          [AllowEmptyCollection()][string[]]$FactorSet = @())
    if ($global:SI_RA_CiContext -and ([string]$global:SI_RA_CiContext).Trim().ToLowerInvariant() -in 'off', 'false', '0') { return , @($Rows) }
    if ($null -eq $Index) { $Index = Get-RACiIndex }
    if ($null -eq $Index -or $Index.Count -eq 0) { return , @($Rows) }
    # #639 a keyed index holds only the CIs of the rows in hand: looked up for THIS slice (the slice before is let go)
    if ($Index.Keyed) { $null = Use-RACiIndexSlice -Index $Index -Rows @($Rows) }
    $mode = $Mode
    $catalog = $Catalog
    if ($mode -eq 'ci' -and $null -eq $catalog) { $catalog = Get-RAFactorCatalog }
    # the tokens this adds show the catalog's display names in both modes (legacy too)
    if ($null -eq $catalog) { try { $catalog = Get-RAFactorCatalog } catch { $catalog = $null } }
    $fsSet = @{}; foreach ($x in @($FactorSet)) { if ($x) { $fsSet[[string]$x] = $true } }
    $labels = @{ 0 = 'Critical - tier 0'; 1 = 'High - tier 1'; 2 = 'Medium - tier 2'; 3 = 'Low - tier 3' }
    # PERFORMANCE (a query slice is tens of thousands of rows over a few thousand CIs): what depends only on the CI -- its
    # risk factors read from their JSON, each factor's token keys -- is worked out once per CI, not once per row
    $hasAssetClass = [bool](Get-Command -Name Get-SIRiskIndexAssetClass -ErrorAction SilentlyContinue)
    $ciFactorsOf = New-Object 'System.Collections.Generic.Dictionary[object,object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
    $faKeysOf = New-Object 'System.Collections.Generic.Dictionary[object,object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
    $assetClassOf = New-Object 'System.Collections.Generic.Dictionary[object,object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
    $cmdbPairs = @(@('cmdbId', 'si_cmdb_id'), @('cmdbName', 'si_cmdb_name'), @('cmdbCriticality', 'si_cmdb_criticality'), @('cmdbDataSensitivity', 'si_cmdb_data_sensitivity'))
    # a long step is never silent (RA-RowShaping.ps1, Step-RAProgress)
    $prog = $null; $ciRowNo = 0
    if (Get-Command -Name New-RAProgress -ErrorAction SilentlyContinue) { $prog = New-RAProgress -What 'the CI context added to' -Total @($Rows).Count }
    foreach ($r in $Rows) {
        $ciRowNo++
        if ($null -ne $prog -and ($ciRowNo % 200) -eq 0) { Step-RAProgress $prog $ciRowNo }
        if ($null -eq $r) { continue }
        $hit = Find-RACiForRow -Row $r -Index $Index
        if ($null -eq $hit) { continue }
        $ci = $hit.Ci
        Set-RARowValue $r 'si_ci_id' ([string]$ci.si_ci_id)
        Set-RARowValue $r 'si_ci_match' ([string]$hit.By)
        # #559 the asset class the risk index keys on (device_server / device_client / identity / cloud_resource / public_ip):
        # the CI's class, a device split by its category / OS (Get-SIRiskIndexAssetClass, RA-RiskIndexSi.ps1)
        if ($ci.PSObject.Properties['si_class'] -and $ci.si_class) {
            Set-RARowValue $r 'si_class' ([string]$ci.si_class)
            if ($hasAssetClass) {
                # (the class depends only on the CI: worked out once per CI)
                $acv = $null
                if (-not $assetClassOf.TryGetValue($ci, [ref]$acv)) {
                    $acDc = $null; $acOp = $null; $acOn = $null
                    if ($ci.PSObject.Properties['si_device_category']) { $acDc = [string]$ci.si_device_category }
                    if ($ci.PSObject.Properties['si_os_platform']) { $acOp = [string]$ci.si_os_platform }
                    if ($ci.PSObject.Properties['si_os_name']) { $acOn = [string]$ci.si_os_name }
                    $acv = Get-SIRiskIndexAssetClass -Class ([string]$ci.si_class) -DeviceCategory $acDc -OsPlatform $acOp -OsName $acOn
                    $assetClassOf[$ci] = $acv
                }
                Set-RARowValue $r 'si_asset_class' $acv
            }
        }
        # one tier per asset: the CI's
        $t = $null
        if ($null -ne $ci.si_tier -and "$($ci.si_tier)" -ne '') { $t = [int](ConvertTo-SINumberOrNullRA $ci.si_tier) }
        if ($null -ne $t -and $labels.ContainsKey($t)) {
            Set-RARowValue $r 'CriticalityTier' $t
            Set-RARowValue $r 'CriticalityTierLevel' $labels[$t]
        }
        # the owning CMDB's values where the report has none
        foreach ($pair in $cmdbPairs) {
            $cur = $r.PSObject.Properties[$pair[0]]
            $v = $ci.PSObject.Properties[$pair[1]]
            # 'ci': the owning CMDB's value on the CI wins; 'legacy': only where the report has none
            if ($v -and $v.Value -and ($mode -eq 'ci' -or -not $cur -or [string]::IsNullOrWhiteSpace([string]$cur.Value))) { Set-RARowValue $r $pair[0] ([string]$v.Value) }
        }
        # rich context: subscription / tenant / management group (ids and names), owner, environment, support group, backup,
        # pending updates ... from the CI, where the row has none of its own
        Add-RACiContextFields -Row $r -Ci $ci
        $factors = $null
        if (-not $ciFactorsOf.TryGetValue($ci, [ref]$factors)) {
            $factors = $ci.si_risk_factors
            if ($factors -is [string]) { try { $factors = $factors | ConvertFrom-Json } catch { $factors = @() } }
            $ciFactorsOf[$ci] = $factors
        }
        $f = ConvertTo-SINumberOrNullRA $ci.si_criticality_factor
        if ($mode -eq 'ci') {
            # M4 (V3-DATA-MODEL 2.21): the CI decides. Weight = the CI's criticality factor (over the report's own
            # weighting); the asset risk factors = the CI's production factors, REPLACING every asset-catalog token the
            # report computed from provider columns (one definition, never twice); finding / report-scoped tokens stay.
            Set-RARowValue $r 'si_data_model' 'ci'
            $stale = $ci.PSObject.Properties['si_stale_']
            if ($stale) { Set-RARowValue $r 'si_ci_stale' ([string]$stale.Value -in 'true', 'True', '1') }
            if ($null -ne $f -and $f -gt 0) { Set-RARowValue $r 'RiskFactor_Weight' ([int][Math]::Round($f * 100)) }
            $ciAll = [System.Collections.Generic.List[string]]::new()
            foreach ($axis in 'probability', 'consequence') {
                $col = 'RiskFactor_Probability_Detailed'; if ($axis -eq 'consequence') { $col = 'RiskFactor_Consequence_Detailed' }
                $ciTokens = [System.Collections.Generic.List[string]]::new()
                foreach ($fa in @($factors)) {
                    if ($null -eq $fa -or [string]$fa.axis -ne $axis) { continue }
                    if ($fsSet.Count -and -not $fsSet.ContainsKey([string]$fa.id)) { continue }
                    if ($fa.PSObject.Properties['stage'] -and [string]$fa.stage -and [string]$fa.stage -ne 'production') { continue }
                    if ((ConvertTo-SINumberOrNullRA $fa.impact) -le 0) { continue }
                    $tok = [string]$fa.id; if ($catalog.Display.ContainsKey($tok)) { $tok = [string]$catalog.Display[$tok] }
                    if (-not $ciTokens.Contains($tok)) { $ciTokens.Add($tok) }
                }
                $existing = @(foreach ($e in (([string]$(if ($r.PSObject.Properties[$col]) { $r.$col } else { '' })) -split '\s*;\s*')) { if ($e) { $e } })
                $kept = @(Select-RACiModeTokens -Tokens $existing -Catalog $catalog -CiTokens @())
                $have = @{}; foreach ($e in $kept) { $have[(ConvertTo-RATokenKey $e)] = $true }
                $merged = [System.Collections.Generic.List[string]]::new()
                foreach ($e in $kept) { $merged.Add($e) }
                foreach ($tok in $ciTokens) { $k = ConvertTo-RATokenKey $tok; if (-not $have.ContainsKey($k)) { $merged.Add($tok); $have[$k] = $true }; $ciAll.Add($tok) }
                Set-RARowValue $r $col ($merged.ToArray() -join ';')
            }
            Set-RARowValue $r 'si_ci_factor_tokens' ($ciAll.ToArray() -join ';')
            continue
        }
        # the criticality factor -- unless the report's own weighting already set one
        $w = $r.PSObject.Properties['RiskFactor_Weight']
        $wv = $null; if ($w) { $wv = ConvertTo-SINumberOrNullRA $w.Value }
        if ($null -ne $f -and $f -gt 0 -and ($null -eq $wv -or $wv -eq 100 -or $wv -le 0)) { Set-RARowValue $r 'RiskFactor_Weight' ([int][Math]::Round($f * 100)) }
        # the CI's asset risk factors as tokens, once
        # the tokens added here are marked (si_ci_factor_tokens) so the score adds them ON TOP of a report that gives its
        # probability as a number only, instead of replacing that number (Calculate-RiskScore; removed from the row there)
        $added = [System.Collections.Generic.List[string]]::new()
        foreach ($axis in 'probability', 'consequence') {
            $col = 'RiskFactor_Probability_Detailed'; if ($axis -eq 'consequence') { $col = 'RiskFactor_Consequence_Detailed' }
            $existing = @(foreach ($e in (([string]$(if ($r.PSObject.Properties[$col]) { $r.$col } else { '' })) -split '\s*;\s*')) { if ($e) { $e } })
            $have = @{}; foreach ($e in $existing) { $have[(ConvertTo-RATokenKey $e)] = $true }
            $add = [System.Collections.Generic.List[string]]::new()
            foreach ($fa in @($factors)) {
                if ($null -eq $fa -or [string]$fa.axis -ne $axis) { continue }
                if ($fsSet.Count -and -not $fsSet.ContainsKey([string]$fa.id)) { continue }
                if ((ConvertTo-SINumberOrNullRA $fa.impact) -le 0) { continue }      # testing factors count 0
                # the factor's token keys depend only on the factor: worked out once per factor
                $keys = $null
                if (-not $faKeysOf.TryGetValue($fa, [ref]$keys)) {
                    $keys = @((ConvertTo-RATokenKey $fa.id)) + @(@($fa.tokens) | ForEach-Object { ConvertTo-RATokenKey $_ })
                    $faKeysOf[$fa] = $keys
                }
                $dup = $false; foreach ($k in $keys) { if ($k -and $have.ContainsKey($k)) { $dup = $true } }
                if ($dup) { continue }
                $tok = [string]$fa.id
                if ($catalog -and $catalog.Display -and $catalog.Display.ContainsKey($tok)) { $tok = [string]$catalog.Display[$tok] }
                $add.Add($tok); $have[(ConvertTo-RATokenKey $tok)] = $true; $have[(ConvertTo-RATokenKey $fa.id)] = $true
            }
            if ($add.Count -gt 0) { Set-RARowValue $r $col (@($existing + $add.ToArray()) -join ';'); $added.AddRange($add) }
        }
        if ($added.Count -gt 0) { Set-RARowValue $r 'si_ci_factor_tokens' ($added.ToArray() -join ';') }
    }
    return , @($Rows)
}

function ConvertTo-SINumberOrNullRA {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return [double]$Value }
    $d = 0.0
    if ([double]::TryParse(([string]$Value).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    return $null
}
