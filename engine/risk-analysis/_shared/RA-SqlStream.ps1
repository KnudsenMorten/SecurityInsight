#Requires -Version 5.1
<#
    Risk Analysis -- THE RESULT GOES TO SQL, A BUCKET AT A TIME (#638, owner 2026-10-13: "ra must newer only be in memory, as
    memory will newer support millions of rows" / "sql is tool gui talks with").

    Per bucket: the report's query (unchanged), the rows scored, WRITTEN to the Pro database, then the next bucket -- the
    result is never gathered in memory across buckets. What needs the whole picture is read back from SQL afterwards, in
    pages, in the final order (score, highest first; then the order the rows were written):

      * a Detailed run writes sidata.Finding (the data sync's mapping, DetailJson = the whole row), a Summary run
        sidata.SummaryRow + sidata.SummaryAsset (the data sync's mapping, RowJson = the whole row) -- the tables the web app
        reads; the run's own collection (sidata.Collection / sidata.SummaryLoad) stays 'Loading' until every bucket of every
        report is in;
      * a retried bucket replaces its own rows (delete by bucket, then insert) -- never doubles; a report that has to start
        again with more buckets, or cannot run at all, has its rows removed;
      * a finding two buckets both returned is kept once, the first written (the same key the scoring de-duplicates on);
      * a Summary report's rows go to sidata.RaStage per bucket first: a group that spans buckets is combined by the SAME
        rules as before (Merge-RASummaryBucketRows), a page of whole groups at a time, then scored and written;
      * two different assets that share a trace name get the asset id at the end of it, decided over the whole report
        (Set-RATraceIdentity per bucket, then one fix-up of the rows whose name another bucket shares);
      * #641: per report, what the source says the report holds (counted in the report's own slices: Measure-RAReportExpectedRows;
        a Summary report in its distinct groups) against what the buckets returned, kept in sidata.RaReportStatus -- a report
        that does not match, or is not in the run, is NOT COMPLETE.

    ONE SEAM: -Invoke (sql, params, mode 'reader'|'scalar'|'nonquery') -- the data sync's (New-SIDataSqlInvoke), so tests
    replace the database. Every statement converts its parameters itself (a test seam may pass them all as text).
    No DDL here: the schema is sql/si-data-schema.sql (the updater's step); a database without it is told and the run
    keeps its result in memory as before.
#>

# #902: the one list of hold kinds (Set-RAStreamReportNotComplete writes only a kind of it)
if (-not (Get-Command -Name Test-SIHoldKind -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-HoldKinds.ps1')) }

# Newtonsoft.Json ships with PowerShell 7; it is loaded on first use of the JSON cmdlets -- made sure of here.
if (-not ('Newtonsoft.Json.JsonConvert' -as [type])) {
    try { $null = ConvertFrom-Json -InputObject '{}' } catch { }
}
$script:RAStreamLegalName = [regex]'^[A-Za-z][A-Za-z0-9_]*$'
$script:RAStreamInv = [System.Globalization.CultureInfo]::InvariantCulture
$script:RAStreamNarrowCols = @('SI_AssetId', 'AssetId', 'ConfigurationId', 'AssetDetectedInReportName', 'ReportName', 'Category', 'AssetName', 'SecurityDomain', 'ConfigurationName',
    'SecuritySeverity', 'CriticalityTier', 'SourceCriticalityTier', 'RiskScoreTotal', 'SI_ExemptionId', 'SI_ExemptedUntil', 'SI_ExemptionRequestId')
$script:RAStreamDedupCols = @('SecurityDomain','Category','Subcategory','ConfigurationName','<cfg>','CriticalityTier','SecuritySeverity','cmdbCriticality','cmdbDataSensitivity','AssetName','SI_AssetId','AssetId','AadDeviceId')
# the finding's TARGET (#690 (3)): appended to the key only when the row carries one (RA-RiskScore.ps1 $targetKeyCols)
$script:RAStreamDedupTargetCols = @('TargetAssetId','LinkedAzureResourceId')

function Get-RAStreamSchemaCheckSql {
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding','RaSeq') IS NOT NULL AND COL_LENGTH('sidata.Finding','RaAssetTier') IS NOT NULL AND COL_LENGTH('sidata.SummaryRow','RowJson') IS NOT NULL AND COL_LENGTH('sidata.Collection','RaCompletedAt') IS NOT NULL AND OBJECT_ID('sidata.RaStage') IS NOT NULL AND OBJECT_ID('sidata.RaReportStatus') IS NOT NULL THEN 1 ELSE 0 END"
}

function Test-RAStreamWanted {
    <# PURE over the globals. Stream to SQL when the Pro database is configured and SI_RA_ResultInSql is not off. #>
    param([hashtable]$Globals)
    $g = { param($n) if ($Globals) { [string]$Globals[$n] } else { [string](Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue) } }
    # [string] around the call: a setting that is not set at all comes back as nothing, not '' (live 2026-10-13: the
    # internal install's Risk Analysis stopped here before its first report, "You cannot call a method on a null-valued expression")
    $sw = ([string](& $g 'SI_RA_ResultInSql')).Trim().ToLowerInvariant()
    if ($sw -in 'off', 'false', '0', 'no') { return $false }
    $srv = & $g 'SI_Pro_DataSqlServer'; if (-not $srv) { $srv = & $g 'SI_ProSqlServer' }
    $db = & $g 'SI_Pro_DataSqlDatabase'; if (-not $db) { $db = & $g 'SI_ProSqlDatabase' }
    [bool]($srv -and $db)
}

# ------------------------------------------------------------------------------------------------------------------
#  ROWS <-> JSON
# ------------------------------------------------------------------------------------------------------------------

function ConvertTo-RAStreamJsonValue {
    param($Value, [System.Collections.Generic.HashSet[string]]$DateCols, [string]$Name)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSObject] -and $Value -isnot [System.Management.Automation.PSCustomObject]) { $Value = $Value.PSObject.BaseObject }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single] -or $Value -is [int16] -or $Value -is [byte]) { return $Value }
    if ($Value -is [datetime]) { if ($DateCols -and $Name) { [void]$DateCols.Add($Name) }; return $Value.ToString('o', $script:RAStreamInv) }
    if ($Value -is [guid]) { return $Value.ToString() }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary] -and $Value -isnot [System.Management.Automation.PSCustomObject]) {
        $simple = $true; $items = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $Value) {
            $b = $e; if ($b -is [System.Management.Automation.PSObject] -and $b -isnot [System.Management.Automation.PSCustomObject]) { $b = $b.PSObject.BaseObject }
            if ($null -eq $b -or $b -is [string] -or $b -is [bool] -or $b -is [int] -or $b -is [long] -or $b -is [double] -or $b -is [decimal]) { $items.Add($b) } else { $simple = $false; break }
        }
        if ($simple) { return , $items.ToArray() }
    }
    # anything richer: PowerShell's own JSON form, kept as it is
    [pscustomobject]@{ __SIRawJson = [string](ConvertTo-Json -InputObject $Value -Compress -Depth 20) }
}

function Test-RAStreamEmpty {
    <# PURE. Log Analytics' pack_all(true) leaves out null, '' and an empty list: the stored row does too (the data sync's DetailJson). #>
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) { return ($Value -eq '') }
    if ($Value -is [System.Collections.ICollection] -and $Value -isnot [System.Collections.IDictionary]) { return ($Value.Count -eq 0) }
    $false
}

function ConvertTo-RAStreamJson {
    <#
        PURE. One result row -> its stored JSON: every property with a legal column name (the names Log Analytics and the
        workbook keep) and a value; null, '' and empty lists left out (as the data sync's DetailJson). A [datetime] value is
        stored in round-trip form and its column is noted in -DateCols (so it is read back as a [datetime]).
        Returns @{ Json; Illegal (property names left out) }.
    #>
    param([Parameter(Mandatory)]$Row, [System.Collections.Generic.HashSet[string]]$DateCols)
    # Written as text, one value at a time: a simple value / a list of simple values through the JSON library's own
    # value writer, anything richer as PowerShell's JSON of it -- never an object graph the library has to walk.
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{')
    $first = $true
    $illegal = 0
    foreach ($p in $Row.PSObject.Properties) {
        if (-not $script:RAStreamLegalName.IsMatch($p.Name)) { $illegal++; continue }
        $v = $p.Value
        # PERFORMANCE (once per column of every row written): Test-RAStreamEmpty and the simple-value branch of
        # ConvertTo-RAStreamJsonValue inline -- a plain text, number or true/false is written as it is, an empty text is
        # left out; anything else goes through the two functions exactly as before
        if ($null -eq $v) { continue }
        if ($v -is [System.Management.Automation.PSObject] -and $v -isnot [System.Management.Automation.PSCustomObject]) { $v = $v.PSObject.BaseObject }
        if ($v -is [string]) {
            if ($v -eq '') { continue }
            $j = $v
        } elseif ($v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal] -or $v -is [single] -or $v -is [int16] -or $v -is [byte]) {
            $j = $v
        } else {
            if (Test-RAStreamEmpty $v) { continue }
            $j = ConvertTo-RAStreamJsonValue -Value $v -DateCols $DateCols -Name $p.Name
            if (Test-RAStreamEmpty $j) { continue }
        }
        $txt = if ($j -is [System.Management.Automation.PSCustomObject] -and $j.PSObject.Properties['__SIRawJson']) { [string]$j.__SIRawJson }
               elseif ($j -is [string]) { [Newtonsoft.Json.JsonConvert]::ToString([string]$j) }
               elseif ($j -is [bool]) { $(if ($j) { 'true' } else { 'false' }) }
               elseif ($j -is [System.Array]) {
                   '[' + ((@(foreach ($e in $j) { if ($null -eq $e) { 'null' } elseif ($e -is [string]) { [Newtonsoft.Json.JsonConvert]::ToString([string]$e) } elseif ($e -is [bool]) { $(if ($e) { 'true' } else { 'false' }) } else { [Newtonsoft.Json.JsonConvert]::ToString($e) } })) -join ',') + ']'
               }
               elseif ($j -is [int] -or $j -is [long] -or $j -is [double] -or $j -is [decimal] -or $j -is [single] -or $j -is [int16] -or $j -is [byte]) { [Newtonsoft.Json.JsonConvert]::ToString($j) }
               else { [string]$j }
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append([Newtonsoft.Json.JsonConvert]::ToString([string]$p.Name)).Append(':').Append($txt)
    }
    [void]$sb.Append('}')
    @{ Json = $sb.ToString(); Illegal = $illegal }
}

function ConvertFrom-RAStreamToken {
    param($Token)
    # by TYPE, never by member: a JObject is a dynamic object to PowerShell -- $token.Type reads a JSON key named "Type"
    if ($null -eq $Token) { return $null }
    if ($Token -is [Newtonsoft.Json.Linq.JObject]) {
        $o = [ordered]@{}
        foreach ($p in $Token.Properties()) { $o[$p.Name] = ConvertFrom-RAStreamToken $p.Value }
        return [pscustomobject]$o
    }
    if ($Token -is [Newtonsoft.Json.Linq.JArray]) { $a = [System.Collections.Generic.List[object]]::new(); foreach ($e in $Token.Children()) { $a.Add((ConvertFrom-RAStreamToken $e)) }; return , $a.ToArray() }
    if ($Token -is [Newtonsoft.Json.Linq.JValue]) { return $Token.ToObject([object]) }
    return $Token.ToString()
}

function ConvertFrom-RAStreamJson {
    <#
        PURE. A stored row -> the row: strings stay strings (no date guessing), the columns in -DateCols become [datetime]
        again, and -Columns (the report's columns, in order) puts every column on the row (absent = $null) -- the shape the
        report's rows had before they were stored.
    #>
    param([Parameter(Mandatory)][string]$Json, [string[]]$Columns, [System.Collections.Generic.HashSet[string]]$DateCols)
    $sr = New-Object System.IO.StringReader($Json)
    $jr = New-Object Newtonsoft.Json.JsonTextReader($sr)
    $jr.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None
    $jr.FloatParseHandling = [Newtonsoft.Json.FloatParseHandling]::Double
    try { $tok = [Newtonsoft.Json.Linq.JToken]::ReadFrom($jr) } finally { $jr.Close() }
    $vals = @{}
    foreach ($p in $tok.Properties()) {
        # a plain value is read here (what ConvertFrom-RAStreamToken does for it, without a call per column: #738)
        $pv = $p.Value
        if ($pv -is [Newtonsoft.Json.Linq.JValue]) { $v = $pv.ToObject([object]) } else { $v = ConvertFrom-RAStreamToken $pv }
        if ($DateCols -and $DateCols.Contains($p.Name) -and $v -is [string]) {
            $dt = [datetime]::MinValue
            if ([datetime]::TryParse($v, $script:RAStreamInv, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) { $v = $dt }
        }
        $vals[$p.Name] = $v
    }
    $o = [ordered]@{}
    if ($Columns -and @($Columns).Count -gt 0) {
        foreach ($c in $Columns) { if ($vals.ContainsKey($c)) { $o[$c] = $vals[$c]; $vals.Remove($c) } else { $o[$c] = $null } }
    }
    foreach ($p in $tok.Properties()) { if ($vals.ContainsKey($p.Name)) { $o[$p.Name] = $vals[$p.Name] } }
    [pscustomobject]$o
}

# ------------------------------------------------------------------------------------------------------------------
#  KEYS -- the same rules the in-memory path applies to the whole report
# ------------------------------------------------------------------------------------------------------------------

function Get-RAStreamHash16 {
    <# PURE. The first 16 bytes of SHA-256 over the UTF-8 text, as 32 hex characters. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) } finally { $sha.Dispose() }
    ([System.BitConverter]::ToString($b, 0, 16) -replace '-', '')
}

function Get-RARowDedupKey {
    <#
        PURE. The key Calculate-RiskScore de-duplicates a non-Summary report's rows on (RA-RiskScore.ps1: every dimension
        column, lower-cased) -- '' when the row has neither a configuration name nor id (such rows are always kept).
        Across buckets the FIRST row written with a key is kept (Complete-RAStreamReport), as the whole-report pass kept the first.
    #>
    param([Parameter(Mandatory)]$Row, [string]$ConfigurationIdInputName = 'ConfigurationId')
    $cfg = if ($ConfigurationIdInputName) { $ConfigurationIdInputName } else { 'ConfigurationId' }
    # (each column read directly -- no script block call per column; the same text, '' when absent)
    $rp = $Row.PSObject.Properties
    $p = $rp['ConfigurationName']; $cn = if ($p) { [string]$p.Value } else { '' }
    $p = $rp[$cfg]; $cv = if ($p) { [string]$p.Value } else { '' }
    if ([string]::IsNullOrWhiteSpace($cn) -and [string]::IsNullOrWhiteSpace($cv)) { return '' }
    $parts = [System.Collections.Generic.List[string]]::new([int]($script:RAStreamDedupCols.Count))
    foreach ($c in $script:RAStreamDedupCols) {
        $n = if ($c -eq '<cfg>') { $cfg } else { $c }
        $p = $rp[$n]
        $parts.Add($(if ($p) { [string]$p.Value } else { '' }))
    }
    # the finding's target (#690 (3)): appended only when the row carries one -- a row without one keeps its key text
    # (PERFORMANCE, once per row written: three direct lookups, nothing built unless the row has a target)
    $t1 = $rp['TargetAssetId']; $t3 = $rp['LinkedAzureResourceId']
    if (($t1 -and [string]$t1.Value) -or ($t3 -and [string]$t3.Value)) {
        $tparts = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $script:RAStreamDedupTargetCols) {
            $p = $rp[$c]
            if ($p -and $null -ne $p.Value -and ([string]$p.Value) -ne '') { $tparts.Add(('{0}={1}' -f $c, [string]$p.Value)) }
        }
        $parts.Add(('target:' + ($tparts -join ';')))
    }
    (($parts -join '|').ToLowerInvariant())
}

function Get-RAStreamCiIdsOfRow {
    <# PURE. The ids a row could be matched to its CI by (Find-RACiForRow's columns), normalised as the CI index keys them. #>
    param([Parameter(Mandatory)]$Row)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($col in 'si_ci_id', 'SI_CorrelationId', 'SI_AssetId', 'MdeDeviceId', 'DeviceId', 'AadDeviceId', 'AzureResourceId', 'ResourceId', 'EntraObjectId', 'EntraAccountObjectId', 'AccountObjectId', 'ObjectId', 'EgNodeId', 'NodeId', 'PrimaryEntityId', 'AssetId') {
        $p = $Row.PSObject.Properties[$col]
        if (-not $p -or -not $p.Value) { continue }
        $k = ConvertTo-RACiIdKey ([string]$p.Value)
        if ($k) { $out.Add($k) }
    }
    $out.ToArray()
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STATEMENTS
# ------------------------------------------------------------------------------------------------------------------

function Get-RAStreamBeginSql {
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($Grain -eq 'Summary') {
        return @'
SET XACT_ABORT ON;
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
BEGIN TRAN;
DELETE FROM sidata.SummaryAsset WHERE CollectionTime = @t;
DELETE FROM sidata.SummaryRow WHERE CollectionTime = @t;
DELETE FROM sidata.SummaryLoad WHERE CollectionTime = @t;
DELETE FROM sidata.RaStage WHERE RunKey = @RunKey;
DELETE FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = 'Summary';
INSERT sidata.SummaryLoad (CollectionTime, RunId, Status, SolutionVersion, Source) VALUES (@t, NULLIF(@RunId, ''), 'Loading', NULLIF(@SolutionVersion, ''), 'risk-analysis');
COMMIT;
SELECT 0;
'@
    }
    @'
SET XACT_ABORT ON;
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
IF EXISTS (SELECT 1 FROM sidata.Collection WHERE Kind = 'Detailed' AND CollectionTime = @t)
    THROW 50001, 'a collection with this time already exists', 1;
DELETE FROM sidata.RaStage WHERE RunKey = @RunKey;
DELETE FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = 'Detailed';
INSERT sidata.Collection (CollectionTime, Kind, RunId, Status, SolutionVersion, Source)
OUTPUT inserted.CollectionId
VALUES (@t, 'Detailed', NULLIF(@RunId, ''), 'Loading', NULLIF(@SolutionVersion, ''), 'risk-analysis');
'@
}

function Get-RAStreamDeleteBucketSql {
    <# One bucket's rows of one report (-Bucket '*' = the whole report), so a retried bucket never doubles. #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($Grain -eq 'Summary') {
        return @'
SET XACT_ABORT ON;
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126); DECLARE @r int = CONVERT(int, @Report);
BEGIN TRAN;
DELETE a FROM sidata.SummaryAsset a JOIN sidata.SummaryRow s ON s.CollectionTime = a.CollectionTime AND s.RowNo = a.RowNo
WHERE s.CollectionTime = @t AND s.RaReport = @r AND (@Bucket = '*' OR s.RaBucket = @Bucket);
DELETE FROM sidata.SummaryRow WHERE CollectionTime = @t AND RaReport = @r AND (@Bucket = '*' OR RaBucket = @Bucket);
DECLARE @n int = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
    }
    # PERFORMANCE (live 2026-10-16: minutes per slice, with no line, once a report had stored hundreds of thousands of
    # rows): "RaSeq IS NOT NULL" lets the database use the index made for exactly this (IX_Finding_RaBucket, which holds
    # only the rows Risk Analysis wrote) instead of reading every stored row of the run, JSON included, for every slice.
    # The same rows are removed: every row Risk Analysis writes carries its RaSeq (Get-RAStreamInsertFindingSql), and no
    # other writer sets RaReport.
    @'
DELETE FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL AND (@Bucket = '*' OR RaBucket = @Bucket);
SELECT @@ROWCOUNT;
'@
}

function Get-RAStreamInsertFindingSql {
    # The data sync's finding insert (Get-SIDataInsertFindingSql, same mapping) plus Risk Analysis' own columns.
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, DetailJson,
                       ExemptionId, ExemptedUntil, ExemptionRequestId,
                       RaReport, RaBucket, RaSeq, RaDedup, RaSort, RaInView, RaTraceHash, RaTraceKey, RaTraceSuffixed, RaFindingKey, RaAssetId, RaAssetTier)
SELECT CONVERT(int, @CollectionId), NULLIF(j.AssetKey, ''), NULLIF(j.AssetName, ''), NULLIF(j.ReportName, ''), NULLIF(j.SecurityDomain, ''),
       NULLIF(j.ConfigurationId, ''), NULLIF(j.Cve, ''), NULLIF(j.Title, ''), NULLIF(j.Severity, ''), j.Tier, j.RiskScore, j.DetailJson,
       j.ExemptionId, CONVERT(datetime2(0), NULLIF(j.ExemptedUntil, ''), 126), j.ExemptionRequestId,
       j.RaReport, j.RaBucket, j.RaSeq, CONVERT(binary(16), NULLIF(j.RaDedup, ''), 2), j.RaSort, j.RaInView,
       CONVERT(binary(16), NULLIF(j.RaTraceHash, ''), 2), NULLIF(j.RaTraceKey, ''), j.RaTraceSuffixed, NULLIF(j.RaFindingKey, ''), NULLIF(j.RaAssetId, ''), j.RaAssetTier
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), AssetName nvarchar(400), ReportName nvarchar(256), SecurityDomain nvarchar(128),
                        ConfigurationId nvarchar(256), Cve nvarchar(100), Title nvarchar(1000), Severity nvarchar(30), Tier tinyint,
                        RiskScore float, DetailJson nvarchar(max), ExemptionId bigint, ExemptedUntil nvarchar(40), ExemptionRequestId bigint,
                        RaReport int, RaBucket nvarchar(64), RaSeq bigint, RaDedup varchar(32), RaSort float, RaInView bit,
                        RaTraceHash varchar(32), RaTraceKey nvarchar(450), RaTraceSuffixed bit, RaFindingKey nvarchar(900), RaAssetId nvarchar(400), RaAssetTier tinyint) j;
DECLARE @n int = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
}

function Get-RAStreamInsertSummaryRowSql {
    # The data sync's Summary row insert (Get-SIDataSummaryInsertRowSql, same mapping) plus Risk Analysis' own columns.
    $base = Get-SIDataSummaryInsertRowSql
    $base = $base.Replace('FixRemediation, FixRecommendedUpdate, FixRecommendedUpdateId, AffectedSoftware, ConfigurationDescription, RiskDescription)',
        'FixRemediation, FixRecommendedUpdate, FixRecommendedUpdateId, AffectedSoftware, ConfigurationDescription, RiskDescription, RaReport, RaBucket, RaDedup, RaSort, RaInView, RaTraceHash, RaTraceKey, RaTraceSuffixed, RaTrendSeverity, RaTrendTier, RaTrendDomain, RaTrendScore, RaExempt, RaTrendAssetIds, RowJson)')
    $base = [regex]::Replace($base, 'j\.ConfigurationDescription, j\.RiskDescription\s*\r?\nFROM OPENJSON', "j.ConfigurationDescription, j.RiskDescription, j.RaReport, j.RaBucket, CONVERT(binary(16), NULLIF(j.RaDedup, ''), 2), j.RaSort, j.RaInView, CONVERT(binary(16), NULLIF(j.RaTraceHash, ''), 2), NULLIF(j.RaTraceKey, ''), j.RaTraceSuffixed, j.RaTrendSeverity, j.RaTrendTier, j.RaTrendDomain, j.RaTrendScore, j.RaExempt, j.RaTrendAssetIds, j.RowJson`nFROM OPENJSON")
    $base = $base.Replace('ConfigurationDescription nvarchar(4000), RiskDescription nvarchar(4000)) j;',
        'ConfigurationDescription nvarchar(4000), RiskDescription nvarchar(4000), RaReport int, RaBucket nvarchar(64), RaDedup varchar(32), RaSort float, RaInView bit, RaTraceHash varchar(32), RaTraceKey nvarchar(450), RaTraceSuffixed bit, RaTrendSeverity nvarchar(256), RaTrendTier nvarchar(256), RaTrendDomain nvarchar(256), RaTrendScore float, RaExempt bit, RaTrendAssetIds nvarchar(max), RowJson nvarchar(max)) j;')
    "SET XACT_ABORT ON;`nBEGIN TRAN;`n" + $base.Replace('SELECT @@ROWCOUNT;', "DECLARE @n int = @@ROWCOUNT;`nCOMMIT;`nSELECT @n;")
}

function Get-RAStreamInsertStageSql {
    @'
INSERT sidata.RaStage (RunKey, RaReport, RaBucket, RaSeq, GroupHash, RowJson)
SELECT @RunKey, j.RaReport, j.RaBucket, j.RaSeq, CONVERT(binary(16), j.GroupHash, 2), j.RowJson
FROM OPENJSON(@j) WITH (RaReport int, RaBucket nvarchar(64), RaSeq bigint, GroupHash varchar(32), RowJson nvarchar(max)) j;
SELECT @@ROWCOUNT;
'@
}

function Get-RAStreamDeleteStageSql {
    "DELETE FROM sidata.RaStage WHERE RunKey = @RunKey AND RaReport = CONVERT(int, @Report) AND (@Bucket = '*' OR RaBucket = @Bucket); SELECT @@ROWCOUNT;"
}

function Get-RAStreamStageGroupsSql {
    <# The staged report's groups, in the order their first row was written, with their size -- what the pages are cut from. #>
    @'
SELECT g.G0, g.Chars FROM (
    SELECT MIN(RaSeq) AS G0, SUM(CAST(LEN(RowJson) AS bigint)) AS Chars
    FROM sidata.RaStage WHERE RunKey = @RunKey AND RaReport = CONVERT(int, @Report) GROUP BY GroupHash) g
ORDER BY g.G0;
'@
}

function Get-RAStreamStagePageSql {
    <# The rows of the groups whose first row is in (@From, @To], group by group, each in its written order. #>
    @'
WITH g AS (SELECT GroupHash, MIN(RaSeq) AS G0 FROM sidata.RaStage WHERE RunKey = @RunKey AND RaReport = CONVERT(int, @Report) GROUP BY GroupHash)
SELECT s.RowJson FROM sidata.RaStage s JOIN g ON g.GroupHash = s.GroupHash
WHERE s.RunKey = @RunKey AND s.RaReport = CONVERT(int, @Report) AND g.G0 > CONVERT(bigint, @From) AND g.G0 <= CONVERT(bigint, @To)
ORDER BY g.G0, s.RaSeq;
'@
}

function Get-RAStreamDedupSql {
    <# A finding two buckets both returned is kept ONCE -- the first written (the whole-report pass kept the first too). #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($Grain -eq 'Summary') {
        return @'
SET XACT_ABORT ON;
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126); DECLARE @r int = CONVERT(int, @Report);
DECLARE @d TABLE (RowNo int PRIMARY KEY);
INSERT @d SELECT f.RowNo FROM sidata.SummaryRow f
WHERE f.CollectionTime = @t AND f.RaReport = @r AND f.RaDedup IS NOT NULL
  AND EXISTS (SELECT 1 FROM sidata.SummaryRow e WHERE e.CollectionTime = @t AND e.RaReport = @r AND e.RaDedup = f.RaDedup AND e.RowNo < f.RowNo);
BEGIN TRAN;
DELETE a FROM sidata.SummaryAsset a JOIN @d d ON d.RowNo = a.RowNo WHERE a.CollectionTime = @t;
DELETE s FROM sidata.SummaryRow s JOIN @d d ON d.RowNo = s.RowNo WHERE s.CollectionTime = @t;
DECLARE @n int = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
    }
    @'
DECLARE @c int = CONVERT(int, @CollectionId); DECLARE @r int = CONVERT(int, @Report);
DELETE f FROM sidata.Finding f
WHERE f.CollectionId = @c AND f.RaReport = @r AND f.RaDedup IS NOT NULL
  AND EXISTS (SELECT 1 FROM sidata.Finding e WHERE e.CollectionId = @c AND e.RaReport = @r AND e.RaDedup = f.RaDedup AND e.RaSeq < f.RaSeq);
SELECT @@ROWCOUNT;
'@
}

function Get-RAStreamDedupPageSql {
    <#
        ONE PAGE of "a finding two buckets both returned is kept ONCE -- the first written" (the rule of Get-RAStreamDedupSql,
        which did it in ONE statement over the whole report). Live 2026-10-21, the largest tenant: that one statement over a
        report of 964,276 rows timed out three times at the database's command timeout, the report failed and its rows could
        not be removed either -- the run ended failed. Now the report is walked in pages through the index made for this
        (IX_Finding_RaDedup / IX_SummaryRow_RaDedup: the run, the report, the key, the write order), each page its own short
        statement:
          * the page = the next @Page keys after the cursor (@After, the last key of the page before; '' = the start), and
            EVERY row of the last key -- a key is never split over two pages, so its first row is always seen with the rest;
          * in the page, a row is removed when a row with the SAME key was written BEFORE it (RANK by the write order > 1 --
            exactly "a row with the same key and a lower RaSeq exists", the old rule; rows without a write number take no
            part, as before);
          * answers Removed (rows removed), Seen (keys read for the page) and LastKey (the page's last key, hex; the cursor).
        The page size is the caller's (Invoke-RAStreamDedup): measured, halved on a timeout, grown when fast -- no fixed size.
        The same rows are removed as by the whole statement; the first written row is kept.
    #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($Grain -eq 'Summary') {
        return @'
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126); DECLARE @r int = CONVERT(int, @Report);
DECLARE @a binary(16) = CONVERT(binary(16), NULLIF(@After, N''), 2);
DECLARE @k binary(16), @seen bigint;
SELECT @seen = COUNT_BIG(*), @k = MAX(p.RaDedup) FROM (
    SELECT TOP (CONVERT(bigint, @Page)) RaDedup FROM sidata.SummaryRow
    WHERE CollectionTime = @t AND RaReport = @r AND RaDedup IS NOT NULL AND (@a IS NULL OR RaDedup > @a)
    ORDER BY RaDedup) p;
DECLARE @d TABLE (RowNo int PRIMARY KEY);
DECLARE @n int = 0;
IF @k IS NOT NULL
BEGIN
    INSERT @d (RowNo) SELECT x.RowNo FROM (
        SELECT RowNo, RANK() OVER (PARTITION BY RaDedup ORDER BY RowNo) AS Rk FROM sidata.SummaryRow
        WHERE CollectionTime = @t AND RaReport = @r AND RaDedup IS NOT NULL AND (@a IS NULL OR RaDedup > @a) AND RaDedup <= @k) x
    WHERE x.Rk > 1;
    BEGIN TRAN;
    DELETE a FROM sidata.SummaryAsset a JOIN @d d ON d.RowNo = a.RowNo WHERE a.CollectionTime = @t;
    DELETE s FROM sidata.SummaryRow s JOIN @d d ON d.RowNo = s.RowNo WHERE s.CollectionTime = @t;
    SET @n = @@ROWCOUNT;
    COMMIT;
END
SELECT @n AS Removed, ISNULL(@seen, 0) AS Seen, ISNULL(CONVERT(varchar(32), @k, 2), '') AS LastKey;
'@
    }
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @c int = CONVERT(int, @CollectionId); DECLARE @r int = CONVERT(int, @Report);
DECLARE @a binary(16) = CONVERT(binary(16), NULLIF(@After, N''), 2);
DECLARE @k binary(16), @seen bigint;
SELECT @seen = COUNT_BIG(*), @k = MAX(p.RaDedup) FROM (
    SELECT TOP (CONVERT(bigint, @Page)) RaDedup FROM sidata.Finding
    WHERE CollectionId = @c AND RaReport = @r AND RaDedup IS NOT NULL AND (@a IS NULL OR RaDedup > @a)
    ORDER BY RaDedup) p;
DECLARE @n int = 0;
IF @k IS NOT NULL
BEGIN
    DELETE f FROM sidata.Finding f
    JOIN (SELECT FindingId, RANK() OVER (PARTITION BY RaDedup ORDER BY RaSeq) AS Rk FROM sidata.Finding
          WHERE CollectionId = @c AND RaReport = @r AND RaDedup IS NOT NULL AND RaSeq IS NOT NULL AND (@a IS NULL OR RaDedup > @a) AND RaDedup <= @k) x
      ON x.FindingId = f.FindingId AND x.Rk > 1
    WHERE f.CollectionId = @c;
    SET @n = @@ROWCOUNT;
END
SELECT @n AS Removed, ISNULL(@seen, 0) AS Seen, ISNULL(CONVERT(varchar(32), @k, 2), '') AS LastKey;
'@
}

function Get-RAStreamDeleteReportBatchSql {
    <#
        ONE BATCH of "the rows of one report (or of one of its slices: -Bucket; '*' = the whole report)" -- the batched form
        of Get-RAStreamDeleteBucketSql, for the removals that can be as large as a whole report: a report that failed or runs
        again (Clear-RAStreamReport) and a report whose item did not deliver. Live 2026-10-21, the largest tenant: the one
        statement over a failed report's 964,276 rows timed out, the run could not take the report back and ended failed.
        @Batch rows per statement (sized by the caller, Remove-RAStreamRowsBatched); answers the rows removed. The same rows
        as the one statement (the same condition, the same index: IX_Finding_RaBucket). Summary: a batch of the report's
        rows with their assets, in one transaction.
    #>
    param([ValidateSet('Detailed', 'Summary', 'Stage', 'Seq')][string]$Grain)
    switch ($Grain) {
        'Summary' {
            return @'
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126); DECLARE @r int = CONVERT(int, @Report);
DECLARE @d TABLE (RowNo int PRIMARY KEY);
INSERT @d (RowNo) SELECT TOP (CONVERT(int, @Batch)) RowNo FROM sidata.SummaryRow WHERE CollectionTime = @t AND RaReport = @r AND (@Bucket = '*' OR RaBucket = @Bucket);
BEGIN TRAN;
DELETE a FROM sidata.SummaryAsset a JOIN @d d ON d.RowNo = a.RowNo WHERE a.CollectionTime = @t;
DELETE s FROM sidata.SummaryRow s JOIN @d d ON d.RowNo = s.RowNo WHERE s.CollectionTime = @t;
DECLARE @n int = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
        }
        'Stage' { return "DELETE TOP (CONVERT(int, @Batch)) FROM sidata.RaStage WHERE RunKey = @RunKey AND RaReport = CONVERT(int, @Report) AND (@Bucket = '*' OR RaBucket = @Bucket); SELECT @@ROWCOUNT;" }
        # #831 B: one part of a split report -- its write-number range [@From, @To)
        'Seq' { return 'DELETE TOP (CONVERT(int, @Batch)) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq >= CONVERT(bigint, @From) AND RaSeq < CONVERT(bigint, @To); SELECT @@ROWCOUNT;' }
    }
    "DELETE TOP (CONVERT(int, @Batch)) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL AND (@Bucket = '*' OR RaBucket = @Bucket); SELECT @@ROWCOUNT;"
}

function Get-RAStreamTraceCandidatesSql {
    <# The rows whose trace name another asset of the SAME report shares, that did not get the asset id at the end yet. #>
    # #741 (1) PERFORMANCE (live 2026-10-16, a school install: "Timeout expired" on ExecuteReader, five reports failed): the
    # statement had no index to use, so the database read the trace columns of every row of the report through the
    # clustered index (JSON included), twice. Now it carries the condition of the index made for it (IX_Finding_RaTrace /
    # IX_SummaryRow_RaTrace: the run, the report, the trace hash, the key and the "suffixed" flag; WHERE RaSeq / RaReport IS
    # NOT NULL -- every row Risk Analysis writes has them, no other writer sets RaReport), the shared hashes are found in
    # that index alone (two different keys on one hash = MIN <> MAX, the same test as COUNT(DISTINCT) > 1 under the same
    # collation, without a sort), and only the rows that really share a name are read whole. The same rows as before.
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    $t = 'sidata.Finding'; $run = 'CollectionId = CONVERT(int, @CollectionId)'; $cond = 'RaSeq IS NOT NULL'; $id = 'f.FindingId'; $j = 'f.DetailJson'
    if ($Grain -eq 'Summary') { $t = 'sidata.SummaryRow'; $run = 'CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126)'; $cond = 'RaReport IS NOT NULL'; $id = 'f.RowNo'; $j = 'f.RowJson' }
    @"
WITH s AS (SELECT RaTraceHash FROM $t
           WHERE $run AND RaReport = CONVERT(int, @Report) AND $cond AND RaTraceKey IS NOT NULL
           GROUP BY RaTraceHash HAVING MIN(RaTraceKey) <> MAX(RaTraceKey))
SELECT $id AS Id, $j AS Json FROM $t f JOIN s ON s.RaTraceHash = f.RaTraceHash
WHERE f.$run AND f.RaReport = CONVERT(int, @Report) AND f.$cond AND f.RaTraceSuffixed = 0 AND f.RaTraceKey IS NOT NULL;
"@
}

function Get-RAStreamTraceUpdateSql {
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($Grain -eq 'Summary') {
        return @'
UPDATE f SET RowJson = JSON_MODIFY(JSON_MODIFY(f.RowJson, '$.TraceName', j.N), '$.TraceID', j.I), RaTraceSuffixed = 1
FROM sidata.SummaryRow f JOIN OPENJSON(@j) WITH (Id int, N nvarchar(4000), I nvarchar(32)) j ON f.RowNo = j.Id
WHERE f.CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126);
SELECT @@ROWCOUNT;
'@
    }
    @'
UPDATE f SET DetailJson = JSON_MODIFY(JSON_MODIFY(f.DetailJson, '$.TraceName', j.N), '$.TraceID', j.I), RaTraceSuffixed = 1
FROM sidata.Finding f JOIN OPENJSON(@j) WITH (Id bigint, N nvarchar(4000), I nvarchar(32)) j ON f.FindingId = j.Id
WHERE f.CollectionId = CONVERT(int, @CollectionId);
SELECT @@ROWCOUNT;
'@
}

function Get-RAStreamCountSql {
    <# How many rows the run holds -- all of them, the workbook / mail view, or one report. #>
    # -Held (#877): the ordinals of the reports held back this run -- their rows are never counted as the run's result
    param([ValidateSet('Detailed', 'Summary')][string]$Grain, [ValidateSet('All', 'View', 'Report')][string]$Source = 'All', [int[]]$Held = @())
    $w = if ($Grain -eq 'Summary') { 'FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND RaReport IS NOT NULL' } else { 'FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaSeq IS NOT NULL' }
    if ($Source -eq 'View') { $w += ' AND RaInView = 1' }
    if ($Source -eq 'Report') { $w += ' AND RaReport = CONVERT(int, @Report)' }
    $w += Get-RAStreamHeldFilter -Held $Held
    "SELECT COUNT_BIG(*) $w;"
}

function Get-RAStreamHeldFilter {
    <# PURE (#877). ' AND RaReport NOT IN (<ordinals>)' for the reports held back this run ('' when none) -- whole numbers only. #>
    param([int[]]$Held = @())
    $o = @(@($Held) | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
    if (-not $o.Count) { return '' }
    ' AND RaReport NOT IN ({0})' -f (($o | ForEach-Object { [string][int]$_ }) -join ', ')
}

function Get-RAStreamPageSql {
    <#
        One page of the run's rows in the FINAL ORDER: the sort score (highest first), then the order they were written --
        the report order, then each report's buckets in order. Keyset paging: after (@Sort, @Seq).
        -Source FindingKey: grouped by the SI finding key (SI_Finding_CL), rows without one left out.
    #>
    # -After (#738): a page AFTER the first -- the keyset as a range the order index can SEEK to (RaSort <= @Sort, then
    # the exact tie rule), instead of "@First = '1' OR ..." which no index can seek and is read from the start of the
    # collection for every page. The same rows in the same order: the range only states what the tie rule implies.
    # -Held (#877): the ordinals of the reports held back this run -- their rows are never read as the run's result
    param([ValidateSet('Detailed', 'Summary')][string]$Grain, [ValidateSet('All', 'View', 'FindingKey')][string]$Source = 'All', [switch]$After, [int[]]$Held = @())
    $hf = Get-RAStreamHeldFilter -Held $Held
    if ($Grain -eq 'Summary') {
        $view = if ($Source -eq 'View') { ' AND RaInView = 1' } else { '' }
        $view += $hf
        $key = if ($After) { "`n  AND RaSort <= CONVERT(float, @Sort) AND (RaSort < CONVERT(float, @Sort) OR RowNo > CONVERT(bigint, @Seq))" } else { "`n  AND (@First = '1' OR RaSort < CONVERT(float, @Sort) OR (RaSort = CONVERT(float, @Sort) AND RowNo > CONVERT(bigint, @Seq)))" }
        return @"
SELECT TOP (CONVERT(int, @Take)) RowNo AS Seq, RaSort, RaReport, RowJson AS Json FROM sidata.SummaryRow
WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND RaReport IS NOT NULL$view$key
ORDER BY RaSort DESC, RowNo;
"@
    }
    if ($Source -eq 'FindingKey') {
        $key = if ($After) { "`n  AND RaFindingKey >= @FKey AND (RaFindingKey > @FKey OR RaSeq > CONVERT(bigint, @Seq))" } else { "`n  AND (@First = '1' OR RaFindingKey > @FKey OR (RaFindingKey = @FKey AND RaSeq > CONVERT(bigint, @Seq)))" }
        return @"
SELECT TOP (CONVERT(int, @Take)) RaSeq AS Seq, RaFindingKey AS FKey, RaReport, DetailJson AS Json FROM sidata.Finding
WHERE CollectionId = CONVERT(int, @CollectionId) AND RaSeq IS NOT NULL AND RaFindingKey IS NOT NULL$hf$key
ORDER BY RaFindingKey, RaSeq;
"@
    }
    $view = if ($Source -eq 'View') { ' AND RaInView = 1' } else { '' }
    $view += $hf
    $key = if ($After) { "`n  AND RaSort <= CONVERT(float, @Sort) AND (RaSort < CONVERT(float, @Sort) OR RaSeq > CONVERT(bigint, @Seq))" } else { "`n  AND (@First = '1' OR RaSort < CONVERT(float, @Sort) OR (RaSort = CONVERT(float, @Sort) AND RaSeq > CONVERT(bigint, @Seq)))" }
    @"
SELECT TOP (CONVERT(int, @Take)) RaSeq AS Seq, RaSort, RaReport, DetailJson AS Json FROM sidata.Finding
WHERE CollectionId = CONVERT(int, @CollectionId) AND RaSeq IS NOT NULL$view$key
ORDER BY RaSort DESC, RaSeq;
"@
}

function Get-RAReportQueryFingerprint {
    <#
        PURE. #690 (34) -- the fingerprint of what a report ASKS: SHA-256 (64 hex, lower case) over its query as authored
        (before the run's substitutions -- exclusions, hand-off lists, scalars -- so a run-time value never reads as a change)
        with line endings and runs of white space made one, plus its tier and severity scope. A query that was corrected gets a
        different fingerprint, so a finding that leaves it closes as 'report changed', never as 'remediated'. Over-sensitive
        (a comment edit counts) is the safe direction: it never claims a fix. Empty query = '' (not recorded).
    #>
    # #902 (5): -AcceptedEmpty -- the source tables an Admin accepted as empty for good FOR THIS REPORT (cfg.RaSourceAccept).
    # Only when there are any is '|accepted-empty=<tables>' added: the findings the report no longer lists then close as
    # 'report changed', never as 'remediated'. With none the text -- and so every other report's fingerprint -- is exactly
    # as before.
    param([AllowEmptyString()][string]$Query = '', $TierScope = $null, $SeverityScope = $null, [AllowEmptyCollection()][string[]]$AcceptedEmpty = @())
    if (-not ([string]$Query).Trim()) { return '' }
    $norm = [regex]::Replace(([string]$Query).Trim(), '\s+', ' ')
    $scope = { param($v) if ($null -eq $v) { '' } else { (@($v) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) -join ',' } }
    $text = '{0}|tier={1}|severity={2}' -f $norm, (& $scope $TierScope), (& $scope $SeverityScope)
    $acc = @($AcceptedEmpty | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique)
    if ($acc.Count) { $text += ('|accepted-empty={0}' -f ($acc -join ',')) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

# =====================================================================================================================
#  #692 A CHANGE OF STRUCTURE ONLY IS NOT A CHANGED REPORT. The owner accepted ONE fingerprint change (2026-10-19: "let
#  every report carry the generated output block (one-time fingerprint change), plus the bucket filter on the two Defender
#  recommendation reports (also a one-time fingerprint change)" -> "Yes, both, in one release"). What such a change added
#  to a query is DECLARED in data-model/report-fingerprint-carry.locked.json; the fingerprint the report had BEFORE it
#  (the query with that text taken out again) is stored with the verdict as its CARRY (sidata.RaReportStatus
#  QueryHashCarry). The finding lifecycle and the close loop read a report whose new fingerprint carries the old one as
#  UNCHANGED -- the key of the report moves, its findings keep FirstDetected and their history, and nothing closes as
#  'report changed' or 'remediated' because of it (the #464 alias carry, for the report's key instead of the finding's).
# =====================================================================================================================
$script:RAFingerprintCarryDoc = $null

function Get-RAFingerprintCarry {
    <#
        The declared structure-only changes (data-model/report-fingerprint-carry.locked.json), parsed once. -Path: another
        file (tests). Never throws: a file that cannot be read declares nothing (every fingerprint as before, no carry).
    #>
    param([string]$Path = '')
    if (-not $Path -and $null -ne $script:RAFingerprintCarryDoc) { return $script:RAFingerprintCarryDoc }
    $doc = [pscustomobject]@{ changes = @() }
    try {
        $p = $Path
        if (-not $p) { $p = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'data-model', 'report-fingerprint-carry.locked.json') }
        if ([System.IO.File]::Exists($p)) { $doc = ([System.IO.File]::ReadAllText($p)).TrimStart([char]0xFEFF) | ConvertFrom-Json }
    } catch { $doc = [pscustomobject]@{ changes = @() } }
    if (-not $Path) { $script:RAFingerprintCarryDoc = $doc }
    $doc
}

function Remove-RAFingerprintCarryText {
    <#
        PURE. The query as it was before a declared change: -Query (white space already made one); -Blocks (block names: every
        //__<name>_BEGIN__ ... //__<name>_END__ is taken out); -Restore (pairs @{ now; was }: the exact text the change wrote,
        white space made one, put back as it was). White space made one again after.
    #>
    param([AllowEmptyString()][string]$Query = '', [AllowEmptyCollection()][string[]]$Blocks = @(), [AllowEmptyCollection()][object[]]$Restore = @())
    $q = [string]$Query
    foreach ($b in @($Blocks | Where-Object { "$_".Trim() })) {
        $n = ([string]$b).Trim()
        $q = [regex]::Replace($q, [regex]::Escape('//__' + $n + '_BEGIN__') + '.*?' + [regex]::Escape('//__' + $n + '_END__'), ' ')
        $q = [regex]::Replace($q.Trim(), '\s+', ' ')
    }
    foreach ($r in @($Restore | Where-Object { $null -ne $_ })) {
        $now = ''; $was = ''
        if ($r -is [System.Collections.IDictionary]) { $now = [string]$r['now']; $was = [string]$r['was'] } else { $now = [string]$r.now; $was = [string]$r.was }
        $now = [regex]::Replace($now.Trim(), '\s+', ' '); $was = [regex]::Replace($was.Trim(), '\s+', ' ')
        if ($now) { $q = $q.Replace($now, $was) }
    }
    [regex]::Replace($q.Trim(), '\s+', ' ')
}

function Get-RAReportQueryFingerprintCarry {
    <#
        PURE (given -Carry). #692 -- the fingerprints a report had BEFORE each declared structure-only change: per change of
        -Carry (Get-RAFingerprintCarry), the query as authored with what that change wrote undone (its removeBlocks for every
        report, plus the report's own removeBlocks / restoreText), fingerprinted the same way (Get-RAReportQueryFingerprint,
        same tier / severity scope). Only a fingerprint that differs from the report's own is returned (a query the change
        did not touch has no carry). Distinct, in the file's order. Empty query or no declared change = @().
    #>
    param([AllowEmptyString()][string]$Query = '', [string]$ReportName = '', $TierScope = $null, $SeverityScope = $null, $Carry = $null)
    if (-not ([string]$Query).Trim()) { return @() }
    if ($null -eq $Carry) { $Carry = Get-RAFingerprintCarry }
    $now = Get-RAReportQueryFingerprint -Query $Query -TierScope $TierScope -SeverityScope $SeverityScope
    $norm = [regex]::Replace(([string]$Query).Trim(), '\s+', ' ')
    $out = New-Object System.Collections.Generic.List[string]
    # #880 THE CHANGES ARE CUMULATIVE: the fingerprint a report had before change i is its query with change i AND every later
    # change undone (newest first) -- a report that changed twice (the #692 block, then the #880 slice filter on the CVE
    # reports) carries both the fingerprint it had before #692 and the one it had between the two
    $steps = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Carry.changes | Where-Object { $_ })) {
        $blocks = New-Object System.Collections.Generic.List[string]; $restore = New-Object System.Collections.Generic.List[object]
        if ($c.PSObject.Properties['removeBlocks']) { foreach ($b in @($c.removeBlocks)) { if ("$b") { $blocks.Add([string]$b) } } }
        if ($ReportName -and $c.PSObject.Properties['reports'] -and $c.reports -and $c.reports.PSObject.Properties[$ReportName]) {
            $r = $c.reports.PSObject.Properties[$ReportName].Value
            if ($r.PSObject.Properties['removeBlocks']) { foreach ($b in @($r.removeBlocks)) { if ("$b") { $blocks.Add([string]$b) } } }
            if ($r.PSObject.Properties['restoreText']) { foreach ($t in @($r.restoreText)) { if ($null -ne $t) { $restore.Add($t) } } }
        }
        $steps.Add([pscustomobject]@{ Blocks = $blocks.ToArray(); Restore = $restore.ToArray() })
    }
    for ($i = 0; $i -lt $steps.Count; $i++) {
        if (@($steps[$i].Blocks).Count -eq 0 -and @($steps[$i].Restore).Count -eq 0) { continue }
        $before = $norm
        for ($k = $steps.Count - 1; $k -ge $i; $k--) {
            if (@($steps[$k].Blocks).Count -eq 0 -and @($steps[$k].Restore).Count -eq 0) { continue }
            $before = Remove-RAFingerprintCarryText -Query $before -Blocks @($steps[$k].Blocks) -Restore @($steps[$k].Restore)
        }
        $h = Get-RAReportQueryFingerprint -Query $before -TierScope $TierScope -SeverityScope $SeverityScope
        if ($h -and $h -ne $now -and -not $out.Contains($h)) { $out.Add($h) }
    }
    # plain output, one fingerprint per item (callers write @(...)): a ", array" return nests inside a caller's @()
    $out.ToArray()
}

function Test-RAReportFingerprintCarried {
    <#
        PURE. #692 -- does a report's fingerprint now (-Now, with its carry -Carry: a ';' / ',' list or an array) stand for the
        one it had before (-Was)? Same fingerprint, or -Was in the carry = $true (the report did not change what it asks).
        Unknown (-Now or -Was empty) = $true: never a change that cannot be shown.
    #>
    param([AllowEmptyString()][string]$Now = '', [AllowEmptyString()][string]$Was = '', $Carry = $null)
    $n = ([string]$Now).Trim().ToLowerInvariant(); $w = ([string]$Was).Trim().ToLowerInvariant()
    if (-not $n -or -not $w -or $n -eq $w) { return $true }
    foreach ($c in @(@($Carry) | ForEach-Object { ([string]$_) -split '[;,]' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })) { if ($c -eq $w) { return $true } }
    $false
}

function Get-RAStreamStatusSql {
    # #690 (34): the report's query fingerprint (@QueryHash) is written only where the database has the column (dynamic SQL:
    # a database the updater has not updated yet stores the verdict exactly as before)
    @'
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
DELETE FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = @Grain AND ReportName = @ReportName;
INSERT sidata.RaReportStatus (CollectionTime, Grain, ReportName, ExpectedRows, RetrievedRows, StoredRows, State, Reason)
VALUES (@t, @Grain, @ReportName, TRY_CONVERT(bigint, NULLIF(@Expected, '')), TRY_CONVERT(bigint, NULLIF(@Retrieved, '')), TRY_CONVERT(bigint, NULLIF(@Stored, '')), @State, NULLIF(LEFT(@Reason, 2000), ''));
IF COL_LENGTH('sidata.RaReportStatus', 'QueryHash') IS NOT NULL AND NULLIF(@QueryHash, '') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.RaReportStatus SET QueryHash = LEFT(@h, 64) WHERE CollectionTime = @t AND Grain = @g AND ReportName = @r',
         N'@h nvarchar(64), @t datetime2(3), @g nvarchar(16), @r nvarchar(256)', @h = @QueryHash, @t = @t, @g = @Grain, @r = @ReportName;
-- #692: the fingerprint(s) the report had before a declared structure-only change (its carry) -- where the column exists
IF COL_LENGTH('sidata.RaReportStatus', 'QueryHashCarry') IS NOT NULL AND NULLIF(@QueryHashCarry, '') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.RaReportStatus SET QueryHashCarry = LEFT(@c, 400) WHERE CollectionTime = @t AND Grain = @g AND ReportName = @r',
         N'@c nvarchar(400), @t datetime2(3), @g nvarchar(16), @r nvarchar(256)', @c = @QueryHashCarry, @t = @t, @g = @Grain, @r = @ReportName;
SELECT 1;
'@
}

function Get-RAStreamCompleteSql {
    <#
        The END of the run: every bucket of every report is in. A Detailed collection is marked so (RaCompletedAt); the data
        sync adds its CIs, recommendations and daily aggregates and marks it 'Complete'. A Summary collection is complete
        here. Only a collection still 'Loading' whose row count is what was written.
    #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($Grain -eq 'Summary') {
        return @'
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
UPDATE sidata.SummaryLoad SET Status = 'Complete', [Rows] = CONVERT(int, @Rows), LoadedAt = SYSUTCDATETIME()
WHERE CollectionTime = @t AND Status = 'Loading'
  AND (SELECT COUNT_BIG(*) FROM sidata.SummaryRow WHERE CollectionTime = @t) = CONVERT(bigint, @Rows);
SELECT @@ROWCOUNT;
'@
    }
    @'
DECLARE @c int = CONVERT(int, @CollectionId);
UPDATE sidata.Collection SET RaCompletedAt = SYSUTCDATETIME(), [Rows] = CONVERT(int, @Rows), RaPartialReason = NULLIF(LEFT(@Partial, 2000), '')
WHERE CollectionId = @c AND Status = 'Loading' AND RaCompletedAt IS NULL
  AND (SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @c) = CONVERT(bigint, @Rows);
SELECT @@ROWCOUNT;
'@
}

function Get-RAStreamTrendSql {
    <#
        The day's trend rollup of a SUMMARY run, in SQL (ConvertTo-SITrendRollup's rules): per dimension (global / severity /
        tier / domain, and the '-counted' twin over the rows without an exemption mark) the rows, the DISTINCT assets they
        hit (the Summary row's asset ids, else its own asset id) and the score total. An empty dimension value adds nothing.
        -Grain Detailed (#636: the daily trend row comes from the Detailed run -- the Summary step is optional and off by
        default): the same rollup over the run's FINDINGS (sidata.Finding of @CollectionId, the rows this run wrote) -- each
        finding one row (the trend counts findings), its asset the finding's asset, its values as the data sync stores them.
    #>
    # -Held (#877): the ordinals of the reports held back this run -- their rows are never in the trend
    param([ValidateSet('Summary', 'Detailed')][string]$Grain = 'Summary', [int[]]$Held = @())
    if ($Grain -eq 'Detailed') {
        return (@'
WITH r AS (SELECT FindingId, NULLIF(LTRIM(RTRIM(ISNULL(Severity, N''))), N'') AS Sev, CONVERT(nvarchar(8), Tier) AS Tr, NULLIF(LTRIM(RTRIM(ISNULL(SecurityDomain, N''))), N'') AS Dom,
                  ISNULL(RiskScore, 0) AS Score, CASE WHEN ExemptionId IS NULL THEN 0 ELSE 1 END AS Ex, NULLIF(LTRIM(RTRIM(ISNULL(AssetKey, N''))), N'') AS A
           FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaSeq IS NOT NULL{HELD}),
d AS (SELECT r.Score, r.A, x.Dim, x.Val FROM r
      CROSS APPLY (VALUES ('global', N'all'), ('severity', r.Sev), ('tier', r.Tr), ('domain', r.Dom)) x(Dim, Val)
      UNION ALL
      SELECT r.Score, r.A, x.Dim + '-counted', x.Val FROM r
      CROSS APPLY (VALUES ('global', N'all'), ('severity', r.Sev), ('tier', r.Tr), ('domain', r.Dom)) x(Dim, Val)
      WHERE r.Ex = 0)
SELECT d.Dim AS Dimension, d.Val AS DimensionValue, COUNT(*) AS Findings, COUNT(DISTINCT d.A) AS Assets, SUM(d.Score) AS ScoreTotal
FROM d WHERE ISNULL(d.Val, N'') <> N''
GROUP BY d.Dim, d.Val
ORDER BY d.Dim, d.Val;
'@).Replace('{HELD}', (Get-RAStreamHeldFilter -Held $Held))
    }
    (@'
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
WITH r AS (SELECT RowNo, RaTrendSeverity, RaTrendTier, RaTrendDomain, ISNULL(RaTrendScore, 0) AS Score, ISNULL(RaExempt, 0) AS Ex, RaTrendAssetIds
           FROM sidata.SummaryRow WHERE CollectionTime = @t AND RaReport IS NOT NULL{HELD}),
d AS (SELECT r.RowNo, r.Score, r.RaTrendAssetIds, x.Dim, x.Val FROM r
      CROSS APPLY (VALUES ('global', N'all'), ('severity', r.RaTrendSeverity), ('tier', r.RaTrendTier), ('domain', r.RaTrendDomain)) x(Dim, Val)
      UNION ALL
      SELECT r.RowNo, r.Score, r.RaTrendAssetIds, x.Dim + '-counted', x.Val FROM r
      CROSS APPLY (VALUES ('global', N'all'), ('severity', r.RaTrendSeverity), ('tier', r.RaTrendTier), ('domain', r.RaTrendDomain)) x(Dim, Val)
      WHERE r.Ex = 0),
f AS (SELECT Dim, Val, COUNT(*) AS Findings, SUM(Score) AS ScoreTotal FROM d WHERE ISNULL(Val, '') <> '' GROUP BY Dim, Val),
a AS (SELECT d.Dim, d.Val, COUNT(DISTINCT LTRIM(RTRIM(i.value))) AS Assets FROM d
      CROSS APPLY OPENJSON(ISNULL(d.RaTrendAssetIds, '[]')) i
      WHERE ISNULL(d.Val, '') <> '' AND LTRIM(RTRIM(i.value)) <> '' GROUP BY d.Dim, d.Val)
SELECT f.Dim AS Dimension, f.Val AS DimensionValue, f.Findings, ISNULL(a.Assets, 0) AS Assets, f.ScoreTotal
FROM f LEFT JOIN a ON a.Dim = f.Dim AND a.Val = f.Val
ORDER BY f.Dim, f.Val;
'@).Replace('{HELD}', (Get-RAStreamHeldFilter -Held $Held))
}

# ------------------------------------------------------------------------------------------------------------------
#  THE RUN
# ------------------------------------------------------------------------------------------------------------------

function Invoke-RAStreamSql {
    <# One statement through the seam, retried on a passing failure (a timeout, a dropped connection): 3 attempts. #>
    # -What (#741 (1)): what the statement does, in plain words -- a statement that still times out after every attempt then
    # fails the report with THAT said ("the database did not answer in time while ..."), never only the driver's text
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{}, [string]$Mode = 'scalar', [int]$Attempts = 3, [string]$What = '')
    for ($a = 1; ; $a++) {
        try { return (& $Stream.Invoke $Sql $Params $Mode) }
        catch {
            $m = $_.Exception.Message
            $passing = $m -match '(?i)timeout|transport-level|connection was (forcibly )?closed|deadlock|40613|40501|49918|10928|10929|semaphore|broken pipe'
            if (-not $passing) { throw }
            if ($a -ge $Attempts) {
                if ($What -and $m -match '(?i)timeout') { throw (New-RAStreamTimeoutError -What $What -Attempts $a -Inner $_.Exception) }
                throw
            }
            Start-Sleep -Seconds ([Math]::Min(60, 5 * $a * $a))
        }
    }
}

function New-RAStreamTimeoutError {
    <# PURE. #741 (1): the error a database statement that timed out on every attempt fails its report with -- the step named,
       the attempts counted, the driver's own line kept at the end. The report loop records it as the report's reason
       ("it failed: ..."), so the report is NotComplete with this said. #>
    param([Parameter(Mandatory)][string]$What, [int]$Attempts = 1, [System.Exception]$Inner)
    $line = ''
    if ($Inner) { $line = ([string]$Inner.Message -split "`n" | Select-Object -First 1).Trim() }
    $msg = 'the database did not answer in time while {0} ({1} attempt(s)) -- the report''s stored result is not complete: {2}' -f $What, $Attempts, $line
    $ex = New-Object System.TimeoutException($msg, $Inner)
    $ex.Data['SIRAStreamTimeout'] = $true
    $ex
}

# ------------------------------------------------------------------------------------------------------------------
#  BATCHED STATEMENTS -- a step over a whole report never depends on one statement's time (live 2026-10-21)
# ------------------------------------------------------------------------------------------------------------------

# the batch size each kind of batched step ended with, carried to the next report of the run (measured, never a setting)
if ($null -eq $script:RAStreamBatchSize) { $script:RAStreamBatchSize = @{} }

function Get-RAStreamFailureKind {
    <# PURE. 'timeout' | 'passing' (a dropped connection, a deadlock, a busy database: worth the same batch again) | 'other'
       -- the classes Invoke-RAStreamSql retries on, with the timeout told apart. #>
    param([string]$Message)
    $m = [string]$Message
    if ($m -match '(?i)timeout') { return 'timeout' }
    if ($m -match '(?i)transport-level|connection was (forcibly )?closed|deadlock|40613|40501|49918|10928|10929|semaphore|broken pipe') { return 'passing' }
    'other'
}

function Get-RAStreamNextBatchSize {
    <# PURE. The next batch size from the last one's measured time (Get-SIDataNextSize where it is loaded: aim for -TargetMs,
       smaller at once when slower, at most double when faster). Never below 1. #>
    param([Parameter(Mandatory)][long]$Current, [Parameter(Mandatory)][long]$ElapsedMs, [long]$TargetMs = 5000)
    if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { return [long](Get-SIDataNextSize -Current $Current -ElapsedMs $ElapsedMs -TargetMs $TargetMs -Minimum 1) }
    $c = [Math]::Max(1L, $Current)
    $limit = [double][Math]::Min([double]([long]::MaxValue / 2), 2.0 * [double]$c)
    $want = if ($ElapsedMs -le 0) { $limit } else { [Math]::Min($limit, [Math]::Floor([double]$c * ([double]$TargetMs / [double]$ElapsedMs))) }
    [long][Math]::Max(1.0, $want)
}

function Invoke-RAStreamBatched {
    <#
        Runs ONE step over a report as a row of short statements (owner: the key figures -- and every step -- must finish at
        any size; no fixed time limit, no fixed batch). -Batch { param($Size) } runs one statement of -Size and answers
        @{ Removed; Done }. The size is measured: grown (at most double) when a batch is fast, smaller when it is slow,
        HALVED when a batch runs into the database's command timeout -- that batch is then asked again, smaller (a statement
        that timed out is rolled back: nothing of it is kept). A passing failure (a dropped connection, a deadlock) asks the
        same batch again, three times. Only a batch of ONE that still times out three times in a row, or any other error,
        fails the step -- said with what it was doing (New-RAStreamTimeoutError). A line of progress at most once a minute
        while it runs, and the size it ended with is kept for the next report of the run (-Kind).
        Returns @{ Removed; Batches; Seconds; Size }.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][scriptblock]$Batch, [Parameter(Mandatory)][string]$What, [string]$Kind = '',
          [long]$StartSize = 5000, [long]$TargetMs = 5000, [int]$ProgressSeconds = 60)
    if ($null -eq $script:RAStreamBatchSize) { $script:RAStreamBatchSize = @{} }
    $size = [Math]::Max(1L, $StartSize)
    if ($Kind -and $script:RAStreamBatchSize.ContainsKey($Kind) -and [long]$script:RAStreamBatchSize[$Kind] -gt 0) { $size = [long]$script:RAStreamBatchSize[$Kind] }
    $log = $null; try { $log = $Stream.Log } catch { $log = $null }
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    $all = [Diagnostics.Stopwatch]::StartNew()
    $total = 0L; $batches = 0; $floorTimeouts = 0; $passing = 0; $lastMs = 0L; $saidAt = 0.0; $halved = 0
    while ($true) {
        if ($paced) { try { $pace = Invoke-SISqlPacing -Invoke $Stream.Invoke -LastBatchMs $lastMs; if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) } } catch { } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = $null
        try { $r = & $Batch $size }
        catch {
            $sw.Stop()
            $kindOf = Get-RAStreamFailureKind -Message ([string]$_.Exception.Message)
            if ($kindOf -eq 'timeout') {
                $passing = 0
                if ($size -le 1) {
                    $floorTimeouts++
                    if ($floorTimeouts -ge 3) { throw (New-RAStreamTimeoutError -What $What -Attempts $floorTimeouts -Inner $_.Exception) }
                    continue
                }
                $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)); $halved++
                if ($log) { & $log 'INFO' ("{0}: one batch took longer than the database allows for one statement -- it is asked again in batches of {1:N0}" -f $What, $size) }
                continue
            }
            if ($kindOf -eq 'passing') {
                $passing++
                if ($passing -ge 3) { throw }
                Start-Sleep -Seconds ([Math]::Min(60, 5 * $passing * $passing))
                continue
            }
            throw
        }
        $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
        $floorTimeouts = 0; $passing = 0
        $batches++
        $n = 0L; $done = $true
        if ($null -ne $r) { $n = [long]$r.Removed; $done = [bool]$r.Done }
        $total += $n
        if ($done) { break }
        $size = Get-RAStreamNextBatchSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs
        if ($log -and ($all.Elapsed.TotalSeconds - $saidAt) -ge $ProgressSeconds) {
            $saidAt = $all.Elapsed.TotalSeconds
            & $log 'INFO' ("{0}: {1:N0} row(s) so far in {2:N0} batch(es), {3:N0} s -- next batch {4:N0}" -f $What, $total, $batches, [Math]::Round($all.Elapsed.TotalSeconds), $size)
        }
    }
    $all.Stop()
    if ($Kind) { $script:RAStreamBatchSize[$Kind] = $size }
    if ($log -and ($halved -gt 0 -or $all.Elapsed.TotalSeconds -ge $ProgressSeconds)) {
        & $log 'INFO' ("{0}: done -- {1:N0} row(s) in {2:N0} batch(es), {3:N0} s" -f $What, $total, $batches, [Math]::Round($all.Elapsed.TotalSeconds))
    }
    @{ Removed = $total; Batches = $batches; Seconds = [Math]::Round($all.Elapsed.TotalSeconds, 1); Size = $size }
}

function Read-RAStreamBatchRow {
    <# The first row a 'reader' statement answered (the seam answers ONE array of hashtables), or $null. #>
    param($Answer)
    foreach ($x in @($Answer)) { foreach ($h in @($x)) { if ($h -is [System.Collections.IDictionary]) { return $h } } }
    $null
}

function Invoke-RAStreamDedup {
    <#
        "A finding two query slices both returned is kept ONCE -- the first written", for the current report, in pages through
        the report's key index (Get-RAStreamDedupPageSql) -- never one statement over the whole report. -Params: the report's
        statement parameters (CollectionTime, CollectionId, Report). Returns the rows removed.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][hashtable]$Params, [string]$What = 'keeping once the findings two query slices both returned')
    $__ddSql = Get-RAStreamDedupPageSql -Grain $Stream.Grain
    $__ddCursor = @{ After = '' }
    $__ddStep = {
        param($Size)
        $q = @{}; foreach ($k in $Params.Keys) { $q[$k] = $Params[$k] }
        $q['Page'] = [string][long]$Size; $q['After'] = [string]$__ddCursor.After
        $h = Read-RAStreamBatchRow -Answer (Invoke-RAStreamSql -Stream $Stream -Sql $__ddSql -Params $q -Mode 'reader' -Attempts 1)
        if ($null -eq $h) { return @{ Removed = 0L; Done = $true } }
        $key = ''; if ($null -ne $h['LastKey'] -and -not ($h['LastKey'] -is [System.DBNull])) { $key = [string]$h['LastKey'] }
        $seen = 0L; if ($null -ne $h['Seen'] -and -not ($h['Seen'] -is [System.DBNull])) { $seen = [long]$h['Seen'] }
        $gone = 0L; if ($null -ne $h['Removed'] -and -not ($h['Removed'] -is [System.DBNull])) { $gone = [long]$h['Removed'] }
        $__ddCursor.After = $key
        @{ Removed = $gone; Done = (-not $key -or $seen -lt [long]$Size) }
    }
    [long](Invoke-RAStreamBatched -Stream $Stream -Batch $__ddStep -What $What -Kind ('dedup|' + $Stream.Grain) -StartSize 50000 -TargetMs 10000).Removed
}

function Remove-RAStreamRowsBatched {
    <#
        Runs a 'DELETE TOP (@Batch) ...; SELECT <rows removed>' statement (Get-RAStreamDeleteReportBatchSql) until it removes
        fewer rows than the batch -- each batch its own short statement, sized by its measured time (Invoke-RAStreamBatched).
        Returns the rows removed.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{}, [Parameter(Mandatory)][string]$What, [string]$Kind = 'remove')
    $__rmStep = {
        param($Size)
        $q = @{}; foreach ($k in $Params.Keys) { $q[$k] = $Params[$k] }
        $q['Batch'] = [string][long]$Size
        $n = [long](@(Invoke-RAStreamSql -Stream $Stream -Sql $Sql -Params $q -Attempts 1)[-1])
        @{ Removed = $n; Done = ($n -lt [long]$Size) }
    }
    [long](Invoke-RAStreamBatched -Stream $Stream -Batch $__rmStep -What $What -Kind $Kind -StartSize 5000 -TargetMs 5000).Removed
}

function New-RAStream {
    <#
        Begins the run's collection in SQL ('Loading'). Returns the stream: the seam, the grain, the collection, the write
        order counter and what is kept per report (its columns, its date columns, rows retrieved) -- a handful of names and
        numbers per report, never rows. Throws when the database does not carry the tables (the caller keeps the result in
        memory as before and says so).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain,
          [Parameter(Mandatory)][datetime]$CollectionTime, [string]$RunId = '', [string]$SolutionVersion = '', [scriptblock]$Log,
          # #742: a queue WORKER joins the run its producer began (its collection id, from the run's manifest) -- nothing is
          # begun or removed here, and a collection that is no longer loading is refused (that run is over)
          [int]$AttachCollectionId = 0)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $s = @{ Invoke = $Invoke; Grain = $Grain; Log = $Log }
    if ([int](& $Invoke (Get-RAStreamSchemaCheckSql) @{} 'scalar') -ne 1) {
        throw 'the Pro database does not have the tables Risk Analysis writes its result to yet -- the updater adds them with the data schema'
    }
    # the database's own load paces the rows written (SI-SqlPacing.ps1, through Write-SIDataJsonRows): its one line goes
    # to the run's log
    if (Get-Command -Name Get-SISqlPacer -ErrorAction SilentlyContinue) { $null = Get-SISqlPacer -Invoke $Invoke -Log $Log }
    $s.TimeText = Format-SIDataSqlTime -Time $CollectionTime
    $s.RunKey = '{0}|{1}' -f $Grain, $s.TimeText
    $s.CollectionTime = $CollectionTime
    if ($AttachCollectionId -gt 0) {
        $st = [string](Invoke-RAStreamSql -Stream $s -Sql "SELECT Status FROM sidata.Collection WHERE CollectionId = CONVERT(int, @CollectionId) AND RaCompletedAt IS NULL;" -Params @{ CollectionId = [string]$AttachCollectionId } -Mode 'scalar')
        if ($st -ne 'Loading') { throw ("the run's collection {0} is not loading any more ({1}) -- that run is over" -f $AttachCollectionId, $(if ($st) { $st } else { 'completed or removed' })) }
        $s.CollectionId = $AttachCollectionId
        $s.Attached = $true
    } else {
    $p = @{ CollectionTime = $s.TimeText; RunId = [string]$RunId; SolutionVersion = [string]$SolutionVersion; RunKey = $s.RunKey }
    $id = Invoke-RAStreamSql -Stream $s -Sql (Get-RAStreamBeginSql -Grain $Grain) -Params $p -Mode 'scalar'
    $s.CollectionId = if ($Grain -eq 'Detailed') { [int]$id } else { 0 }
    if ($Grain -eq 'Detailed' -and $s.CollectionId -le 0) { throw 'the run''s collection could not be registered in the database' }
    }
    $s.Seq = 0L
    $s.Chunk = [long]0
    $s.Reports = [ordered]@{}        # name -> @{ Ordinal; Columns (List); ColSet; DateCols; Retrieved; Staged; StagePlan }
    $s.Ordinal = 0
    $s.Illegal = 0L
    $s.Current = $null
    $s.Broken = ''
    # #877: the reports HELD BACK this run (ordinal -> @{ Report; Ordinal; Cause; Why }) -- see Add-RAStreamHeldReport
    $s.Held = @{}
    $s
}

function Start-RAStreamReport {
    <# A report begins: its ordinal in the run (the final order's tie-break after the score), its rows so far removed.
       #742: a queue worker gives the ordinal the producer planned (-Ordinal) and numbers the report's rows from its own
       base (-SeqBase, RA-ScaleOut.ps1 Get-RAScaleOutSeqBase) -- the single job's order, without asking another process. #>
    # #831 B: -OwnSeq = the write-number ranges @(@{ From; To }) of ONE PART of a split report (RA-ScaleOut.ps1
    # Get-RAScaleOutSplitSeqRanges): every removal of "the report's rows" by this process then removes only this part's own
    # rows, never another part's. -KeepRows: the part's rows are already in (its retry only finishes the report).
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$ReportName, [bool]$Staged, [string]$Query = '', [int]$Ordinal = 0, [long]$SeqBase = -1,
          [object[]]$OwnSeq = $null, [switch]$KeepRows)
    if (-not $Stream.Reports.Contains($ReportName)) {
        if ($Ordinal -gt 0) { $o = $Ordinal; if ($Ordinal -gt $Stream.Ordinal) { $Stream.Ordinal = $Ordinal } } else { $Stream.Ordinal++; $o = $Stream.Ordinal }
        $Stream.Reports[$ReportName] = New-RAStreamReportEntry -Name $ReportName -Ordinal $o -Staged $Staged
    }
    if ($SeqBase -ge 0) { $Stream.Seq = $SeqBase }
    $r = $Stream.Reports[$ReportName]
    $r.Staged = $Staged
    $r.OwnSeq = $(if ($null -ne $OwnSeq -and @($OwnSeq).Count) { @($OwnSeq) } else { $null })
    if ($Staged -and $Query -and (Get-Command -Name Get-RASummaryMergePlan -ErrorAction SilentlyContinue)) { $r.Plan = Get-RASummaryMergePlan -Query $Query }
    $Stream.Current = $r
    $r.Times = @{}   # #873 A: this process's seconds per phase of the report (Add-RAStreamTime), said once at its end
    if (-not $KeepRows) { Clear-RAStreamReport -Stream $Stream -Why '' }
    $r
}

# ---------------------------------------------------------------------------------------------------------------------
# #873 A -- WHERE A REPORT'S TIME GOES (log only: nothing here changes a row, a verdict or the order of anything).
# The largest install's Detailed step took 5 h 25 min and no log line said which phase cost it. Every query slice adds
# its seconds per phase to the report's entry; the report's end says them in ONE line ('[phases] ...'), and the work
# after the reports says each pass's time. The phases, in the order a slice goes through them:
#   hunt     waiting for the hunting answer (the query slice, its late retry, its smaller slices; asked ahead or not)
#   convert  the answer turned into rows
#   score    the risk scores
#   shape    the report's columns and the column-fill count
#   delete   removing what the slice stored before (a retry never doubles)
#   items    each row's stored form (JSON)
#   insert   writing the slice's rows (the findings and the summary rows)
#   dedup / trace / count   the report's finish in the database (kept once, shared trace names, the stored count)
# ---------------------------------------------------------------------------------------------------------------------
$script:RAPhaseOrder = @('hunt', 'convert', 'score', 'shape', 'delete', 'items', 'insert', 'dedup', 'trace', 'count')

function Add-RAStreamTime {
    <# #873 A: -Seconds of -Phase added to the current report of -Stream (nothing when there is none). Never throws.
       'insert' also counts the slice and its rows written (-Rows). #>
    param($Stream, [Parameter(Mandatory)][string]$Phase, [double]$Seconds, [long]$Rows = -1)
    try {
        if ($null -eq $Stream -or $null -eq $Stream.Current) { return }
        $t = $Stream.Current.Times
        if ($null -eq $t) { $t = @{}; $Stream.Current.Times = $t }
        if ($t.ContainsKey($Phase)) { $t[$Phase] = [double]$t[$Phase] + $Seconds } else { $t[$Phase] = $Seconds }
        if ($Phase -eq 'insert') { $t['_slices'] = [int]$t['_slices'] + 1; if ($Rows -ge 0) { $t['_rows'] = [long]$t['_rows'] + $Rows } }
    } catch { }
}

function Format-RAPhaseLine {
    <# PURE (#873 A). The one line of a report's time per phase: '[phases] <What>: hunt 12.0 s, convert 1.5 s, ... = 99.0 s
       (S slice(s) written, R row(s))'. A phase without time is left out; a phase not in the list is said after the others. #>
    param([hashtable]$Times = @{}, [Parameter(Mandatory)][string]$What)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Times) { $Times = @{} }
    $parts = New-Object System.Collections.Generic.List[string]
    $sum = 0.0
    $names = @($script:RAPhaseOrder) + @(@($Times.Keys) | Where-Object { -not ([string]$_).StartsWith('_') -and $script:RAPhaseOrder -notcontains [string]$_ } | Sort-Object)
    foreach ($n in $names) {
        if (-not $Times.ContainsKey($n)) { continue }
        $v = [double]$Times[$n]; $sum += $v
        $parts.Add(('{0} {1} s' -f $n, $v.ToString('0.0', $inv)))
    }
    $tail = ''
    if ($Times.ContainsKey('_slices')) { $tail = (' ({0} slice(s) written, {1} row(s))' -f [int]$Times['_slices'], [long]$Times['_rows']) }
    if (-not $parts.Count) { return ('[phases] {0}: no phase measured{1}' -f $What, $tail) }
    ('[phases] {0}: {1} = {2} s{3}' -f $What, ($parts -join ', '), $sum.ToString('0.0', $inv), $tail)
}

function Get-RAStepPhaseJob {
    <# PURE. The job name a Risk Analysis run's phase rows carry in cfg.StepPhaseTime: risk-analysis-detailed | -summary. #>
    param($Stream)
    $g = 'detailed'; try { if ($null -ne $Stream -and [string]$Stream.Grain) { $g = ([string]$Stream.Grain).ToLowerInvariant() } } catch { }
    'risk-analysis-' + $g
}

function Write-RAStepPhaseRow {
    <# #873 A: ONE phase row to cfg.StepPhaseTime through the run's own database seam (Write-SIStepPhase, SI-StepPhase.ps1).
       Nothing when there is no stream or the helper is not loaded. NEVER throws, never changes a row of the result. #>
    param($Stream, [Parameter(Mandatory)][string]$Phase, [double]$Seconds, [long]$Rows = -1)
    try {
        if ($null -eq $Stream -or $null -eq $Stream.Invoke) { return }
        if (-not (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) { return }
        $log = $null; if ($Stream.Log -is [scriptblock]) { $log = $Stream.Log }
        $null = Write-SIStepPhase -Invoke $Stream.Invoke -Job (Get-RAStepPhaseJob -Stream $Stream) -Phase $Phase -Seconds $Seconds -Rows $Rows -Log $log
    } catch { }
}

function Write-RAStepProgressRow {
    <# #576: the running report's progress -- '<report>', query slice <Done> of <Total> -- through the run's own database seam
       (Write-SIStepProgress, SI-StepPhase.ps1; at a new report and at most every 15 s). Nothing when there is no stream or
       the helper is not loaded. NEVER throws, never changes a row of the result. #>
    param($Stream, [Parameter(Mandatory)][string]$Phase, [long]$Done = -1, [long]$Total = -1)
    try {
        if ($null -eq $Stream -or $null -eq $Stream.Invoke) { return }
        if (-not (Get-Command -Name Write-SIStepProgress -ErrorAction SilentlyContinue)) { return }
        $log = $null; if ($Stream.Log -is [scriptblock]) { $log = $Stream.Log }
        $null = Write-SIStepProgress -Invoke $Stream.Invoke -Job (Get-RAStepPhaseJob -Stream $Stream) -Phase $Phase -Done $Done -Total $Total -Log $log
    } catch { }
}

function Write-RAPhaseTimesToSql {
    <# #873 A: a report's (or a part's) time per phase as rows of cfg.StepPhaseTime -- '<What>: <phase>', one row per phase
       measured, in slice order; the insert row carries the rows written. NEVER throws. #>
    param($Stream, [hashtable]$Times, [Parameter(Mandatory)][string]$What)
    try {
        if ($null -eq $Times) { return }
        $names = @($script:RAPhaseOrder) + @(@($Times.Keys) | Where-Object { -not ([string]$_).StartsWith('_') -and $script:RAPhaseOrder -notcontains [string]$_ } | Sort-Object)
        foreach ($n in $names) {
            if (-not $Times.ContainsKey($n)) { continue }
            $rows = -1L; if ($n -eq 'insert' -and $Times.ContainsKey('_rows')) { $rows = [long]$Times['_rows'] }
            Write-RAStepPhaseRow -Stream $Stream -Phase ('{0}: {1}' -f $What, $n) -Seconds ([double]$Times[$n]) -Rows $rows
        }
    } catch { }
}

function Format-RAAfterReportsLine {
    <# PURE (#873 A). The time of one pass after the reports (the JSON file, the workbook, the AI summary, the key figures). #>
    param([Parameter(Mandatory)][string]$What, [double]$Seconds, [long]$Rows = -1)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $r = ''; if ($Rows -ge 0) { $r = (' ({0} row(s) read)' -f $Rows) }
    ('[phases] after the reports: {0} in {1} s{2}' -f $What, $Seconds.ToString('0.0', $inv), $r)
}

function Format-RAWorkerTimeLine {
    <# PURE (#873 A). A queue worker's time when it stops: how many items, the time it worked on them and the time it waited
       for the queue, with its start and end (UTC) -- the run's workers side by side show when one sat idle. #>
    param([int]$Items, [double]$BusySeconds, [double]$WaitSeconds, [datetime]$StartedUtc, [datetime]$EndedUtc)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    ('[phases] worker: {0} item(s); working {1} s, waiting for the queue {2} s; {3} -> {4} UTC' -f $Items, $BusySeconds.ToString('0.0', $inv), $WaitSeconds.ToString('0.0', $inv),
        $StartedUtc.ToString('yyyy-MM-ddTHH:mm:ss', $inv), $EndedUtc.ToString('yyyy-MM-ddTHH:mm:ss', $inv))
}

function Get-RAStreamDeleteSeqSql {
    <# #831 B: the rows of one report written with numbers in [@From, @To) -- one part of a split report. Detailed. #>
    'DELETE FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq >= CONVERT(bigint, @From) AND RaSeq < CONVERT(bigint, @To); SELECT @@ROWCOUNT;'
}

function Remove-RAStreamSeqRanges {
    <# #831 B: removes the rows report -Ordinal wrote in -Ranges (@(@{ From; To })). Returns the rows removed. #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][int]$Ordinal, [AllowEmptyCollection()][object[]]$Ranges = @())
    if ($Stream.Grain -ne 'Detailed') { throw 'only a Detailed report is run in parts' }
    $n = 0L
    foreach ($g in @($Ranges)) {
        if ($null -eq $g) { continue }
        $p = @{ CollectionId = [string]$Stream.CollectionId; Report = [string]$Ordinal; From = [string][long]$g.From; To = [string][long]$g.To }
        $n += Remove-RAStreamRowsBatched -Stream $Stream -Sql (Get-RAStreamDeleteReportBatchSql -Grain Seq) -Params $p -What 'removing what one part of the report stored' -Kind 'remove|Detailed'
    }
    $n
}

function New-RAStreamReportEntry {
    <# What the stream keeps per report (Start-RAStreamReport) -- also built by a #742 producer from a worker's hand-over:
       the ordinal, the columns in first-seen order, the date columns, the rows retrieved. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$Ordinal, [bool]$Staged = $false,
          [string[]]$Columns = @(), [string[]]$DateCols = @(), [long]$Retrieved = 0, [string[]]$StageCols = @(), [int]$Pages = 0)
    $e = @{ Ordinal = $Ordinal; Name = $Name
        Columns = ([System.Collections.Generic.List[string]]::new()); ColSet = ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase))
        DateCols = ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)); Retrieved = $Retrieved; Account = @{}; Staged = $Staged; Plan = $null; Pages = $Pages
        StageCols = ([System.Collections.Generic.List[string]]::new()); StageColSet = ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)) }
    foreach ($c in @($Columns)) { if ($c -and $e.ColSet.Add([string]$c)) { $e.Columns.Add([string]$c) } }
    foreach ($c in @($DateCols)) { if ($c) { [void]$e.DateCols.Add([string]$c) } }
    foreach ($c in @($StageCols)) { if ($c -and $e.StageColSet.Add([string]$c)) { $e.StageCols.Add([string]$c) } }
    $e
}

function Get-RAStreamReportCounts {
    <# #742: the rows each report holds in the run's result -- ordinal -> rows. #>
    param([Parameter(Mandatory)]$Stream)
    $sql = if ($Stream.Grain -eq 'Summary') { 'SELECT RaReport, COUNT_BIG(*) AS N FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND RaReport IS NOT NULL GROUP BY RaReport;' }
           else { 'SELECT RaReport, COUNT_BIG(*) AS N FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaSeq IS NOT NULL GROUP BY RaReport;' }
    $out = @{}
    foreach ($x in @(Invoke-RAStreamSql -Stream $Stream -Sql $sql -Params @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId } -Mode 'reader')) {
        foreach ($h in @($x)) { if ($h) { $out[[int]$h['RaReport']] = [long]$h['N'] } }
    }
    $out
}

function Clear-RAStreamReport {
    <# Removes everything the current report wrote (its bucket count went up and it starts again, or it could not run). #>
    param([Parameter(Mandatory)]$Stream, [string]$Why = '')
    $r = $Stream.Current; if ($null -eq $r) { return }
    $p = @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId; Report = [string]$r.Ordinal; Bucket = '*'; RunKey = $Stream.RunKey }
    # #831 B: one part of a split report removes only ITS rows (its write-number ranges) -- never another part's
    if ($r.ContainsKey('OwnSeq') -and $null -ne $r.OwnSeq) { $n = Remove-RAStreamSeqRanges -Stream $Stream -Ordinal ([int]$r.Ordinal) -Ranges @($r.OwnSeq) }
    else {
    # in batches, each its own short statement: a report that failed may hold a million rows (live 2026-10-21: the one
    # statement over them timed out, the report could not be taken back and the whole run ended failed)
    $n = Remove-RAStreamRowsBatched -Stream $Stream -Sql (Get-RAStreamDeleteReportBatchSql -Grain $Stream.Grain) -Params $p -What 'removing the rows the report stored' -Kind ('remove|' + $Stream.Grain)
    $n += Remove-RAStreamRowsBatched -Stream $Stream -Sql (Get-RAStreamDeleteReportBatchSql -Grain Stage) -Params $p -What 'removing the rows the report staged' -Kind 'remove|Stage'
    # #877: the whole report's rows are gone now -- a report held back earlier in this run (it runs again) is not held any more
    Remove-RAStreamHeldReport -Stream $Stream -Ordinal ([int]$r.Ordinal)
    }
    $r.Retrieved = 0L
    $r.Account = @{}
    if ($Why -and $n -gt 0) { & $Stream.Log 'INFO' ("{0} row(s) this report already stored are removed -- {1}" -f $n, $Why) }
}

function Undo-RAStreamBucket {
    <#
        ONE query slice of the current report that could not be processed (the process ran out of memory part-way): what it
        stored (its findings, or its staged Summary rows) is removed, its rows leave the report's retrieved count and its
        accounts -- the slice is then asked again in smaller slices (the sub-bucket pass), so nothing of it is counted twice
        and nothing of it is kept half. -Retrieved: the rows the slice had added to the count. Returns the rows removed.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Bucket, [long]$Retrieved = 0)
    $r = $Stream.Current; if ($null -eq $r) { return 0L }
    $p = @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId; Report = [string]$r.Ordinal; Bucket = $Bucket; RunKey = $Stream.RunKey }
    $n = 0L
    if ($r.Staged) { $n += [long](@(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamDeleteStageSql) -Params $p)[-1]) }
    else {
        $n += [long](@(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamDeleteBucketSql -Grain $Stream.Grain) -Params $p)[-1])
        $r.Retrieved = [Math]::Max(0L, [long]$r.Retrieved - [long]$Retrieved)
    }
    if ($r.Account) { foreach ($k in @($Bucket, ('dfc:' + $Bucket))) { if ($r.Account.ContainsKey($k)) { $r.Account.Remove($k) } } }
    $n
}

function Add-RAStreamColumns {
    <# The report's columns, union in first-seen order (case-insensitive) -- what its rows are shaped to when read back. #>
    param([Parameter(Mandatory)]$Stream, [string[]]$Columns)
    $r = $Stream.Current; if ($null -eq $r) { return }
    foreach ($c in @($Columns)) { if ($c -and $script:RAStreamLegalName.IsMatch($c) -and $r.ColSet.Add($c)) { $r.Columns.Add($c) } }
}

function Get-RAStreamTraceInfo {
    <# PURE. The parts of a row's trace identity the report-wide fix-up needs (Get-RATraceBase, RA-RowShaping.ps1). #>
    param([Parameter(Mandatory)]$Row, [bool]$IsDetailed)
    $b = Get-RATraceBase -Row $Row -IsDetailed $IsDetailed
    $tn = ''; $p = $Row.PSObject.Properties['TraceName']; if ($p) { $tn = [string]$p.Value }
    $base = (@($b.Parts) + 'SI') -join '-'
    @{ Hash = (Get-RAStreamHash16 -Text $b.Lower); Key = $(if ($b.AssetKey) { $b.AssetKey.ToLowerInvariant() } else { '' }); Suffixed = ($tn -ne $base) }
}

function ConvertTo-RAStreamSummaryItem {
    <# PURE. One result row as the Summary load reads it: its columns through the data sync's names (si_ first, else the old name). #>
    param([Parameter(Mandatory)]$Row)
    $o = [ordered]@{}
    foreach ($k in $script:SIDataSummaryColumns.Keys) {
        $c = $script:SIDataSummaryColumns[$k]
        $v = $null
        foreach ($n in @($c[1], $c[0])) {
            $p = $Row.PSObject.Properties[$n]
            if (-not $p -or $null -eq $p.Value) { continue }
            $x = $p.Value
            if ($x -is [System.Collections.IEnumerable] -and $x -isnot [string]) { $x = ConvertTo-Json -InputObject @($x) -Compress -Depth 8 } else { $x = [string]$x }
            if ($x -ne '') { $v = $x; break }
        }
        $o[$k] = $v
    }
    [pscustomobject]$o
}

function Join-RAStreamJson {
    <# PURE. Adds the fields of -Extra to the JSON object -Json (both objects as text). #>
    param([Parameter(Mandatory)][string]$Json, [Parameter(Mandatory)][System.Collections.IDictionary]$Extra)
    $add = ConvertTo-SIDataJsonObject -Values $Extra
    $inner = $add.Substring(1, $add.Length - 2)
    if (-not $inner) { return $Json }
    if ($Json.Trim() -eq '{}') { return '{' + $inner + '}' }
    $Json.TrimEnd().Substring(0, $Json.TrimEnd().Length - 1) + ',' + $inner + '}'
}

function ConvertTo-RAStreamRowItems {
    <#
        PURE except -DateCols (the columns holding a date are added to it). The stored form of rows of the current report
        (Write-RAStreamRows): one JSON item per row (sidata.Finding / sidata.SummaryRow), the impacted-asset items of a
        Summary row, and how many rows carried a column name that cannot be stored. -FirstSeq: the write order of the first
        row (the next one +1). -InView: per row, whether the view shows it. -Context: Grain, Ordinal, Bucket,
        IsDetailedShape, ConfigurationIdInputName, SortColumn, FallbackSortColumn, Dedup, Equivalence.
        Returns @{ Items; AssetItems; Illegal }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [long]$FirstSeq, [bool[]]$InView, [Parameter(Mandatory)][hashtable]$Context,
          [System.Collections.Generic.HashSet[string]]$DateCols)
    $items = [System.Collections.Generic.List[string]]::new()
    $assetItems = [System.Collections.Generic.List[string]]::new()
    $illegal = 0L
    # a long step is never silent (RA-RowShaping.ps1, Step-RAProgress)
    $prog = $null
    if (Get-Command -Name New-RAProgress -ErrorAction SilentlyContinue) { $prog = New-RAProgress -What 'prepared for the database:' -Total $Rows.Count }
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        if ($null -ne $prog -and $i -gt 0 -and ($i % 200) -eq 0) { Step-RAProgress $prog $i }
        $row = $Rows[$i]
        $seq = $FirstSeq + $i
        $j = ConvertTo-RAStreamJson -Row $row -DateCols $DateCols
        if ($j.Illegal -gt 0) { $illegal++ }
        $sortP = $row.PSObject.Properties[$Context.SortColumn]; if (-not $sortP) { $sortP = $row.PSObject.Properties[$Context.FallbackSortColumn] }
        $sort = ConvertTo-RADouble -Value $(if ($sortP) { $sortP.Value } else { $null }) -Default 0.0
        $dk = ''; if ($Context.Dedup) { $dk = Get-RARowDedupKey -Row $row -ConfigurationIdInputName $Context.ConfigurationIdInputName }
        $ti = Get-RAStreamTraceInfo -Row $row -IsDetailed ([bool]$Context.IsDetailedShape)
        # (not $inView: PowerShell names are case-insensitive -- that IS the -InView parameter)
        $ra = [ordered]@{ RaReport = $Context.Ordinal; RaBucket = $Context.Bucket; RaDedup = $(if ($dk) { Get-RAStreamHash16 -Text $dk } else { '' }); RaSort = $sort; RaInView = [bool]$InView[$i]
                          RaTraceHash = $ti.Hash; RaTraceKey = $ti.Key; RaTraceSuffixed = [bool]$ti.Suffixed }
        if ($Context.Grain -eq 'Detailed') {
            # the data sync's projection of a Log Analytics row (Get-SIDataFindingsKql), then its mapping (ConvertTo-SIDataFindingJson)
            # (each column read once, as text, '' when absent or null -- the names in one list, no script block call per column)
            $rp = $row.PSObject.Properties
            $nv = @{}
            foreach ($n in $script:RAStreamNarrowCols) { $q = $rp[$n]; $nv[$n] = $(if ($q -and $null -ne $q.Value) { [string]$q.Value } else { '' }) }
            $aid = $nv['SI_AssetId']; if (-not $aid) { $aid = $nv['AssetId'] }
            $cfg = $nv['ConfigurationId']
            $rn = $nv['AssetDetectedInReportName']; if (-not $rn) { $rn = $nv['ReportName'] }
            $cat = $nv['Category']
            $narrow = [pscustomobject]@{ SI_AssetId = $aid; AssetName = $nv['AssetName']; ReportName = $rn; SecurityDomain = $nv['SecurityDomain']
                ConfigurationId = $cfg; Cve = $(if ($cfg.StartsWith('CVE-')) { $cfg.ToUpperInvariant() } else { '' }); Title = $nv['ConfigurationName']; Severity = $nv['SecuritySeverity']
                Tier = $nv['CriticalityTier']; SourceTier = $nv['SourceCriticalityTier']; IsPath = ($rn.StartsWith('Attack_Paths') -or $cat.StartsWith('AttackPath') -or $cat -eq 'Attack Paths')
                RiskScore = $nv['RiskScoreTotal']; ExemptionId = $nv['SI_ExemptionId']; ExemptedUntil = $nv['SI_ExemptedUntil']; ExemptionRequestId = $nv['SI_ExemptionRequestId']; DetailJson = $j.Json }
            $tiers = Get-SIDataRowTiers -Row $narrow
            if ($tiers.IsPath) { $narrow.Tier = $tiers.FindingTier }
            $ra['RaSeq'] = $seq
            $ra['RaFindingKey'] = [string](Get-SIFindingGroupKey -Row $row -Equivalence $Context.Equivalence)
            $ra['RaAssetId'] = $aid
            $ra['RaAssetTier'] = $tiers.AssetTier
            $items.Add((Join-RAStreamJson -Json (ConvertTo-SIDataFindingJson -Row $narrow -KeyOf @{}) -Extra $ra))
        } else {
            $one = ConvertTo-SIDataSummaryItems -Rows @(ConvertTo-RAStreamSummaryItem -Row $row) -StartRowNo $seq
            $tr = @{}
            $tr.Sev = ConvertTo-SITrendDimensionValue ($row.PSObject.Properties['SecuritySeverity'] | ForEach-Object { $_.Value })
            $tr.Tier = ConvertTo-SITrendDimensionValue ($row.PSObject.Properties['CriticalityTier'] | ForEach-Object { $_.Value })
            $tr.Dom = ConvertTo-SITrendDimensionValue ($row.PSObject.Properties['SecurityDomain'] | ForEach-Object { $_.Value })
            $sc = 0.0; $sp = $row.PSObject.Properties['RiskScoreTotal']; if ($sp -and $null -ne $sp.Value -and [string]$sp.Value -ne '') { try { $sc = [double]$sp.Value } catch { $sc = 0.0 } }
            $ex = $row.PSObject.Properties['SI_ExemptionId']; $exempt = [bool]($ex -and -not [string]::IsNullOrEmpty([string]$ex.Value))
            $ids = @(Get-SITrendRowAssetIds -Row $row)
            $ra['RaTrendSeverity'] = $tr.Sev; $ra['RaTrendTier'] = $tr.Tier; $ra['RaTrendDomain'] = $tr.Dom; $ra['RaTrendScore'] = $sc; $ra['RaExempt'] = $exempt
            $ra['RaTrendAssetIds'] = $(if ($ids.Count) { ConvertTo-Json -InputObject @($ids) -Compress } else { $null })
            $ra['RowJson'] = $j.Json
            $items.Add((Join-RAStreamJson -Json $one.Rows[0] -Extra $ra))
            foreach ($a in $one.Assets) { $assetItems.Add($a) }
        }
    }
    [pscustomobject]@{ Items = $items.ToArray(); AssetItems = $assetItems.ToArray(); Illegal = $illegal }
}

function Write-RAStreamRows {
    <#
        Writes ONE bucket's scored rows of the current report (-Bucket names it: '3/16', 'late:3/16', 'sub:...', 'page:2'),
        replacing whatever that bucket wrote before (a retry never doubles). -InView: the rows the workbook / mail view
        shows (by reference). -IsDetailedShape: the trace identity's asset part. Returns the rows written.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][string]$Bucket,
          [System.Collections.Generic.HashSet[object]]$InView, [bool]$IsDetailedShape, [string]$ConfigurationIdInputName = 'ConfigurationId',
          [string]$SortColumn = 'RiskScoreTotal_Weighted', [string]$FallbackSortColumn = 'RiskScoreTotal', [bool]$Dedup = $true, $Equivalence)
    $r = $Stream.Current
    if ($null -eq $r) { throw 'Write-RAStreamRows: no report started' }
    $p = @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId; Report = [string]$r.Ordinal; Bucket = $Bucket; RunKey = $Stream.RunKey }
    # a long step is never silent (live 2026-10-16: minutes per slice here, with no line): its time is said when it is long
    $delSw = [System.Diagnostics.Stopwatch]::StartNew()
    $removed = Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamDeleteBucketSql -Grain $Stream.Grain) -Params $p
    Add-RAStreamTime -Stream $Stream -Phase 'delete' -Seconds $delSw.Elapsed.TotalSeconds
    if ($delSw.Elapsed.TotalSeconds -ge 5) {
        $found = 0L; try { $found = [long](@($removed)[-1]) } catch { $found = 0L }
        & $Stream.Log 'INFO' ("the database checked for rows this query slice stored before (found {0}) in {1:N0} s" -f $found, $delSw.Elapsed.TotalSeconds)
    }
    # the rows written, in order (a null row is skipped), and whether the workbook / mail view shows each (by reference)
    $nn = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) { if ($null -ne $row) { $nn.Add($row) } }
    $rowsNn = $nn.ToArray(); $nn = $null
    $inv = New-Object 'bool[]' ($rowsNn.Count)
    for ($i = 0; $i -lt $rowsNn.Count; $i++) { $inv[$i] = $(if ($null -ne $InView) { $InView.Contains($rowsNn[$i]) } else { $true }) }
    $ctx = @{ Grain = $Stream.Grain; Ordinal = $r.Ordinal; Bucket = $Bucket; IsDetailedShape = $IsDetailedShape; ConfigurationIdInputName = $ConfigurationIdInputName
              SortColumn = $SortColumn; FallbackSortColumn = $FallbackSortColumn; Dedup = $Dedup; Equivalence = $Equivalence }
    $firstSeq = $Stream.Seq + 1
    # PERFORMANCE: a large Detailed slice's rows are turned into their stored form on several cores (RA-ParallelScore.ps1),
    # in contiguous parts put back in order -- the same items as one pass; $null = one pass here
    $built = $null
    $itemsSw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($Stream.Grain -eq 'Detailed' -and (Get-Command -Name Invoke-RAParallelStreamItems -ErrorAction SilentlyContinue)) {
        $built = Invoke-RAParallelStreamItems -Rows $rowsNn -FirstSeq $firstSeq -InView $inv -Context $ctx -DateCols $r.DateCols
    }
    if ($null -eq $built) { $built = ConvertTo-RAStreamRowItems -Rows $rowsNn -FirstSeq $firstSeq -InView $inv -Context $ctx -DateCols $r.DateCols }
    Add-RAStreamTime -Stream $Stream -Phase 'items' -Seconds $itemsSw.Elapsed.TotalSeconds
    $Stream.Seq += $rowsNn.Count
    $Stream.Illegal += [long]$built.Illegal
    $items = [string[]]$built.Items
    $assetItems = [string[]]$built.AssetItems
    if ($items.Count -eq 0) { return 0L }
    $insSw = [System.Diagnostics.Stopwatch]::StartNew()
    $chunk = [ref]$Stream.Chunk
    $what = 'Risk Analysis rows of {0} (bucket {1})' -f $r.Name, $Bucket
    if ($Stream.Grain -eq 'Detailed') {
        $n = Write-SIDataJsonRows -Invoke $Stream.Invoke -Sql (Get-RAStreamInsertFindingSql) -Items $items -Params @{ CollectionId = [string]$Stream.CollectionId } -ChunkChars $chunk -What $what
    } else {
        $n = Write-SIDataJsonRows -Invoke $Stream.Invoke -Sql (Get-RAStreamInsertSummaryRowSql) -Items $items -Params @{ CollectionTime = $Stream.TimeText } -ChunkChars $chunk -What $what
        if ($assetItems.Count) { $null = Write-SIDataJsonRows -Invoke $Stream.Invoke -Sql (Get-SIDataSummaryInsertAssetSql) -Items $assetItems -Params @{ CollectionTime = $Stream.TimeText } -ChunkChars $chunk -What ($what + ', impacted assets') }
    }
    $Stream.Chunk = $chunk.Value
    Add-RAStreamTime -Stream $Stream -Phase 'insert' -Seconds $insSw.Elapsed.TotalSeconds -Rows ([long]$n)
    [long]$n
}

function Add-RAStreamStage {
    <#
        A Summary report's RAW rows of one bucket, staged (sidata.RaStage) until every bucket is in: a group that spans buckets
        is combined later by the same rules (Merge-RASummaryBucketRows). Each row carries its group (the query's final
        summarize-by values, as the merge groups them); a report whose query has no readable summarize-by groups nothing.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][string]$Bucket)
    $r = $Stream.Current
    $p = @{ RunKey = $Stream.RunKey; Report = [string]$r.Ordinal; Bucket = $Bucket }
    $null = Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamDeleteStageSql) -Params $p
    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $Stream.Seq++
        # the staged JSON leaves empty values out: the row's columns are kept, so a page reads every row back with all of
        # them (an empty group column, e.g. cmdbId = '', must still be on the row or the merge refuses the group)
        foreach ($cp in $row.PSObject.Properties) { if ($r.StageColSet.Add($cp.Name)) { $r.StageCols.Add($cp.Name) } }
        $gk = Get-RASummaryGroupKey -Row $row -Plan $r.Plan
        if ($null -eq $gk) { $gk = 'row:' + $Stream.Seq }
        $j = ConvertTo-RAStreamJson -Row $row -DateCols $r.DateCols
        $items.Add((ConvertTo-SIDataJsonObject -Values ([ordered]@{ RaReport = $r.Ordinal; RaBucket = $Bucket; RaSeq = $Stream.Seq; GroupHash = (Get-RAStreamHash16 -Text $gk); RowJson = $j.Json })))
    }
    if ($items.Count -eq 0) { return 0L }
    $chunk = [ref]$Stream.Chunk
    $n = Write-SIDataJsonRows -Invoke $Stream.Invoke -Sql (Get-RAStreamInsertStageSql) -Items $items.ToArray() -Params @{ RunKey = $Stream.RunKey } -ChunkChars $chunk -What ('staged rows of ' + $r.Name)
    $Stream.Chunk = $chunk.Value
    [long]$n
}

function Invoke-RAStreamStagePages {
    <#
        Reads the staged report back a page of WHOLE groups at a time (a group never spans pages), in the order the groups
        were first written, and hands each page to -OnPage (param($rows, $pageNo)). The page size follows the measured size
        of the groups (-TargetChars of stored JSON a page) -- a small report is one page, as before. Then the stage is removed.
        Returns the pages.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][scriptblock]$OnPage, [long]$TargetChars = 64MB)
    $r = $Stream.Current
    $p = @{ RunKey = $Stream.RunKey; Report = [string]$r.Ordinal }
    $groups = @(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamStageGroupsSql) -Params $p -Mode 'reader')
    $groups = @($groups | ForEach-Object { $_ } | Where-Object { $_ })
    [string[]]$stageCols = if ($r.StageCols) { $r.StageCols.ToArray() } else { @() }
    $pages = 0
    $i = 0
    $from = [long]0
    while ($i -lt $groups.Count) {
        $chars = 0L; $j = $i
        while ($j -lt $groups.Count -and ($j -eq $i -or ($chars + [long]$groups[$j]['Chars']) -le $TargetChars)) { $chars += [long]$groups[$j]['Chars']; $j++ }
        $to = [long]$groups[$j - 1]['G0']
        $pp = @{ RunKey = $Stream.RunKey; Report = [string]$r.Ordinal; From = [string]$from; To = [string]$to }
        $rows = @(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamStagePageSql) -Params $pp -Mode 'reader')
        $objs = [System.Collections.Generic.List[object]]::new()
        foreach ($x in $rows) { foreach ($h in @($x)) { if ($h) { $objs.Add((ConvertFrom-RAStreamJson -Json ([string]$h['RowJson']) -Columns $stageCols -DateCols $r.DateCols)) } } }
        $rows = $null
        $pages++
        & $OnPage $objs.ToArray() $pages
        $objs = $null
        $from = $to; $i = $j
    }
    $null = Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamDeleteStageSql) -Params @{ RunKey = $Stream.RunKey; Report = [string]$r.Ordinal; Bucket = '*' }
    $r.Pages = $pages
    $pages
}

function Complete-RAStreamReport {
    <#
        The current report's buckets are all in: a finding two buckets both returned is kept once (the first), two assets
        that share a trace name in DIFFERENT buckets get the asset id at the end of it (as the whole-report pass gave it), and
        the rows the report stored are counted. Returns @{ Stored; Duplicates; Traces }.
    #>
    param([Parameter(Mandatory)]$Stream)
    $r = $Stream.Current
    $p = @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId; Report = [string]$r.Ordinal }
    # in pages through the report's key index, each its own short statement -- never one statement over the whole report
    # (live 2026-10-21: that one statement timed out three times over a report of 964,276 rows)
    $phSw = [System.Diagnostics.Stopwatch]::StartNew()
    $dup = [long](Invoke-RAStreamDedup -Stream $Stream -Params $p -What 'keeping once the findings two query slices both returned')
    Add-RAStreamTime -Stream $Stream -Phase 'dedup' -Seconds $phSw.Elapsed.TotalSeconds; $phSw.Restart()
    if ($dup -gt 0) { & $Stream.Log 'INFO' ("{0} finding(s) two query slices both returned are kept once" -f $dup) }
    $cand = @(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamTraceCandidatesSql -Grain $Stream.Grain) -Params $p -Mode 'reader' -What 'checking which findings share a trace name with another asset''s finding')
    $fix = [System.Collections.Generic.List[string]]::new()
    foreach ($x in $cand) {
        foreach ($h in @($x)) {
            if (-not $h) { continue }
            $row = ConvertFrom-RAStreamJson -Json ([string]$h['Json'])
            $b = Get-RATraceBase -Row $row -IsDetailed $true
            if (-not $b.AssetKey) { continue }
            $name = (@($b.Parts) + $b.AssetKey + 'SI') -join '-'
            $fix.Add((ConvertTo-SIDataJsonObject -Values ([ordered]@{ Id = [long]$h['Id']; N = $name; I = (Get-RATraceId -TraceName $name) })))
        }
    }
    $cand = $null
    $traces = 0L
    if ($fix.Count) {
        $chunk = [ref]$Stream.Chunk
        $traces = Write-SIDataJsonRows -Invoke $Stream.Invoke -Sql (Get-RAStreamTraceUpdateSql -Grain $Stream.Grain) -Items $fix.ToArray() -Params $p -ChunkChars $chunk -What 'trace names'
        & $Stream.Log 'INFO' ("{0} finding(s) share a trace name with another asset's finding in another query slice -- the asset id is added to theirs" -f $traces)
    }
    Add-RAStreamTime -Stream $Stream -Phase 'trace' -Seconds $phSw.Elapsed.TotalSeconds; $phSw.Restart()
    $stored = [long](Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamCountSql -Grain $Stream.Grain -Source Report) -Params $p -What 'counting the rows the report stored')
    Add-RAStreamTime -Stream $Stream -Phase 'count' -Seconds $phSw.Elapsed.TotalSeconds
    [pscustomobject]@{ Stored = $stored; Duplicates = $dup; Traces = $traces }
}

function Set-RAStreamReportStatus {
    <# #641: one report's verdict for this run (Complete | NotComplete | Unverified), with what the source said and what was stored. #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$ReportName, $Expected, $Retrieved, $Stored, [Parameter(Mandatory)][ValidateSet('Complete', 'NotComplete', 'Unverified')][string]$State, [string]$Reason = '',
          # #690 (34): the report's query fingerprint at this run (Get-RAReportQueryFingerprint; '' = not known)
          [string]$QueryHash = '',
          # #692: the fingerprint(s) it had before a declared structure-only change (Get-RAReportQueryFingerprintCarry, ';')
          [string]$QueryHashCarry = '')
    $p = @{ CollectionTime = $Stream.TimeText; Grain = $Stream.Grain; ReportName = $ReportName; State = $State; Reason = [string]$Reason; QueryHash = [string]$QueryHash; QueryHashCarry = [string]$QueryHashCarry
            Expected = $(if ($null -ne $Expected) { [string][long]$Expected } else { '' }); Retrieved = $(if ($null -ne $Retrieved) { [string][long]$Retrieved } else { '' })
            Stored = $(if ($null -ne $Stored) { [string][long]$Stored } else { '' }) }
    $null = Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamStatusSql) -Params $p
}

function Get-RAStreamLastGoodSql {
    # #709: per report, its last COMPLETE run before this one -- the rows it retrieved and its query fingerprint (where the
    # database has the column). One statement, the report names as JSON.
    @'
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
DECLARE @hasHash bit = CASE WHEN COL_LENGTH('sidata.RaReportStatus', 'QueryHash') IS NOT NULL THEN 1 ELSE 0 END;
DECLARE @sql nvarchar(max) = N'SELECT s.ReportName, CONVERT(nvarchar(30), s.RetrievedRows) AS Rows, ' + CASE WHEN @hasHash = 1 THEN N'ISNULL(s.QueryHash, N'''')' ELSE N'N''''' END + N' AS QueryHash
FROM sidata.RaReportStatus s
JOIN (SELECT ReportName, MAX(CollectionTime) AS T FROM sidata.RaReportStatus
      WHERE Grain = @g AND State = N''Complete'' AND CollectionTime < @t AND ReportName IN (SELECT [value] FROM OPENJSON(@n))
      GROUP BY ReportName) l ON l.ReportName = s.ReportName AND l.T = s.CollectionTime
WHERE s.Grain = @g;';
EXEC sp_executesql @sql, N'@t datetime2(3), @g nvarchar(16), @n nvarchar(max)', @t = @t, @g = @Grain, @n = @Names;
'@
}

function Read-RAStreamLastGood {
    <# #709: report -> @{ Rows; QueryHash } of its last complete run, for the reports named. @{} when none / not readable. #>
    param([Parameter(Mandatory)]$Stream, [string[]]$Reports = @())
    $out = @{}
    $names = @($Reports | Where-Object { "$_".Trim() } | Select-Object -Unique)
    if (-not $names.Count) { return $out }
    $rows = @(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamLastGoodSql) -Params @{ CollectionTime = $Stream.TimeText; Grain = $Stream.Grain; Names = (ConvertTo-Json -InputObject @($names) -Compress) } -Mode 'reader' -Attempts 1)
    foreach ($r in $rows) { if ($r -and [string]$r.ReportName) { $out[[string]$r.ReportName] = @{ Rows = [string]$r.Rows; QueryHash = [string]$r.QueryHash } } }
    $out
}

function Set-RAStreamReportNotComplete {
    <#
        Per-report loading: a report judged incomplete at the END of the run (the row-count guard, a lost bucket) after its
        own verdict was stored -- its verdict becomes NotComplete, the numbers it stored kept and the reason added; a report
        with no verdict yet gets one.
    #>
    # #741 (3): the reason that MADE it not complete comes FIRST, the report's own (complete) verdict text after it. It was
    # appended after that text, so a 2,000-character column and every list that shows the start of the reason (live
    # 2026-10-16: "every one of the report's 2 slices answered below the row limit ... (the w...") hid the cause.
    # -HoldKind (#901): a kind of THE list (#902, data-model/hold-kinds.locked.json: 'silent-source' | 'role-read') -- the
    # report was DELIBERATELY held at its last complete result, so it does not make the run partial for the publish
    # (sidata.CollectionHeldOnly). Set only when the report turns NotComplete here (a report already NotComplete for its own
    # reason keeps no kind); a database without the column ignores it. A kind that is not in the list is NOT written: the
    # report stays a real failure (the safe direction).
    # #902 (4): with a kind, -HeldRuns (the runs of this grain in a row it is held, Get-RAHoldStreak), -KeptResultAt (the
    # collection time of its kept, last complete result; '' = none) and -HoldNames (the silent tables, ';'-separated) are
    # stored with it -- each only where the database has its column.
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$ReportName, [string]$Reason = '', [string]$HoldKind = '',
          [int]$HeldRuns = 0, [string]$KeptResultAt = '', [string]$HoldNames = '')
    if ($HoldKind -and -not (Test-SIHoldKind -Kind $HoldKind)) { $HoldKind = '' }
    if (-not $HoldKind) { $HeldRuns = 0; $KeptResultAt = ''; $HoldNames = '' }
    if ($HoldNames.Length -gt 400) { $HoldNames = $HoldNames.Substring(0, 400) }
    $null = Invoke-RAStreamSql -Stream $Stream -Sql @'
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
DECLARE @n int = 0;
UPDATE sidata.RaReportStatus SET State = N'NotComplete', Reason = LEFT(COALESCE(NULLIF(@Reason, N'') + COALESCE(N' | ' + NULLIF(Reason, N''), N''), Reason), 2000)
WHERE CollectionTime = @t AND Grain = @Grain AND ReportName = @ReportName AND State <> N'NotComplete';
SET @n = @@ROWCOUNT;
IF @n = 0 AND NOT EXISTS (SELECT 1 FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = @Grain AND ReportName = @ReportName)
BEGIN
    INSERT sidata.RaReportStatus (CollectionTime, Grain, ReportName, State, Reason) VALUES (@t, @Grain, @ReportName, N'NotComplete', NULLIF(LEFT(@Reason, 2000), N''));
    SET @n = 1;
END
IF @n = 1 AND NULLIF(@HoldKind, N'') IS NOT NULL AND COL_LENGTH('sidata.RaReportStatus', 'HoldKind') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.RaReportStatus SET HoldKind = @k WHERE CollectionTime = @t AND Grain = @g AND ReportName = @r',
         N'@k nvarchar(32), @t datetime2(3), @g nvarchar(16), @r nvarchar(256)', @k = @HoldKind, @t = @t, @g = @Grain, @r = @ReportName;
IF @n = 1 AND NULLIF(@HoldKind, N'') IS NOT NULL AND COL_LENGTH('sidata.RaReportStatus', 'HeldRuns') IS NOT NULL AND TRY_CONVERT(int, @HeldRuns) > 0
    EXEC sp_executesql N'UPDATE sidata.RaReportStatus SET HeldRuns = @h WHERE CollectionTime = @t AND Grain = @g AND ReportName = @r',
         N'@h int, @t datetime2(3), @g nvarchar(16), @r nvarchar(256)', @h = @HeldRuns, @t = @t, @g = @Grain, @r = @ReportName;
IF @n = 1 AND NULLIF(@HoldKind, N'') IS NOT NULL AND COL_LENGTH('sidata.RaReportStatus', 'KeptResultAt') IS NOT NULL AND NULLIF(@KeptResultAt, N'') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.RaReportStatus SET KeptResultAt = CONVERT(datetime2(3), @k, 126) WHERE CollectionTime = @t AND Grain = @g AND ReportName = @r',
         N'@k nvarchar(40), @t datetime2(3), @g nvarchar(16), @r nvarchar(256)', @k = @KeptResultAt, @t = @t, @g = @Grain, @r = @ReportName;
IF @n = 1 AND NULLIF(@HoldKind, N'') IS NOT NULL AND COL_LENGTH('sidata.RaReportStatus', 'HoldNames') IS NOT NULL AND NULLIF(@HoldNames, N'') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.RaReportStatus SET HoldNames = @k WHERE CollectionTime = @t AND Grain = @g AND ReportName = @r',
         N'@k nvarchar(400), @t datetime2(3), @g nvarchar(16), @r nvarchar(256)', @k = @HoldNames, @t = @t, @g = @Grain, @r = @ReportName;
SELECT 1;
'@ -Params @{ CollectionTime = $Stream.TimeText; Grain = $Stream.Grain; ReportName = $ReportName; Reason = [string]$Reason; HoldKind = [string]$HoldKind
              HeldRuns = [int]$HeldRuns; KeptResultAt = [string]$KeptResultAt; HoldNames = [string]$HoldNames }
}

function Get-RAStreamHoldStreakSql {
    # #902 (4): per report named (@Names, JSON), its PREVIOUS verdict row of this grain (the newest before this collection):
    # its HoldKind and HeldRuns where the database has the columns (else NULL), and the collection time of its newest
    # COMPLETE row before this collection (the kept result). One statement.
    @'
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
IF OBJECT_ID('sidata.RaReportStatus') IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS NVARCHAR(32)) AS HoldKind, CAST(NULL AS INT) AS HeldRuns, CAST(NULL AS DATETIME2(3)) AS KeptResultAt WHERE 1 = 0;
    RETURN;
END
DECLARE @k nvarchar(200) = CASE WHEN COL_LENGTH('sidata.RaReportStatus', 'HoldKind') IS NOT NULL THEN N'p.HoldKind' ELSE N'CAST(NULL AS NVARCHAR(32))' END;
DECLARE @h nvarchar(200) = CASE WHEN COL_LENGTH('sidata.RaReportStatus', 'HeldRuns') IS NOT NULL THEN N'p.HeldRuns' ELSE N'CAST(NULL AS INT)' END;
DECLARE @sql nvarchar(max) = N'SELECT n.[value] AS ReportName, ' + @k + N' AS HoldKind, ' + @h + N' AS HeldRuns, c.T AS KeptResultAt
FROM OPENJSON(@n) n
OUTER APPLY (SELECT TOP (1) s.* FROM sidata.RaReportStatus s WHERE s.Grain = @g AND s.ReportName = n.[value] AND s.CollectionTime < @t ORDER BY s.CollectionTime DESC) p
OUTER APPLY (SELECT MAX(s.CollectionTime) AS T FROM sidata.RaReportStatus s WHERE s.Grain = @g AND s.ReportName = n.[value] AND s.State = N''Complete'' AND s.CollectionTime < @t) c;';
EXEC sp_executesql @sql, N'@t datetime2(3), @g nvarchar(16), @n nvarchar(max)', @t = @t, @g = @Grain, @n = @Names;
'@
}

function Read-RAStreamHoldStreak {
    <#
        #902 (4): the reports held ON PURPOSE this run -- -Holds report -> kind -- each with how many runs of this grain in a
        row it is held (Get-RAHoldStreak over its previous verdict row) and its kept result's collection time (UTC, $null =
        none). report -> @{ Kind; HeldRuns; KeptResultAt }. A database that cannot be read: every hold counts 1 run and its
        kept result is not known (no escalation by guess). Never throws.
    #>
    param([Parameter(Mandatory)]$Stream, [hashtable]$Holds = @{})
    $out = @{}
    $names = @(@($Holds.Keys) | Where-Object { "$_".Trim() } | Sort-Object -Unique)
    foreach ($n in $names) { $out[[string]$n] = [pscustomobject]@{ Kind = [string]$Holds[$n]; HeldRuns = 1; KeptResultAt = $null } }
    if (-not $names.Count) { return $out }
    try {
        $rows = @(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamHoldStreakSql) -Params @{ CollectionTime = $Stream.TimeText; Grain = $Stream.Grain; Names = (ConvertTo-Json -InputObject @($names) -Compress) } -Mode 'reader' -Attempts 1 | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        foreach ($r in $rows) {
            $rn = $null; $kept = $null
            if ($r -is [System.Collections.IDictionary]) { $rn = [string]$r['ReportName']; $kept = $r['KeptResultAt'] } else { $rn = [string]$r.ReportName; $kept = $r.KeptResultAt }
            if (-not $rn -or -not $out.ContainsKey($rn)) { continue }
            $out[$rn].HeldRuns = Get-RAHoldStreak -Kind $out[$rn].Kind -Previous $r
            if ($null -ne $kept -and -not ($kept -is [System.DBNull]) -and "$kept" -ne '') { try { $out[$rn].KeptResultAt = [datetime]::SpecifyKind([datetime]$kept, 'Utc') } catch { } }
        }
    } catch { }
    $out
}

# ------------------------------------------------------------------------------------------------------------------
#  #877 A REPORT WHOSE ROWS COULD NOT BE REMOVED IS HELD BACK -- NOT THE WHOLE RUN (owner 2026-10-22: "Hold back that
#  report"). A report whose rows of this run must not go out (it failed, or it is not in this run) has them removed in
#  measured batches (Remove-RAStreamRowsBatched). When even that fails, the run used to be marked broken and fail as a whole
#  -- the data sync then built nothing for the other reports. Now, on a Detailed run, ONLY THAT REPORT is held back:
#    * its verdict is NotComplete with the reason said first (Get-RAStreamHeldReason), and the database records which rows
#      of this run are held (sidata.RaReportStatus.HeldRaReport = the report's write ordinal, Set-RAStreamHeldReports);
#    * its rows of this run are never read as the report: every read of the run's result here leaves them out (the pager,
#      the counts, the trend: Get-RAStreamHeldFilter), and the data sync removes them FIRST when it takes the collection in,
#      before anything is built from it or it is marked complete (SI-DataSync.ps1 Remove-SIDataHeldReportRows) -- so the
#      groupings, the views, the key figures, the closes and the web app never see them;
#    * it keeps its last complete result and closes nothing of it (a NotComplete report, per-report scope 'reports');
#    * every other report loads; the run ends partial, never failed.
#  A Summary run, or a database without the column, keeps the strict rule: the stream is broken and the run fails.
# ------------------------------------------------------------------------------------------------------------------
$script:RAStreamHeldShort = 'held back -- its rows of this run could not be removed'

function Get-RAStreamHeldReason {
    <# PURE (#877). The plain reason a held-back report carries: the short words first, then the cause and what it means. #>
    param([string]$Cause = '')
    $c = ([string]$Cause -split "`n" | Select-Object -First 1)
    if ($null -eq $c) { $c = '' }
    $c = $c.Trim()
    if ($c.Length -gt 300) { $c = $c.Substring(0, 300) + '...' }
    $mid = if ($c) { ' ({0})' -f $c } else { '' }
    '{0}{1}: they are never read as the report -- it keeps its last complete result, nothing of it is closed, and the data sync removes those rows before it delivers this run' -f $script:RAStreamHeldShort, $mid
}

function Add-RAStreamHeldReport {
    <#
        #877. The report -Ordinal (-ReportName) could not have its rows of this run removed (-Cause). A Detailed run holds
        back ONLY that report: it is kept in the stream's held set and $true is returned. A Summary run (its collection is
        complete as soon as the run marks it -- nothing takes it in after the run) cannot: the stream is marked broken as
        before and $false is returned.
    #>
    param([Parameter(Mandatory)]$Stream, [string]$ReportName = '', [int]$Ordinal = 0, [string]$Cause = '')
    if ([string]$Stream.Grain -ne 'Detailed' -or $Ordinal -le 0 -or -not $ReportName) {
        if (-not $Stream.Broken) { $Stream.Broken = $(if ($Cause) { $Cause } else { 'the rows of a report could not be removed' }) }
        return $false
    }
    if ($null -eq $Stream.Held) { $Stream.Held = @{} }
    $Stream.Held[[int]$Ordinal] = @{ Report = $ReportName; Ordinal = [int]$Ordinal; Cause = [string]$Cause; Why = (Get-RAStreamHeldReason -Cause $Cause) }
    $true
}

function Remove-RAStreamHeldReport {
    <# #877. The report's rows of this run were removed after all (it ran again): it is no longer held back. #>
    param([Parameter(Mandatory)]$Stream, [int]$Ordinal = 0)
    if ($null -ne $Stream.Held -and $Stream.Held.ContainsKey([int]$Ordinal)) { $Stream.Held.Remove([int]$Ordinal) }
}

function Get-RAStreamHeldReports {
    <# #877. The reports held back this run, in ordinal order: @{ Report; Ordinal; Why } each (none = nothing). #>
    param($Stream)
    if ($null -eq $Stream -or -not ($Stream -is [System.Collections.IDictionary]) -or -not $Stream.ContainsKey('Held') -or $null -eq $Stream.Held) { return }
    foreach ($k in @($Stream.Held.Keys | Sort-Object { [int]$_ })) { $Stream.Held[$k] }
}

function Get-RAStreamHeldOrdinals {
    <# #877. The ordinals of the reports held back this run ([int[]], empty when none). #>
    param($Stream)
    [int[]]@(Get-RAStreamHeldReports -Stream $Stream | ForEach-Object { [int]$_.Ordinal })
}

function Get-RAStreamHeldSql {
    <#
        #877. ONE held-back report's verdict: NotComplete, the held reason first when it is not in the reason yet, and the
        ordinal of its rows of this run (HeldRaReport) -- the data sync removes those rows before it delivers the collection.
        Answers 1; 0 when the database does not have the column yet (the caller then keeps the strict rule: the run fails).
    #>
    @'
SET NOCOUNT ON;
IF COL_LENGTH('sidata.RaReportStatus', 'HeldRaReport') IS NULL BEGIN SELECT 0; RETURN; END
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
UPDATE sidata.RaReportStatus SET State = N'NotComplete',
       Reason = CASE WHEN CHARINDEX(@Short, ISNULL(Reason, N'')) > 0 THEN Reason ELSE LEFT(@Reason + COALESCE(N' | ' + NULLIF(Reason, N''), N''), 2000) END
WHERE CollectionTime = @t AND Grain = N'Detailed' AND ReportName = @ReportName;
IF @@ROWCOUNT = 0
    INSERT sidata.RaReportStatus (CollectionTime, Grain, ReportName, State, Reason) VALUES (@t, N'Detailed', @ReportName, N'NotComplete', LEFT(@Reason, 2000));
EXEC sp_executesql N'UPDATE sidata.RaReportStatus SET HeldRaReport = CONVERT(int, @r) WHERE CollectionTime = @t2 AND Grain = N''Detailed'' AND ReportName = @n',
     N'@r nvarchar(20), @t2 datetime2(3), @n nvarchar(256)', @r = @Report, @t2 = @t, @n = @ReportName;
SELECT 1;
'@
}

function Set-RAStreamHeldReports {
    <#
        #877. Records every report held back this run (Get-RAStreamHeldSql). Returns the held reports. THROWS when one cannot
        be recorded (a database without the column, or an error) -- the caller then marks the stream broken: rows that are
        not recorded as held could be read as the report, so the strict rule applies.
    #>
    param([Parameter(Mandatory)]$Stream)
    $held = @(Get-RAStreamHeldReports -Stream $Stream)
    foreach ($h in $held) {
        $p = @{ CollectionTime = $Stream.TimeText; ReportName = [string]$h.Report; Report = [string][int]$h.Ordinal; Reason = [string]$h.Why; Short = $script:RAStreamHeldShort }
        $ok = [int](@(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamHeldSql) -Params $p -Mode 'scalar')[-1])
        if ($ok -ne 1) { throw ("the database does not record held-back reports yet (the updater adds it with the data schema) -- report '{0}' cannot be held back" -f $h.Report) }
    }
    $held
}

function Get-RACompletenessVerdict {
    <#
        PURE (#641). A report's verdict from what the source said it holds (-Expected; $null = the count could not be had)
        and what its buckets returned (-Retrieved). Equal = Complete; different = NotComplete (the rows the source has and SI
        does not are UNKNOWN, not resolved); no count = Unverified (said, not a failure). @{ State; Reason }.
    #>
    param($Expected, [long]$Retrieved, [string]$CountError = '')
    if ($null -eq $Expected) {
        # every slice was read whole and only the count itself could not be had: said as that -- not verified, never a failure
        # and never "not complete" (the guards read NotComplete only)
        if ($CountError -match '^count not available') { return @{ State = 'Unverified'; Reason = ('the source''s ' + $CountError) } }
        $why = 'the source could not count the report''s rows in one query'
        if ($CountError) { $why += (' (' + $CountError + ')') }
        return @{ State = 'Unverified'; Reason = $why }
    }
    if ([long]$Expected -eq $Retrieved) { return @{ State = 'Complete'; Reason = '' } }
    # MORE rows than the count is no loss (owner: never fewer than the source; more is fine) -- the count query and the
    # buckets can see a row differently (a finding per target, a row that arrived between the count and the buckets)
    if ($Retrieved -gt [long]$Expected) { return @{ State = 'Complete'; Reason = ('the run retrieved {1} row(s), more than the source''s count of {0} -- nothing is missing' -f [long]$Expected, $Retrieved) } }
    @{ State = 'NotComplete'; Reason = ('the source holds {0} row(s) for this report, the run retrieved {1}' -f [long]$Expected, $Retrieved) }
}

function ConvertTo-RAReadCountTime {
    <# PURE (count timing). A count's time -- a [datetime], or its round-trip text as a part's hand-over carries it -- in UTC;
       $null when there is none or it cannot be read. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $t = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$t)) { return $t.ToUniversalTime() }
    $null
}

function Get-RAReadCountVerdict {
    <#
        PURE (count timing, live 2026-10-26: a false NOT COMPLETE -- the source counted 17 minutes after the read, behind the
        scoring and a slow insert, while the live data had moved). A report's verdict from TWO counts of the source taken
        right next to its read: -Before (C1, just before its first query slice) and -After (C2, just after its last), against
        what its slices returned (-Retrieved).
          * Complete when Retrieved >= the lower of the two counts (the data moved while the report was read);
          * NotComplete when Retrieved is below both -- a lost page or row is below both counts, so it still shows;
          * one count only: that count, judged exactly as Get-RACompletenessVerdict judges it; none: Unverified there
            (-CountError); the two counts equal: the same as one count.
        The reason names both counts and their times (-BeforeUtc / -AfterUtc). @{ State; Reason }.
    #>
    param($Before = $null, $After = $null, [long]$Retrieved, [string]$CountError = '', $BeforeUtc = $null, $AfterUtc = $null)
    if ($null -eq $Before -and $null -eq $After) { return (Get-RACompletenessVerdict -Expected $null -Retrieved $Retrieved -CountError $CountError) }
    if ($null -eq $Before) { return (Get-RACompletenessVerdict -Expected $After -Retrieved $Retrieved -CountError $CountError) }
    if ($null -eq $After) { return (Get-RACompletenessVerdict -Expected $Before -Retrieved $Retrieved -CountError $CountError) }
    $b = [long]$Before; $a = [long]$After
    if ($b -eq $a) { return (Get-RACompletenessVerdict -Expected $a -Retrieved $Retrieved -CountError $CountError) }
    $lo = [Math]::Min($b, $a)
    $at = { param($v) $t = ConvertTo-RAReadCountTime $v; if ($null -eq $t) { '' } else { ' (' + $t.ToString('HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) + 'Z)' } }
    $both = ('{0} row(s) before the read{1} and {2} after it{3}' -f $b, (& $at $BeforeUtc), $a, (& $at $AfterUtc))
    if ($Retrieved -ge $lo) {
        return @{ State = 'Complete'; Reason = ('the source held {0}; the run retrieved {1} -- at least the lower count, so nothing is missing (the source''s data moved while the report was read)' -f $both, $Retrieved) }
    }
    # 'the source holds N row(s) ... retrieved M' is the wording the cause and uplink texts read (SI-UplinkCauses.ps1)
    @{ State = 'NotComplete'; Reason = ('the source holds {0} row(s) for this report at the lower of its two counts -- it held {1}; the run retrieved {2}' -f $lo, $both, $Retrieved) }
}

function Merge-RAReadCounts {
    <#
        PURE (count timing, #831 B). A split report's two counts from its parts' own (-Counts: each part's @{ Before; After },
        each @{ Count; Error; How; At } -- a hashtable, or the map its hand-over's JSON gives back): the EARLIEST count taken
        before a part's read and the LATEST taken after one -- the two that frame the whole report's read. A count that could
        not be had is kept only when no part has one (its error is what the verdict's fallback reads). @{ Before; After }.
    #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Counts = @())
    $get = { param($o, $k) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { $o[$k] } else { $null } } elseif ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
    $out = @{ Before = $null; After = $null }
    foreach ($k in 'Before', 'After') {
        $best = $null; $bestT = $null; $noCount = $null
        foreach ($c in @($Counts)) {
            $x = & $get $c $k
            if ($null -eq $x) { continue }
            $n = & $get $x 'Count'
            $one = @{ Count = $(if ($null -ne $n) { [long]$n } else { $null }); Error = [string](& $get $x 'Error'); How = 'whole'; At = (ConvertTo-RAReadCountTime (& $get $x 'At')) }
            if ($null -eq $n) { if ($null -eq $noCount) { $noCount = $one }; continue }
            $t = $one.At
            $take = ($null -eq $best)
            if (-not $take -and $null -ne $t -and $null -ne $bestT) { $take = $(if ($k -eq 'Before') { $t -lt $bestT } else { $t -gt $bestT }) }
            if ($take) { $best = $one; $bestT = $t }
        }
        $out[$k] = $(if ($null -ne $best) { $best } else { $noCount })
    }
    $out
}

function Get-RALostSliceVerdict {
    <#
        PURE (#741 (3)). A report one of whose query slices could not be read (-Lost: the report's lost-slice reasons,
        $script:_RABucketLoss) is NOT complete -- decided at its own verdict, with the slices named. $null when no slice was
        lost. Before this the verdict took the slices' rows as the source's count ("every one of the report's N slices
        answered below the row limit") although a slice had NOT answered: the report was stored Complete with ExpectedRows =
        what the other slices returned (0 in the live case, 2026-10-16), and only the end of the run turned it NotComplete,
        its cause added after that text where no list showed it.
    #>
    param([AllowEmptyCollection()][AllowNull()][string[]]$Lost = @())
    $l = @(@($Lost) | Where-Object { $_ })
    if ($l.Count -eq 0) { return $null }
    $first = [string]$l[0]
    if ($first.Length -gt 300) { $first = $first.Substring(0, 300) + '...' }
    @{ State = 'NotComplete'; Reason = ('{0} query slice(s) of the report could not be read ({1}) -- the rows of those slices are unknown, not resolved, so the source''s count is not taken from what the other slices returned' -f $l.Count, $first) }
}

function Set-RAStreamAccount {
    <#
        What ONE slice of the current report did with the rows it retrieved (#641 item 4): In (rows into the scoring path),
        Scope (left out by the report's tier / severity scope), Excluded (left out by the default exclusion rules), Duplicate
        (the scoring kept one of rows with the same finding key), Written (stored). A slice written again replaces its own.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Bucket, [Parameter(Mandatory)][hashtable]$Values)
    $r = $Stream.Current; if ($null -eq $r) { return }
    if ($null -eq $r.Account) { $r.Account = @{} }
    if (-not $r.Account.ContainsKey($Bucket)) { $r.Account[$Bucket] = @{ In = 0L; Scope = 0L; Excluded = 0L; Duplicate = 0L; Written = 0L } }
    foreach ($k in $Values.Keys) { $r.Account[$Bucket][$k] = [long]$Values[$k] }
}

function Get-RAStreamAccountTotal {
    <# PURE. The report's slices' accounts added up: @{ In; Scope; Excluded; Duplicate; Written }. #>
    param([hashtable]$Account)
    # #673: Pre (rows retrieved before the Defender filter) and Handed (removed by it, per key kind) -- plan B only
    $t = @{ In = 0L; Scope = 0L; Excluded = 0L; Duplicate = 0L; Written = 0L; Pre = 0L; Handed = 0L; HandedName = 0L; HandedId = 0L; HandedAk = 0L }
    if ($Account) { foreach ($b in $Account.Values) { foreach ($k in @($t.Keys)) { if ($b.ContainsKey($k)) { $t[$k] += [long]$b[$k] } } } }
    $t
}

function Get-RAStoredVerdict {
    <#
        PURE (#641 item 4). A report whose rows the source fully returned (Retrieved = Expected) is COMPLETE only when what
        it STORED is what it retrieved less what is accounted for, each named: the report's tier / severity scope, the default
        exclusion rules, a finding the scoring keeps once, a finding two slices both returned (kept once). Any other
        difference is rows LOST between retrieval and storage -> NotComplete, with the numbers. @{ State; Reason }.
    #>
    # -Handed (#673 plan B): rows the engine removed because the Defender recommendation report lists them -- a named
    # category like the others, so a normal run stays Complete
    param([long]$Retrieved, [long]$Stored, [hashtable]$Total, [long]$CrossSliceDuplicates = 0, [long]$Handed = 0)
    $t = if ($Total) { $Total } else { @{ Scope = 0L; Excluded = 0L; Duplicate = 0L } }
    $explained = [long]$t.Scope + [long]$t.Excluded + [long]$t.Duplicate + $CrossSliceDuplicates + $Handed
    $why = [System.Collections.Generic.List[string]]::new()
    if ($Handed -gt 0) { $why.Add(('{0} handed to the Defender recommendation report' -f $Handed)) }
    if ([long]$t.Scope -gt 0) { $why.Add(('{0} outside the report''s tier / severity scope' -f $t.Scope)) }
    if ([long]$t.Excluded -gt 0) { $why.Add(('{0} left out by the default exclusion rules' -f $t.Excluded)) }
    if ([long]$t.Duplicate -gt 0) { $why.Add(('{0} duplicate finding(s) kept once by the scoring' -f $t.Duplicate)) }
    if ($CrossSliceDuplicates -gt 0) { $why.Add(('{0} finding(s) two query slices both returned, kept once' -f $CrossSliceDuplicates)) }
    $lost = $Retrieved - $explained - $Stored
    if ($lost -eq 0) {
        $reason = if ($why.Count) { 'stored {0} of {1} retrieved: {2}' -f $Stored, $Retrieved, ($why -join ', ') } else { '' }
        return @{ State = 'Complete'; Reason = $reason }
    }
    $acc = if ($why.Count) { ' (accounted for: ' + ($why -join ', ') + ')' } else { '' }
    @{ State = 'NotComplete'; Reason = ('the run retrieved {0} row(s) and stored {1}: {2} row(s) are neither stored nor accounted for{3}' -f $Retrieved, $Stored, $lost, $acc) }
}

function Get-RAReportCountKql {
    <#
        PURE (#641). The count query of ONE slice of a report (-Query: that slice's query): '| count' -- or, with -GroupKeys
        (a Summary report whose final summarize-by the merge groups on), each group's identity (its group values, lower-cased
        as the merge compares them, hashed), so a group that spans slices is counted once.
    #>
    param([Parameter(Mandatory)][string]$Query, [string[]]$GroupKeys)
    $q = $Query.TrimEnd().TrimEnd(';').TrimEnd()
    $keys = @($GroupKeys | Where-Object { $_ })
    if ($keys.Count -eq 0) { return $q + "`n| count" }
    $parts = @($keys | ForEach-Object { 'tostring({0})' -f $_ })
    $e = if ($parts.Count -eq 1) { $parts[0] } else { 'strcat_delim("|~|", {0})' -f ($parts -join ', ') }
    $q + "`n| project SIGroupHash = hash_sha256(tolower($e))`n| distinct SIGroupHash"
}

function Measure-RAReportExpectedRows {
    <#
        #641. What the SOURCE holds for a report, asked the way the report's rows were asked: -BucketCount 1 = the query
        whole; more = slice by slice. -RunSlice gets the slice's index (0..n-1) and returns @{ Ok; Rows; Error } of THAT
        slice's count query (Get-RAReportCountKql) -- the same bucket filter and the same per-slice lookup cut as the slice's
        own query, so a count never carries what the query itself could not (live 2026-10-13: the unbucketed count carried
        every lookup whole -- "413 Request Entity Too Large", 8 reports Unverified).
          Detailed (no -GroupKeys): the slices' counts added -- the slices partition the rows.
          Summary (-GroupKeys): the DISTINCT groups over every slice -- a group that spans slices is one row after the merge.
        A slice that cannot be counted = no count: @{ Count = $null; Error } (the report is then Unverified, never Complete).
    #>
    param([Parameter(Mandatory)][int]$BucketCount, [Parameter(Mandatory)][scriptblock]$RunSlice, [string[]]$GroupKeys)
    $n = [Math]::Max(1, $BucketCount)
    $byGroup = (@($GroupKeys | Where-Object { $_ }).Count -gt 0)
    $sum = 0L
    $groups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    for ($i = 0; $i -lt $n; $i++) {
        $what = if ($n -gt 1) { 'slice {0}/{1}: ' -f ($i + 1), $n } else { '' }
        $r = $null
        try { $r = & $RunSlice $i } catch { return @{ Count = $null; Error = ($what + $_.Exception.Message) } }
        if ($null -eq $r -or -not $r.Ok) { return @{ Count = $null; Error = ($what + $(if ($r) { [string]$r.Error } else { 'no answer' })) } }
        $rows = @(@($r.Rows) | Where-Object { $null -ne $_ })
        if ($byGroup) {
            foreach ($x in $rows) {
                $p = $x.PSObject.Properties['SIGroupHash']
                if (-not $p) { return @{ Count = $null; Error = ($what + 'the count returned no group column') } }
                [void]$groups.Add([string]$p.Value)
            }
            continue
        }
        if ($rows.Count -eq 0) { continue }
        $c = $null
        foreach ($nm in 'Count', 'count_', 'count') { $pp = $rows[0].PSObject.Properties[$nm]; if ($pp -and $null -ne $pp.Value) { $c = [long]$pp.Value; break } }
        if ($null -eq $c) { return @{ Count = $null; Error = ($what + 'the count returned no Count column') } }
        $sum += $c
    }
    if ($byGroup) { return @{ Count = [long]$groups.Count; Error = '' } }
    @{ Count = $sum; Error = '' }
}

function Test-RACountRefusedForSize {
    <# PURE. Did the service refuse a count request for its SIZE (413 Request Entity Too Large -- the request, not the
       answer)? Only then can a count in more parts get through: each part carries only its own slice of the inlined data. #>
    param([string]$Message)
    [bool]([string]$Message -match '(?i)413 Request Entity Too Large|RequestEntityTooLarge|request entity too large')
}

function Measure-RAReportExpectedRowsInParts {
    <#
        The report's count IN PARTS, the way its read is split (live 2026-10-21, the largest tenant: an attack-path report's
        count "could not count the report's rows in one query (413 Request Entity Too Large)" and was left Unverified, while
        its read had been split and was whole). The count is asked in -Start parts (the report's own slice filter and the
        per-slice cut of its inlined lookups, Measure-RAReportExpectedRows); when a part is refused for its SIZE again and
        -CanSplitFiner { param($Error, $Parts) } says a finer split still makes the request smaller, it is asked again in
        twice as many parts. The parts' counts add up to the count (a Summary report: the distinct groups over every part).
        -RunSlice { param($Index, $Parts) } answers one part's count (@{ Ok; Rows; Error }). @{ Count; Error; Parts }:
        Count $null = no count (said, never a failure -- the report is Unverified).
    #>
    param([Parameter(Mandatory)][int]$Start, [Parameter(Mandatory)][scriptblock]$RunSlice, [string[]]$GroupKeys = @(), [scriptblock]$CanSplitFiner)
    $k = [Math]::Max(2, $Start)
    # (named apart: the scriptblock below runs inside Measure-RAReportExpectedRows, whose own -RunSlice would hide this one)
    $__cpRun = $RunSlice
    while ($true) {
        $__cpParts = $k
        $one = { param($i) & $__cpRun $i $__cpParts }
        $m = Measure-RAReportExpectedRows -BucketCount $k -RunSlice $one -GroupKeys $GroupKeys
        if ($null -ne $m.Count) { return @{ Count = [long]$m.Count; Error = ''; Parts = $k } }
        $err = [string]$m.Error
        $finer = $false
        if ((Test-RACountRefusedForSize -Message $err) -and $CanSplitFiner) { try { $finer = [bool](& $CanSplitFiner $err ($k * 2)) } catch { $finer = $false } }
        if (-not $finer) { return @{ Count = $null; Error = $err; Parts = $k } }
        $k = $k * 2
    }
}

function Complete-RAStream {
    <# The run's END: every bucket of every report is in -- the collection is marked so (see Get-RAStreamCompleteSql). Throws when it cannot be. #>
    # -Scope (per-report loading): what the run's incompleteness covers -- 'reports' (every cause is a named report, whose
    # verdict is NotComplete) or 'run'; '' = a complete run. Stored on a Detailed collection (sidata.Collection.RaPartialScope)
    # when the database has the column; the data sync and the closes act per report only on 'reports'.
    param([Parameter(Mandatory)]$Stream, [string]$Partial = '', [ValidateSet('', 'reports', 'run')][string]$Scope = '')
    $p = @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId }
    $rows = [long](Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamCountSql -Grain $Stream.Grain -Source All) -Params $p)
    $p['Rows'] = [string]$rows; $p['Partial'] = [string]$Partial
    $n = [int](Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamCompleteSql -Grain $Stream.Grain) -Params $p)
    if ($n -ne 1) { throw ("the run's result could not be marked complete in the database ({0} row(s))" -f $rows) }
    if ($Scope -and $Stream.Grain -eq 'Detailed') {
        $null = Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamScopeSql) -Params @{ CollectionId = [string]$Stream.CollectionId; Scope = $Scope }
    }
    $rows
}

function Get-RAStreamScopeSql {
    <# Per-report loading: the run's partial scope on its Detailed collection; a database without the column is left as it is. #>
    @'
IF COL_LENGTH('sidata.Collection', 'RaPartialScope') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.Collection SET RaPartialScope = @s WHERE CollectionId = CONVERT(int, @c)', N'@s nvarchar(16), @c nvarchar(20)', @s = @Scope, @c = @CollectionId;
SELECT 1;
'@
}

function Get-RAStreamVerdictsFinalSql {
    <#
        #725 THE VERDICTS ARE FINAL: written on a Detailed collection right before it is marked in, once the guards, the
        per-report verdicts and the Log Analytics post are settled and nothing holds the run -- with the run's partial reason
        and scope. Only a collection carrying it may be completed by the data sync if the run stops before marking it in.
        A database without the column is left as it is.
    #>
    @'
IF COL_LENGTH('sidata.Collection', 'RaVerdictsFinalAt') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.Collection SET RaVerdictsFinalAt = SYSUTCDATETIME(), RaPartialReason = NULLIF(LEFT(@p, 2000), N'''')
        WHERE CollectionId = CONVERT(int, @c) AND Status = N''Loading'' AND RaCompletedAt IS NULL;
        IF COL_LENGTH(''sidata.Collection'', ''RaPartialScope'') IS NOT NULL AND NULLIF(@s, N'''') IS NOT NULL
            EXEC sp_executesql N''UPDATE sidata.Collection SET RaPartialScope = @s2 WHERE CollectionId = CONVERT(int, @c2)'', N''@s2 nvarchar(16), @c2 nvarchar(20)'', @s2 = @s, @c2 = @c;',
         N'@p nvarchar(2000), @s nvarchar(16), @c nvarchar(20)', @p = @Partial, @s = @Scope, @c = @CollectionId;
SELECT 1;
'@
}

function Set-RAStreamVerdictsFinal {
    <# #725: the marker (Get-RAStreamVerdictsFinalSql) on a Detailed collection; a Summary collection has none. Throws on a database error. #>
    param([Parameter(Mandatory)]$Stream, [string]$Partial = '', [string]$Scope = '')
    if ($Stream.Grain -ne 'Detailed') { return }
    $null = Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamVerdictsFinalSql) -Params @{ CollectionId = [string]$Stream.CollectionId; Partial = [string]$Partial; Scope = [string]$Scope }
}

function Get-RAPartialScope {
    <#
        PURE. Per-report loading: does every cause of this run's incompleteness belong to a NAMED report? 'reports' when the
        only causes are reports (incomplete reports, lost buckets -- they name their report); 'run' when anything else made
        the run partial (a Log Analytics post that failed, a profile the run was built on that was partial); '' when nothing
        did. -Reports: the incomplete report names; -RunCauses: the causes that are not one report (their texts).
    #>
    param([AllowEmptyCollection()][string[]]$Reports = @(), [AllowEmptyCollection()][string[]]$RunCauses = @())
    if (@($RunCauses | Where-Object { "$_".Trim() }).Count) { return 'run' }
    if (@($Reports | Where-Object { "$_".Trim() }).Count) { return 'reports' }
    ''
}

# #899: the CI fields that ARE the Entra role read -- a report whose logic reads one of them cannot be complete in a run built
# on a role read that was not complete. The tier fields are not here: they carry the previous values, so a tier-only report
# stays as it is (owner decision 2026-10-25).
$script:RARoleReadFields = @('si_entra_roles_permanent', 'si_entra_roles_eligible', 'si_entra_role_scopes', 'si_is_shadow_admin',
                             'EntraRoles_Permanent', 'EntraRoles_Eligible', 'IsShadowAdmin')

function Get-RARoleReadReports {
    <#
        PURE. #899: of -Names (the reports of this run), the ones whose query READS a role list or shadow admin. The shared CI
        projection every identity report carries (si_x = todynamic(column_ifexists("si_x", ...))) and a plain output rename
        (EntraRoles_Permanent = si_entra_roles_permanent) are not a read: only a use beyond them counts. -Reports: the report
        definitions (ReportName + ReportQuery). Returns the names, sorted. A report without a query is left out.
    #>
    param([AllowEmptyCollection()][object[]]$Reports = @(), [AllowEmptyCollection()][string[]]$Names = @())
    $want = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($Names)) { if ($n) { [void]$want.Add([string]$n) } }
    $f = ($script:RARoleReadFields | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $proj = '(?i)\b(' + $f + ')\s*=\s*(todynamic|tobool|tostring|toint)\(\s*column_ifexists\(\s*"(' + $f + ')"[^\n]*'
    $rename = '(?i)\bEntraRoles_(Permanent|Eligible)\s*=\s*si_entra_roles_(permanent|eligible)\b'
    $use = '(?i)\b(' + $f + ')\b'
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Reports)) {
        if ($null -eq $r) { continue }
        $name = [string]$r.ReportName; if (-not $name -or ($want.Count -gt 0 -and -not $want.Contains($name))) { continue }
        $q = [string]$r.ReportQuery; if (-not $q.Trim()) { continue }
        $q = [regex]::Replace([regex]::Replace($q, $proj, ''), $rename, '')
        if ([regex]::IsMatch($q, $use)) { $out.Add($name) }
    }
    @($out | Sort-Object -Unique)
}

function Resolve-RARoleReadUpstream {
    <#
        PURE. #899: a profile run that is partial ONLY because the identity run's Entra role read was not complete
        (Get-SIUpstreamOutcome RolesOnly) does not hold the whole run: the reports that read role lists or shadow admin
        (Get-RARoleReadReports) are NOT COMPLETE -- named reports, so the per-report freeze keeps what they found and closes
        nothing of them -- and the upstream outcome becomes 'success' (no run cause). Anything else is returned as it is.
        FAIL-SAFE (coordinator review 2026-10-25): no report found (a renamed field, a changed projection -- the match finds
        nothing) is NEVER "nothing is frozen": the outcome is returned as it is, so the whole run stays partial and closes
        nothing, as before this change.
        Returns @{ Outcome; Reports (the reports made not complete); Why }.
    #>
    param($Outcome, [AllowEmptyCollection()][object[]]$Reports = @(), [AllowEmptyCollection()][string[]]$Names = @())
    $none = [pscustomobject]@{ Outcome = $Outcome; Reports = [string[]]@(); Why = '' }
    if ($null -eq $Outcome -or [string]$Outcome.ExitReason -eq 'success') { return $none }
    $ro = $Outcome.PSObject.Properties['RolesOnly']
    if (-not $ro -or -not [bool]$ro.Value) { return $none }
    $names = [string[]]@(Get-RARoleReadReports -Reports $Reports -Names $Names)
    if ($names.Count -eq 0) { return $none }
    $why = 'the newest identity run could not read the Entra role assignments completely -- every identity kept its stored roles, so what this report found is kept and nothing of it is closed'
    [pscustomobject]@{ Outcome = [pscustomobject]@{ ExitReason = 'success'; Message = ''; RolesOnly = $false }; Reports = $names; Why = $why }
}

function Get-RALaCopySql {
    <#
        #743 (1) THE LOG ANALYTICS COPY IS COMPLETE: the mark on the collection (sidata.Collection / sidata.SummaryLoad
        LaCopyAt), written ONLY after every row of the run went to Log Analytics -- a reader of the copy can tell a copy in
        full from one still arriving or broken off. A database without the column is left as it is.
    #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($Grain -eq 'Summary') {
        return @'
IF COL_LENGTH('sidata.SummaryLoad', 'LaCopyAt') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.SummaryLoad SET LaCopyAt = SYSUTCDATETIME() WHERE CollectionTime = CONVERT(datetime2(3), @t, 126)', N'@t nvarchar(40)', @t = @CollectionTime;
SELECT 1;
'@
    }
    @'
IF COL_LENGTH('sidata.Collection', 'LaCopyAt') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.Collection SET LaCopyAt = SYSUTCDATETIME() WHERE CollectionId = CONVERT(int, @c)', N'@c nvarchar(20)', @c = @CollectionId;
SELECT 1;
'@
}

function Complete-RALaCopy {
    <#
        #743 (1), owner 2026-10-17: DELIVER FROM SQL FIRST, THE LOG ANALYTICS COPY AFTER. Called once the collection is
        delivered from the database and the copy was sent. NEVER throws. Returns @{ Level (INFO | WARN | ''); Text; Partial;
        Causes; Marked }:
          -Sent $false        no copy is made on this install (Log Analytics off, or no rows): nothing marked, nothing said
          a copy in full      (nothing -Refused / -NotDelivered) -> the mark on the collection (Get-RALaCopySql), one line
          a copy NOT in full  -> the run is PARTIAL: one plain sentence, the causes for the run record; never a failed run,
                                 never a held collection -- the database holds the result and everything that reads it
                                 there has it
        -Delivered $false (the collection itself could not be completed): the copy is never marked.
    #>
    param($Stream, [bool]$Sent, [AllowEmptyCollection()][object[]]$Refused = @(), [AllowEmptyCollection()][object[]]$NotDelivered = @(), [bool]$Delivered = $true)
    $out = [ordered]@{ Level = ''; Text = ''; Partial = $false; Causes = @(); Marked = $false }
    try {
        if (-not $Sent) { return [pscustomobject]$out }
        $why = @(@($Refused) + @($NotDelivered) | Where-Object { $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        if ($why.Count) {
            $out.Level = 'WARN'; $out.Partial = $true
            $out.Causes = @('the Log Analytics copy of this run is not complete: ' + ($why -join ' | '))
            $out.Text = ('This run''s result is complete in the database and delivered: the web app, the mails and the connectors use it. Its copy in Log Analytics is NOT complete ({0}), so workbooks and Log Analytics queries do not show this run in full -- the run is recorded as partial, and the next run sends a new copy.' -f ($why -join ' | '))
            return [pscustomobject]$out
        }
        if (-not $Delivered -or -not $Stream) { return [pscustomobject]$out }
        $null = Invoke-RAStreamSql -Stream $Stream -Sql (Get-RALaCopySql -Grain $Stream.Grain) -Params @{ CollectionTime = [string]$Stream.TimeText; CollectionId = [string]$Stream.CollectionId }
        $out.Marked = $true; $out.Level = 'INFO'
        $out.Text = 'the Log Analytics copy of this run is complete -- marked on its collection'
    } catch {
        $out.Level = 'INFO'
        $out.Text = ('the Log Analytics copy went out in full; its mark could not be written ({0}) -- the result in the database is not affected' -f $_.Exception.Message)
    }
    [pscustomobject]$out
}

function Get-RAStreamCount {
    param([Parameter(Mandatory)]$Stream, [ValidateSet('All', 'View')][string]$Source = 'All')
    [long](Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamCountSql -Grain $Stream.Grain -Source $Source -Held @(Get-RAStreamHeldOrdinals -Stream $Stream)) -Params @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId })
}

function Get-RAStreamColumnsByOrdinal {
    param([Parameter(Mandatory)]$Stream)
    $m = @{}
    foreach ($k in $Stream.Reports.Keys) { $r = $Stream.Reports[$k]; $m[[int]$r.Ordinal] = $r }
    $m
}

function New-RARowPager {
    <#
        The run's rows a PAGE at a time, in the final order, for everything after the queries (the workbook, the JSON file,
        Log Analytics, the AI summary, the KPIs, the findings). $pager.Next() returns the next page (an array) or $null.
          -Stream: read from SQL -- -Source All (every row), View (the rows the workbook and mail show), FindingKey (grouped
           by the SI finding key). Each row is shaped as its report's rows were (every report column, absent = $null).
          -Rows: no database -- the rows in memory, as one page (the result as before).
        The page size follows the measured size of the rows (-TargetChars of stored JSON per page).
          -ReadAhead (#738): while a page is decoded and delivered, the NEXT page is read from SQL on another thread (the same
           statement, the same parameters, the same connection the seam makes -- New-SIDataSqlInvoke's SIConnectionInfo). A
           seam without it, or a read-ahead that fails, reads the page here as before (with its retries). One page ahead,
           as stored text -- never decoded rows. $pager.Close() ends it (called by the delivery; also at the last page).
    #>
    param($Stream, [AllowNull()][AllowEmptyCollection()][object[]]$Rows, [ValidateSet('All', 'View', 'FindingKey')][string]$Source = 'All', [long]$TargetChars = 32MB,
          [switch]$ReadAhead, [switch]$OneCore)
    # -OneCore (#744): every page decoded here, on this thread (never on the cores of RA-ParallelScore.ps1)
    $st = @{ Stream = $Stream; Rows = $Rows; Source = $Source; Done = $false; First = $true; Sort = 0.0; Seq = 0L; FKey = ''; Take = 2000; Target = $TargetChars; Read = 0L; ByOrd = $null; OneCore = [bool]$OneCore
             ReadAhead = $null; Ahead = $null; AheadPages = 0; AheadFallbacks = 0; FetchSec = 0.0; DecodeSec = 0.0 }
    if ($Stream) { $st.ByOrd = Get-RAStreamColumnsByOrdinal -Stream $Stream }
    if ($Stream -and $ReadAhead -and $Stream.Invoke -and $Stream.Invoke.PSObject.Properties['SIConnectionInfo']) { $st.ReadAhead = $Stream.Invoke.PSObject.Properties['SIConnectionInfo'].Value }
    $o = [pscustomobject]@{ State = $st }
    $o | Add-Member -MemberType ScriptMethod -Name Close -Value { Close-RARowPagerReadAhead -State $this.State }
    $o | Add-Member -MemberType ScriptMethod -Name Next -Value {
        $s = $this.State
        if ($s.Done) { Close-RARowPagerReadAhead -State $s; return $null }
        if ($null -eq $s.Stream) {
            $s.Done = $true
            if ($null -eq $s.Rows) { return $null }
            return , @($s.Rows)
        }
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $hs = $null
        if ($s.Ahead) { $hs = Receive-RARowPagerReadAhead -State $s }
        if ($null -eq $hs) {
            $q = Get-RARowPagerQuery -State $s
            $res = @(Invoke-RAStreamSql -Stream $s.Stream -Sql $q.Sql -Params $q.Params -Mode 'reader')
            $hs = @($res | ForEach-Object { $_ } | Where-Object { $_ })
            $res = $null
        }
        $s.FetchSec += $clock.Elapsed.TotalSeconds
        if ($hs.Count -eq 0) { $s.Done = $true; Close-RARowPagerReadAhead -State $s; return $null }
        $chars = 0L
        foreach ($h in $hs) { $chars += ([string]$h['Json']).Length }
        $last = $hs[$hs.Count - 1]
        $s.First = $false
        $s.Seq = [long]$last['Seq']
        if ($s.Source -eq 'FindingKey') { $s.FKey = [string]$last['FKey'] } else { $s.Sort = [double]$last['RaSort'] }
        if ($hs.Count -lt $s.Take) { $s.Done = $true }
        # measured, not fixed: the next page is sized from this one's stored size (working rule 5)
        if ($chars -gt 0) { $s.Take = [int][Math]::Max(1, [Math]::Min(1000000, [Math]::Floor($s.Take * ([double]$s.Target / [double]$chars)))) }
        # the next page is read while this one is decoded and delivered
        if (-not $s.Done -and $s.ReadAhead) { Start-RARowPagerReadAhead -State $s }
        $clock.Restart()
        # #744: a large page is decoded on several cores (RA-ParallelScore.ps1: the same function per row, in the page's order)
        $dec = $null
        if (-not $s.OneCore -and (Get-Command -Name Invoke-RAParallelDecode -ErrorAction SilentlyContinue)) { $dec = Invoke-RAParallelDecode -Stored $hs -ByOrd $s.ByOrd }
        if ($null -eq $dec) {
            $out = [System.Collections.Generic.List[object]]::new([int]($hs.Count))
            foreach ($h in $hs) {
                $rep = $s.ByOrd[[int]$h['RaReport']]
                $cols = $null; $dc = $null; if ($rep) { $cols = $rep.Columns.ToArray(); $dc = $rep.DateCols }
                $out.Add((ConvertFrom-RAStreamJson -Json ([string]$h['Json']) -Columns $cols -DateCols $dc))
            }
            $dec = $out.ToArray(); $out = $null
        }
        $hs = $null
        $s.DecodeSec += $clock.Elapsed.TotalSeconds
        $s.Read += $dec.Count
        if ($s.Done) { Close-RARowPagerReadAhead -State $s }
        return , $dec
    }
    $o
}

function Get-RARowPagerQuery {
    <# The statement + parameters of the pager's NEXT page (the first page, or a page after the last key read). #>
    param([Parameter(Mandatory)][hashtable]$State)
    $s = $State
    $p = @{ CollectionTime = $s.Stream.TimeText; CollectionId = [string]$s.Stream.CollectionId; Take = [string]$s.Take; First = $(if ($s.First) { '1' } else { '0' })
            Sort = $s.Sort.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture); Seq = [string]$s.Seq; FKey = [string]$s.FKey }
    # #877: a report held back this run is never read as the result (the workbook, the JSON file, Log Analytics, the AI
    # summary, the KPIs, the findings)
    @{ Sql = (Get-RAStreamPageSql -Grain $s.Stream.Grain -Source $s.Source -After:(-not $s.First) -Held @(Get-RAStreamHeldOrdinals -Stream $s.Stream)); Params = $p }
}

function Get-RARowPagerReadAheadScript {
    <# The read on the other thread: the seam's 'reader' (New-SIDataSqlInvoke), as text -- one connection, the statement,
       every row as a hashtable of its columns. #>
    @'
param([string]$ConnectionString, [string]$AccessToken, [int]$CommandTimeout, [string]$Sql, [hashtable]$Params)
$cn = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
if ($AccessToken) { $cn.AccessToken = $AccessToken }
try {
    $cn.Open()
    $cmd = $cn.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = $CommandTimeout
    foreach ($k in $Params.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [System.DBNull]::Value } else { $Params[$k] })) }
    $rd = $cmd.ExecuteReader()
    $out = New-Object System.Collections.Generic.List[object]
    try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
    , $out.ToArray()
} finally { $cn.Dispose() }
'@
}

function Start-RARowPagerReadAhead {
    <# Starts reading the pager's next page on its read-ahead thread. Any failure here: no read-ahead (the page is read in line). #>
    param([Parameter(Mandatory)][hashtable]$State)
    $s = $State
    try {
        $ci = & $s.ReadAhead
        if (-not ($ci -is [hashtable]) -or -not $ci.ConnectionString) { $s.ReadAhead = $null; return }
        if (-not $s.AheadRunspace) {
            $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $rs.Open()
            $s.AheadRunspace = $rs
        }
        $q = Get-RARowPagerQuery -State $s
        $ps = [powershell]::Create()
        $ps.Runspace = $s.AheadRunspace
        $timeout = 0; if ($null -ne $ci.CommandTimeout) { $timeout = [int]$ci.CommandTimeout }   # 0 = no limit: the read-ahead page waits as long as the database needs
        [void]$ps.AddScript((Get-RARowPagerReadAheadScript)).AddArgument([string]$ci.ConnectionString).AddArgument([string]$ci.AccessToken).AddArgument($timeout).AddArgument($q.Sql).AddArgument($q.Params)
        $s.Ahead = @{ PS = $ps; Handle = $ps.BeginInvoke(); Query = $q }
    } catch {
        $s.Ahead = $null; $s.ReadAhead = $null
    }
}

function Receive-RARowPagerReadAhead {
    <# The page read ahead (rows as hashtables), or $null when it failed -- the caller then reads it in line (with retries). #>
    param([Parameter(Mandatory)][hashtable]$State)
    $s = $State
    $a = $s.Ahead; $s.Ahead = $null
    if ($null -eq $a) { return $null }
    try {
        $r = $a.PS.EndInvoke($a.Handle)
        if ($a.PS.HadErrors -or $a.PS.Streams.Error.Count -gt 0) { $s.AheadFallbacks++; return $null }
        $hs = New-Object System.Collections.Generic.List[object]
        foreach ($x in $r) {
            # (.psobject.BaseObject: the array itself -- `$x.BaseObject` on an array reads each row's key of that name)
            $b = $x.psobject.BaseObject
            if ($b -is [System.Collections.IDictionary]) { $hs.Add($b); continue }
            foreach ($h in $b) { if ($h -is [System.Collections.IDictionary]) { $hs.Add($h) } }
        }
        $s.AheadPages++
        return , $hs.ToArray()
    } catch {
        $s.AheadFallbacks++
        return $null
    } finally { try { $a.PS.Dispose() } catch { } }
}

function Close-RARowPagerReadAhead {
    param([Parameter(Mandatory)][hashtable]$State)
    $s = $State
    if ($s.Ahead) { try { $s.Ahead.PS.Stop(); $s.Ahead.PS.Dispose() } catch { }; $s.Ahead = $null }
    if ($s.AheadRunspace) { try { $s.AheadRunspace.Dispose() } catch { }; $s.AheadRunspace = $null }
}

function Get-RAStreamTrendRollup {
    <# The day's trend rollup of the run (its grain: the stream's -- #636: Detailed by default), computed in SQL (Get-RAStreamTrendSql). Rows of Dimension, DimensionValue, Findings, Assets, ScoreTotal. #>
    param([Parameter(Mandatory)]$Stream)
    $g = if ([string]$Stream.Grain -eq 'Detailed') { 'Detailed' } else { 'Summary' }
    $res = @(Invoke-RAStreamSql -Stream $Stream -Sql (Get-RAStreamTrendSql -Grain $g -Held @(Get-RAStreamHeldOrdinals -Stream $Stream)) -Params @{ CollectionTime = $Stream.TimeText; CollectionId = [string]$Stream.CollectionId } -Mode 'reader')
    @(foreach ($x in $res) { foreach ($h in @($x)) { if ($h) { [pscustomobject]@{ Dimension = [string]$h['Dimension']; DimensionValue = [string]$h['DimensionValue']; Findings = [int]$h['Findings']; Assets = [int]$h['Assets']; ScoreTotal = [double]$h['ScoreTotal'] } } } })
}

# ------------------------------------------------------------------------------------------------------------------
#  THE CI CONTEXT OF ONE BUCKET (item 3): the bucket's assets looked up in sidata.Ci -- never the whole tenant's CIs.
# ------------------------------------------------------------------------------------------------------------------

function Get-RAStreamCiSql {
    <#
        The CIs one bucket's rows can be matched to: by an id the CI carries (its own, or a linked object's -- with or
        without SI's id prefixes), or by a name exactly ONE current CI has. Retired CIs are not current.
        #855 W10: a CI is STALE when its lifecycle says not seen (the CI build's, from the install's windows) -- Risk Analysis'
        own day count (SI_ActiveStaleDays) only decides for a CI without a lifecycle. Risk Analysis keeps producing the
        findings; the views count the lifecycle.
    #>
    @'
-- (table variables named apart from the parameters: T-SQL names are case-insensitive)
DECLARE @idList TABLE (v nvarchar(450) PRIMARY KEY);
INSERT @idList SELECT DISTINCT LEFT(value, 450) FROM OPENJSON(@Ids) WHERE value IS NOT NULL AND value <> '';
DECLARE @nameList TABLE (v nvarchar(400) PRIMARY KEY);
INSERT @nameList SELECT DISTINCT LEFT(value, 400) FROM OPENJSON(@Names) WHERE value IS NOT NULL AND value <> '';
SELECT c.CiId, c.DocJson,
       CASE WHEN NULLIF(c.Lifecycle, '') IS NOT NULL THEN CASE WHEN c.Lifecycle = 'not_seen' THEN 1 ELSE 0 END
            WHEN c.LastSeen IS NOT NULL AND c.LastSeen < DATEADD(day, -CONVERT(int, @StaleDays), SYSUTCDATETIME()) THEN 1 ELSE 0 END AS Stale
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, '') <> 'retired' AND c.DocJson IS NOT NULL
  AND (c.CiId IN (SELECT v FROM @idList)
       OR c.CiId IN (SELECT l.CiId FROM sidata.CiLink l WHERE l.NativeId IN (SELECT v FROM @idList))
       OR (c.Name IN (SELECT v FROM @nameList)
           AND (SELECT COUNT(*) FROM sidata.Ci c2 WHERE c2.Name = c.Name AND ISNULL(c2.Lifecycle, '') <> 'retired') = 1));
'@
}

function Get-RAStreamCiIndex {
    <#
        The CI index (New-RACiIndex) of ONE bucket's rows, read from sidata.Ci: only the CIs these rows can match. A name
        is only used when exactly one current CI in the WHOLE tenant has it (as the whole-tenant index did). -Invoke: the seam.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyCollection()][object[]]$Rows = @(), [int]$StaleDays = 30)
    $prefixes = @('', 'az:', 'eg:az:', 'eg:dev:', 'eg:', 'mde:', 'entra-user:', 'entra-sp:', 'entra-device:', 'aad:')
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        foreach ($k in (Get-RAStreamCiIdsOfRow -Row $row)) { foreach ($px in $prefixes) { [void]$ids.Add($px + $k) } }
        foreach ($col in 'SI_AssetName', 'AssetName', 'DeviceName') { $p = $row.PSObject.Properties[$col]; if ($p -and $p.Value) { [void]$names.Add(([string]$p.Value).Trim()) } }
    }
    if ($ids.Count -eq 0 -and $names.Count -eq 0) { return (New-RACiIndex -Cis @()) }
    $res = @(& $Invoke (Get-RAStreamCiSql) @{ Ids = (ConvertTo-Json -InputObject @($ids) -Compress); Names = (ConvertTo-Json -InputObject @($names) -Compress); StaleDays = [string]$StaleDays } 'reader')
    $cis = [System.Collections.Generic.List[object]]::new()
    foreach ($x in $res) {
        foreach ($h in @($x)) {
            if (-not $h -or -not $h['DocJson'] -or $h['DocJson'] -is [System.DBNull]) { continue }
            $c = ConvertFrom-RAStreamJson -Json ([string]$h['DocJson'])
            if (-not $c.PSObject.Properties['si_ci_id']) { Add-Member -InputObject $c -NotePropertyName 'si_ci_id' -NotePropertyValue ([string]$h['CiId']) }
            Add-Member -InputObject $c -NotePropertyName 'si_stale_' -NotePropertyValue $(if ([int]$h['Stale'] -eq 1) { 'true' } else { 'false' }) -Force
            $cis.Add($c)
        }
    }
    New-RACiIndex -Cis $cis.ToArray()
}

function Merge-RAColumnFillSnapshot {
    <# PURE. Two column-fill snapshots of one report (Get-RAColumnFillSnapshot, per bucket) as one: rows and filled counts added. #>
    param($Into, $Add)
    if ($null -eq $Into) { return $Add }
    if ($null -eq $Add) { return $Into }
    $out = @{}
    foreach ($k in $Into.Keys) { $out[$k] = [long]$Into[$k] }
    foreach ($k in $Add.Keys) { if ($out.ContainsKey($k)) { $out[$k] = [long]$out[$k] + [long]$Add[$k] } else { $out[$k] = [long]$Add[$k] } }
    $out
}
