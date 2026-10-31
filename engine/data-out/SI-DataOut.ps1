#Requires -Version 5.1
<#
    SecurityInsight DATA OUT -- P5 of the v3 data model (V3-DATA-MODEL part 2, 2.12; REQUIREMENTS #466 / #467).

    Every output reads ONE thing -- the CI with its linked objects, its findings (with their lifecycle) or its records --
    and its OUTPUT MAP (data-model/outputs/<id>.locked.json + the customer's per-column changes) decides which columns it
    receives and under which names. Pro reads the maps from the settings database (cfg.Template kind 'datamodel' + the
    customer's cfg.ItemOverride rows), materialised for the run ($global:SI_DataModelRoot); Community reads the locked
    files plus its *.custom.json. The mapper only shapes columns: it never decides what is opened or closed.

    EVERY WRITER IS A LISTED CONNECTOR (config/data-out.locked.json; operator 2026-10-07: "we cannot have hidden connectors
    doing changes without telling customers about it or be able to see the results"). Each run of each output records:
      * its run row (cfg.ConnectorRun, under the connector name of the catalog): written / changed / no longer sent /
        unchanged counts, the outcome and the plain why;
      * each item it wrote for the first time, changed (every changed column, value BEFORE and NOW) or stopped sending
        (cfg.ConnectorChange) -- an unchanged item is counted, never logged;
      * the item state it compares against next time (cfg.DataOutItem: output, item key, row hash, the row as sent).
    Without a settings database the run line is logged and every item counts as written (there is nothing to compare to).

    DESTINATIONS
      excel                 one sheet of an .xlsx in the output folder (SI's own writer, no module); the whole output.
      servicenow-importset  the rows to a ServiceNow Import Set staging table -- only the items written or changed since
                            the last run (the row hash is the delta), never a configuration item directly.
      fixed                 written by another registered connector (writtenBy); never written here.

    PURE except Invoke-SIDataOutWriter / Invoke-SIDataOut (they write through the seams they are given).
    PowerShell 7; also parses on 5.1 (no ?. / ??, no ternary). No PowerShell modules.
#>

if (-not (Get-Command -Name Invoke-SIOutputMap -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-OutputMapper.ps1')) }
if (-not (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-DataModelTemplates.ps1')) }
# the connector run row and the item change log (Write-SIConnectorRun / Write-SIConnectorChanges) -- one model for every
# connector. Loaded only after Test-Path finds the connector helper (the Community copy records its run line in the log;
# its runs reach the database through the same helper once it is there).
$script:SIDataOutConnectorHelper = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'asset-cmdb', '_shared', 'SI-Connector.ps1')
if (-not (Get-Command -Name New-SIConnectorJobRunRecord -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $script:SIDataOutConnectorHelper)) { . $script:SIDataOutConnectorHelper }
# each output's time to cfg.StepPhaseTime (measurement only; a copy without the helper only logs it)
$script:SIDataOutStepPhase = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-StepPhase.ps1')
if (-not (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $script:SIDataOutStepPhase)) { . $script:SIDataOutStepPhase }

# disabled accounts and devices -- SI_DisabledAssets_Connectors (data out is a connector: off leaves them out, frozen)
if (-not (Get-Command -Name Test-SIDisabledIncluded -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-DisabledAssets.ps1')) }
# #914 THE DATA-OUT CONTRACT (the action table, the envelope, the clear marker, the requests) and the output scope (#274)
if (-not (Get-Command -Name Get-SIDataOutContractAction -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-DataOutContract.ps1')) }
# #961 ALWAYS dot-sourced, never "only when Get-SIOutputScope is missing": the container's entry loads the Pro settings layer
# (and with it SI-OutputScope.ps1) and then starts this engine with '&' -- the engine SEES Get-SIOutputScope but not the
# tables it keeps in its file's scope ($script:SIOutputScopeDestinations ...), so the ServiceNow hand-off failed with "You
# cannot call a method on a null-valued expression" and sent no rows (live 2026-10-30). The same trap as the verification
# job's data health check (Invoke-SIVerification.ps1, 2026-10-15).
. ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-OutputScope.ps1'))
$script:SIDataOutKinds = @('excel', 'servicenow-importset', 'fixed')
$script:SIDataOutGrains = @('ci', 'ci_finding', 'finding_summary', 'record')
$script:SIDataOutVolatile = @('$row_hash', '$run_time', '$run_id', '$changed_at', '$action', '$batch_id', '$cleared', '$reason', '$replaces')

# =====================================================================================================================
#  THE CATALOG
# =====================================================================================================================

function Get-SIDataOutCatalog {
    <# The listed data-out connectors (config/data-out.locked.json). #>
    param([string]$Path)
    if (-not $Path) { $Path = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'config', 'data-out.locked.json') }
    $doc = [IO.File]::ReadAllText($Path).TrimStart([char]0xFEFF) | ConvertFrom-Json
    return , @($doc.outputs)
}

function Test-SIDataOutCatalog {
    <#
    .SYNOPSIS  PURE. The problems of the catalog against the output maps (empty = fine): every map listed exactly once,
               every entry names a map, a known kind, a connector name, an Excel file + sheet, a ServiceNow table setting,
               and a fixed output the connector that writes it.
    #>
    param([Parameter(Mandatory)][object[]]$Catalog, [Parameter(Mandatory)][string[]]$OutputIds)
    $p = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($e in $Catalog) {
        $id = [string]$e.output
        if (-not $id) { $p.Add('an entry names no output'); continue }
        if ($seen.ContainsKey($id)) { $p.Add("output '$id' is listed twice") }
        $seen[$id] = 1
        if ($OutputIds -notcontains $id) { $p.Add("output '$id' has no output map") }
        if ($script:SIDataOutKinds -notcontains [string]$e.kind) { $p.Add("output '$id': kind '$($e.kind)'") }
        if ([string]::IsNullOrWhiteSpace([string]$e.connector) -or ([string]$e.connector).Length -gt 64) { $p.Add("output '$id' names no connector (at most 64 characters)") }
        if ([string]::IsNullOrWhiteSpace([string]$e.label)) { $p.Add("output '$id' has no label") }
        $st = [string](Get-SIItemValue $e 'step'); if ($st -and @('ci-build', 'data-out') -notcontains $st) { $p.Add("output '$id': step '$st' (ci-build, or none for the data-out step)") }
        foreach ($ed in @($e.editions)) { if (@('community', 'pro') -notcontains [string]$ed) { $p.Add("output '$id': edition '$ed'") } }
        switch ([string]$e.kind) {
            'excel' { if (-not [string]$e.file -or -not [string]$e.sheet) { $p.Add("output '$id': an Excel output needs a file and a sheet") } }
            'servicenow-importset' { if (-not [string]$e.tableSetting) { $p.Add("output '$id': a ServiceNow output needs the setting that names its table") } }
            'fixed' { if (-not [string]$e.writtenBy) { $p.Add("output '$id': a fixed output names the connector that writes it") } }
        }
    }
    foreach ($o in $OutputIds) { if (-not $seen.ContainsKey($o)) { $p.Add("output map '$o' is not a listed connector (config/data-out.locked.json)") } }
    # one problem per output item: @(Test-SIDataOutCatalog ...) sees each problem, never one array
    return $p.ToArray()
}

function Get-SIDataOutEnabled {
    <#
    .SYNOPSIS  PURE. Which outputs this run writes: the setting's list (SI_DataOut_Outputs: ids, comma / semicolon
               separated, or an array) when given, else the catalog's defaults -- only writers of this edition, never a
               'fixed' output. Unknown ids are returned in Unknown (the caller warns), never written.
    #>
    param([Parameter(Mandatory)][object[]]$Catalog, $Setting, [ValidateSet('community', 'pro')][string]$Edition = 'pro', [string]$Step = 'data-out')
    $chosen = @()
    if ($null -ne $Setting) {
        $chosen = @(@($Setting) | ForEach-Object { ([string]$_) -split '[,;]' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    }
    $byId = @{}; foreach ($e in $Catalog) { $byId[[string]$e.output] = $e }
    $unknown = @($chosen | Where-Object { -not $byId.ContainsKey($_) })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $Catalog) {
        if ([string]$e.kind -eq 'fixed') { continue }
        if (@($e.editions) -notcontains $Edition) { continue }
        # written by another step (the CI workbook: the CI build, in both editions) -- never twice in one run
        $st = [string](Get-SIItemValue $e 'step'); if (-not $st) { $st = 'data-out' }
        if ($st -ne $Step) { continue }
        # not chosen: its default -- 'default', or this edition in 'defaultEditions' (every Excel output is off by default in
        # Pro; the Community edition keeps its CI workbook)
        $on = [bool]$e.default -or (@(Get-SIItemValue $e 'defaultEditions') -contains $Edition)
        if ($chosen.Count) { $on = $chosen -contains [string]$e.output }
        if ($on) { $out.Add($e) }
    }
    return [pscustomobject]@{ Outputs = $out.ToArray(); Unknown = $unknown }
}

function Test-SIDataOutSwitchedOn {
    <#
        Whether ONE output is switched on for this install: the setting SI_DataOut_Outputs when it names any output, else the
        output's default for the edition (Get-SIDataOutEnabled's rule). -Edition '' = this install's (Get-SIEdition when the
        licence code is loaded; otherwise the Community edition, whose defaults are the ones that were in force before).
    #>
    param([Parameter(Mandatory)]$Entry, [string]$Edition = '', $Setting)
    if (-not $Edition) {
        $Edition = 'community'
        try { if (Get-Command -Name Get-SIEdition -ErrorAction SilentlyContinue) { $Edition = ([string](Get-SIEdition 3>$null)).ToLowerInvariant() } } catch { $Edition = 'community' }
        if ($Edition -notin 'community', 'pro') { $Edition = 'community' }
    }
    if ($null -eq $Setting) { $Setting = Get-Variable -Name SI_DataOut_Outputs -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    $st = [string](Get-SIItemValue $Entry 'step'); if (-not $st) { $st = 'data-out' }
    $en = Get-SIDataOutEnabled -Catalog @($Entry) -Setting $Setting -Edition $Edition -Step $st
    # a setting that names only OTHER outputs still chooses: this one is then off (the same rule as the step's)
    @($en.Outputs | Where-Object { [string]$_.output -eq [string]$Entry.output }).Count -gt 0
}

# =====================================================================================================================
#  THE ITEMS (from the database: the CI with its linked objects, its findings with their lifecycle, its records)
# =====================================================================================================================

function Get-SIDataOutItemKey {
    <# PURE. The key of one output item: what its before / now is compared on (at most 380 characters, cfg.DataOutItem). #>
    param([Parameter(Mandatory)][string]$Grain, $Item)
    $k = Get-SIDataOutItemKeyFull -Grain $Grain -Item $Item
    if ($k.Length -le 380) { return $k }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($k)) | ForEach-Object { $_.ToString('x2') })).Substring(0, 16) } finally { $sha.Dispose() }
    return ('{0}~{1}' -f $k.Substring(0, 363), $h)
}

function Get-SIDataOutItemKeyFull {
    param([Parameter(Mandatory)][string]$Grain, $Item)
    switch ($Grain) {
        'ci' { return [string](Get-SIItemValue $Item 'si_ci_id') }
        'ci_finding' {
            $owner = [string](Get-SIItemValue $Item 'si_ci_id')
            if (-not $owner) { $owner = 'asset:' + [string](Get-SIItemValue $Item 'si_asset_id') }
            return ('{0}|{1}' -f $owner, [string](Get-SIItemValue $Item 'si_finding_key'))
        }
        'finding_summary' {
            return (@('si_report_name', 'si_finding_key', 'si_tier', 'si_severity', 'si_cmdb_id') | ForEach-Object { [string](Get-SIItemValue $Item $_) }) -join '|'
        }
        'record' { return [string](Get-SIItemValue $Item 'si_record_key') }
        default { throw "unknown output grain '$Grain'" }
    }
}

function Get-SIDataOutCiSql {
    <# The CIs, a page at a time by key: the CI document plus the totals the data sync keeps on the row. #>
    @'
SELECT TOP (CONVERT(int, @Take)) c.CiId, c.Lifecycle, c.Tier, c.RiskScore, c.WeightedRiskScore, c.OpenFindings, c.LinkCount, c.DocJson
FROM sidata.Ci AS c
WHERE c.CiId > @After AND c.DocJson IS NOT NULL
ORDER BY c.CiId;
'@
}

function Get-SIDataOutFindingPageSql {
    <#
        #639 THE FINDINGS GRAIN IN KEY PAGES (it was read whole, then held in about six copies across the outputs): the same
        rows the whole read returned (the open findings with their lifecycle, then the closed ones the newest collection no longer has -- sent once with their state), a page at a time --
          -Part open    the findings of the newest collection, @Take after @After (sidata.CiFinding's own id), with the CI's
                        values and their lifecycle (when the table is there);
          -Part closed  the closed lifecycle rows the newest collection no longer has (sent once with their state), @Take
                        after (@AfterOwner, @AfterKey) -- the lifecycle table's own key.
    #>
    param([Parameter(Mandatory)][ValidateSet('open', 'closed')][string]$Part, [bool]$WithState = $true)
    if ($Part -eq 'open') {
        if (-not $WithState) {
            return @'
SELECT TOP (CONVERT(int, @Take)) f.CiFindingId, f.CiId, f.AssetId, f.FindingKey, f.RiskScore, f.WeightedRiskScore, f.Tier, f.DocJson,
       c.Name AS CiName, c.Class AS CiClass, c.AssetType AS CiAssetType, c.CmdbId, c.CmdbName, c.CmdbCriticality,
       JSON_VALUE(c.DocJson, '$.si_cmdb_data_sensitivity') AS CmdbDataSensitivity,
       CAST(NULL AS nvarchar(16)) AS State, CAST(NULL AS datetime2(3)) AS FirstDetected, CAST(NULL AS datetime2(3)) AS LastSeen,
       CAST(NULL AS datetime2(3)) AS ClosedAt, CAST(NULL AS nvarchar(32)) AS CloseReason, CAST(NULL AS int) AS AbsentRuns
FROM sidata.CiFinding AS f
LEFT JOIN sidata.Ci AS c ON c.CiId = f.CiId
WHERE f.CiFindingId > CONVERT(bigint, @After)
ORDER BY f.CiFindingId;
'@
        }
        return @'
SELECT TOP (CONVERT(int, @Take)) f.CiFindingId, f.CiId, f.AssetId, f.FindingKey, f.RiskScore, f.WeightedRiskScore, f.Tier, f.DocJson,
       c.Name AS CiName, c.Class AS CiClass, c.AssetType AS CiAssetType, c.CmdbId, c.CmdbName, c.CmdbCriticality,
       JSON_VALUE(c.DocJson, '$.si_cmdb_data_sensitivity') AS CmdbDataSensitivity,
       s.State, s.FirstDetected, s.LastSeen, s.ClosedAt, s.CloseReason, s.AbsentRuns
FROM sidata.CiFinding AS f
LEFT JOIN sidata.Ci AS c ON c.CiId = f.CiId
LEFT JOIN sidata.CiFindingState AS s ON s.OwnerKey = COALESCE(f.CiId, N'asset:' + f.AssetId) AND s.FindingKey = f.FindingKey
WHERE f.CiFindingId > CONVERT(bigint, @After)
ORDER BY f.CiFindingId;
'@
    }
    @'
SELECT TOP (CONVERT(int, @Take)) CAST(NULL AS bigint) AS CiFindingId, s.CiId, CASE WHEN s.OwnerKey LIKE N'asset:%' THEN SUBSTRING(s.OwnerKey, 7, 400) END AS AssetId, s.FindingKey,
       CAST(NULL AS float) AS RiskScore, CAST(NULL AS float) AS WeightedRiskScore, CAST(NULL AS tinyint) AS Tier, CAST(NULL AS nvarchar(max)) AS DocJson,
       c.Name AS CiName, c.Class AS CiClass, c.AssetType AS CiAssetType, c.CmdbId, c.CmdbName, c.CmdbCriticality, JSON_VALUE(c.DocJson, '$.si_cmdb_data_sensitivity') AS CmdbDataSensitivity,
       s.State, s.FirstDetected, s.LastSeen, s.ClosedAt, s.CloseReason, s.AbsentRuns, s.OwnerKey AS PageOwner
FROM sidata.CiFindingState AS s
LEFT JOIN sidata.Ci AS c ON c.CiId = s.CiId
WHERE s.State = N'closed'
  AND (s.OwnerKey > @AfterOwner OR (s.OwnerKey = @AfterOwner AND s.FindingKey > @AfterKey))
  AND NOT EXISTS (SELECT 1 FROM sidata.CiFinding AS f WHERE f.FindingKey = s.FindingKey AND COALESCE(f.CiId, N'asset:' + f.AssetId) = s.OwnerKey)
ORDER BY s.OwnerKey, s.FindingKey;
'@
}

function Get-SIDataOutCarrySourceSql {
    <#
        #899 THE LAST COMPLETE RESULT OF EACH REPORT THE NEWEST RUN COULD NOT COMPLETE (@frozenReports, a JSON array): the
        collection the data sync's per-report carry took it from (sidata.CollectionReportCarry.FromCollectionId of the newest
        Detailed collection -- that carry never takes a collection in which the report was NotComplete). One row per report:
        ReportName, FromCollectionId (NULL = no complete earlier result). A database without the carry table answers none.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CollectionReportCarry') IS NULL OR OBJECT_ID('sidata.Collection') IS NULL
BEGIN SELECT CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS INT) AS FromCollectionId WHERE 1 = 0; RETURN; END
DECLARE @newest INT = (SELECT TOP (1) CollectionId FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete' ORDER BY CollectionTime DESC);
SELECT r.k AS ReportName, (SELECT MAX(c.FromCollectionId) FROM sidata.CollectionReportCarry c WHERE c.CollectionId = @newest AND c.ReportName = r.k) AS FromCollectionId
FROM (SELECT DISTINCT LTRIM(RTRIM(k)) AS k FROM OPENJSON(ISNULL(@frozenReports, N'[]')) WITH (k NVARCHAR(256) '$') WHERE NULLIF(LTRIM(RTRIM(k)), N'') IS NOT NULL) r
ORDER BY r.k;
'@
}

function Get-SIDataOutCarryKeysSql {
    <#
        Per report the newest run could not complete: the OPEN findings (sidata.CiFindingState) the newest collection does not
        have -- ONLY those IN THAT REPORT'S LAST COMPLETE RESULT (@src: [{ ReportName, FromId }] from Get-SIDataOutCarrySourceSql;
        the finding's row there, sidata.Finding.RaFindingKey = '<owner>|<finding key>'). Their keys are kept as last sent by
        the findings outputs. #899: a lifecycle state alone is NEVER enough -- a state left open after its report row is gone
        (a key change, an old owner key) is not re-sent as a finding. A database without the lifecycle table or the finding
        key column answers none. #639: a page at a time (@Take after @AfterId, the last complete result's own row id), each
        row with the report it came from.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiFindingState') IS NULL OR OBJECT_ID('sidata.CiFinding') IS NULL OR COL_LENGTH('sidata.Finding', 'RaFindingKey') IS NULL
BEGIN SELECT CAST(NULL AS NVARCHAR(64)) AS CiId, CAST(NULL AS NVARCHAR(400)) AS AssetId, CAST(NULL AS NVARCHAR(256)) AS FindingKey, CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS INT) AS FromCollectionId, CAST(NULL AS BIGINT) AS PageId WHERE 1 = 0; RETURN; END
DECLARE @s TABLE (ReportName NVARCHAR(256) NOT NULL PRIMARY KEY, FromId INT NOT NULL);
INSERT @s SELECT ReportName, MAX(FromId) FROM OPENJSON(ISNULL(@src, N'[]')) WITH (ReportName NVARCHAR(256), FromId INT) WHERE ReportName IS NOT NULL AND FromId IS NOT NULL GROUP BY ReportName;
SELECT TOP (CONVERT(int, @Take)) st.CiId, CASE WHEN st.OwnerKey LIKE N'asset:%' THEN SUBSTRING(st.OwnerKey, 7, 400) END AS AssetId, st.FindingKey,
       f.ReportName, f.CollectionId AS FromCollectionId, f.FindingId AS PageId
FROM sidata.Finding AS f
JOIN @s AS x ON x.FromId = f.CollectionId AND x.ReportName = f.ReportName
CROSS APPLY (SELECT CHARINDEX(N'|', f.RaFindingKey) AS P) AS sp
JOIN sidata.CiFindingState AS st ON sp.P > 1 AND st.OwnerKey = LEFT(f.RaFindingKey, sp.P - 1) AND st.FindingKey = SUBSTRING(f.RaFindingKey, sp.P + 1, 400)
WHERE f.CollectionId IN (SELECT FromId FROM @s) AND f.FindingId > CONVERT(bigint, @AfterId) AND f.RaFindingKey IS NOT NULL
  AND st.State <> N'closed'
  AND NOT EXISTS (SELECT 1 FROM sidata.CiFinding AS cf WHERE cf.FindingKey = st.FindingKey AND COALESCE(cf.CiId, N'asset:' + cf.AssetId) = st.OwnerKey)
ORDER BY f.FindingId;
'@
}

function New-SIDataOutItemCursor {
    <#
        #639 ONE GRAIN, A PAGE AT A TIME, PULLED: the reader of one grain as a cursor -- Get-SIDataOutNextPage hands the next
        page (@{ Items; Frozen }) or $null at the end; nothing but the page in hand is held. The data-out writer pulls a page
        when its destination is ready for it (the streamed workbook asks for its next page), so the grain is never held whole
        and never kept for another output.
          -Invoke   the data database (mode 'reader' | 'scalar' | 'nonquery'), the grain read in key pages
          -Items    an item list already in hand (tests; the CI build) -- handed out in pages of -PageSize
          -Disabled SI_DisabledAssets_Connectors: @{ Cis; Include }, $null = keep all -- a disabled account's items are left
                    out of the page, their keys handed on as Frozen (what was sent for them stays as it was)
          -Stage    the summary grain: the data database's staging of the summary (Test-SIDataOutStageReady), so only one page
                    of findings and one page of groups is held; $null = the groups are built in memory (a database without
                    the staging tables, the offline tests)
          -Source   a reader of its own pages (the CI build's workbook: the CIs of that build, read back from sidata.Ci) --
                    { param($State) } called with -SourceState for each next page -> @{ Items; Frozen; Rows (read) }, or
                    $null at the end. It pages and leaves out the disabled itself; the cursor hands its pages on as they are.
        The summary grain is built from the findings pages as they are read and handed out a page of groups at a time.
    #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][string]$Grain, $Disabled, [int]$PageSize = 5000,
          [AllowEmptyCollection()][object[]]$Items, [switch]$FromItems, [scriptblock]$Stage,
          # the scale measurement (tests\scale): items made a page at a time -- { param([long]$At, [int]$Take) } -> items, -Total in all
          [scriptblock]$Generator, [long]$Total = 0,
          [scriptblock]$Source, [hashtable]$SourceState)
    if ($PageSize -lt 1) { $PageSize = 5000 }
    $c = @{ Grain = $Grain; Invoke = $Invoke; Disabled = $Disabled; PageSize = $PageSize; Phase = 'start'; Rows = 0L; Stage = $Stage
            After = ''; AfterId = 0L; AfterOwner = ''; AfterKey = ''; HasState = $null; Items = $null; At = 0; Inner = $null; Groups = $null; StageId = ''; Seq = 0L; AfterSeq = 0L
            Generator = $Generator; Total = $Total; Source = $Source; SourceState = $SourceState }
    if ($Generator) { $c.Phase = 'gen' }
    elseif ($Source) { $c.Phase = 'source' }
    elseif ($FromItems) { $c.Phase = 'items'; $c.Items = @($Items) }
    elseif (-not $Invoke) { throw 'New-SIDataOutItemCursor: -Invoke (the data database) or -Items is needed' }
    $c
}

function Select-SIDataOutCursorPage {
    <# One page of items through the SI_DisabledAssets_Connectors decision: @{ Items; Frozen } (the summary is never filtered here). #>
    param([Parameter(Mandatory)][hashtable]$Cursor, [AllowEmptyCollection()][object[]]$Items = @(), [string]$Grain)
    if (-not $Grain) { $Grain = $Cursor.Grain }
    if ($null -ne $Cursor.Disabled -and $Grain -ne 'finding_summary') {
        $sel = Select-SIDataOutEnabledItems -Grain $Grain -Items @($Items) -DisabledCis @($Cursor.Disabled.Cis) -Include ([bool]$Cursor.Disabled.Include)
        return @{ Items = @($sel.Kept); Frozen = [string[]]@($sel.FrozenKeys) }
    }
    @{ Items = @($Items); Frozen = [string[]]@() }
}

function Get-SIDataOutNextPage {
    <#
        The next page of the cursor (New-SIDataOutItemCursor): @{ Items; Frozen }, or $null when the grain is read. A page may
        hold no items (all of it left out as disabled) -- the caller asks for the next one. Cursor.Rows counts the rows read.
    #>
    param([Parameter(Mandatory)][hashtable]$Cursor)
    $c = $Cursor
    $take = [int]$c.PageSize
    while ($true) {
        switch ($c.Phase) {
            'items' {
                if ($c.At -ge $c.Items.Count) { $c.Phase = 'done'; $c.Items = $null; continue }
                $n = [Math]::Min($take, $c.Items.Count - $c.At)
                $page = @($c.Items[$c.At..($c.At + $n - 1)])
                $c.At += $n; $c.Rows += $n
                return (Select-SIDataOutCursorPage -Cursor $c -Items $page)
            }
            'gen' {
                if ($c.Rows -ge $c.Total) { $c.Phase = 'done'; continue }
                $n = [int][Math]::Min([long]$take, $c.Total - $c.Rows)
                $page = @(& $c.Generator $c.Rows $n)
                $c.Rows += $n
                return (Select-SIDataOutCursorPage -Cursor $c -Items $page)
            }
            'source' {
                $pg = & $c.Source $c.SourceState
                if ($null -eq $pg) { $c.Phase = 'done'; continue }
                $c.Rows += [long]$pg.Rows
                return @{ Items = @($pg.Items); Frozen = [string[]]@($pg.Frozen) }
            }
            'start' {
                switch ($c.Grain) {
                    { $_ -in 'ci', 'record' } { $c.Phase = 'keyed' }
                    'ci_finding' {
                        $c.HasState = [int](& $c.Invoke "SELECT CASE WHEN OBJECT_ID(N'sidata.CiFindingState') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') -eq 1
                        $c.Phase = 'open'
                    }
                    'finding_summary' { $c.Phase = 'summary-build' }
                    default { throw "unknown output grain '$($c.Grain)'" }
                }
                continue
            }
            'keyed' {
                $sql = if ($c.Grain -eq 'ci') { Get-SIDataOutCiSql } else { Get-SIDataOutRecordSql }
                $keyCol = if ($c.Grain -eq 'ci') { 'CiId' } else { 'RecordKey' }
                $a = & $c.Invoke $sql @{ Take = $take; After = [string]$c.After } 'reader'; $rows = @(@($a) | Where-Object { $_ }); $a = $null
                if ($rows.Count -eq 0) { $c.Phase = 'done'; continue }
                $items = @(foreach ($r in $rows) { if ($c.Grain -eq 'ci') { ConvertFrom-SIDataOutCiRow $r } else { ConvertFrom-SIDataOutRecordRow $r } })
                $c.Rows += $rows.Count
                $c.After = [string]$rows[$rows.Count - 1][$keyCol]
                if ($rows.Count -lt $take) { $c.Phase = 'done' }
                $rows = $null
                return (Select-SIDataOutCursorPage -Cursor $c -Items $items)
            }
            'open' {
                $a = & $c.Invoke (Get-SIDataOutFindingPageSql -Part open -WithState ([bool]$c.HasState)) @{ Take = $take; After = [string]$c.AfterId } 'reader'; $rows = @(@($a) | Where-Object { $_ }); $a = $null
                if ($rows.Count -eq 0) { $c.Phase = $(if ($c.HasState) { 'closed' } else { 'done' }); continue }
                $items = @(foreach ($r in $rows) { ConvertFrom-SIDataOutFindingRow $r })
                $c.Rows += $rows.Count
                $c.AfterId = [long]$rows[$rows.Count - 1]['CiFindingId']
                if ($rows.Count -lt $take) { $c.Phase = $(if ($c.HasState) { 'closed' } else { 'done' }) }
                $rows = $null
                return (Select-SIDataOutCursorPage -Cursor $c -Items $items)
            }
            'closed' {
                $a = & $c.Invoke (Get-SIDataOutFindingPageSql -Part closed) @{ Take = $take; AfterOwner = [string]$c.AfterOwner; AfterKey = [string]$c.AfterKey } 'reader'; $rows = @(@($a) | Where-Object { $_ }); $a = $null
                if ($rows.Count -eq 0) { $c.Phase = 'done'; continue }
                $items = @(foreach ($r in $rows) { ConvertFrom-SIDataOutFindingRow $r })
                $c.Rows += $rows.Count
                $c.AfterOwner = [string]$rows[$rows.Count - 1]['PageOwner']; $c.AfterKey = [string]$rows[$rows.Count - 1]['FindingKey']
                if ($rows.Count -lt $take) { $c.Phase = 'done' }
                $rows = $null
                return (Select-SIDataOutCursorPage -Cursor $c -Items $items)
            }
            'summary-build' {
                # the summary of the findings that are SENT: built from the findings pages after the disabled ones are left
                # out -- in the data database's staging (one page of findings and one page of groups held), else in memory
                $inner = New-SIDataOutItemCursor -Invoke $c.Invoke -Grain 'ci_finding' -Disabled $c.Disabled -PageSize $take
                if ($c.Stage) { $c.StageId = [guid]::NewGuid().ToString() } else { $c.Groups = [ordered]@{} }
                try {
                    while ($null -ne ($pg = Get-SIDataOutNextPage -Cursor $inner)) {
                        if ($c.Stage) { Add-SIDataOutSummaryStage -Cursor $c -Items @($pg.Items) }
                        else { Add-SIDataOutSummaryItems -Groups $c.Groups -Items @($pg.Items) }
                        $pg = $null
                    }
                    $c.Rows = $inner.Rows
                    if ($c.Stage) { [void](& $c.Stage (Get-SIDataOutSummaryGroupSql) @{ StageId = $c.StageId } 'nonquery') }
                } catch {
                    if ($c.Stage) { Clear-SIDataOutSummaryStage -Cursor $c }
                    throw
                }
                $c.Phase = 'summary-emit'
                continue
            }
            'summary-emit' {
                if (-not $c.Stage) {
                    $sum = ConvertFrom-SIDataOutSummaryGroups -Groups $c.Groups   # one list (return , ...): assigned, never @(<call>)
                    $c.Groups = $null; $c.Phase = 'done'
                    return @{ Items = @($sum); Frozen = [string[]]@() }
                }
                $a = & $c.Stage (Get-SIDataOutSummaryPageSql) @{ StageId = $c.StageId; Take = $take; After = [string]$c.AfterSeq } 'reader'; $rows = @(@($a) | Where-Object { $_ }); $a = $null
                if ($rows.Count -eq 0) { Clear-SIDataOutSummaryStage -Cursor $c; $c.Phase = 'done'; continue }
                $items = @(foreach ($r in $rows) { ConvertFrom-SIDataOutSummaryRow $r })
                $c.AfterSeq = [long]$rows[$rows.Count - 1]['FirstSeq']
                if ($rows.Count -lt $take) { Clear-SIDataOutSummaryStage -Cursor $c; $c.Phase = 'done' }
                $rows = $null
                return @{ Items = $items; Frozen = [string[]]@() }
            }
            default { return $null }
        }
    }
}

function Read-SIDataOutItemPages {
    <#
        #639 ONE GRAIN, A PAGE AT A TIME (pushed): each page of the cursor (New-SIDataOutItemCursor) is handed to -OnPage
        { param($Items, $FrozenKeys) } before the next page is read -- the grain is never held whole. Returns the rows read.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Grain, [Parameter(Mandatory)][scriptblock]$OnPage, $Disabled, [int]$PageSize = 5000, [scriptblock]$Stage)
    $cur = New-SIDataOutItemCursor -Invoke $Invoke -Grain $Grain -Disabled $Disabled -PageSize $PageSize -Stage $Stage
    while ($null -ne ($pg = Get-SIDataOutNextPage -Cursor $cur)) { & $OnPage @($pg.Items) ([string[]]@($pg.Frozen)); $pg = $null }
    $cur.Rows
}

# =====================================================================================================================
#  #639 THE DATA DATABASE'S STAGING (additive tables, sql/si-data-schema.sql; created here too when a database set up
#  earlier does not have them yet): the keys an output has seen this run, the keys it keeps, and the summary of the
#  findings -- so what is held is one page, never a set the size of the grain.
# =====================================================================================================================

function Get-SIDataOutStageTablesSql {
    <# The staging tables (the same text as sql/si-data-schema.sql), then a marker row: a database that answers it has them. #>
    @'
IF OBJECT_ID(N'sidata.DataOutKeyStage') IS NULL
BEGIN
    CREATE TABLE sidata.DataOutKeyStage (
        StageId   UNIQUEIDENTIFIER NOT NULL,
        ItemKey   NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
        StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_DataOutKeyStage_StagedAt DEFAULT SYSUTCDATETIME(),
        CONSTRAINT PK_DataOutKeyStage PRIMARY KEY (StageId, ItemKey)
    );
END;
IF OBJECT_ID(N'sidata.DataOutSummaryStage') IS NULL
BEGIN
    CREATE TABLE sidata.DataOutSummaryStage (
        StageId   UNIQUEIDENTIFIER NOT NULL,
        Seq       BIGINT           NOT NULL,
        GroupKey  NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
        CiKey     NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
        Name      NVARCHAR(400)    NULL,
        Score     FLOAT            NULL,
        WScore    FLOAT            NULL,
        AttrJson  NVARCHAR(MAX)    NULL,
        StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_DataOutSummaryStage_StagedAt DEFAULT SYSUTCDATETIME(),
        CONSTRAINT PK_DataOutSummaryStage PRIMARY KEY (StageId, Seq)
    );
END;
IF OBJECT_ID(N'sidata.DataOutSummaryGroupStage') IS NULL
BEGIN
    CREATE TABLE sidata.DataOutSummaryGroupStage (
        StageId   UNIQUEIDENTIFIER NOT NULL,
        FirstSeq  BIGINT           NOT NULL,
        GroupKey  NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL,
        CiCount   INT              NOT NULL,
        NamesJson NVARCHAR(MAX)    NULL,
        MaxScore  FLOAT            NULL,
        MaxWScore FLOAT            NULL,
        AttrJson  NVARCHAR(MAX)    NULL,
        StagedAt  DATETIME2(3)     NOT NULL CONSTRAINT DF_DataOutSummaryGroupStage_StagedAt DEFAULT SYSUTCDATETIME(),
        CONSTRAINT PK_DataOutSummaryGroupStage PRIMARY KEY (StageId, FirstSeq)
    );
END;
SELECT N'si-dataout-stage' AS Ready;
'@
}

function Get-SIDataOutStaleStageSql {
    <# One chunk of what a run that stopped left in the staging tables (older than a day). Answers the rows removed. #>
    @'
DECLARE @n int = 0;
IF OBJECT_ID(N'sidata.DataOutKeyStage') IS NOT NULL BEGIN DELETE TOP (CONVERT(int, @Take)) FROM sidata.DataOutKeyStage WHERE StagedAt < DATEADD(day, -1, SYSUTCDATETIME()); SET @n += @@ROWCOUNT; END;
IF OBJECT_ID(N'sidata.DataOutSummaryStage') IS NOT NULL BEGIN DELETE TOP (CONVERT(int, @Take)) FROM sidata.DataOutSummaryStage WHERE StagedAt < DATEADD(day, -1, SYSUTCDATETIME()); SET @n += @@ROWCOUNT; END;
IF OBJECT_ID(N'sidata.DataOutSummaryGroupStage') IS NOT NULL BEGIN DELETE TOP (CONVERT(int, @Take)) FROM sidata.DataOutSummaryGroupStage WHERE StagedAt < DATEADD(day, -1, SYSUTCDATETIME()); SET @n += @@ROWCOUNT; END;
SELECT @n;
'@
}

function Test-SIDataOutStageReady {
    <#
        The data database's staging tables, created when missing; $true only when the database ANSWERS that they are there
        (a seam that cannot say so -- a fake, an older database the engine may not change -- is $false, and the caller holds
        its keys in memory as before). Leftovers of a run that stopped are removed in chunks. Never throws.
    #>
    param([scriptblock]$Invoke, [scriptblock]$Log)
    if (-not $Invoke) { return $false }
    try {
        $a = & $Invoke (Get-SIDataOutStageTablesSql) @{} 'reader'
        $ok = @(@($a) | Where-Object { $_ -is [System.Collections.IDictionary] -and [string]$_['Ready'] -eq 'si-dataout-stage' }).Count -gt 0
        if (-not $ok) { return $false }
        while ([long](& $Invoke (Get-SIDataOutStaleStageSql) @{ Take = 50000 } 'scalar') -gt 0) { }
        return $true
    } catch {
        if ($Log) { & $Log 'WARN' ("data out  : the staging tables could not be prepared ({0}) -- the keys of this run are held in memory" -f $_.Exception.Message) }
        return $false
    }
}

function New-SIDataOutKeySet {
    <#
        A SET OF ITEM KEYS (ordinal, like the keys themselves): in the data database's staging (-Stage, Test-SIDataOutStageReady)
        so only the page in hand is held, or in memory (no staging: tests, a database without the table). One set per use
        (the keys an output has seen this run, the keys left out as disabled, the keys kept for an incomplete report).
    #>
    param([scriptblock]$Stage)
    if ($Stage) { return @{ Stage = $Stage; Id = [guid]::NewGuid().ToString(); Mem = $null; Count = 0L } }
    @{ Stage = $null; Id = ''; Mem = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)); Count = 0L }
}

function Get-SIDataOutKeyAddSql {
    @'
DECLARE @t TABLE (k NVARCHAR(380) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY);
INSERT @t (k) SELECT DISTINCT j.k COLLATE Latin1_General_100_BIN2 FROM OPENJSON(@klist) WITH (k NVARCHAR(380) '$') AS j WHERE j.k IS NOT NULL;
INSERT sidata.DataOutKeyStage (StageId, ItemKey)
OUTPUT inserted.ItemKey AS ItemKey
SELECT CONVERT(uniqueidentifier, @StageId), t.k FROM @t AS t
WHERE NOT EXISTS (SELECT 1 FROM sidata.DataOutKeyStage AS s WHERE s.StageId = CONVERT(uniqueidentifier, @StageId) AND s.ItemKey = t.k);
'@
}

function Get-SIDataOutKeyFindSql {
    @'
SELECT DISTINCT j.k COLLATE Latin1_General_100_BIN2 AS ItemKey FROM OPENJSON(@klist) WITH (k NVARCHAR(380) '$') AS j
WHERE EXISTS (SELECT 1 FROM sidata.DataOutKeyStage AS s WHERE s.StageId = CONVERT(uniqueidentifier, @StageId) AND s.ItemKey = j.k COLLATE Latin1_General_100_BIN2);
'@
}

function Add-SIDataOutKeys {
    <# Adds keys to the set; returns a HashSet of the keys that were NOT in it before (the ones added now). #>
    param([Parameter(Mandatory)][hashtable]$Set, [AllowEmptyCollection()][string[]]$Keys = @())
    $new = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $ks = @($Keys | Where-Object { $_ })
    if ($ks.Count -eq 0) { return , $new }
    if ($null -ne $Set.Mem) { foreach ($k in $ks) { if ($Set.Mem.Add([string]$k)) { [void]$new.Add([string]$k) } } }
    else {
        for ($i = 0; $i -lt $ks.Count; $i += 2000) {
            $part = @($ks[$i..([Math]::Min($i + 2000, $ks.Count) - 1)])
            $a = & $Set.Stage (Get-SIDataOutKeyAddSql) @{ StageId = $Set.Id; klist = (ConvertTo-Json -InputObject ([string[]]$part) -Compress) } 'reader'
            foreach ($r in @($a)) { if ($r) { [void]$new.Add([string]$r['ItemKey']) } }
        }
    }
    $Set.Count += $new.Count
    , $new
}

function Find-SIDataOutKeys {
    <# The keys of -Keys that are in the set (a HashSet). #>
    param([Parameter(Mandatory)][hashtable]$Set, [AllowEmptyCollection()][string[]]$Keys = @())
    $hit = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $ks = @($Keys | Where-Object { $_ })
    if ($ks.Count -eq 0 -or $Set.Count -eq 0) { return , $hit }
    if ($null -ne $Set.Mem) { foreach ($k in $ks) { if ($Set.Mem.Contains([string]$k)) { [void]$hit.Add([string]$k) } } }
    else {
        for ($i = 0; $i -lt $ks.Count; $i += 2000) {
            $part = @($ks[$i..([Math]::Min($i + 2000, $ks.Count) - 1)])
            $a = & $Set.Stage (Get-SIDataOutKeyFindSql) @{ StageId = $Set.Id; klist = (ConvertTo-Json -InputObject ([string[]]$part) -Compress) } 'reader'
            foreach ($r in @($a)) { if ($r) { [void]$hit.Add([string]$r['ItemKey']) } }
        }
    }
    , $hit
}

function Clear-SIDataOutKeySet {
    <# Lets the set go (the staging rows in chunks). Never throws. #>
    param([hashtable]$Set)
    if (-not $Set) { return }
    try {
        if ($null -ne $Set.Mem) { $Set.Mem.Clear() }
        elseif ($Set.Stage -and $Set.Count -gt 0) {
            while ([long](& $Set.Stage 'DELETE TOP (CONVERT(int, @Take)) FROM sidata.DataOutKeyStage WHERE StageId = CONVERT(uniqueidentifier, @StageId); SELECT @@ROWCOUNT;' @{ StageId = $Set.Id; Take = 50000 } 'scalar') -gt 0) { }
        }
        $Set.Count = 0L
    } catch { }
}

# ---- the summary grain in the staging tables ---------------------------------------------------------------------

function Get-SIDataOutSummaryAddSql {
    @'
INSERT sidata.DataOutSummaryStage (StageId, Seq, GroupKey, CiKey, Name, Score, WScore, AttrJson)
SELECT CONVERT(uniqueidentifier, @StageId), j.q, j.g, j.c, NULLIF(j.n, N''), j.s, j.w, j.a
FROM OPENJSON(@rows) WITH (q bigint, g nvarchar(380), c nvarchar(380), n nvarchar(400), s float, w float, a nvarchar(max) AS JSON) AS j;
'@
}

function Get-SIDataOutSummaryGroupSql {
    <# The groups of the staged summary, set-based: the CIs counted once, their names once each in order, the highest scores,
       the values of the group's first finding; ordered as the findings came (FirstSeq). #>
    @'
INSERT sidata.DataOutSummaryGroupStage (StageId, FirstSeq, GroupKey, CiCount, NamesJson, MaxScore, MaxWScore, AttrJson)
SELECT g.StageId, g.FirstSeq, g.GroupKey, g.CiCount,
       (SELECT N'[' + STRING_AGG(CONVERT(nvarchar(max), N'"' + STRING_ESCAPE(n.Name, 'json') + N'"'), N',') WITHIN GROUP (ORDER BY n.Name) + N']'
        FROM (SELECT DISTINCT s2.Name FROM sidata.DataOutSummaryStage AS s2 WHERE s2.StageId = g.StageId AND s2.GroupKey = g.GroupKey AND s2.Name IS NOT NULL) AS n),
       g.MaxScore, g.MaxWScore,
       (SELECT TOP (1) s3.AttrJson FROM sidata.DataOutSummaryStage AS s3 WHERE s3.StageId = g.StageId AND s3.GroupKey = g.GroupKey AND s3.AttrJson IS NOT NULL ORDER BY s3.Seq)
FROM (SELECT s.StageId, s.GroupKey, MIN(s.Seq) AS FirstSeq, COUNT(DISTINCT s.CiKey) AS CiCount, MAX(s.Score) AS MaxScore, MAX(s.WScore) AS MaxWScore
      FROM sidata.DataOutSummaryStage AS s WHERE s.StageId = CONVERT(uniqueidentifier, @StageId) GROUP BY s.StageId, s.GroupKey) AS g;
'@
}

function Get-SIDataOutSummaryPageSql {
    @'
SELECT TOP (CONVERT(int, @Take)) FirstSeq, GroupKey, CiCount, NamesJson, MaxScore, MaxWScore, AttrJson
FROM sidata.DataOutSummaryGroupStage
WHERE StageId = CONVERT(uniqueidentifier, @StageId) AND FirstSeq > CONVERT(bigint, @After)
ORDER BY FirstSeq;
'@
}

function Add-SIDataOutSummaryStage {
    <# One page of CI-and-finding items into the summary staging (the open findings only), in chunks. #>
    param([Parameter(Mandatory)][hashtable]$Cursor, [AllowEmptyCollection()][object[]]$Items = @())
    $c = $Cursor
    $rows = New-Object System.Collections.Generic.List[object]
    $firstInPage = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $flush = {
        if ($rows.Count -eq 0) { return }
        [void](& $c.Stage (Get-SIDataOutSummaryAddSql) @{ StageId = $c.StageId; rows = (ConvertTo-Json -InputObject $rows.ToArray() -Compress -Depth 6) } 'nonquery')
        $rows.Clear()
    }
    foreach ($it in $Items) {
        if ($null -eq $it) { continue }
        if ([string](Get-SIItemValue $it 'si_finding_state') -eq 'closed') { continue }
        $k = Get-SIDataOutItemKey -Grain 'finding_summary' -Item $it
        $attr = $null
        if ($firstInPage.Add($k)) {
            $attr = [ordered]@{}
            foreach ($f in 'si_security_domain', 'si_report_name', 'si_finding_key', 'si_title', 'si_tier', 'si_severity', 'si_cmdb_id', 'si_cmdb_name', 'si_risk_rating') { $attr[$f] = Get-SIItemValue $it $f }
        }
        $c.Seq++
        $rows.Add([ordered]@{ q = $c.Seq; g = $k; c = (Get-SIDataOutItemKey -Grain 'ci_finding' -Item $it); n = [string](Get-SIItemValue $it 'si_asset_name')
                              s = (ConvertTo-SINumberOrNull (Get-SIItemValue $it 'si_risk_score')); w = (ConvertTo-SINumberOrNull (Get-SIItemValue $it 'si_weighted_risk_score')); a = $attr })
        if ($rows.Count -ge 1000) { & $flush }
    }
    & $flush
}

function ConvertFrom-SIDataOutSummaryRow {
    <# PURE. One staged summary group -> the summary item (ConvertFrom-SIDataOutSummaryGroups' shape). #>
    param([Parameter(Mandatory)]$Row)
    $o = [ordered]@{}
    $attr = $null
    $aj = $Row['AttrJson']; if ($aj -isnot [System.DBNull] -and [string]$aj) { try { $attr = [string]$aj | ConvertFrom-Json } catch { $attr = $null } }
    foreach ($f in 'si_security_domain', 'si_report_name', 'si_finding_key', 'si_title', 'si_tier', 'si_severity', 'si_cmdb_id', 'si_cmdb_name', 'si_risk_rating') {
        $v = $null; if ($attr -and $attr.PSObject.Properties[$f]) { $v = $attr.$f }; $o[$f] = $v
    }
    $o['ci_count'] = [int]$Row['CiCount']
    # the names as the in-memory summary orders them (a SortedSet, ordinal ignoring case)
    $names = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $nj = $Row['NamesJson']
    if ($nj -isnot [System.DBNull] -and [string]$nj) { try { foreach ($n in @([string]$nj | ConvertFrom-Json)) { if ($n) { [void]$names.Add([string]$n) } } } catch { } }
    $o['ci_names'] = @($names)
    $o['max_risk_score'] = $(if ($Row['MaxScore'] -is [System.DBNull]) { $null } else { [double]$Row['MaxScore'] })
    $o['max_weighted_risk_score'] = $(if ($Row['MaxWScore'] -is [System.DBNull]) { $null } else { [double]$Row['MaxWScore'] })
    [pscustomobject]$o
}

function Clear-SIDataOutSummaryStage {
    param([hashtable]$Cursor)
    if (-not $Cursor -or -not $Cursor.Stage -or -not $Cursor.StageId) { return }
    try {
        foreach ($t in 'sidata.DataOutSummaryStage', 'sidata.DataOutSummaryGroupStage') {
            while ([long](& $Cursor.Stage ("DELETE TOP (CONVERT(int, @Take)) FROM {0} WHERE StageId = CONVERT(uniqueidentifier, @StageId); SELECT @@ROWCOUNT;" -f $t) @{ StageId = $Cursor.StageId; Take = 50000 } 'scalar') -gt 0) { }
        }
    } catch { }
}

function Get-SIDataOutRecordSql {
    @'
SELECT TOP (CONVERT(int, @Take)) r.RecordKey, r.CiId, r.Provider, r.RecordType, r.Class, r.Name, r.SourceLastSeen, r.CollectionTime, r.DocJson
FROM sidata.CiRecord AS r
WHERE r.RecordKey > @After
ORDER BY r.RecordKey;
'@
}

function ConvertFrom-SIDataOutJson {
    <# A DocJson text -> an object whose properties can be set ($null / bad JSON -> an empty one). #>
    param($Text)
    if ($null -eq $Text -or $Text -is [System.DBNull] -or [string]::IsNullOrWhiteSpace([string]$Text)) { return [pscustomobject]@{} }
    try { $o = [string]$Text | ConvertFrom-Json; if ($o -is [System.Management.Automation.PSCustomObject]) { return $o } } catch { }
    return [pscustomobject]@{}
}

function Set-SIDataOutValue {
    <# Sets one property of an item (only when -IfMissing is off or the item has no value there). DBNull is $null. #>
    param($Item, [string]$Name, $Value, [switch]$IfMissing)
    if ($Value -is [System.DBNull]) { $Value = $null }
    $p = $Item.PSObject.Properties[$Name]
    if ($p) {
        if ($IfMissing -and -not (Test-SIValueEmpty $p.Value)) { return }
        $p.Value = $Value
    } else { $Item | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

function ConvertFrom-SIDataOutCiRow {
    <# PURE. One sidata.Ci row -> the CI item: its document, with the totals the data sync keeps on the row. #>
    param([Parameter(Mandatory)]$Row)
    $it = ConvertFrom-SIDataOutJson $Row['DocJson']
    Set-SIDataOutValue $it 'si_ci_id' $Row['CiId'] -IfMissing
    Set-SIDataOutValue $it 'si_lifecycle' $Row['Lifecycle'] -IfMissing
    Set-SIDataOutValue $it 'si_tier' $Row['Tier'] -IfMissing
    # the CI's risk score = the sum of its findings' scores (the data sync's totals, Get-SIDataCiTotalsSql)
    Set-SIDataOutValue $it 'si_ci_risk_score' $Row['RiskScore']
    Set-SIDataOutValue $it 'si_ci_weighted_risk_score' $Row['WeightedRiskScore']
    Set-SIDataOutValue $it 'si_open_findings' $Row['OpenFindings']
    Set-SIDataOutValue $it 'si_link_count' $Row['LinkCount'] -IfMissing
    return $it
}

function ConvertFrom-SIDataOutFindingRow {
    <# PURE. One finding row -> the CI-and-finding item: the finding's document, the CI's values, its lifecycle. #>
    param([Parameter(Mandatory)]$Row)
    $it = ConvertFrom-SIDataOutJson $Row['DocJson']
    Set-SIDataOutValue $it 'si_ci_id' $Row['CiId'] -IfMissing
    Set-SIDataOutValue $it 'si_asset_id' $Row['AssetId'] -IfMissing
    Set-SIDataOutValue $it 'si_finding_key' $Row['FindingKey'] -IfMissing
    Set-SIDataOutValue $it 'si_risk_score' $Row['RiskScore'] -IfMissing
    Set-SIDataOutValue $it 'si_weighted_risk_score' $Row['WeightedRiskScore'] -IfMissing
    Set-SIDataOutValue $it 'si_tier' $Row['Tier'] -IfMissing
    Set-SIDataOutValue $it 'si_asset_name' $Row['CiName'] -IfMissing
    Set-SIDataOutValue $it 'si_class' $Row['CiClass'] -IfMissing
    Set-SIDataOutValue $it 'si_asset_type' $Row['CiAssetType'] -IfMissing
    Set-SIDataOutValue $it 'si_cmdb_id' $Row['CmdbId'] -IfMissing
    Set-SIDataOutValue $it 'si_cmdb_name' $Row['CmdbName'] -IfMissing
    Set-SIDataOutValue $it 'si_cmdb_criticality' $Row['CmdbCriticality'] -IfMissing
    Set-SIDataOutValue $it 'si_cmdb_data_sensitivity' $Row['CmdbDataSensitivity'] -IfMissing
    # the lifecycle in the core (sidata.CiFindingState); a finding the lifecycle has not seen yet is open
    $state = $Row['State']; if ($state -is [System.DBNull] -or -not [string]$state) { $state = 'open' }
    Set-SIDataOutValue $it 'si_finding_state' ([string]$state)
    Set-SIDataOutValue $it 'si_first_detected' $Row['FirstDetected'] -IfMissing
    Set-SIDataOutValue $it 'si_last_detected' $Row['LastSeen']
    Set-SIDataOutValue $it 'si_close_reason' $Row['CloseReason']
    Set-SIDataOutValue $it 'closed_at' $Row['ClosedAt']
    Set-SIDataOutValue $it 'absent_runs' $Row['AbsentRuns']
    Set-SIDataOutValue $it 'record_id' $Row['CiFindingId']
    # #914 the STABLE record id (u_source_record_id): '<CI key>|<finding key>' -- the row id above changes when the findings
    # are rebuilt, so it is never sent as a record id
    Set-SIDataOutValue $it 'item_key' (Get-SIDataOutItemKeyFull -Grain 'ci_finding' -Item $it)
    return $it
}

function ConvertFrom-SIDataOutRecordRow {
    <# PURE. One sidata.CiRecord row -> the record item. #>
    param([Parameter(Mandatory)]$Row)
    $it = ConvertFrom-SIDataOutJson $Row['DocJson']
    Set-SIDataOutValue $it 'si_record_key' $Row['RecordKey']
    Set-SIDataOutValue $it 'si_ci_id' $Row['CiId'] -IfMissing
    Set-SIDataOutValue $it 'si_provider' $Row['Provider'] -IfMissing
    Set-SIDataOutValue $it 'si_record_type' $Row['RecordType'] -IfMissing
    Set-SIDataOutValue $it 'si_class' $Row['Class'] -IfMissing
    Set-SIDataOutValue $it 'si_asset_name' $Row['Name'] -IfMissing
    Set-SIDataOutValue $it 'si_source_last_seen' $Row['SourceLastSeen'] -IfMissing
    Set-SIDataOutValue $it 'si_collection_time' $Row['CollectionTime'] -IfMissing
    return $it
}

function ConvertTo-SIDataOutSummaryItems {
    <#
    .SYNOPSIS  PURE. The CI-and-finding items -> one summary item per finding x tier x severity x CMDB group (the open
               findings only): how many CIs, their names, the highest scores.
    #>
    param([AllowEmptyCollection()][object[]]$Items = @())
    $groups = [ordered]@{}
    Add-SIDataOutSummaryItems -Groups $groups -Items $Items
    return , (ConvertFrom-SIDataOutSummaryGroups -Groups $groups)
}

function Add-SIDataOutSummaryItems {
    <# PURE (into -Groups). Adds one page of CI-and-finding items to the summary groups -- the summary is built page by page
       (#639), never from the whole findings grain held at once. #>
    param([Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Groups, [AllowEmptyCollection()][object[]]$Items = @())
    $groups = $Groups
    foreach ($it in $Items) {
        if ($null -eq $it) { continue }
        if ([string](Get-SIItemValue $it 'si_finding_state') -eq 'closed') { continue }
        $k = Get-SIDataOutItemKey -Grain 'finding_summary' -Item $it
        if (-not $groups.Contains($k)) {
            $groups[$k] = [ordered]@{
                si_security_domain = Get-SIItemValue $it 'si_security_domain'; si_report_name = Get-SIItemValue $it 'si_report_name'
                si_finding_key = Get-SIItemValue $it 'si_finding_key'; si_title = Get-SIItemValue $it 'si_title'; si_tier = Get-SIItemValue $it 'si_tier'
                si_severity = Get-SIItemValue $it 'si_severity'; si_cmdb_id = Get-SIItemValue $it 'si_cmdb_id'; si_cmdb_name = Get-SIItemValue $it 'si_cmdb_name'
                si_risk_rating = Get-SIItemValue $it 'si_risk_rating'
                Names = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)); Cis = @{}; Max = $null; MaxW = $null
            }
        }
        $g = $groups[$k]
        $ci = Get-SIDataOutItemKey -Grain 'ci_finding' -Item $it
        $g.Cis[$ci] = 1
        $n = [string](Get-SIItemValue $it 'si_asset_name'); if ($n) { [void]$g.Names.Add($n) }
        $s = ConvertTo-SINumberOrNull (Get-SIItemValue $it 'si_risk_score'); if ($null -ne $s -and ($null -eq $g.Max -or $s -gt $g.Max)) { $g.Max = $s }
        $w = ConvertTo-SINumberOrNull (Get-SIItemValue $it 'si_weighted_risk_score'); if ($null -ne $w -and ($null -eq $g.MaxW -or $w -gt $g.MaxW)) { $g.MaxW = $w }
    }
}

function ConvertFrom-SIDataOutSummaryGroups {
    <# PURE. The summary groups (Add-SIDataOutSummaryItems) -> one summary item per group. #>
    param([Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Groups)
    $groups = $Groups
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($g in $groups.Values) {
        $o = [ordered]@{}
        foreach ($f in 'si_security_domain', 'si_report_name', 'si_finding_key', 'si_title', 'si_tier', 'si_severity', 'si_cmdb_id', 'si_cmdb_name', 'si_risk_rating') { $o[$f] = $g[$f] }
        $o['ci_count'] = $g.Cis.Count
        $o['ci_names'] = @($g.Names)
        $o['max_risk_score'] = $g.Max
        $o['max_weighted_risk_score'] = $g.MaxW
        $out.Add([pscustomobject]$o)
    }
    return , $out.ToArray()
}

function Get-SIDataOutDisabledCiSql {
    <# The CIs whose account a provider record says is disabled in its own directory (records are kept every run, so current). #>
    @'
IF OBJECT_ID('sidata.CiRecord') IS NULL SELECT CAST(NULL AS NVARCHAR(64)) AS CiId WHERE 1 = 0;
ELSE SELECT DISTINCT r.CiId FROM sidata.CiRecord AS r
WHERE r.CiId IS NOT NULL AND r.Provider IN (N'entra', N'ad', N'eg', N'mdi') AND LOWER(JSON_VALUE(r.DocJson, '$.si_account_enabled')) = N'false';
'@
}

function Select-SIDataOutEnabledItems {
    <#
    .SYNOPSIS  PURE. SI_DisabledAssets_Connectors for data out: an item of a disabled account or device (its CI is in
               -DisabledCis, or the item itself says si_account_enabled = false) is left out of what is sent, and its key
               is returned in FrozenKeys -- the writer keeps what it sent before for it (never "no longer sent").
               -Include (the setting on, or collection off) keeps everything. A summary is made from kept findings only.
    .OUTPUTS   @{ Kept; FrozenKeys (string[]); Count }
    #>
    param([Parameter(Mandatory)][string]$Grain, [AllowEmptyCollection()][object[]]$Items = @(), [AllowEmptyCollection()][string[]]$DisabledCis = @(), [bool]$Include = $false)
    if ($Include -or $Grain -eq 'finding_summary') { return [pscustomobject]@{ Kept = @($Items); FrozenKeys = [string[]]@(); Count = 0 } }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in @($DisabledCis)) { if ($c) { [void]$set.Add([string]$c) } }
    $kept = New-Object System.Collections.Generic.List[object]; $frozen = New-Object System.Collections.Generic.List[string]
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        $ci = [string](Get-SIItemValue $it 'si_ci_id')
        if (($ci -and $set.Contains($ci)) -or (Test-SIAssetDisabled -Asset $it)) { $frozen.Add((Get-SIDataOutItemKey -Grain $Grain -Item $it)) } else { $kept.Add($it) }
    }
    [pscustomobject]@{ Kept = $kept.ToArray(); FrozenKeys = $frozen.ToArray(); Count = $frozen.Count }
}

function Read-SIDataOutItems {
    <#
        The items of one grain from the database, WHOLE (-Invoke: the data database, mode 'reader' | 'scalar') -- the pages
        of Read-SIDataOutItemPages collected, for a caller that needs the set at once. The data-out step never does: it hands
        each output the grain a page at a time and keeps no grain for another output (#639). -Cache '__disabled' (the
        SI_DisabledAssets_Connectors decision): disabled accounts' items are left out, their keys kept as '__frozen:<grain>'.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Grain, [hashtable]$Cache = @{})
    $d = $null; if ($Cache.ContainsKey('__disabled')) { $d = $Cache['__disabled'] }
    $all = New-Object System.Collections.Generic.List[object]
    $fz = New-Object System.Collections.Generic.List[string]
    $null = Read-SIDataOutItemPages -Invoke $Invoke -Grain $Grain -Disabled $d -OnPage { param($items, $frozen) foreach ($x in @($items)) { $all.Add($x) }; foreach ($k in @($frozen)) { if ($k) { $fz.Add([string]$k) } } }
    if ($null -ne $d) { $Cache['__frozen:' + $Grain] = [string[]]$fz.ToArray() }
    return , $all.ToArray()
}

# =====================================================================================================================
#  BEFORE / NOW
# =====================================================================================================================

function Get-SIDataOutRowText {
    <# PURE. One cell as text: what is compared, stored and shown as before / now. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [ValueType]) { return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture) }
    return ($Value | ConvertTo-Json -Compress -Depth 6)
}

function ConvertTo-SIDataOutState {
    <#
    .SYNOPSIS  PURE. Mapped rows -> per item: its key, its content as text (column -> text, the run's own columns left
               out: run id, run time, change time, row hash) and the SHA-256 of that content.
    .PARAMETER Volatile  the output's column names whose value is the run's, not the item's
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][string[]]$Keys = @(), [AllowEmptyCollection()][string[]]$Volatile = @())
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $out = [ordered]@{}
    try {
        for ($i = 0; $i -lt $Rows.Count; $i++) {
            $r = $Rows[$i]; $k = [string]$Keys[$i]
            if (-not $k) { continue }
            $cells = [ordered]@{}
            foreach ($p in $r.PSObject.Properties) { if ($Volatile -notcontains $p.Name) { $cells[$p.Name] = Get-SIDataOutRowText $p.Value } }
            $json = ConvertTo-Json -InputObject $cells -Compress
            $h = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))) -replace '-', '').ToLowerInvariant()
            $out[$k] = [pscustomobject]@{ Key = $k; Hash = $h; Cells = $cells; Json = $json; Index = $i }
        }
    } finally { $sha.Dispose() }
    return $out
}

function Compare-SIDataOutState {
    <#
    .SYNOPSIS  PURE. The items of this run against what was sent last time.
    .PARAMETER Previous  key -> @{ Hash; Json } (cfg.DataOutItem); empty = the first run (every item is written)
    .OUTPUTS   @{ Written (keys); Updated (@{ Key; Fields = column -> @(before, now) }); Removed (keys); Unchanged (count) }
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Current, [System.Collections.IDictionary]$Previous = @{})
    $written = New-Object System.Collections.Generic.List[string]
    $updated = New-Object System.Collections.Generic.List[object]
    $removed = New-Object System.Collections.Generic.List[string]
    $unchanged = 0
    foreach ($k in $Current.Keys) {
        $c = $Current[$k]
        if (-not $Previous.Contains($k)) { $written.Add($k); continue }
        $prev = $Previous[$k]
        if ([string]$prev.Hash -eq [string]$c.Hash) { $unchanged++; continue }
        $before = @{}
        if ($prev.Json) { try { $b = [string]$prev.Json | ConvertFrom-Json; foreach ($p in $b.PSObject.Properties) { $before[$p.Name] = [string]$p.Value } } catch { } }
        $fields = [ordered]@{}
        foreach ($n in $c.Cells.Keys) {
            $old = ''; if ($before.ContainsKey($n)) { $old = $before[$n] }
            if ($old -cne [string]$c.Cells[$n]) { $fields[$n] = @($old, [string]$c.Cells[$n]) }
        }
        foreach ($n in $before.Keys) { if (-not $c.Cells.Contains($n)) { $fields[$n] = @($before[$n], '') } }
        $updated.Add([pscustomobject]@{ Key = $k; Fields = $fields })
    }
    foreach ($k in $Previous.Keys) { if (-not $Current.Contains($k)) { $removed.Add([string]$k) } }
    return [pscustomobject]@{ Written = $written.ToArray(); Updated = $updated.ToArray(); Removed = $removed.ToArray(); Unchanged = $unchanged }
}

function ConvertTo-SIDataOutChanges {
    <#
    .SYNOPSIS  PURE. The comparison -> the item change log entries (ConvertTo-SIConnectorChangeRows' input): written (a
               new item), updated (each changed column, before and now), removed (no longer sent).
    #>
    param([Parameter(Mandatory)]$Compare, [Parameter(Mandatory)][System.Collections.IDictionary]$Current, [System.Collections.IDictionary]$Previous = @{},
          [string]$NameColumn, [datetime]$At = ([datetime]::UtcNow), [string]$Reason = '')
    $name = {
        param($cells)
        if ($NameColumn -and $cells -and $cells.Contains($NameColumn)) { return [string]$cells[$NameColumn] }
        return ''
    }
    $prevCells = {
        param([string]$k)
        $h = [ordered]@{}
        if ($Previous.Contains($k) -and $Previous[$k].Json) { try { $b = [string]$Previous[$k].Json | ConvertFrom-Json; foreach ($p in $b.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } } catch { } }
        $h
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $Compare.Written) { $out.Add([pscustomobject]@{ At = $At; Action = 'written'; ObjectName = (& $name $Current[$k].Cells); ObjectKey = $k; Finding = ''; TargetKey = $k; Fields = $null; Reason = $Reason; Error = '' }) }
    foreach ($u in $Compare.Updated) { $out.Add([pscustomobject]@{ At = $At; Action = 'updated'; ObjectName = (& $name $Current[$u.Key].Cells); ObjectKey = $u.Key; Finding = ''; TargetKey = $u.Key; Fields = $u.Fields; Reason = $Reason; Error = '' }) }
    foreach ($k in $Compare.Removed) { $out.Add([pscustomobject]@{ At = $At; Action = 'removed'; ObjectName = (& $name (& $prevCells $k)); ObjectKey = $k; Finding = ''; TargetKey = $k; Fields = $null; Reason = 'no longer in this output'; Error = '' }) }
    return , $out.ToArray()
}

function Get-SIDataOutStateReadSql {
    <# #639: what was sent for ONE PAGE of items (@klist: [{ k; h }]): the hash, and the row as sent only where the hash
       differs (the before of a change) -- never the state of the whole output. #>
    @'
IF OBJECT_ID('cfg.DataOutItem') IS NOT NULL
SELECT ItemKey, RowHash, RowJson FROM (
    SELECT d.ItemKey, d.RowHash, CASE WHEN d.RowHash = p.h THEN NULL ELSE d.RowJson END AS RowJson
    FROM OPENJSON(@klist) WITH (k nvarchar(380) '$.k', h char(64) '$.h') AS p
    JOIN cfg.DataOutItem AS d ON d.OutputId = @OutputId AND d.ItemKey = p.k) AS x;
'@
}

function Get-SIDataOutStatePageSql {
    <# #639: what an output sent before, a page at a time by its key (what is no longer sent, what is kept as last sent). #>
    @'
IF OBJECT_ID('cfg.DataOutItem') IS NOT NULL
SELECT ItemKey, RowHash, RowJson FROM (
    SELECT TOP (CONVERT(int, @Take)) ItemKey, RowHash, RowJson FROM cfg.DataOutItem WHERE OutputId = @OutputId AND ItemKey > @After ORDER BY ItemKey) AS x
ORDER BY ItemKey;
'@
}

function Get-SIDataOutRunStateResetSql {
    <# #912: the item state this run recorded for one output, marked to go again (the hash cleared to a value no row has). #>
    @'
IF OBJECT_ID('cfg.DataOutItem') IS NULL BEGIN SELECT 0 AS N; RETURN; END;
UPDATE cfg.DataOutItem SET RowHash = REPLICATE('0', 64) WHERE OutputId = @OutputId AND RunId = @RunId;
SELECT @@ROWCOUNT AS N;
'@
}

function Get-SIDataOutOrphanStateResetSql {
    <#
        #912: rows an EARLIER run recorded as sent (the last 7 days) whose run never recorded its end (cfg.ConnectorRun has no row
        for that run: the job stopped mid-push, so its batch stayed 'writing' and ServiceNow never imports it) -- marked to go again.
    #>
    @'
IF OBJECT_ID('cfg.DataOutItem') IS NULL OR OBJECT_ID('cfg.ConnectorRun') IS NULL BEGIN SELECT 0 AS N; RETURN; END;
UPDATE d SET RowHash = REPLICATE('0', 64)
FROM cfg.DataOutItem AS d
WHERE d.OutputId = @OutputId AND d.RunId <> @RunId AND d.RowHash <> REPLICATE('0', 64) AND d.SentAt > DATEADD(day, -7, SYSUTCDATETIME())
  AND NOT EXISTS (SELECT 1 FROM cfg.ConnectorRun AS r WHERE r.ConnectorName = @Connector AND r.RunId = d.RunId);
SELECT @@ROWCOUNT AS N;
'@
}

function Reset-SIDataOutOrphanState {
    <# #912: Get-SIDataOutOrphanStateResetSql through the store; how many rows go again. Throws on a store failure (the output fails, said). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$OutputId, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$Connector)
    $a = & $Store.Invoke (Get-SIDataOutOrphanStateResetSql) ([ordered]@{ OutputId = $OutputId; RunId = $RunId; Connector = $Connector }) 'reader'
    $n = 0L
    foreach ($r in @($a)) { if ($r -is [System.Collections.IDictionary] -and $r.Contains('N')) { $n = [long]$r['N'] } elseif ($r -and $r.PSObject.Properties['N']) { $n = [long]$r.N } }
    $n
}

function Reset-SIDataOutRunState {
    <#
        #912: a batch that did not end complete is never imported by ServiceNow -- every row this run recorded as sent for
        -OutputId is marked to go again, so the next complete batch carries it. Returns how many rows. THROWS when it cannot be
        done: the writer's catch then records the output's run as failed (said), never a quiet success over rows ServiceNow
        will not import.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$OutputId, [Parameter(Mandatory)][string]$RunId)
    $a = & $Store.Invoke (Get-SIDataOutRunStateResetSql) ([ordered]@{ OutputId = $OutputId; RunId = $RunId }) 'reader'
    $n = 0L
    foreach ($r in @($a)) { if ($r -is [System.Collections.IDictionary] -and $r.Contains('N')) { $n = [long]$r['N'] } elseif ($r -and $r.PSObject.Properties['N']) { $n = [long]$r.N } }
    $n
}

function Get-SIDataOutStateWriteSql {
    <# One chunk of the item state: the written / changed items upserted, the removed ones deleted (set-based). #>
    @'
IF OBJECT_ID('cfg.DataOutItem') IS NULL RETURN;
DELETE d FROM cfg.DataOutItem AS d JOIN OPENJSON(@gone) WITH (k nvarchar(380) '$') AS g ON g.k = d.ItemKey WHERE d.OutputId = @OutputId;
MERGE cfg.DataOutItem AS t
USING (SELECT j.k, j.h, j.r FROM OPENJSON(@rows) WITH (k nvarchar(380), h char(64), r nvarchar(max)) AS j) AS s
   ON t.OutputId = @OutputId AND t.ItemKey = s.k
WHEN MATCHED THEN UPDATE SET RowHash = s.h, RowJson = s.r, SentAt = SYSUTCDATETIME(), RunId = @RunId
WHEN NOT MATCHED THEN INSERT (OutputId, ItemKey, RowHash, RowJson, SentAt, RunId) VALUES (@OutputId, s.k, s.h, s.r, SYSUTCDATETIME(), @RunId);
'@
}

# =====================================================================================================================
#  ONE WRITER -- #639: A PAGE AT A TIME, END TO END
#  A page of items is filtered, mapped, keyed and hashed, compared with what was sent for THOSE keys (cfg.DataOutItem,
#  read by key), handed to the destination (the sheet streamed into the workbook / the ServiceNow Import Set), and what it
#  changed is recorded (the item state, the change log) -- before the next page is read. What an output holds is one page
#  and a bounded buffer of state rows and change entries; the keys it has seen are staged in the data database
#  (New-SIDataOutKeySet), never a set the size of the output. The items no longer sent are found by paging what was
#  sent before (by key) against the keys seen.
# =====================================================================================================================
$script:SIDataOutSheetRows = 1048575     # Excel's data rows per sheet; a larger output continues on '<sheet> (2)', ...
$script:SIDataOutStateChunk = 1000       # state rows / removed keys per statement
$script:SIDataOutChangeChunk = 20000     # change log entries buffered before they are written

function Invoke-SIDataOutWriterPage {
    <#
        ONE PAGE of the writer (Invoke-SIDataOutWriter's context -W): the map's filter, the mapped rows, their keys and
        hashes, the compare with what was sent for those keys. Counts into W.Res. Returns @{ Mapped; DeltaState (key ->
        @{ Hash; Json }); DeltaRows (the written + changed rows, mapped -- a hand-off only); Changes } or $null when the
        page keeps no item.
    #>
    param([Parameter(Mandatory)][hashtable]$W, [AllowEmptyCollection()][object[]]$Items = @(), [AllowEmptyCollection()][string[]]$Frozen = @())
    if (@($Frozen | Where-Object { $_ }).Count) { $null = Add-SIDataOutKeys -Set $W.FrozenSet -Keys ([string[]]@($Frozen)) }
    # the map's filter first, so every mapped row lines up with the item it came from (its key)
    $kept = @(@($Items) | Where-Object { $null -ne $_ -and (Test-SIOutputFilter -Item $_ -Filter $W.Map.filter) })
    if ($kept.Count -eq 0) { return $null }
    $mapped = @(Invoke-SIOutputMap -Map $W.Map -Items $kept -ValueMaps $W.ValueMaps -Context $W.Ctx)
    $keys = @(foreach ($it in $kept) { Get-SIDataOutItemKey -Grain $W.Grain -Item $it })
    $kept = $null
    if ($keys.Count -ne $mapped.Count) { throw 'the mapped rows do not line up with the items' }
    $W.Res.Rows += $mapped.Count
    $cur = ConvertTo-SIDataOutState -Rows $mapped -Keys $keys -Volatile $W.Volatile
    # an item already seen on an earlier page keeps that page's state (its row is in the output either way)
    $added = Add-SIDataOutKeys -Set $W.Seen -Keys ([string[]]@($cur.Keys))
    $new = [ordered]@{}
    foreach ($k in @($cur.Keys)) { if ($added.Contains([string]$k)) { $new[$k] = $cur[$k] } }
    $cur = $null
    # what was sent for THESE keys (by key, the row as sent only where it changed)
    $prev = [ordered]@{}
    if ($W.Store -and $new.Count) {
        $req = @(foreach ($k in $new.Keys) { [ordered]@{ k = [string]$k; h = [string]$new[$k].Hash } })
        for ($i = 0; $i -lt $req.Count; $i += 2000) {
            $part = @($req[$i..([Math]::Min($i + 2000, $req.Count) - 1)])
            $a = & $W.Store.Invoke (Get-SIDataOutStateReadSql) @{ OutputId = $W.OutputId; klist = (ConvertTo-Json -InputObject $part -Compress) } 'reader'
            foreach ($p in @($a)) {
                if (-not $p) { continue }
                $pk = [string]$p['ItemKey']
                if (-not $new.Contains($pk) -or $prev.Contains($pk)) { continue }
                $prev[$pk] = [pscustomobject]@{ Hash = [string]$p['RowHash']; Json = $(if ($null -eq $p['RowJson'] -or $p['RowJson'] -is [System.DBNull]) { '' } else { [string]$p['RowJson'] }) }
            }
            $a = $null
        }
    }
    $cmp = Compare-SIDataOutState -Current $new -Previous $prev
    $nW = @($cmp.Written).Count; $nU = @($cmp.Updated).Count
    $W.Res.Written += $nW; $W.Res.Updated += $nU; $W.Res.Unchanged += [int]$cmp.Unchanged
    $ds = [ordered]@{}
    $dr = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($cmp.Written) + @($cmp.Updated | ForEach-Object { $_.Key })) {
        if (-not $k) { continue }
        $ds[$k] = [pscustomobject]@{ Hash = $new[$k].Hash; Json = $new[$k].Json }
        if ($W.KeepDelta) { $dr.Add($mapped[$new[$k].Index]) }
    }
    # one list (return , ...): assigned, then enumerated -- @(<the call>) would be ONE item, the list
    $chs = ConvertTo-SIDataOutChanges -Compare $cmp -Current $new -Previous $prev -NameColumn $W.NameCol -Reason $W.Label
    @{ Mapped = $mapped; DeltaState = $ds; DeltaRows = $dr.ToArray(); Changes = @($chs); Written = $nW; Updated = $nU }
}

function Add-SIDataOutCommit {
    <#
        What a page that LANDED leaves behind (never on a what-if, never without the settings database): its change log
        entries (written / changed / no longer sent) and -- -State, when the destination took every row of it -- its item
        state (written / changed upserted, -Gone deleted). Buffered and written in chunks (Write-SIDataOutCommits).
    #>
    param([Parameter(Mandatory)][hashtable]$W, $Page, [bool]$State = $true, [AllowEmptyCollection()][object[]]$Changes = @(), [AllowEmptyCollection()][string[]]$Gone = @())
    if (-not $W.Store -or $W.WhatIf) { return }
    $chs = @(); if ($Page) { $chs = @($Page.Changes) }
    foreach ($ch in @($chs) + @($Changes)) { if ($ch) { $W.ChangeBuf.Add($ch) } }
    if ($State) {
        if ($Page) { foreach ($k in $Page.DeltaState.Keys) { $W.StateBuf.Add([ordered]@{ k = $k; h = $Page.DeltaState[$k].Hash; r = $Page.DeltaState[$k].Json }) } }
        foreach ($g in @($Gone)) { if ($g) { $W.GoneBuf.Add([string]$g) } }
    }
    if ($W.StateBuf.Count -ge $script:SIDataOutStateChunk -or $W.GoneBuf.Count -ge $script:SIDataOutStateChunk) { Write-SIDataOutCommits -W $W -State }
    if ($W.ChangeBuf.Count -ge $script:SIDataOutChangeChunk) { Write-SIDataOutCommits -W $W -Changes }
}

function Write-SIDataOutCommits {
    <# Writes the buffered state (chunks of SIDataOutStateChunk, set-based) and / or the change log entries. A state write
       that fails throws (the output's failure); a change log that cannot be written is said once. #>
    param([Parameter(Mandatory)][hashtable]$W, [switch]$State, [switch]$Changes)
    if (-not $W.Store) { return }
    if ($State) {
        $chunk = $script:SIDataOutStateChunk
        while ($W.StateBuf.Count -gt 0 -or $W.GoneBuf.Count -gt 0) {
            $nr = [Math]::Min($chunk, $W.StateBuf.Count); $ng = [Math]::Min($chunk, $W.GoneBuf.Count)
            $pr = @(); if ($nr) { $pr = $W.StateBuf.GetRange(0, $nr).ToArray() }
            $pg = @(); if ($ng) { $pg = $W.GoneBuf.GetRange(0, $ng).ToArray() }
            [void](& $W.Store.Invoke (Get-SIDataOutStateWriteSql) ([ordered]@{ OutputId = $W.OutputId; RunId = $W.RunId; rows = (ConvertTo-Json -InputObject @($pr) -Compress -Depth 4); gone = (ConvertTo-Json -InputObject ([string[]]@($pg)) -Compress) }) 'nonquery')
            if ($nr) { $W.StateBuf.RemoveRange(0, $nr) }
            if ($ng) { $W.GoneBuf.RemoveRange(0, $ng) }
        }
    }
    if ($Changes -and $W.ChangeBuf.Count -gt 0) {
        $rows = $W.ChangeBuf.ToArray(); $W.ChangeBuf.Clear()
        if (-not (Get-Command -Name Write-SIConnectorChanges -ErrorAction SilentlyContinue)) { return }
        try {
            $Store = $W.Store
            $e2 = Write-SIConnectorChanges -Store $Store -Rows (ConvertTo-SIConnectorChangeRows -Changes $rows -ConnectorName ([string]$W.Entry.connector) -RunId $W.RunId -TargetTable $W.Target)
            if ($e2 -and -not $W.ChangeWarned) { $W.ChangeWarned = $true; & $W.Log 'WARN' ('{0}: the item change log could not be recorded -- {1}' -f $W.Label, $e2) }
        } catch { if (-not $W.ChangeWarned) { $W.ChangeWarned = $true; & $W.Log 'WARN' ('{0}: the item change log could not be recorded -- {1}' -f $W.Label, $_.Exception.Message) } }
    }
}

function Get-SIDataOutPreviousPage {
    <#
        #639 WHAT WAS SENT BEFORE AND IS NOT IN THIS RUN, a page at a time (cfg.DataOutItem by key, against the keys this run
        saw): @{ Carried (cells of the rows kept as last sent: an item of a report the newest run could not complete);
        Gone (@{ Key; Json } -- no longer sent); Frozen (left out as disabled: what was sent stays) } or $null at the end.
        W.PrevAfter is the cursor (set to '' to start over).
    #>
    param([Parameter(Mandatory)][hashtable]$W, [switch]$Cells)
    if (-not $W.Store -or $W.PrevDone) { return $null }
    $take = [int]$W.PageSize
    $a = & $W.Store.Invoke (Get-SIDataOutStatePageSql) @{ OutputId = $W.OutputId; Take = $take; After = [string]$W.PrevAfter } 'reader'
    $rows = @(@($a) | Where-Object { $_ }); $a = $null
    if ($rows.Count -eq 0) { $W.PrevDone = $true; return $null }
    $W.PrevAfter = [string]$rows[$rows.Count - 1]['ItemKey']
    if ($rows.Count -lt $take) { $W.PrevDone = $true }
    $keys = [string[]]@($rows | ForEach-Object { [string]$_['ItemKey'] })
    $seen = Find-SIDataOutKeys -Set $W.Seen -Keys $keys
    $frz = Find-SIDataOutKeys -Set $W.FrozenSet -Keys $keys
    $car = Find-SIDataOutKeys -Set $W.CarrySet -Keys $keys
    $out = @{ Carried = (New-Object 'System.Collections.Generic.List[object[]]'); Gone = (New-Object System.Collections.Generic.List[object]); Frozen = 0 }
    foreach ($r in $rows) {
        $k = [string]$r['ItemKey']
        if ($seen.Contains($k)) { continue }
        if ($frz.Contains($k)) { $out.Frozen++; continue }
        $pj = $(if ($null -eq $r['RowJson'] -or $r['RowJson'] -is [System.DBNull]) { '' } else { [string]$r['RowJson'] })
        $isCarry = $car.Contains($k)
        if (-not $isCarry) { foreach ($cp in $W.CarryPrefixes) { if ($k.StartsWith([string]$cp, [StringComparison]::Ordinal)) { $isCarry = $true; break } } }
        if ($isCarry) {
            # its last row stays in the output (a file is written whole every run); nothing is sent for it
            $cellRow = $null
            if ($Cells -and $pj) { try { $pc = ConvertFrom-Json -InputObject $pj; $cellRow = [object[]]@(foreach ($h in $W.Header) { if ($pc.PSObject.Properties[$h]) { [string]$pc.$h } else { '' } }) } catch { $cellRow = $null } }
            $out.Carried.Add($cellRow)
            continue
        }
        $out.Gone.Add([pscustomobject]@{ Key = $k; Json = $pj })
    }
    $out
}

function Invoke-SIDataOutGonePass {
    <#
        The items no longer sent, page by page (Get-SIDataOutPreviousPage): counted always; with -Apply (the destination
        took the run) each is logged as no longer sent, and with -ApplyState its state row is deleted. Sets W.Res.Removed /
        Carried and W.FrozenGone.
    #>
    param([Parameter(Mandatory)][hashtable]$W, [switch]$Apply, [switch]$ApplyState)
    $W.PrevAfter = ''; $W.PrevDone = $false
    $removed = 0L; $carried = 0L; $frozen = 0L
    while ($null -ne ($pp = Get-SIDataOutPreviousPage -W $W)) {
        $carried += $pp.Carried.Count; $frozen += $pp.Frozen
        $removed += $pp.Gone.Count
        if ($Apply -and $pp.Gone.Count) {
            $prev = [ordered]@{}; foreach ($g in $pp.Gone) { $prev[$g.Key] = [pscustomobject]@{ Hash = ''; Json = $g.Json } }
            $rmCmp = [pscustomobject]@{ Written = @(); Updated = @(); Removed = [string[]]@($pp.Gone | ForEach-Object { $_.Key }); Unchanged = 0 }
            $rmChs = ConvertTo-SIDataOutChanges -Compare $rmCmp -Current ([ordered]@{}) -Previous $prev -NameColumn $W.NameCol -Reason $W.Label
            Add-SIDataOutCommit -W $W -State ([bool]$ApplyState) -Changes @($rmChs) -Gone ([string[]]@($pp.Gone | ForEach-Object { $_.Key }))
        }
        $pp = $null
    }
    $W.Res.Removed = [int]$removed
    $W.Res['Carried'] = [int]$carried
    $W.FrozenGone = $frozen
}

function Get-SIDataOutSheetColumns {
    <# The sheet's column names as the streamed writer makes them (cleaned, non-empty, unique ignoring case) -- each row is
       handed to it by these names. #>
    param([Parameter(Mandatory)][string[]]$Header)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out = New-Object 'string[]' $Header.Count
    for ($i = 0; $i -lt $Header.Count; $i++) {
        $h = (_SIXlsx-CleanName $Header[$i]).Trim(); if ($h.Length -eq 0) { $h = 'Column' + ($i + 1) }; if ($h.Length -gt 255) { $h = $h.Substring(0, 255) }
        $c = $h; $k = 2; while (-not $seen.Add($c)) { $c = $h + $k; $k++ }; $out[$i] = $c
    }
    , $out
}

function ConvertTo-SIDataOutSheetRows {
    <# PURE. Rows of cells (header order) -> one object per row under the sheet's column names (Get-SIDataOutSheetColumns). #>
    param([Parameter(Mandatory)][string[]]$Columns, [AllowEmptyCollection()][object[]]$CellRows = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($cr in $CellRows) {
        if ($null -eq $cr) { continue }
        $o = [ordered]@{}
        for ($i = 0; $i -lt $Columns.Count; $i++) { $o[$Columns[$i]] = $(if ($i -lt $cr.Count) { $cr[$i] } else { $null }) }
        $out.Add([pscustomobject]$o)
    }
    , $out.ToArray()
}

function Get-SIDataOutSheetPage {
    <#
        The streamed workbook's next page (Write-RAXlsxStreamed -NextPage): the next page of items through the writer (its
        rows' cells; what it changed is recorded as it goes), then the rows kept as last sent; $null at the end.
    #>
    param([Parameter(Mandatory)][hashtable]$W)
    while ($true) {
        switch ($W.Phase) {
            'items' {
                $pg = Get-SIDataOutNextPage -Cursor $W.Cursor
                if ($null -eq $pg) { $W.Phase = 'carry'; $W.PrevAfter = ''; $W.PrevDone = (-not $W.HasCarry); continue }
                $r = Invoke-SIDataOutWriterPage -W $W -Items @($pg.Items) -Frozen ([string[]]@($pg.Frozen))
                $pg = $null
                if ($null -eq $r) { continue }
                Add-SIDataOutCommit -W $W -Page $r
                $cells = @(foreach ($m in $r.Mapped) { , [object[]](ConvertTo-SIDataOutCells -Row $m -Header $W.Header) })
                $r = $null
                return , (ConvertTo-SIDataOutSheetRows -Columns $W.SheetColumns -CellRows $cells)
            }
            'carry' {
                $pp = Get-SIDataOutPreviousPage -W $W -Cells
                if ($null -eq $pp) { $W.Phase = 'end'; return $null }
                $cells = @($pp.Carried | Where-Object { $null -ne $_ })
                if ($cells.Count -eq 0) { continue }
                return , (ConvertTo-SIDataOutSheetRows -Columns $W.SheetColumns -CellRows $cells)
            }
            default { return $null }
        }
    }
}

function Join-SIDataOutWorkbook {
    <#
        Puts the sheet(s) of a streamed workbook (-Part, Write-RAXlsxStreamed's: one output, split over '<sheet> (2)', ...
        when larger than a sheet) into the output's workbook (-Path): every other sheet already there stays as it is (its
        XML copied as a stream, its table kept), the sheets of this output written before (same name, or '<name> (n)') are
        replaced. Built beside the target and moved over it only when complete; without a workbook there yet, the part
        becomes it. Returns the sheet names of the part.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Part, [Parameter(Mandatory)][string[]]$PartSheets)
    if (-not [IO.File]::Exists($Path)) { [IO.File]::Move($Part, $Path); return }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $nsMain = $script:SIXlsxNsMain; $nsRel = $script:SIXlsxNsRel; $nsPkg = $script:SIXlsxNsPkg; $nsCt = $script:SIXlsxNsCt
    $tmp = $Path + '.si-join.tmp'
    $zin = $null; $zp = $null; $fs = $null; $zout = $null
    try {
        try { $zin = [System.IO.Compression.ZipFile]::OpenRead($Path) } catch { $zin = $null }
        if ($null -eq $zin -or $null -eq $zin.GetEntry('xl/workbook.xml') -or $null -eq $zin.GetEntry('[Content_Types].xml')) {
            # not a workbook this writer can add to (unreadable): the part replaces it
            if ($null -ne $zin) { $zin.Dispose(); $zin = $null }
            [IO.File]::Delete($Path); [IO.File]::Move($Part, $Path); return
        }
        $read = { param($z, [string]$n) $e = $z.GetEntry($n); if ($null -eq $e) { return $null }; $s = $e.Open(); try { $ms = New-Object System.IO.MemoryStream; $s.CopyTo($ms); , $ms.ToArray() } finally { $s.Dispose() } }
        $wbDoc = _SIXlsx-LoadXml (& $read $zin 'xl/workbook.xml')
        $relsBytes = & $read $zin 'xl/_rels/workbook.xml.rels'
        $wbRels = _SIXlsx-LoadXml $relsBytes
        $ctDoc = _SIXlsx-LoadXml (& $read $zin '[Content_Types].xml')
        $nsm = New-Object System.Xml.XmlNamespaceManager($wbDoc.NameTable); $nsm.AddNamespace('m', $nsMain)
        $sheetsEl = $wbDoc.DocumentElement.SelectSingleNode('m:sheets', $nsm)
        $relById = @{}; foreach ($rel in @($wbRels.DocumentElement.ChildNodes)) { if ($rel.NodeType -eq 'Element') { $relById[$rel.GetAttribute('Id')] = $rel } }
        # the sheets of this output written before: its own names, and '<first name> (n)'
        $family = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $PartSheets) { [void]$family.Add($n) }
        $base = [regex]::Escape([string]$PartSheets[0])
        $drop = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $nodes = @($sheetsEl.SelectNodes('m:sheet', $nsm))
        for ($si = $nodes.Count - 1; $si -ge 0; $si--) {
            $sn = $nodes[$si]; $nm = $sn.GetAttribute('name')
            if (-not ($family.Contains($nm) -or $nm -match ('^(?i)' + $base + ' \(\d+\)$'))) { continue }
            $rid = $sn.GetAttribute('id', $nsRel)
            if ($relById.ContainsKey($rid)) {
                $sp = _SIXlsx-ResolveTarget 'xl' $relById[$rid].GetAttribute('Target')
                [void]$drop.Add($sp)
                $spRels = _SIXlsx-RelsPathFor $sp
                $rb = & $read $zin $spRels
                if ($null -ne $rb) {
                    [void]$drop.Add($spRels)
                    foreach ($r2 in (_SIXlsx-LoadXml $rb).DocumentElement.ChildNodes) {
                        if ($r2.NodeType -ne 'Element' -or $r2.GetAttribute('TargetMode') -eq 'External') { continue }
                        $tp = _SIXlsx-ResolveTarget (_SIXlsx-DirOf $sp) $r2.GetAttribute('Target'); [void]$drop.Add($tp); [void]$drop.Add((_SIXlsx-RelsPathFor $tp))
                    }
                }
                [void]$relById[$rid].ParentNode.RemoveChild($relById[$rid]); $relById.Remove($rid)
            }
            [void]$sheetsEl.RemoveChild($sn)
            foreach ($dn in @($wbDoc.DocumentElement.SelectNodes('m:definedNames/m:definedName', $nsm))) {
                if (-not $dn.HasAttribute('localSheetId')) { continue }
                $l = [int]$dn.GetAttribute('localSheetId')
                if ($l -eq $si) { [void]$dn.ParentNode.RemoveChild($dn) } elseif ($l -gt $si) { $dn.SetAttribute('localSheetId', [string]($l - 1)) }
            }
        }
        foreach ($wv in @($wbDoc.DocumentElement.SelectNodes('m:bookViews/m:workbookView', $nsm))) { foreach ($at in 'activeTab', 'firstSheet') { if ($wv.HasAttribute($at)) { $wv.SetAttribute($at, '0') } } }
        foreach ($rel in @($relById.Values)) { if ($rel.GetAttribute('Type') -like '*/calcChain') { [void]$drop.Add((_SIXlsx-ResolveTarget 'xl' $rel.GetAttribute('Target'))); [void]$rel.ParentNode.RemoveChild($rel); $relById.Remove($rel.GetAttribute('Id')) } }
        $live = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($e in $zin.Entries) { if (-not $drop.Contains($e.FullName)) { [void]$live.Add($e.FullName) } }
        $tblIdMax = 0; $tblNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $live) {
            if ($n -notlike '*/tables/*.xml') { continue }
            try { $td = _SIXlsx-LoadXml (& $read $zin $n); $v = [int]$td.DocumentElement.GetAttribute('id'); if ($v -gt $tblIdMax) { $tblIdMax = $v }; [void]$tblNames.Add($td.DocumentElement.GetAttribute('name')); [void]$tblNames.Add($td.DocumentElement.GetAttribute('displayName')) } catch { }
        }
        $sheetIdMax = 0; foreach ($sn in $sheetsEl.SelectNodes('m:sheet', $nsm)) { $v = [int]$sheetsEl.OwnerDocument.ImportNode($sn, $true).GetAttribute('sheetId'); if ($v -gt $sheetIdMax) { $sheetIdMax = $v } }
        foreach ($ov in @($ctDoc.DocumentElement.ChildNodes)) { if ($ov.NodeType -eq 'Element' -and $ov.LocalName -eq 'Override' -and $drop.Contains(([string]$ov.GetAttribute('PartName')).TrimStart('/'))) { [void]$ctDoc.DocumentElement.RemoveChild($ov) } }

        $zp = [System.IO.Compression.ZipFile]::OpenRead($Part)
        $fs = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite)
        $zout = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        $level = [System.IO.Compression.CompressionLevel]::Optimal
        $copy = { param($from, [string]$fromName, [string]$toName) $e = $from.GetEntry($fromName); $s = $e.Open(); try { $d = $zout.CreateEntry($toName, $level).Open(); try { $s.CopyTo($d) } finally { $d.Dispose() } } finally { $s.Dispose() } }
        $put = { param([string]$name, [byte[]]$bytes) $d = $zout.CreateEntry($name, $level).Open(); try { $d.Write($bytes, 0, $bytes.Length) } finally { $d.Dispose() } }
        $special = @('xl/workbook.xml', 'xl/_rels/workbook.xml.rels', '[Content_Types].xml')
        foreach ($e in $zin.Entries) { if ($live.Contains($e.FullName) -and $special -notcontains $e.FullName) { & $copy $zin $e.FullName $e.FullName } }
        # the part's sheets: new part names, rel ids, sheet ids and table ids / names
        for ($i = 0; $i -lt $PartSheets.Count; $i++) {
            $no = $i + 1
            $k = 1; while ($live.Contains("xl/worksheets/sheet$k.xml")) { $k++ }; $sp = "xl/worksheets/sheet$k.xml"; [void]$live.Add($sp)
            $k = 1; while ($live.Contains("xl/tables/table$k.xml")) { $k++ }; $tp = "xl/tables/table$k.xml"; [void]$live.Add($tp)
            $k = 1; while ($relById.ContainsKey("rId$k")) { $k++ }; $rid = "rId$k"
            & $copy $zp "xl/worksheets/sheet$no.xml" $sp
            $td = _SIXlsx-LoadXml (& $read $zp "xl/tables/table$no.xml")
            $tblIdMax++; $td.DocumentElement.SetAttribute('id', [string]$tblIdMax)
            $tn = $td.DocumentElement.GetAttribute('name'); $cand = $tn; $j = 2; while ($tblNames.Contains($cand)) { $cand = $tn + '_' + $j; $j++ }
            [void]$tblNames.Add($cand); $td.DocumentElement.SetAttribute('name', $cand); $td.DocumentElement.SetAttribute('displayName', $cand)
            & $put $tp (_SIXlsx-XmlBytes $td)
            & $put (_SIXlsx-RelsPathFor $sp) ($utf8.GetBytes('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="' + $nsPkg + '"><Relationship Id="rId1" Type="' + $script:SIXlsxRelTbl + '" Target="../tables/' + [IO.Path]::GetFileName($tp) + '"/></Relationships>'))
            $sheetIdMax++
            $ns = $wbDoc.CreateElement('sheet', $nsMain); $ns.SetAttribute('name', $PartSheets[$i]); $ns.SetAttribute('sheetId', [string]$sheetIdMax); [void]$ns.SetAttribute('id', $nsRel, $rid); [void]$sheetsEl.AppendChild($ns)
            $nr = $wbRels.CreateElement('Relationship', $nsPkg); $nr.SetAttribute('Id', $rid); $nr.SetAttribute('Type', $script:SIXlsxRelWs); $nr.SetAttribute('Target', 'worksheets/' + [IO.Path]::GetFileName($sp)); [void]$wbRels.DocumentElement.AppendChild($nr); $relById[$rid] = $nr
            foreach ($pair in @(@($sp, $script:SIXlsxCtWs), @($tp, $script:SIXlsxCtTbl))) { $ov = $ctDoc.CreateElement('Override', $nsCt); $ov.SetAttribute('PartName', '/' + $pair[0]); $ov.SetAttribute('ContentType', $pair[1]); [void]$ctDoc.DocumentElement.AppendChild($ov) }
        }
        & $put 'xl/workbook.xml' (_SIXlsx-XmlBytes $wbDoc)
        & $put 'xl/_rels/workbook.xml.rels' (_SIXlsx-XmlBytes $wbRels)
        & $put '[Content_Types].xml' (_SIXlsx-XmlBytes $ctDoc)
        $zout.Dispose(); $zout = $null; $fs.Close(); $fs = $null
        $zp.Dispose(); $zp = $null; $zin.Dispose(); $zin = $null
        [IO.File]::Delete($Path); [IO.File]::Move($tmp, $Path); [IO.File]::Delete($Part)
    } catch {
        foreach ($d in @($zout, $fs, $zp, $zin)) { if ($null -ne $d) { try { $d.Dispose() } catch { } } }
        if ([IO.File]::Exists($tmp)) { try { [IO.File]::Delete($tmp) } catch { } }
        if ([IO.File]::Exists($Part)) { try { [IO.File]::Delete($Part) } catch { } }
        throw
    }
}

function Import-SIDataOutXlsx {
    <# Loads the workbook writers (SI's own, no module) into the CALLER's scope: dot-source the lines this returns. #>
    $rs = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'risk-analysis', '_shared')
    @([IO.Path]::Combine($rs, 'RA-XlsxWriter.ps1'), [IO.Path]::Combine($rs, 'RA-WorkbookExport.ps1'))
}

function Write-SIDataOutSheet {
    <#
        THE EXCEL DESTINATION: one sheet of the output's workbook, streamed (Write-RAXlsxStreamed): -NextPage hands the
        rows a page at a time (only one page is held), a sheet holds Excel's 1,048,575 data rows (-SheetRows) and the
        output continues on '<sheet> (2)', ... -- never a cut. Written to its own part beside the workbook, then joined in
        (Join-SIDataOutWorkbook): another output's sheet in the same file stays. Returns @{ Rows; Sheets; Path }.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$SheetName, [Parameter(Mandatory)][string[]]$Header,
          [Parameter(Mandatory)][scriptblock]$NextPage, [int]$SheetRows = 0)
    if ($SheetRows -le 0) { $SheetRows = $script:SIDataOutSheetRows }
    $dir = [IO.Path]::GetDirectoryName($Path)
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $part = '{0}.{1}.si-sheet.xlsx' -f $Path, (([string]$SheetName) -replace '[^A-Za-z0-9]', '')
    if ([IO.File]::Exists($part)) { [IO.File]::Delete($part) }
    $xr = Write-RAXlsxStreamed -Path $part -SheetName $SheetName -Columns $Header -NextPage $NextPage -SheetRows $SheetRows
    Join-SIDataOutWorkbook -Path $Path -Part $part -PartSheets ([string[]]@($xr.Sheets))
    [pscustomobject]@{ Rows = [long]$xr.Rows; Sheets = @($xr.Sheets); Path = $Path }
}

# ---- the ServiceNow Import Set, a page at a time --------------------------------------------------------------------

function Open-SIDataOutSnowSession {
    <#
        THE CHECK BEFORE EVERY RUN, once per run (Invoke-SISnowOutputCheck: the connection, the table, its columns and its
        column mapping against the columns this output sends -- recorded for the web app, the data health page, the heartbeat
        and the daily mail); the pages are then sent through it (Send-SIDataOutSnowPage). Returns the session:
        @{ Table; Connection; Check; Held; Reason; Unavailable (Pro is not installed); Failed (no table); Sent; Errors; Store; Connector }.
    #>
    param([Parameter(Mandatory)]$Entry, [string[]]$Header, $Store, [scriptblock]$SnowConnect, [string]$Here, [string]$RunId = ([guid]::NewGuid().ToString()),
          # #914: the batch's mode (live | resync | test) and the request it carries out; -NoBatch = the check only (the caller
          # opens the batch); -Prelude { param($Session) } runs after the check and before the writing row (the stale batches
          # are ended and the last batch's import result is read back there)
          [ValidateSet('live', 'resync', 'test')][string]$Mode = 'live', [string]$RequestToken = '', [switch]$NoBatch, [scriptblock]$Prelude)
    if (-not $Here) { $Here = $PSScriptRoot }
    $s = @{ Entry = $Entry; Header = @($Header); Table = ''; Connection = $null; Check = $null; Held = $false; Reason = ''; Unavailable = $false; Failed = ''
            Sent = 0L; Errors = (New-Object System.Collections.Generic.List[string]); Store = $Store; Connector = ''; PushReason = ''; Delta = 0L
            RunId = $RunId; StatusTable = ''; BatchId = ''; BatchState = ''; StatusWarning = ''; StatusProblem = ''
            Mode = $Mode; RequestToken = $RequestToken; Counts = (New-SIDataOutActionCounts); StatusOk = $false; EndReason = '' }
    $s.Table = [string](Get-Variable -Name ([string]$Entry.tableSetting) -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrWhiteSpace($s.Table)) { $s.Failed = ('no Import Set table is set ({0})' -f $Entry.tableSetting); return $s }
    $cmdbShared = [IO.Path]::Combine((Split-Path -Parent $Here), 'asset-cmdb', '_shared')
    if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($cmdbShared, 'SI-SnowImportSet.ps1')))) { $s.Unavailable = $true; return $s }
    foreach ($f in 'SI-ServiceNowClient.ps1', 'SI-SnowImportSet.ps1', 'SI-SnowVerify.ps1') {
        $fn = switch -Wildcard ($f) { '*Client*' { 'New-SISnowConnection' } '*ImportSet*' { 'Invoke-SISnowImportSetPush' } default { 'Invoke-SISnowOutputCheck' } }
        if (-not (Get-Command -Name $fn -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($cmdbShared, $f)) }
    }
    # THE ONE WAY a ServiceNow output gets its connection (SI-SnowVerify.ps1, #903): the ONE switched-on ServiceNow data-out
    # connector, which feeds both ServiceNow outputs (its instance and its API key or user + password, by their Key Vault
    # names). None switched on, two switched on, or a registry that cannot be read: NO connection -- the check fails, the push
    # is held and nothing is sent (said). Never the install's own secrets, a switched-off connector or the close-loop's. The
    # data-out connector reaches only the Import Set API: it never writes records directly.
    $sel = [pscustomobject]@{ Entry = $null; Problem = 'the connector registry is not available here -- nothing is sent to ServiceNow'; On = @() }
    if ($Store -and (Get-Command -Name Read-SIConnectorRows -ErrorAction SilentlyContinue)) {
        try { $sel = Select-SISnowDataOutConnector -Rows @(Read-SIConnectorRows -Store $Store) }
        catch { $sel = [pscustomobject]@{ Entry = $null; Problem = ('the connectors could not be read ({0}) -- nothing is sent to ServiceNow' -f $_.Exception.Message); On = @() } }
    }
    $snowEntry = $sel.Entry
    $s.Connector = $(if ($snowEntry) { [string]$snowEntry.Name } else { '' })
    $cn = if ($SnowConnect) { & $SnowConnect $snowEntry } else { Resolve-SISnowOutputConnection -Entry $snowEntry -NoEntryProblem ([string]$sel.Problem) }
    $s.Connection = $cn.Connection; $s.ConnProblem = [string]$cn.Problem; $s.Source = [string]$cn.Source
    # no data-out connector: never a connection, whatever a seam answers
    if (-not $snowEntry) { $s.Connection = $null; if (-not $s.ConnProblem) { $s.ConnProblem = [string]$sel.Problem } }
    # the columns, the table and the mapping (a missing column or a mapping by label HOLDS: nothing is sent and nothing is
    # marked as sent, so every row goes on the next run once the table is right -- absence is never remediation)
    # #912 THE STAGING STATUS TABLE (Get-SISnowStagingStatusTable): set = this output's push is ONE batch -- a writing row before
    # the first data row, u_si_batch_id on every data row, an end row (complete | failed | held) after the last; checked with the
    # output's table (a missing table or column holds). Empty = sent as before, with a warning here and in the check.
    $s.StatusTable = Get-SISnowStagingStatusTable
    $s.BatchId = Get-SISnowBatchId -RunId $RunId -Output ([string]$Entry.output)
    $s.BatchState = ''; $s.BatchStarted = [datetime]::UtcNow; $s.ImportSets = (New-Object System.Collections.Generic.List[string]); $s.Planned = 0L; $s.NotAccepted = 0L
    $s.StatusWarning = ''; $s.StatusProblem = ''
    # #914: every data row carries u_si_batch_id from the output map (the contract's envelope), with or without the table
    if (-not $s.StatusTable) { $s.StatusWarning = Get-SISnowNoStatusTableWarning -Output ([string]$Entry.output) }
    $ckp = @{ Output = ([string]$Entry.output); Table = $s.Table; Connection = $s.Connection; ConnectionProblem = $s.ConnProblem; Source = $s.Source; Header = @($s.Header); Rows = @()
              CheckStatusTable = $true; StatusTable = $s.StatusTable }
    if ($cn.PSObject.Properties['Warning'] -and $cn.Warning) { $ckp['CredentialWarning'] = [string]$cn.Warning }
    $chk = Invoke-SISnowOutputCheck @ckp
    $s.Check = $chk
    # recorded (cfg.ServiceNowCheck -> Data health, the heartbeat, the daily mail) when there is a connector to check, or two
    # are switched on (a real failure: nothing is sent). No data-out connector switched on is the install's choice: the run
    # holds and says so, and no failed check is recorded (owner: no unnecessary alerts)
    if ($Store -and ($snowEntry -or @($sel.On).Count -gt 1)) { $null = Write-SISnowCheck -Store $Store -Result $chk -Trigger run -Connector $s.Connector }
    if ($chk.Hold) { $s.Held = $true; $s.Reason = ('held, nothing was sent -- {0} The rows go on the next run once this is fixed.' -f $chk.Summary) }
    # the writing row: before any data row. It cannot be written -> nothing is sent (data trust: never rows without the marker).
    # Held by the check: writing, then held at the close -- when the status table itself is fine (else nothing can be written).
    $statusOk = $s.StatusTable -and $s.Connection -and -not ($chk.PSObject.Properties['StatusTable'] -and $chk.StatusTable -and ($chk.StatusTable.Exists -eq $false -or @($chk.StatusTable.Missing).Count))
    $s.StatusOk = [bool]($statusOk -and -not ($chk.Hold -and $chk.Connection -and -not $chk.Connection.Ok))
    if ($Prelude -and $s.Connection -and -not $s.Failed) { try { & $Prelude $s } catch { $s.StatusProblem = ('before the batch: {0}' -f $_.Exception.Message) } }
    if ($s.StatusOk -and -not $NoBatch) { $null = Open-SIDataOutSnowBatch -Session $s }
    $s
}

function Open-SIDataOutSnowBatch {
    <# #912: the session's writing row (u_planned_rows is not known yet: data out compares page by page; the end row has it).
       Not written -> the session FAILS (nothing is sent), the reason names the staging status table. #>
    param([Parameter(Mandatory)][hashtable]$Session)
    $s = $Session
    $row = New-SISnowStagingStatusRow -BatchId $s.BatchId -Output ([string]$s.Entry.output) -State writing -Connector $s.Connector -TargetTable $s.Table -SourceRun $s.RunId -Started $s.BatchStarted -SiVersion (Get-SISnowSiVersion) `
            -ContractVersion (Get-SIDataOutContractVersion) -Mode ([string]$s.Mode)
    $w = Write-SISnowStagingStatusRow -Connection $s.Connection -Table $s.StatusTable -Row $row
    if ($w.Ok) { $s.BatchState = 'writing'; Write-SIDataOutBatchRecord -Session $s -State writing; return $true }
    $s.StatusProblem = $w.Error
    if ($s.Held) { return $false }   # held already: nothing is sent either way, the hold stays the reason
    $s.Failed = ('the staging status table could not be written -- {0}. Nothing was sent: no row reaches ServiceNow without its batch marker.' -f $w.Error)
    $false
}

function Close-SIDataOutSnowBatch {
    <#
        #912: the session's end row -- complete (every row of the run's pages accepted), failed (rows not accepted, or a page
        refused) or held (the check held the push, before or while sending). Sets Session.BatchState to what ServiceNow now
        reads ('writing' when the end row could not be written: never imported). No writing row -> nothing.
    #>
    param([Parameter(Mandatory)][hashtable]$Session)
    $s = $Session
    if ($s.BatchState -ne 'writing') { return }
    $nErr = $s.Errors.Count
    $state = if ($s.Held) { 'held' } elseif ($s.Failed -or $nErr -gt 0 -or $s.NotAccepted -gt 0) { 'failed' } else { 'complete' }
    $notSent = [long]([Math]::Max(0, $s.Delta - $s.Sent))
    $reason = switch ($state) {
        'complete' { ('{0} row(s) accepted by {1}' -f $s.Sent, $s.Table) }
        'held'     { [string]$s.Reason }
        default    { ('{0} of {1} row(s) accepted by {2}; {3} not accepted -- {4}' -f $s.Sent, $s.Delta, $s.Table, $notSent, $(if ($s.Failed) { $s.Failed } else { (@($s.Errors) | Select-Object -First 3) -join ' | ' })) }
    }
    $row = New-SISnowStagingStatusRow -BatchId $s.BatchId -Output ([string]$s.Entry.output) -State $state -Connector $s.Connector -TargetTable $s.Table -SourceRun $s.RunId -Started $s.BatchStarted `
            -Finished ([datetime]::UtcNow) -Planned ([long]$s.Delta) -Sent ([long]$s.Sent) -Failed $notSent -ImportSets @($s.ImportSets) -Reason $reason -SiVersion (Get-SISnowSiVersion) `
            -ContractVersion (Get-SIDataOutContractVersion) -Mode ([string]$s.Mode) -Counts $s.Counts
    $w = Write-SISnowStagingStatusRow -Connection $s.Connection -Table $s.StatusTable -Row $row
    $s.EndReason = $reason
    if ($w.Ok) { $s.BatchState = $state; Write-SIDataOutBatchRecord -Session $s -State $state -Reason $reason -Failed $notSent }
    else {
        $s.StatusProblem = ('the end row ({0}) could not be written: {1} -- ServiceNow sees the batch as writing and never imports it' -f $state, $w.Error)
        $s.Errors.Add($s.StatusProblem)
    }
}

function Send-SIDataOutSnowPage {
    <#
        ONE PAGE of new and changed rows to the Import Set table (the session's): checked against the table's columns first
        (a value that would be cut HOLDS the push from here on -- that check is recorded -- and nothing more is sent); then
        sent. Returns @{ Ok; Held; Reason; Errors } for the page.
    #>
    param([Parameter(Mandatory)][hashtable]$Session, [AllowEmptyCollection()][object[]]$Rows = @())
    $s = $Session
    # an empty value is left out (the Import Set API cannot tell empty from not sent): the clear marker u_si_cleared says
    # which columns SecurityInsight knows are empty (#914 a)
    $rows = @(foreach ($r in $Rows) {
            $h = [ordered]@{}
            if ($r -is [System.Collections.IDictionary]) { foreach ($k in @($r.Keys)) { if (-not (Test-SIValueEmpty $r[$k])) { $h[[string]$k] = $r[$k] } } }
            else { foreach ($p in $r.PSObject.Properties) { if (-not (Test-SIValueEmpty $p.Value)) { $h[$p.Name] = $p.Value } } }
            $h })
    $s.Delta += $rows.Count
    if ($rows.Count -eq 0) { return [pscustomobject]@{ Ok = $true; Held = $false; Reason = ''; Errors = @() } }
    if ($s.Held) { return [pscustomobject]@{ Ok = $false; Held = $true; Reason = $s.Reason; Errors = @() } }
    $cols = $null; if ($s.Check -and $s.Check.Columns) { $cols = $s.Check.Columns }
    if ($cols -and $cols.Read) {
        $mapState = 'unknown'; if ($s.Check.Mapping) { $mapState = [string]$s.Check.Mapping.State }
        $cmp = Compare-SISnowSendColumns -Header $s.Header -Rows $rows -Columns @($cols.Columns) -Mapping $mapState -Table $s.Table
        if ($cmp.Hold) {
            # recorded as the run's check (the values that would be cut), as the check before the run would have said it
            $chk = Invoke-SISnowOutputCheck -Output ([string]$s.Entry.output) -Table $s.Table -Connection $s.Connection -ConnectionProblem $s.ConnProblem -Source $s.Source -Header $s.Header -Rows $rows
            if ($s.Store) { $null = Write-SISnowCheck -Store $s.Store -Result $chk -Trigger run -Connector $s.Connector }
            $s.Held = $true
            $what = $(if ($s.Sent -gt 0) { 'nothing more was sent ({0} row(s) were sent before)' -f $s.Sent } else { 'nothing was sent' })
            $s.Reason = ('held, {0} -- {1} The rows go on the next run once this is fixed.' -f $what, $(if ($chk.Hold) { $chk.Summary } else { ('{0}: {1}' -f $s.Table, ((@($cmp.Problems) | Select-Object -First 3 | ForEach-Object { $_.Text }) -join '; ')) }))
            return [pscustomobject]@{ Ok = $false; Held = $true; Reason = $s.Reason; Errors = @() }
        }
    }
    $push = Invoke-SISnowImportSetPush -Connection $s.Connection -Table $s.Table -Rows $rows
    if ($push.Refused) { $s.Failed = [string]$push.Reason; return [pscustomobject]@{ Ok = $false; Held = $false; Reason = [string]$push.Reason; Errors = @() } }
    $s.Sent += [long]$push.Sent
    if ($s.ContainsKey('ImportSets')) { foreach ($x in @($push.ImportSets)) { if ($x) { $s.ImportSets.Add([string]$x) } } }
    if ($s.ContainsKey('NotAccepted')) { $s.NotAccepted += [long]([Math]::Max(0, $rows.Count - [int]$push.Sent)) }
    foreach ($e in @($push.Errors)) { if ($e) { $s.Errors.Add([string]$e) } }
    if ([string]$push.Reason) { $s.PushReason = [string]$push.Reason }
    [pscustomobject]@{ Ok = $true; Held = $false; Reason = [string]$push.Reason; Errors = @($push.Errors | Where-Object { $_ }) }
}

function Close-SIDataOutSnowSession {
    <# The destination's answer for the whole run (Invoke-SIDataOutDestination's shape): @{ Ok; Held; Reason; Errors; Target }. #>
    param([Parameter(Mandatory)][hashtable]$Session)
    $s = $Session
    # #912 the end row first: what ServiceNow reads for this batch (complete | failed | held)
    Close-SIDataOutSnowBatch -Session $s
    if ($s.Failed -and -not $s.Unavailable) { return [pscustomobject]@{ Ok = $false; Reason = $s.Failed; Errors = $s.Errors.ToArray(); Target = $s.Table } }
    if ($s.Unavailable) {
        if ($s.Delta -eq 0) { return [pscustomobject]@{ Ok = $true; Reason = 'nothing new or changed to send'; Errors = @(); Target = $s.Table } }
        return [pscustomobject]@{ Ok = $false; Reason = 'the ServiceNow hand-off is part of SecurityInsight Pro'; Errors = @(); Target = $s.Table }
    }
    if ($s.Delta -eq 0) {
        $why = 'nothing new or changed to send'; if ($s.Check -and $s.Check.Outcome -ne 'ok') { $why += ('; the ServiceNow check says: {0}' -f $s.Check.Summary) }
        return [pscustomobject]@{ Ok = $true; Reason = $why; Errors = @(); Target = $s.Table }
    }
    if ($s.Held) { return [pscustomobject]@{ Ok = $false; Held = $true; Reason = $s.Reason; Errors = $s.Errors.ToArray(); Target = $s.Table } }
    [pscustomobject]@{ Ok = $true; Reason = $s.PushReason; Errors = $s.Errors.ToArray(); Target = $s.Table }
}

# =====================================================================================================================
#  #914 THE CONTRACT WRITER: every run sends the FULL current scoped state of a ServiceNow output, every row with its
#  u_action, as ONE batch (docs/DESIGN.md "One trusted contract for every data-out target")
# =====================================================================================================================

function Write-SIDataOutBatchRecord {
    <# The SecurityInsight-side record of the session's batch (cfg.DataOutBatch). Never throws: a failure is said on the session. #>
    param([Parameter(Mandatory)][hashtable]$Session, [Parameter(Mandatory)][ValidateSet('writing', 'complete', 'failed', 'held')][string]$State, [string]$Reason = '', [long]$Failed = 0)
    $s = $Session
    if (-not $s.Store -or -not $s.Store.Invoke) { return }
    try {
        $p = New-SIDataOutBatchParams -BatchId ([string]$s.BatchId) -OutputId ([string]$s.Entry.output) -RunId ([string]$s.RunId) -State $State -Mode ([string]$s.Mode) -Connector ([string]$s.Connector) `
            -TargetTable ([string]$s.Table) -RequestToken ([string]$s.RequestToken) -Counts $s.Counts -Planned ([long]$s.Delta) -Sent ([long]$s.Sent) -Failed $Failed -ImportSets @($s.ImportSets) -Reason $Reason
        [void](& $s.Store.Invoke (Get-SIDataOutBatchWriteSql) $p 'nonquery')
    } catch { $s.StatusProblem = ('the batch record (cfg.DataOutBatch) could not be written: {0}' -f $_.Exception.Message) }
}

function Get-SIDataOutContractStateSql {
    <# #914: what an output last sent for ONE PAGE of keys (@keys, a JSON array): the hash AND the row with its meta, always. #>
    @'
IF OBJECT_ID('cfg.DataOutItem') IS NOT NULL
SELECT d.ItemKey, d.RowHash, d.RowJson
FROM OPENJSON(@keys) WITH (k nvarchar(380) '$') AS p
JOIN cfg.DataOutItem AS d ON d.OutputId = @OutputId AND d.ItemKey = p.k;
'@
}

function Read-SIDataOutContractState {
    <# The state rows of -Keys for -OutputId (key -> @{ Hash; Json }); in chunks of 2,000. No store = none. #>
    param($Store, [Parameter(Mandatory)][string]$OutputId, [AllowEmptyCollection()][string[]]$Keys = @())
    $out = @{}
    if (-not $Store -or -not $Store.Invoke) { return $out }
    $ks = @($Keys | Where-Object { $_ } | Select-Object -Unique)
    for ($i = 0; $i -lt $ks.Count; $i += 2000) {
        $part = @($ks[$i..([Math]::Min($i + 2000, $ks.Count) - 1)])
        $a = & $Store.Invoke (Get-SIDataOutContractStateSql) @{ OutputId = $OutputId; keys = (ConvertTo-Json -InputObject @($part) -Compress) } 'reader'
        foreach ($r in @($a)) {
            if (-not ($r -is [System.Collections.IDictionary])) { continue }
            $out[[string]$r['ItemKey']] = [pscustomobject]@{ Hash = [string]$r['RowHash']; Json = $(if ($null -eq $r['RowJson'] -or $r['RowJson'] -is [System.DBNull]) { '' } else { [string]$r['RowJson'] }) }
        }
    }
    $out
}

function Stop-SIDataOutStaleBatches {
    <#
        #914 (c) A BATCH THAT NEVER ENDS: at the start of a sync, every batch of the same output that is still 'writing'
        (cfg.DataOutBatch) is ended 'failed' with the reason -- a failed row in the staging status table, the record ended,
        and the rows its run recorded as sent marked to go again. Never two open batches per output. Returns how many.
    #>
    param([Parameter(Mandatory)][hashtable]$Session, [scriptblock]$Log)
    $s = $Session
    if (-not $s.Store -or -not $s.Store.Invoke) { return 0 }
    $open = @(@(& $s.Store.Invoke (Get-SIDataOutOpenBatchSql) @{ OutputId = [string]$s.Entry.output; BatchId = [string]$s.BatchId } 'reader') | Where-Object { $_ -is [System.Collections.IDictionary] })
    $n = 0
    foreach ($b in $open) {
        $why = ('a later sync ({0}) started while this batch was still writing -- it never ended, so it is ended as failed and its rows go again' -f $s.RunId)
        if ($s.StatusTable -and $s.Connection) {
            $mode = [string]$b['Mode']; if ($mode -notin (Get-SIDataOutContractModes)) { $mode = 'live' }
            $row = New-SISnowStagingStatusRow -BatchId ([string]$b['BatchId']) -Output ([string]$s.Entry.output) -State failed -Connector $s.Connector -TargetTable ([string]$b['TargetTable']) `
                -SourceRun ([string]$b['RunId']) -Started $b['StartedAt'] -Finished ([datetime]::UtcNow) -Reason $why -SiVersion (Get-SISnowSiVersion) -ContractVersion (Get-SIDataOutContractVersion) -Mode $mode
            $w = Write-SISnowStagingStatusRow -Connection $s.Connection -Table $s.StatusTable -Row $row
            if (-not $w.Ok -and $Log) { & $Log 'WARN' ('{0}: the failed row of the stale batch {1} could not be written -- {2}' -f $s.Entry.label, $b['BatchId'], $w.Error) }
        }
        [void](& $s.Store.Invoke (Get-SIDataOutEndStaleBatchSql) @{ BatchId = [string]$b['BatchId']; Reason = $why } 'nonquery')
        $null = Reset-SIDataOutRunState -Store $s.Store -OutputId ([string]$s.Entry.output) -RunId ([string]$b['RunId'])
        if ($Log) { & $Log 'WARN' ('{0}: the batch {1} never ended -- ended as failed; its rows go again in this batch' -f $s.Entry.label, $b['BatchId']) }
        $n++
    }
    $n
}

function Read-SIDataOutBatchFeedback {
    <#
        #914 (b) THE IMPORT RESULT, READ BACK: the newest complete batch of the output whose result is not read yet (or was
        pending) -- ServiceNow's own counts per import state for the batch's import sets (Read-SISnowImportFeedback), recorded
        in cfg.DataOutBatch and as a 'feedback' row in the staging status table. Returns @{ BatchId; Counts; Errors; Note }
        or $null. Errors > 0 become the output's issue (Get-SIDataOutIssues -> the run's failure path).
    #>
    param([Parameter(Mandatory)][hashtable]$Session, [scriptblock]$Log)
    $s = $Session
    if (-not $s.Store -or -not $s.Store.Invoke -or -not $s.Connection) { return $null }
    $due = @(@(& $s.Store.Invoke (Get-SIDataOutFeedbackDueSql) @{ OutputId = [string]$s.Entry.output; BatchId = [string]$s.BatchId } 'reader') | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -First 1
    if (-not $due) { return $null }
    $bid = [string]$due['BatchId']
    $ids = [string[]]@(([string]$due['ImportSetIds']) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\(\+' })
    $fb = Read-SISnowImportFeedback -Connection $s.Connection -ImportSets $ids
    if (-not $fb.Ok) {
        if ($Log) { & $Log 'WARN' ('{0}: the import result of batch {1} could not be read back -- {2}' -f $s.Entry.label, $bid, $fb.Note) }
        return [pscustomobject]@{ BatchId = $bid; Counts = $null; Errors = 0; Note = [string]$fb.Note }
    }
    $c = $fb.Counts
    [void](& $s.Store.Invoke (Get-SIDataOutFeedbackWriteSql) @{ BatchId = $bid; Inserted = $c.Inserted; Updated = $c.Updated; Ignored = $c.Ignored; Skipped = $c.Skipped; Errors = $c.Errors; Pending = $c.Pending; Note = '' } 'nonquery')
    if ($s.StatusTable) {
        $row = New-SISnowStagingStatusRow -BatchId $bid -Output ([string]$s.Entry.output) -State feedback -Connector $s.Connector -TargetTable $s.Table -SourceRun $s.RunId -Started ([datetime]::UtcNow) `
            -SiVersion (Get-SISnowSiVersion) -ContractVersion (Get-SIDataOutContractVersion) -Feedback $c `
            -Reason ('your import of batch {0}: {1} inserted, {2} updated, {3} ignored, {4} skipped, {5} error(s), {6} pending' -f $bid, $c.Inserted, $c.Updated, $c.Ignored, $c.Skipped, $c.Errors, $c.Pending)
        $w = Write-SISnowStagingStatusRow -Connection $s.Connection -Table $s.StatusTable -Row $row
        if (-not $w.Ok -and $Log) { & $Log 'WARN' ('{0}: the feedback row of batch {1} could not be written -- {2}' -f $s.Entry.label, $bid, $w.Error) }
    }
    if ($Log) { & $Log $(if ($c.Errors -gt 0) { 'WARN' } else { 'INFO' }) ('{0}: your import of batch {1} -- {2} inserted, {3} updated, {4} ignored, {5} skipped, {6} error(s), {7} pending' -f $s.Entry.label, $bid, $c.Inserted, $c.Updated, $c.Ignored, $c.Skipped, $c.Errors, $c.Pending) }
    [pscustomobject]@{ BatchId = $bid; Counts = $c; Errors = [long]$c.Errors; Note = '' }
}

function ConvertTo-SIDataOutOrderedRow {
    <# PURE. A mapped row (object or dictionary) -> an ordered dictionary, column order kept. #>
    param($Row)
    $h = [ordered]@{}
    if ($Row -is [System.Collections.IDictionary]) { foreach ($k in @($Row.Keys)) { $h[[string]$k] = $Row[$k] } }
    elseif ($null -ne $Row) { foreach ($p in $Row.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $h
}

function ConvertTo-SIDataOutContractRow {
    <#
        PURE. ONE ITEM AS THE CONTRACT SENDS IT, for a reader that shows the push without sending (the ServiceNow test pack):
        the output map (Invoke-SIOutputMap), one date format, and the envelope for -Action. The writer's own pages go through
        Invoke-SIDataOutContractPage; this is the same mapping and envelope for one item.
    #>
    param([Parameter(Mandatory)][string]$Output, [Parameter(Mandatory)]$Map, [Parameter(Mandatory)]$Item, $ValueMaps, [hashtable]$Context = @{},
          [Parameter(Mandatory)][string]$Action, [string]$BatchId = '', [string]$Reason = '')
    $row = ConvertTo-SIDataOutOrderedRow @(Invoke-SIOutputMap -Map $Map -Items @($Item) -ValueMaps $ValueMaps -Context $Context)[0]
    foreach ($dk in @($row.Keys)) { $row[$dk] = ConvertTo-SIDataOutWireValue $row[$dk] }
    $null = Set-SIDataOutEnvelope -Row $row -Output $Output -Action $Action -BatchId $BatchId -Reason $Reason
    $row
}
function Get-SIDataOutContractCiDelivered {
    <#
        #914 (g) Which of -CiKeys the CI output (servicenow-ci) delivered in a complete batch -- this one or an earlier one:
        a state row that is delivered, or that keeps a delivered base. Returns a set (case as stored).
    #>
    param($Store, [AllowEmptyCollection()][string[]]$CiKeys = @())
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $st = Read-SIDataOutContractState -Store $Store -OutputId 'servicenow-ci' -Keys $CiKeys
    foreach ($k in $st.Keys) { $m = Get-SIDataOutStateMeta -Prev $st[$k] -Grain 'ci'; if ($m.Delivered -or $m.Base -ne 'none') { [void]$set.Add([string]$k) } }
    , $set
}

function Invoke-SIDataOutContractPage {
    <#
        #914 ONE PAGE of a contract output: every item of the page (the map's filter first) gets its row and its u_action
        (Get-SIDataOutContractAction against what the target last received in a complete batch), the scope applied (an item
        out of scope gets one out_of_scope row), a vulnerable item whose CI is not delivered held, the re-key named.
        Returns @{ Rows (ordered dictionaries, in page order); State ([{ k; h; r }]); Changes; Counts; Unchanged } or $null.
        -NoState: a test batch -- nothing recorded.
    #>
    param([Parameter(Mandatory)][hashtable]$W, [AllowEmptyCollection()][object[]]$Items = @(), [AllowEmptyCollection()][string[]]$Frozen = @(), [switch]$NoState)
    if (-not $NoState -and @($Frozen | Where-Object { $_ }).Count) { $null = Add-SIDataOutKeys -Set $W.FrozenSet -Keys ([string[]]@($Frozen)) }
    $out = [string]$W.OutputId
    $grain = [string]$W.Grain
    $kept = @(@($Items) | Where-Object { $null -ne $_ -and (Test-SIOutputFilter -Item $_ -Filter $W.Map.filter) })
    if ($kept.Count -eq 0) { return $null }
    if ($grain -eq 'ci_finding') { foreach ($it in $kept) { if (-not [string](Get-SIItemValue $it 'item_key')) { Set-SIDataOutValue $it 'item_key' (Get-SIDataOutItemKeyFull -Grain 'ci_finding' -Item $it) } } }
    $keys = @(foreach ($it in $kept) { Get-SIDataOutItemKey -Grain $grain -Item $it })
    # an item already seen on an earlier page keeps that page's row
    $take = @(0..($kept.Count - 1))
    if (-not $NoState) {
        $added = Add-SIDataOutKeys -Set $W.Seen -Keys ([string[]]$keys)
        $take = @($take | Where-Object { $added.Contains([string]$keys[$_]) })
    }
    if ($take.Count -eq 0) { return $null }
    $items2 = @(foreach ($i in $take) { $kept[$i] }); $keys2 = [string[]]@(foreach ($i in $take) { $keys[$i] })
    $mapped = @(Invoke-SIOutputMap -Map $W.Map -Items $items2 -ValueMaps $W.ValueMaps -Context $W.Ctx)
    if ($mapped.Count -ne $items2.Count) { throw 'the mapped rows do not line up with the items' }
    $prev = Read-SIDataOutContractState -Store $W.Store -OutputId $out -Keys $keys2
    # (f) re-keying: the previous key of each CI on the page (sidata.AssetIdHistory, the data database)
    $ciOf = @(foreach ($it in $items2) { [string](Get-SIItemValue $it 'si_ci_id') })
    $repl = @{}
    if ($W.DataInvoke) {
        try {
            $ck = @($ciOf | Where-Object { $_ } | Select-Object -Unique)
            if ($ck.Count) { $repl = ConvertTo-SIDataOutReplacesMap -Rows @(@(& $W.DataInvoke (Get-SIDataOutReplacesSql) @{ keys = (ConvertTo-Json -InputObject @($ck) -Compress) } 'reader') | Where-Object { $_ -is [System.Collections.IDictionary] }) }
        } catch { if (-not $W.ReplacesWarned) { $W.ReplacesWarned = $true; & $W.Log 'WARN' ('{0}: the re-keyed CIs could not be read ({1}) -- no u_si_replaces this run' -f $W.Label, $_.Exception.Message) } }
    }
    $oldKeys = @{}
    for ($i = 0; $i -lt $items2.Count; $i++) {
        $c = $ciOf[$i]; if (-not $c -or -not $repl.ContainsKey($c)) { continue }
        $ok = $(if ($grain -eq 'ci') { [string]$repl[$c] } else { Get-SIDataOutItemKey -Grain 'ci_finding' -Item ([pscustomobject]@{ si_ci_id = [string]$repl[$c]; si_finding_key = [string](Get-SIItemValue $items2[$i] 'si_finding_key') }) })
        $oldKeys[$keys2[$i]] = $ok
    }
    $oldState = @{}; if ($oldKeys.Count) { $oldState = Read-SIDataOutContractState -Store $W.Store -OutputId $out -Keys ([string[]]@($oldKeys.Values)) }
    # (g) the CIs of the vulnerable items, delivered in a complete batch (only when the CI output is switched on)
    $ciOk = $null
    if ($grain -eq 'ci_finding' -and $W.CiCheck) { $ciOk = Get-SIDataOutContractCiDelivered -Store $W.Store -CiKeys ([string[]]@($ciOf | Where-Object { $_ } | Select-Object -Unique)) }
    $rows = New-Object System.Collections.Generic.List[object]
    $state = New-Object System.Collections.Generic.List[object]
    $chs = New-Object System.Collections.Generic.List[object]
    $counts = New-SIDataOutActionCounts
    $unchanged = 0
    $at = [datetime]::UtcNow
    for ($i = 0; $i -lt $items2.Count; $i++) {
        $it = $items2[$i]; $k = $keys2[$i]
        $meta = Get-SIDataOutStateMeta -Prev $prev[$k] -Grain $grain
        $reason = ''
        $now = ''
        if (-not (Test-SIDataOutInScope -Grain $grain -Item $it -Scope $W.Scope)) { $now = 'out_of_scope' }
        elseif ($grain -eq 'ci_finding' -and -not $ciOf[$i]) { $now = 'held'; $reason = 'the finding has no CI key -- it is held, never sent without its CI' }
        elseif ($null -ne $ciOk -and -not $ciOk.Contains($ciOf[$i])) { $now = 'held'; $reason = ('its CI ({0}) is not delivered in a complete batch yet -- the item is held, never sent without its CI' -f $ciOf[$i]) }
        else { $now = Get-SIDataOutRecordClass -Grain $grain -Item $it }
        $dec = Get-SIDataOutContractAction -Now $now -Base $meta.Base -Resync:([bool]$W.Resync)
        if (-not $dec.Send) {
            if ($now -eq 'held') { Add-SIDataOutActionCount -Counts $counts -Action held }
            continue
        }
        $row = $(if ($now -eq 'held' -and $meta.Cells.Count) { ConvertTo-SIDataOutOrderedRow $meta.Cells } else { ConvertTo-SIDataOutOrderedRow $mapped[$i] })
        # one date format for every column (UTC yyyy-MM-dd HH:mm:ss)
        foreach ($dk in @($row.Keys)) { $row[$dk] = ConvertTo-SIDataOutWireValue $row[$dk] }
        if ($dec.Action -eq 'held' -and $now -eq 'counting') {
            $ar = [string](Get-SIItemValue $it 'absent_runs')
            $reason = ('absent {0} complete run(s) -- SecurityInsight closes a finding only after enough complete runs without it' -f $ar)
        }
        $rp = ''
        if ($oldKeys.ContainsKey($k)) {
            $om = Get-SIDataOutStateMeta -Prev $oldState[$oldKeys[$k]] -Grain $grain
            if ($om.Present -and $om.Class -ne 'gone') { $rp = [string]$oldKeys[$k]; [void]$W.Replaced.Add($rp) }
        }
        $null = Set-SIDataOutEnvelope -Row $row -Output $out -Action $dec.Action -BatchId ([string]$W.BatchId) -Reason $reason -Replaces $rp
        if (-not [string]$row['u_row_hash']) { $row['u_row_hash'] = Get-SIDataOutRowHashText -Row $row }
        $rows.Add($row)
        Add-SIDataOutActionCount -Counts $counts -Action $dec.Action
        $hash = [string]$row['u_row_hash']
        $prevHash = $(if ($meta.Cells.Contains('u_row_hash')) { [string]$meta.Cells['u_row_hash'] } else { '' })
        if ($dec.Action -eq 'update' -and $prevHash -eq $hash) { $unchanged++ }
        if (-not $NoState) {
            $cells = [ordered]@{}; foreach ($ck2 in $row.Keys) { $cells[$ck2] = Get-SIDataOutRowText $row[$ck2] }
            $state.Add([ordered]@{ k = $k; h = $(if ($hash) { $hash } else { Get-SIDataOutRowHashText -Row $row }); r = (ConvertTo-SIDataOutStateJson -Cells $cells -Class $dec.Class -Base $meta.Base -Action $dec.Action) })
            $name = $(if ($W.NameCol -and $row.Contains($W.NameCol)) { [string]$row[$W.NameCol] } else { '' })
            $act = switch ($dec.Action) { 'new' { 'written' } 'reopen' { 'reopened' } 'close' { if ($meta.Class -eq 'closed' -and $meta.Delivered) { '' } else { 'closed' } } 'out_of_scope' { 'out of scope' } 'update' { if ($prevHash -and $prevHash -ne $hash) { 'updated' } else { '' } } default { '' } }
            if ($act) {
                $fields = $null
                if ($act -eq 'updated') { $fields = [ordered]@{}; foreach ($n in $cells.Keys) { $o2 = $(if ($meta.Cells.Contains($n)) { [string]$meta.Cells[$n] } else { '' }); if ($n -notin 'u_action', 'u_si_batch_id', 'u_row_hash', 'u_source_run', 'u_run_time', 'u_changed_at' -and $o2 -cne [string]$cells[$n]) { $fields[$n] = @($o2, [string]$cells[$n]) } } }
                $chs.Add([pscustomobject]@{ At = $at; Action = $act; ObjectName = $name; ObjectKey = $k; Finding = ''; TargetKey = $k; Fields = $fields; Reason = $(if ($reason) { $reason } else { $W.Label }); Error = '' })
            }
        }
    }
    @{ Rows = $rows.ToArray(); State = $state.ToArray(); Changes = $chs.ToArray(); Counts = $counts; Unchanged = $unchanged }
}

function Invoke-SIDataOutContractGonePage {
    <#
        #914 WHAT WAS SENT BEFORE AND IS NOT IN THIS RUN'S ITEMS, a page at a time (cfg.DataOutItem by key): a disabled
        account's record or one of a report the newest run could not complete is HELD with its last values (never "no
        longer sent"); a record that is no longer in SecurityInsight's data gets ONE held row and then none; an out-of-scope
        record stays as it is. Returns @{ Rows; State; Gone (keys whose state row goes); Changes; Counts } or $null at the end.
    #>
    param([Parameter(Mandatory)][hashtable]$W)
    if (-not $W.Store -or $W.PrevDone) { return $null }
    $take = [int]$W.PageSize
    $a = & $W.Store.Invoke (Get-SIDataOutStatePageSql) @{ OutputId = $W.OutputId; Take = $take; After = [string]$W.PrevAfter } 'reader'
    $rs = @(@($a) | Where-Object { $_ -is [System.Collections.IDictionary] }); $a = $null
    if ($rs.Count -eq 0) { $W.PrevDone = $true; return $null }
    $W.PrevAfter = [string]$rs[$rs.Count - 1]['ItemKey']
    if ($rs.Count -lt $take) { $W.PrevDone = $true }
    $keys = [string[]]@($rs | ForEach-Object { [string]$_['ItemKey'] })
    $seen = Find-SIDataOutKeys -Set $W.Seen -Keys $keys
    $frz = Find-SIDataOutKeys -Set $W.FrozenSet -Keys $keys
    $car = Find-SIDataOutKeys -Set $W.CarrySet -Keys $keys
    $rows = New-Object System.Collections.Generic.List[object]; $state = New-Object System.Collections.Generic.List[object]; $gone = New-Object System.Collections.Generic.List[string]
    $chs = New-Object System.Collections.Generic.List[object]; $counts = New-SIDataOutActionCounts
    foreach ($r in $rs) {
        $k = [string]$r['ItemKey']
        if ($seen.Contains($k)) { continue }
        $meta = Get-SIDataOutStateMeta -Prev ([pscustomobject]@{ Hash = [string]$r['RowHash']; Json = $(if ($r['RowJson'] -is [System.DBNull]) { '' } else { [string]$r['RowJson'] }) }) -Grain $W.Grain
        # re-keyed: the new key's row carries u_si_replaces -- the old key gets no row of its own and leaves the state
        if ($W.Replaced.Contains($k)) { $gone.Add($k); continue }
        $isCarry = $car.Contains($k)
        if (-not $isCarry) { foreach ($cp in $W.CarryPrefixes) { if ($k.StartsWith([string]$cp, [StringComparison]::Ordinal)) { $isCarry = $true; break } } }
        $now = 'gone'; $reason = 'not in SecurityInsight''s data any more -- the target keeps the record as it is; SecurityInsight sends no more rows for it'
        if ($frz.Contains($k)) { $now = 'held'; $reason = 'the account or device is disabled and left out by a setting -- the target keeps what it has' }
        elseif ($isCarry) { $now = 'held'; $reason = 'the report that found it could not complete in the newest run -- the target keeps what it has' }
        $dec = Get-SIDataOutContractAction -Now $now -Base $meta.Base
        if (-not $dec.Send) {
            # told already (a delivered gone row), or never delivered: the state row goes; an out-of-scope record keeps its row
            if (($meta.Class -eq 'gone' -and $meta.Delivered) -or ($meta.Base -eq 'none' -and $now -eq 'gone')) { $gone.Add($k) }
            continue
        }
        $row = ConvertTo-SIDataOutOrderedRow $meta.Cells
        $null = Set-SIDataOutEnvelope -Row $row -Output $W.OutputId -Action $dec.Action -BatchId ([string]$W.BatchId) -Reason $reason
        $rows.Add($row); Add-SIDataOutActionCount -Counts $counts -Action $dec.Action
        $cells = [ordered]@{}; foreach ($ck2 in $row.Keys) { $cells[$ck2] = Get-SIDataOutRowText $row[$ck2] }
        $h = [string]$row['u_row_hash']; if (-not $h) { $h = Get-SIDataOutRowHashText -Row $row }
        $state.Add([ordered]@{ k = $k; h = $h; r = (ConvertTo-SIDataOutStateJson -Cells $cells -Class $dec.Class -Base $meta.Base -Action $dec.Action) })
        if ($now -eq 'gone') { $chs.Add([pscustomobject]@{ At = [datetime]::UtcNow; Action = 'removed'; ObjectName = $(if ($W.NameCol -and $cells.Contains($W.NameCol)) { [string]$cells[$W.NameCol] } else { '' }); ObjectKey = $k; Finding = ''; TargetKey = $k; Fields = $null; Reason = $reason; Error = '' }) }
    }
    @{ Rows = $rows.ToArray(); State = $state.ToArray(); Gone = $gone.ToArray(); Changes = $chs.ToArray(); Counts = $counts }
}

function Add-SIDataOutContractCommit {
    <# What a page that LANDED leaves behind: its state rows (upserted), the state rows that go, its change log entries. #>
    param([Parameter(Mandatory)][hashtable]$W, $Page)
    if (-not $W.Store -or $W.WhatIf -or $null -eq $Page) { return }
    foreach ($s2 in @($Page.State)) { if ($s2) { $W.StateBuf.Add($s2) } }
    # the state rows that go are dropped only once the batch is COMPLETE (Invoke-SIDataOutSnowContract): a re-keyed record's
    # old key must stay until the row that names it in u_si_replaces is delivered
    if ($Page.ContainsKey('Gone')) { foreach ($g in @($Page.Gone)) { if ($g) { $W.ContractGone.Add([string]$g) } } }
    foreach ($c in @($Page.Changes)) { if ($c) { $W.ChangeBuf.Add($c) } }
    if ($W.StateBuf.Count -ge $script:SIDataOutStateChunk -or $W.GoneBuf.Count -ge $script:SIDataOutStateChunk) { Write-SIDataOutCommits -W $W -State }
    if ($W.ChangeBuf.Count -ge $script:SIDataOutChangeChunk) { Write-SIDataOutCommits -W $W -Changes }
}

function Add-SIDataOutContractCounts {
    <# The page's counts into the session and the writer's result. #>
    param([Parameter(Mandatory)][hashtable]$W, [Parameter(Mandatory)][hashtable]$Session, $Page)
    if ($null -eq $Page) { return }
    foreach ($a in @($Page.Counts.Keys)) { Add-SIDataOutActionCount -Counts $Session.Counts -Action $a -By ([long]$Page.Counts[$a]) }
    $c = $Page.Counts
    $W.Res.Rows += @($Page.Rows).Count
    $W.Res.Written += [int]$c['new']
    $W.Res.Updated += [int]$c['update'] + [int]$c['reopen'] - $(if ($Page.ContainsKey('Unchanged')) { [int]$Page.Unchanged } else { 0 })
    $W.Res.Unchanged += $(if ($Page.ContainsKey('Unchanged')) { [int]$Page.Unchanged } else { 0 })
    $W.Res.Removed += [int]$c['out_of_scope']
}

function Send-SIDataOutContractTestBatch {
    <#
        #914 (j) THE TEST BATCH: at most -Max rows of the first page, as their own batch '<run>:<output>:test' with
        u_si_mode = test (the importer never imports it) -- writing, the rows, the end row. Nothing is recorded as sent.
        Returns the test batch's state (complete | failed | held | '').
    #>
    param([Parameter(Mandatory)][hashtable]$W, [Parameter(Mandatory)][hashtable]$Session, [AllowEmptyCollection()][object[]]$Items = @(), [int]$Max = 5)
    $s = $Session
    $t = @{}; foreach ($k in $s.Keys) { $t[$k] = $s[$k] }
    $t.BatchId = ('{0}:test' -f $s.BatchId); $t.Mode = 'test'; $t.BatchState = ''; $t.Counts = (New-SIDataOutActionCounts); $t.Sent = 0L; $t.Delta = 0L
    $t.Errors = (New-Object System.Collections.Generic.List[string]); $t.ImportSets = (New-Object System.Collections.Generic.List[string]); $t.NotAccepted = 0L; $t.Failed = ''; $t.BatchStarted = [datetime]::UtcNow
    if (-not (Open-SIDataOutSnowBatch -Session $t)) { & $W.Log 'WARN' ('{0}: the test batch could not start -- {1}' -f $W.Label, $t.StatusProblem); return '' }
    $saveBid = $W.BatchId; $W.BatchId = $t.BatchId
    try { $pg = Invoke-SIDataOutContractPage -W $W -Items @($Items) -NoState } finally { $W.BatchId = $saveBid }
    $rows = @(); if ($pg) { $rows = @($pg.Rows | Select-Object -First $Max) }
    foreach ($r in $rows) { Add-SIDataOutActionCount -Counts $t.Counts -Action ([string]$r['u_action']) }
    $null = Send-SIDataOutSnowPage -Session $t -Rows $rows
    Close-SIDataOutSnowBatch -Session $t
    & $W.Log 'INFO' ('{0}: test batch {1} -- {2} row(s), {3} (u_si_mode = test: your importer never imports it)' -f $W.Label, $t.BatchId, $rows.Count, $t.BatchState)
    [string]$t.BatchState
}

function Invoke-SIDataOutSnowContract {
    <#
        #914 ONE CONTRACT OUTPUT, ONE RUN (Invoke-SIDataOutWriter's ServiceNow branch): the request (a resync or a test
        batch), the scope, the session (the check; then the stale batches ended and the last batch's import result read
        back; then the writing row), every page of items with its rows, what was sent before and is not in this run's items,
        the end row. Returns the destination's answer (@{ Ok; Held; Reason; Errors; Target }).
    #>
    param([Parameter(Mandatory)][hashtable]$W, [scriptblock]$SnowConnect)
    $e = $W.Entry; $out = [string]$e.output
    $spec = Get-SIDataOutContractSpec -Output $out
    # the contract's columns are always sent, whatever a customer's change to the map removed (they are checked against the
    # staging table like every other column: one that is missing there HOLDS the push)
    # Get-SIDataOutContractColumns answers ONE list (return , ...): assigned first, then enumerated
    $cc = Get-SIDataOutContractColumns -Output $out
    $W.Header = [string[]]@(@($W.Header) + @($cc | Where-Object { @($W.Header) -notcontains $_ }))
    # the request: SI_DataOut_ServiceNowRequest = '<resync|test>:<token>' -- carried out once (a complete batch records it)
    $req = ConvertFrom-SIDataOutRequest -Value ([string](Get-Variable -Name SI_DataOut_ServiceNowRequest -Scope Global -ValueOnly -ErrorAction SilentlyContinue))
    if ($req.Problem) { & $W.Log 'WARN' ('{0}: {1}' -f $W.Label, $req.Problem) }
    $reqDone = $false
    if ($req.Kind -and $W.Store) {
        try { $reqDone = [int](@(@(& $W.Store.Invoke (Get-SIDataOutRequestDoneSql) @{ OutputId = $out; Token = $req.Token } 'reader') | Where-Object { $_ -is [System.Collections.IDictionary] } | ForEach-Object { $_['Done'] }) | Select-Object -First 1) -eq 1 } catch { $reqDone = $false }
    } elseif ($req.Kind) { & $W.Log 'WARN' ('{0}: the request {1} needs the settings database -- not carried out' -f $W.Label, $req.Kind); $reqDone = $true }
    $W.Resync = ($req.Kind -eq 'resync' -and -not $reqDone)
    $wantTest = ($req.Kind -eq 'test' -and -not $reqDone)
    # the scope this output receives (#274) -- a scope that cannot be read FAILS the output: a scope set by an Admin never
    # silently becomes "everything"
    $W.Scope = Get-SIOutputScope -Destination ([string]$spec.Scope)
    & $W.Log 'INFO' ('{0}: scope {1} ({2})' -f $W.Label, (Get-SIOutputScopeText $W.Scope), $spec.Scope)
    # (g) the CI reference check: on when the CI output is switched on in this install
    $W.CiCheck = $false
    if ($spec.Grain -eq 'ci_finding' -and $W.Store) {
        # Get-SIDataOutCatalog answers ONE list (return , ...): assigned first, then enumerated
        $ciEntry = $null; try { $cat = Get-SIDataOutCatalog; $ciEntry = @($cat | Where-Object { [string]$_.output -eq 'servicenow-ci' }) | Select-Object -First 1 } catch { $ciEntry = $null }
        if ($ciEntry -and (Test-SIDataOutSwitchedOn -Entry $ciEntry -Edition 'pro')) { $W.CiCheck = $true }
        else { & $W.Log 'INFO' ('{0}: the CI output is switched off -- the vulnerable items are sent without the check that their CI was delivered first' -f $W.Label) }
    }
    # the prelude runs inside Open-SIDataOutSnowSession (dynamic scope): its variables carry names no caller uses
    $__siContractLog = $W.Log; $__siContractRes = $W.Res
    $prelude = {
        param($sess)
        $null = Stop-SIDataOutStaleBatches -Session $sess -Log $__siContractLog
        $fb = Read-SIDataOutBatchFeedback -Session $sess -Log $__siContractLog
        if ($fb -and $fb.Errors -gt 0) { $__siContractRes['ImportErrors'] = [long]$fb.Errors; $__siContractRes['ImportErrorBatch'] = [string]$fb.BatchId }
    }
    $mode = $(if ($W.Resync) { 'resync' } else { 'live' })
    $sn = Open-SIDataOutSnowSession -Entry $e -Header $W.Header -Store $W.Store -SnowConnect $SnowConnect -Here $PSScriptRoot -RunId $W.RunId -Mode $mode `
            -RequestToken $(if ($W.Resync) { $req.Token } else { '' }) -Prelude $prelude -NoBatch:$wantTest
    $W.Target = [string]$sn.Table; $W.Snow = $sn; $W.BatchId = [string]$sn.BatchId
    if ($W.Resync) { & $W.Log 'INFO' ('{0}: a full resync was asked for ({1}) -- every record in scope is sent as new' -f $W.Label, $req.Token) }
    $first = $null
    if ($wantTest -and -not $sn.StatusOk) { & $W.Log 'WARN' ('{0}: a test batch was asked for, but it needs the staging status table -- not sent' -f $W.Label) }
    if ($wantTest) {
        $first = Get-SIDataOutNextPage -Cursor $W.Cursor
        if ($sn.StatusOk -and -not $sn.Failed -and -not $sn.Held) {
            $tsave = $sn.RequestToken; $sn.RequestToken = $req.Token
            $null = Send-SIDataOutContractTestBatch -W $W -Session $sn -Items @(if ($first) { $first.Items })
            $sn.RequestToken = $tsave
        }
        if ($sn.StatusOk) { $null = Open-SIDataOutSnowBatch -Session $sn }
    }
    # #912: a run that stopped mid-push never wrote its end row -- what it recorded as sent goes again in THIS batch
    if ($sn.BatchState -eq 'writing' -and $W.Store) {
        $no = Reset-SIDataOutOrphanState -Store $W.Store -OutputId $out -RunId $W.RunId -Connector ([string]$e.connector)
        if ($no -gt 0) { & $W.Log 'WARN' ('{0}: {1} row(s) of an earlier run that stopped before its batch was complete go again in this batch' -f $e.label, $no) }
    }
    $send = {
        param($pg)
        if ($null -eq $pg) { return }
        if ($sn.Failed -or $sn.Unavailable) { $sn.Delta += @($pg.Rows).Count; return }
        Add-SIDataOutContractCounts -W $W -Session $sn -Page $pg
        $pr = Send-SIDataOutSnowPage -Session $sn -Rows @($pg.Rows)
        # a page that LANDED WHOLE is recorded; a held page, or one with rows not accepted, is not (the batch ends failed or
        # held and its rows go again)
        if ($pr.Ok -and @($pr.Errors).Count -eq 0) {
            Add-SIDataOutContractCommit -W $W -Page $pg
            # what LANDED, for the run record of a batch a later page held
            $W.SentWritten += [int]$pg.Counts['new']; $W.SentUpdated += [int]$pg.Counts['update'] + [int]$pg.Counts['reopen']
        }
    }
    $pgIn = $first
    while ($null -ne $pgIn -or $null -ne ($pgIn = Get-SIDataOutNextPage -Cursor $W.Cursor)) {
        $r = Invoke-SIDataOutContractPage -W $W -Items @($pgIn.Items) -Frozen ([string[]]@($pgIn.Frozen)); $pgIn = $null
        & $send $r
        $r = $null
    }
    # what was sent before and is not in this run's items
    $W.PrevAfter = ''; $W.PrevDone = $false
    while ($null -ne ($g = Invoke-SIDataOutContractGonePage -W $W)) { & $send $g; $g = $null }
    $dw = Close-SIDataOutSnowSession -Session $sn
    # the state rows that go (told already / re-keyed): only after a COMPLETE batch (or, without a staging status table,
    # a run in which every row landed)
    $whole = ($sn.BatchState -eq 'complete') -or (-not $sn.StatusTable -and -not $sn.Failed -and -not $sn.Held -and $sn.Errors.Count -eq 0 -and $sn.NotAccepted -eq 0)
    if ($whole -and $W.Store -and -not $W.WhatIf) { foreach ($g2 in $W.ContractGone) { $W.GoneBuf.Add($g2) } }
    # #928: the CI push is THE route into the ServiceNow CMDB -- its result feeds the ServiceNow CMDB guard (instance not
    # reachable = halted, rows not accepted = held); a complete batch clears them
    if ($out -eq 'servicenow-ci' -and -not $W.WhatIf) { $null = Invoke-SIDataOutSnowGuards -Session $sn -Complete ([bool]$whole) -Log $W.Log }
    $dw
}

function Invoke-SIDataOutSnowGuards {
    <#
        #928: the ServiceNow CMDB guard on the one ServiceNow route. The CI output's push result
        (ConvertTo-SIGuardServiceNowPushResult) -> Get-SIGuardCallsForServiceNowCmdb -Result -> Invoke-SIGuardCalls. When
        the push reached ServiceNow, both checks count as checked: a complete batch (-Complete) clears an open episode.
        -Common: the guard calls' shared arguments (tests); default the data-out engine and the Pro settings database.
        Nothing when the guards are not loaded (a Community run). Never throws. Returns the trips' results.
    #>
    param([Parameter(Mandatory)][hashtable]$Session, [bool]$Complete = $false, [scriptblock]$Log, [hashtable]$Common)
    if (-not (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) -or -not (Get-Command -Name ConvertTo-SIGuardServiceNowPushResult -ErrorAction SilentlyContinue)) { return @() }
    try {
        $res = ConvertTo-SIGuardServiceNowPushResult -Session $Session
        $calls = @(Get-SIGuardCallsForServiceNowCmdb -Result $res)
        if (-not $Common) { $Common = @{ Engine = 'data-out'; Invoke = (Get-SIGuardProInvoke) } }
        if ($res.Reached) {
            $checked = @(@{ GuardId = 'cmdb.servicenow.unreachable'; Detail = 'ServiceNow was reached and the batch was sent.' },
                         @{ GuardId = 'cmdb.servicenow.create-gate'; Detail = 'ServiceNow accepted every row of the batch.' })
            return @(Invoke-SIGuardCalls -Calls $calls -Common $Common -Checked $checked -Complete $Complete)
        }
        @(Invoke-SIGuardCalls -Calls $calls -Common $Common)
    } catch {
        if ($Log) { & $Log 'WARN' ('the ServiceNow CMDB guard could not be told the push result ({0}) -- the push itself is not affected' -f $_.Exception.Message) }
        @()
    }
}

function Invoke-SIDataOutWriter {
    <#
    .SYNOPSIS  ONE listed data-out connector, one run: map the items, compare them with what was sent last time, write
               the destination, record the run and every item written / changed / no longer sent, keep the state.
               Never throws: a failure is the run's outcome, with the reason.
               #639 A PAGE AT A TIME, END TO END: each page is mapped, compared (by its keys, in SQL), written to the
               destination and recorded before the next page is read; nothing the size of the output is held.
    .PARAMETER Entry   the catalog entry (config/data-out.locked.json)
    .PARAMETER Map     the output map in force (the shipped map with the customer's changes)
    .PARAMETER Items   the items in hand (the CI build's) -- handed through in pages; or -Cursor
    .PARAMETER Cursor  the items a PAGE AT A TIME (New-SIDataOutItemCursor) -- pulled when the destination is ready
    .PARAMETER Stage   the data database, for the keys this run has seen (Test-SIDataOutStageReady); $null = in memory
    .PARAMETER Store   the settings database seam (.Invoke sql params mode) -- $null: nothing recorded, no state
    .PARAMETER Write   a test seam, scriptblock (Entry, Header, Rows (every row as its cells, in header order), Delta (the
                       written + changed rows, mapped)) -> @{ Ok; Reason; Errors; Target } -- it gets the whole output at the
                       end (tests only). Default: the entry's kind, page by page (excel / servicenow-importset).
    .OUTPUTS   @{ Output; Connector; Outcome; Rows; Written; Updated; Removed; Unchanged; Errors; Why; Target }
    #>
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)]$Map,
        [AllowEmptyCollection()][object[]]$Items = @(),
        [hashtable]$Cursor,
        $ValueMaps,
        $Store,
        [scriptblock]$Write,
        [string]$RunId = ([guid]::NewGuid().ToString()),
        [string]$OutputDir,
        [switch]$WhatIf,
        [scriptblock]$Log,
        # the keys of items left out as disabled (SI_DisabledAssets_Connectors, Select-SIDataOutEnabledItems): what was sent
        # for them stays as it was -- never "no longer sent"
        [AllowEmptyCollection()][string[]]$FrozenKeys = @(),
        # ONE INCOMPLETE REPORT DOES NOT HOLD A WHOLE RUN (owner 2026-10-14): the items of a report the newest run could not
        # complete that are not in this run -- by key (-CarryKeys, or -CarrySet: a key set staged by the step) or by key
        # prefix (-CarryPrefixes, '<report>|' for the summary) -- are never "no longer sent": what was sent for them stays,
        # and a file output keeps their last row.
        [AllowEmptyCollection()][string[]]$CarryKeys = @(),
        [hashtable]$CarrySet,
        [AllowEmptyCollection()][string[]]$CarryPrefixes = @(),
        [scriptblock]$Stage,
        [int]$PageSize = 5000,
        # tests: Excel's rows per sheet (the split), the ServiceNow connection
        [int]$SheetRows = 0,
        [scriptblock]$SnowConnect,
        # the step already chose this output (Invoke-SIDataOut). Not given -- the CI build hands its workbook straight here --
        # the output is written only when it is switched on (SI_DataOut_Outputs, else its default for the edition:
        # Test-SIDataOutSwitchedOn); off = nothing written, nothing recorded, outcome 'off'
        [switch]$Selected,
        [ValidateSet('', 'community', 'pro')][string]$Edition = '',
        # #914: the data database for the contract's look-ups (the re-keyed CIs) when the items do not come from it (tests,
        # the CI build); default: the cursor's own
        [scriptblock]$DataInvoke
    )
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $id = [string]$Entry.output
    if (-not $Selected -and [string](Get-SIItemValue $Entry 'step') -eq 'ci-build' -and -not (Test-SIDataOutSwitchedOn -Entry $Entry -Edition $Edition)) {
        & $Log 'INFO' ('{0}: switched off (SI_DataOut_Outputs) -- not written; every row is in the database and the web app' -f $Entry.label)
        # an output that ran before records that it is off now (never a silent output)
        if ($Store -and -not $WhatIf -and @(Get-SIDataOutConnectorsThatRan -Store $Store -Names ([string[]]@([string]$Entry.connector))).Count) {
            Write-SIDataOutStateRun -Store $Store -Entry $Entry -RunId $RunId -Outcome off -Why 'switched off (SI_DataOut_Outputs)' -Log $Log
        }
        return [pscustomobject]@{ Output = $id; Connector = [string]$Entry.connector; Outcome = 'off'; Rows = 0; Written = 0; Updated = 0; Removed = 0; Unchanged = 0; Errors = 0; Why = 'switched off'; Target = ''; Carried = 0 }
    }
    $started = [datetime]::UtcNow
    $res = [ordered]@{ Output = $id; Connector = [string]$Entry.connector; Outcome = 'success'; Rows = 0; Written = 0; Updated = 0; Removed = 0; Unchanged = 0; Errors = 0; Why = ''; Target = '' }
    $kind = 'file'; if ([string]$Entry.kind -eq 'servicenow-importset') { $kind = 'servicenow' }
    $W = $null
    $sent = @{ Written = 0; Updated = 0 }
    try {
        if ([string]$Entry.kind -eq 'fixed') { throw ("the output '{0}' is written by the {1} connector, not here" -f $id, $Entry.writtenBy) }
        $header = @($Map.columns | ForEach-Object { Get-SIOutputColumnName $_ })
        $nameCol = ''
        foreach ($c in @($Map.columns)) { if ([string]$c.from -in 'si_asset_name', 'si_title', 'si_record_key') { $nameCol = Get-SIOutputColumnName $c; break } }
        $cur = $Cursor
        if (-not $cur) { $cur = New-SIDataOutItemCursor -Grain ([string]$Map.grain) -Items @($Items) -FromItems -PageSize $PageSize }
        $W = @{ Entry = $Entry; Map = $Map; ValueMaps = $ValueMaps; Ctx = @{ RunId = $RunId; RunTime = $started; ChangedAt = $started }; Header = [string[]]$header
                Volatile = @($Map.columns | Where-Object { $script:SIDataOutVolatile -contains [string]$_.from } | ForEach-Object { Get-SIOutputColumnName $_ })
                NameCol = $nameCol; Grain = [string]$Map.grain; Store = $Store; OutputId = $id; RunId = $RunId; WhatIf = [bool]$WhatIf; Log = $Log; Label = [string]$Entry.label
                Res = $res; KeepDelta = ([string]$Entry.kind -ne 'excel'); Cursor = $cur; PageSize = $PageSize
                Seen = (New-SIDataOutKeySet -Stage $Stage); FrozenSet = (New-SIDataOutKeySet -Stage $Stage); CarrySet = $CarrySet; OwnCarry = $false
                CarryPrefixes = @($CarryPrefixes | Where-Object { $_ }); StateBuf = (New-Object System.Collections.Generic.List[object]); GoneBuf = (New-Object System.Collections.Generic.List[string])
                ChangeBuf = (New-Object System.Collections.Generic.List[object]); ChangeWarned = $false; Target = ''; Phase = 'items'; PrevAfter = ''; PrevDone = $false; FrozenGone = 0L; HasCarry = $false; SheetColumns = $null }
        if ($null -eq $W.CarrySet) {
            $W.CarrySet = New-SIDataOutKeySet -Stage $Stage; $W.OwnCarry = $true
            $null = Add-SIDataOutKeys -Set $W.CarrySet -Keys ([string[]]@($CarryKeys))
        }
        $W.HasCarry = ($W.CarrySet.Count -gt 0 -or $W.CarryPrefixes.Count -gt 0)
        if (@($FrozenKeys | Where-Object { $_ }).Count) { $null = Add-SIDataOutKeys -Set $W.FrozenSet -Keys ([string[]]@($FrozenKeys)) }

        $dw = $null
        if ($WhatIf) {
            while ($null -ne ($pg = Get-SIDataOutNextPage -Cursor $cur)) { $null = Invoke-SIDataOutWriterPage -W $W -Items @($pg.Items) -Frozen ([string[]]@($pg.Frozen)); $pg = $null }
            $dw = [pscustomobject]@{ Ok = $true; Reason = 'what-if: nothing written'; Errors = @(); Target = '' }; $res.Outcome = 'whatif'
        }
        elseif ($Write) {
            # a test seam: the whole output at the end (the cells, the delta), what landed recorded after it answered
            $cells = New-Object 'System.Collections.Generic.List[object[]]'
            $deltaRows = New-Object System.Collections.Generic.List[object]
            $pages = New-Object System.Collections.Generic.List[object]
            while ($null -ne ($pg = Get-SIDataOutNextPage -Cursor $cur)) {
                $r = Invoke-SIDataOutWriterPage -W $W -Items @($pg.Items) -Frozen ([string[]]@($pg.Frozen)); $pg = $null
                if ($null -eq $r) { continue }
                foreach ($m in $r.Mapped) { $cells.Add([object[]](ConvertTo-SIDataOutCells -Row $m -Header $header)) }
                foreach ($d in $r.DeltaRows) { $deltaRows.Add($d) }
                $r.Mapped = $null; $pages.Add($r)
            }
            if ($W.HasCarry) { while ($null -ne ($pp = Get-SIDataOutPreviousPage -W $W -Cells)) { foreach ($cr in $pp.Carried) { if ($null -ne $cr) { $cells.Add($cr) } } } }
            $dw = & $Write $Entry $header $cells $deltaRows.ToArray()
            $cells = $null
            if ($dw.Ok) {
                $nErr = @($dw.Errors | Where-Object { $_ }).Count
                foreach ($r in $pages) { Add-SIDataOutCommit -W $W -Page $r -State ($nErr -eq 0) }
            }
            $pages = $null
        }
        elseif ([string]$Entry.kind -eq 'excel') {
            $dir = $OutputDir
            if (-not $dir) { $dir = [string]$global:SI_RiskAnalysis_OutputDir }
            if (-not $dir) { $dir = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'output') }
            $path = [IO.Path]::Combine($dir, [string]$Entry.file)
            $W.Target = ('{0} ({1})' -f [IO.Path]::GetFileName($path), $Entry.sheet)
            if (-not (Get-Command -Name Write-RAXlsxStreamed -ErrorAction SilentlyContinue)) { foreach ($f in (Import-SIDataOutXlsx)) { . $f } }
            $W.SheetColumns = Get-SIDataOutSheetColumns -Header $header
            try {
                $__siDataOutW = $W
                $xr = Write-SIDataOutSheet -Path $path -SheetName ([string]$Entry.sheet) -Header $header -SheetRows $SheetRows -NextPage { Get-SIDataOutSheetPage -W $__siDataOutW }
                $tg = $W.Target; if (@($xr.Sheets).Count -gt 1) { $tg = ('{0} ({1}, {2} sheets)' -f [IO.Path]::GetFileName($path), $Entry.sheet, @($xr.Sheets).Count) }
                $dw = [pscustomobject]@{ Ok = $true; Reason = ''; Errors = @(); Target = $tg }
            } catch {
                # the workbook is replaced only when complete: the last one stays; the run is a failed output
                $dw = [pscustomobject]@{ Ok = $false; Reason = ('the workbook could not be written -- {0}' -f $_.Exception.Message); Errors = @(); Target = $W.Target }
            }
        }
        elseif ([string]$Entry.kind -eq 'servicenow-importset' -and (Test-SIDataOutContractOutput -Output $id)) {
            # #914 THE CONTRACT: the full current scoped state, every row with its u_action, one batch
            $W.DataInvoke = $(if ($DataInvoke) { $DataInvoke } elseif ($cur -and $cur.ContainsKey('Invoke')) { $cur.Invoke } else { $null })
            $W.Replaced = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)); $W.ReplacesWarned = $false
            $W.BatchId = ''; $W.Resync = $false; $W.Scope = $null; $W.CiCheck = $false; $W.Contract = $true; $W.ContractGone = (New-Object System.Collections.Generic.List[string]); $W.SentWritten = 0; $W.SentUpdated = 0
            $dw = Invoke-SIDataOutSnowContract -W $W -SnowConnect $SnowConnect
            $sent.Written = [int]$W.SentWritten; $sent.Updated = [int]$W.SentUpdated
        }
        elseif ([string]$Entry.kind -eq 'servicenow-importset') {
            $sn = Open-SIDataOutSnowSession -Entry $Entry -Header $header -Store $Store -SnowConnect $SnowConnect -Here $PSScriptRoot -RunId $RunId
            $W.Target = [string]$sn.Table
            $W.Snow = $sn
            # #912: a run that stopped mid-push never wrote its end row -- what it recorded as sent goes again in THIS batch
            if ($sn.BatchState -eq 'writing' -and $Store) {
                $no = Reset-SIDataOutOrphanState -Store $Store -OutputId $id -RunId $RunId -Connector ([string]$Entry.connector)
                if ($no -gt 0) { & $Log 'WARN' ('{0}: {1} row(s) of an earlier run that stopped before its batch was complete go again in this batch' -f $Entry.label, $no) }
            }
            while ($null -ne ($pg = Get-SIDataOutNextPage -Cursor $cur)) {
                $r = Invoke-SIDataOutWriterPage -W $W -Items @($pg.Items) -Frozen ([string[]]@($pg.Frozen)); $pg = $null
                if ($null -eq $r) { continue }
                if ($sn.Failed -or $sn.Unavailable) { $sn.Delta += @($r.DeltaRows).Count; continue }
                $pr = Send-SIDataOutSnowPage -Session $sn -Rows @($r.DeltaRows)
                # a page that LANDED is recorded (its state only when every row of it landed); a held page is not -- it is
                # sent again on the next run
                if ($pr.Ok) {
                    Add-SIDataOutCommit -W $W -Page $r -State (@($pr.Errors).Count -eq 0)
                    $sent.Written += [int]$r.Written; $sent.Updated += [int]$r.Updated
                }
                $r = $null
            }
            $dw = Close-SIDataOutSnowSession -Session $sn
        }
        else { $dw = [pscustomobject]@{ Ok = $false; Reason = ("the output kind '{0}' is not written here" -f $Entry.kind); Errors = @(); Target = '' } }

        $res.Target = [string]$dw.Target
        $res.Errors = @($dw.Errors | Where-Object { $_ }).Count
        # held by the ServiceNow check (a missing column, a value that would be cut, a mapping by label): what was not sent is
        # not marked as sent, so those rows go on the next run; reported as a failed output of this run
        if (-not $dw.Ok -and $dw.PSObject.Properties['Held'] -and $dw.Held) { $res.Outcome = 'held'; $res.Why = [string]$dw.Reason; $res['HeldByCheck'] = $true }
        elseif (-not $dw.Ok) { $res.Outcome = 'failed'; $res.Why = [string]$dw.Reason }
        elseif ($res.Errors -gt 0) { $res.Outcome = 'partial'; $res.Why = [string]$dw.Reason }
        elseif ($dw.Reason -and $res.Outcome -ne 'whatif') { $res.Why = [string]$dw.Reason }
        # no longer in this output: sent before, not seen now -- never an item left out as disabled (what was sent for it
        # stays) nor one of a report the newest run could not complete. Logged and its state removed only when the
        # destination took the whole run.
        $apply = ($dw.Ok -and -not $WhatIf)
        # the contract writer did its own pass over what was sent before (held / gone rows are part of its batch)
        if (-not ($W.ContainsKey('Contract') -and $W.Contract)) { Invoke-SIDataOutGonePass -W $W -Apply:$apply -ApplyState:($apply -and $res.Errors -eq 0) }
        if ($res.Carried) { & $Log 'INFO' ('{0}: {1} item(s) of report(s) the newest run could not complete are kept as last sent (not "no longer sent")' -f $Entry.label, $res.Carried) }
        if ($W.FrozenSet.Count) { & $Log 'INFO' ('{0}: {1}' -f $Entry.label, (Format-SIDisabledStageLine -Stage Connectors -Count ([int]$W.FrozenSet.Count) -Where 'data out')) }
        Write-SIDataOutCommits -W $W -State -Changes
        # #912 A BATCH THAT DID NOT END COMPLETE IS SENT AGAIN WHOLE: ServiceNow's importer never imports it, so every row this
        # run recorded as sent for this output is marked to go again (its hash cleared) -- the next complete batch carries it.
        if ($W.ContainsKey('Snow') -and $W.Snow) {
            $sn2 = $W.Snow
            $res['StagingStatus'] = [string]$sn2.BatchState
            $res['BatchId'] = $(if ($sn2.BatchState) { [string]$sn2.BatchId } else { '' })
            if ($sn2.StatusWarning) { & $Log 'WARN' ('{0}: {1}' -f $Entry.label, $sn2.StatusWarning) }
            if ($sn2.StatusProblem) { & $Log 'WARN' ('{0}: staging status -- {1}' -f $Entry.label, $sn2.StatusProblem) }
            if ($sn2.BatchState) { & $Log 'INFO' ('{0}: staging status {1} -- batch {2} in {3}' -f $Entry.label, $sn2.BatchState, $sn2.BatchId, $sn2.StatusTable) }
            if ($sn2.BatchState -and $sn2.BatchState -ne 'complete' -and $Store -and -not $WhatIf) {
                $n = Reset-SIDataOutRunState -Store $Store -OutputId $id -RunId $RunId
                if ($n -gt 0) { & $Log 'WARN' ('{0}: the batch ended {1}, so ServiceNow does not import it -- its {2} row(s) go again on the next run' -f $Entry.label, $sn2.BatchState, $n) }
                $res.Why = (@($res.Why, ('staging status: {0} (batch {1}) -- its rows go again on the next run' -f $sn2.BatchState, $sn2.BatchId)) | Where-Object { $_ }) -join ' | '
            }
            elseif ($sn2.StatusWarning -and $res.Outcome -eq 'success') { $res.Why = (@($res.Why, ('WARNING: ' + $sn2.StatusWarning)) | Where-Object { $_ }) -join ' | ' }
        }
    } catch {
        $res.Outcome = 'failed'; $res.Why = $_.Exception.Message
    } finally {
        if ($W) {
            Clear-SIDataOutKeySet -Set $W.Seen; Clear-SIDataOutKeySet -Set $W.FrozenSet
            if ($W.OwnCarry) { Clear-SIDataOutKeySet -Set $W.CarrySet }
        }
    }
    if (-not $res.Contains('Carried')) { $res['Carried'] = 0 }
    $line = '{0}: {1} row(s); {2} new, {3} changed, {4} no longer sent, {5} unchanged{6}' -f $Entry.label, $res.Rows, $res.Written, $res.Updated, $res.Removed, $res.Unchanged, $(if ($res.Target) { ' -> ' + $res.Target } else { '' })
    $heldByCheck = ($res.Outcome -eq 'held')
    if ($res.Outcome -eq 'failed') { & $Log 'WARN' ('{0}: not written -- {1}' -f $Entry.label, $res.Why) }
    elseif ($heldByCheck) { & $Log 'WARN' ('{0}: {1} new and {2} changed row(s) {3}' -f $Entry.label, $res.Written, $res.Updated, $res.Why) }
    elseif ($res.Outcome -eq 'partial') { & $Log 'WARN' ('{0} -- {1}' -f $line, $res.Why) }
    else { & $Log 'OK' $line }
    # the run row: every data-out writer is a listed connector (never fails the run)
    if ($Store -and -not (Get-Command -Name Write-SIConnectorRun -ErrorAction SilentlyContinue)) { & $Log 'WARN' ('{0}: the run is not recorded -- the connector helper is not installed' -f $Entry.label) }
    elseif ($Store) {
        try {
            # held: what was not sent is counted as held, never as written (rows sent before a hold are counted as sent)
            $rec = New-SIConnectorJobRunRecord -Name ([string]$Entry.connector) -Kind $kind -RunId $RunId -StartedAt $started -WhatIf:([bool]$WhatIf) -Outcome $res.Outcome `
                -Opened $(if ($heldByCheck) { $sent.Written } else { $res.Written }) -Updated $(if ($heldByCheck) { $sent.Updated } else { $res.Updated }) -Closed $(if ($heldByCheck) { 0 } else { $res.Removed }) `
                -Errors $res.Errors -Why $res.Why -ErrorText $(if ($res.Outcome -eq 'failed') { $res.Why } else { '' })
            if ($heldByCheck) { $rec['Held'] = [int](($res.Written + $res.Updated) - ($sent.Written + $sent.Updated)) }
            $rec['Unchanged'] = $res.Unchanged
            $e1 = Write-SIConnectorRun -Store $Store -Record $rec
            if ($e1) { & $Log 'WARN' ('{0}: the run could not be recorded -- {1}' -f $Entry.label, $e1) }
        } catch { & $Log 'WARN' ('{0}: the run could not be recorded -- {1}' -f $Entry.label, $_.Exception.Message) }
    }
    return [pscustomobject]$res
}

function ConvertTo-SIDataOutCells {
    <# PURE. One mapped row -> its cells in header order, arrays / objects flattened to text (as the workbook shows them). #>
    param($Row, [string[]]$Header)
    , @(foreach ($h in $Header) {
            $v = $Row.$h
            if ($null -eq $v -or $v -is [string] -or $v -is [ValueType]) { $v }
            elseif ($v -is [System.Collections.IEnumerable]) { (@($v | ForEach-Object { if ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ } else { $_ | ConvertTo-Json -Compress -Depth 4 } }) -join '; ') }
            else { $v | ConvertTo-Json -Compress -Depth 4 }
        })
}

function Invoke-SIDataOutDestination {
    <#
    .SYNOPSIS  The destination of one output for rows already in hand, by its kind: excel (one sheet of a workbook in the
               output folder, streamed, split past Excel's sheet size) or servicenow-importset (the written + changed rows
               to the Import Set table the entry's setting names, after the check). Returns @{ Ok; Reason; Errors; Target }.
               The data-out writer goes page by page through the same functions (Write-SIDataOutSheet,
               Open-SIDataOutSnowSession / Send-SIDataOutSnowPage / Close-SIDataOutSnowSession).
    #>
    param([Parameter(Mandatory)]$Entry, [string[]]$Header, [AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][object[]]$Delta = @(), [string]$OutputDir,
          [System.Collections.Generic.List[object[]]]$CellRows,
          # the settings database (the output's ServiceNow connector, the check's record); $null = the install's secrets, not recorded
          $Store,
          # tests: { param($connector) } -> a Resolve-SISnowOutputConnection result (default: the real one)
          [scriptblock]$SnowConnect,
          [int]$SheetRows = 0)
    switch ([string]$Entry.kind) {
        'excel' {
            $dir = $OutputDir
            if (-not $dir) { $dir = [string]$global:SI_RiskAnalysis_OutputDir }
            if (-not $dir) { $dir = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'output') }
            $path = [IO.Path]::Combine($dir, [string]$Entry.file)
            if (-not (Get-Command -Name Write-RAXlsxStreamed -ErrorAction SilentlyContinue)) { foreach ($f in (Import-SIDataOutXlsx)) { . $f } }
            $cols = Get-SIDataOutSheetColumns -Header $Header
            $list = $CellRows
            if ($null -eq $list) { $list = New-Object 'System.Collections.Generic.List[object[]]'; foreach ($r in $Rows) { $list.Add([object[]](ConvertTo-SIDataOutCells -Row $r -Header $Header)) } }
            $__siDestPages = @{ List = $list; At = 0; Cols = $cols; Take = 5000 }
            $next = {
                $q = $__siDestPages
                if ($q.At -ge $q.List.Count) { return $null }
                $n = [Math]::Min($q.Take, $q.List.Count - $q.At); $part = $q.List.GetRange($q.At, $n).ToArray(); $q.At += $n
                return , (ConvertTo-SIDataOutSheetRows -Columns $q.Cols -CellRows $part)
            }
            $xr = Write-SIDataOutSheet -Path $path -SheetName ([string]$Entry.sheet) -Header $Header -SheetRows $SheetRows -NextPage $next
            $tg = ('{0} ({1})' -f [IO.Path]::GetFileName($path), $Entry.sheet); if (@($xr.Sheets).Count -gt 1) { $tg = ('{0} ({1}, {2} sheets)' -f [IO.Path]::GetFileName($path), $Entry.sheet, @($xr.Sheets).Count) }
            return [pscustomobject]@{ Ok = $true; Reason = ''; Errors = @(); Target = $tg }
        }
        'servicenow-importset' {
            $sn = Open-SIDataOutSnowSession -Entry $Entry -Header $Header -Store $Store -SnowConnect $SnowConnect -Here $PSScriptRoot
            if (-not $sn.Failed -and -not $sn.Unavailable) { $null = Send-SIDataOutSnowPage -Session $sn -Rows @($Delta) } else { $sn.Delta += @($Delta).Count }
            return (Close-SIDataOutSnowSession -Session $sn)
        }
        default { return [pscustomobject]@{ Ok = $false; Reason = ("the output kind '{0}' is not written here" -f $Entry.kind); Errors = @(); Target = '' } }
    }
}

# =====================================================================================================================
#  AN OUTPUT THAT WROTE NOTHING SAYS SO: held, switched off, or its findings not stored yet -- a cfg.ConnectorRun row
#  each, so the heartbeat and the web app show a stopped output as stopped (never silent)
# =====================================================================================================================

function Get-SIDataOutConnectorRanSql {
    <# The connector names of @names (a JSON array) that have a run row already (cfg.ConnectorRun). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.ConnectorRun') IS NULL SELECT CAST(NULL AS NVARCHAR(64)) AS ConnectorName WHERE 1 = 0;
ELSE SELECT DISTINCT r.ConnectorName FROM cfg.ConnectorRun r
     WHERE r.ConnectorName IN (SELECT LEFT(z.k, 64) FROM OPENJSON(ISNULL(@names, N'[]')) WITH (k NVARCHAR(256) '$') z WHERE z.k IS NOT NULL);
'@
}

function Get-SIDataOutConnectorsThatRan {
    <# The connectors of -Names that have an earlier run row. A store that cannot be read answers none (nothing is written). #>
    param($Store, [AllowEmptyCollection()][string[]]$Names = @())
    $ns = @($Names | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $Store -or -not $Store.Invoke -or -not $ns.Count) { return @() }
    try {
        $a = & $Store.Invoke (Get-SIDataOutConnectorRanSql) @{ names = (ConvertTo-Json -InputObject @($ns) -Compress) } 'reader'
        @(@($a) | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] } | ForEach-Object { [string]$_['ConnectorName'] } | Where-Object { $_ })
    } catch { @() }
}

function Write-SIDataOutStateRun {
    <#
        One cfg.ConnectorRun row for an output that wrote nothing this run: -Outcome held (why: the hold's reason), off
        (switched off) or source-empty (its findings are not stored yet). Never throws; a failure to record is logged.
    #>
    param($Store, [Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][ValidateSet('held', 'off', 'source-empty')][string]$Outcome,
          [string]$Why = '', [scriptblock]$Log)
    if (-not $Store) { return }
    if (-not (Get-Command -Name Write-SIConnectorRun -ErrorAction SilentlyContinue)) { if ($Log) { & $Log 'WARN' ('{0}: the run is not recorded -- the connector helper is not installed' -f $Entry.label) }; return }
    try {
        $kind = 'file'; if ([string]$Entry.kind -eq 'servicenow-importset') { $kind = 'servicenow' }
        $rec = New-SIConnectorJobRunRecord -Name ([string]$Entry.connector) -Kind $kind -RunId $RunId -StartedAt ([datetime]::UtcNow) -Outcome $Outcome -Why $Why
        $e1 = Write-SIConnectorRun -Store $Store -Record $rec
        if ($e1 -and $Log) { & $Log 'WARN' ('{0}: the run could not be recorded -- {1}' -f $Entry.label, $e1) }
    } catch { if ($Log) { & $Log 'WARN' ('{0}: the run could not be recorded -- {1}' -f $Entry.label, $_.Exception.Message) } }
}

function Get-SIDataOutSourceEmptySql {
    <#
        Is the published Detailed collection holding findings while the findings per CI (sidata.CiFinding) are empty? One row:
        PublishedRows (the published collection's rows; NULL = not known), PublishedHas (1 = it has findings), CiHas (1 = a
        finding per CI is stored). A database without the tables answers PublishedHas 0 (nothing is judged).
    #>
    @'
SET NOCOUNT ON;
DECLARE @id INT = NULL, @rows BIGINT = NULL, @pub INT = 0, @ci INT = 0;
IF OBJECT_ID('sidata.vPublishedCollection') IS NOT NULL
    SELECT TOP (1) @id = v.CollectionId, @rows = CONVERT(bigint, v.[Rows]) FROM sidata.vPublishedCollection v WHERE v.Kind = N'Detailed' ORDER BY v.CollectionTime DESC;
IF @id IS NOT NULL AND (ISNULL(@rows, 0) > 0 OR (OBJECT_ID('sidata.Finding') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.Finding f WHERE f.CollectionId = @id))) SET @pub = 1;
IF OBJECT_ID('sidata.CiFinding') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.CiFinding) SET @ci = 1;
SELECT @rows AS PublishedRows, @pub AS PublishedHas, @ci AS CiHas;
'@
}

# =====================================================================================================================
#  THE STEP
# =====================================================================================================================

function Invoke-SIDataOut {
    <#
    .SYNOPSIS  P5: every enabled data-out connector of this edition, from the database, through its output map in force.
               Never throws; returns one result per output.
    .PARAMETER Invoke  the data database (sidata.*), mode 'reader' | 'scalar'
    .PARAMETER Store   the settings database (cfg.ConnectorRun / ConnectorChange / DataOutItem); $null = not recorded
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Invoke,
        $Store,
        [ValidateSet('community', 'pro')][string]$Edition = 'pro',
        $Setting,
        [string]$RunId = ([guid]::NewGuid().ToString()),
        [string]$OutputDir,
        [scriptblock]$Write,
        [object[]]$Catalog,
        $Model,
        [switch]$WhatIf,
        [scriptblock]$Log,
        # SI_DisabledAssets_* (Get-SIDisabledAssetPolicy; tests) -- default: the live settings
        $DisabledPolicy,
        # the CIs of disabled accounts (tests) -- default: read from the database (Get-SIDataOutDisabledCiSql)
        [string[]]$DisabledCis,
        # ONE INCOMPLETE REPORT DOES NOT HOLD A WHOLE RUN: the reports the newest run could not complete (the data sync's
        # verdict) -- what they found and this run does not have is kept as last sent (Get-SIDataOutCarryKeysSql)
        [AllowEmptyCollection()][string[]]$FrozenReports = @(),
        # CR2 (#656): { param([string]$Connector) } -> a Resolve-SIDataHealthHold result. An output whose connector is HELD
        # (SecurityInsight's data Unhealthy, no SuperAdmin let it through) writes nothing this run: its result is 'held' and
        # what it last sent stays as it was. Not given = nothing is held (as before).
        [scriptblock]$HoldCheck
    )
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $results = New-Object System.Collections.Generic.List[object]
    try {
        if (-not $Catalog) { $Catalog = Get-SIDataOutCatalog }
        if ($null -eq $Setting) { $Setting = Get-Variable -Name SI_DataOut_Outputs -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
        $en = Get-SIDataOutEnabled -Catalog $Catalog -Setting $Setting -Edition $Edition
        foreach ($u in $en.Unknown) { & $Log 'WARN' ("data out  : '{0}' in SI_DataOut_Outputs is no output -- left out" -f $u) }
        # SWITCHED OFF: an output of this step and edition that is not switched on, but ran before, gets an 'off' run row --
        # a stopped output shows as off, never as silent (one that never ran gets none)
        if ($Store -and -not $WhatIf) {
            $onIds = @($en.Outputs | ForEach-Object { [string]$_.output })
            $offs = @($Catalog | Where-Object { $_ -and [string]$_.kind -ne 'fixed' -and @($_.editions) -contains $Edition -and
                                                -not [string](Get-SIItemValue $_ 'step') -and $onIds -notcontains [string]$_.output })
            if ($offs.Count) {
                $ran = @(Get-SIDataOutConnectorsThatRan -Store $Store -Names ([string[]]@($offs | ForEach-Object { [string]$_.connector })))
                foreach ($oe in $offs) {
                    if ($ran -notcontains [string]$oe.connector) { continue }
                    & $Log 'INFO' ("data out  : {0} is switched off (SI_DataOut_Outputs) -- not written; recorded as off" -f [string]$oe.output)
                    $results.Add([pscustomobject]@{ Output = [string]$oe.output; Connector = [string]$oe.connector; Outcome = 'off'; Rows = 0; Written = 0; Updated = 0; Removed = 0; Unchanged = 0; Errors = 0; Why = 'switched off'; Target = '' })
                    Write-SIDataOutStateRun -Store $Store -Entry $oe -RunId $RunId -Outcome off -Why 'switched off (SI_DataOut_Outputs)' -Log $Log
                }
            }
        }
        if (-not @($en.Outputs).Count) { & $Log 'INFO' 'data out  : no output is switched on'; return $results.ToArray() }
        if (-not $Model) { $Model = Get-SIDataModel }
        $vm = $null; if ($Model['value-maps']) { $vm = $Model['value-maps'].maps }
        # SI_DisabledAssets_Connectors: off (the default) leaves disabled accounts and devices out of every output, frozen
        $doDisabled = $null
        if (-not (Test-SIDisabledIncluded -Stage Connectors -Policy $DisabledPolicy)) {
            $dcis = @()
            if ($null -ne $DisabledCis) { $dcis = @($DisabledCis) }
            else {
                try { $dcis = @(@(& $Invoke (Get-SIDataOutDisabledCiSql) @{} 'reader') | Where-Object { $_ } | ForEach-Object { [string]$_['CiId'] } | Where-Object { $_ }) }
                catch { & $Log 'WARN' ("data out  : the disabled accounts could not be read ({0}) -- only items that say so themselves are left out" -f $_.Exception.Message) }
            }
            $doDisabled = [pscustomobject]@{ Cis = [string[]]@($dcis); Include = $false }
        }
        # per report: the findings of reports the newest run could not complete that this run does not have (their open
        # lifecycle rows) -- kept as last sent in every findings output; the summary keeps those reports' groups
        # #639: the data database's staging -- the keys each output has seen this run (and the carried ones) are staged there,
        # a page at a time, never held whole; a database that cannot say it has the tables keeps them in memory as before
        $stage = $null
        if (Test-SIDataOutStageReady -Invoke $Invoke -Log $Log) { $stage = $Invoke }
        $carryKeys = New-SIDataOutKeySet -Stage $stage; $carryPre = @()
        $frz = @($FrozenReports | Where-Object { "$_".Trim() })
        if ($frz.Count) {
            $carryPre = @($frz | ForEach-Object { ([string]$_).Trim() + '|' })
            try {
                # #899: ONLY the findings in each report's LAST COMPLETE result (the collection the data sync's carry took it
                # from) are kept as last sent -- a lifecycle state alone is never enough to re-send a row
                $srcRows = @(@(& $Invoke (Get-SIDataOutCarrySourceSql) @{ frozenReports = (ConvertTo-Json -InputObject @($frz) -Compress) } 'reader') | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] })
                $perRep = [ordered]@{}
                foreach ($sr in $srcRows) {
                    $fid = $sr['FromCollectionId']; if ($fid -is [System.DBNull]) { $fid = $null }
                    $perRep[[string]$sr['ReportName']] = @{ From = $fid; N = 0L }
                }
                $srcJson = ConvertTo-Json -Compress -InputObject @(foreach ($k in $perRep.Keys) { if ($null -ne $perRep[$k].From) { [ordered]@{ ReportName = [string]$k; FromId = [int]$perRep[$k].From } } })
                # a page at a time by the last complete result's own row id, each page's keys staged
                $aid = 0L
                while (@($perRep.Values | Where-Object { $null -ne $_.From }).Count -gt 0) {
                    $a = & $Invoke (Get-SIDataOutCarryKeysSql) @{ src = $srcJson; Take = 5000; AfterId = [string]$aid } 'reader'
                    $rows = @(@($a) | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] }); $a = $null
                    if ($rows.Count -eq 0) { break }
                    $repOf = @{}
                    $pageKeys = [string[]]@(foreach ($cr in $rows) {
                        $ik = Get-SIDataOutItemKey -Grain 'ci_finding' -Item ([pscustomobject]@{ si_ci_id = $(if ($cr['CiId'] -is [System.DBNull]) { '' } else { [string]$cr['CiId'] }); si_asset_id = $(if ($cr['AssetId'] -is [System.DBNull]) { '' } else { [string]$cr['AssetId'] }); si_finding_key = [string]$cr['FindingKey'] })
                        if (-not $repOf.ContainsKey($ik)) { $repOf[$ik] = [string]$cr['ReportName'] }
                        $ik })
                    $new = Add-SIDataOutKeys -Set $carryKeys -Keys $pageKeys
                    foreach ($nk in $new) { $rn = $repOf[[string]$nk]; if ($rn -and $perRep.Contains($rn)) { $perRep[$rn].N++ } }
                    $aid = [long]$rows[$rows.Count - 1]['PageId']
                    if ($rows.Count -lt 5000) { break }
                    $rows = $null
                }
                foreach ($k in $perRep.Keys) {
                    if ($null -eq $perRep[$k].From) { & $Log 'INFO' ("data out  : report {0} not complete: it has no complete earlier result -- nothing of it is re-sent" -f $k) }
                    else { & $Log 'INFO' ("data out  : report {0} not complete: {1} rows of its last complete result re-sent (collection {2})" -f $k, $perRep[$k].N, $perRep[$k].From) }
                }
            } catch { & $Log 'WARN' ("data out  : the findings of the report(s) the newest run could not complete could not be read ({0}) -- they may show as no longer sent this run; nothing is closed on it" -f $_.Exception.Message) }
            & $Log 'INFO' ("data out  : {0} could not be completed in the newest run -- {1} finding(s) of their last complete result that this run does not have are kept as last sent" -f ($frz -join ', '), $carryKeys.Count)
        }
        $srcEmpty = $null
        # #639: every output reads ITS grain from the database a page at a time (Read-SIDataOutItemPages) -- no grain is
        # read whole, and none is kept for the next output (the findings were held in about six copies across the outputs).
        # A read that fails is that output's failure (its result says why), never an output silently left out.
        foreach ($e in $en.Outputs) {
            $map = $Model.Outputs[[string]$e.output]
            if ($null -eq $map) {
                & $Log 'WARN' ("data out  : the output map '{0}' is not in the data model -- left out" -f $e.output)
                $results.Add([pscustomobject]@{ Output = [string]$e.output; Connector = [string]$e.connector; Outcome = 'failed'; Rows = 0; Written = 0; Updated = 0; Removed = 0; Unchanged = 0; Errors = 0; Why = 'its output map is not in the data model'; Target = '' })
                continue
            }
            if ($HoldCheck -and -not $WhatIf) {
                $hold = $null
                try { $hold = & $HoldCheck ([string]$e.connector) } catch { $hold = $null }
                if ($hold -and $hold.Held) {
                    & $Log 'WARN' ("data out  : {0} HELD -- {1}" -f [string]$e.output, [string]$hold.Reason)
                    $results.Add([pscustomobject]@{ Output = [string]$e.output; Connector = [string]$e.connector; Outcome = 'held'; Rows = 0; Written = 0; Updated = 0; Removed = 0; Unchanged = 0; Errors = 0; Why = [string]$hold.Reason; Target = '' })
                    # the hold is recorded as this output's run (held, and why) -- never a silent output
                    Write-SIDataOutStateRun -Store $Store -Entry $e -RunId $RunId -Outcome held -Why ('held -- {0}' -f [string]$hold.Reason) -Log $Log
                    continue
                }
            }
            $doGrain = [string]$map.grain
            # THE FINDINGS ARE NOT STORED YET: the published collection has findings, the findings per CI hold none -- this
            # output would write an empty table. It is NOT a success: the last file is kept, nothing is marked "no longer
            # sent" (the last known good data stands) and the run says why -- a warning, the run goes on
            if ($doGrain -in 'ci_finding', 'finding_summary') {
                if ($null -eq $srcEmpty) {
                    $srcEmpty = [pscustomobject]@{ Empty = $false; Rows = $null }
                    try {
                        $se = @(@(& $Invoke (Get-SIDataOutSourceEmptySql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -First 1
                        if ($se -and [int]$se['PublishedHas'] -eq 1 -and [int]$se['CiHas'] -eq 0) {
                            $srcEmpty = [pscustomobject]@{ Empty = $true; Rows = $(if ($se['PublishedRows'] -is [System.DBNull]) { $null } else { [long]$se['PublishedRows'] }) }
                        }
                    } catch { & $Log 'WARN' ("data out  : whether the findings per CI are stored could not be read ({0}) -- the findings outputs are written as usual" -f $_.Exception.Message) }
                }
                if ($srcEmpty.Empty) {
                    $why = ('the published collection has {0} findings, but the findings per CI are not stored yet -- the last file is kept and nothing is marked no longer sent' -f $(if ($null -ne $srcEmpty.Rows) { '{0:N0}' -f $srcEmpty.Rows } else { 'its' }))
                    & $Log 'WARN' ("data out  : {0} not written -- {1}" -f [string]$e.output, $why)
                    $results.Add([pscustomobject]@{ Output = [string]$e.output; Connector = [string]$e.connector; Outcome = 'source-empty'; Rows = 0; Written = 0; Updated = 0; Removed = 0; Unchanged = 0; Errors = 0; Why = $why; Target = '' })
                    if (-not $WhatIf) { Write-SIDataOutStateRun -Store $Store -Entry $e -RunId $RunId -Outcome source-empty -Why $why -Log $Log }
                    continue
                }
            }
            # the grain is PULLED a page at a time by the writer, when its destination is ready for the next page
            $doCursor = New-SIDataOutItemCursor -Invoke $Invoke -Grain $doGrain -Disabled $doDisabled -Stage $stage
            $ck = @(); $cp = @()
            if ($doGrain -eq 'ci_finding') { $ck = $carryKeys } elseif ($doGrain -eq 'finding_summary') { $cp = $carryPre }
            $owClock = [Diagnostics.Stopwatch]::StartNew()
            $owRes = Invoke-SIDataOutWriter -Entry $e -Map $map -Cursor $doCursor -ValueMaps $vm -Store $Store -Write $Write -RunId $RunId -OutputDir $OutputDir -WhatIf:$WhatIf -Log $Log `
                -CarrySet $(if ($ck -is [hashtable]) { $ck } else { $null }) -CarryPrefixes $cp -Stage $stage -Selected
            $results.Add($owRes)
            # 2026-10-25 each output's time and rows: the log line and cfg.StepPhaseTime (the settings database; never fails the output)
            $owSec = $owClock.Elapsed.TotalSeconds
            $owRows = -1L; try { if ($owRes -and $owRes.PSObject.Properties['Rows']) { $owRows = [long]$owRes.Rows } } catch { $owRows = -1L }
            & $Log 'INFO' ("timing      : data out {0} -- {1:N1} s, {2:N0} row(s)" -f [string]$e.output, $owSec, $owRows)
            if (-not $WhatIf -and $Store -and $Store.Invoke -and (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) { $null = Write-SIStepPhase -Invoke $Store.Invoke -Job 'asset-datasync' -Phase ('data out ' + [string]$e.output) -Seconds $owSec -Rows $owRows }
        }
        Clear-SIDataOutKeySet -Set $carryKeys
    } catch {
        & $Log 'WARN' ("data out  : not run this time -- {0}" -f $_.Exception.Message)
        $results.Add([pscustomobject]@{ Output = '(every output)'; Connector = ''; Outcome = 'failed'; Rows = 0; Written = 0; Updated = 0; Removed = 0; Unchanged = 0; Errors = 0; Why = $_.Exception.Message; Target = '' })
    }
    # one result per output, as items: @(Invoke-SIDataOut ...) counts the outputs
    return $results.ToArray()
}

function Get-SIDataOutIssues {
    <#
        PURE. #639 (working rule 4): the outputs of a data-out step that did not deliver, as run issues -- FAILED, because the
        customer's file or hand-off is missing ('failed') or not whole ('partial': some rows did not land; they are sent again
        next time). One plain line each. -Results: Invoke-SIDataOut's results.
    #>
    param([AllowEmptyCollection()][object[]]$Results = @())
    foreach ($r in @($Results)) {
        if ($null -eq $r) { continue }
        $o = [string]$r.Outcome
        $name = [string]$r.Output; if ($r.PSObject.Properties['Connector'] -and [string]$r.Connector) { $name = '{0} ({1})' -f [string]$r.Output, [string]$r.Connector }
        if ($o -eq 'failed') { [pscustomobject]@{ Level = 'FAILED'; Text = ('the output {0} was not written -- {1}' -f $name, [string]$r.Why) } }
        # held by the ServiceNow check (not by the data health hold, which says so on its own page): the hand-off did not go
        elseif ($o -eq 'held' -and $r.PSObject.Properties['HeldByCheck'] -and $r.HeldByCheck) { [pscustomobject]@{ Level = 'FAILED'; Text = ('the output {0} was {1}' -f $name, [string]$r.Why) } }
        elseif ($o -eq 'partial') { [pscustomobject]@{ Level = 'FAILED'; Text = ('the output {0} is not whole -- {1} row(s) did not land ({2}); they are sent again on the next run' -f $name, [int]$r.Errors, [string]$r.Why) } }
        # #914 (b) the target's own import reported errors for SecurityInsight's batch (read back): an issue of the run, uplinked
        if ($r.PSObject.Properties['ImportErrors'] -and [long]$r.ImportErrors -gt 0) {
            [pscustomobject]@{ Level = 'FAILED'; Text = ('the output {0}: your ServiceNow import reported {1} error row(s) for batch {2} -- check the import set rows of that batch (sys_import_set_row, state error)' -f $name, [long]$r.ImportErrors, [string]$r.ImportErrorBatch) }
        }
        # the findings per CI are not stored yet: not written, the last file kept -- a warning, never a success
        elseif ($o -eq 'source-empty') { [pscustomobject]@{ Level = 'WARNING'; Text = ('the output {0} was not written -- {1}' -f $name, [string]$r.Why) } }
    }
}
