#Requires -Version 5.1
<#
    The CI build (V3-DATA-MODEL part 2 + 2.20 -- #477 steps 2-4): the provider records in SQL become CIs IN SQL.
    Operator 2026-10-09: "we dont support la for correlation, sql only" / "la is slow" -- NOTHING here reads Log Analytics.

      1. GROUP      the records of the lookback, in SQL (label propagation over sidata.RecordIdentifier -> CiGroupMember)
      2. FEEDS      per provider + record type, the newest collection and whether it was complete (link states), in SQL
      3. BATCHES    of ~2,000 CIs: the batch's records from SQL -> the same pure CI core as before (SI-CiBuild.ps1:
                    identity from the ledger -- only the batch's slice of it --, links, fields, then the enrichment rules)
                    -> sidata.Ci / CiLink / CiDaily + the records' CiId, ONLY what changed (content hash, #501)
                    -> the ledger's changes in ONE statement -> SI_CI_CL (the correlated data Risk Analysis's Kusto reads:
                    a slim 'seen' row for every CI, a full row when the CI's posted content changed, a full refresh weekly)
      4. SAY        the time of every phase, the rows written to SQL, the rows + bytes posted to Log Analytics

    #534 INCREMENTAL: after the grouping ONE statement marks the DIRTY groups (a record new, changed, moved or gone, its link
    state or a time threshold changed, its identity-ledger anchors or manual override changed, its CI's full row not yet in
    SI_CI_CL -- SI-CiBuildSql.ps1 Get-SICiDirtySql); only the batches holding one are read, and of them only the dirty
    groups. Every other CI keeps its row exactly (rule 4): one set-based statement moves its collection time and writes
    today's trend row, and its slim 'seen' row is posted. A FULL RECONCILE builds every group: weekly
    (SI_CiBuild_FullReconcileDays, default 7), when the build fingerprint changes (data model, rules, mappings, CMDB, the
    build's code), after a failed or partial build, when the weekly full SI_CI_CL refresh is due, and when forced
    (-FullReconcile). A full reconcile counts the CIs it found changed although their group was clean -- one INFO line in the run log and sidata.CiBuildState LastReconcileCorrected (the rebuild fixed them; no alert).

    A STOPPED REBUILD CARRIES ON: a build of every CI keeps each batch it finishes (the records' built marks are written
    with the batch, not only at the end). When the job is stopped before the end (its time limit on a large tenant), the
    next build -- built from the same things -- does only what is left and what changed since, and says so in the run log
    (SI-CiBuildSql.ps1: Test-SICiCarryOn, Get-SICiDirtySql step 6b, Get-SICiMarkBatchBuiltSql).

    Memory = one batch, at any tenant size. Pro: the end of the asset-correlation job. Community (#477 / #480: SQL in every
    v3 install): Risk Analysis builds the CIs at the start of its run (RA-CiContext.ps1) with the same function.
    No database configured -> no CIs, said plainly (never a Log Analytics fallback). Never throws.

    The identity ledger (engine/data-model/identity: SQL when configured, else blob). Without a ledger there are no CIs: an
    id that is not remembered moves when a group's membership changes, and a CMDB would then hold duplicates.

    -Records is the OFFLINE seam (tests): records already in hand, grouped in memory by the same core; it reads nothing.
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

. (Join-Path $PSScriptRoot 'SI-CiBuild.ps1')
. (Join-Path $PSScriptRoot 'SI-CiEnrich.ps1')
. (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1')
if (-not (Get-Command -Name ConvertTo-SILogValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-RecordCapture.ps1') }
if (-not (Get-Command -Name Get-SICanonicalIdType -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-AssetIdentity.ps1') }
if (-not (Get-Command -Name Resolve-SIObjectIdentity -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'identity\SI-ObjectIdentity.ps1') }
if (-not (Get-Command -Name Get-SIObjectLedgerProvider -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'identity\SI-ObjectLedgerStore.ps1')
    . (Join-Path $PSScriptRoot 'identity\SI-ObjectLedgerBlob.ps1')
    . (Join-Path $PSScriptRoot 'identity\SI-ObjectLedgerProvider.ps1')
}
if (-not (Get-Command -Name Get-SIObjectLedgerSubset -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'identity\SI-ObjectLedgerStore.ps1') }
if (-not (Get-Command -Name Invoke-SICiGrouping -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-CiBuildSql.ps1') }
if (-not (Get-Command -Name Invoke-SICiClassification -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Classification.ps1') }
# #533 (b): disabled accounts and devices -- SI_DisabledAssets_Correlate (engine/_shared)
if (-not (Get-Command -Name Select-SIDisabledForStage -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-DisabledAssets.ps1') }

function Select-SICiGroupsEnabled {
    <#
        PURE. #533 (b) -- the CI groups the build keeps by SI_DisabledAssets_Correlate. A group whose members' records say
        the account is DISABLED in its own directory (si_account_enabled false -- Entra user / SP / device, AD account) is
        left out as a WHOLE: a disabled computer is not built from its Defender record alone. Unknown is enabled. Nothing
        is retired by it: the CI keeps its last build in the database (and its findings), and is built again the run its
        account is enabled again. Returns the Select-SIDisabledForStage result (Kept = groups, Count, Line).
    #>
    param([AllowEmptyCollection()][object[]]$Groups = @(), $Policy)
    Select-SIDisabledForStage -Items @($Groups) -Stage Correlate -Policy $Policy -Where 'CI correlation' -StateOf {
        param($g)
        # disabled wins: the first member that is disabled represents the group; else the first that says enabled
        $en = $null
        foreach ($m in @($g.Members)) {
            $s = Get-SIAssetEnabledState -Asset $m.Record
            if ($s -eq $false) { return $m.Record }
            if ($s -eq $true -and $null -eq $en) { $en = $m.Record }
        }
        $en
    }
}
function Format-SICiScopeLine {
    <# PURE. The one line the CI build logs when the collection scope left CIs out. Customer-facing: the settings named. #>
    param([int]$Count)
    ('CI correlation: left out {0} CI(s) of assets the collection scope settings leave out (SI_IncludeInactive_Endpoint, SI_RequireMdeActive_Endpoint, SI_IncludeInactive_Identity, SI_RequireRecentSignIn_Identity). Each keeps its last build and its findings are kept as they are, not closed; it is built again when the asset is in scope again.' -f $Count)
}

function Select-SICiGroupsInScope {
    <#
        PURE. CIs follow the collection scope (owner 2026-10-10). A group is left out when EVERY member record says it is out of
        scope (si_in_scope = false, marked by the Output stage on the records of an asset the scope settings left out). A group
        with any record not marked -- a live device sharing one record with a stale duplicate, or a record no profile decides
        on -- is built as before. Nothing is retired by it: the CI keeps its last build (and its findings, which freeze), and
        is built again the run its asset is in scope again. Returns @{ Kept; Excluded; Count; Line }.
    #>
    param([AllowEmptyCollection()][object[]]$Groups = @())
    $kept = New-Object System.Collections.Generic.List[object]; $excl = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Groups)) {
        if ($null -eq $g) { continue }
        $members = @($g.Members | Where-Object { $null -ne $_ })
        $out = $members.Count -gt 0
        foreach ($m in $members) {
            $v = Get-SIItemValue $m.Record 'si_in_scope'
            if (-not ($v -eq $false -or ([string]$v) -ieq 'false')) { $out = $false; break }
        }
        if ($out) { $excl.Add($g) } else { $kept.Add($g) }
    }
    $line = ''; if ($excl.Count -gt 0) { $line = Format-SICiScopeLine -Count $excl.Count }
    [pscustomobject]@{ Kept = $kept.ToArray(); Excluded = $excl.ToArray(); Count = $excl.Count; Line = $line }
}

# The ledger decisions read each member's identifiers with Get-SIMemberIdentifiers, which the (Pro-only) correlation engine
# defines. Community has no correlation engine, so the CI build carries the same few lines when it is not loaded.
if (-not (Get-Command -Name Get-SIMemberIdentifiers -ErrorAction SilentlyContinue)) {
    function Get-SIMemberIdentifiers {
        param($Member)
        if ($null -eq $Member) { return @() }
        $p = $Member.PSObject.Properties['Identifiers']
        if ($null -eq $p -or $null -eq $p.Value) { return @() }
        return @(@($p.Value) | Where-Object { $null -ne $_ })
    }
}

function ConvertFrom-SILogRecordRow {
    <# PURE. A stored record row (text cells, JSON text for dynamic) -> the record with catalog types. #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][hashtable]$Types)
    $o = [ordered]@{}
    foreach ($p in $Row.PSObject.Properties) {
        $n = $p.Name; $v = $p.Value
        if ($null -eq $v -or ($v -is [string] -and $v -eq '')) { continue }
        $t = $Types[$n]
        switch ($t) {
            'bool' { $v = ConvertTo-SIBoolOrNull $v }
            'int' { $x = ConvertTo-SINumberOrNull $v; if ($null -ne $x) { $v = [long]$x } else { $v = $null } }
            'real' { $v = ConvertTo-SINumberOrNull $v }
            'datetime' { $v = ConvertTo-SIUtcOrNull $v }
            'dynamic' { if ($v -is [string]) { $s = $v.Trim(); if ($s.StartsWith('[') -or $s.StartsWith('{')) { try { $v = $s | ConvertFrom-Json } catch { } } } }
            default { }
        }
        if ($null -ne $v) { $o[$n] = $v }
    }
    [pscustomobject]$o
}

function Get-SICiRuleSetAll {
    <# Every enrichment rule of every engine (shipped + custom + the Pro overlay), once per rule id. #>
    # the rule loader writes with the profilers' console helpers (Write-SIInfo ...), which the correlation job and Risk
    # Analysis do not load -- ring 1, 2026-10-08: "The term 'Write-SIInfo' is not recognized" stopped the CI build
    if (-not (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue)) {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling\_shared\Write-SIStyle.ps1')
    }
    if (-not (Get-Command -Name Get-SIRuleSet -ErrorAction SilentlyContinue)) {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling\shared\Get-SIRuleSet.ps1')
    }
    # Get-SIRuleSet keeps the default tier rule apart (it is the fallback, not one more vote): -Fallback returns it
    # (plus every turned-off rule, which the conversion skips). Both sets are needed; the CI rules mark fallback itself.
    $seen = @{}
    foreach ($e in 'endpoint', 'identity', 'azure', 'publicip') {
        foreach ($r in @(@(Get-SIRuleSet -Engine $e 3>$null) + @(Get-SIRuleSet -Engine $e -Fallback 3>$null))) {
            if ($null -eq $r) { continue }
            if ($seen.ContainsKey([string]$r.Id)) { continue }
            $seen[[string]$r.Id] = $true
            $r
        }
    }
}

function Get-SICiBuildRules {
    <#
        #462 every CI rule of the run: the AssetProfileBy* rule files converted onto SI fields (ConvertTo-SICiRules) + the
        native rule packs (data-model/rules, SI-CiRules.ps1) with the tagging switches applied. What could not be expressed or
        loaded is said, never silently dropped.
    #>
    param([scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[' + $l + '] ' + $m) } }
    $conv = ConvertTo-SICiRules -RuleSet @(Get-SICiRuleSetAll)
    if (@($conv.Unconverted).Count -gt 0) { & $Log 'WARN' ("CIs: {0} rule detection(s) could not be expressed on SI fields and were skipped: {1}" -f @($conv.Unconverted).Count, ((@($conv.Unconverted) | Select-Object -First 5) -join '; ')) }
    $native = Get-SICiAllNativeRules 3>$null
    if (@($native.Problems).Count -gt 0) { & $Log 'WARN' ("CIs: {0} native rule(s) skipped: {1}" -f @($native.Problems).Count, ((@($native.Problems) | Select-Object -First 5) -join '; ')) }
    # the operator's tier tag, low priority (asserted, last in the trust list) -- the profile has always used it
    # #690 (48) an identity's tier = the tier of the highest privilege it holds today (the privilege tier catalog)
    @($conv.Rules) + @($native.Rules) + @(Get-SICiTagTierRules) + @(Get-SICiPrivilegeTierRules)
}

function Get-SICmdbOwner {
    <# The tenant's ONE CMDB owner (operator 2026-10-08: "one cmdb truth, either si or external"): cmdb | servicenow. #>
    $s = ([string]$global:SIWeb_CmdbSource).Trim().ToLowerInvariant()
    if ($s -in 'servicenow', 'external-connector', 'external') { return 'servicenow' }
    return 'cmdb'
}

function Test-SICiCmdbProviderOn {
    <# PURE. SI_EnableCmdbProvider: on only for a real yes ($true, 'true', '1', 'yes', 'on'); not set or anything else = off. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    $s = ([string]$Value).Trim().TrimStart('$')
    return ($s -match '^(?i)(true|1|yes|on)$')
}

function Get-SICiCmdbIndexFromCache {
    <#
        The CMDB cache (the same Azure Tables the profilers' reconcile reads) -> New-SICiCmdbIndex. No storage account, or a
        cache that cannot be read, gives an EMPTY index and a warning: the CIs are still built, with what the rules set.
    #>
    param([scriptblock]$Log)
    $empty = New-SICiCmdbIndex
    if (-not $global:SI_StorageAccount) { return $empty }
    try {
        $ap = Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling\storage'
        if (-not (Get-Command -Name New-SIStorageContext -ErrorAction SilentlyContinue)) { . (Join-Path $ap 'StorageContext.ps1') }
        if (-not (Get-Command -Name Get-SICmdbServices -ErrorAction SilentlyContinue)) { . (Join-Path $ap 'CmdbCache.ps1') }
        $ctx = New-SIStorageContext -AccountName ([string]$global:SI_StorageAccount)
        $svc = @(Get-SICmdbServices -Context $ctx)
        $cis = @(Get-SICmdbCIs -Context $ctx)
        # #891 part 3: a cache read that could not finish is never used as a short CMDB -- the same handling as a failed read
        if ((Get-Command -Name Test-SICmdbCacheReadComplete -ErrorAction SilentlyContinue) -and -not (Test-SICmdbCacheReadComplete)) { throw ('the cache is incomplete: ' + ((Get-SICmdbCacheReadIssues) -join '; ')) }
        return (New-SICiCmdbIndex -Services $svc -CmdbCis $cis)
    } catch {
        if ($Log) { & $Log 'WARN' ("CIs: the CMDB cache could not be read ({0}) -- CMDB values come only from the rules this run." -f $_.Exception.Message) }
        return $empty
    }
}

function Get-SICiOwnerCmdbRecordSql {
    <# #463 the owning EXTERNAL CMDB's records (provider = @p, type cmdb_ci) from the install database. #>
    @'
SET NOCOUNT ON;
SELECT r.RecordKey, r.DocJson FROM sidata.CiRecord r WHERE r.Provider = @p AND r.RecordType = N'cmdb_ci' AND r.DocJson IS NOT NULL;
'@
}

function Get-SICiCmdbIndexForOwner {
    <#
        #463 ONE CMDB owner per tenant (V3-DATA-MODEL 2.8.1, D11): the CMDB values on the CIs come from the OWNER only.
          cmdb        SecurityInsight's own CMDB -- the CMDB cache the profilers' reconcile reads (Get-SICiCmdbIndexFromCache)
          servicenow  that system's cmdb_ci records in the install database (the servicenow mapping's si_cmdb_* fields);
                      SecurityInsight's own CMDB is NOT read -- a non-owner never decides
        -Sql: the install database seam (the SQL path); without it an external owner has an empty index (said).
    #>
    param([string]$Owner = (Get-SICmdbOwner), [scriptblock]$Sql, [scriptblock]$Log,
          # SI_EnableCmdbProvider (default off): SecurityInsight's own CMDB is used only while it is on -- the same switch the
          # profilers' CMDB refresh and rule cmdbId stamping obey. Off, a cache left from when it was on is NOT read.
          $CmdbProviderOn = $global:SI_EnableCmdbProvider)
    if ($Owner -eq 'cmdb') {
        if (-not (Test-SICiCmdbProviderOn -Value $CmdbProviderOn)) {
            if ($Log) { & $Log 'INFO' 'CIs: SecurityInsight''s own CMDB is off (SI_EnableCmdbProvider) -- CMDB values come only from the rules this run.' }
            return (New-SICiCmdbIndex)
        }
        return (Get-SICiCmdbIndexFromCache -Log $Log)
    }
    $recs = @()
    if ($Sql) {
        try {
            $rows = @(& $Sql (Get-SICiOwnerCmdbRecordSql) @{ p = $Owner } 'rows')
            $recs = @(foreach ($r in $rows) { $j = [string](Get-SIItemValue $r 'DocJson'); if ($j) { try { $j | ConvertFrom-Json } catch { } } })
        } catch { if ($Log) { & $Log 'WARN' ("CIs: the {0} CMDB records could not be read ({1}) -- CMDB values come only from the rules this run." -f $Owner, $_.Exception.Message) } }
    }
    if ($recs.Count -eq 0 -and $Log) { & $Log 'WARN' ("CIs: the CMDB owner is {0} (SIWeb_CmdbSource), but no {0} CMDB records are in the database -- CMDB values come only from the rules; SecurityInsight's own CMDB is not used (one CMDB owner per tenant)." -f $Owner) }
    New-SICiCmdbIndexFromRecords -Records $recs
}

function Read-SICiCmdbCachePages {
    <#
        #639 one table of the CMDB cache (Azure Tables) a PAGE at a time: -OnPage { param($Entities) } with each page of the
        service's answer (up to 1,000 entities) before the next is read -- never the whole table in memory, and no limit on
        how many pages there are (the shared reader stops after 100 pages, ~100,000 entities, without a word). A missing
        table is an empty one; any other failure THROWS (the caller makes it a build issue). A Mock context (tests) hands
        the mock's rows on as one page. Answers the entities read.
    #>
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$Table, [string]$PartitionKey, [Parameter(Mandatory)][scriptblock]$OnPage)
    if ($Context.Mode -eq 'Mock') {
        $rows = @($Context.MockState.Tables[$Table].Values | ForEach-Object { [pscustomobject]$_ })
        if ($PartitionKey) { $rows = @($rows | Where-Object { [string]$_.PartitionKey -eq $PartitionKey }) }
        if ($rows.Count -gt 0) { $null = & $OnPage $rows }
        return $rows.Count
    }
    # #891 part 3: the CMDB cache's own page reader -- every page to the end, through the shared storage helper (its retry)
    if (-not (Get-Command -Name Read-SICmdbTablePages -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'asset-profiling', 'storage', 'CmdbCache.ps1')) }
    Read-SICmdbTablePages -Context $Context -Table $Table -PartitionKey $PartitionKey -OnPage $OnPage
}

function Import-SICiCmdbStage {
    <#
        #639 THE OWNING CMDB, STAGED IN SQL A PAGE AT A TIME (V3-DATA-MODEL 2.8.1, one CMDB owner per tenant -- the same items
        Get-SICiCmdbIndexForOwner reads): every lookup key of every item goes to sidata.CiBuildStage (Kind 'ck') with the hash
        of the item behind it and the item's fields a CI reads (ConvertTo-SICiCmdbStageItem), in chunks. Nothing of the CMDB is
        held beyond one page and one chunk; each batch of the build then looks up only its own keys (Get-SICiCmdbBatchIndex).
          cmdb        SecurityInsight's own CMDB (the CMDB cache, Azure Tables) -- only while SI_EnableCmdbProvider is on
          servicenow  that system's cmdb_ci records in the install database, in record-key pages
        A read that fails is NOT an empty CMDB: Ok = $false with the reason (the caller makes it a build issue and does not
        compare the CMDB's keys this build -- an empty CMDB would dirty and strip every CI that uses one).
        Answers @{ Ok; Items; Keys; Why }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)]$Writer, [string]$Owner = (Get-SICmdbOwner), [scriptblock]$Log,
          $CmdbProviderOn = $global:SI_EnableCmdbProvider, [int]$PageSize = 2000, $StorageContext)
    $res = [ordered]@{ Ok = $true; Items = 0L; Keys = 0L; Why = '' }
    $stage = { param($item, $kind) foreach ($r in @(ConvertTo-SICiCmdbStageItem -Item $item -Kind $kind)) { if ($r) { $Writer.Add([string]$r.K, [string]$r.H, [string]$r.V) } } }
    try {
        if ($Owner -eq 'cmdb') {
            if (-not (Test-SICiCmdbProviderOn -Value $CmdbProviderOn)) {
                if ($Log) { & $Log 'INFO' 'CIs: SecurityInsight''s own CMDB is off (SI_EnableCmdbProvider) -- CMDB values come only from the rules this run.' }
                return [pscustomobject]$res
            }
            if (-not $global:SI_StorageAccount -and $null -eq $StorageContext) { return [pscustomobject]$res }
            $ctx = $StorageContext
            if ($null -eq $ctx) {
                $ap = Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling\storage'
                if (-not (Get-Command -Name New-SIStorageContext -ErrorAction SilentlyContinue)) { . (Join-Path $ap 'StorageContext.ps1') }
                if (-not (Get-Command -Name Get-SICmdbServices -ErrorAction SilentlyContinue)) { . (Join-Path $ap 'CmdbCache.ps1') }
                $ctx = New-SIStorageContext -AccountName ([string]$global:SI_StorageAccount)
            }
            $res.Items += Read-SICiCmdbCachePages -Context $ctx -Table 'sicmdbservices' -PartitionKey 'service' -OnPage { param($page) foreach ($s in $page) { & $stage $s 'service' } }
            $res.Items += Read-SICiCmdbCachePages -Context $ctx -Table 'sicmdbcis' -OnPage { param($page) foreach ($c in $page) { & $stage $c 'ci' } }
        } else {
            $after = ''
            while ($true) {
                $rows = @(& $Sql (Get-SICiOwnerCmdbRecordPageSql) @{ p = $Owner; after = $after; n = [string]$PageSize } 'rows')
                if ($rows.Count -eq 0) { break }
                foreach ($r in $rows) {
                    $j = [string](Get-SIItemValue $r 'DocJson'); if (-not $j) { continue }
                    $rec = $null; try { $rec = $j | ConvertFrom-Json } catch { $rec = $null }
                    if ($null -ne $rec) { $res.Items++; & $stage $rec 'record' }
                }
                $after = [string](Get-SIItemValue $rows[$rows.Count - 1] 'RecordKey')
                $last = $rows.Count -lt $PageSize
                $rows = $null
                if ($last) { break }
            }
            if ($res.Items -eq 0 -and $Log) { & $Log 'WARN' ("CIs: the CMDB owner is {0} (SIWeb_CmdbSource), but no {0} CMDB records are in the database -- CMDB values come only from the rules; SecurityInsight's own CMDB is not used (one CMDB owner per tenant)." -f $Owner) }
        }
        $Writer.Flush()
        $res.Keys = [long]$Writer.Rows
    } catch {
        $res.Ok = $false; $res.Why = $_.Exception.Message
    }
    [pscustomobject]$res
}

function Get-SICiCmdbBatchIndex {
    <# #639 the owning CMDB's items ONE batch can use (Get-SICiCmdbLookupKeys of its documents + the ids the rules and
       overrides can set), looked up in the build's stage -> the index Set-SICiCmdb reads. -Total: the staged keys of the
       whole CMDB (0 = no CMDB: the empty index, nothing read). #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [AllowEmptyCollection()][object[]]$Docs = @(), [AllowEmptyCollection()][string[]]$ExtraIds = @(), [long]$Total = 0)
    if ($Total -le 0) { return (New-SICiCmdbIndex) }
    $keys = Get-SICiCmdbLookupKeys -Docs $Docs -ExtraIds $ExtraIds
    if (@($keys).Count -eq 0) { return (ConvertTo-SICiCmdbBatchIndex -Rows @() -Total $Total) }
    $rows = @(& $Sql (Get-SICiCmdbStageLookupSql) @{ k = (ConvertTo-SIJsonArray @($keys)) } 'rows')
    ConvertTo-SICiCmdbBatchIndex -Rows $rows -Total $Total
}

function Get-SICiWorkbookPage {
    <#
        #639 THE CI WORKBOOK A PAGE AT A TIME: the next id page of the CIs of this build (its collection time, State.Now) from
        sidata.Ci -> @{ Items (the documents); Frozen; Rows (the CIs read) }, or $null when every CI is read.
        SI_DisabledAssets_Connectors leaves a disabled account's CI out of the page (its key handed on as frozen). No cap:
        every CI of the build is in the workbook. -State (New-SICiWorkbookCursor): Sql, Now, IncludeDisabled, PageSize, After, Done.
    #>
    param([Parameter(Mandatory)][hashtable]$State)
    if ($State.Done) { return $null }
    $rows = @(& $State.Sql (Get-SICiWorkbookPageSql) @{ nowText = $State.Now.ToString('o'); after = [string]$State.After; n = [string]$State.PageSize } 'rows')
    if ($rows.Count -eq 0) { $State.Done = $true; return $null }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $js = [string](Get-SIItemValue $r 'DocJson'); if (-not $js) { continue }
        $h = $null
        try { if ($PSVersionTable.PSVersion.Major -ge 6) { $h = ConvertFrom-Json -InputObject $js -AsHashtable } else { $h = ConvertFrom-Json -InputObject $js } } catch { $h = $null }
        if ($null -eq $h) { continue }
        if ($h -is [System.Collections.IDictionary]) { $h['si_collection_time'] = $State.Now } else { $h | Add-Member -NotePropertyName 'si_collection_time' -NotePropertyValue $State.Now -Force }
        $items.Add($h)
    }
    $n = $rows.Count
    $State.After = [string](Get-SIItemValue $rows[$rows.Count - 1] 'CiId')
    if ($rows.Count -lt $State.PageSize) { $State.Done = $true }
    $rows = $null
    $sel = Select-SIDataOutEnabledItems -Grain 'ci' -Items $items.ToArray() -Include ([bool]$State.IncludeDisabled)
    $items = $null
    @{ Items = @($sel.Kept); Frozen = [string[]]@($sel.FrozenKeys); Rows = [long]$n }
}

function New-SICiWorkbookCursor {
    <#
        #639 the CI workbook's items as the data-out writer's cursor (New-SIDataOutItemCursor -Source): the writer PULLS the
        next page of this build's CIs (Get-SICiWorkbookPage) when the streamed workbook asks for it, so one page of CI
        documents is held at a time, at any size. Cursor.Rows: the CIs read.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][datetime]$Now, [bool]$IncludeDisabled = $false, [int]$PageSize = 2000)
    $st = @{ Sql = $Sql; Now = $Now.ToUniversalTime(); IncludeDisabled = $IncludeDisabled; PageSize = [Math]::Max(1, $PageSize); After = ''; Done = $false }
    New-SIDataOutItemCursor -Grain 'ci' -PageSize $st.PageSize -Source { param($State) Get-SICiWorkbookPage -State $State } -SourceState $st
}

function Write-SICiWorkbook {
    <#
        #639 the CI workbook (Excel) of one build, every CI of it a page at a time: the data-out writer (Invoke-SIDataOutWriter)
        pulls the pages from New-SICiWorkbookCursor. The writer never throws (a failure is its outcome). Answers
        @{ Result (the writer's); Read (the CIs read) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][datetime]$Now, [Parameter(Mandatory)]$Entry, [Parameter(Mandatory)]$Map,
          $ValueMaps, $Store, [string]$RunId, [scriptblock]$Log, [bool]$IncludeDisabled = $false, [int]$PageSize = 2000, [string]$OutputDir, [string]$Edition = '')
    $cur = New-SICiWorkbookCursor -Sql $Sql -Now $Now -IncludeDisabled $IncludeDisabled -PageSize $PageSize
    $wa = @{ Entry = $Entry; Map = $Map; Cursor = $cur; ValueMaps = $ValueMaps; Store = $Store; RunId = $RunId; Log = $Log; PageSize = $cur.PageSize }
    if ($OutputDir) { $wa['OutputDir'] = $OutputDir }
    if ($Edition) { $wa['Edition'] = $Edition }
    if (-not $RunId) { $wa.Remove('RunId') }
    $wr = Invoke-SIDataOutWriter @wa
    [pscustomobject]@{ Result = $wr; Read = [long]$cur.Rows }
}

function Invoke-SICiCore {
    <#
        PURE (no I/O). One set of COMPLETE groups -> CI documents (identity from -Ledger, links, resolved fields, enriched).
        The same core for a whole tenant (offline) and for one batch of the SQL build: a group is a whole CI, so a batch
        decides exactly what a whole run would for its groups.
    #>
    param([AllowEmptyCollection()][object[]]$Groups = @(), [Parameter(Mandatory)][hashtable]$FeedLatest, [hashtable]$Ledger = @{},
          [Parameter(Mandatory)]$Model, [AllowEmptyCollection()][object[]]$Rules = @(), [hashtable]$CmdbIndex, [datetime]$Now = [datetime]::UtcNow, [string]$RunId = '',
          # #462 the manual CI overrides in force (ConvertTo-SICiOverrideIndex)
          [hashtable]$Overrides,
          # #496 the business services (New-SICiServiceIndex): which services own each CI, what it inherits; none = not set
          [hashtable]$ServiceIndex,
          # the build's watch (Start-SICiWatch, SI-CiEnrich.ps1): a step that takes long says which CI it is working on
          $Watch,
          # #406 the lifecycle settings (Get-SICiLifecycleSettings), read once per build; not given = the settings in force
          $Lifecycle,
          # #406 CI id -> what the CI was after the last build (@{ Lifecycle; Since; Reason }, Get-SICiBatchStored)
          [hashtable]$PreviousLifecycle,
          # 60.5.0d provider -> the time its collection scope changed (Update-SICiScopeChanges)
          [hashtable]$ScopeChangedAt,
          # #639 the owning CMDB looked up for THIS set: { param($Docs) } -> the index of the items these CIs can use
          # (Get-SICiCmdbBatchIndex), called once the documents are built and before the rules -- instead of -CmdbIndex
          [scriptblock]$CmdbLookup)
    if ($null -eq $Lifecycle) { $Lifecycle = Get-SICiLifecycleSettings }
    Set-SICiWatchPhase -Watch $Watch -Phase 'looking up the ids of its assets'
    $idy = Resolve-SIObjectIdentity -Groups @($Groups) -Ledger $Ledger -Now $Now
    $owner = Get-SICmdbOwner
    $docs = New-Object System.Collections.Generic.List[object]
    $minted = 0; $merged = 0
    # the catalog's resolved fields, read once for the set (not once per CI)
    Set-SICiWatchPhase -Watch $Watch -Phase 'building the CIs from their records' -Total @($idy.Decisions).Count
    $nDone = 0
    # the records each CI is built from (a CI the rules' time limit stops: the build has exactly these built again)
    $recordKeys = @{}
    $fieldPlan = @(Get-SICiFieldPlan -Catalog $Model['field-catalog'])
    # #642 SEVERAL GROUPS OF THIS SET RESOLVED TO ONE ID, and the ledger could not prove them different objects (a proven
    # wrong merge was split off in Resolve-SIObjectIdentity already). The id is ONE CI, so it is built ONCE from the records
    # of all of them -- never "the first group kept, the others dropped", which left a CI with only one group's links and the
    # other groups' records without a CI. Counted and named (Collisions); the build says so as a warning.
    $byCid = [ordered]@{}
    foreach ($d in @($idy.Decisions)) {
        if (-not $d.CorrelationId) { continue }
        $c = [string]$d.CorrelationId
        if (-not $byCid.Contains($c)) { $byCid[$c] = New-Object System.Collections.Generic.List[object] }
        $byCid[$c].Add($d)
    }
    $collisions = New-Object System.Collections.Generic.List[object]
    $one = New-Object System.Collections.Generic.List[object]
    foreach ($c in $byCid.Keys) {
        $ds = $byCid[$c].ToArray()
        if ($ds.Count -eq 1) { $one.Add($ds[0]); continue }
        $collisions.Add([pscustomobject]@{ CiId = $c; Groups = $ds.Count })
        $members = New-Object System.Collections.Generic.List[object]
        foreach ($x in $ds) { foreach ($m in @($x.Group.Members)) { $members.Add($m) } }
        $one.Add([pscustomobject]@{ CorrelationId = $c; Action = [string]$ds[0].Action; Group = [pscustomobject]@{ Members = $members.ToArray() } })
    }
    foreach ($d in $one) {
        if (-not $d.CorrelationId) { continue }
        if ($d.Action -eq 'mint') { $minted++ } elseif ($d.Action -eq 'merge') { $merged++ }
        $recs = @(foreach ($m in @($d.Group.Members)) { $m.Record })
        $cid = [string]$d.CorrelationId
        if (-not $recordKeys.ContainsKey($cid)) { $recordKeys[$cid] = New-Object System.Collections.Generic.List[string] }
        foreach ($r in $recs) { $rk = [string](Get-SIItemValue $r 'si_record_key'); if ($rk) { $recordKeys[$cid].Add($rk) } }
        if ($Watch) { $Watch.Slots['main'] = @((Get-SICiWatchLabel $recs[0] $recs.Count), [datetime]::UtcNow.Ticks, $nDone) }
        $nDone++
        $prevLife = $null; if ($PreviousLifecycle) { $prevLife = $PreviousLifecycle[$cid] }
        $doc = New-SICiDocument -CiId ([string]$d.CorrelationId) -Records $recs -Catalog $Model['field-catalog'] -FeedLatest $FeedLatest -Now $Now -RunId $RunId -CmdbOwner $owner -FieldPlan $fieldPlan -Lifecycle $Lifecycle -Previous $prevLife -ScopeChangedAt $ScopeChangedAt
        $doc['si_ci_action'] = [string]$d.Action
        $docs.Add($doc)
    }
    if ($docs.Count -gt 0) {
        if ($CmdbLookup) { Set-SICiWatchPhase -Watch $Watch -Phase 'looking up the CMDB items of its CIs'; $CmdbIndex = & $CmdbLookup $docs.ToArray() }
        if ($null -eq $CmdbIndex) { $CmdbIndex = New-SICiCmdbIndex }
        $null = Invoke-SICiEnrichment -Cis $docs.ToArray() -Model $Model -Rules @($Rules) -CmdbOwner $owner -CmdbIndex $CmdbIndex -Now $Now -Overrides $Overrides -ServiceIndex $ServiceIndex -Watch $Watch
        Set-SICiWatchPhase -Watch $Watch -Phase 'setting the asset type and the components of its CIs'
        # #561 / #562 the one classification mechanism (SI-Classification.ps1): asset type, asset subtype and the components
        # (SQL, OS, ...) of every CI of the set, from the classification rows; never throws
        $null = Invoke-SICiClassification -Cis $docs.ToArray() -Model $Model -Context @{ Lists = (Get-SIDataModelListContext $Model); Now = $Now }
    }
    Set-SICiWatchPhase -Watch $Watch
    # ONE CI NEVER HOLDS THE BUILD: a CI whose rules took longer than their limit (Invoke-SICiRules -BudgetSeconds) got
    # only part of the rules. Its mark is taken off the document here and it is listed in Incomplete; the caller keeps it
    # OUT of what it writes (Get-SICiHeld), names it in the log, counts it and has it built again in the next run.
    $incomplete = New-Object System.Collections.Generic.List[object]
    foreach ($doc in $docs) {
        if (-not $doc.Contains('si_ci_rules_cut')) { continue }
        $cid = [string]$doc['si_ci_id']
        $rks = @(); if ($recordKeys.ContainsKey($cid)) { $rks = $recordKeys[$cid].ToArray() }
        $incomplete.Add([pscustomobject]@{ CiId = $cid; Label = (Get-SICiWatchLabel $doc); Seconds = $doc['si_ci_rules_cut']; RecordKeys = $rks })
        $doc.Remove('si_ci_rules_cut')
    }
    [pscustomobject]@{ Docs = $docs.ToArray(); Decisions = @($idy.Decisions); Superseded = @($idy.Superseded); Minted = $minted; Merged = $merged; Splits = @($idy.Splits); Incomplete = $incomplete.ToArray()
        # #642 the wrong merges this set repaired (split off the id that also held another object) and the ids several groups
        # of the set still share without proof (built once from all their records)
        WrongMergeSplit = [int]$idy.WrongMergeSplit; WrongMerges = @(@($idy.Splits) | Where-Object { [string]$_.Kind -eq 'wrong-merge' }); Collisions = $collisions.ToArray() }
}

function Format-SICiWrongMergeLines {
    <# PURE. #642 The build's lines about the identity ledger's wrong merges (none when there is nothing to say):
       -Split  objects split off a ledger id that, by proof, also held another object -- each is its own CI from now on
       -SharedGroups  groups that resolved to an id another group also has, without proof that they are different objects --
                      each such id is built as ONE CI from the records of all of them #>
    param([int]$Split = 0, [AllowEmptyCollection()][string[]]$SplitIds = @(), [int]$SharedGroups = 0, [AllowEmptyCollection()][string[]]$SharedIds = @())
    if ($Split -gt 0) {
        'CIs: {0:N0} asset(s) were split off a CI id the identity ledger had given to another asset as well (two or more identifiers an asset has once, e.g. object id and app id, differ) -- the asset the id was made for keeps it, each other one is its own CI from now on (first: {1}).' -f $Split, ((@($SplitIds) | Select-Object -First 5) -join ', ')
    }
    if ($SharedGroups -gt 0) {
        'CIs: {0:N0} group(s) of records resolved to a CI id another group also has, and nothing proves they are different assets -- each such id is built as one CI from all their records (ids: {1}). Check the identity ledger for an identifier the groups share.' -f $SharedGroups, ((@($SharedIds) | Select-Object -First 5) -join ', ')
    }
}
function Format-SICiIncompleteLine {
    <# PURE. The log line of a CI whose rules took longer than their limit (name and kind only, never a property's content).
       -Kept: it has a result of an earlier, complete evaluation, which stays in force; else it is new and is left out. #>
    param($Item, [double]$Budget = 60, [bool]$Kept = $false)
    $what = 'it is new and is left out until it is fully evaluated'
    if ($Kept) { $what = 'it keeps what it had from its last complete evaluation' }
    'CIs: {0} took longer than {1:N0} s in the rules -- not fully evaluated in this run; {2}. It is evaluated again, with every rule, in the next run.' -f [string]$Item.Label, $Budget, $what
}

function Format-SICiIncompleteSummary {
    <# PURE. The one line at the end of a build that could not fully evaluate some CIs: how many, and what happens to them. #>
    param([int]$Count = 0, [int]$Kept = 0, [int]$LeftOut = 0, [double]$Budget = 60)
    'CIs: {0:N0} asset(s) not fully evaluated in this run -- their rules took longer than {1:N0} s each. {2:N0} keep what they had from their last complete evaluation; {3:N0} are new and are left out until they are fully evaluated. No tier and no finding is based on part of the rules. They are evaluated again, with every rule, in the next run.' -f $Count, $Budget, $Kept, $LeftOut
}

function Format-SICiIncompleteNames {
    <# PURE. The names of the CIs a build could not fully evaluate, as one short text for the build's state (name and kind
       only): whole names, at most -MaxLength characters, the rest counted ('... and 12 more'). #>
    param([AllowEmptyCollection()][string[]]$Labels = @(), [int]$Total = -1, [int]$MaxLength = 380)
    $all = @($Labels | Where-Object { $_ })
    if ($Total -lt $all.Count) { $Total = $all.Count }
    if ($all.Count -eq 0) { return '' }
    $out = New-Object System.Collections.Generic.List[string]; $len = 0
    foreach ($l in $all) {
        $more = (' ... and {0:N0} more' -f $Total).Length
        if ($len + $l.Length + 2 + $more -gt $MaxLength) { break }
        $out.Add($l); $len += $l.Length + 2
    }
    $text = $out.ToArray() -join '; '
    if ($out.Count -lt $Total) { if ($text) { $text += (' ... and {0:N0} more' -f ($Total - $out.Count)) } else { $text = ('{0:N0} asset(s)' -f $Total) } }
    $text
}

function Get-SICiHeld {
    <#
        PURE. KEEP IT OUT UNTIL FULLY EVALUATED (owner 2026-10-13). A CI the rules' time limit stopped (-Incomplete, from
        Invoke-SICiCore) got only part of the rules, and a tier is the lowest tier ANY rule gives -- a tier from part of the
        rules is a wrong tier. So nothing of this run's result of such a CI is written or sent:
          Docs     the CIs of the set that ARE complete -- the only ones the batch writes, posts, links and hands on
          Kept     the stopped CIs that have a row from an earlier, complete evaluation (-Stored, Get-SICiBatchStored: the
                   batch read their stored content hash). The row, its links, its SI_CI_CL full row and its findings stay
                   exactly as they are; the CI is only SEEN in this run (Items: the same slim item an unchanged CI sends --
                   its stored content hash, so the database rewrites nothing and moves its last seen -- and the slim 'seen'
                   row to SI_CI_CL), so it is never taken for an asset that is gone
          LeftOut  the stopped CIs without such a row (a first run): not written and not sent at all
          RecordKeys  the records of both: the build takes their built marks off (@h of the two built-mark statements), which is what
                   makes the next build take these CIs up again, with every rule
    #>
    param([AllowEmptyCollection()][object[]]$Docs = @(), [AllowEmptyCollection()][object[]]$Incomplete = @(), $Stored)
    $storedHash = if ($Stored -and $Stored.Hash) { $Stored.Hash } else { @{} }
    $cut = @{}
    foreach ($i in @($Incomplete)) { if ($null -ne $i -and $i.CiId) { $cut[[string]$i.CiId] = $i } }
    if ($cut.Count -eq 0) { return [pscustomobject]@{ Docs = @($Docs); Kept = @(); LeftOut = @(); Items = @(); RecordKeys = @(); KeptIds = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)) } }
    $iso = { param($v) $x = $v; if ($x -isnot [datetime]) { $x = ConvertTo-SIUtcOrNull $x }; if ($x) { $x.ToUniversalTime().ToString('o') } else { $null } }
    $complete = New-Object System.Collections.Generic.List[object]
    $kept = New-Object System.Collections.Generic.List[object]; $left = New-Object System.Collections.Generic.List[object]
    $items = New-Object System.Collections.Generic.List[object]; $rks = New-Object System.Collections.Generic.List[string]
    $keptIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $done = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in @($Docs)) {
        if ($null -eq $c) { continue }
        $id = [string]$c['si_ci_id']
        if (-not $id -or -not $cut.ContainsKey($id)) { $complete.Add($c); continue }
        # two groups that resolved to one id: the id is held once, and no part of it is written
        if (-not $done.Add($id)) { continue }
        $i = $cut[$id]
        foreach ($rk in @($i.RecordKeys)) { if ($rk) { $rks.Add([string]$rk) } }
        $was = [string]$storedHash[$id]
        $h = [pscustomobject]@{ CiId = $id; Label = [string]$i.Label; Seconds = $i.Seconds; Kept = [bool]$was
            CollectionTime = (ConvertTo-SILogValue $c['si_collection_time']); LastSeen = (ConvertTo-SILogValue $c['si_last_seen']); LastSeenValue = $c['si_last_seen'] }
        if ($was) {
            $kept.Add($h); [void]$keptIds.Add($id)
            $items.Add([ordered]@{ CiId = $id; LastSeen = (& $iso $c['si_last_seen']); CollectionTime = (& $iso $c['si_collection_time']); Hash = $was; DocJson = $null; PostHash = $null })
        } else { $left.Add($h) }
    }
    [pscustomobject]@{ Docs = $complete.ToArray(); Kept = $kept.ToArray(); LeftOut = $left.ToArray(); Items = $items.ToArray(); RecordKeys = $rks.ToArray(); KeptIds = $keptIds }
}

function Get-SICiHeldDocSql {
    <# The stored documents of the CIs a batch keeps as they were (@ids = [ "CiId" ], Get-SICiHeld Kept): what the last
       complete evaluation wrote -- handed on (the CI workbook, Risk Analysis building the CIs in its own run) and, when
       every CI's full row is posted to SI_CI_CL in this build, posted again as it is. #>
    @'
SET NOCOUNT ON;
SELECT t.CiId, t.DocJson FROM sidata.Ci t
JOIN (SELECT DISTINCT LEFT(x.value, 64) AS CiId FROM OPENJSON(@ids) x WHERE x.value IS NOT NULL) k ON k.CiId = t.CiId
WHERE t.DocJson IS NOT NULL;
'@
}

function Get-SICiGroupLedgerKeys {
    <# PURE. The ledger keys (canonical type + value) a set of groups carries -- what the batch reads of the ledger. #>
    param([AllowEmptyCollection()][object[]]$Groups = @())
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $Groups) {
        foreach ($m in @($g.Members)) {
            foreach ($id in @($m.Identifiers)) {
                if ($null -eq $id) { continue }
                $t = Get-SICanonicalIdType -Type ([string]$id.Type); $v = ([string]$id.Value).ToLowerInvariant()
                if ($seen.Add("$t|$v")) { [pscustomobject]@{ Type = $t; Value = $v } }
            }
        }
    }
}

function Invoke-SICiBuild {
    <#
    .SYNOPSIS  Records (SQL) -> CIs (SQL + the SI_CI_CL copy). Returns a summary; never throws.
    .PARAMETER Records    OFFLINE seam (tests): records already in hand -- grouped in memory, nothing read
    .PARAMETER SqlInvoke  the install database seam { param($Sql, $Params, $Mode) } (tests); default: SI_ProSqlServer / Database
    .PARAMETER Post       the Log Analytics post seam { param($Rows) } -> rows accepted (tests); default: Send-SIObjectMapRows SI_CI
    #>
    param(
        # the records the build reads: those collected within this many days. 0 = SI_ActiveStaleDays (default 30) -- the
        # one staleness setting: a device off for a week is still a CI, with its latest data
        [int]$LookbackDays = 0,
        [object[]]$Records,
        [string]$RunId = '',
        [switch]$DryRun,
        [scriptblock]$Log,
        # test seam: CI rules already converted (skips loading the rule files)
        [object[]]$Rules,
        # test seam: the CMDB index already built (skips reading the CMDB cache)
        [hashtable]$CmdbIndex,
        # test seam: the manual CI override rows (sidata.CiOverride shape) -- else read from the database (SQL path)
        [object[]]$OverrideRows,
        [scriptblock]$SqlInvoke,
        # test seam: the ledger provider (@{ Kind = sql|blob; Connection|Store }) -- else Get-SIObjectLedgerProvider
        $LedgerProvider,
        [scriptblock]$Post,
        [int]$BatchCis = 2000,
        # a full SI_CI_CL refresh when the last one is older than this (Risk Analysis reads the newest full row per CI)
        [int]$FullPostDays = 7,
        # the CI workbook (Excel): 0 = not written (tests); any other value = written with EVERY CI of the build, read back
        # from the database a page at a time (#639 -- the old 50,000 limit is gone; the value is no longer a limit)
        [int]$WorkbookMaxCis = 50000,
        # TEST SEAM: return every CI's SI_CI_CL row (the RA columns only). No job uses it (#639: Risk Analysis looks its CIs
        # up per query slice, RA-CiContext.ps1) -- it holds every CI, so it is for tests of small fixtures only.
        [switch]$ReturnCis,
        # the grouping stops (said plainly) when it runs longer than this -- a database tier too small for the tenant
        [int]$GroupingBudgetSeconds = 0,   # ignored: the grouping has no clock (Invoke-SICiGrouping)
        # #534 rebuild every group this run (support), whatever the incremental build would decide
        [switch]$FullReconcile,
        # #534 a full reconcile when the last full build is this many days old; -1 = SI_CiBuild_FullReconcileDays (default
        # 7); 0 = a full build every run
        [int]$FullReconcileDays = -1,
        # test seam: the service index already built (#496; skips reading the CMDB services and the service model)
        [hashtable]$ServiceIndex,
        # the SI_CIRelation_CL post seam { param($Rows) } -> rows accepted (tests). Not given while -Post is (a test of the
        # CI rows): the relations are resolved in SQL but not posted.
        [scriptblock]$PostRelations,
        # ONE CI BUILD AT A TIME: the connection the build's lock lives on, { } -> an open connection (tests). Not given:
        # one to this install's database (Get-SICiBuildLockOpen) -- and none with -SqlInvoke, which is a test's own database
        [scriptblock]$LockOpen,
        # #639 rows per page where the build reads a set back from the database (the unchanged CIs' seen rows, the CI workbook,
        # the owning CMDB's records): paces the reads, never limits them
        [int]$PageRows = 5000,
        # test seam: the build's clock (what a CI's ages and time limits are measured from) -- a fixed time makes two builds of
        # the same records comparable CI for CI (tests\fixtures\ci-perf); not given: the current time
        [datetime]$BuildTime,
        # #406 test seam (offline): CI id -> what the CI was after an earlier build (@{ Lifecycle; Since; Reason }); the SQL
        # build reads it from sidata.Ci with the batch
        [hashtable]$PreviousLifecycle
    )
    if (-not $Log) { $Log = { param($l, $m) if ($l -eq 'WARN') { Write-Warning $m } else { Write-Host ('[' + $l + '] ' + $m) } } }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    # #639: what the build caught and went on from -- @{ Level = WARNING | FAILED; Text } (SI-RunOutcome.ps1), returned as
    # Issues: the correlation job fails on a FAILED one (rows short in SI_CI_CL) and says every WARNING
    $buildIssues = New-Object System.Collections.Generic.List[object]
    $phase = [ordered]@{}
    $mark = { param($name) $phase[$name] = [Math]::Round($sw.Elapsed.TotalSeconds, 1); $sw.Restart() }
    $stateRunning = $false; $sql = $null
    # the build's lock: taken by this build ($lockOwned: released at its end), or already held by this process (the
    # correlation job takes it before it writes the identity ledger); $lockLost: the build stops and writes no state
    $locked = $false; $lockOwned = $false; $lockLost = $false
    # the watch of the batches (Start-SICiWatch, SI-CiEnrich.ps1): a batch whose CIs take long says which CI it is working on
    $ciWatch = $null
    # asked before every write of a batch and before the build's own state is written (dot-sourced: it stops the build)
    $holdLock = {
        if ($locked) {
            $lockNow = Test-SICiBuildLock -Log $Log
            if (-not $lockNow.Held) { $lockLost = $true; throw [string]$lockNow.Why }
        }
    }
    try {
        if ($global:SI_DataModelCi -and ([string]$global:SI_DataModelCi).Trim().ToLowerInvariant() -in 'off', 'false', '0') { & $Log 'INFO' 'CIs: switched off (SI_DataModelCi = off).'; return $null }
        $model = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot
        $types = @{}; foreach ($f in @($model['field-catalog'].fields)) { $types[[string]$f.name] = [string]$f.type }
        $now = [datetime]::UtcNow
        if ($PSBoundParameters.ContainsKey('BuildTime')) { $now = $BuildTime.ToUniversalTime() }
        # #406 THE LIFECYCLE SETTINGS, read once: the seen window and the grace period of every category (SI-CiLifecycle.ps1 --
        # the same settings and the same rules as the CMDB sync's asset lifecycle)
        $lifeSettings = Get-SICiLifecycleSettings
        foreach ($w in @($lifeSettings.Warnings)) { & $Log 'WARN' ('CIs: lifecycle -- ' + $w) }

        # ---- the OFFLINE seam: records in hand, one in-memory pass through the same core ----
        if ($null -ne $Records) {
            if (@($Records).Count -eq 0) { & $Log 'INFO' 'CIs: no records -- not built.'; return $null }
            $feeds = Get-SIFeedLatest -Records @($Records)
            # members in ORDINAL record-key order -- the order the SQL build reads a group in (same decisions on both paths)
            # (an INDEX array: PowerShell hands [Array]::Sort a copy of an object[] -- the records would stay unsorted)
            $inHand = @($Records | Where-Object { $_ })
            [string[]]$rk = @($inHand | ForEach-Object { [string](Get-SIItemValue $_ 'si_record_key') }); [int[]]$ix = @(0..($inHand.Count - 1))
            [Array]::Sort($rk, $ix, [StringComparer]::Ordinal)
            $sorted = @(foreach ($i in $ix) { $inHand[$i] })
            $g = Get-SICiGroups -Records $sorted
            # #533 (b): disabled accounts and devices left out by SI_DisabledAssets_Correlate (said in one line)
            $gDis = Select-SICiGroupsEnabled -Groups @($g.Groups)
            if ($gDis.Line) { & $Log 'INFO' $gDis.Line }
            # CIs follow the collection scope: an asset the scope settings leave out keeps its last build
            $gScope = Select-SICiGroupsInScope -Groups @($gDis.Kept)
            if ($gScope.Line) { & $Log 'INFO' $gScope.Line }
            $g['Groups'] = @($gScope.Kept)
            $prov = $null
            try { if ($null -ne $LedgerProvider) { $prov = $LedgerProvider } else { $prov = Get-SIObjectLedgerProvider } } catch { & $Log 'WARN' ("CIs: the identity ledger could not be opened ({0}) -- no CIs this run." -f $_.Exception.Message); return $null }
            if ($null -eq $prov) { & $Log 'WARN' 'CIs: no identity ledger is configured (SQL or storage account) -- no CIs this run: an id that is not remembered moves.'; return $null }
            $read = Read-SIObjectLedger -Provider $prov
            if ($null -eq $Rules) { $Rules = @(Get-SICiBuildRules -Log $Log) }
            $ovIdx = ConvertTo-SICiOverrideIndex -Rows @($OverrideRows) -Now $now
            if ($null -eq $CmdbIndex) { $CmdbIndex = Get-SICiCmdbIndexForOwner -Log $Log }
            # #496 the business services without a database: the service model's rules and the CIs' own CMDB values -- the
            # same CI fields the SQL build sets
            if ($null -eq $ServiceIndex) { $ServiceIndex = Get-SICiServiceIndex -Log $Log }
            $core = Invoke-SICiCore -Groups @($g.Groups) -FeedLatest $feeds -Ledger $read.Ledger -Model $model -Rules @($Rules) -CmdbIndex $CmdbIndex -Now $now -RunId $RunId -Overrides $ovIdx -ServiceIndex $ServiceIndex `
                -Lifecycle $lifeSettings -PreviousLifecycle $PreviousLifecycle
            # a CI whose rules took too long is kept out until it is fully evaluated (nothing is stored here: it is left out)
            $held = Get-SICiHeld -Docs $core.Docs -Incomplete $core.Incomplete
            $docs = @($held.Docs)
            foreach ($ic in @($held.LeftOut)) { & $Log 'INFO' (Format-SICiIncompleteLine -Item $ic -Budget (Get-SICiRulesBudgetSeconds)) }
            if (@($held.LeftOut).Count -gt 0) { & $Log 'WARN' (Format-SICiIncompleteSummary -Count @($held.LeftOut).Count -LeftOut @($held.LeftOut).Count -Budget (Get-SICiRulesBudgetSeconds)) }
            # identities before devices: every identity CI is in hand, so a device / resource links to them in this pass too
            $null = Set-SICiIdentityLinks -Docs $docs -Index (ConvertTo-SICiIdentityIndex -Rows @(Get-SICiIdentityDocKeys -Docs $docs))
            if (-not $DryRun) { $null = Write-SIObjectLedger -Provider $prov -Decisions $core.Decisions -Superseded $core.Superseded -Now $now -IfMatchETag $read.ETag -CurrentLedger $read.Ledger }
            try { Close-SIObjectLedgerProvider -Provider $prov } catch { }
            & $Log 'OK' ("CIs: {0} record(s) -> {1} CI(s); {2} new, {3} merged{4}" -f @($Records).Count, $docs.Count, $core.Minted, $core.Merged, $(if ($DryRun) { ' -- DRY RUN, nothing written' } else { '' }))
            # #642 the identity ledger's wrong merges split off, and ids several groups still share (built as one CI)
            $sharedGroups = 0; foreach ($cc in @($core.Collisions)) { $sharedGroups += [int]$cc.Groups }
            foreach ($wl in @(Format-SICiWrongMergeLines -Split ([int]$core.WrongMergeSplit) -SplitIds @(@($core.WrongMerges) | ForEach-Object { '{0} -> {1}' -f $_.CorrelationId, $_.NewId }) -SharedGroups $sharedGroups -SharedIds @(@($core.Collisions) | ForEach-Object { [string]$_.CiId }))) { & $Log 'WARN' $wl }
            return [pscustomobject]@{ Records = @($Records).Count; Cis = $docs; CiCount = $docs.Count; Minted = $core.Minted; Merged = $core.Merged; Unkeyable = @($g.Unkeyable).Count; Posted = 0; Failed = $false
                Incomplete = @($held.LeftOut).Count; IncompleteCis = @(@($held.LeftOut) | ForEach-Object { [string]$_.Label })
                WrongMergeSplit = [int]$core.WrongMergeSplit; SharedIdGroups = $sharedGroups }
        }

        # ---- SQL ONLY ----
        if ($LookbackDays -le 0) { $LookbackDays = 30; if ($global:SI_ActiveStaleDays -and [int]$global:SI_ActiveStaleDays -gt 0) { $LookbackDays = [int]$global:SI_ActiveStaleDays } }
        $sql = $SqlInvoke
        if ($null -eq $sql) { $sql = New-SIRecordSqlInvoke }
        if ($null -eq $sql) {
            & $Log 'WARN' 'CIs were NOT built: no database is configured (SI_ProSqlServer / SI_ProSqlDatabase). The CIs are built in SQL only -- every v3 install needs its database.'
            return [pscustomobject]@{ Failed = $true; Reason = 'no-database'; CiCount = 0; Cis = @() }
        }

        # 0. the tables and columns the build needs, on a database set up by an older release (additive, idempotent)
        # (read-only: the engine never changes the schema -- the updater applies sql\si-data-schema.sql)
        $missing = @(Get-SIRecordSchemaMissing -Sql $sql)
        if ($missing.Count -gt 0) {
            & $Log 'WARN' ("CIs were NOT built: the database is not updated yet (missing {0}) -- run the updater." -f ($missing -join ', '))
            return [pscustomobject]@{ Failed = $true; Reason = 'the database is not updated yet'; Missing = $missing; CiCount = 0; Cis = @() }
        }

        # 0b. ONE CI BUILD AT A TIME (SI-RecordSql.ps1, Enter-SICiBuildLock): the build holds the database's lock from here
        # to its end. A build that finds another one running waits for it, then builds what is left -- and reads the
        # build's state (below) only now, so a build that is running is never taken for a stopped one (Test-SICiCarryOn).
        if ($null -eq $LockOpen -and $null -eq $SqlInvoke) { $LockOpen = Get-SICiBuildLockOpen }
        if ($LockOpen) {
            $lk = Enter-SICiBuildLock -Open $LockOpen -RunId $RunId -Log $Log
            if (-not $lk.Held) { $lockLost = $true; throw [string]$lk.Why }
            $locked = $true; $lockOwned = [bool]$lk.Owned
            # it waited: the build starts now, not when it was asked for
            if ($lk.Waited) { $now = [datetime]::UtcNow; if ($PSBoundParameters.ContainsKey('BuildTime')) { $now = $BuildTime.ToUniversalTime() }; $phase['wait'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1); $sw.Restart() }
        }

        # 1. grouping, in SQL
        $gr = Invoke-SICiGrouping -Sql $sql -LookbackDays $LookbackDays -BatchCis $BatchCis -BudgetSeconds $GroupingBudgetSeconds -Log $Log
        & $mark 'group'
        # the statement always answers ONE row (Rounds >= 1): no row is a failure, never "no records" (customer H 2026-10-09)
        if ($null -eq $gr -or $null -eq (Get-SIItemValue $gr 'Rounds')) {
            & $Log 'WARN' ("CIs were NOT built: the grouping statement answered no result after {0} s -- the database did not complete it." -f $phase['group'])
            return [pscustomobject]@{ Failed = $true; Reason = 'the grouping statement answered no result'; CiCount = 0; Cis = @() }
        }
        $nRec = [int](Get-SIItemValue $gr 'Records'); $nGroups = [int](Get-SIItemValue $gr 'Groups'); $nBatches = [int](Get-SIItemValue $gr 'Batches')
        $largest = [int](Get-SIItemValue $gr 'Largest'); $unkeyable = [int](Get-SIItemValue $gr 'Unkeyable')
        & $Log 'INFO' ("CIs: grouped {0} record(s) into {1} CI(s) in {2} s ({3} round(s), largest {4} record(s)); {5} record(s) without a strong identifier" -f $nRec, $nGroups, $phase['group'], (Get-SIItemValue $gr 'Rounds'), $largest, $unkeyable)
        if ($nRec -eq 0) { & $Log 'INFO' 'CIs: no records in the lookback -- not built.'; return [pscustomobject]@{ Failed = $false; Records = 0; CiCount = 0; Cis = @() } }
        $fusionAt = [Math]::Max(10, [int]([Math]::Ceiling($nRec * 0.05)))
        if ($largest -ge $fusionAt) { & $Log 'WARN' ("CIs: one CI holds {0} records -- check for a shared identifier that fuses different assets (the CIs are built; this is a warning)." -f $largest) }

        # 2. feeds, in SQL
        $feeds = ConvertTo-SICiFeedLatest -Rows @(& $sql (Get-SICiFeedLatestSql -LookbackDays $LookbackDays) @{} 'rows')
        & $mark 'feeds'

        # 3. the ledger, the rules, the CMDB, the post state
        $prov = $null
        try { if ($null -ne $LedgerProvider) { $prov = $LedgerProvider } else { $prov = Get-SIObjectLedgerProvider } } catch { & $Log 'WARN' ("CIs were NOT built: the identity ledger could not be opened ({0})." -f $_.Exception.Message); return [pscustomobject]@{ Failed = $true; Reason = 'ledger'; CiCount = 0; Cis = @() } }
        if ($null -eq $prov) { & $Log 'WARN' 'CIs were NOT built: no identity ledger is configured (SQL or storage account) -- an id that is not remembered moves.'; return [pscustomobject]@{ Failed = $true; Reason = 'no-ledger'; CiCount = 0; Cis = @() } }
        $whole = $null
        if ([string]$prov.Kind -ne 'sql') {
            # #639 a blob ledger is one document: read whole once per build (there is no per-batch read of a blob). An
            # identity ledger in SQL is read per batch (Get-SIObjectLedgerSubset) and never whole.
            $whole = Read-SIObjectLedger -Provider $prov
            & $Log 'INFO' ("CIs: the identity ledger is a blob -- read whole for this build ({0} anchor(s)); an identity ledger in SQL is read a batch at a time." -f @($whole.Ledger.Keys).Count)
        }
        if ($null -eq $Rules) { $Rules = @(Get-SICiBuildRules -Log $Log) }
        # #462 the manual CI overrides in force (sidata.CiOverride; a database without the table has none)
        if ($null -eq $OverrideRows) { try { $OverrideRows = @(& $sql (Get-SICiOverrideReadSql) @{} 'rows') } catch { & $Log 'WARN' ("CIs: the manual CI overrides could not be read ({0}) -- the rules decide this run." -f $_.Exception.Message); $OverrideRows = @() } }
        $ovIdx = ConvertTo-SICiOverrideIndex -Rows @($OverrideRows) -Now $now
        if ($ovIdx.Count -gt 0) { & $Log 'INFO' ("CIs: {0} CI(s) carry a manual override" -f $ovIdx.Count) }
        # #639 the build's stage (sidata.CiBuildStage): an updated database stages the CMDB keys, the clean CIs and the identity
        # values in SQL in chunks and reads them back per batch / per page. Without it (a database the updater has not updated
        # yet) the build holds them whole as before -- said once, as a warning of the build.
        $hasStage = $false
        try { $hs = @(& $sql (Get-SICiStageCheckSql) @{} 'rows') | Select-Object -First 1; $hasStage = ($hs -and [int](Get-SIItemValue $hs 'HasStage') -eq 1) } catch { $hasStage = $false }
        if ($hasStage) {
            foreach ($sk in 'ck', 'seen', 'idk') { $null = Clear-SICiStage -Sql $sql -Kind $sk }
        } else {
            & $Log 'WARN' 'CIs: the database is not updated yet (sidata.CiBuildStage is missing) -- this build holds the CMDB keys, the identity index and the unchanged CIs whole in memory as before; run the updater.'
            $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = 'the database is not updated yet (sidata.CiBuildStage is missing) -- this build held the CMDB keys, the identity index and the unchanged CIs whole in memory; run the updater' })
        }
        # #639 the owning CMDB: a test's index in hand is used whole (its keys staged in chunks); else the CMDB is staged in
        # SQL a page at a time and every batch looks up only its own keys (Get-SICiCmdbBatchIndex). A read that fails is a
        # build ISSUE and the CMDB's keys are not compared this build (an empty CMDB would make every CI that uses one lose its
        # CMDB values) -- never only a WARN line.
        $cmdbLookup = $null; $cmdbCompare = $true; $cmdbStaged = $false; $cmdbKeysJson = '[]'
        $ckWriter = $null; if ($hasStage) { $ckWriter = New-SICiStageWriter -Sql $sql -Kind 'ck' }
        if ($null -eq $CmdbIndex -and $hasStage) {
            $bw0 = [System.Diagnostics.Stopwatch]::StartNew()
            $cs = Import-SICiCmdbStage -Sql $sql -Writer $ckWriter -Log $Log -PageSize $PageRows
            if (-not $cs.Ok) {
                $cmdbCompare = $false
                & $Log 'WARN' ("CIs: the owning CMDB ({0}) could not be read ({1}) -- CMDB values come only from the rules this run, and the CIs that use a CMDB item are not rebuilt because of it." -f (Get-SICmdbOwner), $cs.Why)
                $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the owning CMDB ({0}) could not be read ({1}) -- CMDB values came only from the rules in this build' -f (Get-SICmdbOwner), $cs.Why) })
            } elseif ($cs.Items -gt 0) {
                & $Log 'INFO' ("CIs: the owning CMDB ({0}): {1:N0} item(s), {2:N0} lookup key(s) staged in {3} statement(s) in {4:N1} s -- each batch looks up only its own" -f (Get-SICmdbOwner), $cs.Items, $cs.Keys, $ckWriter.Statements, $bw0.Elapsed.TotalSeconds)
            }
            $cmdbTotal = [long]$cs.Keys
            $cmdbExtra = Get-SICiRuleCmdbIds -Rules @($Rules) -Overrides $ovIdx
            # (not a closure: it runs inside Invoke-SICiCore, called from here, and finds $sql / $cmdbExtra / $cmdbTotal here)
            $cmdbLookup = { param($Docs) Get-SICiCmdbBatchIndex -Sql $sql -Docs $Docs -ExtraIds $cmdbExtra -Total $cmdbTotal }
            $CmdbIndex = $null
        } elseif ($null -eq $CmdbIndex) {
            # a CLOSURE (also below): inside the reader, $Log is THIS block -- a plain block called itself there until the call
            # depth overflowed, on every line the reader says (a CMDB that could not be read, an owner with no records)
            $CmdbIndex = Get-SICiCmdbIndexForOwner -Sql $sql -Log ({ param($l, $m) & $Log $l $m; if ($l -eq 'WARN' -and $m -match 'could not be read') { $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ([string]$m -replace '^CIs: ', '') }) } }.GetNewClosure())
        }
        # #496 the business services: the CMDB page's links and the service catalog (Pro), the service model's binding rules
        # (#639 a read that fails is a build issue)
        if ($null -eq $ServiceIndex) { $ServiceIndex = Get-SICiServiceIndex -Sql $sql -Log ({ param($l, $m) & $Log $l $m; if ($l -eq 'WARN') { $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ([string]$m -replace '^CIs: ', '') }) } }.GetNewClosure()) }
        & $Log 'INFO' ("CIs: {0} business service(s), {1} CI(s) linked to a service on the CMDB page, {2} service model rule(s)" -f $ServiceIndex.Services.Count, $ServiceIndex.Links.Count, @($ServiceIndex.Bindings).Count)
        # #496: no service at all is not an error, but it must be said in plain words -- every CI then belongs to no business
        # service, the Services view is empty and nothing is grouped or prioritised by service
        $noServiceText = Get-SICiNoServiceText -Services $ServiceIndex.Services.Count -Links $ServiceIndex.Links.Count -Bindings @($ServiceIndex.Bindings).Count
        if ($noServiceText) { & $Log 'INFO' ('CIs: ' + $noServiceText) }
        # #493 the relations the data model declares (stage production)
        $relRules = @(Get-SICiRelationRules -Model $model)
        # the build's state (sidata.CiBuildState): the last full SI_CI_CL refresh, and (#534) the last full build, its
        # fingerprint, how the last build ended and when it started
        $state = @{}
        try { foreach ($sr in @(& $sql (Get-SICiStateAllSql) @{} 'rows')) { $state[[string](Get-SIItemValue $sr 'Name')] = [string](Get-SIItemValue $sr 'Value') } } catch { & $Log 'WARN' ("CIs: the build state could not be read ({0}) -- this build is full." -f $_.Exception.Message) }
        $lastFull = $state['LastFullPost']
        $full = Test-SICiFullPostDue -Last $lastFull -Now $now -Days $FullPostDays
        # 🔴 THE SI_CI_CL COLUMN CONTRACT CHANGED, OR A BUILD POSTED INTO COLUMNS AZURE WAS NOT STORING YET: every CI's full
        # row is posted again. A full row is posted only when its content changes, so the values a release's NEW columns
        # carried on their first build -- dropped while Azure was still adding the columns (~45 minutes) -- stayed missing
        # until the CI changed or the weekly refresh came round: ring 1 lost the classification (si_components), the app id,
        # the credential expiry and the unknown fields of every CI for a week (Risk Analysis read them as empty).
        $postContract = Get-SICiPostContractHash
        if (-not $full -and [string]$state['PostContract'] -ne $postContract) {
            $full = $true
            & $Log 'INFO' 'CIs: every CI''s full row is posted to SI_CI_CL this build -- its columns changed (or the last build posted into columns Azure was not storing yet).'
        }
        if (-not $Post -and -not $DryRun -and -not (Get-Command -Name Send-SIObjectMapRows -ErrorAction SilentlyContinue)) {
            . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-LogIngest.ps1')
        }

        # 60.5.0d THE COLLECTION SCOPE IS VERSIONED INPUT: the settings that narrow what each provider lists, compared with the
        # last build's. A provider whose scope changed keeps the time of the change: a record it last listed BEFORE that is
        # frozen (an asset that leaves because we stopped looking has told us nothing), never not seen or retired.
        $scope = $null
        try {
            $scopeStored = @{}
            if ($state['CollectionScope']) { $sj = ConvertFrom-Json ([string]$state['CollectionScope']); foreach ($sp in @($sj.PSObject.Properties)) { $scopeStored[[string]$sp.Name] = $sp.Value } }
            $scope = Update-SICiScopeChanges -Stored $scopeStored -Current (Get-SICiCollectionScope) -Now $now
            if (@($scope.Changed).Count -gt 0) { & $Log 'INFO' ("CIs: the collection scope of {0} changed since the last build -- an asset those sources no longer list because of it keeps its state (it is not moved to not seen or retired)." -f (@($scope.Changed) -join ', ')) }
            if (-not $DryRun) { $null = & $sql (Get-SICiStateSetSql) @{ j = (ConvertTo-SIJsonArray @([ordered]@{ n = 'CollectionScope'; v = (ConvertTo-Json -InputObject $scope.State -Compress -Depth 4) })) } 'rows' }
        } catch { & $Log 'WARN' ("CIs: the collection scope could not be compared with the last build's ({0}) -- no asset is moved to not seen or retired because a source stopped listing it this run." -f $_.Exception.Message); $scope = [pscustomobject]@{ State = @{}; ChangedAt = @{ azure = $now; mdc = $now; entra = $now; mde = $now; intune = $now; ad = $now; eg = $now; mdi = $now; shodan = $now; cmdb = $now; servicenow = $now }; Changed = @() } }
        # #534 FULL or INCREMENTAL: the fingerprint of what the CIs are built from, compared with the last build's
        $thresholds = @(Get-SICiTimeThresholds -Model $model -Rules @($Rules) -Lifecycle $lifeSettings)
        $fingerprint = ''
        try {
            # the CMDB OWNER is in it, its items are not (they dirty only the groups that use them); the build VERSION is in it,
            # the build's code is not (a release that does not change what a CI looks like is incremental). #496 the service
            # model's binding rules ride with the CI rules: a rule can place any CI, so a changed rule rebuilds every CI once (the
            # CMDB page's links and the services dirty only the CIs that use them -- Get-SICiServiceKeyHashes)
            $fingerprint = Get-SICiBuildFingerprint -Model $model -Rules (@($Rules) + @($ServiceIndex.Bindings)) -CmdbOwner (Get-SICmdbOwner) -Thresholds $thresholds -LookbackDays $LookbackDays `
                -BuildVersion $script:SICiBuildVersion -ExposedRanges ((@($global:SI_InternetExposedRanges) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ',') `
                -CollectionScope ((@($scope.State.Keys) | Sort-Object | ForEach-Object { '{0}={1}' -f $_, (Get-SIItemValue $scope.State[$_] 'h') }) -join ';')
        } catch { & $Log 'WARN' ("CIs: the build fingerprint could not be computed ({0}) -- this build is full." -f $_.Exception.Message) }
        if ($FullReconcileDays -lt 0) { $FullReconcileDays = Get-SICiFullReconcileDays }
        $decision = Get-SICiFullReconcileDecision -State $state -Fingerprint $fingerprint -Now $now -Days $FullReconcileDays -Force:([bool]$FullReconcile) -FullPostDue:$full
        $fullBuild = [bool]$decision.Full
        $reasons = New-Object System.Collections.Generic.List[string]; foreach ($x in @($decision.Reasons)) { $reasons.Add([string]$x) }
        if (-not $fingerprint) { $fullBuild = $true; $reasons.Add('the build fingerprint could not be computed') }
        # Risk Analysis building the CIs in its own run reads a skipped CI back from its stored document (PowerShell 6+)
        if (-not $fullBuild -and $ReturnCis -and $PSVersionTable.PSVersion.Major -lt 6) { $fullBuild = $true; $reasons.Add('every CI is returned and this PowerShell cannot read a stored CI back') }
        # CARRY ON (SI-CiBuildSql.ps1, Test-SICiCarryOn): a rebuild of every CI that was stopped before it finished is not
        # started again -- the batches it finished are kept, and this build does what is left (and what changed since)
        $carry = Test-SICiCarryOn -State $state -Fingerprint $fingerprint -PostContract $postContract -FullBuild $fullBuild -FullPost ([bool]$full) -Force:([bool]$FullReconcile)
        $carryOn = [bool]$carry.CarryOn
        if ($carryOn -and $ReturnCis -and $PSVersionTable.PSVersion.Major -lt 6) { $carryOn = $false }
        # the identity ledger's anchors written since the last build started (a new or re-pointed anchor can move a CI id)
        $since = [string]$state['LastBuildStart']
        $lchg = [pscustomobject]@{ Keys = @(); CiIds = @() }
        if ((-not $fullBuild -or $carryOn) -and $since) {
            try {
                if ([string]$prov.Kind -eq 'sql') {
                    $lchg = ConvertTo-SICiLedgerChanges -Rows @(Invoke-SIObjectLedgerSql -Connection $prov.Connection -Sql (Get-SICiLedgerChangedSql) -Params @{ sinceText = $since })
                } else {
                    $sinceT = ConvertTo-SIUtcOrNull $since
                    $lchg = ConvertTo-SICiLedgerChanges -Rows @(foreach ($lk in @($whole.Ledger.Keys)) {
                            $le = $whole.Ledger[$lk]
                            $fs = $null; if ($le -and $le.FirstSeen) { $fs = ConvertTo-SIUtcOrNull $le.FirstSeen }
                            if ($fs -and $sinceT -and $fs -gt $sinceT.AddSeconds(1)) { $ix = ([string]$lk).IndexOf('|'); if ($ix -gt 0) { [pscustomobject]@{ T = ([string]$lk).Substring(0, $ix); V = ([string]$lk).Substring($ix + 1); C = [string]$le.CorrelationId } } }
                        })
                }
            } catch { & $Log 'WARN' ("CIs: the identity ledger's changes since the last build could not be read ({0}) -- this build is full." -f $_.Exception.Message); $fullBuild = $true; $carryOn = $false; $reasons.Add('the identity ledger''s changes could not be read') }
        }
        if ($carry.Stopped -and -not $carryOn -and $carry.Why) { & $Log 'INFO' ("CIs: the previous build was stopped before it finished, and {0} -- this build starts again with every CI." -f $carry.Why) }
        # every group is read and built (a full build that does not carry on); else only the dirty ones
        $buildAll = ($fullBuild -and -not $carryOn)
        # a full build keeps every batch it finishes (their records' built marks, at once): stopped later, it is carried on.
        # Only with the identity ledger in SQL, which is written with every batch -- a blob ledger is written once, at the
        # end, so a stopped build's new ids are not remembered and its batches must not count as finished.
        $markBatches = ($fullBuild -and -not $DryRun -and [bool]$fingerprint -and [string]$prov.Kind -eq 'sql')
        & $mark 'prepare'

        # #534 the DIRTY groups, in SQL (every build: a full build compares what it rebuilds with what an incremental one would)
        # the owning CMDB's lookup keys and the hash of the item behind each, compared in SQL with the last build's
        # (#639: staged in chunks and compared in SQL -- the CMDB's keys are already in the stage when it was read a page at a
        # time; a test's index in hand is staged here. Without the stage, one parameter as before.)
        $cmdbKeys = @()
        if ($null -ne $CmdbIndex) { $cmdbKeys = @(Get-SICiCmdbKeyHashes -Index $CmdbIndex) }
        # #496 the business services ride the same mechanism: a changed link, service or service model rule dirties only the
        # CIs that used it (their refs are written with the CMDB refs, Get-SICiCmdbRefKeys)
        $cmdbKeys = @(@($cmdbKeys) + @(Get-SICiServiceKeyHashes -Index $ServiceIndex))
        if ($hasStage) {
            foreach ($ckr in $cmdbKeys) { $ckWriter.Add([string]$ckr.k, [string]$ckr.h, $null) }
            $ckWriter.Flush()
            $cmdbKeys = $null; $cmdbStaged = $true
        } else {
            $cmdbKeysJson = ConvertTo-SIJsonArray $cmdbKeys -Depth 3; $cmdbKeys = $null
        }
        $dirty = $null; $batchDirty = @{}; $batchGroups = @{}
        $global:SISqlLastRead = $null
        $dg = @(& $sql (Get-SICiDirtySql -LookbackDays $LookbackDays -Thresholds $thresholds -CmdbStaged:$cmdbStaged) @{ nowText = $now.ToString('o'); sinceText = $since; lk = (ConvertTo-SIJsonArray @($lchg.Keys)); lc = (ConvertTo-SIJsonArray @($lchg.CiIds)); ck = $cmdbKeysJson; ckOn = $(if ($cmdbCompare) { '1' } else { '0' }); carry = $(if ($carryOn) { '1' } else { '0' }) } 'rows')
        foreach ($dr in $dg) {
            $kind = [string](Get-SIItemValue $dr 'Kind')
            if ($kind -eq 'summary') { $dirty = $dr }
            elseif ($kind -eq 'batch') { $bn = [int](Get-SIItemValue $dr 'BatchNo'); $batchDirty[$bn] = [int](Get-SIItemValue $dr 'DirtyGroups'); $batchGroups[$bn] = [int](Get-SIItemValue $dr 'Groups') }
        }
        if ($null -eq $dirty) { throw ('the dirty-group statement answered no result ({0})' -f (Get-SISqlLastReadText -Answered $dg.Count)) }
        & $mark 'dirty'
        # CARRY ON: say what the stopped build left done, and stamp the groups this build keeps with its own start -- BEFORE
        # the state below moves the start: stopped between the two, the next build still reads the same picture
        $carrySince = $now.ToString('o')
        if (-not $DryRun) { . $holdLock }
        if ($carryOn) {
            if ([string]$state['CarryOnSince']) { $carrySince = [string]$state['CarryOnSince'] } else { $carrySince = $since }
            & $Log 'INFO' (Format-SICiCarryOnLine -Groups ([int](Get-SIItemValue $dirty 'Groups')) -ToBuild ([int](Get-SIItemValue $dirty 'DirtyGroups')) -NotRebuilt ([int](Get-SIItemValue $dirty 'NotRebuilt')) -Since $carrySince)
            if (-not $DryRun) { $null = & $sql (Get-SICiCarryOnKeepSql) @{ nowText = $now.ToString('o') } 'rows' }
        } elseif ($markBatches) {
            & $Log 'INFO' ("CIs: every CI is rebuilt in this build ({0} batch(es)). Each finished batch is kept -- if the build is stopped before the end, the next build carries on with the rest." -f $nBatches)
        }
        # the build is running: a build that never finishes leaves 'running', and the next build is full -- or, when this
        # one rebuilds every CI, carries on with what it is building with (the CarryOn* values, Test-SICiCarryOn)
        $stateRunning = $false
        if (-not $DryRun) {
            $null = & $sql (Get-SICiStateSetSql) @{ j = (ConvertTo-SIJsonArray @([ordered]@{ n = 'LastBuildStatus'; v = 'running' }, [ordered]@{ n = 'LastBuildStart'; v = $now.ToString('o') },
                        [ordered]@{ n = 'CarryOnFingerprint'; v = $(if ($markBatches) { $fingerprint } else { '' }) }, [ordered]@{ n = 'CarryOnPostContract'; v = $postContract },
                        [ordered]@{ n = 'CarryOnFullPost'; v = $(if ($full) { '1' } else { '0' }) }, [ordered]@{ n = 'CarryOnSince'; v = $carrySince })) } 'rows'
            $stateRunning = $true
        }

        # 4. the batches
        $t = [ordered]@{ Cis = 0; Changed = 0; LastSeenOnly = 0; Links = 0; RecordCi = 0; Daily = 0; Anchors = 0; Superseded = 0; PostedFull = 0; PostedSeen = 0; Bytes = [long]0; Minted = 0; Merged = 0; PostFailed = 0; Slim = 0; Resent = 0; Touched = 0; Marked = 0; IdentityLinked = 0; Incomplete = 0; IncompleteKept = 0; IncompleteLeftOut = 0; WrongMergeSplit = 0; Collisions = 0; Duplicates = 0; Trimmed = 0 }
        # #642 the ledger ids this build found holding several objects: split off (proven) and still shared (not proven); the first 20 of each
        $wrongIds = New-Object System.Collections.Generic.List[string]; $collIds = New-Object System.Collections.Generic.List[string]
        # KEEP IT OUT UNTIL FULLY EVALUATED: the records of the CIs the rules' time limit stopped in this build (their built
        # marks are taken off, so the next build takes them up again) and the CIs' names (name and kind) for the build's state
        $heldRecords = New-Object System.Collections.Generic.List[string]
        $heldNames = New-Object System.Collections.Generic.List[string]
        $unknownFactorCounts = @{}
        # #515 the CIs a batch posted in full, marked (PostedHash) by the next batch's write statement
        $pendingMarks = New-Object System.Collections.Generic.List[object]
        $times = [ordered]@{ read = 0.0; core = 0.0; write = 0.0; ledger = 0.0; post = 0.0 }
        $raCis = New-Object System.Collections.Generic.List[object]
        $blobDecisions = New-Object System.Collections.Generic.List[object]; $blobSuperseded = New-Object System.Collections.Generic.List[object]
        $bw = [System.Diagnostics.Stopwatch]::new()
        $step = [Math]::Max(1, [int][Math]::Ceiling($nBatches / 10))
        $disabledPolicy = Get-SIDisabledAssetPolicy; $disabledLeftOut = 0; $scopeLeftOut = 0
        # #534 groups built this run; on a full build, the CIs that changed although their group was clean (a defect)
        $built = 0
        # #493 / #496 the graph: written once before (else this build records no history), the database carries it
        $graphSeeded = ([string]$state['GraphSeeded'] -eq '1'); $graphMissing = $false
        $gt = [ordered]@{ Services = 0; Claims = 0; ServiceChanges = 0; Cis = 0 }
        $idIndex = $null
        # #639 the identity values staged in SQL (once, $idStaged) and the identity CIs built after that (normally none)
        $idStaged = $false; $idLate = New-Object System.Collections.Generic.List[object]
        $mismatch = New-Object System.Collections.Generic.List[string]
        # CARRY ON: the batches this build kept as finished; said once when Azure adding columns stops that
        $batchesKept = 0; $marksOff = $false
        # A BUILD THAT STANDS STILL SAYS WHERE (2026-10-12: a first run went silent for 68 minutes in the middle of its
        # batches, and the log could not say in which batch or step). Every batch says when it starts and when its CIs
        # are about to be built; every other step says that it starts when this loop has said nothing for two minutes.
        $said = @{ At = [datetime]::UtcNow }
        $sayStep = {
            param([string]$What)
            if (([datetime]::UtcNow - $said.At).TotalSeconds -ge 120) { & $Log 'INFO' ("CIs: batch {0} of {1} -- {2}" -f $b, $nBatches, $What); $said.At = [datetime]::UtcNow }
        }
        $ciWatch = Start-SICiWatch
        for ($b = 1; $b -le $nBatches; $b++) {
            # an incremental build -- and a build that carries on a stopped rebuild -- reads only the batches that hold a
            # dirty group, and of them only the dirty groups. In batch order: the identity batches first, and the batches a
            # stopped build finished hold nothing to read, so what is left is done first.
            if (-not $buildAll -and -not ($batchDirty[$b] -gt 0)) { continue }
            $bw.Restart()
            & $Log 'INFO' ("CIs: batch {0} of {1} started -- reading its records ({2} CI(s) built so far)" -f $b, $nBatches, $t.Cis); $said.At = [datetime]::UtcNow
            $batchRows = @(& $sql (Get-SICiBatchSql) @{ b = [string]$b; only = $(if ($buildAll) { '0' } else { '1' }) } 'rows')
            $dirtyRec = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            foreach ($row in $batchRows) { if ($null -ne $row -and [bool](Get-SIItemValue $row 'Dirty')) { [void]$dirtyRec.Add([string](Get-SIItemValue $row 'RecordKey')) } }
            $bg = ConvertTo-SICiBatchGroups -Rows $batchRows -Types $types
            # #533 (b): disabled accounts and devices left out by SI_DisabledAssets_Correlate (counted, said once below)
            $bgDis = Select-SICiGroupsEnabled -Groups @($bg.Groups) -Policy $disabledPolicy
            $disabledLeftOut += $bgDis.Count
            # CIs follow the collection scope (counted, said once below)
            $bgScope = Select-SICiGroupsInScope -Groups @($bgDis.Kept); $scopeLeftOut += $bgScope.Count
            $bg = [pscustomobject]@{ Groups = @($bgScope.Kept); Records = $bg.Records }
            $built += @($bg.Groups).Count
            # #515 what the last build left for these records (read in the same statement): unchanged CIs go slim
            $stored = Get-SICiBatchStored -Rows $batchRows
            $batchRows = $null
            $times.read += $bw.Elapsed.TotalSeconds; $bw.Restart()
            $ledger = $null
            & $sayStep 'looking up the ids its assets already have'
            if ([string]$prov.Kind -eq 'sql') { $ledger = Get-SIObjectLedgerSubset -Connection $prov.Connection -Keys @(Get-SICiGroupLedgerKeys -Groups $bg.Groups) }
            else { $ledger = $whole.Ledger }
            $times.ledger += $bw.Elapsed.TotalSeconds; $bw.Restart()
            # always said: this step works in memory only -- no database and no Azure call shows that it is running
            & $Log 'INFO' ("CIs: batch {0} of {1} -- building {2} CI(s) from {3} record(s)" -f $b, $nBatches, @($bg.Groups).Count, [int]$bg.Records); $said.At = [datetime]::UtcNow
            if ($ciWatch) { $ciWatch.What = ('batch {0} of {1} -- ' -f $b, $nBatches) }
            $core = Invoke-SICiCore -Groups $bg.Groups -FeedLatest $feeds -Ledger $ledger -Model $model -Rules @($Rules) -CmdbIndex $CmdbIndex -Now $now -RunId $RunId -Overrides $ovIdx -ServiceIndex $ServiceIndex -Watch $ciWatch `
                -Lifecycle $lifeSettings -PreviousLifecycle $stored.Lifecycle -ScopeChangedAt $scope.ChangedAt -CmdbLookup $cmdbLookup
            Set-SICiWatchPhase -Watch $ciWatch -Phase 'linking its CIs to their owners and users, and preparing them for the database'
            # KEEP IT OUT UNTIL FULLY EVALUATED (Get-SICiHeld): a CI whose rules took too long got only part of the rules, so
            # nothing of this run's result of it is written, posted, linked or handed on -- $docs are the complete CIs of the
            # batch. One that was evaluated completely before keeps that row and is only SEEN in this run ($held.Kept); a new
            # one is left out ($held.LeftOut). Each is named (the first 50), counted, and built again in the next run.
            $held = Get-SICiHeld -Docs $core.Docs -Incomplete $core.Incomplete -Stored $stored
            $docs = @($held.Docs)
            $t.Minted += $core.Minted; $t.Merged += $core.Merged; $t.Cis += $docs.Count + @($held.Kept).Count
            foreach ($ic in @(@($held.Kept) + @($held.LeftOut))) {
                $t.Incomplete++; if ($ic.Kept) { $t.IncompleteKept++ } else { $t.IncompleteLeftOut++ }
                if ($t.Incomplete -le 50) { $heldNames.Add([string]$ic.Label); & $Log 'INFO' (Format-SICiIncompleteLine -Item $ic -Budget (Get-SICiRulesBudgetSeconds) -Kept ([bool]$ic.Kept)) }
            }
            foreach ($rk in @($held.RecordKeys)) { $heldRecords.Add([string]$rk) }
            # #546 the factors these CIs could not decide (unknown is never a finding -- it is counted)
            try { $null = Add-SICiUnknownFactorCounts -Counts $unknownFactorCounts -Cis $docs } catch { }
            # IDENTITIES BEFORE DEVICES: the identity batches come first (the grouping numbers them so) and are written before
            # this point; a device / resource CI links to the identity CIs its owner and users name, in this run
            $idLinks = $null
            if (@($docs | Where-Object { [string]$_['si_class'] -ne 'identity' } | Select-Object -First 1).Count -gt 0) {
                if ($hasStage) {
                    # #639 the identity CIs go to the stage ONCE (set-based, when the first device / resource batch needs them --
                    # after every identity batch is written); each batch then looks up only the values its CIs name
                    if (-not $idStaged) {
                        $null = & $sql (Get-SICiIdentityStageSql) @{} 'rows'
                        $idStaged = $true
                    }
                    $idKeys = Get-SICiIdentityBatchKeys -Docs $docs
                    $bIdx = $null
                    if (@($idKeys).Count -gt 0) { $bIdx = ConvertTo-SICiIdentityIndex -Rows @(& $sql (Get-SICiIdentityLookupSql) @{ k = (ConvertTo-SIJsonArray @($idKeys)) } 'rows') }
                    else { $bIdx = ConvertTo-SICiIdentityIndex -Rows @() }
                    if ($idLate.Count -gt 0) { $null = ConvertTo-SICiIdentityIndex -Rows $idLate.ToArray() -Into $bIdx }
                    $idLinks = Set-SICiIdentityLinks -Docs $docs -Index $bIdx
                    $bIdx = $null; $idKeys = $null
                } else {
                    if ($null -eq $idIndex) { $idIndex = ConvertTo-SICiIdentityIndex -Rows @(& $sql (Get-SICiIdentityIndexSql) @{} 'rows') }
                    $idLinks = Set-SICiIdentityLinks -Docs $docs -Index $idIndex
                }
                $t.IdentityLinked += [int]$idLinks.Linked
            }
            # an identity CI built after the index was read (it never is: identity batches come first) still links
            if ($null -ne $idIndex) { $null = ConvertTo-SICiIdentityIndex -Rows @(Get-SICiIdentityDocKeys -Docs $docs) -Into $idIndex }
            elseif ($idStaged) { foreach ($lr in @(Get-SICiIdentityDocKeys -Docs $docs)) { $idLate.Add($lr) } }
            $items = ConvertTo-SICiSqlItems -Cis $docs -Stored $stored
            $t.Slim += [int]$items.Unchanged
            # #534 the full reconcile: a CI whose content differs from what was stored although no input of its group changed
            if ($buildAll -and -not $decision.FingerprintChanged) { foreach ($x in @(Get-SICiReconcileMismatch -Items $items.Cis -Docs $docs -DirtyRecords $dirtyRec -Stored $stored)) { $mismatch.Add([string]$x) } }
            # #642 a wrong merge split off, and ids several groups still share (built once from all their records): counted, said once at the end
            $t.WrongMergeSplit += [int]$core.WrongMergeSplit; foreach ($w in @($core.WrongMerges)) { if ($wrongIds.Count -lt 20) { $wrongIds.Add(('{0} -> {1}' -f $w.CorrelationId, $w.NewId)) } }
            foreach ($cc in @($core.Collisions)) { $t.Collisions += [int]$cc.Groups; if ($collIds.Count -lt 20) { $collIds.Add([string]$cc.CiId) } }
            # (Invoke-SICiCore builds one CI per id, so two items for one id is a defect of the build itself -- never data to drop silently)
            if (@($items.Duplicates).Count -gt 0) { $t.Duplicates += @($items.Duplicates).Count; & $Log 'WARN' ("CIs: {0} CI(s) of batch {1} came out twice under one id ({2}) -- a defect of the build: the first is written." -f @($items.Duplicates).Count, $b, ((@($items.Duplicates) | Select-Object -First 3) -join ', ')) }
            # (-ReturnCis is a test seam: no job asks for every CI any more -- Risk Analysis looks its CIs up per slice, #639;
            # the CI workbook reads the CIs back from the database a page at a time after the batches)
            if ($ReturnCis) { foreach ($p in $items.Post) { $raCis.Add($p.Row) } }
            Set-SICiWatchPhase -Watch $ciWatch
            $times.core += $bw.Elapsed.TotalSeconds; $bw.Restart()
            # the batch is finished when everything of it is written and its rows reached SI_CI_CL
            $batchDone = $true
            if (-not $DryRun -and $core.Docs.Count -gt 0) {
                # still the one build that writes (a lost lock stops the build here, before this batch is written)
                . $holdLock
                # the ledger first: a CI is never written under an id the ledger does not hold
                & $sayStep 'its CIs are built; writing their ids'
                if ([string]$prov.Kind -eq 'sql') {
                    $lw = Save-SIObjectLedgerSet -Connection $prov.Connection -Decisions $core.Decisions -Superseded $core.Superseded -Now $now
                    $t.Anchors += [int]$lw.AnchorsWritten; $t.Superseded += [int]$lw.SupersededWritten
                } else {
                    foreach ($d in $core.Decisions) { if ($d.CorrelationId) { $blobDecisions.Add([pscustomobject]@{ CorrelationId = $d.CorrelationId; Action = $d.Action; NewIdentifiers = @($d.NewIdentifiers) }) } }
                    foreach ($s in $core.Superseded) { $blobSuperseded.Add($s) }
                }
                $times.ledger += $bw.Elapsed.TotalSeconds; $bw.Restart()
                # ONE statement: this batch's CIs + the previous batch's posted marks (#515)
                & $sayStep 'writing its CIs to the database'
                # (with them, the slim items of the CIs kept as they were: nothing of them is rewritten, they are seen)
                $w = @(& $sql (Get-SICiWriteSql) @{ j = (ConvertTo-SIJsonArray (@($items.Cis) + @($held.Items)) -Depth 14); l = (ConvertTo-SIJsonArray $items.Links); m = (ConvertTo-SIJsonArray $items.Map); p = (ConvertTo-SIJsonArray $pendingMarks.ToArray()) } 'rows')
                $pendingMarks.Clear()
                $posted = @{}
                $resend = New-Object System.Collections.Generic.List[string]
                $readW = {
                    param($Rows)
                    foreach ($r in $Rows) {
                        $kind = [string](Get-SIItemValue $r 'Kind')
                        if ($kind -eq 'summary') {
                            $t.Changed += [int](Get-SIItemValue $r 'Changed'); $t.LastSeenOnly += [int](Get-SIItemValue $r 'LastSeenOnly'); $t.Links += [int](Get-SIItemValue $r 'Links')
                            $t.RecordCi += [int](Get-SIItemValue $r 'Records'); $t.Daily += [int](Get-SIItemValue $r 'Daily')
                        } elseif ($kind -eq 'resend') { $rid = [string](Get-SIItemValue $r 'CiId'); if (-not $held.KeptIds.Contains($rid)) { $resend.Add($rid) } }
                        else { $posted[[string](Get-SIItemValue $r 'CiId')] = [string](Get-SIItemValue $r 'PostedHash') }
                    }
                }
                & $readW $w
                if ($resend.Count -gt 0) {
                    # a CI sent slim whose stored hash moved after the batch was read: sent whole now (rare)
                    $rs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase); foreach ($x in $resend) { [void]$rs.Add($x) }
                    $whole2 = ConvertTo-SICiSqlItems -Cis @($docs | Where-Object { $rs.Contains([string]$_['si_ci_id']) })
                    $t.Slim -= $resend.Count; $t.Resent += $resend.Count
                    $resend.Clear()
                    & $readW @(& $sql (Get-SICiWriteSql) @{ j = (ConvertTo-SIJsonArray $whole2.Cis -Depth 14); l = (ConvertTo-SIJsonArray $whole2.Links); m = (ConvertTo-SIJsonArray $whole2.Map); p = '[]' } 'rows')
                }
                # the owner / user values the batch's device / resource records named (a dirty identity dirties them next run)
                if ($null -ne $idLinks) { $null = & $sql (Get-SICiIdentityRefWriteSql) @{ rk = (ConvertTo-SIJsonArray @($idLinks.RecordKeys)); r = (ConvertTo-SIJsonArray @($idLinks.Refs)) } 'rows' }
                # the CMDB lookup keys the batch's CIs used (a changed CMDB item dirties exactly those groups next run)
                $cr = Get-SICiCmdbRefs -Docs $docs
                $null = & $sql (Get-SICiCmdbRefWriteSql) @{ rk = (ConvertTo-SIJsonArray @($cr.RecordKeys)); r = (ConvertTo-SIJsonArray @($cr.Refs)) } 'rows'
                # #493 / #496 the graph of the CIs this batch rewrote: their services and relation claims are replaced. A full
                # build replaces every built CI's (a changed relation or service model reaches the unchanged CIs too); an
                # incremental build only the CIs whose content changed (the services and claims are part of the content)
                if (-not $graphMissing) {
                    $only = $null
                    if (-not $fullBuild) {
                        $only = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                        foreach ($ci in @($items.Cis)) { if ($null -ne $ci -and $null -ne $ci['DocJson']) { [void]$only.Add([string]$ci['CiId']) } }
                    }
                    $gi = ConvertTo-SICiGraphItems -Docs $docs -Rules $relRules -Only $only
                    if (@($gi.CiIds).Count -gt 0) {
                        $gw = @(& $sql (Get-SICiGraphWriteSql) @{ ids = (ConvertTo-SIJsonArray @($gi.CiIds)); s = (ConvertTo-SIJsonArray @($gi.Services)); c = (ConvertTo-SIJsonArray @($gi.Claims))
                                                                 now = $now.ToString('o'); seeded = $(if ($graphSeeded) { '1' } else { '0' }); run = $RunId } 'rows') | Select-Object -First 1
                        if ($gw -and [int](Get-SIItemValue $gw 'Skipped') -eq 1) {
                            $graphMissing = $true
                            & $Log 'INFO' 'CIs: the services and relations of the CIs were not written -- the database is not updated yet (run the updater).'
                        } elseif ($gw) {
                            $gt.Services += [int](Get-SIItemValue $gw 'Services'); $gt.Claims += [int](Get-SIItemValue $gw 'Claims'); $gt.ServiceChanges += [int](Get-SIItemValue $gw 'ServiceChanges'); $gt.Cis += @($gi.CiIds).Count
                        }
                    }
                }
                $times.write += $bw.Elapsed.TotalSeconds; $bw.Restart()
                # SI_CI_CL: every CI's slim seen row + the full rows whose posted content changed (all of them on a full refresh)
                $sel = @(Select-SICiPostRows -Post $items.Post -PostedHash $posted -Full:$full)
                $rows = New-Object System.Collections.Generic.List[object]
                foreach ($p in $items.Post) { $rows.Add($p.Seen) }
                foreach ($p in $sel) { $rows.Add($p.Row) }
                # the CIs kept as they were: SEEN in this run (the slim row, with the hash of the full row SI_CI_CL already
                # holds) -- Risk Analysis and the views read them from their last complete evaluation, and none looks gone.
                # Their stored document is handed on where the build hands every CI on, and posted again as it is when every
                # CI's full row is posted in this build (so it stays within what Risk Analysis looks back on).
                $keptSeen = 0
                if (@($held.Kept).Count -gt 0) {
                    $keptDocs = @{}
                    try {
                        foreach ($dr in @(& $sql (Get-SICiHeldDocSql) @{ ids = (ConvertTo-SIJsonArray @(@($held.Kept) | ForEach-Object { [string]$_.CiId })) } 'rows')) {
                            $js = [string](Get-SIItemValue $dr 'DocJson'); if (-not $js) { continue }
                            $h = $null; try { $h = ConvertFrom-Json -InputObject $js -AsHashtable } catch { continue }
                            if ($null -ne $h) { $keptDocs[[string](Get-SIItemValue $dr 'CiId')] = $h }
                        }
                    } catch { & $Log 'INFO' ("CIs: the stored result of {0} CI(s) kept from their last complete evaluation could not be read back ({1}) -- they are still kept and seen." -f @($held.Kept).Count, $_.Exception.Message) }
                    foreach ($k in @($held.Kept)) {
                        $ph = [string]$posted[[string]$k.CiId]
                        if ($ph) { $rows.Add([pscustomobject][ordered]@{ si_ci_id = [string]$k.CiId; si_row_kind = 'seen'; si_collection_time = $k.CollectionTime; si_content_hash = $ph; si_last_seen = $k.LastSeen }); $keptSeen++ }
                        $h = $keptDocs[[string]$k.CiId]
                        if ($null -eq $h) { continue }
                        $h['si_collection_time'] = $now.ToUniversalTime()
                        if ($null -ne $k.LastSeenValue) { $h['si_last_seen'] = $k.LastSeenValue }
                        if ($ReturnCis -or ($full -and $ph)) {
                            $pr = ConvertTo-SICiPostRow -Ci $h
                            $pr | Add-Member -NotePropertyName 'si_row_kind' -NotePropertyValue 'full'
                            $pr | Add-Member -NotePropertyName 'si_content_hash' -NotePropertyValue (Get-SIContentHash -Item $pr -Exclude @('si_collection_time', 'si_last_seen', 'si_row_kind'))
                            if ($ReturnCis) { $raCis.Add($pr) }
                            if ($full -and $ph) { $rows.Add($pr) }
                        }
                    }
                }
                # one CI too large for a Log Analytics post never fails its batch: each FULL row (the slim seen rows are a few
                # fields) is measured and, over the post's limit, cut where it is largest (Limit-SICiPostRowSize) -- said
                # once per CI with its size; a row that still does not fit is left out of the post and said, the rest go
                $ciCompress = ($null -ne $global:EnableCompressionDefault -and [bool]$global:EnableCompressionDefault)
                for ($ri = $rows.Count - 1; $ri -ge 0; $ri--) {
                    $rw = $rows[$ri]
                    if ($rw.PSObject.Properties['si_row_kind'] -and [string]$rw.si_row_kind -eq 'seen') { continue }
                    $lim = Limit-SICiPostRowSize -Row $rw -Compressed $ciCompress
                    if (-not $lim.Trimmed) { continue }
                    $t.Trimmed = [int]$t.Trimmed + 1
                    if ($lim.Fits) {
                        $rows[$ri] = $lim.Row
                        & $Log 'INFO' ("CIs: CI {0} was {1:N0} bytes, over the limit of one Log Analytics post -- it is sent to SI_CI_CL cut to {2:N0} bytes ({3}); the database keeps the whole CI." -f [string]$rw.si_ci_id, $lim.OriginalBytes, $lim.Bytes, ($lim.Fields -join '; '))
                    } else {
                        $rows.RemoveAt($ri)
                        & $Log 'WARN' ("CIs: CI {0} ({1:N0} bytes) does not fit one Log Analytics post even with its lists cut, so it is not sent to SI_CI_CL in this build; the database keeps the whole CI, and every other row of the batch is sent." -f [string]$rw.si_ci_id, $lim.OriginalBytes)
                    }
                }
                # the payload size, measured once per batch (#515: one serialisation per row cost as much as the post itself)
                if ($rows.Count -gt 0) { $t.Bytes += (ConvertTo-Json -InputObject $rows.ToArray() -Compress -Depth 8).Length }
                $sent = 0
                & $sayStep ('sending {0} row(s) to SI_CI_CL' -f $rows.Count)
                try {
                    if ($Post) { $sent = [int](& $Post $rows.ToArray()) }
                    else { $sent = [int](Send-SIObjectMapRows -Rows $rows.ToArray() -TableName 'SI_CI' -DcrName $(if ($global:SI_CI_DcrName) { [string]$global:SI_CI_DcrName } else { 'dcr-si-ci' })) }
                } catch { & $Log 'WARN' ("CIs: batch {0}'s rows could not be posted to SI_CI_CL -- {1}. They are posted again on the next build." -f $b, $_.Exception.Message); $sent = 0 }
                if ($sent -ge $rows.Count) {
                    $t.PostedSeen += $items.Post.Count + $keptSeen; $t.PostedFull += $sel.Count
                    # marked by the NEXT batch's write statement (one round trip per batch); the last batch's after the loop
                    foreach ($x in $sel) { $pendingMarks.Add([ordered]@{ CiId = $x.CiId; Hash = $x.Hash }) }
                } else { $t.PostFailed++; $batchDone = $false }
                $times.post += $bw.Elapsed.TotalSeconds; $bw.Restart()
            }
            # CARRY ON: a finished batch of a build that rebuilds every CI is kept at once -- its records remember what they
            # were built from (the same marks the end of the build writes), so a build that is stopped later is carried on
            # from here. Not while Azure is adding columns to SI_CI_CL in this run: a full row posted then can
            # lack their values, so those batches are built (and posted) again.
            if ($markBatches -and $batchDone) {
                if (Test-SICiPostGainedColumns) {
                    if (-not $marksOff) { $marksOff = $true; & $Log 'INFO' 'CIs: SI_CI_CL gained columns in this build, so its batches are not kept as finished -- if this build is stopped, the next one starts again with every CI.' }
                } else {
                    # with the batch's posted marks (else they ride in the next batch's write): a kept batch leaves nothing open
                    & $sayStep 'its rows are sent; keeping the batch as finished'
                    # (not the records of a CI kept out until it is fully evaluated: @h takes their marks off again)
                    $null = & $sql (Get-SICiMarkBatchBuiltSql -Thresholds $thresholds) @{ nowText = $now.ToString('o'); all = $(if ($buildAll) { '1' } else { '0' }); b = [string]$b
                                                                                         p = (ConvertTo-SIJsonArray $pendingMarks.ToArray()); h = (ConvertTo-SIJsonArray @($held.RecordKeys)) } 'rows'
                    $pendingMarks.Clear()
                    $batchesKept++
                }
                $times.write += $bw.Elapsed.TotalSeconds; $bw.Restart()
            }
            if ($b -eq $nBatches -or ($b % $step) -eq 0) {
                & $Log 'INFO' ("CIs: batch {0} of {1} -- {2} CI(s) built so far, {3} changed ({4:N0} s)" -f $b, $nBatches, $t.Cis, $t.Changed, ($times.read + $times.ledger + $times.core + $times.write + $times.post))
            }
        }
        # the batches are done: the watch ends here (a build that fails ends it where the failure is caught)
        Stop-SICiWatch -Watch $ciWatch; $ciWatch = $null
        if ($disabledLeftOut -gt 0) { & $Log 'INFO' (Format-SIDisabledStageLine -Stage Correlate -Count $disabledLeftOut -Where 'CI correlation') }
        if ($scopeLeftOut -gt 0) { & $Log 'INFO' (Format-SICiScopeLine -Count $scopeLeftOut) }
        if ($t.Incomplete -gt 0) { & $Log 'WARN' (Format-SICiIncompleteSummary -Count $t.Incomplete -Kept $t.IncompleteKept -LeftOut $t.IncompleteLeftOut -Budget (Get-SICiRulesBudgetSeconds)) }
        # the last batch's posted marks (the only separate mark statement of the build)
        if (-not $DryRun -and $pendingMarks.Count -gt 0) {
            $bw.Restart()
            $null = & $sql (Get-SICiMarkPostedSql) @{ p = (ConvertTo-SIJsonArray $pendingMarks.ToArray()) } 'scalar'
            $pendingMarks.Clear()
            $times.post += $bw.Elapsed.TotalSeconds
        }
        $workSeconds = $times.read + $times.ledger + $times.core + $times.write + $times.post
        # the end of the build writes too (the unchanged CIs' seen marks, the relations, the retired CIs, the build's state)
        if (-not $DryRun) { . $holdLock }

        # #534 the CIs of the CLEAN groups (incremental): their collection time and today's trend row in ONE statement, and
        # the slim SI_CI_CL 'seen' row every CI gets every build (#515) -- nothing else of them changes (rule 4)
        $skippedCis = 0; $seenPages = 0; $seenHeldMax = 0
        if (-not $buildAll -and -not $DryRun -and $hasStage) {
            # #639 the clean CIs go to the stage in the same statement that moves their collection time; their slim rows are
            # then read and posted a PAGE at a time (keyset on the CI id) -- never every clean CI of the tenant at once
            $bw.Restart()
            $utcNow = ConvertTo-SILogValue $now
            $ss = @(& $sql (Get-SICiSeenSql -Stage) @{ nowText = $now.ToString('o') } 'rows') | Select-Object -First 1
            if ($null -eq $ss) { throw ('the statement that marks the unchanged CIs seen answered no result ({0})' -f (Get-SISqlLastReadText -Answered 0)) }
            $t.Touched += [int](Get-SIItemValue $ss 'Touched'); $t.Daily += [int](Get-SIItemValue $ss 'Daily')
            $times.write += $bw.Elapsed.TotalSeconds; $bw.Restart()
            $seenPage = [Math]::Max(1, $PageRows); $after = ''
            while ($true) {
                $pr = @(& $sql (Get-SICiSeenPageSql) @{ after = $after; n = [string]$seenPage } 'rows')
                if ($pr.Count -eq 0) { break }
                $chunk = New-Object 'object[]' $pr.Count
                for ($i = 0; $i -lt $pr.Count; $i++) {
                    $sr = $pr[$i]
                    $ls = Get-SIItemValue $sr 'LastSeen'
                    if ($ls -is [datetime]) { $ls = [datetime]::SpecifyKind($ls, [DateTimeKind]::Utc) }
                    $chunk[$i] = [pscustomobject][ordered]@{ si_ci_id = [string](Get-SIItemValue $sr 'CiId'); si_row_kind = 'seen'; si_collection_time = $utcNow
                        si_content_hash = [string](Get-SIItemValue $sr 'PostHash'); si_last_seen = (ConvertTo-SILogValue $ls) }
                }
                $after = [string](Get-SIItemValue $pr[$pr.Count - 1] 'CiId')
                $last = $pr.Count -lt $seenPage
                $pr = $null
                $seenPages++; if ($chunk.Count -gt $seenHeldMax) { $seenHeldMax = $chunk.Count }
                $skippedCis += $chunk.Count
                $t.Bytes += (ConvertTo-Json -InputObject $chunk -Compress -Depth 4).Length
                $sent = 0
                try {
                    if ($Post) { $sent = [int](& $Post $chunk) }
                    else { $sent = [int](Send-SIObjectMapRows -Rows $chunk -TableName 'SI_CI' -DcrName $(if ($global:SI_CI_DcrName) { [string]$global:SI_CI_DcrName } else { 'dcr-si-ci' })) }
                } catch { & $Log 'WARN' ("CIs: the seen rows of the unchanged CIs could not be posted to SI_CI_CL -- {0}. They are posted again on the next build." -f $_.Exception.Message); $sent = 0 }
                if ($sent -ge $chunk.Count) { $t.PostedSeen += $chunk.Count } else { $t.PostFailed++ }
                $chunk = $null
                if ($last) { break }
            }
            $t.Cis += $skippedCis; $t.Slim += $skippedCis
            $times.post += $bw.Elapsed.TotalSeconds
        } elseif (-not $buildAll -and -not $DryRun) {
            $bw.Restart()
            $seenRows = New-Object System.Collections.Generic.List[object]
            $utcNow = ConvertTo-SILogValue $now
            foreach ($sr in @(& $sql (Get-SICiSeenSql) @{ nowText = $now.ToString('o') } 'rows')) {
                $kind = [string](Get-SIItemValue $sr 'Kind')
                if ($kind -eq 'summary') { $t.Touched += [int](Get-SIItemValue $sr 'Touched'); $t.Daily += [int](Get-SIItemValue $sr 'Daily'); continue }
                if ($kind -ne 'seen') { continue }
                $ls = Get-SIItemValue $sr 'LastSeen'
                if ($ls -is [datetime]) { $ls = [datetime]::SpecifyKind($ls, [DateTimeKind]::Utc) }
                $seenRows.Add([pscustomobject][ordered]@{ si_ci_id = [string](Get-SIItemValue $sr 'CiId'); si_row_kind = 'seen'; si_collection_time = $utcNow
                        si_content_hash = [string](Get-SIItemValue $sr 'PostHash'); si_last_seen = (ConvertTo-SILogValue $ls) })
            }
            $skippedCis = $seenRows.Count
            $t.Cis += $skippedCis; $t.Slim += $skippedCis
            $times.write += $bw.Elapsed.TotalSeconds; $bw.Restart()
            for ($i = 0; $i -lt $seenRows.Count; $i += 5000) {
                $chunk = $seenRows.GetRange($i, [Math]::Min(5000, $seenRows.Count - $i)).ToArray()
                $t.Bytes += (ConvertTo-Json -InputObject $chunk -Compress -Depth 4).Length
                $sent = 0
                try {
                    if ($Post) { $sent = [int](& $Post $chunk) }
                    else { $sent = [int](Send-SIObjectMapRows -Rows $chunk -TableName 'SI_CI' -DcrName $(if ($global:SI_CI_DcrName) { [string]$global:SI_CI_DcrName } else { 'dcr-si-ci' })) }
                } catch { & $Log 'WARN' ("CIs: the seen rows of the unchanged CIs could not be posted to SI_CI_CL -- {0}. They are posted again on the next build." -f $_.Exception.Message); $sent = 0 }
                if ($sent -ge $chunk.Count) { $t.PostedSeen += $chunk.Count } else { $t.PostFailed++ }
            }
            $times.post += $bw.Elapsed.TotalSeconds
        }

        # #534 a skipped CI handed on as the last build wrote it: only the -ReturnCis test seam (every CI's SI_CI_CL row). The CI
        # workbook reads every CI of the build back from the database a page at a time below (#639).
        $wbWanted = (-not $DryRun -and $WorkbookMaxCis -gt 0 -and -not ($global:SI_CiWorkbook -and ([string]$global:SI_CiWorkbook).Trim().ToLowerInvariant() -in 'off', 'false', '0'))
        if (-not $buildAll -and $ReturnCis) {
            $bw.Restart()
            for ($b = 1; $b -le $nBatches; $b++) {
                if (-not ($batchGroups[$b] -gt $batchDirty[$b])) { continue }
                foreach ($dr in @(& $sql (Get-SICiCleanDocSql) @{ b = [string]$b } 'rows')) {
                    $js = [string](Get-SIItemValue $dr 'DocJson'); if (-not $js) { continue }
                    $h = $null; try { $h = ConvertFrom-Json -InputObject $js -AsHashtable } catch { continue }
                    if ($null -eq $h) { continue }
                    $h['si_collection_time'] = $now.ToUniversalTime()
                    if ($ReturnCis) {
                        $pr = ConvertTo-SICiPostRow -Ci $h
                        $pr | Add-Member -NotePropertyName 'si_row_kind' -NotePropertyValue 'full'
                        $pr | Add-Member -NotePropertyName 'si_content_hash' -NotePropertyValue (Get-SIContentHash -Item $pr -Exclude @('si_collection_time', 'si_last_seen', 'si_row_kind'))
                        $raCis.Add($pr)
                    }
                }
            }
            $times.read += $bw.Elapsed.TotalSeconds
        }
        foreach ($k in $times.Keys) { $phase[$k] = [Math]::Round($times[$k], 1) }
        $sw.Restart()
        if (-not $DryRun -and [string]$prov.Kind -ne 'sql' -and $blobDecisions.Count -gt 0) {
            $lw = Write-SIObjectLedger -Provider $prov -Decisions $blobDecisions.ToArray() -Superseded $blobSuperseded.ToArray() -Now $now -IfMatchETag $whole.ETag -CurrentLedger $whole.Ledger
            if ($lw) { $t.Anchors += [int]$lw.AnchorsWritten; $t.Superseded += [int]$lw.SupersededWritten }
        }
        try { Close-SIObjectLedgerProvider -Provider $prov } catch { }
        # #493 the relations: the claims resolved into sidata.CiRelation (both ways), the changes posted to SI_CIRelation_CL
        # (every active relation with the weekly full refresh, or when the last post did not land)
        $rel = $null
        if (-not $DryRun -and -not $graphMissing) {
            $relFull = ($full -or [string]$state['RelationFullPostDue'] -eq '1')
            $relArgs = @{ Sql = $sql; Now = $now; Full = [bool]$relFull; Seeded = [bool]$graphSeeded; RunId = $RunId; Log = $Log }
            if ($PostRelations) { $relArgs['Post'] = $PostRelations } elseif ($Post) { $relArgs['NoPost'] = $true }
            $rel = Invoke-SICiRelationStep @relArgs
            # #639 the relations not updated, or not all posted, is a build issue -- never only a WARN line
            if ($null -ne $rel -and -not $rel.Skipped -and ([string]$rel.Error -or $rel.PostFailed)) {
                $why = if ([string]$rel.Error) { [string]$rel.Error } else { 'not every relation reached SI_CIRelation_CL' }
                $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the relations between CIs were not updated in full this build ({0}) -- every CI is built; the next build tries again' -f $why) })
            }
            if ($gt.Cis -gt 0) { & $Log 'INFO' ("CIs: services and relation claims written for {0} CI(s) -- {1} service membership(s), {2} claim(s), {3} membership change(s) recorded" -f $gt.Cis, $gt.Services, $gt.Claims, $gt.ServiceChanges) }
        }

        # the CIs no current record builds any more (records aged out of the lookback, or none at all) are RETIRED once unseen
        # longer than the retire brake -- never deleted; recorded again, they are rebuilt active (Get-SICiRetireSql)
        $retired = $null
        if (-not $DryRun) {
            try {
                $retired = @(& $sql (Get-SICiRetireSql -FloorDays (Get-SICiRetireDays)) @{ run = [string]$RunId } 'rows') | Select-Object -First 1
                if ($retired -and [int](Get-SIItemValue $retired 'Retired') -gt 0) {
                    & $Log 'INFO' ("CIs: {0} CI(s) retired -- no source records them any more (not seen for longer than {1} day(s){2}); retired, never deleted -- recorded again, a CI is active again." -f [int](Get-SIItemValue $retired 'Retired'), (Get-SICiRetireDays), $(if ([int](Get-SIItemValue $retired 'Orphans') -gt 0) { ('; {0} of them had no record at all' -f [int](Get-SIItemValue $retired 'Orphans')) } else { '' }))
                }
            } catch {
                & $Log 'WARN' ("CIs: the CIs no source records any more could not be retired this build ({0}) -- tried again on the next build." -f $_.Exception.Message)
                $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the CIs no source records any more were not retired this build ({0}) -- every CI is stored; they are retired by the next build' -f $_.Exception.Message) })
            }
        }

        # THE CI VIEWS' STORED COLUMNS ARE CURRENT WHEN THE BUILD ENDS (Pro): the columns the web app's CI views filter and
        # sort on are filled from the documents of the CIs this build changed -- set-based, in batches, still inside the
        # build's lock. Until now only the data sync did it, so the views read those CIs from their document from here to
        # the next data sync. The fill lives with the data sync (engine\pro-data, not part of the free edition): it is
        # loaded only when it is there, and it never fails the build.
        $viewColumns = $null
        if (-not $DryRun) {
            try {
                $fillScript = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'pro-data', '_shared', 'SI-DataCi.ps1')
                if (-not (Get-Command -Name Invoke-SIDataCiStoredColumns -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $fillScript)) { . $fillScript }
                if (Get-Command -Name Invoke-SIDataCiStoredColumns -ErrorAction SilentlyContinue) { $viewColumns = Invoke-SIDataCiStoredColumns -Invoke $sql -Log $Log }
            # INFO, never WARN: a warning of the build is an alert, and the build and its CIs are fine -- the data sync fills them
            } catch { & $Log 'INFO' ("CIs: the columns the CI views read were not filled at the end of this build ({0}) -- the data sync fills them." -f $_.Exception.Message) }
        }

        # #534 the records of the built groups remember what they were built from; the build's state. A build whose rows did
        # not all reach SI_CI_CL is 'partial' -- the next build is full.
        if (-not $DryRun) {
            # (@h: the records of the CIs kept out until they are fully evaluated lose their marks -- the next build, whatever
            # kind it is, finds their groups changed and builds them again with every rule)
            $mk = @(& $sql (Get-SICiMarkBuiltSql -Thresholds $thresholds) @{ nowText = $now.ToString('o'); all = $(if ($buildAll) { '1' } else { '0' }); h = (ConvertTo-SIJsonArray $heldRecords.ToArray()) } 'rows')
            if ($mk.Count -gt 0) { $t.Marked = [int](Get-SIItemValue $mk[0] 'Marked') }
            $sv = New-Object System.Collections.Generic.List[object]
            $sv.Add([ordered]@{ n = 'LastBuildStatus'; v = $(if ($t.PostFailed -eq 0) { 'ok' } else { 'partial' }) })
            if ($fingerprint) { $sv.Add([ordered]@{ n = 'BuildFingerprint'; v = $fingerprint }) }
            if ($fullBuild) { $sv.Add([ordered]@{ n = 'LastFullBuild'; v = $now.ToString('o') }) }
            # (a build that carried on compared nothing: the count of the last whole reconcile stays)
            if ($buildAll) { $sv.Add([ordered]@{ n = 'LastReconcileCorrected'; v = [string]$mismatch.Count }) }
            # the CIs this build could not fully evaluate (0 when there is none): what the web app and support read to say
            # "N asset(s) not fully evaluated in the last run", with their names (name and kind, the first of them)
            $sv.Add([ordered]@{ n = 'NotFullyEvaluated'; v = [string]$t.Incomplete })
            $sv.Add([ordered]@{ n = 'NotFullyEvaluatedCis'; v = (Format-SICiIncompleteNames -Labels $heldNames.ToArray() -Total $t.Incomplete) })
            # #642 the run record of the identity ledger's wrong merges: split off in this build, and ids groups still share
            $sv.Add([ordered]@{ n = 'WrongMergesSplit'; v = [string]$t.WrongMergeSplit })
            $sv.Add([ordered]@{ n = 'WrongMergesSplitIds'; v = ($wrongIds.ToArray() -join '; ') })
            $sv.Add([ordered]@{ n = 'SharedIdGroups'; v = [string]$t.Collisions })
            $sv.Add([ordered]@{ n = 'SharedIds'; v = ($collIds.ToArray() -join '; ') })
            # the build finished: there is nothing to carry on
            $sv.Add([ordered]@{ n = 'CarryOnFingerprint'; v = '' })
            if ($full -and $t.PostFailed -eq 0) { $sv.Add([ordered]@{ n = 'LastFullPost'; v = $now.ToString('o') }) }
            # the column contract the posted rows are complete for: kept when this build posted into no NEW column; a build
            # that added columns to SI_CI_CL clears it, so the next build posts every full row again (into stored columns)
            $gained = Test-SICiPostGainedColumns
            if ($gained) { $sv.Add([ordered]@{ n = 'PostContract'; v = '' }); & $Log 'INFO' 'CIs: SI_CI_CL gained columns in this build -- the next build posts every CI''s full row again, so the values Azure was not yet storing arrive.' }
            elseif ($t.PostFailed -eq 0 -and ($full -or [string]$state['PostContract'] -eq $postContract)) { $sv.Add([ordered]@{ n = 'PostContract'; v = $postContract }) }
            # #493 / #496 the graph is written from now on (history is recorded); the relations' post landed or is due again
            if (-not $graphMissing -and $gt.Cis -gt 0) { $sv.Add([ordered]@{ n = 'GraphSeeded'; v = '1' }) }
            if ($null -ne $rel -and -not $rel.Skipped) { $sv.Add([ordered]@{ n = 'RelationFullPostDue'; v = $(if ($rel.PostFailed) { '1' } else { '0' }) }) }
            $null = & $sql (Get-SICiStateSetSql) @{ j = (ConvertTo-SIJsonArray $sv.ToArray()) } 'rows'
            $stateRunning = $false
            # the owning CMDB as this build saw it (the next build compares its items with these) -- not when it could not be
            # read (#639: the next build compares with the last CMDB that was read, never with an empty one)
            if ($cmdbCompare) {
                if ($cmdbStaged) { $null = & $sql (Get-SICiCmdbKeySaveSql -FromStage) @{} 'rows' }
                else { $null = & $sql (Get-SICiCmdbKeySaveSql) @{ ck = $cmdbKeysJson } 'rows' }
            }
        }
        & $mark 'finish'

        # #534 the run log: incremental or full, groups built / skipped, why a full ran -- and what the full reconcile corrected
        & $Log 'INFO' (Format-SICiBuildModeLine -Full $fullBuild -Reasons $reasons.ToArray() -Groups $nGroups -Built $built -Dirty $dirty -WorkSeconds $workSeconds)
        if ($fullBuild) {
            if ($carryOn) {
                & $Log 'INFO' ("CIs: the rebuild of every CI that a stopped build started is complete -- {0} CI(s) changed in this build." -f $t.Changed)
            } elseif ($decision.FingerprintChanged) {
                & $Log 'INFO' ("CIs: what the CIs are built from changed -- every CI was rebuilt; {0} of them changed." -f $t.Changed)
            } elseif ($mismatch.Count -gt 0) {
                # owner 2026-10-10: "no need to send alerts, if full reconcile fixes things" -- one plain INFO line (the count is
                # also kept in sidata.CiBuildState LastReconcileCorrected); it never changes the run outcome
                & $Log 'INFO' ("CIs: the weekly full rebuild brought {0} CI(s) up to date (first: {1})." -f $mismatch.Count, ((@($mismatch) | Select-Object -First 5) -join ', '))
            } else {
                & $Log 'INFO' 'CIs: the full reconcile found every CI as the incremental builds left it -- nothing to correct.'
            }
        }

        # the CI workbook (Excel) through its output map in force (data-model/outputs/excel-ci + the customer's column
        # changes) -- a listed data-out connector (config/data-out.locked.json, data-out-excel-ci): its run and each CI
        # written, changed (column before / now) or no longer in it are recorded. Never fails the build.
        # #639 EVERY CI OF THE BUILD, NO CAP, A PAGE AT A TIME: the CIs are read back from the database in id pages, each page
        # pulled by the writer through its -Cursor (Write-SICiWorkbook); the build holds no CI document for the workbook. (What
        # the writer keeps across pages is the data-out writer's, engine\data-out\SI-DataOut.ps1.) Live 2026-10-22: the call
        # passed -ReadPages, a parameter the writer no longer had -- the workbook was never written.
        $wbRead = 0L
        if ($wbWanted -and $t.Cis -gt 0) {
            try {
                if (-not (Get-Command -Name Invoke-SIDataOutWriter -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-out', 'SI-DataOut.ps1')) }
                $wbCatalog = Get-SIDataOutCatalog   # one list (return , @()): filter the variable, never the call's pipeline
                $wbEntry = @($wbCatalog | Where-Object { [string]$_.output -eq 'excel-ci' })[0]
                $wbStore = $null; try { $wbStore = New-SIConnectorRegistryStore } catch { }
                # SI_DisabledAssets_Connectors (the workbook is data out): a disabled account's CI is left out of it, frozen
                $wbInclude = [bool](Test-SIDisabledIncluded -Stage Connectors -Policy $disabledPolicy)
                $wb = Write-SICiWorkbook -Sql $sql -Now $now -Entry $wbEntry -Map $model.Outputs['excel-ci'] -ValueMaps $model['value-maps'].maps -Store $wbStore -RunId $RunId -Log $Log -IncludeDisabled $wbInclude -PageSize ([Math]::Max(1, $PageRows))
                $wr = $wb.Result
                $wbRead = [long]$wb.Read
                & $Log 'INFO' ("CIs: the CI workbook -- {0:N0} CI(s) read from the database a page at a time, {1:N0} row(s) written" -f $wbRead, [long]$wr.Rows)
                # #639: a WARNING of the build (every CI is whole in the database and the web app; only the file is missing)
                if ($wr -and [string]$wr.Outcome -in 'failed', 'partial') { $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the CI workbook was not written ({0}) -- every CI is in the database and the web app' -f [string]$wr.Why) }) }
            } catch {
                & $Log 'WARN' ("CIs: the CI workbook could not be written -- {0}" -f $_.Exception.Message)
                $buildIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the CI workbook was not written ({0}) -- every CI is in the database and the web app' -f $_.Exception.Message) })
            }
        }
        & $mark 'workbook'

        $phaseText = (@($phase.Keys | ForEach-Object { '{0} {1} s' -f $_, $phase[$_] }) -join ', ')
        if ($DryRun) {
            & $Log 'OK' ("CIs: {0} record(s) -> {1} CI(s); {2} new, {3} merged -- DRY RUN, nothing written. Times: {4}" -f $nRec, $t.Cis, $t.Minted, $t.Merged, $phaseText)
        } else {
            & $Log 'OK' ("CIs: {0} record(s) -> {1} CI(s) ({2} changed, {3} new, {4} merged); SQL: {5} CI row(s), {6} link row(s), {7} record link(s), {8} daily row(s), {9} ledger anchor(s); SI_CI_CL: {10} seen + {11} full row(s), ~{12:N0} KB{13}. Times: {14}" -f `
                $nRec, $t.Cis, $t.Changed, $t.Minted, $t.Merged, ($t.Changed + $t.LastSeenOnly), $t.Links, $t.RecordCi, $t.Daily, $t.Anchors, $t.PostedSeen, $t.PostedFull, ($t.Bytes / 1KB), $(if ($full) { ' (weekly full refresh)' } else { '' }), $phaseText)
            if ($t.PostFailed -gt 0) {
                & $Log 'WARN' ("CIs: {0} batch(es) could not be posted to SI_CI_CL; the next build posts them." -f $t.PostFailed)
                # #639 FAILED: Risk Analysis reads its CI context from SI_CI_CL, and this build's rows of those batches are not there
                $buildIssues.Add([pscustomobject]@{ Level = 'FAILED'; Text = ('{0} batch(es) of CIs did not reach SI_CI_CL -- Risk Analysis would read those CIs from an older build or not at all; the next build posts every CI''s row again' -f $t.PostFailed) })
            }
            & $Log 'INFO' ("CIs: {0} of {1} CI(s) unchanged since the last build -- sent without their document{2}" -f $t.Slim, $t.Cis, $(if ($t.Resent -gt 0) { ("; {0} found changed by the database and sent whole" -f $t.Resent) } else { '' }))
        }
        # #642 the identity ledger's wrong merges (sidata.CiBuildState WrongMergesSplit / SharedIdGroups keep the counts)
        foreach ($wl in @(Format-SICiWrongMergeLines -Split $t.WrongMergeSplit -SplitIds $wrongIds.ToArray() -SharedGroups $t.Collisions -SharedIds $collIds.ToArray())) { & $Log 'WARN' $wl }
        # #546 (counted over the CIs this build evaluated -- an incremental build evaluates only the CIs whose records changed)
        $unkLine = ''; try { $unkLine = Format-SICiUnknownFactorLine -Counts $unknownFactorCounts } catch { }
        if ($unkLine) { & $Log 'INFO' $unkLine }
        return [pscustomobject]@{ Failed = $false; Records = $nRec; CiCount = $t.Cis; Cis = $raCis.ToArray(); Changed = $t.Changed; Minted = $t.Minted; Merged = $t.Merged; Unkeyable = $unkeyable; Slim = $t.Slim; Resent = $t.Resent
            PostedSeen = $t.PostedSeen; PostedFull = $t.PostedFull; Bytes = $t.Bytes; SqlRows = ($t.Changed + $t.LastSeenOnly + $t.Links + $t.RecordCi + $t.Daily + $t.Anchors); Full = [bool]$full; Phases = $phase
            # #534 the build's mode and what it did
            BuildMode = $(if ($fullBuild) { 'full' } else { 'incremental' }); FullBuild = [bool]$fullBuild; FullReasons = $reasons.ToArray(); GroupsBuilt = $built
            # a rebuild of every CI that was stopped, carried on by this build; the batches this build kept as finished
            CarryOn = [bool]$carryOn; BatchesKept = $batchesKept
            GroupsSkipped = [Math]::Max(0, $nGroups - $built); SkippedCis = $skippedCis; Touched = $t.Touched; Marked = $t.Marked; Dirty = $dirty
            # the CIs whose rules took too long: kept out until fully evaluated (Kept = their last complete evaluation stays in
            # force, LeftOut = new and not written), built again in the next run; their names (name and kind, the first 50)
            Incomplete = $t.Incomplete; IncompleteKept = $t.IncompleteKept; IncompleteLeftOut = $t.IncompleteLeftOut; IncompleteCis = $heldNames.ToArray()
            ReconcileCorrected = $mismatch.Count; ReconcileCorrectedIds = $mismatch.ToArray(); Fingerprint = $fingerprint; IdentityLinked = $t.IdentityLinked
            # #642 the identity ledger's wrong merges this build split off, and the groups that still share an id (built as one CI)
            WrongMergeSplit = $t.WrongMergeSplit; WrongMergeSplitIds = $wrongIds.ToArray(); SharedIdGroups = $t.Collisions; SharedIds = $collIds.ToArray(); DuplicateCis = $t.Duplicates
            # #493 / #496 the graph
            GraphCis = $gt.Cis; ServiceMemberships = $gt.Services; RelationClaims = $gt.Claims; ServiceChanges = $gt.ServiceChanges; GraphMissing = $graphMissing; Relations = $rel
            # the CIs no source records any more, retired this build
            Retired = $(if ($retired) { [int](Get-SIItemValue $retired 'Retired') } else { 0 })
            # the CI views' stored columns filled at the end of this build ($null: not this edition, or a dry run)
            ViewColumns = $viewColumns
            # #639 what the build caught and went on from (WARNING / FAILED, one plain line each)
            Issues = $buildIssues.ToArray()
            # #639 what the build held at most: the slim seen rows of one page (and how many pages), the CIs of the workbook read
            # back a page at a time, whether the build's stage was there (else the whole-set path of before)
            SeenPages = $seenPages; SeenHeldMax = $seenHeldMax; WorkbookRead = $wbRead; Staged = [bool]$hasStage }
    } catch {
        Stop-SICiWatch -Watch $ciWatch
        # an unreachable database lands here too (the first statement is the grouping): a plain failure with its reason --
        # never a Log Analytics fallback
        & $Log 'WARN' ("CIs could not be built this run -- {0}. The correlation map is unaffected; the next build tries again." -f $_.Exception.Message)
        # #534 the next build is full (best effort: the database may be what failed). Not after a lost lock: the build's
        # state may be another build's by now, and a stopped build is carried on by the next one as it is
        if ($stateRunning -and $sql -and -not $lockLost) { try { $null = & $sql (Get-SICiStateSetSql) @{ j = (ConvertTo-SIJsonArray @([ordered]@{ n = 'LastBuildStatus'; v = 'failed' })) } 'rows' } catch { } }
        return [pscustomobject]@{ Failed = $true; Reason = $_.Exception.Message; CiCount = 0; Cis = @() }
    } finally {
        # the lock this build took is released whatever happened (a killed process: the server frees it with the connection)
        if ($lockOwned) { Exit-SICiBuildLock }
    }
}
