#Requires -Version 5.1
<#
    Invoke-Reconcile.ps1

    RECONCILE phase (ARCHITECTURE.md § 13). Runs AFTER all per-asset
    engines have produced profile rows. Two outputs:

      1. CmdbMatchState field on every profile row (forward direction):
         matched-pinned | matched-exact | matched-rule | matched-fuzzy
         | orphan-discovered | stale-cache

      2. Reconciliation_Gap_CL table (reverse direction): one row per
         CMDB CI that did not match any discovered asset.

    Match priority chain (per § 13):
      1. Pin              -> matched-pinned
      2. Direct CMDB rel  -> matched-exact   (cmdbmembership table)
      3. Identity match   -> matched-exact   (azure_resource_id / entra_object_id / fqdn)
      4. Custom rule      -> matched-rule    (rules-custom/shared/cmdb-membership.yaml)
      5. Fuzzy            -> matched-fuzzy   (name + env heuristic, conf >= 0.8)
      6. No match         -> orphan-discovered

    ships the scaffold + match priorities 1, 3, 6 (the simplest).
    Pin file (cmdb-pins.yaml), direct membership (cmdbmembership table is
    empty in sample-CSV mode), custom grouping rules, and fuzzy matching
    are stubbed with TODOs.

    Stage Profile writes Verdict + cmdbId to records first.
    Reconcile bolts on CmdbMatchState and overwrites cmdbId only when match
    priority 1-5 produced a stronger match.

    Untested in tenant.
#>

function Invoke-SIReconcile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext
    )

    # opt-in flag dropped. Reconcile always runs. CMDB cache may
    # be empty (state='never'); the per-asset loop below handles that gracefully
    # by tagging every row 'orphan-discovered' without failing the stage.
    $engine = $RunContext.Engine
    $v22Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $v22Root 'engine\asset-profiling\storage\StagingBlob.ps1')
    . (Join-Path $v22Root 'engine\asset-profiling\storage\CmdbCache.ps1')

    # ensure cache tables exist before any read. Without this, the
    # first engine run on a new tenant emits doubled "Can not find table
    # 'sicmdbservices'" warnings (one from Get-SICmdbCacheAge, one from
    # Get-SICmdbServices). Initialize is idempotent -- safe on every run.
    try { Initialize-SICmdbCacheTables -Context $RunContext.StorageContext | Out-Null }
    catch { Write-Warning ("Initialize-SICmdbCacheTables failed: {0}. Continuing -- empty-cache path will fire." -f $_.Exception.Message) }

    # Cache freshness gate
    $age = Get-SICmdbCacheAge -Context $RunContext.StorageContext
    if ($age.State -eq 'critical') {
        Write-Warning ('CMDB cache is {0}h old (>7d). Tagging every row stale-cache; gap report suppressed.' -f $age.HoursOld)
    } elseif ($age.State -eq 'stale') {
        Write-Warning ('CMDB cache is {0}h old (warning threshold 24h). Proceeding.' -f $age.HoursOld)
    } elseif ($age.State -eq 'never') {
        Write-Warning 'CMDB cache is empty (no sync run yet). Every row will be orphan-discovered.'
    } else {
        Write-SIInfo ('CMDB cache age: {0}h (fresh)' -f $age.HoursOld)
    }

    # Load assets from staging (Stage Profile writes to Stage='Classify')
    $records = @(Read-SIStageShards -Context $RunContext.StorageContext `
                                    -ContainerName $RunContext.StagingContainer `
                                    -RunId $RunContext.RunId `
                                    -Stage 'Classify')
    Write-SIInfo ("{0} records read from staging" -f $records.Count)

    $cis      = @(Get-SICmdbCIs      -Context $RunContext.StorageContext)
    $services = @(Get-SICmdbServices -Context $RunContext.StorageContext)
    Write-SIInfo ("CMDB cache: {0} services, {1} CIs" -f $services.Count, $cis.Count)

    # Build CI lookup indexes for priority-3 (identity match)
    $byArmId  = @{}
    $byEntra  = @{}
    $byFqdn   = @{}
    foreach ($c in $cis) {
        if ($c.azure_resource_id) { $byArmId[([string]$c.azure_resource_id).ToLower()] = $c }
        if ($c.entra_object_id)   { $byEntra[([string]$c.entra_object_id).ToLower()]   = $c }
        if ($c.fqdn)              { $byFqdn[([string]$c.fqdn).ToLower()]               = $c }
    }
    # services lookup by id -- Stage Profile stamps cmdbId from rule
    # matches (rules-custom/<engine>/AssetProfileBy*.yaml set.cmdbId). Reconcile
    # then folds the FULL service record (all CSV columns surfaced by Refresh-
    # CmdbCache.ps1) onto $Record.Metadata.CMDB_*.
    $byServiceId = @{}
    foreach ($s in $services) {
        if ($s.id)   { $byServiceId[([string]$s.id).ToLower()]   = $s }
        elseif ($s.RowKey) { $byServiceId[([string]$s.RowKey).ToLower()] = $s }
    }
    $matchedCiIds = New-Object System.Collections.Generic.HashSet[string]

    # explicit two-phase mapping (per user direction):
    #   Phase 1 -- "1:1 mapping based on rules"
    #              Stage Profile evaluated YAML rules and may have stamped
    #              `$r.cmdbId` from a `set.cmdbId` clause in a matched rule.
    #              When set, Phase 1 wins; we DO NOT run identity-match.
    #   Phase 2 -- "mapping of resources (gaps)"
    #              For rows Phase 1 didn't touch, attempt direct CMDB CI
    #              identity match (azure_resource_id / entra_object_id / fqdn).
    # CmdbMatchPhase column makes the source visible: 'rule' | 'identity' | 'orphan'
    # | 'stale-cache'. CmdbMatchRule keeps the previous semantics (rule-id when
    # rule-matched, 'identity-match' when CI-matched, 'no-match' otherwise).
    $stats = @{ rulePhase=0; identityPhase=0; orphan=0; staleCache=0 }
    foreach ($r in $records) {
        $CmdbMatchPhase = $null
        $CmdbMatchState = $null
        $CmdbMatchRule  = $null
        $confidence = 1.0
        $matchedCi  = $null

        # Has Phase 1 already mapped this row? Profile sets $r.cmdbId from
        # a YAML rule's `set.cmdbId`. SI_RuleMatches[] records WHICH rule.
        $rulecmdbId = if ($r.PSObject.Properties['cmdbId']) { [string]$r.cmdbId } else { '' }
        $ruleMatchSource = $null
        if ($rulecmdbId -and $r.PSObject.Properties['Verdict'] -and $r.Verdict.PSObject.Properties['SI_RuleMatches']) {
            $hit = @($r.Verdict.SI_RuleMatches) | Where-Object { [string]$_.cmdbId -eq $rulecmdbId } | Select-Object -First 1
            if ($hit) { $ruleMatchSource = [string]$hit.RuleId }
        }

        if ($age.State -eq 'critical') {
            $CmdbMatchPhase = 'stale-cache'; $CmdbMatchState = 'stale-cache'
            $stats.staleCache++
        } elseif ($rulecmdbId) {
            # ---- Phase 1: rule-driven (1:1) ----
            $CmdbMatchPhase = 'rule'
            $CmdbMatchState = 'matched-by-rule'
            $CmdbMatchRule  = if ($ruleMatchSource) { $ruleMatchSource } else { 'rule-cmdbid' }
            # Try to also locate a CI by cmdbId so MatchedCi-derived columns fill
            # too (LastSeenInCmdb, cmdbCriticality, etc).
            foreach ($c in $cis) {
                if ([string]$c.id -eq $rulecmdbId) { $matchedCi = $c; [void]$matchedCiIds.Add(([string]$c.id).ToLower()); break }
            }
            $stats.rulePhase++
        } else {
            # ---- Phase 2: identity-match gap mapping ----
            $armId = [string]$r.AZ_ResourceId
            if (-not $armId -and $r.PSObject.Properties['Metadata']) { $armId = [string]$r.Metadata.AZ_ResourceId }
            $entId = [string]$r.PrimaryEntityId
            $fqdn  = [string]$r.Fqdn
            $candidate = $null
            if ($armId -and $byArmId.ContainsKey($armId.ToLower())) { $candidate = $byArmId[$armId.ToLower()] }
            elseif ($entId -and $byEntra.ContainsKey($entId.ToLower())) { $candidate = $byEntra[$entId.ToLower()] }
            elseif ($fqdn  -and $byFqdn.ContainsKey($fqdn.ToLower()))   { $candidate = $byFqdn[$fqdn.ToLower()] }

            if ($candidate) {
                $CmdbMatchPhase = 'identity'
                $CmdbMatchState = 'matched-by-identity'
                $CmdbMatchRule  = 'identity-match'
                [void]$matchedCiIds.Add(([string]$candidate.id).ToLower())
                $matchedCi = $candidate
                $stats.identityPhase++
            } else {
                $CmdbMatchPhase = 'orphan'
                $CmdbMatchState = 'orphan-discovered'
                $CmdbMatchRule  = 'no-match'
                $confidence = 0.0
                $stats.orphan++
            }
        }

        $reconcileFields = @{
            CmdbMatchPhase      = $CmdbMatchPhase
            CmdbMatchState      = $CmdbMatchState
            CmdbMatchRule       = $CmdbMatchRule
            CmdbMatchConfidence = $confidence
            LastSeenInCmdb  = if ($matchedCi) { [string]$matchedCi.last_seen } else { $null }
        }
        # Bolt onto record
        foreach ($k in $reconcileFields.Keys) {
            if ($r.PSObject.Properties[$k]) { $r.$k = $reconcileFields[$k] }
            else { Add-Member -InputObject $r -MemberType NoteProperty -Name $k -Value $reconcileFields[$k] -Force }
        }
        # Inherit cmdb* fields from matched CI (only when not already set by Stage Profile)
        if ($matchedCi) {
            foreach ($f in @('cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity')) {
                $sourceKey = switch ($f) {
                    'cmdbId'             { 'id' }
                    'cmdbName'           { 'name' }
                    'cmdbCriticality'    { 'criticality' }
                    'cmdbDataSensitivity'{ 'dataSensitivity' }
                }
                $val = [string]$matchedCi.$sourceKey
                if ($val) {
                    if ($r.PSObject.Properties[$f]) {
                        if ([string]::IsNullOrWhiteSpace([string]$r.$f)) { $r.$f = $val }
                    }
                    else { Add-Member -InputObject $r -MemberType NoteProperty -Name $f -Value $val -Force }
                }
            }
        }

        # services lookup by cmdbId (Stage Profile stamped this from a
        # rule match). Folds the FULL service record onto $r.Metadata.CMDB_* so all
        # CSV columns Refresh-CmdbCache.ps1 surfaced (Owner, OwnerMail, plus any
        # custom columns) reach Properties.collect.cmdb in the row builders.
        $serviceId = if ($r.PSObject.Properties['cmdbId']) { [string]$r.cmdbId } else { '' }
        if ($serviceId) {
            $svc = $byServiceId[$serviceId.ToLower()]
            if ($svc) {
                # 2026-05-02: stamp canonical cmdb* columns directly on the row from the
                # matched service record. Without this, rule-driven Phase 1 leaves the
                # row with only cmdbId (the service's "1") populated -- cmdbName /
                # cmdbCriticality / cmdbDataSensitivity stay empty in SI_*_Profile_CL,
                # because Phase 1's CI fallback (line 137-139) only matches CIs whose
                # `id` equals the SERVICE id, which they never do. Service-row enrichment
                # must do this directly. Mirror the CI inheritance map (line 183-188).
                $svcGet = {
                    param($Obj, $Name)
                    if ($Obj -is [System.Collections.IDictionary]) {
                        if ($Obj.Contains($Name)) { return $Obj[$Name] }
                        return $null
                    }
                    if ($Obj.PSObject.Properties[$Name]) { return $Obj.PSObject.Properties[$Name].Value }
                    return $null
                }
                $svcFieldMap = @{
                    cmdbName            = 'name'
                    cmdbCriticality     = 'criticality'
                    cmdbDataSensitivity = 'dataSensitivity'
                }
                foreach ($f in $svcFieldMap.Keys) {
                    $sourceKey = $svcFieldMap[$f]
                    $val = [string](& $svcGet $svc $sourceKey)
                    if (-not $val) { continue }
                    if ($r.PSObject.Properties[$f]) {
                        if ([string]::IsNullOrWhiteSpace([string]$r.$f)) { $r.$f = $val }
                    } else {
                        Add-Member -InputObject $r -MemberType NoteProperty -Name $f -Value $val -Force
                    }
                }

                # Folds the FULL service record onto $r.Metadata.CMDB_* so
                # all CSV columns Refresh-CmdbCache.ps1 surfaced (Owner, OwnerMail, plus
                # any custom columns) reach Properties.collect.cmdb in the row builders.
                $meta = $r.Metadata
                if ($null -eq $meta) {
                    $meta = @{}
                    if ($r.PSObject.Properties['Metadata']) { $r.Metadata = $meta }
                    else { Add-Member -InputObject $r -MemberType NoteProperty -Name 'Metadata' -Value $meta -Force }
                }
                $skip = @('PartitionKey','RowKey','Etag','TableTimestamp','TableName')
                $cols = if ($svc -is [System.Collections.IDictionary]) { @($svc.Keys) } else { @($svc.PSObject.Properties.Name) }
                foreach ($k in $cols) {
                    if ($k -in $skip) { continue }
                    $val = if ($svc -is [System.Collections.IDictionary]) { $svc[$k] } else { $svc.$k }
                    if ($null -eq $val -or [string]::IsNullOrWhiteSpace([string]$val)) { continue }
                    $cmdbKey = 'CMDB_' + $k
                    if ($meta -is [System.Collections.IDictionary]) { $meta[$cmdbKey] = $val }
                    else {
                        if ($meta.PSObject.Properties[$cmdbKey]) { $meta.$cmdbKey = $val }
                        else { Add-Member -InputObject $meta -MemberType NoteProperty -Name $cmdbKey -Value $val -Force }
                    }
                }
            }
        }
    }

    # Re-write enriched records back to staging
    Write-SIStageShard -Context $RunContext.StorageContext `
                       -ContainerName $RunContext.StagingContainer `
                       -RunId $RunContext.RunId `
                       -Stage 'Classify' `
                       -ShardIndex $RunContext.ShardIndex `
                       -Records $records | Out-Null

    # Reverse direction: gap rows (CMDB CIs nothing discovered)
    $gapRows = New-Object System.Collections.ArrayList
    if ($age.State -ne 'critical') {
        foreach ($c in $cis) {
            $cid = ([string]$c.id).ToLower()
            if (-not $matchedCiIds.Contains($cid)) {
                [void]$gapRows.Add([pscustomobject]@{
                    CollectionTime  = $RunContext.CollectionTime
                    cmdbId          = [string]$c.id
                    cmdbName        = [string]$c.name
                    cmdbCriticality = [string]$c.criticality
                    ExpectedEngine  = if ($c.azure_resource_id) { 'azure' } elseif ($c.entra_object_id) { 'identity' } else { 'endpoint' }
                    LastSeenInCmdb  = [string]$c.last_seen
                    Reason          = 'never-seen-in-discovery'
                })
            }
        }
    }
    Write-SIInfo ("gap rows: {0}" -f $gapRows.Count)

    # NOTE: gap-row LA ingest not yet shipped (Reconciliation_Gap_CL table
    # creation lands in ). returns the rows in
    # StageResult so a custom launcher can dispatch them manually.

    Write-SIInfo ('phase summary: rule={0} identity={1} orphan={2} stale-cache={3} gap-cis={4}' -f `
        $stats.rulePhase, $stats.identityPhase, $stats.orphan, $stats.staleCache, $gapRows.Count)

    return [pscustomobject]@{
        Stage          = 'Reconcile'
        Engine         = $engine
        AssetsScanned  = $records.Count
        RulePhaseCount = $stats.rulePhase
        IdentityPhase  = $stats.identityPhase
        OrphanCount    = $stats.orphan
        StaleCacheRows = $stats.staleCache
        GapRowCount    = $gapRows.Count
        GapRows        = $gapRows.ToArray()
        CacheState     = $age.State
        CacheHoursOld  = $age.HoursOld
        Summary        = ('rule={0} identity={1} orphan={2} gap={3} cache={4}' -f $stats.rulePhase, $stats.identityPhase, $stats.orphan, $gapRows.Count, $age.State)
    }
}
