#Requires -Version 5.1
<#
    Stage Recommendations (azure engine only) -- publish every Defender for Cloud recommendation to
    SI_AzureRecommendation_CL (#147). Runs LAST, after the profile rows have landed, so a problem here can
    never cost the profile output.

    * Resource Graph not readable to the end -> NOTHING is published and a loud warning says the previous
      snapshot stays the latest. A shorter list would read as "fixed" (working rule 4).
    * Publishing fails -> the stage throws: the recommendations ARE this stage's output.
    * Opt out with $global:SI_CollectDefenderRecommendations = $false.

    #1399 ONCE PER RUN, ALL OR NOTHING (owner 2026-11-26: data quality first, no duplicates; the two-agent review of 716e218a9).
    * A run in ONE piece publishes here, as before (the child -> parent map from this process's capture).
    * A run IN PARTS never publishes from a part (every part read the whole tenant's list: each row N times under one
      CollectionTime). It publishes ONCE, after the run's records are published (container\Start-SIInContainer.ps1, phase
      'recommendations'), with the child -> parent map from the STORED records of every part (sidata.CiRecord).
    * Every bucket is rolled up to disk FIRST; the rows are posted only when the whole roll-up succeeded, and the snapshot's
      'SnapshotComplete' marker (its row count) is posted LAST. The readers (Risk Analysis, the data sync) take the newest
      snapshot with its marker and at least that many rows, one row per key -- a post that broke half way, or a run published
      twice, never reads as recommendations that were fixed, and never as copies.
    * Not possible: nothing new is published, one line says "recommendations not refreshed this run: <reason>", and the run's
      outcome says it (the stage's summary starts INCOMPLETE -> success-partial, Get-SIRunOutcome).
#>

function Invoke-SIRecommendations {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$RunContext)

    # (the run's recommendations phase writes its records as 'azure-recommendations', its own name -- Invoke-SIEngineRun)
    if ([string]$RunContext.Engine -notin 'azure', 'azure-recommendations') {
        return [pscustomobject]@{ Summary = 'n/a for this engine'; Published = 0 }
    }
    if ($global:SI_CollectDefenderRecommendations -eq $false) {
        return [pscustomobject]@{ Summary = 'Defender for Cloud recommendations: turned off (SI_CollectDefenderRecommendations = $false)'; Published = 0 }
    }
    $phase = 'all'; if ($RunContext.PSObject.Properties['Phase'] -and [string]$RunContext.Phase) { $phase = [string]$RunContext.Phase }
    # a part of a run in parts: the run publishes once, after its last part (never per part)
    if ($phase -eq 'parts') {
        return [pscustomobject]@{ Summary = 'Defender for Cloud recommendations: published once for the whole run, after its last part'; Published = 0 }
    }
    # the older replica sharding (several replicas of one run, each a slice): the first replica alone, never one copy per replica
    $__parts = 0; $__part = 0
    if ($RunContext.PSObject.Properties['ShardCount']) { $__parts = [int]$RunContext.ShardCount }
    if ($RunContext.PSObject.Properties['ShardIndex']) { $__part = [int]$RunContext.ShardIndex }
    if ($phase -eq 'all' -and $__parts -gt 1) {
        # (a message of an older producer, during an update only): no replica knows the whole run's child resources -- none of
        # them publishes; the run after the update does, once (phase 'recommendations')
        if ($__part -ne 0) { return [pscustomobject]@{ Summary = ('Defender for Cloud recommendations: not published by a replica (replica {0} of {1})' -f ($__part + 1), $__parts); Published = 0 } }
        Write-Warning 'Defender for Cloud recommendations not refreshed this run: a run in replicas (an older producer) does not know the child resources of every replica -- the previous complete snapshot stays the latest; the next run publishes them once.'
        return [pscustomobject]@{ Summary = 'INCOMPLETE -- not refreshed: a run in replicas (older producer) does not publish them'; Published = 0 }
    }

    $discoveryRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'discovery'
    . (Join-Path $discoveryRoot 'Invoke-SIArgPaged.ps1')
    . (Join-Path $discoveryRoot 'Get-SIDefenderRecommendations.ps1')
    # The generic publisher lives in engine/_shared: the correlation engine is Pro and absent from the
    # Community edition, so this free stage must never load a file from its folder.
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-LogIngest.ps1')

    $notRefreshed = {
        param([string]$Why)
        $line = ('recommendations not refreshed this run: {0} -- the previous complete snapshot stays the latest.' -f $Why)
        Write-Warning ('Defender for Cloud ' + $line)
        [pscustomobject]@{ Summary = ('INCOMPLETE -- not refreshed: {0}' -f $Why); Published = 0; NotRefreshed = $line }
    }

    # Azure child resources (a VM extension, a disk, a SQL database ...) roll up into their parent: one row per parent and
    # recommendation, the children listed (data-model collection-scope; never a row -- or a CI -- of their own)
    $azScope = $null; $childParents = @{}
    try {
        if (-not (Get-Command -Name Get-SIAzureCiScope -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\SI-AzureChildren.ps1') }
        $azScope = Get-SIAzureCiScope
    } catch { Write-Warning ('Defender for Cloud recommendations: Azure child resources are not rolled up into their parent this run -- {0}' -f $_.Exception.Message) }
    if ($phase -eq 'recommendations') {
        # the whole run's map: the stored records of every part (and the records kept from earlier runs)
        try {
            if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\SI-RecordSql.ps1') }
            $recInv = New-SIRecordSqlInvoke
            if ($null -eq $recInv) { return (& $notRefreshed 'no database is configured, so the run''s stored records (the child resources of every part) cannot be read') }
            $childParents = Read-SIDefenderStoredChildParents -Invoke $recInv
        } catch { return (& $notRefreshed ('the stored records (the child resources of every part) could not be read: {0}' -f $_.Exception.Message)) }
    } else {
        try { $childParents = Get-SIRecordChildParentMap } catch { Write-Warning ('Defender for Cloud recommendations: the child resources of this run are not known -- {0}' -f $_.Exception.Message) }
    }

    $ct = [datetime]$RunContext.CollectionTime
    $table = if ($global:SI_AzureRecommendation_TableName) { [string]$global:SI_AzureRecommendation_TableName } else { 'SI_AzureRecommendation' }
    $dcr   = if ($global:SI_AzureRecommendation_DcrName)   { [string]$global:SI_AzureRecommendation_DcrName }   else { 'dcr-si-azure-recommendation' }
    # 1. the whole roll-up to disk -- nothing is posted before every bucket is worked out
    $outB = New-SIDiskBuckets -Name 'defender-out' -Count 64
    # the marker counts the DISTINCT keys (the readers' key, Get-SIAzureRecRowKey); a bucket's keys are its own (the roll-up buckets
    # by parent resource, and the key carries it), so they are counted a bucket at a time -- never one set for the tenant
    if (-not (Get-Command -Name Get-SIAzureRecRowKey -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-AzureRecSnapshot.ps1') }
    $pub = @{ N = 0L; Keys = 0L; Next = 0; Template = $null }
    $onRows = {
        param($Rows)
        $rs = @($Rows); if ($rs.Count -eq 0) { return }
        if ($null -eq $pub.Template) { $pub.Template = $rs[0] }
        Add-SIDiskBucketRows -Buckets $outB -Bucket $pub.Next -Rows $rs
        $pub.Next = ($pub.Next + 1) % $outB.Count
        $pub.N += $rs.Count
        $ks = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($x in $rs) { [void]$ks.Add((Get-SIAzureRecRowKey -Row $x)) }
        $pub.Keys += $ks.Count
    }
    try {
        $res = Get-SIDefenderRecommendations -CollectionTime $ct -RunId ([string]$RunContext.RunId) -Scope $azScope -ChildParents $childParents -OnRows $onRows

        if (-not $res.Complete) {
            Write-Warning ("Defender for Cloud recommendations: Resource Graph could not be read to the end ({0} assessment(s) retrieved before it failed). NOTHING was published -- the previous complete snapshot stays the latest, because a shorter list would read as recommendations that were fixed. {1}" -f $res.RawCount, $res.Error)
            $nr = & $notRefreshed ('the read or the roll-up did not complete ({0} assessment(s) read): {1}' -f $res.RawCount, $res.Error)
            $nr.Summary = ('INCOMPLETE -- not published ({0} read before failure)' -f $res.RawCount)
            return $nr
        }
        if ([long]$res.RowCount -eq 0) {
            return [pscustomobject]@{ Summary = 'Defender for Cloud: 0 unhealthy recommendations -- nothing to publish'; Published = 0 }
        }
        if ([bool]$RunContext.WhatIf) {
            return [pscustomobject]@{ Summary = ('dry run: {0} Defender for Cloud row(s) found, not published' -f $res.RowCount); Published = 0 }
        }
        # 2. every row, then the marker LAST -- a post that breaks leaves no marker: the readers keep the previous snapshot
        $posted = 0L
        try {
            for ($b = 0; $b -lt $outB.Count; $b++) {
                $chunk = Read-SIDiskBucketRows -Buckets $outB -Bucket $b
                if ($chunk.Count -gt 0) { $posted += [long](Send-SIObjectMapRows -Rows $chunk -TableName $table -DcrName $dcr) }
                Close-SIDiskBucket -Buckets $outB -Bucket $b
            }
            if ($posted -ne [long]$pub.N) { throw ('{0} of {1} row(s) were accepted' -f $posted, $pub.N) }
            $null = Send-SIObjectMapRows -Rows @(New-SIDefenderSnapshotMarker -Template $pub.Template -Rows $pub.Keys -RunId ([string]$RunContext.RunId)) -TableName $table -DcrName $dcr
        } catch {
            $nr = & $notRefreshed ('the post broke after {0} of {1} row(s) -- {2}; without its completion marker the readers never use this snapshot' -f $posted, $pub.N, $_.Exception.Message)
            throw ('Defender for Cloud ' + $nr.NotRefreshed)
        }

        $byKind = @($res.ByKind.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $res.ByKind[$_] }) -join ' '
        $entities = [long]$res.Entities
        [pscustomobject]@{
            Summary   = ('Defender for Cloud: {0} unhealthy assessment(s) -> {1} row(s) [{2}] ({3} container-image / cloud-posture entities and Azure child resources rolled up; {5} finding(s) listed on their recommendation) -> {4}_CL, marked complete' -f $res.RawCount, $posted, $byKind, [int]$entities, $table, [int]$res.SubCount)
            Published = $posted
        }
    } finally {
        Remove-SIDiskBuckets $outB
    }
}
