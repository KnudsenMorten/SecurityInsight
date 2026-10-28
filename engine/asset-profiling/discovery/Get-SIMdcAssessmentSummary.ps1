#Requires -Version 5.1
<#
    Get-SIMdcAssessmentSummary -- Defender for Cloud's assessments as part of the resource RECORD, SUMMARISED PER RESOURCE
    (owner 2026-10-11, "Both, in two steps" -- step 2: record capture, summarised per resource rather than one record per
    assessment row).

    ONE Azure Resource Graph query (securityresources, type microsoft.security/assessments), summarised INSIDE the query
    to one row per assessed resource: how many assessments, how many unhealthy and per severity, the oldest first
    evaluation and the newest status change among the unhealthy ones, and the TOP unhealthy ones -- id (the assessment
    key) AND name, severity. Paged to the end and sorted (a stable order across pages).

    Each resource becomes part 'assessments' of its Defender for Cloud record (provider mdc, record type azure_resource),
    beside part 'resource' (its id -- the record's key), so the properties show under "Records per source", in continuous
    discovery and -- through data-model/mappings/mdc.locked.json -- as SI fields on the resource and its CI. The FINDINGS
    themselves keep arriving through Risk Analysis; nothing here changes a report or a score.

    A resource Defender for Cloud has no assessment for gets NO part: unknown is never written as "healthy".
    REST only (Resource Graph through Search-SIAzGraph); rights: the Reader access the Azure collector already uses.
    READ ONLY. Never throws into the profiler: a failed read is said and the pull is recorded incomplete.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
if (-not (Get-Command -Name Invoke-SIArgPaged -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1') }

$script:SIMdcAssessmentTop = 5

function Get-SIMdcAssessmentSummaryKql {
    <# PURE. The Resource Graph query: one row per assessed resource. The top items are collected per severity (never by row order). #>
    param([int]$Top = $script:SIMdcAssessmentTop)
    if ($Top -lt 1) { $Top = 1 }
    @"
securityresources
| where type =~ 'microsoft.security/assessments'
| extend ResourceId = tolower(tostring(properties.resourceDetails.Id)), Status = tostring(properties.status.code), Severity = tostring(properties.metadata.severity),
         AssessmentName = tostring(properties.displayName), AssessmentKey = tolower(name),
         FirstEvaluated = todatetime(properties.status.firstEvaluationDate), StatusChanged = todatetime(properties.status.statusChangeDate)
| where isnotempty(ResourceId)
| extend Bad = (Status =~ 'Unhealthy'), Item = pack('id', AssessmentKey, 'name', AssessmentName, 'severity', Severity)
| summarize Assessed = count(), Unhealthy = countif(Bad), High = countif(Bad and Severity =~ 'High'), Medium = countif(Bad and Severity =~ 'Medium'), Low = countif(Bad and Severity =~ 'Low'),
            OldestUnhealthy = minif(FirstEvaluated, Bad), NewestChange = maxif(StatusChanged, Bad),
            TopHigh = make_list_if(Item, Bad and Severity =~ 'High', $Top), TopMedium = make_list_if(Item, Bad and Severity =~ 'Medium', $Top),
            TopLow = make_list_if(Item, Bad and not(Severity =~ 'High') and not(Severity =~ 'Medium'), $Top) by ResourceId
| order by ResourceId asc
"@
}

function ConvertTo-SIMdcTopItems {
    <# PURE. Lists of top items in order of importance -> the first -Top as objects (id, name, severity); a list may be an array or its JSON text. #>
    param([object[]]$Lists = @(), [int]$Top = $script:SIMdcAssessmentTop)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($l in $Lists) {
        $items = $l
        if ($l -is [string]) { $t = $l.Trim(); $items = $null; if ($t.StartsWith('[')) { try { $items = $t | ConvertFrom-Json } catch { $items = $null } } }
        foreach ($i in @($items)) {
            if ($out.Count -ge $Top) { break }
            if ($null -eq $i -or $i -is [string]) { continue }
            $id = ''; if ($i.PSObject.Properties['id']) { $id = ([string]$i.id).Trim() }
            if (-not $id -or $seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $name = ''; if ($i.PSObject.Properties['name']) { $name = ([string]$i.name).Trim() }
            $sev = ''; if ($i.PSObject.Properties['severity']) { $sev = ([string]$i.severity).Trim() }
            $out.Add([pscustomobject][ordered]@{ id = $id; name = $name; severity = $sev })
        }
    }
    return , $out.ToArray()
}

function ConvertTo-SIMdcAssessmentObjects {
    <#
    .SYNOPSIS  PURE. Resource Graph rows -> one object per resource: @{ resourceId; Assessments = the 'assessments' part }.
               Only what has a value; TopText = "id -- name (severity)" (id and name side by side).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $id = ([string]$r.ResourceId).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $g = { param($n) $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
        $o = [ordered]@{}
        foreach ($n in 'Assessed', 'Unhealthy', 'High', 'Medium', 'Low') {
            $v = & $g $n; $x = 0
            if ($null -ne $v -and [int]::TryParse(([string]$v), [ref]$x)) { $o[$n] = $x }
        }
        if (-not $o.Contains('Assessed') -or [int]$o['Assessed'] -le 0) { continue }
        foreach ($n in 'OldestUnhealthy', 'NewestChange') { $v = & $g $n; if ($null -ne $v -and "$v" -ne '') { $o[$n] = $v } }
        $top = ConvertTo-SIMdcTopItems -Lists @((& $g 'TopHigh'), (& $g 'TopMedium'), (& $g 'TopLow'))
        if (@($top).Count -gt 0) {
            $o['Top'] = @($top)
            $o['TopText'] = @(@($top) | ForEach-Object {
                $t = [string]$_.id; if ($_.name) { $t = $t + ' -- ' + [string]$_.name }
                if ($_.severity) { $t = $t + ' (' + [string]$_.severity + ')' }
                $t
            })
        }
        $out.Add([pscustomobject]@{ resourceId = $id; Assessments = [pscustomobject]$o })
    }
    return , $out.ToArray()
}

function Invoke-SIMdcAssessmentSummaryCapture {
    <#
    .SYNOPSIS  Reads the assessment summary of every assessed resource and hands each to the record capture (provider
               mdc, parts 'resource' and 'assessments'). Returns the number of resources; 0 when the record capture is not
               loaded or the read failed. Never throws.
    .PARAMETER Query  test seam: { param($Kql) } -> rows (the whole answer).
    #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$Query)
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return 0 }
    $err = ''; $complete = $true
    # Defender for Cloud assesses far more than the resource types that become CIs (subnets, disks, subscriptions ...). The
    # record capture leaves those out by itself; its count of "Azure objects not recorded as CIs" is about the Azure read,
    # so it is put back as it was -- a summary that has no CI to sit on is not an Azure object that went missing.
    $cst = $null; $droppedBefore = $null
    if ($null -ne $global:SIRecordCaptureState -and (Get-Command -Name Get-SIRecordChildState -ErrorAction SilentlyContinue)) {
        try {
            $cst = Get-SIRecordChildState $global:SIRecordCaptureState
            if ($cst -and $null -ne $cst.Dropped) { $droppedBefore = @{}; foreach ($k in @($cst.Dropped.Keys)) { $droppedBefore[$k] = $cst.Dropped[$k] } }
        } catch { $cst = $null; $droppedBefore = $null }
    }
    # #727 PAGE BY PAGE: each page's resources go to the record capture (which streams them in the producer) and are let go
    $script:SIMdcSummaryTaken = 0
    $take = {
        param($Rows)
        foreach ($o in (ConvertTo-SIMdcAssessmentObjects -Rows @($Rows))) {
            try {
                Add-SIRecordPart -Provider 'mdc' -RecordType 'azure_resource' -Key $o.resourceId -Part 'resource' -Object ([pscustomobject]@{ resourceId = $o.resourceId })
                Add-SIRecordPart -Provider 'mdc' -RecordType 'azure_resource' -Key $o.resourceId -Part 'assessments' -Object $o.Assessments
                $script:SIMdcSummaryTaken++
            } catch { }
        }
    }
    try {
        $kql = Get-SIMdcAssessmentSummaryKql
        if ($Query) { $null = & $take @(& $Query $kql) }
        else {
            $page = Invoke-SIArgPaged -Query $kql -SourceLabel 'Defender for Cloud assessments per resource' -SubscriptionIds $SubscriptionIds -OnPage $take -WarningAction SilentlyContinue
            $complete = [bool]$page.Complete
            if (-not $complete) { $err = [string]$page.Error }
        }
    } catch { $err = [string]$_.Exception.Message; $complete = $false }
    if ($err) { Write-Warning ('Defender for Cloud assessments per resource: not read completely ({0}) -- the resources not read keep their previous summary; the findings in Risk Analysis are not affected.' -f $err) }
    $n = [int]$script:SIMdcSummaryTaken
    if ($cst -and $null -ne $droppedBefore) {
        try { $cst.Dropped.Clear(); foreach ($k in @($droppedBefore.Keys)) { $cst.Dropped[$k] = $droppedBefore[$k] } } catch { }
    }
    if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'mdc' -Complete $complete -ErrorText $err }
    return $n
}
