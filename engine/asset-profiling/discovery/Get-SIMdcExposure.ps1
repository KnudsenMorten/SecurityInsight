#Requires -Version 5.1
<#
    DEFENDER FOR CLOUD AS AN INTERNET-EXPOSURE PROVIDER (#527 (7), owner 2026-10-10: "factors in si are more static, but
    source fields may chg").

    The same fact has a different field name in every source. Defender for Cloud says it through its internet-exposure
    ASSESSMENTS in Azure Resource Graph (securityresources, type microsoft.security/assessments): a resource with an
    Unhealthy internet-exposure assessment is reachable from the internet. Each such resource becomes a record part
    (provider 'mdc', record type azure_resource, part 'exposure'); data-model/mappings/mdc.locked.json maps
    exposure.internetExposed onto si_internet_exposed -- the only field the risk factor internet_exposed reads. A new
    or renamed assessment is a change HERE (or a mapping override), never a factor change.

    REST only (Resource Graph through Search-SIAzGraph, engine/_shared/SI-AzRest.ps1); no PowerShell modules. Rights:
    securityresources is readable with the Reader access the Azure collector already uses -- no new permission.
    Never throws into the profiler: a failed read is said and the pull is recorded incomplete (absence proves nothing).
    PowerShell 5.1: no ?. / ??, no ternary.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1) -- loaded here, so this file works however it is loaded.
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

# Defender for Cloud assessments that mean "reachable from the internet" (assessment key = the assessment's name)
$script:SIMdcInternetExposureAssessments = @(
    '483f12ed-ae23-447e-a2de-a67a10db4353'   # Internet-facing virtual machines should be protected with network security groups
    '22730e10-96f6-4aac-ad84-9383d35b5917'   # Management ports should be closed on your virtual machines
    '805651bc-6ecd-4c73-9b55-97a19d0582d0'   # Management ports of virtual machines should be protected with just-in-time network access control
    '9daedab3-fb2d-461e-b861-71790eead4f6'   # All network ports should be restricted on network security groups associated to your virtual machine
    '1c5de8e1-f68d-6a17-e0d2-ec259c42768c'   # Storage accounts should restrict network access
)

function Get-SIMdcExposureKql {
    <# PURE. The Resource Graph query: one row per resource with an Unhealthy internet-exposure assessment. #>
    param([string[]]$AssessmentKeys = $script:SIMdcInternetExposureAssessments)
    $keys = (@($AssessmentKeys) | ForEach-Object { "'" + ([string]$_).ToLowerInvariant().Replace("'", '') + "'" }) -join ', '
    @"
securityresources
| where type =~ 'microsoft.security/assessments'
| where tostring(properties.status.code) =~ 'Unhealthy'
| extend AssessmentKey = tolower(name), DisplayName = tostring(properties.displayName)
| where AssessmentKey in ($keys) or DisplayName has 'internet'
| extend ResourceId = tolower(tostring(properties.resourceDetails.Id))
| where isnotempty(ResourceId)
| summarize Assessments = make_set(DisplayName) by ResourceId
"@
}

function ConvertTo-SIMdcExposureObjects {
    <# PURE. Resource Graph rows -> the 'exposure' part objects: @{ resourceId; internetExposed = true; assessments }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $id = ([string]$r.ResourceId).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $out.Add([pscustomobject][ordered]@{ resourceId = $id; internetExposed = $true; assessments = @(@($r.Assessments) | Where-Object { $_ } | ForEach-Object { [string]$_ }) })
    }
    return , $out.ToArray()
}

function Invoke-SIMdcExposureCapture {
    <#
    .SYNOPSIS  Reads the internet-exposure assessments and hands each resource to the record capture (provider mdc).
               Returns the number of resources; 0 when the record capture is not loaded or the read failed.
    #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$Query)
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return 0 }
    $err = ''
    $n = 0
    # #727 PAGE BY PAGE: each page's resources go to the record capture (which streams them in the producer) and are let go
    $take = {
        param($Rows)
        foreach ($o in (ConvertTo-SIMdcExposureObjects -Rows @($Rows))) {
            try {
                # part 'resource' holds the record's key: the Defender for Cloud record of a resource is ONE record whether it
                # has an exposure, an assessment summary (Get-SIMdcAssessmentSummary.ps1) or both
                Add-SIRecordPart -Provider 'mdc' -RecordType 'azure_resource' -Key $o.resourceId -Part 'resource' -Object ([pscustomobject]@{ resourceId = $o.resourceId })
                Add-SIRecordPart -Provider 'mdc' -RecordType 'azure_resource' -Key $o.resourceId -Part 'exposure' -Object $o; $script:SIMdcExposureTaken++
            } catch { }
        }
    }
    $script:SIMdcExposureTaken = 0
    try {
        if ($Query) { $null = & $take @(& $Query (Get-SIMdcExposureKql)) }
        else {
            $p = @{ Query = (Get-SIMdcExposureKql); First = 1000 }
            if (@($SubscriptionIds).Count -gt 0) { $p['Subscription'] = $SubscriptionIds }
            do {
                $page = Search-SIAzGraph @p -ErrorAction Stop
                $rowsOfPage = New-Object System.Collections.Generic.List[object]
                foreach ($x in $page) { $rowsOfPage.Add($x) }
                $null = & $take $rowsOfPage.ToArray()
                $rowsOfPage = $null
                $p['SkipToken'] = $page.SkipToken
            } while ($p['SkipToken'])
        }
    } catch { $err = [string]$_.Exception.Message; Write-Warning ('Defender for Cloud exposure: not read ({0}) -- internet exposure comes from the other providers this run.' -f $err) }
    $n = [int]$script:SIMdcExposureTaken
    if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'mdc' -Complete (-not $err) -ErrorText $err }
    return $n
}
