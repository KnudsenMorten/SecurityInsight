#Requires -Version 5.1
<#
.SYNOPSIS
    The asset-tagging CONTAINER JOB (caj-si-asset-tagging, #236): runs engine\asset-tagging\AssetTagging.ps1 in a
    SecurityInsight Pro container.

.DESCRIPTION
    Pro is container-only, so asset tagging -- until now a VM scheduled task signed in as an SPN -- runs as its own
    Container Apps job, after the profilers. The container entry point (container\Start-SIInContainer.ps1) has already
    signed in, loaded the customer's settings and, on a Pro install, the Pro settings database: the rules then come
    from the SQL templates and the customer's overrides, materialised to $global:SI_ProAssetTaggingPath, and the
    engine reads them from there instead of the shipped rule files.

    REPORT ONLY BY DEFAULT. Without -Apply nothing is written: every tag the rules WOULD set is logged (console and
    the asset-tag activity table) and nothing in Defender, Azure or Entra changes. The container passes -Apply only
    when the Pro setting SI_Pro_AssetTagging_Apply is on (Get-SIContainerEngineDispatch). Writing also needs the
    job's own identity to hold the write grants (Bootstrap-ContainerAppJob.ps1 -GrantTaggingRoles, or
    setup\Grant-SIIdentity.ps1 -Tagging) -- the collection identity never does.

.PARAMETER Apply
    Write the tags. Without it the run only reports what it would write.
#>
[CmdletBinding()]
param([switch]$Apply)

$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# CR2 (#656): while SecurityInsight's data is Unhealthy tagging reports only, unless a SuperAdmin let it through
if ($Apply) {
    try {
        . ([System.IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-DataHealthHold.ps1'))
        if ((Resolve-SIDataHealthHold -Channel 'asset-tagging' -Log { param($l, $m) Write-Host ('[asset-tagging] {0}' -f $m) }).Held) { $Apply = [switch]$false }
    } catch { Write-Host ('[asset-tagging] the data health hold could not be checked ({0}) -- tagging runs as configured' -f $_.Exception.Message) }
}

# The run mode is decided HERE, from -Apply only -- a WhatIfMode value copied from a VM config can never turn a
# container run into a writing one, and never turn a writing one back into a report.
$global:WhatIfMode = -not [bool]$Apply
$global:AutomationFramework = $false   # the internal platform framework never exists in a container
if ($null -eq $global:SuppressErrors)   { $global:SuppressErrors = $false }
if ($null -eq $global:SuppressWarnings) { $global:SuppressWarnings = $false }
if (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }
if ([string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    $global:SettingsPath = [System.IO.Path]::Combine($siRoot, 'asset-profiling-enrichment', 'endpoint')
}
if (-not $global:LockedYamlFile) { $global:LockedYamlFile = 'AssetTagging.locked.yaml' }
if (-not $global:CustomYamlFile) { $global:CustomYamlFile = 'AssetTagging.custom.yaml' }

Write-Host ('[asset-tagging] {0}' -f $(if ($Apply) { 'WRITES ON -- tags are set in Defender, Azure and Entra (SI_Pro_AssetTagging_Apply is on)' }
                                       else { 'REPORT ONLY -- nothing is changed; every tag the rules would set is logged (turn SI_Pro_AssetTagging_Apply on to write)' }))
if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProAssetTaggingPath)) {
    Write-Host ('[asset-tagging] rules from the SecurityInsight Pro settings database: {0}' -f $global:SI_ProAssetTaggingPath)
} else {
    Write-Host ('[asset-tagging] rules from the shipped rule files: {0}' -f $global:SettingsPath)
}

# #429 (operator 2026-10-07: "we cannot have hidden connectors doing changes without telling customers") -- asset tagging
# writes to Defender, Azure and Entra, so it is a REGISTERED connector: every run on Configuration > Connectors > Runs
# (cfg.ConnectorRun, name 'asset-tagging'). The tags it set or would set, per asset, are in SI_AssetTagActivity_CL.
$tagRunId = [guid]::NewGuid().ToString(); $tagStarted = [datetime]::UtcNow; $tagError = ''
try { & ([System.IO.Path]::Combine($siRoot, 'engine', 'asset-tagging', 'AssetTagging.ps1')) -RunMode $(if ($Apply) { 'write' } else { 'report' }) }   # the decision above is passed on; the engine never re-decides it
catch { $tagError = $_.Exception.Message; throw }
finally {
    try {
        # Pro only: the Community edition has no connector registry (and no Pro database) -- nothing to record there
        $cxHelper = [System.IO.Path]::Combine($siRoot, 'engine', 'asset-cmdb', '_shared', 'SI-Connector.ps1')
        $tagStore = $null
        if (Test-Path -LiteralPath $cxHelper) { . $cxHelper; $tagStore = New-SIConnectorRegistryStore }
        if ($tagStore) {
            $why = if ($Apply) { 'tags set in Defender, Azure and Entra -- each tag, per asset, is in SI_AssetTagActivity_CL' } else { 'report only -- nothing was written; the tags the rules would set are in SI_AssetTagActivity_CL' }
            $row = New-SIConnectorJobRunRecord -Name 'asset-tagging' -Kind 'defender-azure-entra' -RunId $tagRunId -StartedAt $tagStarted -WhatIf (-not [bool]$Apply) `
                       -Outcome $(if ($tagError) { 'failed' } else { 'success' }) -Errors $(if ($tagError) { 1 } else { 0 }) -Why $why -ErrorText $tagError
            $w = Write-SIConnectorRun -Store $tagStore -Record $row
            if ($w) { Write-Host ('[asset-tagging] the run could not be recorded in cfg.ConnectorRun: {0}' -f $w) }
        }
    } catch { Write-Host ('[asset-tagging] the run could not be recorded -- {0}' -f $_.Exception.Message) }
}
