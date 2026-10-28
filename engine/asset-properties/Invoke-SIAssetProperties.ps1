#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight_AssetProperties -- RETIRED as a collection job (REQUIREMENTS #412, operator 2026-10-06).

.DESCRIPTION
    Operator: "we dont pull in the same data twice (limited and full) ... if we do asset full, then it is 100% the same
    fields as limited - but with the extra metadata." Approved: one pull per source + history.

    This job used to read every source a SECOND time after the profilers (MDE, Entra devices / users / service
    principals, ARM, AD, Intune, Exposure Graph) and publish SI_AssetProperties_CL. It reads nothing any more: with
    SI_AssetProperties = 'full' each PROFILER reads each source once, builds its security row from that object, and
    publishes the whole object to SI_AssetProperties_CL with the profile row's CollectionTime
    (engine\asset-properties\_shared\SI-AssetPropertiesProfiler.ps1). The collection-change guard (#301) moved with it.

    What is left here, so an existing install never breaks:
      * a run ends SUCCESSFULLY at once and says the job is retired -- an install whose pipeline or timer still starts
        caj-si-asset-properties (or the VM task) gets a clean, explained no-op. The pipeline drops the step when it is
        read (config\job-flow.locked.json marks the job 'retired'); Bootstrap no longer creates the job.
      * -ReleaseCollectionChange <runId>: releases, ONCE, a collection-change hold from the command line (the same as Release
        in Operations > Guards (safety checks)). It is applied by the next run of the profiler that read the source.

.NOTES
    Solution : SecurityInsight
    Engine   : asset-properties (retired -- the profilers publish the full asset metadata)
    Docs     : docs/V3-ARCHITECTURE.md 3.6b, docs/REQUIREMENTS.md #301 / #408 / #412
#>
[CmdletBinding()]
param(
    # Kept so an existing launcher or container argument list still binds. They do nothing any more.
    [switch]$DryRun,
    [string[]]$Source,
    [int]$RowLimit = 0,
    [string]$JsonOutPath,

    # Release, ONCE, the collection-change hold of the run with this id (the run id the guard mail and Operations >
    # Guards show). Applied by the next run of the profiler that read the held source.
    [string]$ReleaseCollectionChange
)

$ErrorActionPreference = 'Stop'
Write-Host '[INFO] asset-properties is retired as a collection job: with SI_AssetProperties = ''full'' each profiler (endpoint, identity, azure) reads each source ONCE and publishes the full asset metadata itself, with the same CollectionTime as its profile rows. Nothing is read or published here.' -ForegroundColor Gray
Write-Host '[INFO] This job can be removed from the install: the pipeline drops it by itself, and a timer it still has can be turned off (Operations > Jobs).' -ForegroundColor Gray

if ($ReleaseCollectionChange) {
    try {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-cmdb/_shared/SI-VulnRelease.ps1')
        . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-Guard.ps1')
        $proInvoke = $null
        if (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue) { $proInvoke = Get-SIGuardProInvoke }
        $store = if ($proInvoke) { New-SIVulnReleaseStore -Invoke $proInvoke } else { New-SIVulnReleaseStore -Folder ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'state', 'asset-properties-held')) }
        if ($DryRun) {
            Write-Host ('[INFO] dry run -- the hold of run {0} would be released once' -f $ReleaseCollectionChange) -ForegroundColor Gray
        } else {
            $n = $store.Approve($ReleaseCollectionChange, '', ('command line ({0})' -f [Environment]::UserName))
            Write-Host ('[OK]   released the collection-change hold of run {0} for {1} source(s) -- applied by the next run of the profiler that read it' -f $ReleaseCollectionChange, $n) -ForegroundColor Green
        }
    } catch {
        throw ('asset-properties: the hold of run {0} could not be released -- {1}' -f $ReleaseCollectionChange, $_.Exception.Message)
    }
}
