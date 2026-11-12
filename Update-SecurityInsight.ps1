<#
.SYNOPSIS
    Retired. SecurityInsight -- Pro and Community alike -- is updated by its updater job in Azure.

.DESCRIPTION
    SecurityInsight 3 updates every install the same way: the updater job in your own subscription takes the release
    Invardia signs for your update ring at its nightly run, checks its signature, size and SHA-256, and rolls the jobs and
    the web app (restoring the previous version on any failure). There is nothing to run here.

    An install without the updater job creates it once with:  .\setup\Install-SIUpdaterJob.ps1

    REMOVE-ME: this file stays only so that an updater released before 3.1, which requires a release to carry it, still
    accepts the next release. Remove it once no supported install runs such an updater.

.EXAMPLE
    .\setup\Install-SIUpdaterJob.ps1
#>
[CmdletBinding()]
param(
    # accepted and ignored: older schedules call this file with these parameters
    [Parameter(ValueFromRemainingArguments)] [object[]]$Ignored
)
Write-Host 'SecurityInsight is updated by its updater job in Azure (Pro and Community alike) -- nothing to run here.'
Write-Host 'An install without the updater job creates it once with: .\setup\Install-SIUpdaterJob.ps1'
exit 0
