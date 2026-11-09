#Requires -Version 7.0
<#
    The CI build speed suites' SHARED SET-UP (SIv3-CiBuildSpeed, -Sql, -Threads): dot-sourced in each file's BeforeAll, so each
    file builds the same before-world, model, rules and records. Split 2026-11-08 (framework 12.1 rule 10: no runner execution
    over ~2 min; one file took 450-530 s on the Linux runner). Restore-CiPerfSpeedGlobals in each AfterAll.
#>
$script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ($PSVersionTable.PSVersion.Major -lt 7) { return }
. (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
. (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
. (Join-Path $script:SIRoot 'tests\fixtures\ci-perf\CiPerfFixture.ps1')
$script:World = New-CiPerfBeforeWorld -SIRoot $script:SIRoot -BeforeFile (Join-Path $script:SIRoot 'tests\fixtures\ci-perf\before\ci-build.d3b2fe9ed.txt')
. ([scriptblock]::Create($script:World.Text))
# one thread: the old enrichment's threads would load the CURRENT files (the threads are tested on their own below)
$script:ParallelWas = $global:SI_CiParallel
$global:SI_CiParallel = 'off'
# #406 (CI build version 10): the build as it was had no time rule in its lifecycle -- with a seen window longer than any
# record's age the designed lifecycle decides exactly what it decided (active / not seen / retired), so every other field
# is compared as before; the lifecycle's own evidence (since, reason, days, a link's reason) is new and taken off
# (Remove-CiPerfLifecycleEvidence). The time rule itself is SIv3-CiLifecycle.Tests.ps1.
$script:SeenWas = $global:SI_Pro_CmdbSql_SeenWithinDays
$global:SI_Pro_CmdbSql_SeenWithinDays = 100000
function script:Remove-CiPerfLifecycleEvidence($docs) {
    foreach ($d in @($docs)) {
        if ($null -eq $d) { continue }
        foreach ($k in 'si_lifecycle_since', 'si_lifecycle_reason', 'si_not_seen_days') { if ($d.Contains($k)) { $d.Remove($k) } }
        foreach ($l in @($d['si_linked_objects'])) { if ($l -and $l.PSObject.Properties['reason']) { $l.PSObject.Properties.Remove('reason') } }
    }
}
$script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
$script:Rules = @(Get-SICiBuildRules -Log { param($l, $m) })
# the records' times from the hour before now (the database build reads the last 30 days); the build's clock 5 minutes on
$script:T = [datetime]::SpecifyKind([datetime]::UtcNow.Date.AddHours([datetime]::UtcNow.Hour), [DateTimeKind]::Utc).AddHours(-1)
$script:Now = $script:T.AddMinutes(5)
$script:Recs = @((Write-CiPerfTenant -Scale 0.005 -Model $script:Model -Collect -T $script:T).Rows)
function script:Groups { $g = Get-SICiGroups -Records $script:Recs; @($g.Groups) }
$script:Feeds = Get-SIFeedLatest -Records $script:Recs
function script:Canon($x) { ConvertTo-CiPerfCanonicalJson (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $x -Depth 20 -Compress) -AsHashtable) }

function script:Restore-CiPerfSpeedGlobals {
    if ($PSVersionTable.PSVersion.Major -ge 7) { $global:SI_CiParallel = $script:ParallelWas; $global:SI_Pro_CmdbSql_SeenWithinDays = $script:SeenWas }
}
