#Requires -Version 5.1
<#
    CR8 (framework DOCS/REQUIREMENTS.md 12.11f item 1, SI #659): THE WEB APP NEVER CHANGES A JOB -- with start-only rights a
    job trigger change is a cfg.JobTriggerRequest row, and the pipeline runner applies it as its own identity.
    What must hold (engine\_shared\SI-JobTriggerRequests.ps1, on a fake database + a fake ARM):
      * only a caj-si-* job of THIS install, only to-manual / to-schedule, only a 5-field cron; else REFUSED, nothing sent;
      * a request older than a day is EXPIRED, never applied late;
      * the PATCH carries the trigger and the tags only (never the image, the env, the secrets);
      * the change is READ BACK; a change that does not read back is FAILED;
      * every row is recorded (AppliedUtc + Outcome + Detail); an ARM error is recorded and the run goes on (never throws);
      * the runner applies them at every wake-up in a container with a Pro database, before the pipeline.
    OFFLINE. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobTriggerRequests.ps1')
    $script:Base = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs'

    function New-FakeJob([string]$Trigger, [string]$Cron, [hashtable]$Tags = @{}) {
        $cfg = [ordered]@{ triggerType = $Trigger; replicaTimeout = 3600 }
        if ($Trigger -eq 'Schedule') { $cfg.scheduleTriggerConfig = [ordered]@{ cronExpression = $Cron; parallelism = 1; replicaCompletionCount = 1 } }
        else { $cfg.manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } }
        ([ordered]@{ name = 'x'; tags = $Tags; properties = [ordered]@{ configuration = $cfg; template = [ordered]@{ containers = @([ordered]@{ image = 'acr/si:1'; env = @(@{ name = 'A'; value = 'b' }) }) } } } | ConvertTo-Json -Depth 10) | ConvertFrom-Json
    }

    function New-FakeWorld([object[]]$Rows, [hashtable]$Jobs, [switch]$NoApply, [switch]$ArmThrows) {
        $world = [pscustomobject]@{ Rows = $Rows; Jobs = $Jobs; Calls = New-Object System.Collections.Generic.List[object]; Records = New-Object System.Collections.Generic.List[object] }
        $na = [bool]$NoApply; $at = [bool]$ArmThrows; $mk = ${function:New-FakeJob}
        $inv = { param($sql, $p, $mode) if ($mode -eq 'reader') { return $world.Rows }; $world.Records.Add([pscustomobject]@{ Sql = $sql; P = $p }); 1 }.GetNewClosure()
        $world | Add-Member -NotePropertyName Invoke -NotePropertyValue $inv
        $arm = { param($m, $path, $body)
                $world.Calls.Add([pscustomobject]@{ M = $m; Path = $path; Body = $body })
                if ($at -and $m -eq 'PATCH') { throw 'ARM PATCH returned 409: the job is busy' }
                $name = ($path -split '/')[-1]
                if ($m -eq 'GET') { return $world.Jobs[$name] }
                if (-not $na) {
                    $c = $body.properties.configuration
                    $world.Jobs[$name] = & $mk ([string]$c.triggerType) $(if ($c.PSObject.Properties['scheduleTriggerConfig']) { [string]$c.scheduleTriggerConfig.cronExpression } else { '' })
                }
                $null }.GetNewClosure()
        $world | Add-Member -NotePropertyName Arm -NotePropertyValue $arm
        $world
    }
    function Row($id, $job, $act, $cron, $age = 1) { [pscustomobject]@{ RequestId = $id; JobName = $job; Action = $act; Cron = $cron; RequestedBy = 'admin@example.test'; AgeMinutes = $age } }
}

Describe 'SIv3-JobTriggerRequests: the pipeline runner applies what the web app asked for' {
    It 'a disable request becomes Manual, read back and recorded applied; the PATCH carries the trigger and tags only' {
        $w = New-FakeWorld -Rows @(Row 1 'caj-si-risk-analysis' 'to-manual' '') -Jobs @{ 'caj-si-risk-analysis' = (New-FakeJob 'Schedule' '0 3 * * *') }
        $r = @(Invoke-SIJobTriggerRequests -Invoke $w.Invoke -Arm $w.Arm -Base $script:Base -Installed @('caj-si-risk-analysis') -Sleep { })
        $r[0].Outcome | Should -Be 'applied'
        $patch = @($w.Calls | Where-Object { $_.M -eq 'PATCH' })
        $patch.Count | Should -Be 1
        $patch[0].Path | Should -Be "$($script:Base)/caj-si-risk-analysis"
        $json = $patch[0].Body | ConvertTo-Json -Depth 10 -Compress
        $json | Should -Not -Match '"template"|"image"|"env"|"secrets"'
        $json | Should -Match '"si-disabled-cron":"0 3 \* \* \*"'
        $w.Records[0].P.Outcome | Should -Be 'applied'
        $w.Records[0].P.Id | Should -Be 1
        $w.Records[0].Sql | Should -Match 'AppliedUtc IS NULL'
    }
    It 'a schedule request with a cron is applied and read back with that cron' {
        $w = New-FakeWorld -Rows @(Row 2 'caj-si-close-loop' 'to-schedule' '30 2 * * *') -Jobs @{ 'caj-si-close-loop' = (New-FakeJob 'Manual' '' @{ 'si-disabled-cron' = '0 5 * * *' }) }
        (@(Invoke-SIJobTriggerRequests -Invoke $w.Invoke -Arm $w.Arm -Base $script:Base -Installed @('caj-si-close-loop') -Sleep { }))[0].Outcome | Should -Be 'applied'
        $w.Jobs['caj-si-close-loop'].properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '30 2 * * *'
    }
    It 'refuses a job that is not this install''s, a non-SI name, an unknown action and a bad cron -- and sends nothing' {
        $rows = @((Row 3 'caj-si-other' 'to-manual' ''), (Row 4 'ca-pim-web' 'to-manual' ''), (Row 5 'caj-si-risk-analysis' 'delete' ''), (Row 6 'caj-si-risk-analysis' 'to-schedule' 'every day'))
        $w = New-FakeWorld -Rows $rows -Jobs @{ 'caj-si-risk-analysis' = (New-FakeJob 'Schedule' '0 3 * * *') }
        $r = @(Invoke-SIJobTriggerRequests -Invoke $w.Invoke -Arm $w.Arm -Base $script:Base -Installed @('caj-si-risk-analysis') -Sleep { })
        @($r | ForEach-Object Outcome) | Should -Be @('refused', 'refused', 'refused', 'refused')
        $w.Calls.Count | Should -Be 0
        $w.Records.Count | Should -Be 4
    }
    It 'a request older than a day is expired, never applied late' {
        $w = New-FakeWorld -Rows @(Row 7 'caj-si-risk-analysis' 'to-manual' '' (25 * 60)) -Jobs @{ 'caj-si-risk-analysis' = (New-FakeJob 'Schedule' '0 3 * * *') }
        (@(Invoke-SIJobTriggerRequests -Invoke $w.Invoke -Arm $w.Arm -Base $script:Base -Installed @('caj-si-risk-analysis') -Sleep { }))[0].Outcome | Should -Be 'expired'
        $w.Calls.Count | Should -Be 0
    }
    It 'a change that does not read back is failed; an ARM error is failed and recorded; neither throws' {
        $w = New-FakeWorld -Rows @(Row 8 'caj-si-risk-analysis' 'to-manual' '') -Jobs @{ 'caj-si-risk-analysis' = (New-FakeJob 'Schedule' '0 3 * * *') } -NoApply
        (@(Invoke-SIJobTriggerRequests -Invoke $w.Invoke -Arm $w.Arm -Base $script:Base -Installed @('caj-si-risk-analysis') -Sleep { }))[0].Outcome | Should -Be 'failed'
        $w2 = New-FakeWorld -Rows @(Row 9 'caj-si-risk-analysis' 'to-manual' '') -Jobs @{ 'caj-si-risk-analysis' = (New-FakeJob 'Schedule' '0 3 * * *') } -ArmThrows
        $r = @(Invoke-SIJobTriggerRequests -Invoke $w2.Invoke -Arm $w2.Arm -Base $script:Base -Installed @('caj-si-risk-analysis') -Sleep { })
        $r[0].Outcome | Should -Be 'failed'
        $r[0].Detail | Should -Match '409'
        $w2.Records[0].P.Outcome | Should -Be 'failed'
    }
    It 'a database without the table: nothing to do, no throw' {
        $inv = { param($s, $p, $m) throw "Invalid object name 'cfg.JobTriggerRequest'." }
        { Invoke-SIJobTriggerRequests -Invoke $inv -Arm { throw 'no' } -Base $script:Base -Installed @() } | Should -Not -Throw
    }
    It 'the runner applies them at every wake-up in a container with a Pro database, before the pipeline is read' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $s | Should -Match "Invoke-SIJobTriggerRequests -Invoke \`$proStore\.Invoke -Arm \`$armSeams\.Arm -Base \`$armSeams\.Base"
        $s.IndexOf('Invoke-SIJobTriggerRequests') | Should -BeLessThan $s.IndexOf('# ---- the definition ----')
    }
}
