#Requires -Version 5.1
<#
    #1391 / #1392 -- the owner's click test on internal 3.1.50 (2026-11-25, "we cannot have that admins cannot use the gui").
    #1391: caj-si-job-requests answered BOTH requests it got with "failed ... the request could not be answered: Cannot index
    into a null array". The container entrypoint (Start-SIInContainer.ps1) loads engine\_shared\SI-JobStartRequest.ps1 for
    the start-request claim and then runs the engine as ITS OWN script; the engine found Get-SIJobStartRequestAllowed defined,
    did not load the file again, and the function read $script:SIJobStartRequestAllowed from the ENGINE's script scope, where
    it was never set. Every web app request on the queue failed this way (Run now, a step, Stop, Update now, Test mail ...).
    #1392: the same for engine\_shared\SI-Guard.ps1 (loaded by the entrypoint's collection run gate): "The property 'Catalog'
    cannot be found on this object" in the privilege tier classifier's log, and every guard event of such an engine refused.
    And a step a person's CANCEL closed is not a failed step.
    These tests load the files EXACTLY as the container does: a parent script dot-sources the shared files, then runs the
    engine as a child script. The messages are tests\fixtures\job-request-web-messages.json -- the web app's own writer
    (QueuedStartJobsClient.Message) is held to the same file by JobRequestQueueTests (both sides). Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Fixture = Join-Path $script:SIRoot 'tests\fixtures\job-request-web-messages.json'
    $script:Parent = Join-Path $TestDrive 'entrypoint.ps1'
    $script:Child = Join-Path $TestDrive 'engine.ps1'
    # the container entrypoint: the shared files at ITS script level, then the engine as its own script
    Set-Content -LiteralPath $script:Parent -Encoding UTF8 -Value @'
param([string]$SIRoot, [string]$Child, [string]$FixturePath, [string]$Mode)
$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-JobStartRequest.ps1'))
. ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-Guard.ps1'))
& $Child -SIRoot $SIRoot -FixturePath $FixturePath -Mode $Mode
'@
    Set-Content -LiteralPath $script:Child -Encoding UTF8 -Value @'
param([string]$SIRoot, [string]$FixturePath, [string]$Mode)
$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }
if ($Mode -eq 'guard') {
    # an engine that records its run health: Send-SIRunHealthRow.ps1 loads SI-Guard.ps1 only when it is not there yet
    if (-not (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-Guard.ps1')) }
    $cat = Get-SIGuardCatalog
    $ev = New-SIGuardEvent -GuardId 'licence.state.grace' -Outcome warning
    return [pscustomobject]@{ Guards = @($cat.guards).Count; GuardId = [string]$ev.GuardId; Mails = [bool](Test-SIGuardOutcomeMails -Event $ev); Outcome = (ConvertTo-SIGuardWireOutcome -Outcome 'warning') }
}
if ($Mode -eq 'runner') {
    # the pipeline runner (#1292): Invoke-SIJobFlowRun.ps1 loads SI-JobStartRequest.ps1 only when it is not there yet
    if (-not (Get-Command -Name Invoke-SIJobRunnerStarts -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-JobStartRequest.ps1')) }
    $seen = @{}
    $null = Invoke-SIJobRunnerStarts -Invoke { param($s, $p, $m) if ($p -and $p.ContainsKey('MaxAge')) { $seen.MaxAge = $p.MaxAge }; @() } -Start { param($j) 'x' }
    $d = Get-SIJobRunnerStartDecision -Request ([pscustomobject]@{ JobName = 'caj-si-close-loop-mail'; EnvJson = '{"SI_SNOW_VERIFY":"sn-1"}' }) -Installed @('caj-si-close-loop-mail')
    return [pscustomobject]@{ MaxAge = $seen.MaxAge; Ok = [bool]$d.Ok; Why = [string]$d.Why }
}
# (names unlike the job's own locals: a seam scriptblock reads the job function's $msgs first)
# the job request job, as engine\job-requests\Invoke-SIJobRequests.ps1 loads it
if (-not (Get-Command -Name New-SIJobStartTemplate -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-UpdaterStart.ps1')) }
. ([IO.Path]::Combine($SIRoot, 'engine', 'job-requests', 'SI-JobRequests.ps1'))
$now = [datetime]::SpecifyKind([datetime]'2026-11-25T22:21:30', 'Utc')
$i = 0
$fixtureMsgs = @(foreach ($e in @(Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json)) {
    $i++; [pscustomobject]@{ Id = ('q-{0:d2}' -f $i); PopReceipt = "pr-$i"; Inserted = $now.AddSeconds(-60 + $i); Text = [string]$e.message }
})
$started = New-Object System.Collections.Generic.List[object]
$r = Invoke-SIJobRequestsJob -Receive { , $fixtureMsgs } -Remove { param($m) } -NowUtc $now `
    -Installed { @('caj-si-flow', 'caj-si-risk-analysis', 'caj-si-updater', 'caj-si-close-loop-mail', 'caj-si-templates', 'caj-si-asset-vulnerabilities', 'caj-si-asset-vulns-servicenow', 'caj-si-job-requests') } `
    -Start { param($Job, $Env) $started.Add([pscustomobject]@{ Job = $Job; Names = @($Env.Keys) }); "$Job-exec" }
[pscustomobject]@{ ExitCode = $r.ExitCode; Lines = @($r.Lines); Results = @($r.Results); Started = $started.ToArray(); Count = $fixtureMsgs.Count }
'@
}

Describe '#1391 every button''s message, loaded as the container loads the job request job' {
    It 'the fixture is there and lists every button' {
        $f = @(Get-Content -LiteralPath $script:Fixture -Raw | ConvertFrom-Json)
        $f.Count | Should -BeGreaterOrEqual 10
        @($f | ForEach-Object { [string]$_.job } | Select-Object -Unique) | Should -Contain 'caj-si-updater'
    }
    It 'starts every one of them -- never "Cannot index into a null array"' {
        $o = & $script:Parent -SIRoot $script:SIRoot -Child $script:Child -FixturePath $script:Fixture -Mode 'queue'
        $o.ExitCode | Should -Be 0
        $o.Count | Should -BeGreaterOrEqual 10
        @($o.Results).Count | Should -Be $o.Count     # one answer per message (never a vacuous pass)
        ($o.Lines -join "`n") | Should -Not -Match 'null array'
        @($o.Results | Where-Object { $_.Result -ne 'started' } | ForEach-Object { '{0}: {1}' -f $_.Id, $_.Detail }) | Should -BeNullOrEmpty
        @($o.Started).Count | Should -Be $o.Count
        # each line names the web app's request id and the person, never the bare queue message
        foreach ($l in $o.Lines) { $l | Should -Match '^JOB-REQUEST id=[0-9a-f]{12} job=caj-si-[a-z-]+ by=admin@contoso\.com result=started ' }
        # the Stop carries the runner's cancel values; the test mail its verify run
        @($o.Started | Where-Object { $_.Names -contains 'SI_FLOW_CANCEL_RUN' }).Count | Should -Be 1
        @($o.Started | Where-Object { $_.Job -eq 'caj-si-close-loop-mail' -and $_.Names -contains 'SI_MAIL_VERIFY' }).Count | Should -Be 1
    }
}

Describe '#1391 the Resend page''s four names -- exactly those, nothing like them' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-UpdaterStart.ps1')
        . (Join-Path $script:SIRoot 'engine\job-requests\SI-JobRequests.ps1')
        $script:RNow = [datetime]::SpecifyKind([datetime]'2026-11-25T22:21:30', 'Utc')
        $script:RInstalled = @('caj-si-asset-vulnerabilities', 'caj-si-asset-vulns-servicenow', 'caj-si-flow')
        function script:New-R([string]$Job, [hashtable]$Env) {
            ([ordered]@{ SI_JOBREQ_ACTION = 'start'; SI_JOBREQ_JOB = $Job; SI_JOBREQ_ENV = $Env; SI_JOBREQ_ID = 'r9'; SI_AUDIT_STARTED_BY = 'admin@contoso.com' }) | ConvertTo-Json -Compress -Depth 5
        }
    }
    It 'every Resend message of the fixture (send again, undo, ServiceNow) is started with its values' {
        $res = @(Get-Content -LiteralPath $script:Fixture -Raw | ConvertFrom-Json) | Where-Object { $_.button -like 'Resend*' }
        @($res).Count | Should -Be 3
        foreach ($e in $res) {
            $r = Invoke-SIJobRequestsJob -Receive { , @([pscustomobject]@{ Id = 'q'; PopReceipt = 'p'; Inserted = $script:RNow.AddSeconds(-10); Text = [string]$e.message }) } `
                -Remove { param($x) } -NowUtc $script:RNow -Installed { $script:RInstalled } -Start { param($j, $v) 'exec-' + (@($v.Keys) -join '+') }
            $r.Results[0].Result | Should -Be 'started' -Because $e.button
            $r.Results[0].Detail | Should -Match 'SI_VulnSync_SendId' -Because $e.button
            $r.Results[0].Detail | Should -Match 'SI_VulnSync_Connector' -Because $e.button
        }
    }
    It 'NEGATIVE: any other mixed-case name is still refused as not an environment variable name' {
        foreach ($bad in 'SI_VulnSync_Other', 'SI_VulnSync_sendid', 'si_vulnsync_sendid', 'SI_Vulnsync_SendId', 'SI_Flow_Step', 'Path') {
            $r = Invoke-SIJobRequestsJob -Receive { , @([pscustomobject]@{ Id = 'q'; PopReceipt = 'p'; Inserted = $script:RNow.AddSeconds(-10); Text = (New-R 'caj-si-asset-vulnerabilities' @{ $bad = '1' }) }) } `
                -Remove { param($x) } -NowUtc $script:RNow -Installed { $script:RInstalled } -Start { param($j, $v) 'x' }
            $r.Results[0].Result | Should -Be 'refused' -Because $bad
            $r.Results[0].Detail | Should -Match 'is not an environment variable name' -Because $bad
        }
    }
    It 'NEGATIVE: the four names only on the connector jobs -- refused on any other job' {
        $r = Invoke-SIJobRequestsJob -Receive { , @([pscustomobject]@{ Id = 'q'; PopReceipt = 'p'; Inserted = $script:RNow.AddSeconds(-10); Text = (New-R 'caj-si-flow' @{ SI_VulnSync_SendId = '1' }) }) } `
            -Remove { param($x) } -NowUtc $script:RNow -Installed { $script:RInstalled } -Start { param($j, $v) 'x' }
        $r.Results[0].Result | Should -Be 'refused'
        $r.Results[0].Detail | Should -Match 'SI_VulnSync_SendId may not be set on caj-si-flow'
    }
}

Describe '#1391 a request that breaks in an unforeseen way is said with what is known of it' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-UpdaterStart.ps1')
        . (Join-Path $script:SIRoot 'engine\job-requests\SI-JobRequests.ps1')
    }
    It 'names the request id, its kind, its job, who asked and the step it broke in' {
        $now = [datetime]::SpecifyKind([datetime]'2026-11-25T22:21:30', 'Utc')
        $text = (@(Get-Content -LiteralPath $script:Fixture -Raw | ConvertFrom-Json) | Where-Object { $_.job -eq 'caj-si-updater' } | Select-Object -First 1).message
        $m = [pscustomobject]@{ Id = 'aa0e83ff-05dd-4e55-84c6-633c9d987cba'; PopReceipt = 'p'; Inserted = $now.AddSeconds(-20); Text = $text }
        $r = Invoke-SIJobRequestsJob -Receive { , @($m) } -Remove { param($x) } -NowUtc $now -Installed { @('caj-si-updater') } -Start { param($j, $e) 'x' } `
            -Say { param($l, $t) } -ErrorAction Stop
        $r.Results[0].Result | Should -Be 'started'
        # an unforeseen break (the job list answers something that cannot be compared): said with the request's own words
        Mock Get-SIJobRequestDecision { throw 'Cannot index into a null array.' }
        $r = Invoke-SIJobRequestsJob -Receive { , @($m) } -Remove { param($x) } -NowUtc $now -Installed { @('caj-si-updater') } -Start { param($j, $e) 'x' }
        $r.Results[0].Result | Should -Be 'failed'
        $r.Lines[0] | Should -Match '^JOB-REQUEST id=f6a1b2c3d4e5 job=caj-si-updater by=admin@contoso\.com result=failed '
        $r.Lines[0] | Should -Match 'kind start'
        $r.Lines[0] | Should -Match 'queue message aa0e83ff-05dd-4e55-84c6-633c9d987cba'
        $r.Lines[0] | Should -Match 'while deciding whether this install may start it'
        $r.Lines[0] | Should -Match 'Nothing was started'
    }
}

Describe '#1392 the guard file, loaded by the entrypoint, works from the engine''s own script' {
    It 'reads its catalog and builds an event -- no "property Catalog cannot be found", no "not a guard source ()"' {
        $o = & $script:Parent -SIRoot $script:SIRoot -Child $script:Child -FixturePath $script:Fixture -Mode 'guard'
        $o.Guards | Should -BeGreaterThan 0
        $o.GuardId | Should -Be 'licence.state.grace'
        $o.Mails | Should -BeTrue
        $o.Outcome | Should -Be 'warning'
    }
}

Describe '#1391 the pipeline runner''s starts for a person (#1292), loaded as the container loads the runner' {
    It 'reads its max age (30, never 0) and its allowed jobs' {
        $o = & $script:Parent -SIRoot $script:SIRoot -Child $script:Child -FixturePath $script:Fixture -Mode 'runner'
        $o.MaxAge | Should -Be 30
        $o.Ok | Should -BeTrue
    }
}

Describe '#1392 a step a cancel closed is not a failed step' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-ErrorClass.ps1')
        . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    }
    It 'Interrupted by the cancel = not failed; Failed / TimedOut / Interrupted otherwise = failed' {
        Test-SIJobFlowStepFailed -Step ([pscustomobject]@{ State = 'Interrupted'; ErrorClass = 'cancelled' }) | Should -BeFalse
        Test-SIJobFlowStepFailed -Step ([pscustomobject]@{ State = 'Interrupted'; ErrorClass = 'stopped' }) | Should -BeTrue
        Test-SIJobFlowStepFailed -Step ([pscustomobject]@{ State = 'Failed'; ErrorClass = 'job-failed' }) | Should -BeTrue
        Test-SIJobFlowStepFailed -Step ([pscustomobject]@{ State = 'TimedOut'; ErrorClass = 'timeout' }) | Should -BeTrue
        Test-SIJobFlowStepFailed -Step ([pscustomobject]@{ State = 'Success'; ErrorClass = '' }) | Should -BeFalse
        Test-SIJobFlowStepFailed -Step $null | Should -BeFalse
    }
    It 'a cancelled step is said by its own record, never by a stray line of its log' {
        $st = [pscustomobject]@{ Job = 'caj-si-ptc'; State = 'Interrupted'; ErrorClass = 'cancelled'; Error = 'stopped: the run was cancelled by admin@contoso.com: test' }
        $log = @('[2026-11-25 22:21:50] [SUCCESS] Skipping rebuild -- existing catalog is 12.9h old (<24h).',
                 'PS>TerminatingError(): "The property ''Catalog'' cannot be found on this object. Verify that the property exists and can be set."')
        $f = Get-SIJobFlowStepFailure -Step $st -LogLines $log
        $f.Text | Should -Be 'stopped: the run was cancelled by admin@contoso.com: test'
        $f.Text | Should -Not -Match 'TerminatingError'
    }
    It 'the runner picks its failed step with that rule (Invoke-SIJobFlowRun.ps1)' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1') -Raw
        $src | Should -Match '\$pipeBad = @\(\$pipeResult\.Steps \| Where-Object \{ Test-SIJobFlowStepFailed -Step \$_ \}'
    }
}
