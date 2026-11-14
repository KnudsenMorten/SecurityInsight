#Requires -Version 5.1
<#
    framework SEC-LANE-1 (the products' agreed change G5) -- THE PIPELINE RUNNER'S WAKE-UP STARTS THE UPDATER FOR A WAITING
    IMAGE-ONLY SECURITY RELEASE (engine/_shared/SI-ImageOnlyWake.ps1, wired in engine/flow/Invoke-SIJobFlowRun.ps1).

    What must hold: an image patch of the release this install runs, while no updater runs = the updater started ONCE for
    that release (SI_UPDATER_MODE image-only) with one plain line; a code release, nothing released, no ring, an updater that
    runs = nothing started and nothing said; Invardia asked at most every 15 minutes; a start Azure refuses is one WARN line
    and tried again later; the runner calls it on EVERY wake-up, the one during a run too (it never touches the run).
    Offline: every seam is a fake.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ImageOnlyWake.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-14T10:00:00', [DateTimeKind]::Utc)
    function script:New-Wake([string]$Version = '3.1.17.1', [string]$Action = 'update', [object[]]$Execs = @(), [string]$Mark = '', [switch]$StartFails) {
        $w = @{ Mark = $Mark; Asks = 0; Starts = 0 }
        $w.Args = @{
            Installed = '3.1.17'; Ring = 2; NowUtc = $script:Now
            Ask = { $w.Asks++; [pscustomobject]@{ Action = $Action; Version = $Version; Reason = 'test' } }.GetNewClosure()
            ReadMark = { $w.Mark }.GetNewClosure()
            SaveMark = { param($Json) $w.Mark = $Json }.GetNewClosure()
            Executions = { $Execs }.GetNewClosure()
            Start = { $w.Starts++; if ($StartFails) { throw 'HTTP 403 AuthorizationFailed' }; 'caj-si-updater-abc12' }.GetNewClosure()
        }
        $w
    }
}

Describe 'Invoke-SIImageOnlyWakeCheck' {
    It 'an image patch of what runs, no updater running: the updater is started ONCE, one line, the mark recorded' {
        $w = New-Wake
        $a = $w.Args
        $r = Invoke-SIImageOnlyWakeCheck @a
        $r.Status | Should -Be 'started'; $r.Started | Should -BeTrue
        $r.Line | Should -Match 'image-only security update 3\.1\.17\.1 waits.*the updater is started now \(execution caj-si-updater-abc12\)'
        $w.Starts | Should -Be 1
        ($w.Mark | ConvertFrom-Json).version | Should -Be '3.1.17.1'
        # the next wake-ups: not asked again within 15 minutes; after that asked, but never started twice for that release
        $a.NowUtc = $script:Now.AddMinutes(5); (Invoke-SIImageOnlyWakeCheck @a).Status | Should -Be 'not-due'
        $a.NowUtc = $script:Now.AddMinutes(20); $r3 = Invoke-SIImageOnlyWakeCheck @a
        $r3.Status | Should -Be 'started-already'; $r3.Line | Should -Be ''
        $w.Starts | Should -Be 1; $w.Asks | Should -Be 2
    }
    It 'NEGATIVE <Case>: nothing started, nothing said' -ForEach @(
        @{ Case = 'a code release'; Version = '3.1.18'; Action = 'update'; Status = 'not-image-only' }
        @{ Case = 'nothing released'; Version = ''; Action = 'none'; Status = 'none' }
        @{ Case = 'the release that runs'; Version = '3.1.17'; Action = 'current'; Status = 'none' }
        @{ Case = 'an older image patch'; Version = '3.1.16.4'; Action = 'update'; Status = 'not-image-only' }
    ) {
        $w = New-Wake -Version $Version -Action $Action
        $a = $w.Args
        $r = Invoke-SIImageOnlyWakeCheck @a
        $r.Status | Should -Be $Status; $r.Line | Should -Be ''; $w.Starts | Should -Be 0
    }
    It 'an updater that runs already: not started (it takes the release itself), asked again later' {
        $w = New-Wake -Execs @([pscustomobject]@{ name = 'caj-si-updater-x'; properties = [pscustomobject]@{ status = 'Running'; startTime = $script:Now.AddMinutes(-3).ToString('o') } })
        $a = $w.Args
        (Invoke-SIImageOnlyWakeCheck @a).Status | Should -Be 'updater-running'
        $w.Starts | Should -Be 0
    }
    It 'no ring recorded: Invardia is not asked' {
        $w = New-Wake; $a = $w.Args; $a.Ring = $null
        (Invoke-SIImageOnlyWakeCheck @a).Status | Should -Be 'no-ring'
        $w.Asks | Should -Be 0
    }
    It 'a start Azure refuses: one WARN line, the release not marked as started (a later wake-up tries again); never a throw' {
        $w = New-Wake -StartFails
        $a = $w.Args
        $r = Invoke-SIImageOnlyWakeCheck @a
        $r.Status | Should -Be 'start-failed'; $r.Line | Should -Match 'could not be started \(HTTP 403'
        ($w.Mark | ConvertFrom-Json).version | Should -Be ''
        $a.Ask = { throw 'boom' }; $a.NowUtc = $script:Now.AddHours(1)
        { $script:R2 = Invoke-SIImageOnlyWakeCheck @a } | Should -Not -Throw
        $script:R2.Status | Should -Be 'error'
    }
    It 'the mark fits cfg.InstallState (400 characters)' {
        (ConvertTo-SIImageOnlyWakeMark -Mark ([pscustomobject]@{ AskedUtc = $script:Now; Version = '3.1.17.1'; StartedUtc = $script:Now; Execution = ('e' * 500) })).Length | Should -BeLessOrEqual 400
    }
}

Describe 'the pipeline runner calls it on every wake-up (Invoke-SIJobFlowRun.ps1, its source)' {
    BeforeAll { $script:Src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1') }
    It 'during a run (the housekeeping-only wake-up, before it ends) and on a normal wake-up (before the queue)' {
        $hk = [regex]::Match($script:Src, 'if \(\$housekeepingOnly\) \{\r?\n    # SEC-LANE-1').Index
        $hk | Should -BeGreaterThan 0
        $script:Src.IndexOf("& `$imageOnlyWake ''", $hk) | Should -BeLessThan $script:Src.IndexOf('exit 0', $hk)
        $d = $script:Src.IndexOf('$drain = Invoke-SIPipelineDrain')
        $script:Src.IndexOf('& $imageOnlyWake $updaterJobName') | Should -BeLessThan $d
        $script:Src.IndexOf('& $imageOnlyWake $updaterJobName') | Should -BeGreaterThan 0
    }
    It 'reads the updater''s own update route (Request-SIInvardiaManifest, the code kind) and starts the updater with SI_UPDATER_MODE image-only' {
        $script:Src | Should -Match ([regex]::Escape("Request-SIInvardiaManifest -Kind code -Seams @{ ReadSecret = `$rs } -RunningVersion `$siVersion -Ring `$iwRing"))
        $script:Src | Should -Match ([regex]::Escape("New-SIUpdateNowStartTemplate -Job `$uj -Mode 'image-only'"))
    }
}
