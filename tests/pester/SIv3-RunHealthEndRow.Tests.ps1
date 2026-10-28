#Requires -Version 5.1
<#
    #317 -- EVERY ENGINE RUN THAT WROTE A START RECORD WRITES ITS END RECORD, success or failure, in every host.

    Live on ring 1 (2026-10-05) the Run health page said "Started -- no end row yet" for asset-datasync and asset-trend
    while the job flow said both steps ended OK. Two causes, both covered here:
      1. the page: a run's Start and End records carry the SAME CollectionTime (the run's start), and the page took the
         first of the two tied rows -- often the Start (fixed in the web app, RunHealthLatestTests);
      2. the data sync sent its END from two places in the middle of the run, so anything that failed between or after
         them (the guard calls, the refused-summary, the exec view, the audit step) left the START with no END.
         It now sends the END once, from a finally that encloses everything after the START -- as the trend does.
    The wiring is checked on the source (AST); the data sync's END is also checked by RUNNING the script's run-health
    region with stubbed work, in every outcome.
#>

BeforeAll {
    # #830: these tests drive the data sync's Log Analytics fallback for the Detailed collections (the report-row copy ON;
    # off by default, the data sync reads them from the database only -- SIv3-SqlOnlyReaders.Tests.ps1)
    $script:SendToLaBefore = $global:SendToLogAnalytics; $global:SendToLogAnalytics = $true
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    $script:DataSync = Join-Path $script:SIRoot 'engine\pro-data\Invoke-SIDataSync.ps1'
    $script:Trend = Join-Path $script:SIRoot 'engine\asset-trend\Invoke-SITrend.ps1'
    # The data sync is Pro: a Community copy does not carry it, so its cases are skipped there (Test-Path, never loaded).
    $script:HasDataSync = Test-Path -LiteralPath $script:DataSync

    function script:Test-IsEndCall {
        # `& $sendHealth 'End' ...` or `Stop-SIRunHealth ...`
        param($c)
        if ($c -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
        if ($c.GetCommandName() -eq 'Stop-SIRunHealth') { return $true }
        $e = @($c.CommandElements)
        return ($c.InvocationOperator -eq 'Ampersand' -and $e.Count -ge 2 -and $e[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $e[0].VariablePath.UserPath -eq 'sendHealth' -and $e[1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $e[1].Value -eq 'End')
    }
    function script:Test-IsStartCall {
        param($c)
        if ($c -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
        if ($c.GetCommandName() -eq 'Start-SIRunHealth') { return $true }
        $e = @($c.CommandElements)
        return ($c.InvocationOperator -eq 'Ampersand' -and $e.Count -ge 2 -and $e[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $e[0].VariablePath.UserPath -eq 'sendHealth' -and $e[1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $e[1].Value -eq 'Start')
    }
    function script:Get-EndShape {
        # Where the END calls sit, and whether the try whose finally holds the END encloses every statement after the START.
        param([string]$Path)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $ends = @($ast.FindAll({ param($n) Test-IsEndCall $n }, $true))
        $top = @($ast.EndBlock.Statements)
        $startIx = -1
        for ($i = 0; $i -lt $top.Count; $i++) { if (@($top[$i].FindAll({ param($n) Test-IsStartCall $n }, $true)).Count) { $startIx = $i; break } }
        $after = if ($startIx -ge 0) { @($top | Select-Object -Skip ($startIx + 1)) } else { @() }
        $tries = @($after | Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] })
        $last = if ($after.Count) { $after[$after.Count - 1] } else { $null }
        # statements between the START and that try may only be plain assignments of values (nothing that can fail a run)
        $between = @($after | Select-Object -First ([Math]::Max(0, $after.Count - 1)))
        $plain = @($between | Where-Object { $_ -isnot [System.Management.Automation.Language.AssignmentStatementAst] -or @($_.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)).Count }).Count -eq 0
        $inFinally = @($ends | Where-Object {
            $p = $_.Parent; $hit = $false
            while ($p) { if ($p -is [System.Management.Automation.Language.TryStatementAst] -and $p.Finally -and $p.Finally.Extent.StartOffset -le $_.Extent.StartOffset -and $_.Extent.EndOffset -le $p.Finally.Extent.EndOffset) { $hit = ($p -eq $last); break }; $p = $p.Parent }
            $hit
        })
        [pscustomobject]@{ Ends = $ends.Count; EndsInLastFinally = $inFinally.Count; StartFound = ($startIx -ge 0); LastIsTry = ($last -is [System.Management.Automation.Language.TryStatementAst]); OnlyPlainBetween = $plain }
    }
}

Describe 'WIRING: the END record is sent once, from a finally that encloses the whole run after the START' {
    It '<Name>' -TestCases @(
        @{ Name = 'asset-datasync (engine/pro-data/Invoke-SIDataSync.ps1)'; Key = 'DataSync' }
        @{ Name = 'asset-trend (engine/asset-trend/Invoke-SITrend.ps1)'; Key = 'Trend' }
    ) {
        param($Name, $Key)
        if ($Key -eq 'DataSync' -and -not $script:HasDataSync) { Set-ItResult -Skipped -Because 'the data sync is SecurityInsight Pro'; return }
        $path = if ($Key -eq 'DataSync') { $script:DataSync } else { $script:Trend }
        $s = Get-EndShape -Path $path
        $s.StartFound | Should -BeTrue
        $s.Ends | Should -Be 1                       # one END call in the whole script
        $s.LastIsTry | Should -BeTrue                # the run after the START is one try ...
        $s.EndsInLastFinally | Should -Be 1          # ... whose finally sends the END
        $s.OnlyPlainBetween | Should -BeTrue         # nothing between the START and that try can fail the run
    }

    It 'the trend still records nothing on a dry run, and its END says error when the body threw' {
        $src = Get-Content -Raw -LiteralPath $script:Trend
        $src | Should -Match "if \(-not \`$DryRun\) \{ \`$rh = Start-SIRunHealth -Engine 'asset-trend'"
        $src | Should -Match "\`$rhExit = 'error'; \`$rhMsg = if \(Get-Command -Name Get-SIErrorRecordSummary"
    }
}

Describe 'BEHAVIOUR: the data sync sends exactly one END in every outcome (the script''s own run-health region, run)' {
    BeforeAll {
        if (-not $script:HasDataSync) { return }
        # The region of the real script from the END state through its last line: the load, the guard calls, the
        # refused summary, the exec view, the audit step -- and the finally. Run with the work stubbed.
        $src = Get-Content -Raw -LiteralPath $script:DataSync
        $at = $src.IndexOf('$rhEnd = @{')
        $at | Should -BeGreaterThan 0
        $script:Region = $src.Substring($at)
        # a stand-in tree: the audit module the region dot-sources (the exec view's files are absent: that block says so
        # and goes on, as it does when a run cannot read the view)
        $script:FakeRoot = Join-Path ([IO.Path]::GetTempPath()) ('si-endrow-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $script:FakeRoot 'engine\pro-settings')
        Set-Content -LiteralPath (Join-Path $script:FakeRoot 'engine\pro-settings\SI-Audit.ps1') -Encoding ascii -Value @'
function Get-SIAuditActor { param($Job) 'job' }
function Write-SIAuditEvent { }
function Invoke-SIAuditRetention { param($Invoke, $Months, [switch]$DryRun, $Actor, $Log) $null }
'@
        # #639 made every step after the load report what it caught (SI-RunOutcome.ps1, the real pure functions) and
        # dot-source its own file: the Summary rows, the data-out outputs, the exec view, data quality. Each one is
        # stood in here as a step that ran clean, so the run's verdict is decided by the load and the refused summary
        # this suite drives -- a missing file would be a caught FAILED / WARNING issue and change every verdict.
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $script:FakeRoot 'engine\_shared'), (Join-Path $script:FakeRoot 'engine\pro-data\_shared'), (Join-Path $script:FakeRoot 'engine\_shared\data-sql'), (Join-Path $script:FakeRoot 'engine\data-out'), (Join-Path $script:FakeRoot 'engine\risk-analysis\_shared')
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-RunOutcome.ps1') -Destination (Join-Path $script:FakeRoot 'engine\_shared\SI-RunOutcome.ps1')
        $stubs = [ordered]@{
            'engine\_shared\data-sql\SI-DataSummary.ps1'     = 'function Invoke-SIDataSummarySync { param($Query, $Invoke, $EditionMajor, $Settings, [switch]$DryRun, $Log) [pscustomobject]@{ Problem = ''''; Failed = @() } }'
            'engine\data-out\SI-DataOut.ps1'                 = "function New-SIConnectorRegistryStore { `$null }`nfunction Invoke-SIDataOut { param(`$Invoke, `$Store, `$Edition, `$Log) @() }`nfunction Get-SIDataOutIssues { param(`$Results) @() }"
            'engine\risk-analysis\_shared\RA-AISummaryMode.ps1' = '# stand-in'
            'engine\risk-analysis\_shared\RA-ExecView.ps1'      = '# stand-in'
            'engine\_shared\data-sql\SI-DataExecView.ps1'    = 'function Invoke-SIDataExecViewSync { param($ReadView, $Invoke, $Top50BlobName, [switch]$DryRun, $Log) [pscustomobject]@{ Problem = '''' } }'
            'engine\pro-data\_shared\SI-DataQuality.ps1'     = 'function Invoke-SIDataQuality { param($Query, $Invoke, $SettingsInvoke, $Send, $RunId, $LookbackDays, [switch]$DryRun, $Log) [pscustomobject]@{ Lines = @() } }'
            # the Detailed mail with its stored Protection Score (the outbox step, SI-RaMailOutbox.ps1): a step that ran
            # clean with nothing waiting
            'engine\_shared\SI-ProtectionScore.ps1'          = '# stand-in'
            'engine\risk-analysis\_shared\RA-ReportMail.ps1' = '# stand-in'
            'engine\_shared\SI-MailTransport.ps1'            = "function Send-SIMail { @{ Sent = `$true; Error = '' } }`nfunction Get-SIMailSettings { @{ Mode = 'smtp' } }"
            'engine\_shared\data-sql\SI-RaMailOutbox.ps1'    = "function Update-SIRaExecViewProtection { param(`$Invoke, `$Log) `$null }`nfunction Set-SIRaMailSender { param(`$Invoke, `$MailSettings, `$Log) `$null }`nfunction Invoke-SIRaMailOutbox { param(`$Invoke, `$Role, `$Send, `$RunStartedUtc, `$KeyFigures, [switch]`$DryRun, `$Log) [pscustomobject]@{ Sent = 0; Failed = 0 } }"
        }
        foreach ($k in $stubs.Keys) { Set-Content -LiteralPath (Join-Path $script:FakeRoot $k) -Encoding ascii -Value $stubs[$k] }
        function script:Invoke-Region {
            param([scriptblock]$Core, [scriptblock]$Refused)
            $sent = New-Object System.Collections.ArrayList
            $sb = [scriptblock]::Create(@'
param($Region, $FakeRoot, $Core, $Refused, $Sent)
$ErrorActionPreference = 'Stop'
$siRoot = $FakeRoot; $here = Join-Path $FakeRoot 'engine\pro-data'; $DryRun = $false
$query = $null; $invoke = $null; $edition = '3'; $settings = [pscustomobject]@{ Server = 's'; Database = 'd' }; $log = { }; $responsibility = $null
$guardCommon = @{ Engine = 'datasync' }
function Write-DataOk ($m) { } ; function Write-DataInfo ($m) { } ; function Write-DataWarn ($m) { }
function Invoke-SIDataSyncCore { & $Core }
function Get-SIDataRefusedSummary { param($Result) & $Refused }
# #428 added the asset-kind count anomaly to the END (SI-DataModel.ps1); its own suite is SIv3-AssetKindCoverage -- here: none
function Get-SIDataKindCoverageSummary { param($Result) '' }
# one failed step does not cost the rest of the run: the data sync asks whether the pipeline started it after a failed
# step (its own suite is SIv3-RunGoesOnAfterFailedStep) -- here: a complete run
function Get-SIDataRunOnStored { param($Invoke, $Job) [pscustomobject]@{ OnStored = $false; Known = $true; Why = '' } }
# #881 the outputs are held when the findings per CI kept the previous set (SI-DataSync.ps1, loaded before the START; its own
# suite covers it) -- here: the newest set was stored
function Test-SIDataOutHoldForStaleFindings { param($DataModel) $false }
# #639: what the core caught (SI-DataSync.ps1); its own suite is SIv3-DataSync -- here: nothing
function Get-SIDataSyncIssues { param($Result) @() }
$sendHealth = { param([string]$phase, [string]$exit, [string]$err) [void]$Sent.Add([pscustomobject]@{ Phase = $phase; Exit = $exit; Message = $err }) }
. ([scriptblock]::Create($Region))
'@)
            $threw = $null
            try { & $sb $script:Region $script:FakeRoot $Core $Refused $sent } catch { $threw = $_.Exception.Message }
            [pscustomobject]@{ Sent = @($sent); Threw = $threw }
        }
    }
    AfterAll { if ($script:FakeRoot -and (Test-Path -LiteralPath $script:FakeRoot)) { Remove-Item -LiteralPath $script:FakeRoot -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'a good run: one END, success' {
        if (-not $script:HasDataSync) { Set-ItResult -Skipped -Because 'the data sync is SecurityInsight Pro'; return }
        $r = Invoke-Region -Core { [pscustomobject]@{ Loaded = @(1); Skipped = @(); Held = @(); Refused = @(); Untimed = @() } } -Refused { '' }
        $r.Threw | Should -BeNullOrEmpty
        @($r.Sent | Where-Object Phase -eq 'End').Count | Should -Be 1
        $r.Sent[-1].Exit | Should -Be 'success'
    }
    It 'a refused snapshot: one END, success-partial with the reason' {
        if (-not $script:HasDataSync) { Set-ItResult -Skipped -Because 'the data sync is SecurityInsight Pro'; return }
        $r = Invoke-Region -Core { [pscustomobject]@{ Loaded = @(); Skipped = @(); Held = @(); Refused = @(1); Untimed = @() } } -Refused { '1 collection refused' }
        @($r.Sent | Where-Object Phase -eq 'End').Count | Should -Be 1
        $r.Sent[-1].Exit | Should -Be 'success-partial'
        $r.Sent[-1].Message | Should -Be '1 collection refused'
    }
    It 'the load fails: one END, error, and the failure still reaches the caller' {
        if (-not $script:HasDataSync) { Set-ItResult -Skipped -Because 'the data sync is SecurityInsight Pro'; return }
        $r = Invoke-Region -Core { throw 'the database refused the load' } -Refused { '' }
        $r.Threw | Should -Match 'the database refused the load'
        @($r.Sent | Where-Object Phase -eq 'End').Count | Should -Be 1
        $r.Sent[-1].Exit | Should -Be 'error'
        $r.Sent[-1].Message | Should -Match 'the database refused the load'
    }
    It 'a failure AFTER the load (it left the START with no END before): one END, error' {
        if (-not $script:HasDataSync) { Set-ItResult -Skipped -Because 'the data sync is SecurityInsight Pro'; return }
        $r = Invoke-Region -Core { [pscustomobject]@{ Loaded = @(1); Skipped = @(); Held = @(); Refused = @(); Untimed = @() } } -Refused { throw 'summary failed' }
        $r.Threw | Should -Match 'summary failed'
        @($r.Sent | Where-Object Phase -eq 'End').Count | Should -Be 1
        $r.Sent[-1].Exit | Should -Be 'error'
    }
}

AfterAll { $global:SendToLogAnalytics = $script:SendToLaBefore }
