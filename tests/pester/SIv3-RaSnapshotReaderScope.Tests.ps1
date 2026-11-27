#Requires -Version 5.1
<#
    THE DEFENDER SNAPSHOT CHECK'S OWN READER FINDS THE ENGINE'S LOG ANALYTICS READER (3.1.55).
    Get-RARecSnapshotPartialError (engine\risk-analysis\_shared\RA-DefenderFilter.ps1) built its default reader as
    `{ ... Invoke-LogAnalyticsKqlQuery ... }.GetNewClosure()`. A .GetNewClosure() block is bound to a NEW dynamic module:
    its command lookup goes from the block to the GLOBAL scope and skips the script scope of the engine, where
    Invoke-LogAnalyticsKqlQuery is dot-sourced (Invoke-RiskAnalysis.ps1). Every live run said "The term
    'Invoke-LogAnalyticsKqlQuery' is not recognized" and the two Azure recommendation Detailed reports ended NOT COMPLETE.
    The existing tests (SIv3-MemoryStream) always passed -Read, so they never met the default reader.

    These tests load the files THE WAY THE ENGINE DOES: dot-sourced into a SCRIPT scope (a harness script run with &, never
    the global scope), with Invoke-LogAnalyticsKqlQuery stubbed in that SAME script scope, and call the check WITHOUT -Read.
    On the 3.1.54 code the first case is red (the reader is not found: the check returns the "could not be read" error).

    The source-shape guard: no .GetNewClosure() block in the engine, container or setup code calls, by its bare name, a
    function SecurityInsight defines by dot-sourcing (not global:) -- such a block cannot see it wherever it is not global.
    A block that only calls through a captured command (& $fn) is fine. Offline: every source is a fake.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    # no global copy of the reader may hide the defect (another suite in the same process, a profile)
    $script:SavedGlobalLa = $null
    if (Test-Path -LiteralPath 'function:global:Invoke-LogAnalyticsKqlQuery') {
        $script:SavedGlobalLa = (Get-Item -LiteralPath 'function:global:Invoke-LogAnalyticsKqlQuery').ScriptBlock
        Remove-Item -LiteralPath 'function:global:Invoke-LogAnalyticsKqlQuery'
    }
    $script:SavedWs = $global:SI_WorkspaceResourceId
    $global:SI_WorkspaceResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/la-test'
    $script:RecQuery = "let _recAll = SI_AzureRecommendation_CL;`n//__SI_REC_SNAPSHOT_BEGIN__`nlet _recLatest = 1;`n//__SI_REC_SNAPSHOT_END__`n_rec"

    # The harness: a SCRIPT, run with & -- its own script scope, as Invoke-RiskAnalysis.ps1 is. The files are dot-sourced into
    # it, the stub reader and Write-Warn2 are defined in it, and the check is called in it without -Read.
    $script:Harness = Join-Path $TestDrive 'RaSnapshotHarness.ps1'
    $h = @'
param([string]$SIRoot, [string]$Query, [string]$Mode)
. (Join-Path $SIRoot 'engine\_shared\SI-AzureRecSnapshot.ps1')
. (Join-Path $SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
. (Join-Path $SIRoot 'engine\risk-analysis\_shared\RA-DefenderFilter.ps1')
$calls = [System.Collections.Generic.List[object]]::new()
$warns = [System.Collections.Generic.List[string]]::new()
function Invoke-LogAnalyticsKqlQuery {
    param([string]$WorkspaceResourceId, [string]$Query, [int]$TimeoutSec = 0)
    $calls.Add([pscustomobject]@{ Ws = $WorkspaceResourceId; Query = $Query })
    switch ($Mode) {
        'whole'   { return , @([pscustomobject]@{ CollectionTime = '2026-11-25T02:00:00Z'; SnapshotRule = 1 }) }
        'partial' { return , @([pscustomobject]@{ CollectionTime = '2026-11-25T02:00:00Z'; SnapshotRule = 3 }) }
        'absent'  { throw "'where' operator: Failed to resolve table or column expression named 'SI_AzureRecommendation_CL'" }
        'transient' {
            if ($calls.Count -eq 1) { throw 'HTTP 503 Service Unavailable' }
            return , @([pscustomobject]@{ CollectionTime = '2026-11-25T02:00:00Z'; SnapshotRule = 1 })
        }
    }
}
function Write-Warn2 { param($m) $warns.Add([string]$m) }
$script:RARecSnapVerdict = $null
$e1 = Get-RARecSnapshotPartialError -Query $Query -Sleep { }
$e2 = Get-RARecSnapshotPartialError -Query $Query -Sleep { }
[pscustomobject]@{
    First = $e1; Second = $e2; Calls = @($calls); Warns = @($warns)
    ReaderIsGlobal = [bool](Test-Path -LiteralPath 'function:global:Invoke-LogAnalyticsKqlQuery')
}
'@
    [IO.File]::WriteAllText($script:Harness, $h)
    function script:Invoke-RaSnapshotHarness([string]$Mode, [string]$Query = $script:RecQuery) {
        & $script:Harness -SIRoot $script:SIRoot -Query $Query -Mode $Mode
    }
}

AfterAll {
    $global:SI_WorkspaceResourceId = $script:SavedWs
    if ($script:SavedGlobalLa) { Set-Item -LiteralPath 'function:global:Invoke-LogAnalyticsKqlQuery' -Value $script:SavedGlobalLa }
}

Describe 'the snapshot check reads Log Analytics through the engine''s own reader (no -Read, files dot-sourced in a script scope)' {
    It 'a whole snapshot: the engine''s reader is found and asked once, on the run''s workspace; nothing ends, no warning' {
        $r = Invoke-RaSnapshotHarness -Mode 'whole'
        $r.ReaderIsGlobal | Should -BeFalse -Because 'the reader lives in the engine''s script scope, as in a live run'
        $r.Warns | Should -BeNullOrEmpty -Because 'the reader is found (3.1.54: "The term ''Invoke-LogAnalyticsKqlQuery'' is not recognized")'
        $r.First | Should -BeNullOrEmpty -Because 'a whole snapshot ends no report'
        $r.Second | Should -BeNullOrEmpty
        @($r.Calls).Count | Should -Be 1 -Because 'one small query per run'
        $r.Calls[0].Ws | Should -BeExactly $global:SI_WorkspaceResourceId
        $r.Calls[0].Query | Should -Match 'SnapshotRule'
    }
    It 'a partial snapshot: the reports that read it end NOT COMPLETE through the lookup-unavailable path, asked once' {
        $r = Invoke-RaSnapshotHarness -Mode 'partial'
        @($r.Calls).Count | Should -Be 1
        $r.First | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath 'function:Test-RALookupUnavailableError' | Should -BeFalse -Because 'the harness keeps the engine''s functions to itself'
        $r.First.Message | Should -Match '^a lookup this report needs could not be read -- the newest Defender for Cloud recommendation snapshot'
        $r.First.Message | Should -Not -Match 'not recognized'
        $r.Second.Message | Should -BeExactly $r.First.Message
        @($r.Warns).Count | Should -Be 1
    }
    It 'a table that does not exist is no snapshot: nothing ends, no warning' {
        $r = Invoke-RaSnapshotHarness -Mode 'absent'
        @($r.Calls).Count | Should -Be 1
        $r.First | Should -BeNullOrEmpty
        $r.Warns | Should -BeNullOrEmpty
    }
    It 'a platform answer (503) is asked again once through the same reader, then the answer counts' {
        $r = Invoke-RaSnapshotHarness -Mode 'transient'
        @($r.Calls).Count | Should -Be 2
        $r.Calls[1].Ws | Should -BeExactly $global:SI_WorkspaceResourceId
        $r.First | Should -BeNullOrEmpty
        $r.Warns | Should -BeNullOrEmpty
    }
    It 'a report that does not read the snapshot never asks' {
        $r = Invoke-RaSnapshotHarness -Mode 'whole' -Query 'DeviceInfo | take 1'
        @($r.Calls).Count | Should -Be 0
        $r.First | Should -BeNullOrEmpty
    }
}

Describe 'source shape: no .GetNewClosure() block calls a dot-sourced SecurityInsight function by its bare name' {
    BeforeAll {
        $dirs = @('engine', 'container', 'setup') | ForEach-Object { Join-Path $script:SIRoot $_ } | Where-Object { Test-Path -LiteralPath $_ }
        $script:Files = @(Get-ChildItem -LiteralPath $dirs -Recurse -File -Include '*.ps1', '*.psm1')
        $script:Asts = @{}
        $local = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $glob = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        # the functions SecurityInsight defines: every product file (not the tests), wherever a closure might call it from
        $testsDir = (Join-Path $script:SIRoot 'tests') + [IO.Path]::DirectorySeparatorChar
        $defFiles = @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Include '*.ps1', '*.psm1' | Where-Object { -not $_.FullName.StartsWith($testsDir, [StringComparison]::OrdinalIgnoreCase) -and $_.FullName -notmatch '[\\/](node_modules|bin|obj)[\\/]' })
        foreach ($f in $defFiles) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            $script:Asts[$f.FullName] = $ast
            foreach ($fd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                $n = [string]$fd.Name
                if ($n -match '^global:(.+)$') { [void]$glob.Add($Matches[1]) }
                elseif ($n -match '^(script|local|private):(.+)$') { [void]$local.Add($Matches[2]) }
                else { [void]$local.Add($n) }
            }
        }
        # A name defined ONLY as global: somewhere is visible to a closure; a name defined without global: anywhere is not.
        $script:Risky = $local
        # Reviewed sites where the bare call is safe, each with its reason (relative path|function name).
        $script:Allowed = @{
        }
        $script:Findings = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $script:Files) {
            $ast = $script:Asts[$f.FullName]
            $rel = $f.FullName.Substring($script:SIRoot.Length + 1).Replace('\', '/')
            $calls = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                    -not $n.Static -and [string]$n.Member.Value -eq 'GetNewClosure' -and
                    $n.Expression -is [System.Management.Automation.Language.ScriptBlockExpressionAst]
                }, $true)
            foreach ($c in $calls) {
                $sb = $c.Expression.ScriptBlock
                $inner = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                foreach ($fd in $sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$inner.Add(([string]$fd.Name -replace '^\w+:', '')) }
                foreach ($cmd in $sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                    $name = $cmd.GetCommandName()
                    if (-not $name -or $cmd.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot) { continue }
                    $name = $name -replace '^\w+:', ''
                    if (-not $script:Risky.Contains($name) -or $inner.Contains($name)) { continue }
                    $key = '{0}|{1}' -f $rel, $name
                    if ($script:Allowed.ContainsKey($key)) { continue }
                    $script:Findings.Add(('{0}:{1} {2}' -f $rel, $cmd.Extent.StartLineNumber, $name))
                }
            }
        }
    }
    It 'the scan read the code (a parse of every file, the snapshot check among them)' {
        $script:Files.Count | Should -BeGreaterThan 100
        $script:Risky.Contains('Invoke-LogAnalyticsKqlQuery') | Should -BeTrue
    }
    It 'no such block (each site found is named)' {
        $script:Findings | Should -BeNullOrEmpty -Because ("a .GetNewClosure() block cannot see a dot-sourced function; capture it (`$fn = `${function:Name}` / Get-Command) and call & `$fn, or use a plain block. Found:`n" + (@($script:Findings) -join "`n"))
    }
}
