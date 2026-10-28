#Requires -Version 5.1
<#
    #902 THE ONE LIST OF REPORTS HELD ON PURPOSE (data-model/hold-kinds.locked.json; engine/_shared/SI-HoldKinds.ps1).
      * every kind has its two catalogue codes (data-model/errors.locked.json): the information code (class held-last-good,
        Action none, no ticket) and the escalation code (class held-too-long, Action support, a ticket);
      * the code never emits a hold kind that is not in the list (an AST scan of every engine file) and no ValidateSet of
        kinds comes back (the list is the only place);
      * a kind that is not in the list is NOT kept as a hold -- the report stays a real failure (the safe direction);
      * the streak (Get-RAHoldStreak) and the escalation (Test-SIHoldEscalated, Detailed only, 3 runs in a row);
      * the web app's embedded copy is held to the original by an xunit test (HoldKindsTests).
    Offline. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HoldKinds.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SilentSource.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
    $script:ListPath = Join-Path $script:SIRoot 'data-model\hold-kinds.locked.json'
    $script:Catalogue = @([IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\errors.locked.json')) | ConvertFrom-Json)
    $script:List = Get-SIHoldKinds
}

Describe 'the list (data-model/hold-kinds.locked.json)' {
    It 'reads: silent-source and role-read, each with its two codes, escalated after 3 Detailed runs' {
        @($script:List.Kinds).Count | Should -BeGreaterOrEqual 2
        $script:List.EscalateAfterDetailedRuns | Should -Be 3
        (Get-SIHoldKind 'silent-source').Code | Should -Be 'si-ra-0911'
        (Get-SIHoldKind 'silent-source').EscalationCode | Should -Be 'si-ra-0913'
        (Get-SIHoldKind 'role-read').Code | Should -Be 'si-ra-0912'
        (Get-SIHoldKind 'role-read').EscalationCode | Should -Be 'si-ra-0914'
        Test-SIHoldKindAcceptEmpty 'silent-source' | Should -BeTrue
        Test-SIHoldKindAcceptEmpty 'role-read' | Should -BeFalse -Because 'a role list that was not read is a read failure, never an empty source'
    }
    It 'every code is in the catalogue with its class, action and ticket -- and no code is used twice' {
        $codes = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($script:List.Kinds)) {
            foreach ($pair in @(@($k.Code, 'held-last-good', 'none', $false), @($k.EscalationCode, 'held-too-long', 'support', $true))) {
                $e = @($script:Catalogue | Where-Object { $_.code -eq $pair[0] })[0]
                $e | Should -Not -BeNullOrEmpty -Because ('{0} must be in errors.locked.json' -f $pair[0])
                $e.causeClass | Should -Be $pair[1] -Because $pair[0]
                $e.action | Should -Be $pair[2] -Because $pair[0]
                [bool]$e.opensTicket | Should -Be $pair[3] -Because $pair[0]
                $pair[0] | Should -MatchExactly '^si-ra-\d{4}$'
                $codes.Add([string]$pair[0])
            }
        }
        @($codes | Select-Object -Unique).Count | Should -Be $codes.Count
    }
    It 'a list that cannot be read has NO kinds: nothing is ever hidden as held' {
        $none = Get-SIHoldKinds -Path (Join-Path $TestDrive 'missing.json')
        @($none.Kinds).Count | Should -Be 0
        [IO.File]::WriteAllText((Join-Path $TestDrive 'bad.json'), '{ not json')
        @((Get-SIHoldKinds -Path (Join-Path $TestDrive 'bad.json')).Kinds).Count | Should -Be 0
        Test-SIHoldKind '' | Should -BeFalse
        Test-SIHoldKind 'held-back' | Should -BeFalse -Because 'a #877 hold-back is a failure, never a deliberate hold'
        Get-SIHoldKindCode 'nope' | Should -Be ''
    }
}

Describe 'no code emits a kind that is not in the list' {
    It 'every literal -Kind of Add-RADeliberateHold and -HoldKind of Set-RAStreamReportNotComplete in the engine is in the list' {
        $known = @($script:List.Kinds | ForEach-Object { $_.Kind })
        $bad = New-Object System.Collections.Generic.List[string]
        $seen = 0
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Filter '*.ps1' -Recurse -File)) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($c in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Add-RADeliberateHold', 'Set-RAStreamReportNotComplete') }, $true))) {
                $els = @($c.CommandElements)
                for ($i = 0; $i -lt $els.Count - 1; $i++) {
                    if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -in @('Kind', 'HoldKind')) {
                        $v = $els[$i + 1]
                        if ($v -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                            $seen++
                            if ($known -notcontains $v.Value) { $bad.Add(('{0}:{1} {2} -{3} {4}' -f $f.Name, $c.Extent.StartLineNumber, $c.GetCommandName(), $els[$i].ParameterName, $v.Value)) }
                        }
                    }
                }
            }
        }
        $seen | Should -BeGreaterOrEqual 2 -Because 'the silent-source and the role-read holds are both literal calls'
        @($bad) | Should -BeNullOrEmpty
    }
    It 'no ValidateSet of hold kinds anywhere in the engine (the list is the only place)' {
        $hits = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Filter '*.ps1' -Recurse -File | Select-String -Pattern "ValidateSet\([^)]*'silent-source'" | ForEach-Object { '{0}:{1}' -f $_.Filename, $_.LineNumber })
        $hits | Should -BeNullOrEmpty
    }
    It 'a kind that is not in the list is not kept (the report stays a real failure) and is never written' {
        $h = @{}
        Add-RADeliberateHold -Store $h -Report 'R1' -Kind 'invented-kind' -Why 'not complete: x'
        $h.ContainsKey('R1') | Should -BeFalse
        Get-RADeliberateHoldKind -Report 'R1' -Holds $h -Failures @(@{ Report = 'R1'; Why = 'not complete: x' }) | Should -Be ''
        $script:SqlParams = $null
        $st = @{ Invoke = { param($Sql, $Params, $Mode) $script:SqlParams = $Params; 1 }; Grain = 'Detailed'; TimeText = '2026-10-26T01:00:00.000' }
        Set-RAStreamReportNotComplete -Stream $st -ReportName 'R1' -Reason 'not complete: x' -HoldKind 'invented-kind' -HeldRuns 4 -HoldNames 'T'
        $script:SqlParams.HoldKind | Should -Be ''
        $script:SqlParams.HeldRuns | Should -Be 0
        $script:SqlParams.HoldNames | Should -Be ''
        Set-RAStreamReportNotComplete -Stream $st -ReportName 'R1' -Reason 'not complete: x' -HoldKind 'silent-source' -HeldRuns 2 -KeptResultAt '2026-10-24T01:00:00.000' -HoldNames 'DeviceTvmBrowserExtensions'
        $script:SqlParams.HoldKind | Should -Be 'silent-source'
        $script:SqlParams.HeldRuns | Should -Be 2
        $script:SqlParams.KeptResultAt | Should -Be '2026-10-24T01:00:00.000'
        $script:SqlParams.HoldNames | Should -Be 'DeviceTvmBrowserExtensions'
    }
    It 'a hold keeps what it is about (the silent tables) once each' {
        $h = @{}
        Add-RADeliberateHold -Store $h -Report 'R1' -Kind 'silent-source' -Why 'not complete: a' -Names @('T1', 'T2')
        Add-RADeliberateHold -Store $h -Report 'R1' -Kind 'silent-source' -Why 'not complete: a' -Names @('T2')
        @($h['R1'].Names) | Should -Be @('T1', 'T2')
        @($h['R1'].Whys).Count | Should -Be 1
    }
}

Describe 'the streak and the escalation' {
    It 'Get-RAHoldStreak: <Case>' -ForEach @(
        @{ Case = 'no earlier row'; Prev = $null; Want = 1 }
        @{ Case = 'held the same kind 1 run'; Prev = @{ HoldKind = 'silent-source'; HeldRuns = 1 }; Want = 2 }
        @{ Case = 'held the same kind 2 runs'; Prev = @{ HoldKind = 'silent-source'; HeldRuns = 2 }; Want = 3 }
        @{ Case = 'complete before'; Prev = @{ HoldKind = [DBNull]::Value; HeldRuns = [DBNull]::Value }; Want = 1 }
        @{ Case = 'another kind before'; Prev = @{ HoldKind = 'role-read'; HeldRuns = 5 }; Want = 1 }
        @{ Case = 'a row from before the column'; Prev = @{ HoldKind = 'silent-source'; HeldRuns = [DBNull]::Value }; Want = 1 }
    ) {
        Get-RAHoldStreak -Kind 'silent-source' -Previous $Prev | Should -Be $Want
    }
    It 'escalated only on a Detailed run held 3 runs in a row or more' {
        Test-SIHoldEscalated -HeldRuns 3 -Grain 'Detailed' | Should -BeTrue
        Test-SIHoldEscalated -HeldRuns 7 -Grain 'Detailed' | Should -BeTrue
        Test-SIHoldEscalated -HeldRuns 2 -Grain 'Detailed' | Should -BeFalse
        Test-SIHoldEscalated -HeldRuns 9 -Grain 'Summary' | Should -BeFalse -Because 'the same cause escalates through the Detailed run'
        Test-SIHoldEscalated -HeldRuns $null -Grain 'Detailed' | Should -BeFalse
        Test-SIHoldEscalated -HeldRuns ([DBNull]::Value) -Grain 'Detailed' | Should -BeFalse
    }
    It 'Read-RAStreamHoldStreak: the previous rows give the runs in a row and the kept result; an unreadable database = 1 run, nothing guessed' {
        $rows = @(@{ ReportName = 'R1'; HoldKind = 'silent-source'; HeldRuns = 2; KeptResultAt = [datetime]'2026-10-23T01:00:00' },
                  @{ ReportName = 'R2'; HoldKind = [DBNull]::Value; HeldRuns = [DBNull]::Value; KeptResultAt = [DBNull]::Value })
        $st = @{ Invoke = { param($Sql, $Params, $Mode) , $rows }.GetNewClosure(); Grain = 'Detailed'; TimeText = '2026-10-26T01:00:00.000' }
        $s = Read-RAStreamHoldStreak -Stream $st -Holds @{ R1 = 'silent-source'; R2 = 'role-read' }
        $s['R1'].HeldRuns | Should -Be 3
        $s['R1'].KeptResultAt | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-23T01:00:00', 'Utc'))
        $s['R2'].HeldRuns | Should -Be 1
        $s['R2'].KeptResultAt | Should -BeNullOrEmpty
        $bad = @{ Invoke = { param($Sql, $Params, $Mode) throw 'the database did not answer' }; Grain = 'Detailed'; TimeText = '2026-10-26T01:00:00.000' }
        $s2 = Read-RAStreamHoldStreak -Stream $bad -Holds @{ R1 = 'silent-source' }
        $s2['R1'].HeldRuns | Should -Be 1
        $s2['R1'].KeptResultAt | Should -BeNullOrEmpty
    }
    It 'the split names each held report with its runs, its kept result and whether it is escalated -- whether it is held does not change' {
        $h = @{}
        Add-RADeliberateHold -Store $h -Report 'R1' -Kind 'silent-source' -Why 'not complete: a source went silent: T' -Names @('T')
        Add-RADeliberateHold -Store $h -Report 'R2' -Kind 'role-read' -Why 'not complete: roles'
        $f = @(@{ Report = 'R1'; Why = 'not complete: a source went silent: T' }, @{ Report = 'R2'; Why = 'not complete: roles' }, @{ Report = 'R3'; Why = 'it failed: timeout' })
        $plain = Split-RAReportFailures -Failures $f -Holds $h
        $s = Split-RAReportFailures -Failures $f -Holds $h -Grain 'Detailed' -Streak @{ R1 = [pscustomobject]@{ HeldRuns = 3; KeptResultAt = [datetime]'2026-10-23T01:00:00Z' }; R2 = [pscustomobject]@{ HeldRuns = 1; KeptResultAt = $null } }
        @($s.Held | ForEach-Object { $_.Report }) | Should -Be @($plain.Held | ForEach-Object { $_.Report })
        @($s.Real).Count | Should -Be @($plain.Real).Count
        $r1 = @($s.Held | Where-Object Report -eq 'R1')[0]
        $r1.Escalated | Should -BeTrue
        $r1.HeldRuns | Should -Be 3
        @($r1.Names) | Should -Be @('T')
        @($s.Held | Where-Object Report -eq 'R2')[0].Escalated | Should -BeFalse
        @($plain.Held | Where-Object Report -eq 'R1')[0].Escalated | Should -BeFalse -Because 'no streak known = its first run'
    }
}
