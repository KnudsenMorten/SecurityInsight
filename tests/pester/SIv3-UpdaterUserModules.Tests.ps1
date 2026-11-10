#Requires -Version 5.1
<#
    #1164 (live 2026-11-10): the identity clean-up could not drop the OLD updater user -- "The database principal is set as the
    execution context of one or more procedures ... and cannot be dropped". The one module is sidata.StatisticsRefreshTable
    (WITH EXECUTE AS SELF, made by whoever applied the schema: on an existing install the updater). Offline, script-scoped fakes:
      * the batch (setup\_shared\SI-IdentityMoveSql.ps1 Get-SIIdentityMoveSqlModuleSql) re-makes an UNSIGNED procedure
        SecurityInsight makes AS THE NEW USER (EXECUTE AS USER ... CREATE OR ALTER ... REVERT), reads it back (the new user,
        its marker, its permissions) in one transaction; a signed or unknown module is KEPT; no GRANT / ADD SIGNATURE / DROP;
      * the database setup job's drop (SI_DBINIT_DROPS) and the Support-session clean-up run it AFTER the coverage gate and
        BEFORE the drop; the old user is dropped ONLY when no module runs as it any more -- else KEPT, said why.
    The real-SQL case (a procedure made as one user, re-made as another, then the first dropped) is in SIv3-StatisticsFresh.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-IdentityMoveSql.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-DbInitJob.ps1')
    $script:Old = '11111111-0000-0000-0000-0000000000a1'
    $script:New = '22222222-0000-0000-0000-0000000000b2'
    function script:Get-SIFunctionText([string]$Rel, [string]$Name) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $Rel), [ref]$null, [ref]$null)
        $f = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $Name }, $true))[0]
        if ($f) { $f.Extent.Text } else { '' }
    }
    # a fake product database as the database setup job sees it: both users with the same role (the coverage gate passes),
    # the module batch's answer from $script:ModRows, every write recorded
    function script:New-DbFake([object[]]$ModRows) {
        $script:F = @{ Mod = $ModRows; Writes = (New-Object System.Collections.Generic.List[string]); Reads = (New-Object System.Collections.Generic.List[string]) }
        {
            param([string]$Database, [string]$Query, $Params, [string]$Mode)
            $F = $script:F
            if ($Query -match 'sys\.sql_modules') { $F.Reads.Add('modules'); return , @($F.Mod) }
            if ($Mode -ne 'nonquery') {
                if ($Query -match 'DECLARE @old varbinary') {
                    $rows = @(@{ Kind = 'user'; Who = 'old'; Name = 'uami-si-updater' }, @{ Kind = 'role'; Who = 'old'; Name = 'db_ddladmin' })
                    if (-not ($F.Writes | Where-Object { $_ -match 'DROP USER' })) { } else { $rows = @() }
                    $rows += @(@{ Kind = 'user'; Who = 'new'; Name = 'id-si-updater' }, @{ Kind = 'role'; Who = 'new'; Name = 'db_ddladmin' })
                    return , $rows
                }
                return , @()
            }
            $F.Writes.Add($Query)
        }
    }
    $script:Drop = { [pscustomobject]@{ Moves = @(); Drops = @([pscustomobject]@{ Component = 'updater'; ClientId = $script:Old; KeepClientId = $script:New; KeepName = 'id-si-updater' }) } }
}

Describe 'the module batch: re-made as the new user, read back, nothing else' {
    BeforeAll { $script:Q = Get-SIIdentityMoveSqlModuleSql -OldSid (ConvertTo-SIMoveSid $script:Old) -NewSid (ConvertTo-SIMoveSid $script:New) }
    It 'finds every module whose execution context is the old user' {
        $script:Q | Should -Match 'FROM sys\.sql_modules AS m WHERE m\.execute_as_principal_id = @old'
        $script:Q | Should -Match ([regex]::Escape("sid = $(ConvertTo-SIMoveSid $script:Old)"))
        $script:Q | Should -Match ([regex]::Escape("sid = $(ConvertTo-SIMoveSid $script:New)"))
    }
    It 're-makes ONLY an unsigned procedure SecurityInsight makes (its marker), as the new user, and reverts' {
        $script:Q | Should -Match "INSERT @marks \(M\) SELECT N'si-statistics-refresh v1'"
        $script:Q | Should -Match 'sys\.crypt_properties WHERE major_id = @id'
        $script:Q | Should -Match "OBJECTPROPERTY\(@id, N'IsProcedure'\) <> 1"
        $script:Q | Should -Match '(?s)EXECUTE AS USER = @new;\s+EXEC \(@t\);\s+REVERT;'
        $script:Q | Should -Match "STUFF\(@t, @p, 6, N'CREATE OR ALTER'\)"
        $script:Q | Should -Match 'IF USER_NAME\(\) <> @me REVERT;'
    }
    It 'reads back in the same transaction: the new user, the marker, the permissions as they were -- else rolled back' {
        $script:Q | Should -Match 'execute_as_principal_id = @newId'
        $script:Q | Should -Match 'CHARINDEX\(@mark, ISNULL\(OBJECT_DEFINITION\(@id\)'
        $script:Q | Should -Match 'IF @after <> @before'
        $script:Q | Should -Match 'IF @@TRANCOUNT > 0 ROLLBACK;'
        $script:Q | Should -Match "N'left'"
    }
    It 'sends no grant, no signature, no drop, no deny / revoke' {
        $script:Q | Should -Not -Match '(?i)\bGRANT\s|ADD SIGNATURE|\bDROP\b|\bDENY\b|\bREVOKE\b|ALTER ROLE|CREATE USER'
    }
    It 'a SID that is not a SID literal is refused' {
        { Get-SIIdentityMoveSqlModuleSql -OldSid "0x01'; DROP USER x;--" -NewSid '0x02' } | Should -Throw
    }
}

Describe 'the answer: drop only when no module runs as the old user' {
    It 'moved + none left -> clear, one line per module' {
        $r = Resolve-SIIdentityMoveSqlModules -Rows @(@{ Module = '[sidata].[StatisticsRefreshTable]'; Action = 'moved'; Why = 'it now runs as id-si-updater (read back: the new user, its marker, its permissions)' }, @{ Module = ''; Action = 'left'; Why = '0' })
        $r.Clear | Should -BeTrue
        @($r.Moved).Count | Should -Be 1
        $r.Moved[0] | Should -Match 'the procedure \[sidata\]\.\[StatisticsRefreshTable\]: it now runs as id-si-updater'
    }
    It 'kept + one left -> not clear, said why' {
        $r = Resolve-SIIdentityMoveSqlModules -Rows @(@{ Module = '[cfg].[X]'; Action = 'kept'; Why = 'it is signed -- making it again would lose its signature' }, @{ Module = ''; Action = 'left'; Why = '1' })
        $r.Clear | Should -BeFalse
        $r.Kept[0] | Should -Match 'the procedure \[cfg\]\.\[X\] runs as the old user and is kept \(it is signed'
    }
    It 'no answer at all is never read as clear' {
        (Resolve-SIIdentityMoveSqlModules -Rows @()).Clear | Should -BeFalse
    }
}

Describe 'the database setup job''s drop (SI_DBINIT_DROPS)' {
    It 'the procedure is re-made as the new user, THEN the old user is dropped' {
        $sql = New-DbFake @(@{ Module = '[sidata].[StatisticsRefreshTable]'; Action = 'moved'; Why = 'it now runs as id-si-updater (read back)' }, @{ Module = ''; Action = 'left'; Why = '0' })
        $res = Invoke-SIDbInitMoves -DbInput (& $script:Drop) -Sql $sql -Databases @('sqldb-si-pro')
        @($res.Problems).Count | Should -Be 0 -Because (@($res.Problems) -join ' | ')
        $res.States['updater'] | Should -Be 'dropped'
        @($script:F.Writes | Where-Object { $_ -match 'DROP USER' }).Count | Should -Be 1
        ($res.Lines -join "`n") | Should -Match 'done: sqldb-si-pro: the procedure \[sidata\]\.\[StatisticsRefreshTable\]: it now runs as id-si-updater'
    }
    It 'a module that cannot be moved KEEPS the old user: no drop, said why' {
        $sql = New-DbFake @(@{ Module = '[cfg].[Signed]'; Action = 'kept'; Why = 'it is signed -- making it again would lose its signature' }, @{ Module = ''; Action = 'left'; Why = '1' })
        $res = Invoke-SIDbInitMoves -DbInput (& $script:Drop) -Sql $sql -Databases @('sqldb-si-pro')
        $res.States['updater'] | Should -Be 'failed'
        @($script:F.Writes | Where-Object { $_ -match 'DROP USER' }).Count | Should -Be 0
        ($res.Problems -join "`n") | Should -Match 'KEPT: the old updater user uami-si-updater: the procedure \[cfg\]\.\[Signed\] runs as the old user and is kept'
    }
    It 'no answer from the module batch: no drop' {
        $sql = New-DbFake @()
        $res = Invoke-SIDbInitMoves -DbInput (& $script:Drop) -Sql $sql -Databases @('sqldb-si-pro')
        @($script:F.Writes | Where-Object { $_ -match 'DROP USER' }).Count | Should -Be 0
        $res.States['updater'] | Should -Be 'failed'
    }
    It 'ORDER: the coverage gate, then the modules, then the drop' {
        $t = Get-SIFunctionText 'setup\_shared\SI-DbInitJob.ps1' 'Invoke-SIDbInitMoves'
        $g = $t.IndexOf('Test-SIIdentityMoveSqlCovered -Rows'); $m = $t.IndexOf('Get-SIIdentityMoveSqlModuleSql -OldSid'); $d = $t.IndexOf('Get-SIIdentityMoveSqlDropSql -OldClientId')
        $g | Should -BeGreaterThan 0; $m | Should -BeGreaterThan $g; $d | Should -BeGreaterThan $m
    }
}

Describe 'the Support-session clean-up (Move-SIIdentity -Step clean-up)' {
    It 'ORDER: the coverage gate, then the modules, then the drop; a module kept = KEPT and the clean-up stops' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-IdentityMove.ps1'))
        $g = $t.IndexOf('$cov = Test-SIIdentityMoveSqlCovered -Rows $rowsNow')
        $m = $t.IndexOf('Get-SIIdentityMoveSqlModuleSql -OldSid (ConvertTo-SIMoveSid $old.ClientId) -NewSid (ConvertTo-SIMoveSid $sel.New.ClientId)')
        $d = $t.IndexOf('-Query (Get-SIIdentityMoveSqlDropSql -OldClientId $old.ClientId)')
        $g | Should -BeGreaterThan 0; $m | Should -BeGreaterThan $g; $d | Should -BeGreaterThan $m
        $t | Should -Match ([regex]::Escape("if (-not `$mods.Clear) { `$stop = `$true; `$lines.Add(('KEPT: SQL user of {0} in {1}: {2}'"))
    }
}
