#Requires -Version 5.1
<#
    #1021 -- THE SUPPORT GRANT ON REAL SQL (the test VM's SQL Server Express): the schema block, the admin steps (the Support
    app's user + the read-only role, the consent, the signature in db_owner, the grants), and as an engine user with ONLY
    EXECUTE on the four procedures:
      * open setup -> the Support app's user is in db_owner, one open marker, the read-back says so; close -> removed,
        the read-only role and the user stay (framework 4a);
      * the LOWER of the asked and the consented level; no consent -> 51803; a bad request -> 51802;
      * a membership the Support app had BEFORE the grant (PreExisting) is never removed by the close;
      * an expired marker (a job that died mid-grant) is removed by the sweep -- only the expired one;
      * the engine cannot write the consent, the markers or the journal itself, and cannot add itself to db_owner;
      * an ALTER of a procedure drops its signature -> the open refuses (51801); the sign step refuses a changed text.
    The Support app's user is made FOR a SQL login created WITH SID = its client id's bytes (the same SID an Entra
    application's TYPE = E user has), so the procedures find it exactly as in Azure.
#>

BeforeDiscovery {
    $script:HasSql = [bool]((Get-Command sqlcmd -ErrorAction SilentlyContinue) -and (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\pro-settings\SI-SupportGrantSql.ps1')
    . (Join-Path $script:SIRoot 'engine\support-grant\SI-SupportGrant.ps1')
    # the updater's one write, from the update step's own file (the same text the update sends)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SupportGrantUpdate.ps1')
    function script:Master([string]$Sql) {
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    function script:NewInvoke($Cn) {
        $global:SIPesterSgCn = $Cn
        {
            param($Sql, $Params, $Mode)
            $c = $global:SIPesterSgCn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600
            if ($Params) { foreach ($k in $Params.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [System.DBNull]::Value } else { [string]$Params[$k] })) } }
            switch ($Mode) {
                'rows' {
                    $rd = $c.ExecuteReader(); $out = [System.Collections.Generic.List[object]]::new()
                    try { do { if ($rd.FieldCount -gt 0) { $out = [System.Collections.Generic.List[object]]::new(); while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) } } } while ($rd.NextResult()) } finally { $rd.Close() }
                    $out.ToArray()   # each row on its own (the callers take [0])
                }
                'scalar' { $c.ExecuteScalar() }
                default { [void]$c.ExecuteNonQuery() }
            }
        }
    }
}

Describe 'REAL SQL: the Invardia Support app''s just-in-time grant (#1021)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:SetupError = $null
        try {
            $tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
            $script:DbName = 'si_test_sgrant_' + $tag
            $script:Login = 'si_t_support_' + $tag
            $script:App = [guid]::NewGuid().ToString()
            $sid = ConvertTo-SISupportGrantSid -ClientId $script:App
            Master "CREATE DATABASE [$($script:DbName)]"
            Master ("CREATE LOGIN [{0}] WITH PASSWORD = N'{1}', SID = {2}, CHECK_POLICY = OFF" -f $script:Login, ('P' + [guid]::NewGuid().ToString('N') + '!a1'), $sid)
            $script:Cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$($script:DbName);Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
            $script:Cn.Open()
            $script:A = NewInvoke $script:Cn
            # the product's roles, an engine user with only si_engine, the updater with DDL + data (as before its cut-over), the
            # Support app's user (its SID = its client id) -- as the install leaves them
            & $script:A ("CREATE ROLE si_engine; CREATE ROLE si_web; CREATE ROLE si_updater;
                CREATE USER si_t_engine WITHOUT LOGIN; ALTER ROLE si_engine ADD MEMBER si_t_engine;
                CREATE USER si_t_upd WITHOUT LOGIN; ALTER ROLE db_ddladmin ADD MEMBER si_t_upd; ALTER ROLE db_datawriter ADD MEMBER si_t_upd; ALTER ROLE db_datareader ADD MEMBER si_t_upd;
                CREATE USER [Invardia Support] FOR LOGIN [{0}];" -f $script:Login) @{} 'nonquery'
            $script:Steps = @(Get-SISupportGrantAdminSteps -ClientId $script:App -UserName 'Invardia Support' -Level setup -Source customer -By 'pester')
            foreach ($s in $script:Steps) { $script:Last = & $script:A $s.Sql @{} 'scalar' }
            $script:As = {
                param([string]$User, [string]$Sql, $Params, [string]$Mode)
                & $script:A ("EXECUTE AS USER = N'{0}';" -f $User) @{} 'nonquery'
                try { & $script:A $Sql $Params $Mode } finally { & $script:A 'REVERT;' @{} 'nonquery' }
            }
            $script:Eng = { param($Sql, $Params, $Mode) & $script:As 'si_t_engine' $Sql $Params $Mode }
            $script:Member = { param([string]$Role) [int](& $script:A ("SELECT COUNT(*) FROM sys.database_role_members m WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(N'Invardia Support') AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'{0}')" -f $Role) @{} 'scalar') }
            $script:Open = { param([string]$Level = 'setup', [int]$Minutes = 60) @(& $script:Eng (Get-SISupportGrantCallSql -Name Open) @{ RequestId = [guid]::NewGuid().ToString(); Level = $Level; MaxUntilUtc = [datetime]::UtcNow.AddMinutes($Minutes).ToString('yyyy-MM-ddTHH:mm:ssZ'); Reason = 'pester ticket'; Ticket = 'T-1'; StartedBy = 'pester' } 'rows')[0] }
            $script:Close = { @(& $script:Eng (Get-SISupportGrantCallSql -Name Close) @{ RequestId = [guid]::NewGuid().ToString(); Reason = 'pester close'; StartedBy = 'pester' } 'rows')[0] }
            $script:SetConsent = { param([string]$Level) & $script:A ("UPDATE cfg.SupportConsent SET [Level] = N'{0}' WHERE Id = 1;" -f $Level) @{} 'nonquery' }
        } catch { $script:SetupError = (($_.Exception.Message + ' AT ' + $_.InvocationInfo.PositionMessage) -replace '\s+', ' ') }
    }
    AfterAll {
        try { $script:Cn.Dispose() } catch { }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        try { Master "ALTER DATABASE [$($script:DbName)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:DbName)]" } catch { }
        try { Master "DROP LOGIN [$($script:Login)]" } catch { }
    }

    It 'the setup ran (database, roles, users, every admin step)' { $script:SetupError | Should -BeNullOrEmpty }

    It 'the admin steps read back: tables, 4 procedures of this release, signed (2099, key removed), signer in db_owner, the read-only role, the consent, the engine may EXECUTE' {
        $st = ConvertFrom-SISupportGrantState -Row (@(& $script:A (Get-SISupportGrantStateSql -ClientId $script:App) @{} 'rows')[0])
        ($st.Lines -join '; ') | Should -BeNullOrEmpty
        $st.Consent | Should -Be 'setup|customer'
        (& $script:Member 'si_support_read') | Should -Be 1
        (& $script:Member 'db_owner') | Should -Be 0
    }

    It 'the admin steps are idempotent: a second run changes nothing and signs nothing again' {
        $before = [int](& $script:A "SELECT COUNT(*) FROM sys.certificates WHERE name LIKE N'si_support_signer%'" @{} 'scalar')
        foreach ($s in $script:Steps) { $null = & $script:A $s.Sql @{} 'scalar' }
        [int](& $script:A "SELECT COUNT(*) FROM sys.certificates WHERE name LIKE N'si_support_signer%'" @{} 'scalar') | Should -Be $before
    }

    It 'OPEN at setup as the engine: the Support app''s own user is in db_owner, one open marker, the read-back says so' {
        $r = & $script:Open 'setup' 60
        $r['LevelGranted'] | Should -Be 'setup'; $r['RoleName'] | Should -Be 'db_owner'; [int]$r['RoleHeld'] | Should -Be 1; [int]$r['ReadOnlyHeld'] | Should -Be 1
        (& $script:Member 'db_owner') | Should -Be 1
        [int](& $script:A 'SELECT COUNT(*) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL' @{} 'scalar') | Should -Be 1
        # the Support app really holds the right: as it, a db_owner-only statement works
        { & $script:As 'Invardia Support' 'CREATE TABLE dbo.PesterBySupport (Id int); DROP TABLE dbo.PesterBySupport;' @{} 'nonquery' } | Should -Not -Throw
    }

    It 'a second open EXTENDS the open grant and adds no second marker' {
        $r = & $script:Open 'setup' 120
        [int](& $script:A 'SELECT COUNT(*) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL' @{} 'scalar') | Should -Be 1
        ([datetime]::Parse([string]$r['UntilUtc'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')) | Should -BeGreaterThan ([datetime]::UtcNow.AddMinutes(100))
    }

    It 'CLOSE removes ONLY what the grant added: db_owner goes; the user and the read-only role stay (4a); the journal has every step' {
        $r = & $script:Close
        [int]$r['RolesRemoved'] | Should -Be 1; [int]$r['RolesStillHeld'] | Should -Be 0; [int]$r['StillOpen'] | Should -Be 0
        [int]$r['UserPresent'] | Should -Be 1; [int]$r['ReadOnlyHeld'] | Should -Be 1
        (& $script:Member 'db_owner') | Should -Be 0
        (& $script:Member 'si_support_read') | Should -Be 1
        { & $script:As 'Invardia Support' 'CREATE TABLE dbo.PesterBySupport2 (Id int);' @{} 'nonquery' } | Should -Throw
        [int](& $script:A "SELECT COUNT(*) FROM cfg.SupportGrant WHERE Action = N'open' AND Outcome = N'granted'" @{} 'scalar') | Should -Be 2
        [int](& $script:A "SELECT COUNT(*) FROM cfg.SupportGrant WHERE Action = N'close' AND Outcome = N'revoked'" @{} 'scalar') | Should -Be 1
    }

    It 'the LOWER level wins: consent troubleshoot + a setup request = db_datareader only' {
        & $script:SetConsent 'troubleshoot'
        try {
            $r = & $script:Open 'setup' 30
            $r['LevelGranted'] | Should -Be 'troubleshoot'; $r['RoleName'] | Should -Be 'db_datareader'
            (& $script:Member 'db_datareader') | Should -Be 1; (& $script:Member 'db_owner') | Should -Be 0
            $null = & $script:Close
            (& $script:Member 'db_datareader') | Should -Be 0
        } finally { & $script:SetConsent 'setup' }
    }

    It 'a membership the Support app had BEFORE the grant is never removed by the close (PreExisting)' {
        & $script:A "ALTER ROLE db_owner ADD MEMBER [Invardia Support];" @{} 'nonquery'
        try {
            $null = & $script:Open 'setup' 30
            [int](& $script:A "SELECT TOP (1) CONVERT(int, PreExisting) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL" @{} 'scalar') | Should -Be 1
            $r = & $script:Close
            [int]$r['RolesRemoved'] | Should -Be 0
            (& $script:Member 'db_owner') | Should -Be 1
            # the status names it: db_owner outside a support grant
            [int](@(& $script:Eng (Get-SISupportGrantCallSql -Name Status) @{} 'rows')[0]['StandingOwner']) | Should -Be 1
        } finally { & $script:A "ALTER ROLE db_owner DROP MEMBER [Invardia Support];" @{} 'nonquery' }
    }

    It 'a job that died mid-grant: the SWEEP removes the EXPIRED grant only -- an open, unexpired one stays' {
        $null = & $script:Open 'setup' 60
        # the grant's marker is made to have expired (as if the close never came)
        & $script:A "UPDATE cfg.SupportJitMarker SET ExpiresUtc = DATEADD(MINUTE, -1, SYSUTCDATETIME()) WHERE ClosedUtc IS NULL;" @{} 'nonquery'
        $st = @(& $script:Eng (Get-SISupportGrantCallSql -Name Status) @{} 'rows')[0]
        [int]$st['JitOverdue'] | Should -Be 1
        $sw = Invoke-SISupportGrantSweep -Databases ([ordered]@{ pester = $script:Eng }) -By 'pester'
        $sw.Closed | Should -Be 1; $sw.RolesRemoved | Should -Be 1; @($sw.Failed).Count | Should -Be 0
        (& $script:Member 'db_owner') | Should -Be 0; (& $script:Member 'si_support_read') | Should -Be 1
        $null = & $script:Open 'troubleshoot' 60
        $sw2 = Invoke-SISupportGrantSweep -Databases ([ordered]@{ pester = $script:Eng }) -By 'pester'
        $sw2.Closed | Should -Be 0
        $null = & $script:Close
    }

    It 'the request is checked INSIDE the procedure: a bad level, a maxUntil over 24 h or in the past, an empty reason -> 51802' {
        foreach ($p in @(
            @{ RequestId = [guid]::NewGuid().ToString(); Level = 'admin'; MaxUntilUtc = [datetime]::UtcNow.AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ'); Reason = 'x'; Ticket = ''; StartedBy = '' },
            @{ RequestId = [guid]::NewGuid().ToString(); Level = 'setup'; MaxUntilUtc = [datetime]::UtcNow.AddHours(30).ToString('yyyy-MM-ddTHH:mm:ssZ'); Reason = 'x'; Ticket = ''; StartedBy = '' },
            @{ RequestId = [guid]::NewGuid().ToString(); Level = 'setup'; MaxUntilUtc = [datetime]::UtcNow.AddHours(-1).ToString('yyyy-MM-ddTHH:mm:ssZ'); Reason = 'x'; Ticket = ''; StartedBy = '' },
            @{ RequestId = [guid]::NewGuid().ToString(); Level = 'setup'; MaxUntilUtc = [datetime]::UtcNow.AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ'); Reason = '  '; Ticket = ''; StartedBy = '' })) {
            $e = $null; try { $null = & $script:Eng (Get-SISupportGrantCallSql -Name Open) $p 'rows' } catch { $e = $_ }
            $e | Should -Not -BeNullOrEmpty
            Get-SISupportGrantErrorResult $e | Should -Be 'bad-request'
        }
        (& $script:Member 'db_owner') | Should -Be 0
    }

    It 'no consent -> 51803 (no-consent); the engine can NOT write the consent itself; the updater may record a DERIVED one only into the empty table' {
        $saved = @(& $script:A 'SELECT AppId, [Level], Source, ConsentedBy FROM cfg.SupportConsent' @{} 'rows')[0]
        & $script:A 'DELETE FROM cfg.SupportConsent;' @{} 'nonquery'
        try {
            $e = $null; try { $null = & $script:Open 'setup' 30 } catch { $e = $_ }
            Get-SISupportGrantErrorResult $e | Should -Be 'no-consent'
            { & $script:Eng ("INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, N'{0}', N'setup', N'customer', N'x');" -f $script:App) @{} 'nonquery' } | Should -Throw
            # the updater (DDL + data, before its cut-over): a CUSTOMER consent is refused; a DERIVED one into the empty table is taken
            { & $script:As 'si_t_upd' ("INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, N'{0}', N'setup', N'customer', N'x');" -f $script:App) @{} 'nonquery' } | Should -Throw
            $back = @(& $script:As 'si_t_upd' (Get-SISupportGrantDerivedConsentSql) @{ AppId = $script:App; Level = 'troubleshoot'; By = 'pester' } 'rows')[0]
            $back['Consent'] | Should -Be 'troubleshoot|derived'
            # ... and it can never change it afterwards
            { & $script:As 'si_t_upd' "UPDATE cfg.SupportConsent SET [Level] = N'setup' WHERE Id = 1;" @{} 'nonquery' } | Should -Throw
        } finally {
            & $script:A 'DELETE FROM cfg.SupportConsent;' @{} 'nonquery'
            & $script:A "INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, @a, @l, @s, @b);" @{ a = [string]$saved['AppId']; l = [string]$saved['Level']; s = [string]$saved['Source']; b = [string]$saved['ConsentedBy'] } 'nonquery'
        }
    }

    It 'the engine cannot write the markers or the journal, and cannot add anyone to db_owner itself -- only through the signed procedure' {
        { & $script:Eng ("INSERT cfg.SupportJitMarker (GrantId, RoleName, Sid, PreExisting, ExpiresUtc) VALUES (NEWID(), N'db_owner', 0x00, 1, SYSUTCDATETIME());") @{} 'nonquery' } | Should -Throw
        { & $script:Eng "UPDATE cfg.SupportGrant SET Outcome = N'x';" @{} 'nonquery' } | Should -Throw
        { & $script:Eng 'ALTER ROLE db_owner ADD MEMBER [Invardia Support];' @{} 'nonquery' } | Should -Throw
        (& $script:Member 'db_owner') | Should -Be 0
    }

    It 'an ALTER of a procedure drops its signature: the open then refuses (51801, not-prepared); the sign step refuses the changed text' {
        # dropped and made again with the SAME text: the signature is gone with it
        $def = Get-SISupportGrantProcedureText -Name Open
        & $script:A 'DROP PROCEDURE cfg.SupportGrantOpen;' @{} 'nonquery'
        & $script:A $def @{} 'nonquery'
        & $script:A 'GRANT EXECUTE ON OBJECT::cfg.SupportGrantOpen TO [si_engine];' @{} 'nonquery'
        $e = $null; try { $null = & $script:Open 'setup' 30 } catch { $e = $_ }
        Get-SISupportGrantErrorResult $e | Should -Be 'not-prepared'
        (& $script:Member 'db_owner') | Should -Be 0
        # the same text, re-signed by the admin step, works again; a CHANGED text is refused by it
        $sign = @($script:Steps | Where-Object Step -eq 'sign')[0]
        $null = & $script:A $sign.Sql @{} 'scalar'
        $r = & $script:Open 'setup' 30
        [int]$r['RoleHeld'] | Should -Be 1
        $null = & $script:Close
        & $script:A 'DROP PROCEDURE cfg.SupportGrantOpen;' @{} 'nonquery'
        & $script:A ($def -replace 'SET NOCOUNT ON;', 'SET NOCOUNT ON; -- changed') @{} 'nonquery'
        { & $script:A $sign.Sql @{} 'scalar' } | Should -Throw '*not this release*'
    }
}

