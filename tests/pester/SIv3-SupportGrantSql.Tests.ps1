#Requires -Version 5.1
<#
    #1021 -- THE SUPPORT GRANT'S SQL, static (engine\pro-settings\SI-SupportGrantSql.ps1):
      * sql\si-pro-settings.sql carries the generated block WORD FOR WORD (one source), additive, one guarded statement per
        batch, the procedures created ONCE (never CREATE OR ALTER: that would drop the signature on every update);
      * the procedures: signed check first; the principal from cfg.SupportConsent, never a parameter; the LOWER level; at
        most 24 h; only db_owner / db_datareader ever added or removed; the close never DROPs a user, never touches the
        read-only role, removes only PreExisting = 0 markers; every value a parameter;
      * the admin steps ONLY ADD (no DROP USER / DROP MEMBER / REVOKE); the sign step compares the release's SHA-256 before
        signing, 2099, private key removed, signer in db_owner; DENY ALTER to the updater; derived never replaces customer;
      * the engine's grants: EXECUTE on the four procedures and nothing on the tables (DENY); the web app: the sweep only;
        the inventory sees only the four EXECUTEs from engine code.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\pro-settings\SI-SupportGrantSql.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SchemaGate.ps1')
    $script:File = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql')) -replace "`r`n", "`n"
    $script:Schema = Get-SISupportGrantSchemaSql
    $script:Proc = @{}; foreach ($n in 'Open', 'Close', 'Sweep', 'Status') { $script:Proc[$n] = Get-SISupportGrantProcedureText -Name $n }
    $script:App = '11111111-2222-3333-4444-555555555555'
    $script:Steps = @(Get-SISupportGrantAdminSteps -ClientId $script:App -UserName 'Invardia Support' -Level setup -Source customer)
}

Describe 'ONE source: the schema file carries the generated block word for word' {
    It 'sql\si-pro-settings.sql has exactly the block (markers and all)' {
        $script:File.Contains((Get-SISupportGrantSchemaFileBlock)) | Should -BeTrue -Because 'regenerate the block from Get-SISupportGrantSchemaFileBlock'
        ([regex]::Matches($script:File, 'GENERATED SUPPORT GRANT')).Count | Should -Be 2
    }
    It 'additive (the schema gate), one guarded statement per batch, every CREATE guarded' {
        (Test-SISchemaIsAdditive -Sql $script:Schema).IsAdditive | Should -BeTrue
        $batches = @(($script:Schema -split '(?m)^\s*$') | Where-Object { ($_ -replace '(?m)^\s*--.*$', '').Trim() })
        foreach ($b in $batches) { @([regex]::Matches(($b -replace '(?m)^\s*--.*$', ''), '(?im)^IF\b')).Count | Should -BeLessOrEqual 1 }
        foreach ($t in (Get-SISupportGrantContract).Tables) { $script:Schema | Should -Match ("IF OBJECT_ID\(N'{0}'\) IS NULL\nCREATE TABLE {0}" -f [regex]::Escape($t)) }
    }
    It 'the procedures are created ONCE and never altered by a release (an ALTER would drop the signature)' {
        foreach ($p in (Get-SISupportGrantContract).Procedures) { $script:Schema | Should -Match ("IF OBJECT_ID\(N'{0}'\) IS NULL EXEC \(N'CREATE PROCEDURE {0}" -f [regex]::Escape($p)) }
        $script:Schema | Should -Not -Match '(?i)CREATE OR ALTER PROCEDURE'
        $script:Schema | Should -Not -Match '(?i)ALTER PROCEDURE'
    }
    It 'the SHA-256 the sign step compares is the stored text''s (UTF-16LE, line endings removed)' {
        $h = Get-SISupportGrantProcedureSha256 -Name Open
        $h | Should -Match '^0x[0-9A-F]{64}$'
        $sha = [Security.Cryptography.SHA256]::Create()
        try { '0x' + (($sha.ComputeHash([Text.Encoding]::Unicode.GetBytes(($script:Proc['Open'] -replace "`r", ''))) | ForEach-Object { $_.ToString('X2') }) -join '') | Should -Be $h } finally { $sha.Dispose() }
    }
}

Describe 'the procedures: the principal, the level, the time, what is removed' {
    It 'each changing procedure checks its OWN signature first (51801)' {
        foreach ($n in 'Open', 'Close', 'Sweep') {
            $t = $script:Proc[$n]
            $t | Should -Match 'cp\.major_id = @@PROCID AND c\.name LIKE N''si_support_signer%'''
            $t.IndexOf('THROW 51801') | Should -BeLessThan $t.IndexOf('BEGIN TRANSACTION')
        }
    }
    It 'OPEN: the principal is ALWAYS the consent''s app (no principal parameter); the lower level; at most 24 h; a reason; a GUID request id' {
        $t = $script:Proc['Open']
        $t | Should -Match 'SELECT @app = AppId, @consent = \[Level\] FROM cfg\.SupportConsent WHERE Id = 1'
        $t | Should -Match 'DECLARE @sid varbinary\(85\) = CONVERT\(varbinary\(16\), @app\)'
        ($t -split "`n" | Select-Object -First 3) -join ' ' | Should -Not -Match '(?i)@(Sid|AppId|User|Principal|Role)\b'
        $t | Should -Match "WHEN @Level = N'setup' AND @consent = N'setup' THEN N'setup' ELSE N'troubleshoot'"
        $t | Should -Match "CASE @granted WHEN N'setup' THEN N'db_owner' ELSE N'db_datareader' END"
        $t | Should -Match 'DATEADD\(MINUTE, 1442, @now\)'
        $t | Should -Match 'THROW 51803'
        $t | Should -Match 'LEN\(@Reason\) > 200'
    }
    It 'OPEN: the role change and its marker in ONE transaction; a new open extends; the read-back is from the catalog' {
        $t = $script:Proc['Open']
        $b = $t.IndexOf('BEGIN TRANSACTION'); $c = $t.IndexOf('COMMIT TRANSACTION')
        $t.IndexOf('ALTER ROLE ') | Should -BeGreaterThan $b; $t.IndexOf('INSERT cfg.SupportJitMarker') | Should -BeLessThan $c
        $t | Should -Match 'SET XACT_ABORT ON'
        $t | Should -Match 'UPDATE cfg\.SupportJitMarker SET ExpiresUtc = @until WHERE ClosedUtc IS NULL AND ExpiresUtc < @until'
        $t.Substring($c) | Should -Match 'sys\.database_role_members'
    }
    It 'CLOSE / SWEEP: never a DROP USER, never the read-only role, only the two JIT roles, only what a marker ADDED (PreExisting = 0); the sweep only the expired' {
        foreach ($n in 'Close', 'Sweep') {
            $t = $script:Proc[$n]
            $t | Should -Not -Match '(?i)DROP USER'
            $t | Should -Not -Match "(?i)ALTER ROLE \[?si_support_read"
            $t | Should -Match "t\.PreExisting = 0 AND t\.RoleName IN \(N'db_owner', N'db_datareader'\)"
            $t | Should -Match 'DROP MEMBER'
            $t | Should -Match 'ReadOnlyHeld'
        }
        $script:Proc['Sweep'] | Should -Match 'ClosedUtc IS NULL AND ExpiresUtc <= @now'
        $script:Proc['Close'] | Should -Not -Match 'ExpiresUtc <= @now'
    }
    It 'the marker table accepts only the two JIT roles; the consent table one row of troubleshoot | setup, customer | derived' {
        $script:Schema | Should -Match "CK_SupportJitMarker_Role CHECK \(RoleName IN \(N'db_owner', N'db_datareader'\)\)"
        $script:Schema | Should -Match 'CK_SupportConsent_One CHECK \(Id = 1\)'
        $script:Schema | Should -Match "CK_SupportConsent_Source CHECK \(Source IN \(N'customer', N'derived'\)\)"
    }
    It 'the consent trigger: the database owner, or the updater ONCE with a DERIVED consent into the empty table -- nobody else' {
        $script:Schema | Should -Match "IF ISNULL\(IS_ROLEMEMBER\(N''db_owner''\), 0\) = 1 RETURN;"
        $script:Schema | Should -Match "NOT EXISTS \(SELECT 1 FROM inserted WHERE Source <> N''derived''\)"
        $script:Schema | Should -Match 'THROW 51806'
    }
    It 'every call the job and the heartbeat send passes the values as PARAMETERS' {
        Get-SISupportGrantCallSql -Name Open | Should -Be 'EXEC cfg.SupportGrantOpen @RequestId = @RequestId, @Level = @Level, @MaxUntilUtc = @MaxUntilUtc, @Reason = @Reason, @Ticket = @Ticket, @StartedBy = @StartedBy;'
        Get-SISupportGrantCallSql -Name Close | Should -Match '^EXEC cfg\.SupportGrantClose @RequestId = @RequestId, @Reason = @Reason, @StartedBy = @StartedBy;$'
    }
}

Describe 'the admin steps ONLY ADD (4a) and sign only this release''s text' {
    It 'in order: schema, user, consent, sign, grants -- and nothing removes a role, a user or a right' {
        $script:Steps.Step -join ';' | Should -Be 'schema;user;consent;sign;grants'
        foreach ($s in $script:Steps | Where-Object Step -ne 'schema') {
            $s.Sql | Should -Not -Match '(?i)DROP USER|DROP MEMBER|REVOKE |DELETE FROM'
        }
    }
    It 'user: the Support app''s own user by SID (its client id) when it has none, and the READ-ONLY role (metadata and health, no data)' {
        $u = @($script:Steps | Where-Object Step -eq 'user')[0].Sql
        $u | Should -Match ('WITH SID = {0}, TYPE = E' -f (ConvertTo-SISupportGrantSid -ClientId $script:App))
        $u | Should -Match 'GRANT VIEW DEFINITION TO \[si_support_read\];'
        $u | Should -Match 'GRANT VIEW DATABASE STATE TO \[si_support_read\];'
        $u | Should -Not -Match '(?i)db_owner|db_datareader|GRANT SELECT'
    }
    It 'consent: a derived consent never replaces the customer''s; no -Level = no consent step' {
        $d = @(Get-SISupportGrantAdminSteps -ClientId $script:App -Level troubleshoot -Source derived | Where-Object Step -eq 'consent')[0].Sql
        $d | Should -Match "AND NOT EXISTS \(SELECT 1 FROM cfg\.SupportConsent WHERE Id = 1 AND Source = N'customer'\)"
        @(Get-SISupportGrantAdminSteps -ClientId $script:App | Where-Object Step -eq 'consent').Count | Should -Be 0
    }
    It 'sign: the release''s SHA-256 of all four, refused otherwise (nothing signed); 2099; the signer in db_owner; the private key REMOVED last' {
        $s = @($script:Steps | Where-Object Step -eq 'sign')[0].Sql
        foreach ($n in 'Open', 'Close', 'Sweep', 'Status') { $s | Should -Match ([regex]::Escape((Get-SISupportGrantProcedureSha256 -Name $n))) }
        $s | Should -Match "HASHBYTES\('SHA2_256', REPLACE\(OBJECT_DEFINITION"
        $s.IndexOf('THROW 51807') | Should -BeLessThan $s.IndexOf('CREATE CERTIFICATE')
        $s | Should -Match "EXPIRY_DATE = ''20991231''"
        $s | Should -Match 'ALTER ROLE db_owner ADD MEMBER '' \+ QUOTENAME\(@cert\)'
        $s.IndexOf('ADD SIGNATURE') | Should -BeLessThan $s.IndexOf('REMOVE PRIVATE KEY')
    }
    It 'grants: EXECUTE for the engine (4) and the web app (sweep); DENY writes on the tables to the product roles; DENY ALTER to the updater' {
        $g = @($script:Steps | Where-Object Step -eq 'grants')[0].Sql
        foreach ($p in (Get-SISupportGrantContract).Procedures) { $g | Should -Match ("GRANT EXECUTE ON OBJECT::{0} TO \[si_engine\]" -f [regex]::Escape($p)) }
        $g | Should -Match 'GRANT EXECUTE ON OBJECT::cfg\.SupportGrantSweep TO \[si_web\]'
        $g | Should -Not -Match 'cfg\.SupportGrantOpen TO \[si_web\]'
        foreach ($t in (Get-SISupportGrantContract).Tables) { $g | Should -Match ("DENY INSERT, UPDATE, DELETE ON OBJECT::{0} TO \[si_engine\]" -f [regex]::Escape($t)) }
        $g | Should -Match 'DENY ALTER ON OBJECT::cfg\.SupportGrantOpen TO \[si_updater\]'
    }
    It 'the read-back names every gap in plain words; a complete row is Ok' {
        $ok = ConvertFrom-SISupportGrantState -Row @{ Database = 'd'; Tables = 3; Procedures = 4; Current = 4; Signed = 4; SignerOwner = 1; UserPresent = 1; ReadOnlyHeld = 1; Consent = 'setup|customer'; EngineExecute = 4 }
        $ok.Ok | Should -BeTrue
        $bad = ConvertFrom-SISupportGrantState -Row @{ Database = 'd'; Tables = 3; Procedures = 4; Current = 4; Signed = 2; SignerOwner = 0; UserPresent = 1; ReadOnlyHeld = 0; Consent = ''; EngineExecute = 0 }
        $bad.Ok | Should -BeFalse
        ($bad.Lines -join ' | ') | Should -Match 'signed.*db_owner.*read-only role.*no consent.*EXECUTE'
    }
}

Describe 'the engine''s and the web app''s rights on the support grant (least privilege)' {
    It 'the engine: EXECUTE on the four procedures; DENY writes on the three tables; the inventory sees only those EXECUTEs' {
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1')
        $rows = Get-SIEngineGrantList
        foreach ($p in (Get-SISupportGrantContract).Procedures) { @($rows | Where-Object { $_.Kind -eq 'object' -and $_.Target -eq $p -and $_.Permission -eq 'EXECUTE' }).Count | Should -Be 1 }
        foreach ($t in (Get-SISupportGrantContract).Tables) {
            @($rows | Where-Object { $_.Kind -eq 'object' -and $_.Target -eq $t }).Count | Should -Be 0
            @($rows | Where-Object { $_.Kind -eq 'deny' -and $_.Target -eq $t }).Count | Should -Be 3
        }
        $all = Get-SIEngineSqlReference -SIRoot $script:SIRoot   # answers ONE array (unrolled below)
        $refs = @($all | ForEach-Object { $_ } | Where-Object { $_.Object -like 'cfg.Support*' })
        @($refs | Where-Object { $_.Permission -notin 'EXECUTE', 'VIEW' }) | Should -BeNullOrEmpty
        @($refs | Where-Object Permission -eq 'EXECUTE' | ForEach-Object Object | Sort-Object -Unique) | Should -Be @('cfg.SupportGrantClose', 'cfg.SupportGrantOpen', 'cfg.SupportGrantStatus', 'cfg.SupportGrantSweep')
    }
    It 'the web app: EXECUTE on the sweep only; its sweep sends nothing but the procedure' {
        $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\deploy\SI-ManagementGrants.ps1'))
        $g | Should -Match "@\{ Object = 'cfg\.SupportGrantSweep';\s+Verbs = 'EXECUTE' \}"
        $g | Should -Not -Match "cfg\.Support(Consent|JitMarker|GrantOpen|GrantClose)'"
        $cs = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\Support\SupportGrantSweep.cs'))
        $cs | Should -Match "EXEC cfg\.SupportGrantSweep @By = N'web app';"
        $cs | Should -Match 'TimeSpan\.FromMinutes\(5\)'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\Notify\WebFeatureServices.cs')) | Should -Match 'AddHostedService<SI\.Management\.Web\.Support\.SupportGrantSweep>'
    }
}
