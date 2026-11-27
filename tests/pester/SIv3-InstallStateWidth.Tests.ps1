#Requires -Version 5.1
<#
    #1426 cfg.InstallState.Value HAS NO SHORT LIMIT (owner rule: customer schemas: lengths >= the longest SI value, no short
    limits). At one install the identity-names report could not be stored: "String or binary data would be truncated in table
    'sqldb-si-pro.cfg.InstallState'" -- the column was NVARCHAR(400) and the report grows with the install.

    Proven here (offline, the shipped text): a new install creates the column NVARCHAR(MAX); an existing install reaches the
    same state through the updater's schema re-apply (one guarded ALTER COLUMN, a no-op once it reads -1); the file still
    passes the schema gate (which allows exactly this widening and nothing else); the two procedures the web app writes its
    rows through take NVARCHAR(MAX) (a procedure parameter cuts a longer value WITHOUT an error); and no writer reads the
    previous value into a shorter variable (DECLARE ... nvarchar(400) = (SELECT Value ...) cuts silently, too). Opt-in REAL SQL
    (SI_TEST_LOCALSQL): an old NVARCHAR(400) table with a row is widened, the row kept, a 5,000-character value stored and
    read back whole, and the block run twice changes nothing.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SqlText = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'sql', 'si-pro-settings.sql'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-SchemaGate.ps1'))
    # the widening block as the schema runner sends it (one blank-line-separated block)
    $script:ProductFiles = @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Include '*.ps1', '*.sql', '*.cs' | Where-Object { $_.FullName -notmatch '[\\/](tests|\.git|bin|obj)[\\/]' })
    $script:Widen = @($script:SqlText -split '(\r?\n){2,}' | Where-Object { $_ -match 'ALTER TABLE cfg\.InstallState ALTER COLUMN' })[0]
}

Describe '#1426 the schema: NVARCHAR(MAX) for a new install, the same for an existing one, idempotent' {
    It 'a new install creates Value NVARCHAR(MAX)' {
        $script:SqlText | Should -Match '(?s)CREATE TABLE cfg\.InstallState \(\s+Name\s+NVARCHAR\(64\)[^\r\n]*\r?\n\s+Value\s+NVARCHAR\(MAX\)\s+NOT NULL'
        $script:SqlText | Should -Not -Match '(?m)^\s+Value\s+NVARCHAR\(400\)\s+NOT NULL,\s*$' -Because 'no copy of the old column definition is left'
    }
    It 'an existing install is widened once, guarded on the column''s length (-1 = MAX: nothing to do)' {
        $script:Widen | Should -Not -BeNullOrEmpty
        $script:Widen | Should -Match "(?m)^IF COL_LENGTH\('cfg\.InstallState', 'Value'\) <> -1\r?\nALTER TABLE cfg\.InstallState ALTER COLUMN Value NVARCHAR\(MAX\) NOT NULL;"
        $script:SqlText.IndexOf('ALTER TABLE cfg.InstallState ALTER COLUMN') | Should -BeGreaterThan $script:SqlText.IndexOf('CREATE TABLE cfg.InstallState (') -Because 'after the table is there'
        @([regex]::Matches($script:SqlText, 'ALTER COLUMN')).Count | Should -Be 1 -Because 'the one widening, nothing else'
    }
    It 'the file still passes the schema gate (the updater refuses the whole set otherwise)' {
        $r = Test-SISchemaIsAdditive -Sql $script:SqlText
        @($r.Findings).Count | Should -Be 0 -Because ((@($r.Findings) | ForEach-Object { '{0}: {1}' -f $_.Line, $_.Why }) -join '; ')
    }
    It 'the file changed, so the updater''s schema step re-applies it on its next run (the schema record is a hash over the files)' {
        $code = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-ProSchema.ps1'))
        $code | Should -Match "sql\\si-pro-settings\.sql"
        $code | Should -Match 'SHA-256 over every file'
    }
}

Describe '#1426 nothing cuts a cfg.InstallState value without an error' {
    It 'the web app''s two write procedures take NVARCHAR(MAX) (a parameter cuts a longer value silently): <_>' -ForEach @('cfg.GuardStrictEndSet', 'cfg.MailRestrictionAttestationSet') {
        $script:SqlText | Should -Match ("CREATE OR ALTER PROCEDURE {0} @Value NVARCHAR\(MAX\)," -f [regex]::Escape($_))
    }
    It 'no file reads the stored value into a shorter variable -- DECLARE @x nvarchar(n) = (SELECT Value ...) or DECLARE @x nvarchar(n) ... SELECT @x = Value FROM cfg.InstallState' {
        $hits = foreach ($f in $script:ProductFiles) {
            $t = [IO.File]::ReadAllText($f.FullName)
            foreach ($m in [regex]::Matches($t, '(?i)DECLARE\s+@\w+\s+nvarchar\(\s*\d+\s*\)\s*=\s*\(\s*SELECT\s+Value\s+FROM\s+cfg\.InstallState')) { '{0}: {1}' -f $f.Name, $m.Value }
            foreach ($m in [regex]::Matches($t, '(?i)SELECT\s+(?:TOP\s*\(?\s*\d+\s*\)?\s+)?(@\w+)\s*=\s*(?:\w+\.)?Value\b[^;]*?FROM\s+cfg\.InstallState')) {
                $v = $m.Groups[1].Value
                foreach ($d in [regex]::Matches($t, '(?i)(?:DECLARE\s+|,\s*)' + [regex]::Escape($v) + '\s+nvarchar\(\s*\d+\s*\)')) { '{0}: {1} ({2})' -f $f.Name, $d.Value.Trim(), $m.Value }
            }
        }
        @($hits | Sort-Object -Unique) | Should -BeNullOrEmpty
    }
    It 'no writer cuts the value it stores (LEFT(@Value, n) into cfg.InstallState)' {
        $hits = foreach ($f in $script:ProductFiles) {
            foreach ($m in [regex]::Matches([IO.File]::ReadAllText($f.FullName), '(?i)(UPDATE\s+cfg\.InstallState\s+SET\s+Value\s*=\s*LEFT\(|INSERT\s+cfg\.InstallState\s*\([^)]*\)\s*VALUES\s*\([^,]+,\s*LEFT\()')) { '{0}: {1}' -f $f.Name, $m.Value }
        }
        @($hits) | Should -BeNullOrEmpty
    }
    It 'the identity-names report and the per-role move rows have no limit of their own any more' {
        . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-IdentityMove.ps1'))
        $script:SIMove.InstallStateMax | Should -Be 0
    }
}

Describe '#1426 REAL SQL (opt-in, SI_TEST_LOCALSQL): an old table is widened, its rows kept, a long value stored whole' {
    BeforeAll {
        $script:Server = "$env:SI_TEST_LOCALSQL".Trim()
        $script:Db = 'si_test_isw_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
        function script:Invoke-T([string]$Database, [string]$Sql, [switch]$Scalar) {
            $cn = New-Object System.Data.SqlClient.SqlConnection ("Server={0};Database={1};{2};Pooling=false" -f $script:Server, $Database, $env:SI_TEST_SQL_AUTH)
            $cn.Open()
            try { $c = $cn.CreateCommand(); $c.CommandText = $Sql; if ($Scalar) { $c.ExecuteScalar() } else { $null = $c.ExecuteNonQuery() } } finally { $cn.Close() }
        }
        if ($script:Server) {
            Invoke-T 'master' "CREATE DATABASE [$($script:Db)];"
            Invoke-T $script:Db "CREATE SCHEMA cfg;"
            Invoke-T $script:Db "CREATE TABLE cfg.InstallState (Name NVARCHAR(64) NOT NULL CONSTRAINT PK_InstallState PRIMARY KEY, Value NVARCHAR(400) NOT NULL, [Version] NVARCHAR(32) NULL, UpdatedAt DATETIME2(0) NOT NULL DEFAULT SYSUTCDATETIME(), UpdatedBy NVARCHAR(256) NOT NULL);"
            Invoke-T $script:Db "INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'Ring', N'{""ring"":1}', N'test');"
        }
    }
    AfterAll { if ($script:Server) { try { Invoke-T 'master' "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)];" } catch { } } }
    It 'the old column refuses a long value with an error (never a cut) -- the failure the install saw' {
        if (-not $script:Server) { Set-ItResult -Skipped -Because 'SI_TEST_LOCALSQL is not set'; return }
        { Invoke-T $script:Db ("DECLARE @v nvarchar(max) = REPLICATE(CONVERT(nvarchar(max), N'a'), 5000); INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'IdentityNames', @v, N'test');") } | Should -Throw '*truncated*'
    }
    It 'the shipped block widens it, the row stays, a 5,000-character value is stored and read back whole; twice = no change' {
        if (-not $script:Server) { Set-ItResult -Skipped -Because 'SI_TEST_LOCALSQL is not set'; return }
        Invoke-T $script:Db $script:Widen
        Invoke-T $script:Db "SELECT COL_LENGTH('cfg.InstallState', 'Value')" -Scalar | Should -Be -1
        Invoke-T $script:Db "SELECT Value FROM cfg.InstallState WHERE Name = N'Ring'" -Scalar | Should -Be '{"ring":1}'
        Invoke-T $script:Db ("DECLARE @v nvarchar(max) = REPLICATE(CONVERT(nvarchar(max), N'a'), 5000); INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'IdentityNames', @v, N'test');")
        Invoke-T $script:Db "SELECT LEN(Value) FROM cfg.InstallState WHERE Name = N'IdentityNames'" -Scalar | Should -Be 5000
        Invoke-T $script:Db $script:Widen
        Invoke-T $script:Db "SELECT COUNT(*) FROM cfg.InstallState" -Scalar | Should -Be 2
    }
}
