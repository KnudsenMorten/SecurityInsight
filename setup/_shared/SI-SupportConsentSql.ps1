#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the just-in-time support grant's per-database statements of setup\Grant-SISupportAccess.ps1: the
    Support app's standing read-only role and the customer's CONSENT, written so that a database WITHOUT the consent table
    still runs the batch.

.DESCRIPTION
    #1093 (a private Pro install on 3.0.31): Grant-SISupportAccess failed in the identity ledger database
    (sqldb-si-identity) with "Invalid object name 'cfg.SupportConsent'". Its IF OBJECT_ID guard did not help: the batch's
    last SELECT named the table inside a CASE, and SQL Server compiles a statement against every object it names, whichever
    branch runs. On a NEW install the ledger has no cfg schema yet at that point: the install's support-app step runs this
    script FIRST and puts the support grant's tables into the ledger right after (Set-SIInstallSupportAppDatabase,
    Get-SISupportGrantAdminSteps -- schema, user, consent, sign, grants).

    Which databases carry the consent (SI #1021, framework SECAUDIT-1a): EVERY product database -- the Pro database, the
    identity ledger, the data database -- has its own cfg.SupportConsent, because each one's signed procedures check the
    consent in that database before they open anything. So the consent is NOT left out of the ledger (a lowered level must
    reach every database, or one would keep the higher one); instead every statement on cfg.SupportConsent runs as dynamic
    SQL (sys.sp_executesql, parameters only) under its IF OBJECT_ID guard: a database that does not carry the table yet
    compiles and runs the batch and says "no support grant here yet" -- the support grant's own step brings the table and
    the consent -- and the step ends ok.
    Pure functions plus one that takes the database call as a script block -- the tests run them offline:
        -Run { param([string]$Database, [string]$Sql) }   ONE scalar from that database; throws on a refusal
    (A file loaded from inside a function: nothing here depends on a value of its own script scope.)
#>

function Get-SISupportGrantSql {
    <# PURE. The batch for ONE database: the Support app (by -Sid, its client id as 0x<16 bytes>) in the read-only role
       si_support_read where the database has it, and the consent at -Level where the database carries cfg.SupportConsent
       -- that table is named ONLY inside the sp_executesql text. Ends with ONE scalar: the consent as recorded
       ("setup (customer)"), or "no support grant here yet (the update brings it)". #>
    param([Parameter(Mandatory)][ValidatePattern('^0x[0-9A-Fa-f]{32}$')][string]$Sid,
          [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$AppId,
          [Parameter(Mandatory)][ValidateSet('troubleshoot', 'setup')][string]$Level)
    $AppId = ([guid]$AppId).ToString()
    $dyn = ("IF NOT EXISTS (SELECT 1 FROM cfg.SupportConsent WHERE Id = 1) INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, @a, @l, N'customer', N'Grant-SISupportAccess'); " +
            "ELSE UPDATE cfg.SupportConsent SET AppId = @a, [Level] = @l, Source = N'customer', ConsentedBy = N'Grant-SISupportAccess', ConsentedUtc = SYSUTCDATETIME() WHERE Id = 1; " +
            "SELECT @o = ISNULL((SELECT [Level] + N' (' + Source + N')' FROM cfg.SupportConsent WHERE Id = 1), N'');").Replace("'", "''")
    @(
        "DECLARE @n sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $Sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K')), @s nvarchar(400);",
        "IF @n IS NOT NULL AND DATABASE_PRINCIPAL_ID(N'si_support_read') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.role_principal_id = DATABASE_PRINCIPAL_ID(N'si_support_read') AND m.member_principal_id = DATABASE_PRINCIPAL_ID(@n)) BEGIN SET @s = N'ALTER ROLE [si_support_read] ADD MEMBER ' + QUOTENAME(@n) + N';'; EXEC (@s); END",
        "DECLARE @r nvarchar(400) = N'no support grant here yet (the update brings it)';",
        "IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL",
        "    EXEC sys.sp_executesql N'$dyn', N'@a uniqueidentifier, @l nvarchar(16), @o nvarchar(400) OUTPUT', @a = '$AppId', @l = N'$Level', @o = @r OUTPUT;",
        "SELECT @r;") -join "`n"
}

function Invoke-SISupportGrantDatabase {
    <# The read-only role and the consent in ONE database, through -Run. Never throws.
       Returns [pscustomobject]@{ Database; State = 'ok' | 'FAILED'; Consent (the scalar); Text (for the line); Sql }. #>
    param([Parameter(Mandatory)][scriptblock]$Run, [Parameter(Mandatory)][string]$Database,
          [Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$Level)
    $sql = Get-SISupportGrantSql -Sid $Sid -AppId $AppId -Level $Level
    try {
        $v = [string](& $Run $Database $sql)
        [pscustomobject]@{ Database = $Database; State = 'ok'; Consent = $v; Text = ('{0}: read-only role; consent {1}' -f $Database, $v); Sql = $sql }
    } catch {
        [pscustomobject]@{ Database = $Database; State = 'FAILED'; Consent = ''; Text = ('{0}: the read-only role / consent -- {1}' -f $Database, $_.Exception.Message); Sql = $sql }
    }
}
