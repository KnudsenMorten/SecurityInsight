#Requires -Version 5.1
<#
    THE USERS' SIGN-IN METHODS IN FULL, READ IN THE BACKGROUND, THE CUSTOMER'S CHOICE (owner 2026-11-05: "make the auth api
    collection a gui setting. mark it as slow as consequence if not enabled. let customer understand and decide" / "can we
    cache auth methods and chk for last chg hash per user" / "but i need all these details that per user covers" /
    "including device info" / "it must be covered all in si" / "yes do that" -- the pipeline never waits for the read).

    TWO SOURCES
      the tenant-wide registration report (reports/authenticationMethods/userRegistrationDetails) -- read by EVERY identity
          collection for every user (IdentityRoleFetcher.ps1): MFA registered / capable, passwordless capable, SSPR registered
          / capable / enabled, the registered methods, default / preferred / system-preferred methods, isAdmin, last update.
      the per-user read (GET /users/{id}/authentication/methods + the device of each Windows Hello for Business / Microsoft
          Authenticator method, $expand=device; SI-AuthMethodsRead.ps1) -- every property of every method. It is the only
          source of: si_auth_methods (the full detail and the device), si_auth_method_types, si_has_password,
          si_passwordless_only, and the link to the device's CI. It is slow on a large tenant (one read per user, Microsoft
          throttles: about 8.5 hours at 150,000 users), so the PIPELINE NEVER MAKES IT:

    THE COLLECTION (Invoke-SISignInMethodsPage, inside the identity collection's user pages -- no Graph call)
      For each page of users it records, in ONE statement, the user's work row in sidata.UserSignInMethods (privileged or not,
      the change key the registration report gives it today, seen now) and takes the saved detail of the users the choice
      covers. A user with saved detail gets its record part 'authenticationMethods' from it, with the date it was read
      (si_auth_methods_read); a user not read yet has no part: unknown, never no.

    THE FILLER (Invoke-SISignInMethodsFill, its OWN job caj-si-signin-methods every 15 minutes -- engine\signin-methods\Invoke-SISignInMethods.ps1)
      Reads per user, into the saved detail, for at most SI_Identity_SignInMethodsFillMinutes (default 8) per tick, then
      stops and carries on next tick; one tick at a time (the claim row cfg.InstallState 'SignInMethodsFill'). Who is read
      first (one SQL pick, Get-SISignInMethodsFillPickSql):
        1. privileged users (an Entra role permanent or eligible, through a group or PIM for Groups, an Azure role, or the
           report's isAdmin -- as the last collection recorded it), by the order below
        2. users whose change key differs from the key their detail was read under (the report's lastUpdatedDateTime AND a
           hash of its methodsRegistered: both, because lastUpdatedDateTime can lag), or whose devices were not read whole
        3. users never read
        4. users read SI_Identity_SignInMethodsMaxAgeDays (default 90) ago or longer, oldest first
      A user tried in the last 10 minutes is not picked again (a throttled user waits for the next tick); a user the last
      14 days of collections did not list is not read.

    THE CHOICE (SI_Identity_SignInMethodsPerUser) -- which users the filler reads, and whose saved detail the collection uses
      all         every member user the identity profile keeps (default)
      privileged  privileged users only
      off         nobody: no filler, the tenant-wide report only
      Anything else is read as the default, and said.

    NEVER FAILS A RUN: the saved detail that cannot be read or written (no database, the tables not there yet, an error) is
    given up for the run and said ONCE; the users are then unknown, never no.
    PowerShell 5.1 and 7: no ?. / ??, no ternary. Graph and SQL only behind seams (-ReadUsers, -Invoke, -ProInvoke).
    Tests: tests\pester\SIv3-SignInMethodsSetting.Tests.ps1.
#>

$script:SISignInMethodsModes = @('all', 'privileged', 'off')
$script:SISignInMethodsDefaults = @{ Mode = 'all'; MaxAgeDays = 90; FillMinutes = 8 }
$script:SISignInMethodsFill = @{ ClaimRow = 'SignInMethodsFill'; BatchSize = 200; RetryAfterMinutes = 10; ListedWithinDays = 14; KeepUnlistedDays = 60 }
if (-not (Get-Variable -Name _SICache -Scope Script -ErrorAction SilentlyContinue)) { $script:_SICache = @{} }

# =====================================================================================================================
#  The choice -- PURE
# =====================================================================================================================
function Get-SISignInMethodsChoice {
    <#
        PURE (reads the three settings unless -Values is passed). The install's choice: @{ Mode; MaxAgeDays; FillMinutes; Note }.
        Mode: all | privileged | off (not set = all); MaxAgeDays: 1..365 (not set = 90); FillMinutes: 1..25 (not set = 8). A
        value that is none of these = the default, with a Note.
    #>
    param([hashtable]$Values)
    $raw = @{}
    foreach ($n in 'SI_Identity_SignInMethodsPerUser', 'SI_Identity_SignInMethodsMaxAgeDays', 'SI_Identity_SignInMethodsFillMinutes') {
        if ($Values) { if ($Values.ContainsKey($n)) { $raw[$n] = $Values[$n] } }
    }
    if (-not $Values) {
        $raw['SI_Identity_SignInMethodsPerUser'] = $global:SI_Identity_SignInMethodsPerUser
        $raw['SI_Identity_SignInMethodsMaxAgeDays'] = $global:SI_Identity_SignInMethodsMaxAgeDays
        $raw['SI_Identity_SignInMethodsFillMinutes'] = $global:SI_Identity_SignInMethodsFillMinutes
    }
    $notes = New-Object System.Collections.Generic.List[string]
    $mode = $script:SISignInMethodsDefaults.Mode
    $m = ([string]$raw['SI_Identity_SignInMethodsPerUser']).Trim().ToLowerInvariant()
    if ($m) {
        if ($script:SISignInMethodsModes -contains $m) { $mode = $m }
        else { $notes.Add(("SI_Identity_SignInMethodsPerUser '{0}' is not one of all / privileged / off -- '{1}' is used" -f [string]$raw['SI_Identity_SignInMethodsPerUser'], $mode)) }
    }
    $num = {
        param([string]$Name, [int]$Default, [int]$Min, [int]$Max)
        $v = $Default
        $a = ([string]$raw[$Name]).Trim()
        if ($a) {
            $n = 0
            if ([int]::TryParse($a, [ref]$n) -and $n -ge $Min -and $n -le $Max) { $v = $n }
            else { $notes.Add(("{0} '{1}' is not a whole number from {2} to {3} -- {4} is used" -f $Name, $a, $Min, $Max, $Default)) }
        }
        $v
    }
    $age = & $num 'SI_Identity_SignInMethodsMaxAgeDays' $script:SISignInMethodsDefaults.MaxAgeDays 1 365
    $fill = & $num 'SI_Identity_SignInMethodsFillMinutes' $script:SISignInMethodsDefaults.FillMinutes 1 25
    [pscustomobject]@{ Mode = $mode; MaxAgeDays = [int]$age; FillMinutes = [int]$fill; Note = ($notes -join '; ') }
}

function Test-SISignInMethodsLookupHas {
    <# PURE. $true when a lookup (hashtable or SI's on-disk lookup) holds a non-empty value for the key. #>
    param([AllowNull()]$Map, [string]$Key)
    if ($null -eq $Map -or -not $Key) { return $false }
    $has = $false
    try { $has = [bool]$Map.ContainsKey($Key) } catch { $has = $false }
    if (-not $has) { return $false }
    $v = $Map[$Key]
    if ($null -eq $v) { return $false }
    if ($v -is [string]) { return [bool]$v.Trim() }
    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [System.Collections.IDictionary])) { return (@($v | Where-Object { $null -ne $_ }).Count -gt 0) }
    return $true
}

function Test-SISignInMethodsPrivileged {
    <#
        PURE. Is the user privileged (read first by the filler; the only users read under 'privileged')? From the lookups the
        identity discovery builds BEFORE the user pages: -Lookups @{ PermRoles; EligRoles (principal -> roles); MemberToGroups
        (member -> the role-holding groups it is in); PimGroups (principal -> PIM for Groups eligibility); Azure (principal or
        group -> Azure role assignments); Registration (user -> the registration report entry: IsAdmin) }.
    #>
    param([string]$UserId, [hashtable]$Lookups)
    if (-not $UserId -or $null -eq $Lookups) { return $false }
    # PimGroupMembers (#1192): a plain member of a group that holds nothing but can activate into a privilege-holding group
    foreach ($k in 'PermRoles', 'EligRoles', 'MemberToGroups', 'PimGroups', 'PimGroupMembers', 'Azure') {
        if ($Lookups.ContainsKey($k) -and (Test-SISignInMethodsLookupHas -Map $Lookups[$k] -Key $UserId)) { return $true }
    }
    if ($Lookups.ContainsKey('MemberToGroups') -and $Lookups.ContainsKey('Azure') -and $null -ne $Lookups['Azure'] -and (Test-SISignInMethodsLookupHas -Map $Lookups['MemberToGroups'] -Key $UserId)) {
        foreach ($g in @($Lookups['MemberToGroups'][$UserId])) { if (Test-SISignInMethodsLookupHas -Map $Lookups['Azure'] -Key ([string]$g)) { return $true } }
    }
    if ($Lookups.ContainsKey('Registration') -and $null -ne $Lookups['Registration']) {
        $e = $null; try { $e = $Lookups['Registration'][$UserId] } catch { $e = $null }
        if ($e -and $e.PSObject.Properties['IsAdmin'] -and $e.IsAdmin -eq $true) { return $true }
    }
    return $false
}

function Get-SISignInMethodsHashText {
    <# PURE. The lower-case SHA-256 hex of a text. #>
    param([AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text)) } finally { $sha.Dispose() }
    -join ($b | ForEach-Object { $_.ToString('x2') })
}

function ConvertTo-SISignInMethodsStamp {
    <# PURE. The report's lastUpdatedDateTime as one fixed text (UTC, to the second); '' when there is none. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
    $s = ([string]$Value).Trim()
    if (-not $s) { return '' }
    $d = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([DateTimeOffset]::TryParse($s, $inv, $styles, [ref]$d)) { return $d.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
    $s
}

function Get-SISignInMethodsChangeKey {
    <#
        PURE. The change key of one user from its registration report entry: @{ Stamp (lastUpdatedDateTime); Hash (SHA-256 of
        the registered methods, lower case, sorted, once each) }. No entry = $null (the key is unknown: the filler reads it).
    #>
    param([AllowNull()]$Entry)
    if ($null -eq $Entry) { return $null }
    $list = $null
    if ($Entry.PSObject.Properties['MethodsRegistered']) { $list = $Entry.MethodsRegistered }
    elseif ($Entry.PSObject.Properties['methodsRegistered']) { $list = $Entry.methodsRegistered }
    elseif ($Entry.PSObject.Properties['MfaMethods']) { $list = $Entry.MfaMethods }
    $items = @(@($list) | Where-Object { $null -ne $_ -and ([string]$_).Trim() } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $stamp = $null
    if ($Entry.PSObject.Properties['MfaLastUpdatedDateTime']) { $stamp = $Entry.MfaLastUpdatedDateTime }
    elseif ($Entry.PSObject.Properties['lastUpdatedDateTime']) { $stamp = $Entry.lastUpdatedDateTime }
    [pscustomobject]@{ Stamp = (ConvertTo-SISignInMethodsStamp $stamp); Hash = (Get-SISignInMethodsHashText ($items -join ',')) }
}

function ConvertTo-SISignInMethodsDetail {
    <# PURE. The saved detail of one user read whole: {"methods":[every property of every method, with its device],"devicesRead":bool}. #>
    param([AllowNull()][object[]]$Methods, [bool]$DevicesRead = $true)
    $ms = @(foreach ($m in @($Methods)) { if ($null -ne $m) { [pscustomobject](ConvertTo-SIAuthMethodRaw -Method $m) } })
    ConvertTo-Json -InputObject ([ordered]@{ methods = $ms; devicesRead = [bool]$DevicesRead }) -Depth 12 -Compress
}

function ConvertFrom-SISignInMethodsDetail {
    <# PURE. The saved detail back: @{ Methods (each through ConvertTo-SIAuthMethodRaw -- the same objects a fresh read keeps);
       DevicesRead }, or $null when it does not read back. #>
    param([AllowNull()][string]$Text)
    if (-not $Text -or -not $Text.Trim()) { return $null }
    $o = $null
    try { $o = $Text | ConvertFrom-Json } catch { return $null }
    if ($null -eq $o -or -not $o.PSObject.Properties['methods']) { return $null }
    $ms = @(foreach ($m in @($o.methods)) { if ($null -ne $m) { ConvertTo-SIAuthMethodRaw -Method $m } })
    $dr = $true; if ($o.PSObject.Properties['devicesRead']) { $dr = [bool]$o.devicesRead }
    [pscustomobject]@{ Methods = $ms; DevicesRead = $dr }
}

function ConvertTo-SISignInMethodsUtc {
    <# PURE. A saved time (DATETIME2 as ISO text or a [datetime]) as a UTC [datetime]; $null when there is none. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $d = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d.UtcDateTime }
    $null
}

function Get-SISqlRowValue {
    <# PURE. A column of a row (object or dictionary); DBNull = $null. #>
    param([AllowNull()]$Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    else { $p = $Row.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($v -is [DBNull]) { return $null }
    $v
}

# =====================================================================================================================
#  The saved detail -- SQL (the seams: data { param($Sql, $Params, $Mode) } = New-SIRecordSqlInvoke; Pro = the Pro store)
# =====================================================================================================================
$script:SISignInMethodsMissingTables = "IF OBJECT_ID(N'sidata.UserSignInMethods') IS NULL OR OBJECT_ID(N'sidata.UserSignInMethodsDetail') IS NULL THROW 50000, N'the tables of the saved sign-in methods are not in the database yet (the next update adds them)', 1;"

function Get-SISignInMethodsPageSql {
    <#
        ONE statement per page of users of the identity collection: records each user's work row (@rows = [{ UserId; Privileged;
        Stamp; Hash; InScope }]: privileged, the change key the report gives today, seen @now) and answers the saved detail of
        the users in scope (InScope = 1) that were read: UserId, ReadStamp, ReadHash, CurrentStamp, CurrentHash, ReadAt,
        DevicesRead, Detail.
    #>
    @"
SET NOCOUNT ON;
$($script:SISignInMethodsMissingTables)
DECLARE @t DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), @now, 127), SYSUTCDATETIME());
DECLARE @r TABLE (UserId NVARCHAR(64) NOT NULL PRIMARY KEY, Privileged BIT NOT NULL, Stamp NVARCHAR(64) NULL, Hash NVARCHAR(64) NULL, InScope BIT NOT NULL);
INSERT @r (UserId, Privileged, Stamp, Hash, InScope)
SELECT LOWER(x.UserId), MAX(CASE WHEN x.Privileged = 1 THEN 1 ELSE 0 END), MAX(x.Stamp), MAX(x.Hash), MAX(CASE WHEN x.InScope = 1 THEN 1 ELSE 0 END)
FROM OPENJSON(@rows) WITH (UserId NVARCHAR(64), Privileged BIT, Stamp NVARCHAR(64), Hash NVARCHAR(64), InScope BIT) x
WHERE x.UserId IS NOT NULL AND x.UserId <> N''
GROUP BY LOWER(x.UserId);
MERGE sidata.UserSignInMethods AS t
USING @r AS s ON t.UserId = s.UserId
WHEN MATCHED THEN UPDATE SET Privileged = s.Privileged, CurrentStamp = s.Stamp, CurrentHash = s.Hash, SeenAt = @t
WHEN NOT MATCHED THEN INSERT (UserId, Privileged, CurrentStamp, CurrentHash, SeenAt) VALUES (s.UserId, s.Privileged, s.Stamp, s.Hash, @t);
SELECT w.UserId, w.ReadStamp, w.ReadHash, w.CurrentStamp, w.CurrentHash, CONVERT(NVARCHAR(33), w.ReadAt, 127) AS ReadAt,
       CAST(ISNULL(w.DevicesRead, 0) AS INT) AS DevicesRead, CAST(DECOMPRESS(d.Detail) AS NVARCHAR(MAX)) AS Detail
FROM @r s
JOIN sidata.UserSignInMethods w ON w.UserId = s.UserId
JOIN sidata.UserSignInMethodsDetail d ON d.UserId = s.UserId
WHERE s.InScope = 1 AND w.ReadAt IS NOT NULL;
"@
}

function Get-SISignInMethodsFillPickSql {
    <#
        The filler's next @n users, in priority order (header: privileged first; then a changed key or devices not read whole;
        then never read; then read @maxAge days ago or longer, oldest first), and marks them tried (@now) so they are not
        picked again for 10 minutes. @all = 1: every user; 0: privileged only. Answers UserId, CurrentStamp, CurrentHash,
        Privileged, Reason (changed | never | maxage).
    #>
    @"
SET NOCOUNT ON;
$($script:SISignInMethodsMissingTables)
DECLARE @t DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), @now, 127), SYSUTCDATETIME());
DECLARE @take INT = ISNULL(TRY_CONVERT(INT, @n), 200), @days INT = ISNULL(TRY_CONVERT(INT, @maxAge), 90), @every BIT = CASE WHEN @all = N'1' THEN 1 ELSE 0 END;
WITH due AS (
    SELECT TOP (@take) w.*
    FROM sidata.UserSignInMethods w
    WHERE w.SeenAt >= DATEADD(day, -$($script:SISignInMethodsFill.ListedWithinDays), @t)
      AND (@every = 1 OR w.Privileged = 1)
      AND (w.LastTryAt IS NULL OR w.LastTryAt < DATEADD(minute, -$($script:SISignInMethodsFill.RetryAfterMinutes), @t))
      AND (w.ReadAt IS NULL OR ISNULL(w.ReadStamp, N'') <> ISNULL(w.CurrentStamp, N'') OR ISNULL(w.ReadHash, N'') <> ISNULL(w.CurrentHash, N'')
           OR w.DevicesRead = 0 OR w.ReadAt < DATEADD(day, -@days, @t))
    ORDER BY w.Privileged DESC,
             CASE WHEN w.ReadAt IS NOT NULL AND (ISNULL(w.ReadStamp, N'') <> ISNULL(w.CurrentStamp, N'') OR ISNULL(w.ReadHash, N'') <> ISNULL(w.CurrentHash, N'') OR w.DevicesRead = 0) THEN 0
                  WHEN w.ReadAt IS NULL THEN 1
                  ELSE 2 END,
             ISNULL(w.LastTryAt, '19000101'), w.ReadAt, w.UserId
)
UPDATE due SET LastTryAt = @t
OUTPUT inserted.UserId, inserted.CurrentStamp, inserted.CurrentHash, CAST(inserted.Privileged AS INT) AS Privileged,
       CASE WHEN inserted.ReadAt IS NULL THEN N'never'
            WHEN ISNULL(inserted.ReadStamp, N'') <> ISNULL(inserted.CurrentStamp, N'') OR ISNULL(inserted.ReadHash, N'') <> ISNULL(inserted.CurrentHash, N'') OR inserted.DevicesRead = 0 THEN N'changed'
            ELSE N'maxage' END AS Reason;
"@
}

function Get-SISignInMethodsFillSaveSql {
    <# Saves what the filler read: @rows = [{ UserId; Stamp; Hash; Detail (JSON text, kept compressed); DevicesRead; ReadAt }].
       Answers Written. Also lets go of users no collection listed for 60 days (a bounded number per call). #>
    @"
SET NOCOUNT ON;
$($script:SISignInMethodsMissingTables)
DECLARE @s TABLE (UserId NVARCHAR(64) NOT NULL PRIMARY KEY, Stamp NVARCHAR(64) NULL, Hash NVARCHAR(64) NULL, Detail NVARCHAR(MAX) NULL, DevicesRead BIT NOT NULL, ReadAt DATETIME2(3) NOT NULL);
INSERT @s (UserId, Stamp, Hash, Detail, DevicesRead, ReadAt)
SELECT LOWER(x.UserId), MAX(x.Stamp), MAX(x.Hash), MAX(x.Detail), MAX(CASE WHEN x.DevicesRead = 1 THEN 1 ELSE 0 END), ISNULL(MAX(TRY_CONVERT(DATETIME2(3), x.ReadAt, 127)), SYSUTCDATETIME())
FROM OPENJSON(@rows) WITH (UserId NVARCHAR(64), Stamp NVARCHAR(64), Hash NVARCHAR(64), Detail NVARCHAR(MAX), DevicesRead BIT, ReadAt NVARCHAR(40)) x
WHERE x.UserId IS NOT NULL AND x.UserId <> N'' AND x.Detail IS NOT NULL
GROUP BY LOWER(x.UserId);
UPDATE w SET ReadStamp = s.Stamp, ReadHash = s.Hash, ReadAt = s.ReadAt, DevicesRead = s.DevicesRead
FROM sidata.UserSignInMethods w JOIN @s s ON s.UserId = w.UserId;
DECLARE @n INT = @@ROWCOUNT;
MERGE sidata.UserSignInMethodsDetail AS t
USING (SELECT s.UserId, COMPRESS(s.Detail) AS Detail FROM @s s JOIN sidata.UserSignInMethods w ON w.UserId = s.UserId) AS s ON t.UserId = s.UserId
WHEN MATCHED THEN UPDATE SET Detail = s.Detail
WHEN NOT MATCHED THEN INSERT (UserId, Detail) VALUES (s.UserId, s.Detail);
DELETE TOP (5000) d FROM sidata.UserSignInMethodsDetail d JOIN sidata.UserSignInMethods w ON w.UserId = d.UserId WHERE w.SeenAt < DATEADD(day, -$($script:SISignInMethodsFill.KeepUnlistedDays), SYSUTCDATETIME());
DELETE TOP (5000) FROM sidata.UserSignInMethods WHERE SeenAt < DATEADD(day, -$($script:SISignInMethodsFill.KeepUnlistedDays), SYSUTCDATETIME());
SELECT @n AS Written;
"@
}

function Get-SISignInMethodsFillClaimSql {
    <# Claim the filler for @until (cfg.InstallState 'SignInMethodsFill'): no row, or a claim that ran out (until < @now) = taken.
       Answers Claimed (1 / 0). No cfg.InstallState = 0 (no claim can be shared: the tick does not read). #>
    @"
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NULL BEGIN SELECT CAST(0 AS int) AS Claimed; RETURN; END
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @cur NVARCHAR(400) = NULL, @has int = 0, @ok int = 0;
SELECT @cur = Value, @has = 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'$($script:SISignInMethodsFill.ClaimRow)';
DECLARE @u DATETIME2(0) = CASE WHEN ISJSON(@cur) = 1 THEN TRY_CONVERT(DATETIME2(0), JSON_VALUE(@cur, '`$.until'), 127) END;
IF @has = 0 BEGIN INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'$($script:SISignInMethodsFill.ClaimRow)', @Value, NULL, N'sign-in methods'); SET @ok = 1; END
ELSE IF @u IS NULL OR @u < TRY_CONVERT(DATETIME2(0), @now, 127)
BEGIN UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'sign-in methods' WHERE Name = N'$($script:SISignInMethodsFill.ClaimRow)'; SET @ok = 1; END
COMMIT;
SELECT @ok AS Claimed;
"@
}

function Get-SISignInMethodsFillReleaseSql {
    <# Ends this tick's claim (only while the row is still this tick's: @by). #>
    @"
SET NOCOUNT ON;
DECLARE @n int = 0;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'sign-in methods'
    WHERE Name = N'$($script:SISignInMethodsFill.ClaimRow)' AND ISJSON(Value) = 1 AND JSON_VALUE(Value, '`$.by') = @by;
    SET @n = @@ROWCOUNT;
END
SELECT @n AS Released;
"@
}

function Get-SISignInMethodsSettingsSql {
    <# The install's stored choice (cfg.Setting, scope solution or the identity engine) -- the filler runs outside the engines'
       settings layer. #>
    "SELECT Name, Scope, ValueJson FROM cfg.Setting WHERE Name IN (N'SI_Identity_SignInMethodsPerUser', N'SI_Identity_SignInMethodsMaxAgeDays', N'SI_Identity_SignInMethodsFillMinutes') AND (Scope = N'solution' OR Scope LIKE N'engine:identity%')"
}

function New-SISignInMethodsCache {
    <# The collection's handle on the saved detail: @{ Invoke; Usable; Note; Noted }. -Invoke: the data seam; none = the
       install's database (New-SIRecordSqlInvoke); no database = not usable (said once). #>
    param([scriptblock]$Invoke, [switch]$NoDatabaseLookup)
    if (-not $Invoke -and -not $NoDatabaseLookup) {
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) {
            $rs = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'SI-RecordSql.ps1')
            if ([IO.File]::Exists($rs)) { try { . $rs } catch { } }
        }
        if (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) { try { $Invoke = New-SIRecordSqlInvoke } catch { $Invoke = $null } }
    }
    $c = [pscustomobject]@{ Invoke = $Invoke; Usable = [bool]$Invoke; Note = ''; Noted = $false }
    if (-not $Invoke) { $c.Note = 'no database is configured for this install' }
    $c
}

function Set-SISignInMethodsCacheBroken {
    <# The saved detail is given up for the rest of the run; said ONCE (information: the run goes on, the users are unknown). #>
    param([Parameter(Mandatory)]$Cache, [string]$Why)
    $Cache.Usable = $false
    if (-not $Cache.Note) { $Cache.Note = $Why }
    if (-not $Cache.Noted) {
        $Cache.Noted = $true
        $m = ('[perms] sign-in methods: the saved detail could not be used ({0}) -- this run shows the users'' per-user sign-in facts as unknown, never as no; the registration report''s facts are complete' -f $Why)
        if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m }
    }
}

# =====================================================================================================================
#  The identity collection: one page of users, from the saved detail only (no Graph call)
# =====================================================================================================================
function Reset-SISignInMethodsPlan { $script:_SICache.Remove('SignInMethodsPlan') }

function Get-SISignInMethodsPlan {
    <# This run's counts: Mode; MaxAgeDays; Users; InScope; OutOfScope; FromSaved; NotRead; Stale; Oldest (the oldest read date taken). #>
    if (-not $script:_SICache.ContainsKey('SignInMethodsPlan') -or $null -eq $script:_SICache['SignInMethodsPlan']) {
        $script:_SICache['SignInMethodsPlan'] = [pscustomobject]@{ Mode = ''; MaxAgeDays = 0; Users = 0; InScope = 0; OutOfScope = 0; FromSaved = 0; NotRead = 0; Stale = 0; Oldest = $null; PasswordlessOnly = 0 }
    }
    $script:_SICache['SignInMethodsPlan']
}

function Invoke-SISignInMethodsPage {
    <#
        One page of users (already narrowed by Select-SIAuthMethodReadUsers): records their work rows and answers user id ->
        @{ ReadComplete; PasswordlessOnly; MethodTypes; Methods; DevicesRead; ReadAt } for every user in scope with saved
        detail, writing its record part (the same part a fresh read writes, dated with the read). NO GRAPH CALL. Never throws.
          -Choice        Get-SISignInMethodsChoice;  -IsPrivileged { param($User) } -> bool
          -Registration  the registration report lookup (user id -> entry): the change key;  -Cache  New-SISignInMethodsCache
    #>
    param(
        [AllowNull()][object[]]$Users,
        [Parameter(Mandatory)]$Choice,
        [scriptblock]$IsPrivileged,
        [AllowNull()]$Registration,
        [AllowNull()]$Cache,
        [datetime]$Now = [datetime]::UtcNow
    )
    $plan = Get-SISignInMethodsPlan
    $plan.Mode = [string]$Choice.Mode; $plan.MaxAgeDays = [int]$Choice.MaxAgeDays
    $answer = @{}
    $list = @(@($Users) | Where-Object { $null -ne $_ -and [string]$_.id })
    if ($list.Count -eq 0) { return $answer }
    $plan.Users = [int]$plan.Users + $list.Count
    if ($Choice.Mode -eq 'off') { $plan.OutOfScope = [int]$plan.OutOfScope + $list.Count; return $answer }

    $rows = New-Object System.Collections.Generic.List[object]
    $byId = @{}
    foreach ($u in $list) {
        $id = [string]$u.id; $lid = $id.ToLowerInvariant()
        $priv = $false
        if ($IsPrivileged) { try { $priv = [bool](& $IsPrivileged $u) } catch { $priv = $false } }
        $in = ($Choice.Mode -eq 'all' -or $priv)
        if ($in) { $plan.InScope = [int]$plan.InScope + 1 } else { $plan.OutOfScope = [int]$plan.OutOfScope + 1 }
        $entry = $null
        if ($null -ne $Registration) { try { $entry = $Registration[$id] } catch { $entry = $null } }
        $key = Get-SISignInMethodsChangeKey -Entry $entry
        $rows.Add([ordered]@{ UserId = $lid; Privileged = $priv; Stamp = $(if ($key) { [string]$key.Stamp } else { $null }); Hash = $(if ($key) { [string]$key.Hash } else { $null }); InScope = $in })
        $byId[$lid] = $u
    }
    $saved = @()
    if ($Cache -and $Cache.Usable) {
        try {
            $j = ConvertTo-Json -InputObject @($rows.ToArray()) -Compress -Depth 4
            if (-not $j.TrimStart().StartsWith('[')) { $j = '[' + $j + ']' }
            $saved = @(& $Cache.Invoke (Get-SISignInMethodsPageSql) @{ rows = $j; now = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture) } 'rows')
        } catch { Set-SISignInMethodsCacheBroken -Cache $Cache -Why ([string]$_.Exception.Message); $saved = @() }
    }
    $got = 0
    foreach ($r in $saved) {
        if ($null -eq $r) { continue }
        $lid = ([string](Get-SISqlRowValue $r 'UserId')).ToLowerInvariant()
        if (-not $lid -or -not $byId.ContainsKey($lid)) { continue }
        $d = ConvertFrom-SISignInMethodsDetail ([string](Get-SISqlRowValue $r 'Detail'))
        if ($null -eq $d) { continue }
        $u = $byId[$lid]
        $readAt = ConvertTo-SISignInMethodsUtc (Get-SISqlRowValue $r 'ReadAt'); if ($null -eq $readAt) { continue }
        $types = @(Get-SIAuthMethodTypes -Methods $d.Methods)
        $verdict = Get-SIPasswordlessOnlyVerdict -Methods $types -ReadComplete $true -User $u
        $res = [pscustomobject]@{ ReadComplete = $true; PasswordlessOnly = $verdict; MethodTypes = $types; Methods = $d.Methods; DevicesRead = [bool]$d.DevicesRead; ReadAt = $readAt }
        $answer[[string]$u.id] = $res
        Add-SIAuthMethodsRecordPart -User $u -Result $res -ReadAt $readAt
        $got++
        if ($verdict -eq $true) { $plan.PasswordlessOnly = [int]$plan.PasswordlessOnly + 1 }
        if ($null -eq $plan.Oldest -or $readAt -lt $plan.Oldest) { $plan.Oldest = $readAt }
        $stale = ([string](Get-SISqlRowValue $r 'ReadStamp') -ne [string](Get-SISqlRowValue $r 'CurrentStamp')) -or ([string](Get-SISqlRowValue $r 'ReadHash') -ne [string](Get-SISqlRowValue $r 'CurrentHash')) -or (($Now.ToUniversalTime() - $readAt).TotalDays -ge $Choice.MaxAgeDays) -or -not [bool]$d.DevicesRead
        if ($stale) { $plan.Stale = [int]$plan.Stale + 1 }
    }
    $plan.FromSaved = [int]$plan.FromSaved + $got
    $inScope = @($rows | Where-Object { $_.InScope }).Count
    $plan.NotRead = [int]$plan.NotRead + [Math]::Max(0, $inScope - $got)
    $answer
}

function Get-SISignInMethodsSummaryLine {
    <# PURE. The collection's ONE line about the per-user sign-in facts. Customer text. #>
    param([Parameter(Mandatory)]$Plan, [AllowNull()]$Cache)
    $mode = [string]$Plan.Mode; if (-not $mode) { $mode = $script:SISignInMethodsDefaults.Mode }
    $head = ('[perms] sign-in methods per user (SI_Identity_SignInMethodsPerUser = {0})' -f $mode)
    if ($mode -eq 'off') {
        return ('{0}: not read; {1:N0} user(s) take their sign-in facts from the tenant-wide registration report only -- the per-user facts (each method''s detail and device, password present, passwordless only) show as unknown, never as no.' -f $head, [int]$Plan.OutOfScope)
    }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $line = ('{0}: {1:N0} user(s) in scope -- {2:N0} taken from the detail read in the background' -f $head, [int]$Plan.InScope, [int]$Plan.FromSaved)
    if ($null -ne $Plan.Oldest) { $line += (' (the oldest read {0})' -f ([datetime]$Plan.Oldest).ToString('yyyy-MM-dd', $inv)) }
    if ([int]$Plan.Stale) { $line += (', {0:N0} of them due to be read again' -f [int]$Plan.Stale) }
    $line += ('; {0:N0} not read yet, shown as unknown (never as no) until the background read reaches them' -f [int]$Plan.NotRead)
    if ($mode -eq 'privileged') { $line += ('; {0:N0} not privileged, from the tenant-wide registration report only' -f [int]$Plan.OutOfScope) }
    $line += '. The collection does not wait for it.'
    if ($Cache -and -not $Cache.Usable) { $line += (' The saved detail was not used this run ({0}).' -f [string]$Cache.Note) }
    $line
}

function Write-SISignInMethodsSummary {
    <# Writes the one line -- information, never a warning. #>
    param($Plan = (Get-SISignInMethodsPlan), $Cache, [string]$Note)
    if ($null -eq $Plan -or [int]$Plan.Users -eq 0) { return }
    $m = Get-SISignInMethodsSummaryLine -Plan $Plan -Cache $Cache
    if ($Note) { $m += (' ' + $Note + '.') }
    if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m }
}

# =====================================================================================================================
#  The filler: per-user reads into the saved detail, in time-boxed slices (its own job, caj-si-signin-methods)
# =====================================================================================================================
function Read-SISignInMethodsStoredChoice {
    <# The install's choice as stored in the Pro database (cfg.Setting), laid over the shipped defaults / the job's globals.
       Never throws: the database not answering = the globals. #>
    param([scriptblock]$ProInvoke)
    $v = @{
        SI_Identity_SignInMethodsPerUser     = $global:SI_Identity_SignInMethodsPerUser
        SI_Identity_SignInMethodsMaxAgeDays  = $global:SI_Identity_SignInMethodsMaxAgeDays
        SI_Identity_SignInMethodsFillMinutes = $global:SI_Identity_SignInMethodsFillMinutes
    }
    if ($ProInvoke) {
        try {
            $rows = @(& $ProInvoke (Get-SISignInMethodsSettingsSql) @{} 'reader' | ForEach-Object { $_ })
            # solution first, an identity engine row wins over it
            foreach ($r in @($rows | Where-Object { $null -ne $_ } | Sort-Object { if ([string](Get-SISqlRowValue $_ 'Scope') -eq 'solution') { 0 } else { 1 } })) {
                $n = [string](Get-SISqlRowValue $r 'Name'); $j = [string](Get-SISqlRowValue $r 'ValueJson')
                if (-not $n -or -not $j) { continue }
                try { $v[$n] = ($j | ConvertFrom-Json) } catch { }
            }
        } catch { }
    }
    Get-SISignInMethodsChoice -Values $v
}

function New-SISignInMethodsClaimValue {
    <# PURE. The claim row's value: {by, claimedUtc, until} (under 400 characters). #>
    param([Parameter(Mandatory)][string]$By, [Parameter(Mandatory)][datetime]$NowUtc, [Parameter(Mandatory)][datetime]$UntilUtc)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    ConvertTo-Json -Compress -InputObject ([ordered]@{ by = $By; claimedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv); until = $UntilUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) })
}

function Invoke-SISignInMethodsFill {
    <#
        ONE tick of the filler. Claims the filler (-ProInvoke, cfg.InstallState), then -- until -BudgetSeconds have gone by --
        picks the next users in priority order (-DataInvoke), reads them per user (-ReadUsers { param($Users) } -> id -> result,
        Get-SIEntraPasswordlessByUser -ReadDevices) and saves what came back whole; a user not read whole (throttled, refused,
        gone) is left for a later tick. Stops at the budget, when nothing is due, or when the read was refused. Releases the
        claim. Never throws. Answers @{ Status (off | busy | no-database | done | budget | refused | error); Picked; Read;
        Unread; Privileged; Reasons; Seconds; Line }.
          -Clock { } -> the time now (UTC) -- a test seam
    #>
    param(
        [Parameter(Mandatory)]$Choice,
        [scriptblock]$DataInvoke,
        [scriptblock]$ProInvoke,
        [Parameter(Mandatory)][scriptblock]$ReadUsers,
        [int]$BudgetSeconds = 0,
        [int]$BatchSize = $script:SISignInMethodsFill.BatchSize,
        [scriptblock]$Clock,
        [string]$By = ('{0}-{1}' -f [Environment]::MachineName, [guid]::NewGuid().ToString('N').Substring(0, 8)),
        [scriptblock]$IsRefused
    )
    if (-not $Clock) { $Clock = { [datetime]::UtcNow } }
    if ($BudgetSeconds -le 0) { $BudgetSeconds = 60 * [int]$Choice.FillMinutes }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $out = [pscustomobject]@{ Status = ''; Picked = 0; Read = 0; Unread = 0; Privileged = 0; Reasons = [ordered]@{ changed = 0; never = 0; maxage = 0 }; Seconds = 0.0; Line = '' }
    $start = [datetime](& $Clock)
    $say = {
        param($Status, $Text)
        $out.Status = $Status
        $out.Seconds = [Math]::Round(([datetime](& $Clock) - $start).TotalSeconds, 1)
        $out.Line = ('sign-in methods (background read, SI_Identity_SignInMethodsPerUser = {0}): {1}' -f $Choice.Mode, $Text)
        $out
    }
    if ($Choice.Mode -eq 'off') { return (& $say 'off' 'off -- nobody is read per user; the collections take the tenant-wide registration report only') }
    if (-not $DataInvoke -or -not $ProInvoke) { return (& $say 'no-database' 'not read -- this install has no database to keep the detail in') }
    # one tick at a time: the claim lasts the budget and five minutes more
    $claimed = $false
    try {
        $p = @{ Value = (New-SISignInMethodsClaimValue -By $By -NowUtc $start -UntilUtc $start.AddSeconds($BudgetSeconds + 300)); now = $start.ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
        $r = @(& $ProInvoke (Get-SISignInMethodsFillClaimSql) $p 'reader' | ForEach-Object { $_ }) | Select-Object -First 1
        $c = Get-SISqlRowValue $r 'Claimed'; if ($null -eq $c -and ($r -is [ValueType])) { $c = $r }
        $claimed = ([int]$c -eq 1)
    } catch { return (& $say 'error' ('not read this tick -- the claim could not be made ({0})' -f $_.Exception.Message)) }
    if (-not $claimed) { return (& $say 'busy' 'another tick is still reading -- this one leaves it alone') }
    $stop = ''
    try {
        while ($true) {
            $now = [datetime](& $Clock)
            if (($now - $start).TotalSeconds -ge $BudgetSeconds) { $stop = 'budget'; break }
            $pick = @(& $DataInvoke (Get-SISignInMethodsFillPickSql) @{ n = [string]$BatchSize; maxAge = [string]$Choice.MaxAgeDays; all = $(if ($Choice.Mode -eq 'all') { '1' } else { '0' }); now = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv) } 'rows')
            $pick = @($pick | Where-Object { $null -ne $_ -and [string](Get-SISqlRowValue $_ 'UserId') })
            if ($pick.Count -eq 0) { $stop = 'done'; break }
            $out.Picked = [int]$out.Picked + $pick.Count
            $users = New-Object System.Collections.Generic.List[object]
            $keys = @{}
            foreach ($r in $pick) {
                $id = ([string](Get-SISqlRowValue $r 'UserId')).ToLowerInvariant()
                $users.Add([pscustomobject]@{ id = $id })
                $keys[$id] = $r
                if ([int](Get-SISqlRowValue $r 'Privileged') -eq 1) { $out.Privileged = [int]$out.Privileged + 1 }
                $why = [string](Get-SISqlRowValue $r 'Reason'); if ($out.Reasons.Contains($why)) { $out.Reasons[$why] = [int]$out.Reasons[$why] + 1 }
            }
            $got = $null
            try { $got = & $ReadUsers @($users.ToArray()) } catch { $got = $null }
            if ($got -is [System.Array]) { $got = @($got | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -Last 1 }
            $save = New-Object System.Collections.Generic.List[object]
            $readAt = [datetime](& $Clock)
            if ($got) {
                foreach ($k in @($got.Keys)) {
                    $res = $got[$k]; if ($null -eq $res -or -not [bool]$res.ReadComplete) { continue }
                    $lid = ([string]$k).ToLowerInvariant(); $row = $keys[$lid]; if ($null -eq $row) { continue }
                    $ms = @(); if ($res.PSObject.Properties['Methods']) { $ms = @($res.Methods) }
                    $dr = $true; if ($res.PSObject.Properties['DevicesRead']) { $dr = [bool]$res.DevicesRead }
                    $save.Add([ordered]@{ UserId = $lid; Stamp = [string](Get-SISqlRowValue $row 'CurrentStamp'); Hash = [string](Get-SISqlRowValue $row 'CurrentHash')
                                          Detail = (ConvertTo-SISignInMethodsDetail -Methods $ms -DevicesRead $dr); DevicesRead = $dr
                                          ReadAt = $readAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv) })
                }
            }
            if ($save.Count -gt 0) {
                $j = ConvertTo-Json -InputObject @($save.ToArray()) -Compress -Depth 4
                if (-not $j.TrimStart().StartsWith('[')) { $j = '[' + $j + ']' }
                $null = & $DataInvoke (Get-SISignInMethodsFillSaveSql) @{ rows = $j } 'rows'
            }
            $out.Read = [int]$out.Read + $save.Count
            $out.Unread = [int]$out.Unread + ($pick.Count - $save.Count)
            $refused = $false
            if ($IsRefused) { try { $refused = [bool](& $IsRefused) } catch { } }
            elseif (Get-Command -Name Get-SIEntraAuthMethodsState -ErrorAction SilentlyContinue) { $st = Get-SIEntraAuthMethodsState; if ($st -and [bool]$st.Refused) { $refused = $true } }
            if ($refused) { $stop = 'refused'; break }
        }
    } catch {
        $stop = 'error'; $out.Line = [string]$_.Exception.Message
    } finally {
        try { $null = & $ProInvoke (Get-SISignInMethodsFillReleaseSql) @{ Value = (New-SISignInMethodsClaimValue -By $By -NowUtc $start -UntilUtc ([datetime](& $Clock))); by = $By } 'reader' } catch { }
    }
    $err = $out.Line
    $txt = ('{0:N0} user(s) read per user and saved, {1:N0} left for a later tick (Microsoft asked to slow down, or they could not be read); picked {2:N0}: {3:N0} privileged, {4:N0} changed, {5:N0} never read, {6:N0} older than {7} days' -f
        [int]$out.Read, [int]$out.Unread, [int]$out.Picked, [int]$out.Privileged, [int]$out.Reasons['changed'], [int]$out.Reasons['never'], [int]$out.Reasons['maxage'], [int]$Choice.MaxAgeDays)
    switch ($stop) {
        'done'    { $txt += ' -- nothing more is due' }
        'budget'  { $txt += (' -- the {0}-minute slice is used; the next tick carries on' -f [Math]::Round($BudgetSeconds / 60.0, 1)) }
        'refused' { $txt += ' -- Microsoft refused the read: the identity needs UserAuthenticationMethod.Read.All with admin consent' }
        'error'   { $txt += (' -- stopped: {0}' -f $err) }
    }
    & $say $stop $txt
}

function Invoke-SISignInMethodsFillTick {
    <#
        The job's call (engine\signin-methods\Invoke-SISignInMethods.ps1): loads the read, takes the install's choice (cfg.Setting over the shipped defaults), a Microsoft
        Graph token, and runs one tick (Invoke-SISignInMethodsFill). Never throws; answers the tick's outcome.
    #>
    param([scriptblock]$DataInvoke, [scriptblock]$ProInvoke, [string]$SIRoot)
    try {
        if (-not (Get-Command -Name Get-SIEntraPasswordlessByUser -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-AuthMethodsRead.ps1')) }
        $choice = Read-SISignInMethodsStoredChoice -ProInvoke $ProInvoke
        if ($choice.Mode -eq 'off' -or -not $DataInvoke -or -not $ProInvoke) { return (Invoke-SISignInMethodsFill -Choice $choice -DataInvoke $DataInvoke -ProInvoke $ProInvoke -ReadUsers { param($Users) @{} }) }
        if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) }
        if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'auth', 'Get-SIGraphToken.ps1')) }
        $tok = Get-SIGraphToken -Resource Graph
        Reset-SIEntraAuthMethodsState
        $read = [scriptblock]::Create('param($Users) Get-SIEntraPasswordlessByUser -Token ''{0}'' -Users $Users -ReadDevices -MaxRounds 3 -MaxDelaySeconds 30' -f ([string]$tok).Replace("'", "''"))
        Invoke-SISignInMethodsFill -Choice $choice -DataInvoke $DataInvoke -ProInvoke $ProInvoke -ReadUsers $read
    } catch {
        [pscustomobject]@{ Status = 'error'; Picked = 0; Read = 0; Unread = 0; Line = ('sign-in methods (background read): not run this tick ({0})' -f $_.Exception.Message) }
    }
}
