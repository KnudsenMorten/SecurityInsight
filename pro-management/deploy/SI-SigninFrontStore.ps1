#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- WHAT THE SHARED SIGN-IN FRONT 1.3.0 NEEDS BEFORE IT STARTS (#852, framework DOCS/REQUIREMENTS.md
    12.11g item 9). The front keeps its sessions, its token cache and its Data Protection keys in the product's OWN SQL
    database (schema "signin", tables created by the front on first use) and wraps the keys with a Key Vault key; it REFUSES
    to start without SIGNIN_SQL_SERVER, SIGNIN_SQL_DATABASE and SIGNIN_KEYVAULT_KEY_ID. Its identity is the managed identity
    named by SIGNIN_STATE_MI_CLIENT_ID (SecurityInsight sets it to the web app's identity, the same one as
    SIGNIN_FIC_MI_CLIENT_ID).

    ONE library for every path that reaches an install:
      * a new install (Deploy-SIManagement.ps1 -SigninStoreKeyVaultName, run by the guided install as the server's admin);
      * the cutover (SI-ManagementSigninFront.ps1, Set-SISigninFront.ps1 through the Support app);
      * every update (setup\Invoke-SIContainerUpdate.ps1 step 9g, run by caj-si-updater from the release).
    The pieces, each idempotent, each one plain line, each read back:
      key         an RSA key "signin-front-dp" in the install's own Key Vault (RSA 3072, wrapKey / unwrapKey) -- created over
                  ARM when it is not there; an existing one is used as it is, never changed, never removed;
      key-access  "Key Vault Crypto Service Encryption User" for the identity on THAT KEY only (never the vault);
      sql-user    the identity's contained database user (WITH SID = its client id, TYPE = E -- the SI way; the test VM's
                  SQL Server has no Entra users: a user WITHOUT LOGIN stands in) -- only when there is none;
      sql-schema  the schema "signin" owned by that user (CREATE SCHEMA ... AUTHORIZATION). A sign-in that may not name
                  another owner creates it as itself and gives the user CONTROL on that one schema -- the same rights;
      sql-grant   GRANT CREATE TABLE to that user (the front creates its two tables on first use).
    LEAST PRIVILEGE: the identity gets only that key (wrap / unwrap) and only its own schema + CREATE TABLE -- never
    db_owner, never a vault-wide role. The settings the front needs (Get-SISigninStoreEnv) are handed out ONLY when every
    piece reads back: a front 1.3.0 without them refuses to start and the update puts back the front that ran, so a missing
    piece never breaks the sign-in. A front 1.2.1 ignores the settings and the unused schema.

    Every call to Azure goes through -Arm { param([string]$Method, [string]$Path, $Body) } (Path = an ARM path WITH its
    api-version; a GET of something that is not there answers $null) and to SQL through -Sql { param([string]$Query,
    $Params, [string]$Mode) } (Mode 'reader' = rows, 'nonquery'). No module, no az, no native exe. PS 5.1 + pwsh 7.
#>

$script:SISigninStoreKeyName = 'signin-front-dp'
$script:SISigninStoreSchema = 'signin'
$script:SISigninStoreKvApi = '2023-07-01'
$script:SISigninStoreAuthApi = '2022-04-01'
$script:SISigninStoreResApi = '2021-04-01'
# Key Vault Crypto Service Encryption User (built-in): get, wrapKey, unwrapKey on keys
$script:SISigninStoreCryptoRole = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'
$script:SISigninStoreSettingNames = @('SIGNIN_SQL_SERVER', 'SIGNIN_SQL_DATABASE', 'SIGNIN_KEYVAULT_KEY_ID', 'SIGNIN_STATE_MI_CLIENT_ID')

function Get-SISigninStoreProp {
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = $(if ($o.Contains($p)) { $o[$p] } else { $null }); continue }
        $pp = $o.PSObject.Properties[$p]
        $o = $(if ($pp) { $pp.Value } else { $null })
    }
    $o
}

function Test-SISigninFrontNeedsStore {
    <# PURE. Does the pinned front (-Pin, or a version text) refuse to start without its SQL + Key Vault settings? 1.3.0 on. #>
    param([Parameter(Mandatory)]$Pin)
    $v = $(if ($Pin -is [string]) { $Pin } else { [string](Get-SISigninStoreProp $Pin @('version')) })
    $pv = $null
    if (-not [version]::TryParse("$v".Trim(), [ref]$pv)) { return $false }
    $pv -ge [version]'1.3.0'
}

function Get-SISigninStoreSqlFqdn {
    <# PURE. The SQL server's host name (a bare server name gets .database.windows.net). '' stays ''. #>
    param([AllowEmptyString()][string]$Server)
    $s = "$Server".Trim()
    if ($s -match '^tcp:') { $s = $s.Substring(4) }
    $s = ($s -split ',')[0].Trim()
    if ($s -and $s -notmatch '\.') { $s = $s + '.database.windows.net' }
    $s
}

function Get-SISigninStoreKeyUri {
    <# PURE. The key id the front gets: the VERSIONLESS data-plane id (https://<vault>/keys/<name>) -- a new key version
       is taken up without a change here. From the key as ARM returns it (keyUri, else keyUriWithVersion). '' = none. #>
    param($Key)
    $ku = [string](Get-SISigninStoreProp $Key @('properties', 'keyUri'))
    if (-not $ku) { $ku = [string](Get-SISigninStoreProp $Key @('properties', 'keyUriWithVersion')) }
    $ku = $ku.Trim().TrimEnd('/')
    $m = [regex]::Match($ku, '(?i)^(https://[^/]+/keys/[^/]+)(/[^/]+)?$')
    if (-not $m.Success) { return '' }
    $m.Groups[1].Value
}

function Get-SISigninStoreEnv {
    <# PURE. The front container's store settings ('N=V'), exactly the names the front reads (signin-front 1.3.0 README). #>
    param([Parameter(Mandatory)][string]$SqlServer, [Parameter(Mandatory)][string]$SqlDatabase, [Parameter(Mandatory)][string]$KeyUri,
          [Parameter(Mandatory)][string]$StateClientId)
    @(
        ('SIGNIN_SQL_SERVER={0}' -f (Get-SISigninStoreSqlFqdn -Server $SqlServer)),
        ('SIGNIN_SQL_DATABASE={0}' -f $SqlDatabase.Trim()),
        ('SIGNIN_KEYVAULT_KEY_ID={0}' -f $KeyUri.Trim()),
        ('SIGNIN_STATE_MI_CLIENT_ID={0}' -f $StateClientId.Trim().ToLowerInvariant())
    )
}

function Test-SISigninStoreEnvComplete {
    <# PURE. Do these settings ('N=V' lines, or ARM env entries) carry every REQUIRED store setting with a value? #>
    param([AllowNull()][object[]]$Env)
    $have = @{}
    foreach ($e in @(@($Env) | Where-Object { $_ })) {
        if ($e -is [string]) { $p = $e -split '=', 2; if ($p.Count -eq 2 -and "$($p[1])".Trim()) { $have[$p[0]] = $true } }
        else { $n = [string](Get-SISigninStoreProp $e @('name')); $v = [string](Get-SISigninStoreProp $e @('value')); if ($n -and $v.Trim()) { $have[$n] = $true } }
    }
    foreach ($n in 'SIGNIN_SQL_SERVER', 'SIGNIN_SQL_DATABASE', 'SIGNIN_KEYVAULT_KEY_ID') { if (-not $have.ContainsKey($n)) { return $false } }
    $true
}

function Get-SISigninStoreKeyPath {
    <# PURE. The ARM id of the key in the vault (-VaultId = the vault's ARM id). #>
    param([Parameter(Mandatory)][string]$VaultId, [string]$KeyName = $script:SISigninStoreKeyName)
    '{0}/keys/{1}' -f $VaultId.Trim().TrimEnd('/'), $KeyName
}

function Get-SISigninStoreKeyBody {
    <# PURE. A new key: RSA 3072, only wrapKey / unwrapKey (it wraps the front's Data Protection keys and does nothing else). #>
    [ordered]@{ properties = [ordered]@{ kty = 'RSA'; keySize = 3072; keyOps = @('wrapKey', 'unwrapKey') } }
}

function Get-SISigninStoreRoleRequest {
    <# PURE. The ONE role assignment: Key Vault Crypto Service Encryption User for -PrincipalId, SCOPE = THE KEY (its ARM
       id). Returns @{ Path (with api-version); Body }. -Name: the assignment's guid (tests pass one). #>
    param([Parameter(Mandatory)][string]$KeyId, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$SubscriptionId, [string]$Name = '')
    if (-not $Name) { $Name = [guid]::NewGuid().ToString() }
    [pscustomobject]@{
        Path = '{0}/providers/Microsoft.Authorization/roleAssignments/{1}?api-version={2}' -f $KeyId.TrimEnd('/'), $Name, $script:SISigninStoreAuthApi
        Body = [ordered]@{ properties = [ordered]@{
            roleDefinitionId = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $SubscriptionId, $script:SISigninStoreCryptoRole)
            principalId = $PrincipalId; principalType = 'ServicePrincipal' } }
    }
}

function Test-SISigninStoreRolePresent {
    <# PURE. Does a role assignment list (as read at the key's scope, filtered to the principal) give the crypto role on the
       key -- at the key itself or inherited from above it (a broader grant someone made is enough; never made here)? #>
    param([AllowNull()][object[]]$Assignments, [Parameter(Mandatory)][string]$KeyId, [Parameter(Mandatory)][string]$PrincipalId)
    $k = $KeyId.Trim().TrimEnd('/').ToLowerInvariant()
    foreach ($a in @(@($Assignments) | Where-Object { $_ })) {
        $rd = [string](Get-SISigninStoreProp $a @('properties', 'roleDefinitionId'))
        $pr = [string](Get-SISigninStoreProp $a @('properties', 'principalId'))
        $sc = ([string](Get-SISigninStoreProp $a @('properties', 'scope'))).Trim().TrimEnd('/').ToLowerInvariant()
        if ($rd -notmatch ('(?i)/' + $script:SISigninStoreCryptoRole + '$')) { continue }
        if ($pr -and $pr -ine $PrincipalId) { continue }
        if (-not $sc -or $sc -eq $k -or $k.StartsWith($sc + '/')) { return $true }
    }
    $false
}

function Get-SISigninStoreStateSql {
    <# PURE. READ ONLY: the identity's user (by SID = its client id; on a non-Azure engine -- the test VM -- by name), the
       schema, its owner, CONTROL on it, CREATE TABLE. Parameters @ClientId, @UserName. One row. #>
    @'
SET NOCOUNT ON;
DECLARE @sid varbinary(16) = CONVERT(varbinary(16), CAST(@ClientId AS uniqueidentifier));
DECLARE @u sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = @sid AND [type] IN ('E', 'X'));
IF @u IS NULL AND CONVERT(int, SERVERPROPERTY('EngineEdition')) NOT IN (5, 8)
    SET @u = (SELECT TOP (1) name FROM sys.database_principals WHERE name = @UserName AND [type] IN ('S', 'E', 'X'));
DECLARE @uid int = DATABASE_PRINCIPAL_ID(@u);
SELECT @u AS UserName,
       CAST(CASE WHEN SCHEMA_ID(N'signin') IS NULL THEN 0 ELSE 1 END AS bit) AS SchemaExists,
       (SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin') AS SchemaOwner,
       CAST(CASE WHEN @uid IS NOT NULL AND EXISTS (SELECT 1 FROM sys.database_permissions WHERE class = 3 AND major_id = SCHEMA_ID(N'signin')
                 AND grantee_principal_id = @uid AND permission_name = N'CONTROL' AND [state] IN ('G', 'W')) THEN 1 ELSE 0 END AS bit) AS SchemaControl,
       CAST(CASE WHEN @uid IS NOT NULL AND EXISTS (SELECT 1 FROM sys.database_permissions WHERE class = 0 AND grantee_principal_id = @uid
                 AND permission_name = N'CREATE TABLE' AND [state] IN ('G', 'W')) THEN 1 ELSE 0 END AS bit) AS CreateTable,
       CONVERT(int, SERVERPROPERTY('EngineEdition')) AS EngineEdition;
'@
}

function ConvertFrom-SISigninStoreStateRow {
    <# PURE. The state row as @{ User; SchemaExists; SchemaOwner; SchemaOk (owned by the user, or CONTROL on it); CreateTable }. #>
    param($Row)
    $g = { param($k) $v = Get-SISigninStoreProp $Row @($k); if ($v -is [DBNull]) { $null } else { $v } }
    $user = [string](& $g 'UserName')
    $owner = [string](& $g 'SchemaOwner')
    $exists = [bool](& $g 'SchemaExists')
    $control = [bool](& $g 'SchemaControl')
    [pscustomobject]@{
        User = $user; SchemaExists = $exists; SchemaOwner = $owner
        SchemaOk = [bool]($user -and $exists -and (($owner -ceq $user) -or $control))
        CreateTable = [bool](& $g 'CreateTable')
    }
}

function Get-SISigninStorePlan {
    <#
        PURE. What is missing, in the order it is made: 'key', 'key-access', 'sql-user', 'sql-schema', 'sql-grant'. Nothing
        missing = an empty plan (nothing is sent). -KeyPresent / -KeyAccess: the key and the identity's right on it read;
        -Sql: ConvertFrom-SISigninStoreStateRow. A missing key means its right is missing too; a missing user means its
        schema ownership and its grant are missing too.
    #>
    param([bool]$KeyPresent, [bool]$KeyAccess, [Parameter(Mandatory)]$Sql)
    $a = New-Object System.Collections.Generic.List[string]
    if (-not $KeyPresent) { $a.Add('key') }
    if (-not $KeyPresent -or -not $KeyAccess) { $a.Add('key-access') }
    if (-not $Sql.User) { $a.Add('sql-user') }
    if (-not $Sql.User -or -not $Sql.SchemaOk) { $a.Add('sql-schema') }
    if (-not $Sql.User -or -not $Sql.CreateTable) { $a.Add('sql-grant') }
    $a.ToArray()   # unrolled: callers wrap the call in @( )
}

function Get-SISigninStoreSql {
    <#
        PURE. The T-SQL of ONE SQL action ('sql-user', 'sql-schema', 'sql-grant') for the identity (@ClientId, @UserName as
        parameters; every name QUOTENAME'd inside SQL). Each is idempotent on its own: it checks before it changes.
          sql-user    CREATE USER [name] WITH SID = <client id>, TYPE = E (Azure SQL / Managed Instance); any other engine
                      -- only the test VM's SQL Server -- has no Entra users: CREATE USER [name] WITHOUT LOGIN;
          sql-schema  CREATE SCHEMA [signin] AUTHORIZATION [user] (an existing schema owned by someone else: ALTER
                      AUTHORIZATION); when this sign-in may not name another owner, the schema is made as the caller and the
                      user gets CONTROL on that one schema -- the same rights, nothing wider;
          sql-grant   GRANT CREATE TABLE TO [user].
    #>
    param([Parameter(Mandatory)][ValidateSet('sql-user', 'sql-schema', 'sql-grant')][string]$Action)
    $head = @'
SET NOCOUNT ON;
DECLARE @s nvarchar(max);
DECLARE @sid varbinary(16) = CONVERT(varbinary(16), CAST(@ClientId AS uniqueidentifier));
DECLARE @u sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = @sid AND [type] IN ('E', 'X'));
IF @u IS NULL AND CONVERT(int, SERVERPROPERTY('EngineEdition')) NOT IN (5, 8)
    SET @u = (SELECT TOP (1) name FROM sys.database_principals WHERE name = @UserName AND [type] IN ('S', 'E', 'X'));
'@
    switch ($Action) {
        'sql-user' { $head + @'
IF @u IS NULL
BEGIN
    IF @UserName IS NULL OR LEN(@UserName) < 1 OR LEN(@UserName) > 128 OR @UserName LIKE N'%[^A-Za-z0-9 ._@-]%'
        THROW 51852, N'the sign-in front identity needs a safe user name (letters, digits, space . _ @ -)', 1;
    IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @UserName)
        THROW 51852, N'another database principal already has the sign-in front identity''s name -- an administrator resolves it', 1;
    IF CONVERT(int, SERVERPROPERTY('EngineEdition')) IN (5, 8)
        SET @s = N'CREATE USER ' + QUOTENAME(@UserName) + N' WITH SID = ' + CONVERT(nvarchar(40), @sid, 1) + N', TYPE = E;';
    ELSE SET @s = N'CREATE USER ' + QUOTENAME(@UserName) + N' WITHOUT LOGIN;';
    EXEC sys.sp_executesql @s;
END
'@ }
        'sql-schema' { $head + @'
IF @u IS NULL THROW 51852, N'the sign-in front identity has no user in this database', 1;
IF SCHEMA_ID(N'signin') IS NULL
BEGIN
    BEGIN TRY
        SET @s = N'CREATE SCHEMA [signin] AUTHORIZATION ' + QUOTENAME(@u) + N';'; EXEC sys.sp_executesql @s;
    END TRY
    BEGIN CATCH
        -- this sign-in may not name another owner: the schema as the caller, CONTROL on it for the user (the owner's rights)
        IF SCHEMA_ID(N'signin') IS NULL EXEC (N'CREATE SCHEMA [signin];');
        SET @s = N'GRANT CONTROL ON SCHEMA::[signin] TO ' + QUOTENAME(@u) + N';'; EXEC sys.sp_executesql @s;
    END CATCH
END
ELSE IF ISNULL((SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin'), N'') <> @u
     AND NOT EXISTS (SELECT 1 FROM sys.database_permissions WHERE class = 3 AND major_id = SCHEMA_ID(N'signin')
                     AND grantee_principal_id = DATABASE_PRINCIPAL_ID(@u) AND permission_name = N'CONTROL' AND [state] IN ('G', 'W'))
BEGIN
    BEGIN TRY
        SET @s = N'ALTER AUTHORIZATION ON SCHEMA::[signin] TO ' + QUOTENAME(@u) + N';'; EXEC sys.sp_executesql @s;
    END TRY
    BEGIN CATCH
        SET @s = N'GRANT CONTROL ON SCHEMA::[signin] TO ' + QUOTENAME(@u) + N';'; EXEC sys.sp_executesql @s;
    END CATCH
END
'@ }
        'sql-grant' { $head + @'
IF @u IS NULL THROW 51852, N'the sign-in front identity has no user in this database', 1;
IF NOT EXISTS (SELECT 1 FROM sys.database_permissions WHERE class = 0 AND grantee_principal_id = DATABASE_PRINCIPAL_ID(@u)
               AND permission_name = N'CREATE TABLE' AND [state] IN ('G', 'W'))
BEGIN
    SET @s = N'GRANT CREATE TABLE TO ' + QUOTENAME(@u) + N';'; EXEC sys.sp_executesql @s;
END
'@ }
    }
}

function Get-SISigninStoreActionText {
    <# PURE. One plain line per action (what it does, never a secret). #>
    param([Parameter(Mandatory)][string]$Action, [string]$KeyName = $script:SISigninStoreKeyName, [string]$VaultName = '', [string]$User = '')
    switch ($Action) {
        'key'        { 'the key {0} is created in the Key Vault {1} (RSA 3072, wrap and unwrap only)' -f $KeyName, $VaultName }
        'key-access' { 'the identity {0} gets "Key Vault Crypto Service Encryption User" on the key {1} only' -f $User, $KeyName }
        'sql-user'   { 'the identity {0} gets its own user in the database (by its client id)' -f $User }
        'sql-schema' { 'the schema signin is created, owned by {0}' -f $User }
        'sql-grant'  { '{0} may create tables (GRANT CREATE TABLE) -- the front creates its two tables in its own schema' -f $User }
        default      { $Action }
    }
}

function Get-SISigninStoreRecordSql {
    <# PURE. The step's marker: cfg.InstallState 'SigninFrontStore' = @Value (JSON), by @By -- written or replaced. #>
    @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'SigninFrontStore')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'SigninFrontStore';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'SigninFrontStore', @Value, NULL, @By);
END
'@
}

function Resolve-SISigninStoreVaultId {
    <# The ARM id of the install's Key Vault -VaultName: in -ResourceGroup first, else anywhere in the subscription (one ARM
       resource list filtered by type and name). '' when it is not found. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup = '', [Parameter(Mandatory)][string]$VaultName)
    if ($ResourceGroup) {
        $id = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}' -f $SubscriptionId, $ResourceGroup, $VaultName
        $v = & $Arm 'GET' ('{0}?api-version={1}' -f $id, $script:SISigninStoreKvApi) $null
        if ($v) { return [pscustomobject]@{ Id = $id; Vault = $v } }
    }
    $flt = [uri]::EscapeDataString(("resourceType eq 'Microsoft.KeyVault/vaults' and name eq '{0}'" -f $VaultName))
    $l = & $Arm 'GET' ('/subscriptions/{0}/resources?$filter={1}&api-version={2}' -f $SubscriptionId, $flt, $script:SISigninStoreResApi) $null
    $hit = @(@(Get-SISigninStoreProp $l @('value')) | Where-Object { $_ -and [string](Get-SISigninStoreProp $_ @('name')) -ieq $VaultName }) | Select-Object -First 1
    if (-not $hit) { return $null }
    $id = [string](Get-SISigninStoreProp $hit @('id'))
    $v = & $Arm 'GET' ('{0}?api-version={1}' -f $id, $script:SISigninStoreKvApi) $null
    [pscustomobject]@{ Id = $id; Vault = $v }
}

function Invoke-SISigninFrontStore {
    <#
        Makes sure of every piece (see the file header) for the identity -Identity (@{ ClientId; PrincipalId; Name }) in the
        install's vault -VaultName and its Pro database (-SqlServer / -SqlDatabase, reached through -Sql as the CALLER).
        -Apply:$false = the plan only (what is missing, one line each; nothing changed). Never throws.
        Returns @{ Ok (every piece reads back); Env (the front's settings -- ONLY when Ok, else empty); Actions (what was
        missing); Lines; Failed (the piece that could not be made, '' = none); Why }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$ResourceGroup = '', [Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$SqlServer,
          [Parameter(Mandatory)][string]$SqlDatabase, [Parameter(Mandatory)]$Identity, [string]$KeyName = $script:SISigninStoreKeyName,
          [switch]$Apply, [scriptblock]$Log = { param($m) Write-Host $m }, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [int]$ReadBackTries = 6, [int]$ReadBackSeconds = 5)
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param($m) $lines.Add([string]$m); & $Log $m }
    $res = { param([bool]$ok, $actions, [string]$failed, [string]$why, $env)
        [pscustomobject]@{ Ok = $ok; Env = @($env); Actions = @($actions); Lines = $lines.ToArray(); Failed = $failed; Why = $why } }
    $actions = @()
    try {
        $cid = ([string](Get-SISigninStoreProp $Identity @('ClientId'))).Trim().ToLowerInvariant()
        $prin = ([string](Get-SISigninStoreProp $Identity @('PrincipalId'))).Trim().ToLowerInvariant()
        $uname = ([string](Get-SISigninStoreProp $Identity @('Name'))).Trim()
        if ($cid -notmatch '^[0-9a-f-]{36}$' -or $prin -notmatch '^[0-9a-f-]{36}$' -or -not $uname) { return (& $res $false @() 'identity' 'the sign-in front''s identity (client id, object id, name) could not be read' @()) }
        $srv = Get-SISigninStoreSqlFqdn -Server $SqlServer
        if (-not $srv -or -not "$SqlDatabase".Trim()) { return (& $res $false @() 'sql' 'the Pro database (server and name) is not known here' @()) }
        # ---- the vault and the key (read) ----
        $vr = Resolve-SISigninStoreVaultId -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $VaultName
        if (-not $vr -or -not $vr.Id) { return (& $res $false @() 'key' ('the Key Vault {0} was not found' -f $VaultName) @()) }
        if ($vr.Vault -and (Get-SISigninStoreProp $vr.Vault @('properties', 'enableRbacAuthorization')) -eq $false) {
            return (& $res $false @() 'key-access' ('the Key Vault {0} uses access policies, not Azure roles -- the front''s right on its key cannot be given on the key alone' -f $VaultName) @())
        }
        $keyId = Get-SISigninStoreKeyPath -VaultId $vr.Id -KeyName $KeyName
        $keyPath = '{0}?api-version={1}' -f $keyId, $script:SISigninStoreKvApi
        $key = & $Arm 'GET' $keyPath $null
        $kty = [string](Get-SISigninStoreProp $key @('properties', 'kty'))
        if ($key -and $kty -and $kty -notmatch '^RSA') { return (& $res $false @() 'key' ('the key {0} in {1} is {2}, not RSA -- it is left as it is' -f $KeyName, $VaultName, $kty) @()) }
        $roleListPath = '{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}&api-version={2}' -f $keyId, [uri]::EscapeDataString(("principalId eq '{0}'" -f $prin)), $script:SISigninStoreAuthApi
        $access = $false
        if ($key) { $access = Test-SISigninStoreRolePresent -Assignments @(Get-SISigninStoreProp (& $Arm 'GET' $roleListPath $null) @('value')) -KeyId $keyId -PrincipalId $prin }
        # ---- the database (read) ----
        $st = ConvertFrom-SISigninStoreStateRow -Row (@(& $Sql (Get-SISigninStoreStateSql) ([ordered]@{ ClientId = $cid; UserName = $uname }) 'reader' | ForEach-Object { $_ }) | Select-Object -First 1)
        $user = $(if ($st.User) { $st.User } else { $uname })
        $actions = @(Get-SISigninStorePlan -KeyPresent ([bool]$key) -KeyAccess $access -Sql $st)
        $envOf = { param($k) Get-SISigninStoreEnv -SqlServer $srv -SqlDatabase $SqlDatabase -KeyUri (Get-SISigninStoreKeyUri -Key $k) -StateClientId $cid }
        if (-not @($actions).Count) {
            & $say ('sign-in front store: in place (key {0} in {1}, the identity''s right on it, schema signin of {2}, CREATE TABLE)' -f $KeyName, $VaultName, $user)
            $env = & $envOf $key
            if (-not (Test-SISigninStoreEnvComplete -Env $env)) { return (& $res $false @() 'key' ('the key {0} does not show its address' -f $KeyName) @()) }
            return (& $res $true @() '' '' $env)
        }
        if (-not $Apply) {
            foreach ($a in $actions) { & $say ('sign-in front store (plan): ' + (Get-SISigninStoreActionText -Action $a -KeyName $KeyName -VaultName $VaultName -User $user)) }
            return (& $res $false $actions '' 'plan only' @())
        }
        # ---- make what is missing, in order; each read back ----
        foreach ($a in $actions) {
            $text = Get-SISigninStoreActionText -Action $a -KeyName $KeyName -VaultName $VaultName -User $user
            try {
                switch ($a) {
                    'key' {
                        $null = & $Arm 'PUT' $keyPath (Get-SISigninStoreKeyBody)
                        for ($i = 1; $i -le $ReadBackTries; $i++) { $key = & $Arm 'GET' $keyPath $null; if (Get-SISigninStoreKeyUri -Key $key) { break }; if ($i -lt $ReadBackTries) { & $Sleep $ReadBackSeconds } }
                        if (-not (Get-SISigninStoreKeyUri -Key $key)) { throw 'the key does not read back' }
                    }
                    'key-access' {
                        $rq = Get-SISigninStoreRoleRequest -KeyId $keyId -PrincipalId $prin -SubscriptionId $SubscriptionId
                        $null = & $Arm 'PUT' $rq.Path $rq.Body
                        $ok = $false
                        for ($i = 1; $i -le $ReadBackTries; $i++) {
                            $ok = Test-SISigninStoreRolePresent -Assignments @(Get-SISigninStoreProp (& $Arm 'GET' $roleListPath $null) @('value')) -KeyId $keyId -PrincipalId $prin
                            if ($ok) { break }; if ($i -lt $ReadBackTries) { & $Sleep $ReadBackSeconds }
                        }
                        if (-not $ok) { throw 'the role assignment does not read back' }
                    }
                    default { $null = & $Sql (Get-SISigninStoreSql -Action $a) ([ordered]@{ ClientId = $cid; UserName = $uname }) 'nonquery' }
                }
            } catch {
                $why = ('{0} -- FAILED: {1}' -f $text, $_.Exception.Message)
                & $say ('sign-in front store: ' + $why)
                return (& $res $false $actions $a $why @())
            }
            & $say ('sign-in front store: ' + $text + ' (done)')
        }
        # ---- the database read back as a whole ----
        $st = ConvertFrom-SISigninStoreStateRow -Row (@(& $Sql (Get-SISigninStoreStateSql) ([ordered]@{ ClientId = $cid; UserName = $uname }) 'reader' | ForEach-Object { $_ }) | Select-Object -First 1)
        if (-not $st.User -or -not $st.SchemaOk -or -not $st.CreateTable) {
            $why = 'the database does not read back as made (user: {0}; schema signin of the user: {1}; CREATE TABLE: {2})' -f $(if ($st.User) { $st.User } else { 'none' }), $st.SchemaOk, $st.CreateTable
            & $say ('sign-in front store: ' + $why)
            return (& $res $false $actions 'sql' $why @())
        }
        $env = & $envOf $key
        if (-not (Test-SISigninStoreEnvComplete -Env $env)) { return (& $res $false $actions 'key' ('the key {0} does not show its address' -f $KeyName) @()) }
        & $say 'sign-in front store: read back -- the front''s settings are ready'
        & $res $true $actions '' '' $env
    } catch {
        $why = ('could not be checked: {0}' -f $_.Exception.Message)
        & $say ('sign-in front store: ' + $why)
        & $res $false $actions 'read' $why @()
    }
}
