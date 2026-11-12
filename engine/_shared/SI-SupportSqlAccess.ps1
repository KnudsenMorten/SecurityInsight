#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- the Invardia Support app's database access, READ ONLY: what the identified heartbeat reports as
    supportSqlAccess (framework DOCS/REQUIREMENTS.md section 4.1b; owner 2026-10-18).

.DESCRIPTION
    Section 4.1b: on every install the Support app holds BOTH (a) membership of the install's SQL admin group (the SQL
    server's Entra administrator, kind Group) and (b) its own contained user, with db_owner, in each product database.
    SecurityInsight makes them (the guided install, setup\Grant-SISupportAccess.ps1, setup\Grant-SISupportAppDatabase.ps1)
    and never removes them; INVARDIA repairs a missing part itself (owner 2026-10-18) -- so SI never heals, and this file
    only CHECKS and REPORTS:
        "supportSqlAccess": { "group": true|false|null, "dbUser": true|false|null, "checkedUtc": "<ISO>", "healedUtc": null }
      group      the Support app's service principal is a member of the group the database server names as its Entra
                 administrator -- asked from the MEMBER's side (checkMemberGroups: a group's /members listing hides
                 service principals from many callers); null = could not be checked (never "not a member");
      dbUser     its own user (the SID of its CLIENT id) with db_owner is in EVERY product database; false = read, and not
                 there in at least one; null = at least one could not be read and none was read as missing;
      healedUtc  always null: SecurityInsight never heals (Invardia does).
    No Support app recorded on the install (cfg.InstallState 'SupportApp') = the field is left out (not known).

    TWO STATES, each named in the job's line (#1021, owner decision 2026-10-31: the Support app's admin becomes just in time):
      standing admin   (no cut-over record) the state above: a member of the admin group, its own user with db_owner.
      just in time     (cfg.InstallState 'SupportStandingAccess' names the steps setup\Remove-SISupportStandingAccess.ps1
                       made: db-owner, admin-group) the EXPECTED state is NOT a member and its own user in the read-only
                       role si_support_read in every product database; db_owner comes only with an open support grant.
                       group = what was read (false = not a member, as expected); dbUser = its own user WITH the read-only
                       role in every database. A membership read back after the cut-over is named "standing admin is
                       back" -- never reported as the expected state.

    The single home of the SID and the read statements: setup\_shared\SI-SupportAppDatabase.ps1 (the writer) loads this
    file. Pure except the seams; PowerShell 5.1 and 7; no PowerShell module; NEVER throws where the heartbeat calls it.
#>

function ConvertTo-SISqlSidFromClientId {
    <# PURE. The SID Azure SQL gives an Entra application: its CLIENT id (never the object id) as the 16 bytes of
       [guid]::ToByteArray() -- the first three groups byte-swapped -- written as 0x + 32 hex digits. #>
    param([Parameter(Mandatory)][string]$ClientId)
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SISupportAppDatabaseCheckSql {
    <# PURE. READS ONLY. One value (column Value): '<user>|1' when the database has a user with the Support app's SID that is
       a member of db_owner, '<user>|0' when it is not, '' when there is no such user -- and '?' when there is none THAT THIS
       CONNECTION CAN SEE (it lacks VIEW DEFINITION, so other principals are hidden from it: "could not be checked", never
       "missing"). dbo and the other built-in principals (principal_id 1-4) are never it. #>
    param([Parameter(Mandatory)][string]$ClientId)
    $sid = ConvertTo-SISqlSidFromClientId -ClientId $ClientId
    @"
SELECT ISNULL((SELECT TOP (1) u.name COLLATE DATABASE_DEFAULT + N'|' + CASE WHEN EXISTS (
        SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
        WHERE m.member_principal_id = u.principal_id AND r.name = N'db_owner') THEN N'1' ELSE N'0' END
    FROM sys.database_principals u WHERE u.sid = $sid AND u.principal_id > 4),
    CASE WHEN ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW DEFINITION'), 0) = 1 THEN N'' ELSE N'?' END) AS Value;
"@
}

function ConvertFrom-SISupportAppDatabaseAnswer {
    <# PURE. The check's / who-am-I's value -> @{ User; Owner; Hidden }. '' = no user; '?' = Hidden (could not be seen). #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = ([string]$Text).Trim()
    if ($t -eq '?') { return [pscustomobject]@{ User = ''; Owner = $false; Hidden = $true } }
    if (-not $t) { return [pscustomobject]@{ User = ''; Owner = $false; Hidden = $false } }
    $i = $t.LastIndexOf('|')
    if ($i -lt 0) { return [pscustomobject]@{ User = $t; Owner = $false; Hidden = $false } }
    [pscustomobject]@{ User = $t.Substring(0, $i); Owner = ($t.Substring($i + 1) -eq '1'); Hidden = $false }
}

function Get-SISupportAppRecordReadSql {
    <# PURE. READS ONLY. The recorded Support app client id (column Value), '' when none (or no table). #>
    "SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportApp'), N'') END AS Value;"
}

function Get-SISupportStandingCutoverReadSql {
    <# PURE. READS ONLY. The cut-over record (column Value): the short JSON setup\Remove-SISupportStandingAccess.ps1 keeps in
       cfg.InstallState 'SupportStandingAccess' ({ at, applied: 'db-owner,admin-group', file }), '' when none (or no table). #>
    "SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportStandingAccess'), N'') END AS Value;"
}

function ConvertFrom-SISupportStandingCutover {
    <# PURE. The record's text -> @{ DbOwner; Group; At } -- DbOwner / Group: that step was made (the cut-over state is the
       expected one for it). A rollback names its steps rollback-..., so it is never read as cut over. Unreadable = neither. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $o = [pscustomobject]@{ DbOwner = $false; Group = $false; At = '' }
    if (-not "$Text".Trim()) { return $o }
    try { $j = $Text | ConvertFrom-Json } catch { return $o }
    $applied = @(([string]$j.applied) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $o.DbOwner = $applied -contains 'db-owner'; $o.Group = $applied -contains 'admin-group'
    # the time as written (PowerShell 7's ConvertFrom-Json would turn it into a local date)
    if ($Text -match '"at"\s*:\s*"([^"]+)"') { $o.At = $Matches[1] }
    $o
}

function Get-SISupportAppReadRoleCheckSql {
    <# PURE. READS ONLY. After the cut-over: '<user>|<db_owner 1/0>|<si_support_read 1/0>' for the user with the Support app's
       SID, '' = no such user, '?' = this connection cannot see the database's users (could not be checked). #>
    param([Parameter(Mandatory)][string]$ClientId)
    $sid = ConvertTo-SISqlSidFromClientId -ClientId $ClientId
    $has = { param($r) "CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = u.principal_id AND r.name = N'$r') THEN N'1' ELSE N'0' END" }
    @"
SELECT ISNULL((SELECT TOP (1) u.name COLLATE DATABASE_DEFAULT + N'|' + $(& $has 'db_owner') + N'|' + $(& $has 'si_support_read')
    FROM sys.database_principals u WHERE u.sid = $sid AND u.principal_id > 4),
    CASE WHEN ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW DEFINITION'), 0) = 1 THEN N'' ELSE N'?' END) AS Value;
"@
}

function Get-SISupportAppServicePrincipal {
    <# The Support app's service principal in this tenant: @{ Id (object id); DisplayName }, or $null when the tenant has
       none. A directory that cannot be read THROWS -- "could not read" is never "not there". #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$ClientId)
    $id = ([guid]$ClientId).ToString()
    $r = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$id'&`$select=id,appId,displayName") $null
    $sp = $null
    if ($r -is [System.Collections.IDictionary]) { $sp = @($r['value'])[0] } elseif ($r -and $r.PSObject.Properties['value']) { $sp = @($r.value)[0] }
    if (-not $sp) { return $null }
    $get = { param($o, $k) if ($o -is [System.Collections.IDictionary]) { $o[$k] } elseif ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
    [pscustomobject]@{ Id = [string](& $get $sp 'id'); DisplayName = [string](& $get $sp 'displayName') }
}

function Test-SISupportAppGroupMember {
    <# Is the service principal a member of the group? Asked from the MEMBER's side (checkMemberGroups): a plain /members
       listing leaves service principals out for many callers. THROWS when the directory cannot be asked. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$ServicePrincipalId)
    $r = & $Graph 'POST' ("https://graph.microsoft.com/v1.0/directoryObjects/$ServicePrincipalId/checkMemberGroups") @{ groupIds = @([string]$GroupId) }
    $v = @(); if ($r -is [System.Collections.IDictionary]) { $v = @($r['value']) } elseif ($r -and $r.PSObject.Properties['value']) { $v = @($r.value) }
    [bool](@($v | ForEach-Object { [string]$_ }) -contains [string]$GroupId)
}

function Read-SISupportSqlValue {
    <# The first row's Value through a { param($Sql, $Params, $Mode) } seam (mode 'rows'; the answer flattened whatever its
       shape). Throws when the database cannot be read. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql)
    $row = @(& $Invoke $Sql @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
    if ($null -eq $row) { return '' }
    if ($row -is [string]) { return $row }
    if ($row -is [System.Collections.IDictionary]) { return [string]$row['Value'] }
    if ($row.PSObject.Properties['Value']) { return [string]$row.Value }
    [string]$row
}

function Get-SISupportSqlAccess {
    <#
        THE READ-ONLY CHECK of both parts, for the identified heartbeat. Writes nothing, anywhere. NEVER throws.
          -Databases  ordered @{ <database> = { param($Sql, $Params, $Mode) } } -- every product database of the install;
                      the FIRST holds the record (the Pro database)
          -Graph      { param([string]$Method, [string]$Uri, $Body) } -> the parsed answer; throws on a failure
          -AdminSid   { } -> the object id the database server names as its Entra administrator; throws when not readable
        Returns @{ Wire; Text } -- Wire = the heartbeat's supportSqlAccess ([ordered] group, dbUser, checkedUtc, healedUtc),
        or $null (no Support app recorded, or the record could not be read: not known -> the field is left out); Text = one
        plain line for the job's log.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Databases, [scriptblock]$Graph, [scriptblock]$AdminSid,
          [Parameter(Mandatory)][datetime]$NowUtc)
    $none = { param($why) [pscustomobject]@{ Wire = $null; Text = ('support SQL access: not known -- {0}' -f $why) } }
    try {
        $names = @($Databases.Keys | Where-Object { "$_".Trim() })
        if (-not $names.Count) { return (& $none 'the install names no product database') }
        $app = ''
        try { $app = (Read-SISupportSqlValue -Invoke $Databases[$names[0]] -Sql (Get-SISupportAppRecordReadSql)).Trim() }
        catch { return (& $none ('the record of the Support app could not be read ({0})' -f $_.Exception.Message)) }
        if ($app -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return (& $none 'no Support app is recorded on this install') }
        $said = New-Object System.Collections.Generic.List[string]
        # #1021: which state is EXPECTED -- the cut-over record says (a record that cannot be read = the standing state)
        $cut = ConvertFrom-SISupportStandingCutover $(try { Read-SISupportSqlValue -Invoke $Databases[$names[0]] -Sql (Get-SISupportStandingCutoverReadSql) } catch { '' })
        $back = New-Object System.Collections.Generic.List[string]

        # (a) a member of the admin group -- the group the database server names as its administrator, asked member-side
        $group = $null
        try {
            if (-not $Graph -or -not $AdminSid) { throw 'no directory or database server reader in this run' }
            $gid = ([string](& $AdminSid)).Trim()
            if ($gid -notmatch '^[0-9a-fA-F-]{36}$') { throw 'the database server''s Entra administrator could not be read' }
            $sp = Get-SISupportAppServicePrincipal -Graph $Graph -ClientId $app
            if (-not $sp) { $group = $false; $said.Add('group: the tenant has no service principal for the Support app') }
            else {
                $group = [bool](Test-SISupportAppGroupMember -Graph $Graph -GroupId $gid -ServicePrincipalId $sp.Id)
                if ($cut.Group) { if ($group) { $back.Add('the admin group'); $said.Add('group: a member AGAIN -- standing admin is back (the cut-over took it out)') } else { $said.Add('group: not a member -- as expected (admin only just in time)') } }
                else { $said.Add(('group: {0}' -f $(if ($group) { 'a member of the admin group' } else { 'NOT a member of the admin group' }))) }
            }
        } catch { $group = $null; $said.Add(('group: could not be checked ({0})' -f $_.Exception.Message)) }

        # (b) standing: its own user with db_owner in every product database; just in time: its own user in the read-only
        # role in every product database (db_owner there = an open support grant, or standing admin back)
        $check = if ($cut.DbOwner) { Get-SISupportAppReadRoleCheckSql -ClientId $app } else { Get-SISupportAppDatabaseCheckSql -ClientId $app }
        $missing = 0; $unknown = 0
        foreach ($n in $names) {
            try {
                $raw = Read-SISupportSqlValue -Invoke $Databases[$n] -Sql $check
                if ($cut.DbOwner) {
                    $t = ([string]$raw).Trim()
                    if ($t -eq '?') { $unknown++; $said.Add(('{0}: could not be checked (this identity cannot see the database''s users)' -f $n)); continue }
                    $p = @($t -split '\|')
                    if (-not $t -or $p.Count -lt 3) { $missing++; $said.Add(('{0}: NO user of its own' -f $n)); continue }
                    $owner = $p[$p.Count - 2] -eq '1'; $read = $p[$p.Count - 1] -eq '1'
                    if (-not $read) { $missing++; $said.Add(('{0}: its own user WITHOUT the read-only role' -f $n)) }
                    elseif ($owner) { $back.Add($n); $said.Add(('{0}: its own user, read-only role, and db_owner now (an open support grant -- or standing admin back)' -f $n)) }
                    else { $said.Add(('{0}: its own user, read-only role -- as expected' -f $n)) }
                    continue
                }
                $a = ConvertFrom-SISupportAppDatabaseAnswer $raw
                if ($a.Hidden) { $unknown++; $said.Add(('{0}: could not be checked (this identity cannot see the database''s users)' -f $n)) }
                elseif ($a.User -and $a.Owner) { $said.Add(('{0}: its own user, with db_owner' -f $n)) }
                else { $missing++; $said.Add(('{0}: {1}' -f $n, $(if ($a.User) { 'its own user WITHOUT db_owner' } else { 'NO user of its own' }))) }
            } catch { $unknown++; $said.Add(('{0}: could not be checked ({1})' -f $n, $_.Exception.Message)) }
        }
        $dbUser = $(if ($missing) { $false } elseif ($unknown) { $null } else { $true })
        $iso = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        $wire = [ordered]@{ group = $group; dbUser = $dbUser; checkedUtc = $iso; healedUtc = $null }
        $state = if (-not $cut.DbOwner -and -not $cut.Group) { 'standing admin (before the cut-over)' }
                 elseif ($cut.DbOwner -and $cut.Group) { $(if (@($back | Where-Object { $_ -eq 'the admin group' }).Count) { 'just in time expected -- STANDING ADMIN IS BACK' } else { 'just in time (cut over {0})' -f $cut.At }) }
                 else { 'partly cut over ({0})' -f $(if ($cut.DbOwner) { 'db_owner removed, the admin group not yet' } else { 'the admin group removed, db_owner not yet' }) }
        [pscustomobject]@{ Wire = $wire; State = $state; Back = $back.ToArray(); Text = ('support SQL access (read only, never healed here) -- {0}: {1}' -f $state, ($said.ToArray() -join '; ')) }
    } catch { & $none ('the check failed ({0})' -f $_.Exception.Message) }
}

function New-SISupportSqlAccessSeams {
    <#
        The heartbeat job's seams for Get-SISupportSqlAccess, on the real thing: @{ Databases; Graph; AdminSid }, or $null
        when the install has no Pro database or the helpers are not loaded. The install's product databases
        (SI_ProSqlDatabase, SI_LedgerDatabase, SI_Pro_DataSqlDatabase, each on its own server setting) signed in as the job
        (New-SIRecordSqlInvoke); Microsoft Graph and ARM as the job's identity (Invoke-SIAzRestRequest; two tries, short
        timeouts -- a heartbeat never waits long for this). Plain script blocks, NOT closures: a GetNewClosure() block does
        not see the functions of a dot-sourced file -- these find them where the check calls them.
    #>
    $proSrv = [string]$global:SI_ProSqlServer; $proDb = [string]$global:SI_ProSqlDatabase
    if (-not $proSrv.Trim() -or -not $proDb.Trim()) { return $null }
    if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) -or -not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction SilentlyContinue)) { return $null }
    $dbs = [ordered]@{}
    $dbs[$proDb] = New-SIRecordSqlInvoke -Server $proSrv -Database $proDb
    $ledSrv = $(if ([string]$global:SI_LedgerSqlServer) { [string]$global:SI_LedgerSqlServer } else { $proSrv })
    if ([string]$global:SI_LedgerDatabase -and -not $dbs.Contains([string]$global:SI_LedgerDatabase)) { $dbs[[string]$global:SI_LedgerDatabase] = New-SIRecordSqlInvoke -Server $ledSrv -Database ([string]$global:SI_LedgerDatabase) }
    $datSrv = $(if ([string]$global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { $proSrv })
    if ([string]$global:SI_Pro_DataSqlDatabase -and -not $dbs.Contains([string]$global:SI_Pro_DataSqlDatabase)) { $dbs[[string]$global:SI_Pro_DataSqlDatabase] = New-SIRecordSqlInvoke -Server $datSrv -Database ([string]$global:SI_Pro_DataSqlDatabase) }
    $graph = {
        param([string]$Method, [string]$Uri, $Body)
        $a = @{ Method = $Method; Uri = $Uri; Audience = 'Graph'; MaxAttempts = 2; TimeoutSec = 30; What = 'Microsoft Graph (support SQL access)' }
        if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Compress -Depth 5) }
        $r = Invoke-SIAzRestRequest @a
        if (-not $r -or [string]::IsNullOrWhiteSpace([string]$r.Content)) { return $null }
        [string]$r.Content | ConvertFrom-Json
    }
    $adminSid = {
        $sub = @([string]$env:SI_FLOW_SUBSCRIPTIONID, [string]$global:SI_AzSubscriptionId, [string]$global:SI_Bootstrap_SubscriptionId) | Where-Object { "$_".Trim() } | Select-Object -First 1
        $rg = @([string]$env:SI_FLOW_RESOURCEGROUP, [string]$global:SI_Bootstrap_ResourceGroupName) | Where-Object { "$_".Trim() } | Select-Object -First 1
        if (-not "$sub".Trim() -or -not "$rg".Trim()) { throw 'the install''s subscription / resource group is not known in this job' }
        $short = ([string]$global:SI_ProSqlServer).Split('.')[0]
        $r = Invoke-SIAzRestRequest -Method GET -Uri ('https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}?api-version=2021-11-01' -f "$sub".Trim(), "$rg".Trim(), $short) -MaxAttempts 2 -TimeoutSec 30 -What 'the database server (support SQL access)'
        $s = [string]$r.Content | ConvertFrom-Json
        if ($s -and $s.properties -and $s.properties.PSObject.Properties['administrators'] -and $s.properties.administrators) { [string]$s.properties.administrators.sid } else { '' }
    }
    @{ Databases = $dbs; Graph = $graph; AdminSid = $adminSid }
}
