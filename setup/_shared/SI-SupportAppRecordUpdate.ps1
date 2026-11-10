#Requires -Version 5.1
<#
    #1161 -- THE UPDATE RECORDS WHICH INVARDIA SUPPORT APP AN INSTALL HAS, WHERE THAT RECORD IS MISSING. RECORDS ONLY.

    An install whose support access was set up before the record existed has the Support app's own database user, but no
    cfg.InstallState 'SupportApp' -- so the heartbeat's support SQL access reads "not known", and Invardia's setup step
    support-arm reads 'unknown'. The steps that write the record (Grant-SISupportAccess, Grant-SISupportAppDatabase, the
    database setup job's support-user step) also ADD db_owner and the SQL admin group membership back, which would undo the
    just-in-time cut-over (#1021). So the update records the Support app here, and NOTHING ELSE:
      * the client id is READ from the install's own Support app database user in the Pro database: a contained Entra user
        (type E) that is a member of the read-only role si_support_read, or is named invardia-support-app -- its SID IS the
        application's client id ([guid]::ToByteArray() order, 16 bytes), converted and checked by the round trip (the
        conversion is the same as ConvertTo-SISqlSidFromClientId's -- written out here because this file ships in both
        editions and loads no Pro file; a Pro test holds the two equal);
      * it is CHECKED against the consent the install records (cfg.SupportConsent AppId, when there is one) and against
        -ExpectedClientId (an id Invardia names -- Invardia sends none to the updater today, so nothing passes it yet);
      * written ONCE, INSERT only (a record that is there is never replaced), READ BACK, one plain line;
      * nothing is written, and one plain line says why, when: the record is there but is not an id; this identity cannot
        see the database's users; no such user; more than one; its SID is not an application id; it disagrees with the
        consent or the given id. A valid record already there = nothing done, nothing said.
    NEVER a role, a grant, a user, a group membership: no statement here changes a right (a test holds the text).
    PURE apart from the seam -Store (the updater's Pro database: @{ Invoke = { param($Sql, $Params, $Mode) } }, modes reader /
    nonquery). PS 5.1 and 7; no module. Never throws.
#>

function ConvertTo-SISupportAppRecordSid {
    <# PURE. An application client id -> the SID Azure SQL gives its contained user: '0x' + the 16 bytes of
       [guid]::ToByteArray() as hex (the same as ConvertTo-SISqlSidFromClientId). #>
    param([Parameter(Mandatory)][string]$ClientId)
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SISupportAppRecordNames {
    <# PURE. The record, the user name and the role this step looks for, and who it writes as. #>
    @{ Row = 'SupportApp'; UserName = 'invardia-support-app'; ReadRole = 'si_support_read'; By = 'caj-si-updater' }
}

function Get-SISupportAppRecordStateSql {
    <# PURE. READ ONLY, one row: Present (1 = a 'SupportApp' row is there), Record (its value), HasTable, ConsentApp (the
       consent's AppId, '' = none / no table), CanSee (1 = this connection may see the database's other users). A table that
       is not there is never compiled into a statement that runs (each read sits behind its own IF). #>
    $n = Get-SISupportAppRecordNames
    @"
DECLARE @present int = 0, @rec nvarchar(400) = N'', @tbl int = 0, @consent nvarchar(36) = N'';
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    SET @tbl = 1;
    SELECT @present = 1, @rec = ISNULL(Value, N'') FROM cfg.InstallState WHERE Name = N'$($n.Row)';
END
IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL
    SELECT TOP (1) @consent = ISNULL(CONVERT(nvarchar(36), AppId), N'') FROM cfg.SupportConsent;
SELECT @present AS Present, @rec AS Record, @tbl AS HasTable, @consent AS ConsentApp,
       CAST(ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW DEFINITION'), 0) AS int) AS CanSee;
"@
}

function Get-SISupportAppRecordUserSql {
    <# PURE. READ ONLY. Every contained Entra user (type E) that is the Support app's by its role (si_support_read) or by
       its name (invardia-support-app): Sid ('0x' + hex), Name. Built-in principals (1-4) are never it. #>
    $n = Get-SISupportAppRecordNames
    @"
SELECT CONVERT(varchar(200), u.sid, 1) AS Sid, u.name AS Name
FROM sys.database_principals u
WHERE u.principal_id > 4 AND u.type = 'E'
  AND (u.name = N'$($n.UserName)'
       OR EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
                  WHERE m.member_principal_id = u.principal_id AND r.name = N'$($n.ReadRole)'));
"@
}

function Get-SISupportAppRecordWriteSql {
    <# PURE. ONE row INSERTED (@Value, @By) only when there is none: a record that is there is never replaced. #>
    $n = Get-SISupportAppRecordNames
    @"
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$($n.Row)')
    INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'$($n.Row)', @Value, @By);
"@
}

function Get-SISupportAppRecordSqlTexts {
    <# PURE. Every statement this step can send -- what the test reads to hold that none of them changes a right. #>
    @((Get-SISupportAppRecordStateSql), (Get-SISupportAppRecordUserSql), (Get-SISupportAppRecordWriteSql))
}

function ConvertFrom-SISqlSidToClientId {
    <# PURE. A database user's SID ('0x' + 32 hex digits) -> the application client id it was made from, or '' when it is
       not 16 bytes, is the empty id, or does not convert back to the same SID. #>
    param([AllowNull()][AllowEmptyString()][string]$Sid)
    $h = "$Sid".Trim()
    if ($h -notmatch '^0x[0-9A-Fa-f]{32}$') { return '' }
    $bytes = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $bytes[$i] = [Convert]::ToByte($h.Substring(2 + 2 * $i, 2), 16) }
    $g = New-Object guid -ArgumentList (, $bytes)
    if ($g -eq [guid]::Empty) { return '' }
    $id = $g.ToString()
    if ((ConvertTo-SISupportAppRecordSid -ClientId $id) -ine $h) { return '' }
    $id
}

function Test-SISupportAppRecordId {
    <# PURE. A text that is a non-empty GUID. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $g = [guid]::Empty
    [bool]([guid]::TryParse("$Text".Trim(), [ref]$g) -and $g -ne [guid]::Empty)
}

function Resolve-SISupportAppRecord {
    <#
        PURE. The decision. -State: the state row (Present, Record, HasTable, ConsentApp, CanSee); -Users: the candidate rows
        (Sid, Name); -ExpectedClientId: an id Invardia names ('' = none). Returns @{ Action (none | write | skip); ClientId;
        Line ('' = nothing to say) }.
    #>
    param([Parameter(Mandatory)]$State, [object[]]$Users = @(), [AllowEmptyString()][string]$ExpectedClientId = '')
    $out = { param($a, $id, $l) [pscustomobject]@{ Action = $a; ClientId = [string]$id; Line = [string]$l } }
    $p = 'support app record: '
    if (-not [int]$State.HasTable) { return (& $out 'skip' '' ($p + 'not checked -- the install''s settings table is not there yet; checked again at the next update')) }
    if ([int]$State.Present) {
        if (Test-SISupportAppRecordId $State.Record) { return (& $out 'none' '' '') }
        return (& $out 'skip' '' ($p + 'a record of the Invardia Support app is there but holds no valid application id -- it is left as it is (Invardia support corrects it)'))
    }
    if (-not [int]$State.CanSee) { return (& $out 'skip' '' ($p + 'the update''s identity cannot see the database''s users, so the Invardia Support app''s database user could not be looked up -- nothing recorded')) }
    $users = @($Users | Where-Object { $null -ne $_ })
    if (-not $users.Count) { return (& $out 'skip' '' ($p + 'no database user of the Invardia Support app was found -- nothing recorded')) }
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($u in $users) {
        $id = ConvertFrom-SISqlSidToClientId -Sid ([string]$u.Sid)
        if (-not $id) { return (& $out 'skip' '' ($p + ('the database user {0} looks like the Invardia Support app''s, but its id is not an application id -- nothing recorded' -f [string]$u.Name))) }
        if (-not ($ids -contains $id)) { $ids.Add($id) }
    }
    if ($ids.Count -gt 1) { return (& $out 'skip' '' ($p + ('{0} different database users look like the Invardia Support app''s -- nothing recorded, so the wrong one is never named' -f $ids.Count))) }
    $id = $ids[0]
    if ("$ExpectedClientId".Trim() -and -not ((Test-SISupportAppRecordId $ExpectedClientId) -and ([guid]$ExpectedClientId).ToString() -ieq $id)) {
        return (& $out 'skip' '' ($p + 'the Invardia Support app''s database user is not the Support app Invardia names for this install -- nothing recorded'))
    }
    if ((Test-SISupportAppRecordId $State.ConsentApp) -and ([guid]([string]$State.ConsentApp).Trim()).ToString() -ine $id) {
        return (& $out 'skip' '' ($p + 'the Invardia Support app''s database user is not the Support app the install''s support consent names -- nothing recorded'))
    }
    & $out 'write' $id ''
}

function Read-SISupportAppRecordRows {
    <# The rows of one read through the seam (mode 'reader'), each as a hashtable-or-object; @() when none. Throws on a failure. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Sql)
    @(& $Store.Invoke $Sql @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
}

function ConvertTo-SISupportAppRecordState {
    <# PURE. One state row (hashtable, DataRow or object) -> @{ Present; Record; HasTable; ConsentApp; CanSee }. #>
    param($Row)
    $v = { param($k) if ($null -eq $Row) { $null } elseif ($Row -is [System.Collections.IDictionary]) { $Row[$k] } elseif ($Row -is [System.Data.DataRow]) { $x = $Row[$k]; if ($x -is [System.DBNull]) { $null } else { $x } } elseif ($Row.PSObject.Properties[$k]) { $Row.$k } else { $null } }
    $i = { param($k) $x = & $v $k; if ($null -eq $x -or "$x" -eq '') { 0 } else { [int]$x } }
    [pscustomobject]@{ Present = (& $i 'Present'); Record = [string](& $v 'Record'); HasTable = (& $i 'HasTable'); ConsentApp = [string](& $v 'ConsentApp'); CanSee = (& $i 'CanSee') }
}

function Invoke-SISupportAppRecordStep {
    <#
        THE STEP (see the file's help). -Store: the updater's Pro database. -ExpectedClientId: an id Invardia names ('' = none;
        none is passed today). Returns @{ Action (none | recorded | skipped | failed); ClientId; Lines }. Never throws.
    #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyString()][string]$ExpectedClientId = '')
    $res = { param($a, $id, $l) [pscustomobject]@{ Action = $a; ClientId = [string]$id; Lines = @(@($l) | Where-Object { $_ }) } }
    $p = 'support app record: '
    try {
        $state = ConvertTo-SISupportAppRecordState ((Read-SISupportAppRecordRows -Store $Store -Sql (Get-SISupportAppRecordStateSql)) | Select-Object -First 1)
        # a valid record already there: nothing more is read, nothing is said
        if ([int]$state.HasTable -and [int]$state.Present -and (Test-SISupportAppRecordId $state.Record)) { return (& $res 'none' '' '') }
        $users = @()
        if ([int]$state.HasTable -and -not [int]$state.Present -and [int]$state.CanSee) {
            $users = @(Read-SISupportAppRecordRows -Store $Store -Sql (Get-SISupportAppRecordUserSql) | ForEach-Object {
                $r = $_
                if ($r -is [System.Collections.IDictionary]) { [pscustomobject]@{ Sid = [string]$r['Sid']; Name = [string]$r['Name'] } }
                elseif ($r -is [System.Data.DataRow]) { [pscustomobject]@{ Sid = [string]$r['Sid']; Name = [string]$r['Name'] } }
                else { [pscustomobject]@{ Sid = [string]$r.Sid; Name = [string]$r.Name } } })
        }
        $d = Resolve-SISupportAppRecord -State $state -Users $users -ExpectedClientId $ExpectedClientId
        if ($d.Action -eq 'none') { return (& $res 'none' '' '') }
        if ($d.Action -ne 'write') { return (& $res 'skipped' '' $d.Line) }
        $null = & $Store.Invoke (Get-SISupportAppRecordWriteSql) @{ Value = $d.ClientId; By = (Get-SISupportAppRecordNames).By } 'nonquery'
        $back = ConvertTo-SISupportAppRecordState ((Read-SISupportAppRecordRows -Store $Store -Sql (Get-SISupportAppRecordStateSql)) | Select-Object -First 1)
        if ([int]$back.Present -and ([string]$back.Record).Trim() -ieq $d.ClientId) {
            return (& $res 'recorded' $d.ClientId ($p + 'the Invardia Support app is now recorded on this install (read from its own database user, and read back) -- its support access is reported again; no right was changed'))
        }
        if ([int]$back.Present -and (Test-SISupportAppRecordId $back.Record)) {
            return (& $res 'skipped' '' ($p + 'another record of the Invardia Support app was written at the same time -- it is kept, nothing replaced'))
        }
        & $res 'failed' '' ($p + 'the record of the Invardia Support app was written but does not read back -- tried again at the next update')
    } catch {
        & $res 'failed' '' ($p + ('not checked ({0}) -- checked again at the next update' -f $_.Exception.Message))
    }
}
