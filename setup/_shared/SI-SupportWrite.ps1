#Requires -Version 5.1
<#
    SECURITYINSIGHT -- A SUPPORT TOOL THAT WRITES, AT AN INSTALL WHERE VENDOR SUPPORT HOLDS NO STANDING DATABASE ADMIN
    (framework DOCS/REQUIREMENTS.md SECAUDIT-1a / §5.5; SI: the support grant job caj-si-support-grant,
    engine\support-grant\SI-SupportGrant.ps1).

    After setup\Remove-SISupportStandingAccess.ps1 the Invardia Support app keeps only its read-only role si_support_read
    (metadata and health, no data) and gets admin JUST IN TIME: the Support session puts ONE request on the install's queue
    si-support-requests, the queue starts caj-si-support-grant, and its signed procedures add the role of the granted level
    (setup = db_owner, troubleshoot = db_datareader) for at most 8 hours -- never above the customer's consent. Invardia's
    Support session does all of that in ONE call, Open-InvardiaSupportGrant -Product si (and Close-InvardiaSupportGrant):
    the back office records the session first, the request goes on the queue, the call waits for the job and throws when it
    did not grant. Found live 2026-11-08 at the vendor's own install: after the cut-over every support tool that writes
    through the Support session failed ("could not be written", "The SELECT permission was denied on the object
    'InstallState'").

    Invoke-SISupportWithGrant -- THE ONE WAY such a tool writes:
      1. READ the Support app's own rights in the database (one read-only statement, Get-SISupportAccessProbeSql: its
         membership of db_owner, db_datareader and si_support_read -- functions on itself, which the read-only role may ask).
      2. ENOUGH already (a standing right at an install not moved yet, or a support grant someone opened before): the write
         runs as before and NO grant is asked. The rights could not be read, or the Support app is not in the read-only
         role (an install not on just-in-time access): also as before.
      3. Read-only: the grant is OPENED (-Level, 1 hour, the reason names the tool and the purpose), its READ-BACK waited
         for on a new connection (bounded: -ReadBackTries x -ReadBackSeconds, said plainly), the write made, and the grant
         CLOSED again in every case (only a grant this call opened -- never one that was open before). Each said in ONE line.
      4. The grant cannot be opened (no consent, the customer consented to a lower level, the job refused, an older Support
         session without the open call): said exactly, with what to do. -Kind audit: a WARNING, the main action goes on
         (the caller writes "NOT written (...)"); -Kind setting: it FAILS plainly (throws) -- a setting that was asked for and
         not written is never a success.

    Seams (tests pass fakes; New-SISupportGrantSeams gives the real ones over the open Support session):
      -Probe { }                     -> the probe row (Get-SISupportAccessProbeSql run read-only); throws = not known
      -Open  { param($Level, $Reason) } -> what the open answered (MaxUntil / Level when it says); THROWS when not granted
      -Close { param($Reason) }       throws when it could not close
      -Do    { }                     the write itself (what it returns is handed back as Value)
      -GrantSay { param([string]$Text, [string]$Color) }   -GrantSleep { param($Seconds) }
    A caller's seam dictionary (@{ Open; Close } and, in tests, Say / Sleep / ReadBackTries / ReadBackSeconds) is mapped
    onto these by the caller.
    No module; PS 5.1 and 7. Strict-mode safe. The -Do / -Probe blocks run as children of this function's scope (PowerShell
    scopes are dynamic), so its parameters carry names a caller does not use ($GrantLevel, $WriteKind, $GrantSay ... -- not
    $Level / $Say / $Sleep, which the setup scripts do use) and its locals are prefixed __g: a block that reads its caller's
    variables never finds one of this function's instead.
#>

$script:SISupportWrite = [ordered]@{
    ReadRole        = 'si_support_read'
    # a support tool's write is short: the shortest grant Invardia's open call gives (1..8 h); the close ends it at once anyway
    Hours           = 1
    # the support grant job allows 1-200 characters for the reason
    ReasonMax       = 200
    ReadBackTries   = 6
    ReadBackSeconds = 10
    LevelRole       = [ordered]@{ setup = 'db_owner'; troubleshoot = 'db_datareader' }
}

function Get-SISupportWriteContract { $script:SISupportWrite }

function Get-SISupportAccessProbeSql {
    <# PURE. ONE read-only statement: the signed-in principal's own role memberships (the read-only role may ask this). #>
    "SELECT USER_NAME() AS UserName, ISNULL(IS_ROLEMEMBER(N'db_owner'), 0) AS IsOwner, ISNULL(IS_ROLEMEMBER(N'db_datareader'), 0) AS IsReader, ISNULL(IS_ROLEMEMBER(N'$($script:SISupportWrite.ReadRole)'), 0) AS IsReadOnly;"
}

function ConvertFrom-SISupportAccessRow {
    <# PURE. The probe row -> @{ Known; User; Owner; Reader; ReadOnly }. Known false for no row. #>
    param($Row)
    $get = {
        param($n)
        if ($null -eq $Row) { return $null }
        if ($Row -is [System.Collections.IDictionary]) { return $Row[$n] }
        if ($Row -is [System.Data.DataRow]) { if ($Row.Table.Columns.Contains($n)) { return $Row[$n] } else { return $null } }
        $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null }
    }
    $yes = { param($v) ($null -ne $v) -and -not ($v -is [System.DBNull]) -and ("$v" -in '1', 'True', 'true') }
    if ($null -eq $Row -or $null -eq (& $get 'IsOwner')) { return [pscustomobject]@{ Known = $false; User = ''; Owner = $false; Reader = $false; ReadOnly = $false } }
    [pscustomobject]@{ Known = $true; User = [string](& $get 'UserName'); Owner = [bool](& $yes (& $get 'IsOwner')); Reader = [bool](& $yes (& $get 'IsReader')); ReadOnly = [bool](& $yes (& $get 'IsReadOnly')) }
}

function Test-SISupportAccessEnough {
    <# PURE. Does -Access carry what -Level needs (setup = db_owner; troubleshoot = db_datareader or db_owner)? #>
    param([Parameter(Mandatory)]$Access, [ValidateSet('setup', 'troubleshoot')][string]$Level = 'setup')
    if (-not $Access.Known) { return $false }
    if ($Level -eq 'setup') { return [bool]$Access.Owner }
    [bool]($Access.Owner -or $Access.Reader)
}

function Get-SISupportGrantNeed {
    <# PURE. Is a support grant asked for this write? @{ Ask; Why }. Asked ONLY when the Support app is in the read-only role
       (the just-in-time model is in place) and lacks the right -Level needs; every other case runs as before. #>
    param([Parameter(Mandatory)]$Access, [ValidateSet('setup', 'troubleshoot')][string]$Level = 'setup')
    if (-not $Access.Known) { return [pscustomobject]@{ Ask = $false; Why = 'the Support app''s own database rights could not be read -- the step runs as before' } }
    if (Test-SISupportAccessEnough -Access $Access -Level $Level) { return [pscustomobject]@{ Ask = $false; Why = 'the Support app holds the right already (a standing right, or a support grant that is open) -- no support grant is asked' } }
    if (-not $Access.ReadOnly) { return [pscustomobject]@{ Ask = $false; Why = ('the Support app is not in the read-only role {0} here (this install is not on just-in-time support access) -- no support grant is asked' -f $script:SISupportWrite.ReadRole) } }
    [pscustomobject]@{ Ask = $true; Why = ('the Support app is read-only here ({0}) and this needs {1}' -f $script:SISupportWrite.ReadRole, $script:SISupportWrite.LevelRole[$Level]) }
}

function Get-SISupportGrantReason {
    <# PURE. The reason the grant request carries: 'SecurityInsight <tool>: <purpose>', one line, at most 200 characters. #>
    param([Parameter(Mandatory)][string]$Tool, [Parameter(Mandatory)][string]$Purpose)
    $t = ('SecurityInsight {0}: {1}' -f $Tool.Trim(), $Purpose.Trim()) -replace '[\x00-\x1F\x7F]+', ' '
    if ($t.Length -gt $script:SISupportWrite.ReasonMax) { $t = $t.Substring(0, $script:SISupportWrite.ReasonMax) }
    $t
}

function Invoke-SISupportWithGrant {
    <#
        THE ONE WAY (see the header). Returns @{ Done; Asked; Opened; Closed; Value; Why; Lines }:
          Done    the write ran and did not throw
          Asked   a support grant was asked for (the Support app was read-only)
          Opened  this call opened one;  Closed  it was closed again
          Why     why the write was not made ('' when Done)
        -WriteKind setting: a grant that cannot be opened, a read-back that never shows the right, and a write that throws all
        THROW (after the close). -WriteKind audit: never throws -- Done false and Why say it.
    #>
    param(
        [Parameter(Mandatory)][string]$Purpose,
        [Parameter(Mandatory)][string]$Tool,
        [ValidateSet('setup', 'troubleshoot')][string]$GrantLevel = 'setup',
        [ValidateSet('audit', 'setting')][string]$WriteKind = 'setting',
        [Parameter(Mandatory)][scriptblock]$Do,
        [Parameter(Mandatory)][scriptblock]$Probe,
        [scriptblock]$Open,
        [scriptblock]$Close,
        [scriptblock]$GrantSay = { param([string]$Text, [string]$Color) if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text } },
        [scriptblock]$GrantSleep = { param($Seconds) Start-Sleep -Seconds $Seconds },
        [ValidateRange(1, 60)][int]$GrantReadBackTries = $script:SISupportWrite.ReadBackTries,
        [ValidateRange(0, 120)][int]$GrantReadBackSeconds = $script:SISupportWrite.ReadBackSeconds
    )
    $__gLines = New-Object System.Collections.Generic.List[string]
    $__gSay = { param([string]$t, [string]$c) $__gLines.Add($t); try { & $GrantSay $t $c } catch { } }
    $__gRes = [ordered]@{ Done = $false; Asked = $false; Opened = $false; Closed = $false; Value = $null; Why = ''; Lines = @() }
    $__gReason = Get-SISupportGrantReason -Tool $Tool -Purpose $Purpose
    $__gRole = $script:SISupportWrite.LevelRole[$GrantLevel]
    $__gRead = { $__gRow = $null; try { $__gRow = @(& $Probe | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0] } catch { $__gRow = $null }; ConvertFrom-SISupportAccessRow -Row $__gRow }
    $__gFail = {
        param([string]$why)
        $__gRes.Why = $why
        $__gRes.Lines = $__gLines.ToArray()
        if ($WriteKind -eq 'setting') { throw $why }
        [pscustomobject]$__gRes
    }
    $__gRun = {
        try { $__gRes.Value = & $Do; $__gRes.Done = $true }
        catch {
            if ($WriteKind -eq 'setting') { throw }
            $__gRes.Why = $_.Exception.Message
        }
    }

    # 1-2. the Support app's own rights; enough (or not on just-in-time access) = as before, no grant asked
    $__gNeed = Get-SISupportGrantNeed -Access (& $__gRead) -Level $GrantLevel
    if (-not $__gNeed.Ask) {
        & $__gRun
        $__gRes.Lines = $__gLines.ToArray()
        return [pscustomobject]$__gRes
    }

    # 3. read-only: open, read back, write, close
    $__gRes.Asked = $true
    $__gHow = 'open it by hand (Open-InvardiaSupportGrant -Product si -Level {0} -Reason ''<why>''; the customer must have consented to {0}) and run this again' -f $GrantLevel
    if (-not $Open) { return (& $__gFail ('{0} was not made: the Support app is read-only here and this Support session cannot open the support grant -- {1}' -f $Purpose, $__gHow)) }
    & $__gSay ('the Support app is read-only here: opening the support grant ({0}, at most {1} h) for: {2}' -f $GrantLevel, $script:SISupportWrite.Hours, $Purpose) 'Cyan'
    $__gAns = $null
    try { $__gAns = & $Open $GrantLevel $__gReason }
    catch {
        $__gW = ($_.Exception.Message -split "`n")[0]
        & $__gSay ('the support grant could NOT be opened: {0}' -f $__gW) 'Yellow'
        return (& $__gFail ('{0} was not made: the support grant could not be opened ({1}) -- {2}' -f $Purpose, $__gW, $__gHow))
    }
    $__gRes.Opened = $true
    $__gUntil = ''; try { if ($__gAns -and $__gAns.PSObject.Properties['MaxUntil'] -and "$($__gAns.MaxUntil)") { $__gUntil = [string]$__gAns.MaxUntil } } catch { $__gUntil = '' }
    $__gGot = ''; try { if ($__gAns -and $__gAns.PSObject.Properties['Level'] -and "$($__gAns.Level)") { $__gGot = [string]$__gAns.Level } } catch { $__gGot = '' }
    $__gCloseIt = {
        try {
            if ($Close) { $null = & $Close $__gReason; $__gRes.Closed = $true; & $__gSay 'support grant closed again' 'Gray' }
            else { & $__gSay ('the support grant was not closed from here (this Support session has no close call) -- it ends by itself{0}' -f $(if ($__gUntil) { ' at ' + $__gUntil + ' UTC' } else { ' within the hour' })) 'Yellow' }
        } catch {
            & $__gSay ('the support grant could NOT be closed ({0}) -- it ends by itself{1}; to close it now: Close-InvardiaSupportGrant -Product si -Reason ''<why>''' -f (($_.Exception.Message -split "`n")[0]), $(if ($__gUntil) { ' at ' + $__gUntil + ' UTC' } else { ' within the hour' })) 'Yellow'
        }
    }
    $__gThrow = ''
    try {
        # the read-back on a NEW connection (a role reaches a sign-in only when it signs in again) -- bounded, said plainly
        $__gOk = $false
        for ($__gI = 1; $__gI -le $GrantReadBackTries; $__gI++) {
            if (Test-SISupportAccessEnough -Access (& $__gRead) -Level $GrantLevel) { $__gOk = $true; break }
            if ($__gI -eq 1 -and $GrantReadBackTries -gt 1) { & $__gSay ('waiting for the support grant to read back ({0} in this database; up to {1} s)' -f $__gRole, (($GrantReadBackTries - 1) * $GrantReadBackSeconds)) 'DarkGray' }
            if ($__gI -lt $GrantReadBackTries) { & $GrantSleep $GrantReadBackSeconds }
        }
        if (-not $__gOk) {
            $__gW = 'the support grant was opened{0} but this database does not show {1} after {2} s{3}' -f $(if ($__gGot) { ' at level ' + $__gGot } else { '' }), $__gRole, (($GrantReadBackTries - 1) * $GrantReadBackSeconds), $(if ($__gGot -and $__gGot -ne $GrantLevel) { (' -- the customer consented to {0}, this needs {1}' -f $__gGot, $GrantLevel) } else { '' })
            & $__gSay $__gW 'Yellow'
            $__gRes.Why = ('{0} was not made: {1}' -f $Purpose, $__gW)
            if ($WriteKind -eq 'setting') { $__gThrow = $__gRes.Why }
        } else {
            & $__gSay ('support grant open ({0}{1}), read back: {2} in this database' -f $GrantLevel, $(if ($__gUntil) { ' until ' + $__gUntil + ' UTC' } else { '' }), $__gRole) 'Gray'
            & $__gRun
        }
    } finally {
        # closed in EVERY case -- also when the write threw (a -WriteKind setting write: its error goes on after the close)
        & $__gCloseIt
    }
    $__gRes.Lines = $__gLines.ToArray()
    if ($__gThrow) { throw $__gThrow }
    [pscustomobject]$__gRes
}

function Get-SISupportGrantArgs {
    <# PURE. A caller's seam dictionary -> the matching arguments of Invoke-SISupportWithGrant: Open / Close, and (tests)
       Say -> GrantSay, Sleep -> GrantSleep, ReadBackTries / ReadBackSeconds -> GrantReadBackTries / GrantReadBackSeconds.
       -Say: the caller's own line writer, used when the dictionary names none. #>
    param([System.Collections.IDictionary]$SupportGrant, [scriptblock]$Say)
    $a = @{ Open = $null; Close = $null }
    if ($Say) { $a['GrantSay'] = $Say }
    if (-not $SupportGrant) { return $a }
    foreach ($k in 'Open', 'Close') { if ($SupportGrant.Contains($k)) { $a[$k] = $SupportGrant[$k] } }
    foreach ($k in 'Say', 'Sleep', 'ReadBackTries', 'ReadBackSeconds') { if ($SupportGrant.Contains($k) -and $null -ne $SupportGrant[$k]) { $a['Grant' + $k] = $SupportGrant[$k] } }
    $a
}

function ConvertTo-SISupportInlineSql {
    <# PURE. The statement with its parameters DECLAREd in front (Invardia's audited SQL call takes no parameters): text as
       N'...' (quotes doubled), whole numbers, a number, bit, datetime2, NULL. A name that is not a plain name is refused. #>
    param([Parameter(Mandatory)][string]$Query, [System.Collections.IDictionary]$Params)
    if (-not $Params -or -not $Params.Count) { return $Query }
    $d = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Params.Keys)) {
        if ("$k" -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,63}$') { throw ("'{0}' is not a parameter name" -f $k) }
        $v = $Params[$k]
        if ($null -eq $v -or $v -is [System.DBNull]) { $d.Add(('DECLARE @{0} nvarchar(max) = NULL;' -f $k)) }
        elseif ($v -is [bool]) { $d.Add(('DECLARE @{0} bit = {1};' -f $k, [int]$v)) }
        elseif ($v -is [int] -or $v -is [long] -or $v -is [int16] -or $v -is [byte]) { $d.Add(('DECLARE @{0} bigint = {1};' -f $k, [long]$v)) }
        elseif ($v -is [double] -or $v -is [decimal] -or $v -is [single]) { $d.Add(('DECLARE @{0} float = {1};' -f $k, ([double]$v).ToString('R', [Globalization.CultureInfo]::InvariantCulture))) }
        elseif ($v -is [datetime]) { $d.Add(("DECLARE @{0} datetime2(7) = '{1}';" -f $k, $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffff', [Globalization.CultureInfo]::InvariantCulture))) }
        else { $d.Add(("DECLARE @{0} nvarchar(max) = N'{1}';" -f $k, ([string]$v).Replace("'", "''"))) }
    }
    ($d -join "`n") + "`n" + $Query
}

function New-SIProSettingSupportStore {
    <# The Pro settings store (the shape New-SIProSettingsStore returns: @{ Name; Invoke { param($Sql, $Params, $Mode) } })
       over Invardia's audited Invoke-InvardiaSupportSql -- every statement with -Reason in the customer's audit log, reads
       sent as reads. -Invoke replaces Invoke-InvardiaSupportSql (tests). #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$Reason, [scriptblock]$Invoke)
    $srv = if ($Server -match '\.') { $Server } else { $Server + '.database.windows.net' }
    if (-not $Invoke) { $Invoke = { param($S, $D, $Q, $R, [bool]$RO) Invoke-InvardiaSupportSql -Server $S -Database $D -Query $Q -Reason $R -ReadOnly:$RO } }
    $inline = ${function:ConvertTo-SISupportInlineSql}
    $db = $Database; $why = $Reason
    $inv = {
        param([string]$Sql, $Params, [string]$Mode)
        $res = & $Invoke $srv $db (& $inline -Query $Sql -Params $Params) $why ($Mode -eq 'reader')
        $rows = @(@(if ($null -ne $res -and $res.PSObject.Properties['Rows']) { $res.Rows } else { $res }) | Where-Object { $null -ne $_ })
        if ($Mode -eq 'scalar') {
            if (-not $rows.Count) { return $null }
            $r0 = $rows[0]
            if ($r0 -is [System.Data.DataRow]) { return $r0.ItemArray[0] }
            if ($r0 -is [System.Collections.IDictionary]) { return @($r0.Values)[0] }
            return @($r0.PSObject.Properties)[0].Value
        }
        if ($Mode -eq 'nonquery') { if ($null -ne $res -and $res.PSObject.Properties['RowsAffected']) { return [int]$res.RowsAffected }; return 0 }
        , @($rows)
    }.GetNewClosure()
    [pscustomobject]@{ Name = ('{0}/{1} (Invardia Support app)' -f $srv, $Database); Invoke = $inv }
}

function New-SISupportGrantSeams {
    <#
        The REAL -Open / -Close over the open Invardia Support session: Open-InvardiaSupportGrant / Close-InvardiaSupportGrant
        -Product si (Invardia's tools\Connect-InvardiaSupport.ps1 -- the back office records the session, ONE request goes on
        si-support-requests, the call waits for caj-si-support-grant and throws when it did not grant). -SubscriptionId /
        -ResourceGroup / -StorageAccount are passed when known (else Invardia's call finds them from the environment).
        After each, the SQL connection pools of this process are cleared: a pooled connection keeps the rights it signed in
        with, so the read-back and the write must sign in again. @{ Open; Close } -- Open $null when this session has no
        open call (an older Connect-InvardiaSupport): the write then says so.
    #>
    param([string]$SubscriptionId = '', [string]$ResourceGroup = '', [string]$StorageAccount = '')
    if (-not (Get-Command -Name Open-InvardiaSupportGrant -ErrorAction SilentlyContinue)) { return @{ Open = $null; Close = $null } }
    $where = @{}
    if ("$SubscriptionId".Trim()) { $where['SubscriptionId'] = "$SubscriptionId".Trim() }
    if ("$ResourceGroup".Trim()) { $where['ResourceGroup'] = "$ResourceGroup".Trim() }
    if ("$StorageAccount".Trim()) { $where['StorageAccount'] = "$StorageAccount".Trim() }
    $hours = [int]$script:SISupportWrite.Hours
    $open = {
        param([string]$Level, [string]$Reason)
        try { Open-InvardiaSupportGrant -Product si -Level $Level -Reason $Reason -Hours $hours @where }
        finally { try { [System.Data.SqlClient.SqlConnection]::ClearAllPools() } catch { } }
    }.GetNewClosure()
    $close = $null
    if (Get-Command -Name Close-InvardiaSupportGrant -ErrorAction SilentlyContinue) {
        $close = {
            param([string]$Reason)
            try { Close-InvardiaSupportGrant -Product si -Reason $Reason @where }
            finally { try { [System.Data.SqlClient.SqlConnection]::ClearAllPools() } catch { } }
        }.GetNewClosure()
    }
    @{ Open = $open; Close = $close }
}
