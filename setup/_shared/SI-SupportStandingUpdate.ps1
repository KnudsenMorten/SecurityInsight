#Requires -Version 5.1
<#
    #1151 (1) SEC-01 / OPEN-01 -- THE UPDATE'S HALF OF "NO STANDING SUPPORT ADMIN" (rule: existing installs reach the
    new-install state through the update; framework SECAUDIT-1a: the Invardia Support app keeps ONLY its read-only role
    standing, everything more comes just in time through the signed support grant procedures).

    On every update, after the database setup job (caj-si-dbinit) has run as the updater's job:
      1. INPUT -- the updater names the Support app recorded on the install (cfg.InstallState 'SupportApp') to the job
         (SI_DBINIT_SUPPORT_STANDING_OFF). Never when no Support app is recorded, and never when the cut-over record
         (cfg.InstallState 'SupportStandingAccess') names a ROLLBACK: standing access put back on purpose is not taken again
         by an update.
      2. THE JOB (setup\_shared\SI-DbInitJob.ps1, Invoke-SIDbInitStandingOff) takes db_owner off the Support app's own user
         in each product database ONLY where the just-in-time path reads back in the same batch (engine\pro-settings\
         SI-SupportGrantSql.ps1, Get-SISupportStandingOffSql: read-only role held, the four procedures this release's text and
         signed, signer in db_owner, the engine may run them, consent recorded, no grant open) and records the outcome in
         its row 'DbJobSupportStanding'.
      3. THE UPDATER reads that row (it must carry THIS run's id), reads the Support app's membership of the SQL admin group
         from the MEMBER's side (its read-only Graph rights, framework §4.5 G5), and writes:
           * the state row 'SupportStanding' { state ok | missing | unknown, dbOwner, group, checkedUtc, why } -- what the
             heartbeat's setup step support-grant-jit reads ('missing' while any standing access is still there);
           * the cut-over record 'SupportStandingAccess' (the same short shape setup\Remove-SISupportStandingAccess.ps1
             keeps: { at, applied, file }) -- only ADDING what is now read back as gone, so the heartbeat's
             supportSqlAccess expects the just-in-time state.
    EVERY UPDATER RUN, ALSO ONE THAT INSTALLS NOTHING (live 2026-11-09: the state row stayed 'missing' for hours after Invardia
    support had removed the standing admin, because only an update that installs a release ran step 3):
      4. RE-CHECK (Invoke-SISupportStandingCheck -Recheck) -- READ ONLY, without the database setup job: the membership of
         the SQL admin group read NOW (the member's side), db_owner from the NEWEST read-back on record -- the job's row
         'DbJobSupportStanding' of any run, or the state row itself when it is newer (written by the job's verdict or by the
         Support-app step below after ITS read-back). The re-check never takes anything off and never runs after a
         deliberate rollback; a re-check that could read nothing never replaces a row that knows more.
    THE SUPPORT-APP STEP setup\Remove-SISupportStandingAccess writes the state row in the SAME shape
    (New-SISupportStandingStateValue over New-SISupportStandingStepVerdict): 'ok' once its own read-back proves no db_owner in
    any product database AND not a member of the SQL admin group (also when it finds nothing to do); 'missing' after a
    rollback.
    WHAT THE UPDATE NEVER DOES: remove a group member (it holds no right to change a role-assignable group, by design: least
    privilege, framework §4.5 G5) -- while the Support app is still a member, ONE line names the Support-app step that
    does it, setup\Remove-SISupportStandingAccess.ps1 (it refuses unless the server's Entra admin is the group AND the
    group keeps another member: the break-glass admin is never lost). Never touches the server's Entra administrator,
    never drops a user, never touches the read-only role. Never fails or holds the update.

    PURE apart from the seams (-Store { param($Sql, $Params, $Mode) }, -Graph { param($Method, $Uri, $Body) }). PS 5.1 and 7;
    no module.
#>

function Get-SISupportStandingNames {
    <# PURE. The rows and the one Support-app step this file names. #>
    @{
        StateRow   = 'SupportStanding'
        CutoverRow = 'SupportStandingAccess'
        JobRow     = 'DbJobSupportStanding'
        # named without its extension: the step is in the Pro package only (a free file never names a Pro file in code)
        Step       = 'setup\Remove-SISupportStandingAccess'
        RecordMax  = 400
    }
}

function Get-SISupportStandingInputSql {
    <# PURE. READ ONLY, one row: the recorded Support app, the cut-over record, the job's standing-off row, the state row itself
       ('' = none / no table). #>
    $n = Get-SISupportStandingNames
    $v = { param($name) "CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'$name'), N'') END" }
    "SELECT $(& $v 'SupportApp') AS SupportApp, $(& $v $n.CutoverRow) AS Cutover, $(& $v $n.JobRow) AS JobRow, $(& $v $n.StateRow) AS StateRow;"
}

function ConvertFrom-SISupportStandingUtcText {
    <# PURE. One "yyyy-MM-ddTHH:mm:ssZ" field of a row's raw JSON text (read by pattern: ConvertFrom-Json would turn it into a
       local DateTime) -> a UTC [datetime], or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Field)
    if (-not "$Text".Trim()) { return $null }
    if ("$Text" -notmatch ('"{0}"\s*:\s*"([^"]+)"' -f [regex]::Escape($Field))) { return $null }
    $t = [datetime]::MinValue
    if ([datetime]::TryParse($Matches[1], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$t)) { return $t }
    $null
}

function Resolve-SISupportStandingDbOwnerEvidence {
    <#
        PURE. Step 4 (the re-check without the database setup job): the Support app's standing db_owner from the NEWEST read-back
        on record -- -JobRow: the job's row 'DbJobSupportStanding' (any run; its 'at'); -StateRow: the state row 'SupportStanding'
        (its dbOwner + checkedUtc: written by the job's verdict or by the Support-app step after its own read-back). An entry
        that says 'unknown', or has no time, is no evidence. Returns @{ State (off | kept); Run; Why; At; Source (job | state) }
        in the shape Resolve-SISupportStandingState takes as -Job, or $null (nothing on record).
    #>
    param([AllowNull()][AllowEmptyString()][string]$JobRow, [AllowNull()][AllowEmptyString()][string]$StateRow)
    $cands = New-Object System.Collections.Generic.List[object]
    $job = ConvertFrom-SISupportStandingJobRow -Text $JobRow
    $jAt = ConvertFrom-SISupportStandingUtcText -Text $JobRow -Field 'at'
    if ($job -and $job.State -in 'off', 'kept' -and $jAt) { $cands.Add([pscustomobject]@{ State = $job.State; Run = $job.Run; Why = $job.Why; At = $jAt; Source = 'job' }) }
    if ("$StateRow".Trim()) {
        $s = $null; try { $s = "$StateRow" | ConvertFrom-Json -ErrorAction Stop } catch { $s = $null }
        $sAt = ConvertFrom-SISupportStandingUtcText -Text $StateRow -Field 'checkedUtc'
        $sDb = if ($s -and $s.PSObject.Properties['dbOwner']) { ([string]$s.dbOwner).Trim().ToLowerInvariant() } else { '' }
        if ($sDb -in 'off', 'kept' -and $sAt) { $cands.Add([pscustomobject]@{ State = $sDb; Run = ''; Why = $(if ($s.PSObject.Properties['why']) { [string]$s.why } else { '' }); At = $sAt; Source = 'state' }) }
    }
    if (-not $cands.Count) { return $null }
    # the newest wins; the same second = the state row (it was written from that read-back, or after it)
    @($cands | Sort-Object -Property @{ Expression = 'At'; Descending = $true }, @{ Expression = { if ($_.Source -eq 'state') { 0 } else { 1 } }; Descending = $false })[0]
}

function New-SISupportStandingStepVerdict {
    <#
        PURE. The verdict the Support-app step (setup\Remove-SISupportStandingAccess) records in the state row, in the shape
        New-SISupportStandingStateValue writes: -Outcome ok (its OWN read-back proved no db_owner in any product database AND
        not a member of the SQL admin group) | rollback (standing access put back on purpose: missing; the update does not
        take it again; -DbOwner / -Group: what the rollback put back and read back). The heartbeat's words name no command.
    #>
    param([Parameter(Mandatory)][ValidateSet('ok', 'rollback')][string]$Outcome,
          [ValidateSet('off', 'kept', 'unknown')][string]$DbOwner = 'kept', [ValidateSet('member', 'not-member', 'unknown')][string]$Group = 'member')
    if ($Outcome -eq 'ok') { return (Resolve-SISupportStandingState -Job ([pscustomobject]@{ State = 'off'; Run = ''; Why = '' }) -Member $false) }
    [pscustomobject]@{ State = 'missing'; DbOwner = $DbOwner; Group = $Group; Applied = $null; Lines = @()
                       Detail = 'Standing admin was put back on purpose (a rollback by Invardia support); the update does not take it again.' }
}

function ConvertFrom-SISupportStandingCutoverText {
    <# PURE. The cut-over record's text -> @{ Applied[]; Rollback (it names a rollback step); At }. Unreadable = nothing applied. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $o = [pscustomobject]@{ Applied = @(); Rollback = $false; At = '' }
    if (-not "$Text".Trim()) { return $o }
    try { $j = "$Text" | ConvertFrom-Json -ErrorAction Stop } catch { return $o }
    $a = @(([string]$j.applied) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $o.Applied = $a
    $o.Rollback = [bool](@($a | Where-Object { $_ -like 'rollback-*' }).Count)
    if ("$Text" -match '"at"\s*:\s*"([^"]+)"') { $o.At = $Matches[1] }
    $o
}

function Get-SISupportStandingOffInput {
    <#
        PURE. Step 1: which Support app the updater names to its database setup job run (SI_DBINIT_SUPPORT_STANDING_OFF).
        -SupportApp: cfg.InstallState 'SupportApp'; -Cutover: the cut-over record's text. Returns @{ ClientId ('' = none);
        Why (a plain line when none) }.
    #>
    param([AllowNull()][AllowEmptyString()][string]$SupportApp, [AllowNull()][AllowEmptyString()][string]$Cutover)
    $g = [guid]::Empty
    if (-not [guid]::TryParse("$SupportApp".Trim(), [ref]$g) -or $g -eq [guid]::Empty) { return [pscustomobject]@{ ClientId = ''; Why = '' } }
    $c = ConvertFrom-SISupportStandingCutoverText -Text $Cutover
    if ($c.Rollback) { return [pscustomobject]@{ ClientId = ''; Why = ('support standing access: a rollback put the Invardia Support app''s standing access back on purpose ({0}) -- the update does not take it again' -f $(if ($c.At) { $c.At } else { 'time not recorded' })) } }
    [pscustomobject]@{ ClientId = $g.ToString(); Why = '' }
}

function ConvertFrom-SISupportStandingJobRow {
    <# PURE. The job's row 'DbJobSupportStanding' -> @{ State (off | kept | unknown); Run; Dbs; Why }, or $null (none / unreadable). #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if (-not "$Text".Trim()) { return $null }
    try { $j = "$Text" | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if (-not $j -or -not $j.PSObject.Properties['state']) { return $null }
    $st = ([string]$j.state).Trim().ToLowerInvariant(); if ($st -notin 'off', 'kept', 'unknown') { $st = 'unknown' }
    [pscustomobject]@{ State = $st; Run = $(if ($j.PSObject.Properties['run']) { [string]$j.run } else { '' }); Dbs = $(if ($j.PSObject.Properties['dbs']) { [string]$j.dbs } else { '' }); Why = $(if ($j.PSObject.Properties['why']) { [string]$j.why } else { '' }) }
}

function Resolve-SISupportStandingState {
    <#
        PURE. Step 3's verdict. -Job: ConvertFrom-SISupportStandingJobRow of THIS run ($null = the job wrote none for this run);
        -Member: the Support app in the SQL admin group ($true | $false | $null = not known); -Prior: the cut-over record's text.
        Returns @{ State (ok | missing | unknown); DbOwner (off | kept | unknown); Group (member | not-member | unknown);
        Applied (the new applied list, or $null = nothing to write); Detail (the heartbeat's words, no command); Lines }.
    #>
    param($Job, [AllowNull()][object]$Member, [AllowNull()][AllowEmptyString()][string]$Prior = '', [string]$GroupName = 'the SQL admin group', [string]$ResourceGroup = '<resource group>')
    $n = Get-SISupportStandingNames
    $lines = New-Object System.Collections.Generic.List[string]
    $db = if ($Job) { [string]$Job.State } else { 'unknown' }
    $grp = if ($Member -eq $true) { 'member' } elseif ($Member -eq $false) { 'not-member' } else { 'unknown' }
    $state = if ($db -eq 'off' -and $grp -eq 'not-member') { 'ok' } elseif ($db -eq 'kept' -or $grp -eq 'member') { 'missing' } else { 'unknown' }
    switch ($db) {
        'off'   { $lines.Add('support standing access: the Invardia Support app holds no standing db_owner in any product database (the just-in-time path read back first)') }
        'kept'  { $lines.Add(('support standing access: db_owner KEPT where the just-in-time path does not read back yet ({0}) -- it is put in place by the database setup job''s support run, or the support grant install step (Install-SISupportGrantProcedure) in a Support session; the next update takes db_owner off once it reads back' -f $(if ($Job.Why) { $Job.Why } else { 'no reason recorded' }))) }
        default { $lines.Add('support standing access: the database setup job recorded no standing-off result for this run -- checked again at the next update') }
    }
    if ($grp -eq 'member') {
        $lines.Add(('support standing access: the Invardia Support app is still a STANDING member of {0}. The update may not remove a member of that role-assignable group (least privilege) -- Invardia support removes it in the install''s Support session: {1} -ResourceGroup {2} (plan first, then -Apply; it refuses unless the group stays the server''s Entra admin with another member){3}' -f $GroupName, $n.Step, $ResourceGroup, $(if ($db -ne 'off') { '. It runs after db_owner is off.' } else { '' })))
    } elseif ($grp -eq 'unknown') { $lines.Add('support standing access: the Invardia Support app''s membership of the SQL admin group could not be read -- checked again at the next update') }
    $detail = switch ($state) {
        'ok'      { 'No standing admin: the read-only role and the just-in-time grant only.' }
        'missing' {
            if ($grp -eq 'member' -and $db -eq 'off') { 'Standing admin remains: still a member of the SQL admin group (one Invardia Support-app step removes it).' }
            elseif ($grp -eq 'member') { 'Standing admin remains: db_owner and SQL admin group membership (the just-in-time grant must read back first).' }
            else { 'Standing db_owner remains where the just-in-time grant does not read back yet.' }
        }
        default   { 'The standing access could not be read fully.' }
    }
    # the record ADDS only what is read back as gone; a rollback record is never overwritten
    $p = ConvertFrom-SISupportStandingCutoverText -Text $Prior
    $applied = $null
    if (-not $p.Rollback) {
        $want = New-Object System.Collections.Generic.List[string]
        foreach ($x in @($p.Applied)) { if (-not $want.Contains($x)) { $want.Add($x) } }
        if ($db -eq 'off' -and -not $want.Contains('db-owner')) { $want.Add('db-owner') }
        if ($grp -eq 'not-member' -and -not $want.Contains('admin-group')) { $want.Add('admin-group') }
        $ordered = @(@('db-owner', 'admin-group') | Where-Object { $want.Contains($_) }) + @($want | Where-Object { $_ -notin 'db-owner', 'admin-group' })
        if ($want.Count -ne @($p.Applied).Count) { $applied = $ordered }
    }
    [pscustomobject]@{ State = $state; DbOwner = $db; Group = $grp; Applied = $applied; Detail = $detail; Lines = $lines.ToArray() }
}

function New-SISupportStandingStateValue {
    <# PURE. The state row 'SupportStanding': compact JSON, at most 400 characters. #>
    param([Parameter(Mandatory)]$Verdict, [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{ state = [string]$Verdict.State; dbOwner = [string]$Verdict.DbOwner; group = [string]$Verdict.Group
                     checkedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); why = [string]$Verdict.Detail }
    $v = ConvertTo-Json -InputObject $o -Compress
    if ($v.Length -gt (Get-SISupportStandingNames).RecordMax) { $o.why = ''; $v = ConvertTo-Json -InputObject $o -Compress }
    $v
}

function New-SISupportStandingCutoverValue {
    <# PURE. The cut-over record in the short shape setup\Remove-SISupportStandingAccess.ps1 keeps ({ at, applied, file }). #>
    param([Parameter(Mandatory)][string[]]$Applied, [datetime]$NowUtc = [datetime]::UtcNow)
    ConvertTo-Json -Compress -InputObject ([ordered]@{ at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); applied = ($Applied -join ','); file = ''; by = 'caj-si-updater' })
}

function Get-SISupportStandingWriteSql {
    <# PURE. ONE row of cfg.InstallState written or replaced (@Value, @By) -- -Name: the state row or the cut-over record. #>
    param([Parameter(Mandatory)][ValidateSet('SupportStanding', 'SupportStandingAccess')][string]$Name)
    @"
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$Name')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'$Name';
    ELSE INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'$Name', @Value, @By);
END
"@
}

function Test-SISupportStandingMember {
    <# The Support app's membership of -GroupId, asked from the MEMBER's side (checkMemberGroups: a group's member list hides
       service principals from many callers). $true | $false | $null (not known -- never read as "not a member"). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$ClientId, [AllowEmptyString()][string]$GroupId)
    if (-not "$GroupId".Trim()) { return $null }
    try {
        $r = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id" -f ([guid]$ClientId).ToString()) $null
        $sp = @($(if ($r -is [System.Collections.IDictionary]) { $r['value'] } elseif ($r -and $r.PSObject.Properties['value']) { $r.value }) | Where-Object { $_ })[0]
        if (-not $sp) { return $false }   # no service principal in this tenant: it cannot be a member
        $spId = if ($sp -is [System.Collections.IDictionary]) { [string]$sp['id'] } else { [string]$sp.id }
        $m = & $Graph 'POST' ("https://graph.microsoft.com/v1.0/directoryObjects/$spId/checkMemberGroups") @{ groupIds = @([string]$GroupId) }
        $v = @($(if ($m -is [System.Collections.IDictionary]) { $m['value'] } elseif ($m -and $m.PSObject.Properties['value']) { $m.value }) | ForEach-Object { [string]$_ })
        [bool]($v -contains [string]$GroupId)
    } catch { $null }
}

function Invoke-SISupportStandingCheck {
    <#
        Step 3 (see the file's help), after the job's run -Run. -Store: the updater's Pro database seam. -Graph: the updater's
        Graph seam. -GroupId: the group the SQL server names as its Entra administrator ('' = not a group / not read).
        Writes the state row and (only when more is read back as gone) the cut-over record. Never throws. Returns the verdict
        (Resolve-SISupportStandingState) plus @{ Written }.
        -Recheck: step 4 -- every updater run, without the database setup job (no -Run): db_owner from the newest read-back on
        record (Resolve-SISupportStandingDbOwnerEvidence), the membership read now. Never after a deliberate rollback (nothing
        read, nothing written); a verdict of 'unknown' never replaces a state row that is already there.
    #>
    param([Parameter(Mandatory)]$Store, [scriptblock]$Graph, [Parameter(Mandatory)][string]$ClientId, [string]$Run = '', [AllowEmptyString()][string]$GroupId = '',
          [string]$GroupName = 'the SQL admin group', [string]$ResourceGroup = '<resource group>', [datetime]$NowUtc = [datetime]::UtcNow, [switch]$Recheck)
    $n = Get-SISupportStandingNames
    $val = { param($r, $k) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { [string]$r[$k] } elseif ($r -is [System.Data.DataRow]) { $x = $r[$k]; if ($x -is [System.DBNull]) { '' } else { [string]$x } } elseif ($r.PSObject.Properties[$k]) { [string]$r.$k } else { '' } }
    try {
        $row = @(& $Store.Invoke (Get-SISupportStandingInputSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $pre = New-Object System.Collections.Generic.List[string]
        if ($Recheck) {
            if ((ConvertFrom-SISupportStandingCutoverText -Text (& $val $row 'Cutover')).Rollback) {
                return [pscustomobject]@{ State = 'skipped'; DbOwner = ''; Group = ''; Applied = $null; Detail = ''; Written = @()
                                          Lines = @('support standing access: not re-checked -- a rollback put the standing access back on purpose; the state row stays as the rollback wrote it') }
            }
            $job = Resolve-SISupportStandingDbOwnerEvidence -JobRow (& $val $row 'JobRow') -StateRow (& $val $row 'StateRow')
            $pre.Add(('support standing access: re-checked on this run (read only, without the database setup job): the SQL admin group read now; db_owner {0}' -f $(if ($job) { 'from the newest read-back on record ({0}, {1})' -f $(if ($job.Source -eq 'job') { 'the database setup job' } else { 'the state row' }), $job.At.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { 'not on record yet' })))
        } else {
            $job = ConvertFrom-SISupportStandingJobRow -Text (& $val $row 'JobRow')
            if ($job -and $Run -and $job.Run -ne $Run) { $job = $null }   # a row of another run is never taken
        }
        $member = if ($Graph) { Test-SISupportStandingMember -Graph $Graph -ClientId $ClientId -GroupId $GroupId } else { $null }
        $v = Resolve-SISupportStandingState -Job $job -Member $member -Prior (& $val $row 'Cutover') -GroupName $GroupName -ResourceGroup $ResourceGroup
        if ($pre.Count) { $v.Lines = @($pre.ToArray()) + @($v.Lines) }
        $written = New-Object System.Collections.Generic.List[string]
        $keep = $Recheck -and $v.State -eq 'unknown' -and "$(& $val $row 'StateRow')".Trim()
        if ($keep) { $v.Lines = @($v.Lines) + @('support standing access: the re-check could not read enough -- nothing is written, the state row keeps what it says') }
        else { try { $null = & $Store.Invoke (Get-SISupportStandingWriteSql -Name $n.StateRow) @{ Value = (New-SISupportStandingStateValue -Verdict $v -NowUtc $NowUtc); By = 'caj-si-updater' } 'nonquery'; $written.Add($n.StateRow) } catch { } }
        if ($v.Applied -and -not $keep) {
            try { $null = & $Store.Invoke (Get-SISupportStandingWriteSql -Name $n.CutoverRow) @{ Value = (New-SISupportStandingCutoverValue -Applied @($v.Applied) -NowUtc $NowUtc); By = 'caj-si-updater' } 'nonquery'; $written.Add($n.CutoverRow) } catch { }
        }
        $v | Add-Member -NotePropertyName Written -NotePropertyValue $written.ToArray() -PassThru
    } catch {
        [pscustomobject]@{ State = 'unknown'; DbOwner = 'unknown'; Group = 'unknown'; Applied = $null; Detail = 'The standing access could not be read fully.'; Written = @()
                           Lines = @(('support standing access: not checked ({0}) -- checked again at the next update' -f $_.Exception.Message)) }
    }
}
