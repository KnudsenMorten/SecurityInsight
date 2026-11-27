#Requires -Version 5.1
<#
    SECURITYINSIGHT -- SQL LEAST PRIVILEGE SWITCHED ON THROUGH THE UPDATER (framework section 12.23 SQL-ACCESS, OPEN-05; Invardia
    decision 2026-11-20). The product path for an EXISTING install: no ops SQL write, no Support-session script.

    THE CONTROL-PLANE VALUE (on the install's updater job caj-si-updater, set by Invardia, read back like every other):
      SI_UPDATER_SQL_LEAST_PRIVILEGE   plan | apply | off
      SI_UPDATER_CONTROLPLANE_REASON   '<person>: <why>' -- REQUIRED (Test-SIControlPlaneReason); without a usable one the
                                       value is refused in one warning line and nothing changes.
    The updater hands the mode to the database setup job caj-si-dbinit (SI_DBINIT_SQLLP, per execution: the install's SQL
    admin, the identity that holds the rights) which does the work in the Pro database (Invoke-SIDbInitSqlLeastPrivilege).

    INVARDIA'S RULES (each one has its test: tests\pester\SIv3-SqlLeastPrivilege.Tests.ps1):
      1. ONLY the broad db_datareader / db_datawriter / db_ddladmin memberships of SI's OWN job identities are removed, and
         ONLY after their least-privilege role grants are in place and READ BACK in the same run. "SI's own" = a principal of
         the job's input (SI_DBINIT_PRINCIPALS, by its SID = its client id), named id-si-* or a name the install recorded
         for it (SI_DBINIT_SQLLP_NAMES), an Entra user (type E) -- never the Invardia Support app (the install's recorded
         one, the one named to the run), never the job's own identity, never a group (the SQL admin group is one), never a
         person (a name with '@'), never anything not on the list. Today the list (Get-SISqlLpModel) has ONE entry: the
         engine identity, replaced by si_engine (engine\pro-settings\SI-EngineGrants.ps1; its grants cover every statement
         of this release: Test-SIEngineCutoverReady). The updater keeps db_datareader + db_datawriter + db_ddladmin (its
         schema step, framework section 12.23 P4); web, MCP and asset tagging keep db_datareader (no role replaces it yet).
      2. PLAN FIRST. 'plan' writes the exact list it WOULD remove, and the grants that replace them, to the job's log and
         its run record (cfg.InstallState 'DbJobSqlLeastPrivilege', the plan itself in 'DbJobSqlLeastPrivilegePlan' with
         its hash). 'apply' runs ONLY when a plan for the SAME state (the same hash) ran before. On apply: a snapshot of
         sys.database_permissions and every role membership BEFORE, the removals in ONE transaction, a snapshot AFTER, the
         diff -- and anything that disappeared and is not one of the planned removals (a permission or a membership) RESTORES
         everything at once (the planned removals too), read back. Nothing is half-applied.
      3. AUDITED: the run record + its line in the updater's log and the heartbeat's setup step sql-least-privilege; per
         identity read back: the broad role is gone AND its replacement grants are there (else: restored).
      4. 'off' = the way back: the broad memberships put back (the ones this path removed, recorded in
         'DbJobSqlLeastPrivilegeRemoved', and today's db_datareader + db_datawriter of the engine), read back; the updater
         then hands the switches off again (SI_DBINIT_ENGINE_ROLE_ONLY / SI_DBINIT_SIGNED_GRANTS 0).
      It NEVER fails the update: a refusal or a failure is a warning line and its record; the job's own verdict is unchanged.

    GAP 1 (the switches reach the updater -- an update NEVER adds the broad roles back once least privilege is on): the
    switches in force are kept in cfg.InstallState 'SqlLeastPrivilege' { engineRoleOnly, signedGrants, at, by }, written by
    the updater (a switch ON on its job, an apply that read back) and by the guided install's run of the job. Every update
    reads it (Get-SISqlLpDecision): engine role only = the job's switch ON, or the row, or 'apply' -- and only 'off' turns it
    off again. A job environment rewritten without the switch (the updater rewrites its own job) no longer brings the broad
    roles back.

    PURE except Invoke-SIDbInitSqlLeastPrivilege (the job's -Sql seam). PS 5.1 and 7; no module.
#>

function Get-SISqlLpNames {
    <# PURE. The fixed names. #>
    [ordered]@{
        Variable       = 'SI_UPDATER_SQL_LEAST_PRIVILEGE'
        JobVariable    = 'SI_DBINIT_SQLLP'
        NamesVariable  = 'SI_DBINIT_SQLLP_NAMES'
        ReasonVariable = 'SI_DBINIT_SQLLP_REASON'
        Switches       = 'SqlLeastPrivilege'
        Record         = 'DbJobSqlLeastPrivilege'
        PlanRecord     = 'DbJobSqlLeastPrivilegePlan'
        RemovedRecord  = 'DbJobSqlLeastPrivilegeRemoved'
        BroadRoles     = @('db_datareader', 'db_datawriter', 'db_ddladmin')
        RecordMax      = 400
    }
}

function Get-SISqlLpModel {
    <# PURE. THE LIST: which of SI's own job identities may lose which broad roles, and the role that replaces them. A
       component that is not here keeps every role it has (Get-SISqlLpKeptReason says why). #>
    @([pscustomobject]@{ Component = 'engine'; Role = 'si_engine'; Remove = @('db_datareader', 'db_datawriter', 'db_ddladmin') })
}

function Get-SISqlLpKeptReason {
    <# PURE. Why a component of the input keeps its broad roles. #>
    param([string]$Component)
    switch ($Component) {
        'updater' { 'the update''s schema step needs them (framework section 12.23 P4: the updater keeps its DDL)' }
        'web'     { 'no least-privilege role replaces db_datareader for the web app in this release' }
        'mcp'     { 'no least-privilege role replaces db_datareader for the MCP server in this release' }
        'tagging' { 'no least-privilege role replaces db_datareader for asset tagging in this release' }
        default   { 'not on the list' }
    }
}

function ConvertFrom-SISqlLpMode {
    <# PURE. A mode value -> @{ Mode ('' | plan | apply | off); Refused ('' or the warning) }. #>
    param([AllowNull()][AllowEmptyString()][string]$Value, [string]$Name = 'SI_UPDATER_SQL_LEAST_PRIVILEGE')
    $v = "$Value".Trim().Trim('"').Trim()
    if (-not $v) { return [pscustomobject]@{ Mode = ''; Refused = '' } }
    $l = $v.ToLowerInvariant()
    if ($l -in 'plan', 'apply', 'off') { return [pscustomobject]@{ Mode = $l; Refused = '' } }
    [pscustomobject]@{ Mode = ''; Refused = ("{0}='{1}' is not plan, apply or off -- SQL least privilege is left as it is" -f $Name, $(if ($v.Length -gt 40) { $v.Substring(0, 40) + '...' } else { $v })) }
}

function ConvertFrom-SISqlLpSwitches {
    <# PURE. The row 'SqlLeastPrivilege' -> @{ Present; EngineRoleOnly; SignedGrants; At; By }. Unreadable = not present. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $no = [pscustomobject]@{ Present = $false; EngineRoleOnly = $false; SignedGrants = $false; At = ''; By = '' }
    if (-not "$Value".Trim()) { return $no }
    try { $o = "$Value" | ConvertFrom-Json -ErrorAction Stop } catch { return $no }
    if ($o -isnot [System.Management.Automation.PSCustomObject]) { return $no }
    $b = { param($n) $p = $o.PSObject.Properties[$n]; ($null -ne $p) -and ("$($p.Value)".Trim() -match '^(?i)(1|true)$') }
    $s = { param($n) $p = $o.PSObject.Properties[$n]; if ($null -ne $p) { "$($p.Value)" } else { '' } }
    [pscustomobject]@{ Present = $true; EngineRoleOnly = [bool](& $b 'engineRoleOnly'); SignedGrants = [bool](& $b 'signedGrants'); At = (& $s 'at'); By = (& $s 'by') }
}

function New-SISqlLpSwitchesValue {
    <# PURE. The row 'SqlLeastPrivilege': compact JSON { engineRoleOnly, signedGrants, at, by }. #>
    param([bool]$EngineRoleOnly, [bool]$SignedGrants, [string]$By = 'updater', [datetime]$NowUtc = [datetime]::UtcNow)
    ConvertTo-Json -Compress -InputObject ([ordered]@{ engineRoleOnly = $(if ($EngineRoleOnly) { 1 } else { 0 }); signedGrants = $(if ($SignedGrants) { 1 } else { 0 })
        at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); by = $By })
}

function Get-SISqlLpDecision {
    <#
        PURE. THE UPDATER'S DECISION for one update (gap 1 + gap 2):
          -ModeValue      SI_UPDATER_SQL_LEAST_PRIVILEGE as set on the job
          -ReasonProblem  Test-SIControlPlaneReason's answer for SI_UPDATER_CONTROLPLANE_REASON ('' = usable)
          -Switches       ConvertFrom-SISqlLpSwitches of the row in force
          -EnvEngineOn / -EnvSignedOn   the job's own SI_Setup_EngineLeastPrivilege / SI_Setup_SignedGrantProcedure ON
        Returns @{ Mode (what the job is handed: '' | plan | apply | off); EngineRoleOnly; SignedGrants; Lines; Refused }.
        THE RULES: engine role only = a switch ON, or the row, or 'apply'; signed grants = a switch ON, or the row; 'off'
        turns both off (the way back). A mode without a usable reason, or a value that is not a mode, is refused (one line)
        and changes nothing -- the switches in force stay.
    #>
    param([AllowEmptyString()][string]$ModeValue = '', [AllowEmptyString()][string]$ReasonProblem = '', $Switches = $null, [bool]$EnvEngineOn = $false, [bool]$EnvSignedOn = $false)
    $n = Get-SISqlLpNames
    $lines = New-Object System.Collections.Generic.List[string]
    $refused = ''
    $m = ConvertFrom-SISqlLpMode -Value $ModeValue -Name $n.Variable
    $mode = $m.Mode
    if ($m.Refused) { $refused = $m.Refused }
    elseif ($mode -and $ReasonProblem) { $refused = ('{0}={1} not handed on -- every change of SQL least privilege needs SI_UPDATER_CONTROLPLANE_REASON to name who asked and why (''<person>: <why>''); {2}' -f $n.Variable, $mode, $ReasonProblem); $mode = '' }
    if ($refused) { $lines.Add('WARNING: control-plane value: ' + $refused) }
    $sw = if ($Switches) { $Switches } else { ConvertFrom-SISqlLpSwitches -Value '' }
    $eng = [bool]($EnvEngineOn -or $sw.EngineRoleOnly -or $mode -eq 'apply')
    $sig = [bool]($EnvSignedOn -or $sw.SignedGrants)
    if ($mode -eq 'off') { $eng = $false; $sig = $false }
    if ($eng -and -not $EnvEngineOn -and $sw.EngineRoleOnly -and $mode -ne 'apply') { $lines.Add(('SQL least privilege: the engine keeps its role si_engine only -- switched on for this install since {0} (cfg.InstallState {1}); the update adds no broad role back ({2}=off is the way back)' -f $(if ($sw.At) { $sw.At } else { 'earlier' }), $n.Switches, $n.Variable)) }
    [pscustomobject]@{ Mode = $mode; EngineRoleOnly = $eng; SignedGrants = $sig; Lines = $lines.ToArray(); Refused = $refused }
}

function Get-SISqlLpNextSwitches {
    <#
        PURE. The row 'SqlLeastPrivilege' after a run of the job that SUCCEEDED (-Decision: Get-SISqlLpDecision; -JobState:
        the job's least-privilege state for this run, '' = none). Returns @{ Write; EngineRoleOnly; SignedGrants } -- Write
        only when the row changes. 'off' = both off; an apply that read back ('applied' / 'already') = engine role only on;
        a switch ON on the job = kept on (the next job environment without it changes nothing).
    #>
    param([Parameter(Mandatory)]$Decision, $Switches = $null, [bool]$EnvEngineOn = $false, [bool]$EnvSignedOn = $false, [AllowEmptyString()][string]$JobState = '')
    $sw = if ($Switches) { $Switches } else { ConvertFrom-SISqlLpSwitches -Value '' }
    $eng = [bool]$sw.EngineRoleOnly; $sig = [bool]$sw.SignedGrants
    if ($Decision.Mode -eq 'off') { $eng = $false; $sig = $false }
    else {
        if ($EnvEngineOn) { $eng = $true }
        if ($EnvSignedOn) { $sig = $true }
        if ($Decision.Mode -eq 'apply' -and $JobState -in 'applied', 'already') { $eng = $true }
    }
    $write = (-not $sw.Present -and ($eng -or $sig -or $Decision.Mode -eq 'off')) -or ($sw.Present -and ($eng -ne [bool]$sw.EngineRoleOnly -or $sig -ne [bool]$sw.SignedGrants))
    [pscustomobject]@{ Write = [bool]$write; EngineRoleOnly = $eng; SignedGrants = $sig }
}

function Get-SISqlLpRecordLine {
    <# PURE. The updater's one line for the job's record (@{ mode; state; n; list; why }), '' when none. WARNING for a
       refusal, a failure and a restore. #>
    param($Record)
    if (-not $Record -or -not $Record.PSObject.Properties['state']) { return '' }
    $g = { param($k) $p = $Record.PSObject.Properties[$k]; if ($null -ne $p) { "$($p.Value)" } else { '' } }
    $st = & $g 'state'; $mode = & $g 'mode'; $list = & $g 'list'; $why = & $g 'why'; $cnt = & $g 'n'
    $t = switch ($st) {
        'planned'            { 'SQL least privilege PLAN: {0} broad membership(s) would be removed{1} -- nothing changed; apply runs only on this same state' -f $cnt, $(if ($list) { ' (' + $list + ')' } else { '' }) }
        'applied'            { 'SQL least privilege APPLIED: {0} broad membership(s) removed ({1}); read back per identity: the broad role is gone and its replacement grants are there' -f $cnt, $list }
        'already'            { 'SQL least privilege: already in force -- no broad membership is left to remove; the replacement grants read back' }
        'back'               { 'SQL least privilege OFF: the broad memberships are back ({0}), read back' -f $list }
        'refused'            { 'WARNING: SQL least privilege ({0}) refused, nothing changed: {1}' -f $mode, $why }
        'not-ready'          { 'WARNING: SQL least privilege ({0}): nothing removed -- {1}' -f $mode, $why }
        'restored'           { 'WARNING: SQL least privilege ({0}): a loss was found after the change and EVERYTHING was restored at once, read back -- {1}' -f $mode, $why }
        'restore-incomplete' { 'WARNING: SQL least privilege ({0}): a loss was found and the restore did NOT read back complete -- {1}; Invardia support restores it through the Support app' -f $mode, $why }
        default              { 'WARNING: SQL least privilege ({0}) not done: {1}' -f $mode, $why }
    }
    $t
}

# =====================================================================================================================
#  THE JOB'S SIDE (caj-si-dbinit)
# =====================================================================================================================

function Get-SISqlLpSnapshotSql {
    <# PURE. READ ONLY, ONE result set: every role membership and every database permission of the database. #>
@'
SET NOCOUNT ON;
SELECT N'member' AS Kind, r.name AS RoleName, m.name AS Member, CONVERT(varchar(200), m.sid, 1) AS Sid, m.[type] AS MemberType,
       CAST(NULL AS int) AS Class, CAST(NULL AS nvarchar(128)) AS SchemaName, CAST(NULL AS nvarchar(256)) AS ObjectName, CAST(NULL AS nvarchar(128)) AS ColumnName,
       CAST(NULL AS nvarchar(128)) AS Permission, CAST(NULL AS nvarchar(2)) AS State, CAST(NULL AS nvarchar(128)) AS Grantee, CAST(NULL AS nvarchar(2)) AS TargetType
FROM sys.database_role_members AS rm
JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id
JOIN sys.database_principals AS m ON m.principal_id = rm.member_principal_id
UNION ALL
SELECT N'perm', NULL, NULL, NULL, NULL, p.class,
       CASE p.class WHEN 1 THEN OBJECT_SCHEMA_NAME(p.major_id) WHEN 3 THEN SCHEMA_NAME(p.major_id)
                    WHEN 6 THEN (SELECT SCHEMA_NAME(t.schema_id) FROM sys.types AS t WHERE t.user_type_id = p.major_id) END,
       CASE p.class WHEN 1 THEN OBJECT_NAME(p.major_id) WHEN 4 THEN USER_NAME(p.major_id) WHEN 6 THEN TYPE_NAME(p.major_id)
                    WHEN 24 THEN (SELECT k.name FROM sys.symmetric_keys AS k WHERE k.symmetric_key_id = p.major_id)
                    WHEN 25 THEN (SELECT c.name FROM sys.certificates AS c WHERE c.certificate_id = p.major_id)
                    WHEN 26 THEN (SELECT a.name FROM sys.asymmetric_keys AS a WHERE a.asymmetric_key_id = p.major_id) END,
       CASE WHEN p.class = 1 AND p.minor_id > 0 THEN COL_NAME(p.major_id, p.minor_id) END,
       p.permission_name, p.[state], USER_NAME(p.grantee_principal_id),
       CASE WHEN p.class = 4 THEN (SELECT dp.[type] FROM sys.database_principals AS dp WHERE dp.principal_id = p.major_id) END
FROM sys.database_permissions AS p;
'@
}

function Get-SISqlLpRowValue {
    <# PURE. One field of a row (hashtable, PSObject or DataRow) as text ('' = none). #>
    param($Row, [string]$Name)
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row -is [System.Data.DataRow]) { if ($Row.Table.Columns.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($null -ne $Row -and $Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($null -eq $v -or $v -is [System.DBNull]) { return '' }
    [string]$v
}

function Get-SISqlLpMemberKey { <# PURE. #> param([string]$Role, [string]$Sid) ('m|{0}|{1}' -f "$Role".ToLowerInvariant(), "$Sid".ToUpperInvariant()) }

function ConvertFrom-SISqlLpSnapshot {
    <# PURE. Rows of Get-SISqlLpSnapshotSql -> @{ Members (@{ Key; Role; Member; Sid; Type }); Perms (@{ Key; Class; Schema;
       Object; Column; Permission; State; Grantee; TargetType }); Keys (HashSet of every key) }. #>
    param([object[]]$Rows = @())
    $members = New-Object System.Collections.Generic.List[object]; $perms = New-Object System.Collections.Generic.List[object]
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $g = { param($k) Get-SISqlLpRowValue -Row $r -Name $k }
        $kind = & $g 'Kind'
        if ($kind -eq 'member') {
            $sid = (& $g 'Sid').ToUpperInvariant() -replace '^0X', '0x'
            $o = [pscustomobject]@{ Key = (Get-SISqlLpMemberKey -Role (& $g 'RoleName') -Sid $sid); Role = (& $g 'RoleName'); Member = (& $g 'Member'); Sid = $sid; Type = (& $g 'MemberType').Trim() }
            if ($keys.Add($o.Key)) { $members.Add($o) }
        } elseif ($kind -eq 'perm') {
            $o = [pscustomobject]@{ Class = [int]("0" + (& $g 'Class')); Schema = (& $g 'SchemaName'); Object = (& $g 'ObjectName'); Column = (& $g 'ColumnName')
                                    Permission = (& $g 'Permission'); State = (& $g 'State').Trim(); Grantee = (& $g 'Grantee'); TargetType = (& $g 'TargetType').Trim(); Key = '' }
            $o.Key = ('p|{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $o.Class, $o.Schema, $o.Object, $o.Column, $o.Permission, $o.State, $o.Grantee).ToLowerInvariant()
            if ($keys.Add($o.Key)) { $perms.Add($o) }
        }
    }
    [pscustomobject]@{ Members = $members.ToArray(); Perms = $perms.ToArray(); Keys = $keys }
}

function Compare-SISqlLpSnapshot {
    <#
        PURE. THE DIFF. -Before / -After: ConvertFrom-SISqlLpSnapshot; -Planned: the member keys this run means to remove.
        Returns @{ Lost (members + perms that disappeared and are NOT planned: any one = restore); Removed (planned and gone);
        NotRemoved (planned and still there); Gained (new since BEFORE: said, never undone) }.
    #>
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After, [string[]]$Planned = @())
    $plan = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($k in @($Planned)) { if ($k) { [void]$plan.Add($k) } }
    $lost = New-Object System.Collections.Generic.List[object]; $removed = New-Object System.Collections.Generic.List[object]; $notRemoved = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Before.Members) + @($Before.Perms)) {
        if ($null -eq $x) { continue }
        $gone = -not $After.Keys.Contains($x.Key)
        if ($plan.Contains($x.Key)) { if ($gone) { $removed.Add($x) } else { $notRemoved.Add($x) } }
        elseif ($gone) { $lost.Add($x) }
    }
    $gained = @(@($After.Members) + @($After.Perms) | Where-Object { $_ -and -not $Before.Keys.Contains($_.Key) })
    [pscustomobject]@{ Lost = $lost.ToArray(); Removed = $removed.ToArray(); NotRemoved = $notRemoved.ToArray(); Gained = $gained }
}

function Format-SISqlLpItem {
    <# PURE. One member or permission in plain words. #>
    param($Item)
    if ($Item.Key -like 'm|*') { return ('{0} in {1}' -f $Item.Member, $Item.Role) }
    $on = switch ($Item.Class) { 0 { 'the database' } 1 { '{0}.{1}{2}' -f $Item.Schema, $Item.Object, $(if ($Item.Column) { ' (' + $Item.Column + ')' } else { '' }) } 3 { 'SCHEMA::' + $Item.Schema } default { 'class {0} {1}' -f $Item.Class, $Item.Object } }
    '{0} {1} on {2} to {3}' -f $(switch ($Item.State) { 'D' { 'DENY' } 'W' { 'GRANT (with grant option)' } default { 'GRANT' } }), $Item.Permission, $on, $Item.Grantee
}

function ConvertTo-SISqlLpLiteral { <# PURE. A text as an N'...' literal. #> param([string]$Text) "N'" + "$Text".Replace("'", "''") + "'" }
function ConvertTo-SISqlLpBracket { <# PURE. A name as [name] (']' doubled). #> param([string]$Name) '[' + "$Name".Replace(']', ']]') + ']' }

function Get-SISqlLpRestoreStatements {
    <#
        PURE. THE RESTORE: one statement per lost item -- a membership added back (the member found by its SID, the role by
        its name; only when it is not a member already), a permission granted / denied again (WITH GRANT OPTION where it had
        it). Returns @{ Statements (@{ Item; Sql }); Unrestorable (items no statement can restore, said) }.
    #>
    param([object[]]$Items = @())
    $out = New-Object System.Collections.Generic.List[object]; $bad = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Items | Where-Object { $_ })) {
        if ($x.Key -like 'm|*') {
            if ($x.Sid -notmatch '^0x[0-9A-Fa-f]{2,170}$') { $bad.Add($x); continue }
            $sql = @"
DECLARE @r int = DATABASE_PRINCIPAL_ID($(ConvertTo-SISqlLpLiteral $x.Role)), @m int = (SELECT principal_id FROM sys.database_principals WHERE sid = $($x.Sid)), @s nvarchar(800);
IF @r IS NOT NULL AND @m IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.database_role_members WHERE role_principal_id = @r AND member_principal_id = @m)
BEGIN SET @s = N'ALTER ROLE ' + QUOTENAME($(ConvertTo-SISqlLpLiteral $x.Role)) + N' ADD MEMBER ' + QUOTENAME(USER_NAME(@m)); EXEC (@s); END
"@
            $out.Add([pscustomobject]@{ Item = $x; Sql = $sql }); continue
        }
        if ($x.Permission -notmatch '^[A-Z][A-Z ]{1,60}$' -or -not $x.Grantee) { $bad.Add($x); continue }
        $target = switch ($x.Class) {
            0  { '' }
            1  { if ($x.Schema -and $x.Object) { ' ON OBJECT::' + (ConvertTo-SISqlLpBracket $x.Schema) + '.' + (ConvertTo-SISqlLpBracket $x.Object) } else { $null } }
            3  { if ($x.Schema) { ' ON SCHEMA::' + (ConvertTo-SISqlLpBracket $x.Schema) } else { $null } }
            4  { if ($x.Object) { ' ON ' + $(switch ($x.TargetType) { 'R' { 'ROLE' } 'A' { 'APPLICATION ROLE' } default { 'USER' } }) + '::' + (ConvertTo-SISqlLpBracket $x.Object) } else { $null } }
            6  { if ($x.Schema -and $x.Object) { ' ON TYPE::' + (ConvertTo-SISqlLpBracket $x.Schema) + '.' + (ConvertTo-SISqlLpBracket $x.Object) } else { $null } }
            24 { if ($x.Object) { ' ON SYMMETRIC KEY::' + (ConvertTo-SISqlLpBracket $x.Object) } else { $null } }
            25 { if ($x.Object) { ' ON CERTIFICATE::' + (ConvertTo-SISqlLpBracket $x.Object) } else { $null } }
            26 { if ($x.Object) { ' ON ASYMMETRIC KEY::' + (ConvertTo-SISqlLpBracket $x.Object) } else { $null } }
            default { $null }
        }
        if ($null -eq $target) { $bad.Add($x); continue }
        $col = if ($x.Class -eq 1 -and $x.Column) { ' (' + (ConvertTo-SISqlLpBracket $x.Column) + ')' } else { '' }
        $verb = if ($x.State -eq 'D') { 'DENY' } else { 'GRANT' }
        $tail = if ($x.State -eq 'W') { ' WITH GRANT OPTION' } else { '' }
        $out.Add([pscustomobject]@{ Item = $x; Sql = ('{0} {1}{2}{3} TO {4}{5};' -f $verb, $x.Permission, $col, $target, (ConvertTo-SISqlLpBracket $x.Grantee), $tail) })
    }
    [pscustomobject]@{ Statements = $out.ToArray(); Unrestorable = $bad.ToArray() }
}

function Get-SISqlLpPlan {
    <#
        PURE. RULE 1 -- THE EXACT LIST. -Before: the snapshot; -Principals: the job's input (@{ Component; Name; ClientId;
        Sid? } -- Sid defaults to the client id's SID); -AllowedNames: the names the install recorded for its identities;
        -NeverSids: the Invardia Support app(s) and the job's own identity; -Ready: component -> @{ Ok; Lines; Grants } (the
        replacement role's grants READ BACK in this run); -AllowedTypes: the principal types that may lose a role (E = an
        Entra user / managed identity; the tests' SQL Server users are S).
        Returns @{ Removals (@{ Component; Member; Sid; Role; Key; Replacement }); Kept; Never; NotReady; Hash; Text }.
        A membership is on the list ONLY when ALL hold: the role is db_datareader / db_datawriter / db_ddladmin; the member
        is a principal of the input by its SID; its component is on Get-SISqlLpModel with that role; it is not a group, not
        a person ('@'), not a Support app, not the job itself; its name is id-si-* or recorded; its replacement is ready.
    #>
    param([Parameter(Mandatory)]$Before, [object[]]$Principals = @(), [string[]]$AllowedNames = @(), [string[]]$NeverSids = @(),
          [hashtable]$Ready = @{}, [string[]]$AllowedTypes = @('E'))
    $n = Get-SISqlLpNames
    $model = @{}; foreach ($m in @(Get-SISqlLpModel)) { $model[$m.Component] = $m }
    $never = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($NeverSids)) { if ($s) { [void]$never.Add([string]$s) } }
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($AllowedNames)) { if ("$a".Trim()) { [void]$names.Add("$a".Trim()) } }
    $bySid = @{}
    foreach ($p in @($Principals | Where-Object { $_ })) {
        $sid = if ($p.PSObject.Properties['Sid'] -and $p.Sid) { [string]$p.Sid } elseif ($p.ClientId) { Get-SISqlLpSid -ClientId ([string]$p.ClientId) } else { '' }
        if ($sid) { $bySid[$sid.ToUpperInvariant() -replace '^0X', '0x'] = $p; if ($p.Name) { [void]$names.Add([string]$p.Name) } }
    }
    $rem = New-Object System.Collections.Generic.List[object]; $kept = New-Object System.Collections.Generic.List[string]
    $nev = New-Object System.Collections.Generic.List[string]; $notReady = New-Object System.Collections.Generic.List[string]
    foreach ($mb in @($Before.Members | Where-Object { $_ -and $n.BroadRoles -contains ([string]$_.Role).ToLowerInvariant() })) {
        $p = $bySid[[string]$mb.Sid]
        $label = '{0} in {1}' -f $mb.Member, $mb.Role
        if ($never.Contains([string]$mb.Sid)) { $nev.Add($label + ' -- the Invardia Support app or the job''s own identity: never touched'); continue }
        if ($mb.Type -eq 'X' -or $mb.Type -eq 'G') { $nev.Add($label + ' -- a group (the SQL admin group is one): never touched'); continue }
        if ("$($mb.Member)" -match '@') { $nev.Add($label + ' -- a person: never touched'); continue }
        if (-not $p) { $nev.Add($label + ' -- not one of SecurityInsight''s own job identities: never touched'); continue }
        if ($AllowedTypes -notcontains [string]$mb.Type) { $nev.Add(('{0} -- a principal of type {1}, not an Entra identity: never touched' -f $label, $mb.Type)); continue }
        if ("$($mb.Member)" -notmatch '^id-si-[A-Za-z0-9-]+$' -and -not $names.Contains([string]$mb.Member)) { $nev.Add($label + ' -- its name is neither id-si-* nor a name the install recorded: never touched'); continue }
        $c = [string]$p.Component
        $mo = $model[$c]
        if (-not $mo -or @($mo.Remove) -notcontains ([string]$mb.Role).ToLowerInvariant()) { $kept.Add(('{0} ({1}) -- kept: {2}' -f $label, $c, (Get-SISqlLpKeptReason -Component $c))); continue }
        $rd = $Ready[$c]
        if (-not $rd -or -not $rd.Ok) { $notReady.Add(('{0} ({1}) -- kept: its role {2} is not ready{3}' -f $label, $c, $mo.Role, $(if ($rd -and @($rd.Lines).Count) { ': ' + ((@($rd.Lines) | Select-Object -First 2) -join '; ') } else { '' }))); continue }
        $rem.Add([pscustomobject]@{ Component = $c; Member = [string]$mb.Member; Sid = [string]$mb.Sid; Role = ([string]$mb.Role).ToLowerInvariant(); Key = $mb.Key; Replacement = $mo.Role })
    }
    $sorted = @($rem | Sort-Object Component, Sid, Role)
    $text = (@($sorted | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Component, $_.Sid, $_.Role, $_.Replacement }) -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('sqllp v1' + "`n" + $text))) -replace '-', '').Substring(0, 16).ToLowerInvariant() } finally { $sha.Dispose() }
    [pscustomobject]@{ Removals = $sorted; Kept = $kept.ToArray(); Never = $nev.ToArray(); NotReady = $notReady.ToArray(); Hash = $hash; Text = $text }
}

function Get-SISqlLpSid {
    <# PURE. An Entra principal's database SID (0x + the 16 bytes in Guid.ToByteArray order, upper case). #>
    param([Parameter(Mandatory)][string]$ClientId)
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Format-SISqlLpList {
    <# PURE. 'member:role,role; member2:role' -- the list in the record (at most -Max characters). #>
    param([object[]]$Items = @(), [int]$Max = 160)
    $t = (@($Items | Group-Object Member | ForEach-Object { '{0}:{1}' -f $_.Name, (@($_.Group | ForEach-Object Role) -join ',') }) -join '; ')
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    $t
}

function Get-SISqlLpRemoveSql {
    <#
        PURE. THE REMOVAL -- ONE transaction (XACT_ABORT): per identity, its replacement role is checked INSIDE the batch
        first (not a member = THROW, nothing removed), then each planned membership dropped where it is there. The member is
        found by its SID, the roles are the fixed names of the list. Any error rolls the whole batch back.
    #>
    param([object[]]$Removals = @())
    $n = Get-SISqlLpNames
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('SET NOCOUNT ON; SET XACT_ABORT ON;')
    [void]$sb.AppendLine('DECLARE @m int, @rr int, @r int, @s nvarchar(800);')
    [void]$sb.AppendLine('BEGIN TRY')
    [void]$sb.AppendLine('BEGIN TRANSACTION;')
    foreach ($g in @($Removals | Where-Object { $_ } | Group-Object Sid)) {
        $first = $g.Group[0]
        if ($first.Sid -notmatch '^0x[0-9A-Fa-f]{2,170}$') { throw ('not a SID: {0}' -f $first.Sid) }
        if ($first.Replacement -notmatch '^si_[a-z_]{1,40}$') { throw ('not a component role: {0}' -f $first.Replacement) }
        [void]$sb.AppendLine(("SET @m = (SELECT principal_id FROM sys.database_principals WHERE sid = {0} AND [type] NOT IN ('R', 'X', 'G') AND principal_id > 4);" -f $first.Sid))
        [void]$sb.AppendLine(("IF @m IS NULL THROW 51000, N'the identity {0} is not in this database', 1;" -f "$($first.Member)".Replace("'", "''")))
        [void]$sb.AppendLine(("SET @rr = DATABASE_PRINCIPAL_ID(N'{0}');" -f $first.Replacement))
        [void]$sb.AppendLine(("IF @rr IS NULL OR NOT EXISTS (SELECT 1 FROM sys.database_role_members WHERE role_principal_id = @rr AND member_principal_id = @m) THROW 51001, N'the identity {0} is not in its replacement role {1} -- nothing is removed', 1;" -f "$($first.Member)".Replace("'", "''"), $first.Replacement))
        foreach ($x in $g.Group) {
            if ($n.BroadRoles -notcontains $x.Role) { throw ('not a broad role: {0}' -f $x.Role) }
            [void]$sb.AppendLine(("SET @r = DATABASE_PRINCIPAL_ID(N'{0}');" -f $x.Role))
            [void]$sb.AppendLine(("IF @r IS NOT NULL AND EXISTS (SELECT 1 FROM sys.database_role_members WHERE role_principal_id = @r AND member_principal_id = @m) BEGIN SET @s = N'ALTER ROLE [{0}] DROP MEMBER ' + QUOTENAME(USER_NAME(@m)); EXEC (@s); END" -f $x.Role))
        }
    }
    [void]$sb.AppendLine('COMMIT TRANSACTION;')
    [void]$sb.AppendLine('END TRY')
    [void]$sb.AppendLine('BEGIN CATCH IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION; THROW; END CATCH')
    $sb.ToString()
}

function Get-SISqlLpAddBackSql {
    <# PURE. RULE 4 (off): each membership (@{ Sid; Role; Member }) added where it is not there -- ONE transaction; the roles
       only the broad ones of the list. #>
    param([object[]]$Items = @())
    $n = Get-SISqlLpNames
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('SET NOCOUNT ON; SET XACT_ABORT ON;')
    [void]$sb.AppendLine('DECLARE @m int, @r int, @s nvarchar(800);')
    [void]$sb.AppendLine('BEGIN TRANSACTION;')
    foreach ($x in @($Items | Where-Object { $_ })) {
        if ($x.Sid -notmatch '^0x[0-9A-Fa-f]{2,170}$') { throw ('not a SID: {0}' -f $x.Sid) }
        if ($n.BroadRoles -notcontains ([string]$x.Role).ToLowerInvariant()) { throw ('not a broad role: {0}' -f $x.Role) }
        [void]$sb.AppendLine(("SET @m = (SELECT principal_id FROM sys.database_principals WHERE sid = {0} AND [type] NOT IN ('R', 'X', 'G') AND principal_id > 4); SET @r = DATABASE_PRINCIPAL_ID(N'{1}');" -f $x.Sid, ([string]$x.Role).ToLowerInvariant()))
        [void]$sb.AppendLine(("IF @m IS NOT NULL AND @r IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.database_role_members WHERE role_principal_id = @r AND member_principal_id = @m) BEGIN SET @s = N'ALTER ROLE [{0}] ADD MEMBER ' + QUOTENAME(USER_NAME(@m)); EXEC (@s); END" -f ([string]$x.Role).ToLowerInvariant()))
    }
    [void]$sb.AppendLine('COMMIT TRANSACTION;')
    $sb.ToString()
}

function New-SISqlLpRecordValue {
    <# PURE. The run record: compact JSON { mode, state, at, run, n, hash, list, why }, at most 400 characters (why cut first). #>
    param([string]$Mode = '', [Parameter(Mandatory)][string]$State, [string]$Run = '', [int]$Count = 0, [string]$Hash = '', [string]$List = '', [string]$Why = '',
          [datetime]$NowUtc = [datetime]::UtcNow)
    $max = (Get-SISqlLpNames).RecordMax
    $o = [ordered]@{ mode = $Mode; state = $State; at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Run) { $o.run = $Run }
    $o.n = $Count
    if ($Hash) { $o.hash = $Hash }
    $l = [regex]::Replace("$List", '[\x00-\x1F]', ' '); if ($l.Length -gt 160) { $l = $l.Substring(0, 157) + '...' }
    if ($l) { $o.list = $l }
    $w = [regex]::Replace([regex]::Replace("$Why", '[\x00-\x1F]', ' '), '\s+', ' ').Trim()
    $room = $max - (ConvertTo-Json -InputObject $o -Compress).Length - 12
    if ($w.Length -gt $room) { $w = $(if ($room -gt 3) { $w.Substring(0, $room - 3).TrimEnd() + '...' } else { '' }) }
    if ($w) { $o.why = $w }
    $v = ConvertTo-Json -InputObject $o -Compress
    while ($v.Length -gt $max -and $o.Contains('why') -and ([string]$o.why).Length -gt 16) { $o.why = ([string]$o.why).Substring(0, ([string]$o.why).Length - 13) + '...'; $v = ConvertTo-Json -InputObject $o -Compress }
    $v
}

function Invoke-SIDbInitSqlLeastPrivilege {
    <#
        THE JOB'S STEP (Invoke-SIDbInit, after its batches -- the replacement grants were just applied -- and before its
        read-back). -DbInput: Read-SIDbInitInput (SqlLp = plan | apply | off; SqlLpNames; SqlLpReason); -Sql: the job's seam;
        -Required: this release's engine inventory (Get-SIEngineRequiredPermission; empty = the engine cannot be proven
        ready: nothing removed). -Ready: a test seam { param($Component, $UserName) } -> @{ Ok; Lines; Grants }.
        -AfterChange: a test seam run right after the change (to simulate a side effect that drops a grant).
        Pro database only (the identity ledger has no least-privilege role). NEVER throws; never part of the job's verdict.
        Returns @{ State; Lines; Record }.
    #>
    param([Parameter(Mandatory)]$DbInput, [Parameter(Mandatory)][scriptblock]$Sql, [object[]]$Required = @(), [scriptblock]$Ready, [scriptblock]$AfterChange,
          [string[]]$AllowedTypes = @('E'), [scriptblock]$Now = { [datetime]::UtcNow })
    $n = Get-SISqlLpNames
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param($m) $lines.Add([string]$m) }
    $mode = [string](Get-SIDbInitProp $DbInput @('SqlLp'))
    $pro = [string]$DbInput.Database
    $run = [string]$DbInput.Run
    $err = { param($e) (([string]$e.Exception.Message) -split "`n")[0].Trim() }
    $reason = [string](Get-SIDbInitProp $DbInput @('SqlLpReason'))
    $writeRow = {
        param([string]$Name, [string]$Value)
        try { $null = & $Sql $pro (Get-SIDbInitRecordSql -Name $Name) @{ Value = $Value; Version = $null; By = 'caj-si-dbinit' } 'nonquery' }
        catch { & $say ('WARNING: SQL least privilege: the row {0} could not be written: {1}' -f $Name, (& $err $_)) }
    }
    $finish = {
        param([string]$State, [int]$Count = 0, [string]$Hash = '', [string]$List = '', [string]$Why = '')
        $why2 = if ($reason) { ('{0}{1}asked: {2}' -f $Why, $(if ($Why) { '; ' } else { '' }), $reason) } else { $Why }
        $v = New-SISqlLpRecordValue -Mode $mode -State $State -Run $run -Count $Count -Hash $Hash -List $List -Why $why2 -NowUtc (& $Now)
        & $writeRow $n.Record $v
        & $say ('SQL least privilege recorded: {0}' -f $v)
        [pscustomobject]@{ State = $State; Lines = $lines.ToArray(); Record = $v }
    }
    if ($mode -notin 'plan', 'apply', 'off') { return [pscustomobject]@{ State = 'none'; Lines = @(); Record = '' } }
    $snap = { ConvertFrom-SISqlLpSnapshot -Rows @(& $Sql $pro (Get-SISqlLpSnapshotSql) @{} 'rows' | ForEach-Object { $_ }) }
    $readRow = { param([string]$Name) try { [string](Get-SIDbInitProp (@(& $Sql $pro (Get-SIDbInitRecordReadSql -Name $Name) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1) @('Value')) } catch { '' } }
    if (-not $Ready) {
        $Ready = {
            param([string]$Component, [string]$UserName)
            if ($Component -ne 'engine') { return [pscustomobject]@{ Ok = $false; Lines = @('no least-privilege role for this component'); Grants = 0 } }
            if (-not (Get-Command -Name Test-SIEngineCutoverReady -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Ok = $false; Lines = @('this package carries no engine grant list'); Grants = 0 } }
            if (-not @($Required).Count) { return [pscustomobject]@{ Ok = $false; Lines = @('the release''s engine code inventory could not be read -- the role cannot be proven to cover it'); Grants = 0 } }
            # #1430: which of the release's tables this database has (a package before #1430 reads as before)
            $sa = @{}; if (Get-Command -Name Get-SIEngineRequiredObjects -ErrorAction SilentlyContinue) { $sa.Objects = Get-SIEngineRequiredObjects -Required $Required }
            $st = ConvertFrom-SIEngineAccessRows -Rows @(& $Sql $pro (Get-SIEngineAccessStateSql -UserName $UserName @sa) @{} 'rows' | ForEach-Object { $_ })
            $t = Test-SIEngineCutoverReady -State $st -Required $Required -UserName $UserName
            $tn = @(); if ($t.PSObject.Properties['Notes']) { $tn = @($t.Notes | Where-Object { $_ }) }
            [pscustomobject]@{ Ok = [bool]$t.Ok; Lines = @($t.Lines); Grants = (@($st.Granted).Count + @($st.Denied).Count); Notes = $tn }
        }
    }
    try {
        & $say ('SQL least privilege ({0}) in {1} -- only db_datareader / db_datawriter / db_ddladmin of SecurityInsight''s own job identities, only after their replacement role reads back' -f $mode, $pro)
        $before = & $snap
        # who is NEVER touched: the Invardia Support app (recorded on the install, named to this run) and the job itself
        $neverSids = New-Object System.Collections.Generic.List[string]
        $supRec = (& $readRow 'SupportApp').Trim()
        foreach ($c in @($supRec, [string](Get-SIDbInitProp $DbInput @('StandingOff')), [string](Get-SIDbInitProp $DbInput @('Support', 'ClientId')), [string]$DbInput.MiClientId)) {
            $g = [guid]::Empty; if ($c -and [guid]::TryParse($c.Trim(), [ref]$g) -and $g -ne [guid]::Empty) { $neverSids.Add((Get-SISqlLpSid -ClientId $g.ToString())) }
        }
        $principals = @($DbInput.Principals | Where-Object { $_ })
        $readyBy = @{}
        foreach ($m in @(Get-SISqlLpModel)) {
            $p = @($principals | Where-Object { $_.Component -eq $m.Component })[0]
            if (-not $p) { continue }
            $sid = if ($p.PSObject.Properties['Sid'] -and $p.Sid) { [string]$p.Sid } else { Get-SISqlLpSid -ClientId ([string]$p.ClientId) }
            $dbName = @($before.Members | Where-Object { $_.Sid -ieq $sid } | ForEach-Object Member | Select-Object -First 1)[0]
            if (-not $dbName) { $dbName = [string]$p.Name }
            $readyBy[$m.Component] = & $Ready $m.Component $dbName
            # (never $n here: it holds Get-SISqlLpNames -- the record names every later step writes and reads)
            if ($readyBy[$m.Component] -and $readyBy[$m.Component].PSObject.Properties['Notes']) { foreach ($readyNote in @($readyBy[$m.Component].Notes | Where-Object { $_ })) { & $say ('  {0}: {1}' -f $m.Component, $readyNote) } }
        }
        $plan = Get-SISqlLpPlan -Before $before -Principals $principals -AllowedNames @($DbInput.SqlLpNames) -NeverSids $neverSids.ToArray() -Ready $readyBy -AllowedTypes $AllowedTypes
        $list = Format-SISqlLpList -Items $plan.Removals
        foreach ($x in $plan.Removals) { & $say ('  {0}: {1} ({2}) in {3} -- replaced by {4}' -f $(if ($mode -eq 'plan') { 'WOULD REMOVE' } elseif ($mode -eq 'apply') { 'to remove' } else { 'removable' }), $x.Member, $x.Component, $x.Role, $x.Replacement) }
        foreach ($c in @($readyBy.Keys)) { $r = $readyBy[$c]; & $say ('  the replacement of {0}: {1}{2}' -f $c, $(if ($r.Ok) { 'ready -- its role holds {0} grant(s) / deny(s), read back; every statement of this release allowed' -f $r.Grants } else { 'NOT ready' }), $(if (-not $r.Ok -and @($r.Lines).Count) { ' (' + ((@($r.Lines) | Select-Object -First 2) -join '; ') + ')' } else { '' })) }
        foreach ($l in @($plan.Kept) + @($plan.NotReady) + @($plan.Never)) { & $say ('  ' + $l) }

        if ($mode -eq 'plan') {
            $pv = ConvertTo-Json -Compress -InputObject ([ordered]@{ hash = $plan.Hash; at = (& $Now).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); run = $run; n = @($plan.Removals).Count; list = $(if ($list.Length -gt 200) { $list.Substring(0, 197) + '...' } else { $list }) })
            & $writeRow $n.PlanRecord $pv
            return (& $finish 'planned' @($plan.Removals).Count $plan.Hash $list $(if (@($plan.NotReady).Count) { (@($plan.NotReady) | Select-Object -First 1) } else { '' }))
        }

        if ($mode -eq 'off') {
            # RULE 4: what this path removed (its own row) + the engine's db_datareader / db_datawriter of today's model
            $items = New-Object System.Collections.Generic.List[object]
            $eng = @($principals | Where-Object { $_.Component -eq 'engine' })[0]
            if ($eng) {
                $esid = if ($eng.PSObject.Properties['Sid'] -and $eng.Sid) { [string]$eng.Sid } else { Get-SISqlLpSid -ClientId ([string]$eng.ClientId) }
                foreach ($r in 'db_datareader', 'db_datawriter') { $items.Add([pscustomobject]@{ Sid = $esid; Role = $r; Member = [string]$eng.Name; Key = (Get-SISqlLpMemberKey -Role $r -Sid $esid) }) }
            }
            $rv = & $readRow $n.RemovedRecord
            if ($rv) {
                try { foreach ($x in @(($rv | ConvertFrom-Json -ErrorAction Stop).items)) {
                    $s = [string]$x.sid; $ro = ([string]$x.role).ToLowerInvariant()
                    $sNorm = ($s.ToUpperInvariant() -replace '^0X', '0x')
                    if ($s -match '^0x[0-9A-Fa-f]{2,170}$' -and $n.BroadRoles -contains $ro -and -not $neverSids.Contains($sNorm) -and -not @($items | Where-Object { $_.Key -eq (Get-SISqlLpMemberKey -Role $ro -Sid $s) }).Count) {
                        $items.Add([pscustomobject]@{ Sid = $s; Role = $ro; Member = [string]$x.member; Key = (Get-SISqlLpMemberKey -Role $ro -Sid $s) })
                    }
                } } catch { & $say ('  the row {0} could not be read -- only the engine''s db_datareader / db_datawriter are put back' -f $n.RemovedRecord) }
            }
            if (-not $items.Count) { return (& $finish 'back' 0 '' '' 'no identity of the list in the input') }
            try { $null = & $Sql $pro (Get-SISqlLpAddBackSql -Items $items.ToArray()) @{} 'nonquery' }
            catch { return (& $finish 'failed' 0 '' (Format-SISqlLpList -Items $items.ToArray()) ('the memberships could not be put back: ' + (& $err $_))) }
            $after = & $snap
            $d = Compare-SISqlLpSnapshot -Before $before -After $after
            $missing = @($items | Where-Object { -not $after.Keys.Contains($_.Key) })
            if ($d.Lost.Count) {
                $rs = Get-SISqlLpRestoreStatements -Items $d.Lost
                foreach ($st in $rs.Statements) { try { $null = & $Sql $pro $st.Sql @{} 'nonquery' } catch { & $say ('  restore failed: {0}: {1}' -f (Format-SISqlLpItem $st.Item), (& $err $_)) } }
                $after2 = & $snap; $d2 = Compare-SISqlLpSnapshot -Before $before -After $after2
                return (& $finish $(if ($d2.Lost.Count) { 'restore-incomplete' } else { 'restored' }) 0 '' '' ('{0} item(s) disappeared while the memberships were put back: {1}' -f $d.Lost.Count, ((@($d.Lost) | Select-Object -First 2 | ForEach-Object { Format-SISqlLpItem $_ }) -join '; ')))
            }
            if ($missing.Count) { return (& $finish 'failed' 0 '' (Format-SISqlLpList -Items $missing) 'put back but not read back') }
            foreach ($x in $items) { & $say ('  read back: {0} in {1}' -f $x.Member, $x.Role) }
            & $writeRow $n.RemovedRecord (ConvertTo-Json -Compress -InputObject ([ordered]@{ items = @(); at = (& $Now).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); run = $run }))
            return (& $finish 'back' $items.Count '' (Format-SISqlLpList -Items $items.ToArray()) '')
        }

        # ---- apply ----
        if (-not @($plan.Removals).Count) {
            $anyBroad = @($plan.NotReady).Count
            if ($anyBroad) { return (& $finish 'not-ready' 0 $plan.Hash '' (@($plan.NotReady) | Select-Object -First 1)) }
            $notReadyRole = @($readyBy.Keys | Where-Object { -not $readyBy[$_].Ok })
            if ($notReadyRole.Count) { return (& $finish 'not-ready' 0 $plan.Hash '' ('the replacement of {0} is not ready' -f ($notReadyRole -join ', '))) }
            return (& $finish 'already' 0 $plan.Hash '' '')
        }
        $pv = & $readRow $n.PlanRecord
        $prev = $null; if ($pv) { try { $prev = $pv | ConvertFrom-Json -ErrorAction Stop } catch { $prev = $null } }
        if (-not $prev -or -not $prev.PSObject.Properties['hash']) { return (& $finish 'refused' 0 $plan.Hash $list ('no plan has run for this install -- set {0}=plan first, read the list, then apply' -f $n.Variable)) }
        if ([string]$prev.hash -cne $plan.Hash) { return (& $finish 'refused' 0 $plan.Hash $list ('the state is not the one planned at {0} (plan {1}, now {2}) -- set {3}=plan again' -f [string]$prev.at, [string]$prev.hash, $plan.Hash, $n.Variable)) }
        $keys = @($plan.Removals | ForEach-Object Key)
        $changeErr = ''
        try { $null = & $Sql $pro (Get-SISqlLpRemoveSql -Removals $plan.Removals) @{} 'nonquery' } catch { $changeErr = & $err $_ }
        if ($AfterChange) { try { & $AfterChange } catch { } }
        $after = & $snap
        $d = Compare-SISqlLpSnapshot -Before $before -After $after -Planned $keys
        # per identity: the broad role gone AND its replacement still ready (read back)
        $readyAfter = @{}
        foreach ($c in @($plan.Removals | ForEach-Object Component | Select-Object -Unique)) {
            $x = @($plan.Removals | Where-Object Component -eq $c)[0]
            $readyAfter[$c] = & $Ready $c $x.Member
        }
        $badAfter = @($readyAfter.Keys | Where-Object { -not $readyAfter[$_].Ok })
        if (-not $changeErr -and -not $d.Lost.Count -and -not $d.NotRemoved.Count -and -not $badAfter.Count) {
            foreach ($c in @($readyAfter.Keys)) {
                $gone = @($d.Removed | Where-Object { $k = $_.Key; @($plan.Removals | Where-Object { $_.Component -eq $c -and $_.Key -eq $k }).Count })
                & $say ('  read back: {0} -- {1} gone; its role {2} holds {3} grant(s) / deny(s), every statement of this release allowed' -f $c, ((@($gone | ForEach-Object Role) -join ', ')), @($plan.Removals | Where-Object Component -eq $c)[0].Replacement, $readyAfter[$c].Grants)
            }
            $items = @($plan.Removals | ForEach-Object { [ordered]@{ sid = $_.Sid; role = $_.Role; member = $_.Member } })
            $prevRemoved = & $readRow $n.RemovedRecord
            try { if ($prevRemoved) { foreach ($x in @(($prevRemoved | ConvertFrom-Json -ErrorAction Stop).items)) { if (-not @($items | Where-Object { $_.sid -eq [string]$x.sid -and $_.role -eq [string]$x.role }).Count) { $items += [ordered]@{ sid = [string]$x.sid; role = [string]$x.role; member = [string]$x.member } } } } } catch { }
            & $writeRow $n.RemovedRecord (ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ items = @($items); at = (& $Now).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); run = $run }))
            return (& $finish 'applied' @($plan.Removals).Count $plan.Hash $list '')
        }
        # RESTORE AT ONCE: everything that is gone -- the lost items AND the planned removals -- back as it was BEFORE
        $why = New-Object System.Collections.Generic.List[string]
        if ($changeErr) { $why.Add('the removal failed (rolled back): ' + $changeErr) }
        if ($d.Lost.Count) { $why.Add(('{0} item(s) disappeared that were not planned: {1}' -f $d.Lost.Count, ((@($d.Lost) | Select-Object -First 2 | ForEach-Object { Format-SISqlLpItem $_ }) -join '; '))) }
        if ($d.NotRemoved.Count) { $why.Add(('{0} planned membership(s) still there' -f $d.NotRemoved.Count)) }
        if ($badAfter.Count) { $why.Add(('the replacement of {0} did not read back after the change' -f ($badAfter -join ', '))) }
        foreach ($l in $why) { & $say ('  LOSS / FAILURE: ' + $l) }
        $rs = Get-SISqlLpRestoreStatements -Items (@($d.Lost) + @($d.Removed))
        foreach ($st in $rs.Statements) {
            try { $null = & $Sql $pro $st.Sql @{} 'nonquery'; & $say ('  restored: {0}' -f (Format-SISqlLpItem $st.Item)) }
            catch { & $say ('  restore FAILED: {0}: {1}' -f (Format-SISqlLpItem $st.Item), (& $err $_)) }
        }
        foreach ($u in $rs.Unrestorable) { & $say ('  cannot be restored by a statement: {0}' -f (Format-SISqlLpItem $u)) }
        $after2 = & $snap
        $d2 = Compare-SISqlLpSnapshot -Before $before -After $after2
        if ($d2.Lost.Count) {
            foreach ($x in $d2.Lost) { & $say ('  STILL MISSING after the restore: {0}' -f (Format-SISqlLpItem $x)) }
            return (& $finish 'restore-incomplete' 0 $plan.Hash $list (($why.ToArray() -join '; ') + ('; still missing: {0}' -f ((@($d2.Lost) | Select-Object -First 2 | ForEach-Object { Format-SISqlLpItem $_ }) -join '; '))))
        }
        & $say '  read back: every permission and membership is as it was before the change'
        & $finish 'restored' 0 $plan.Hash $list ($why.ToArray() -join '; ')
    } catch {
        & $finish 'failed' 0 '' '' (& $err $_)
    }
}
