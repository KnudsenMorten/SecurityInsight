#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- identity role + permission fetcher.

    Bulk-fetches Entra role assignments, PIM eligible schedules, SP application
    permissions, and SP delegated permissions via Microsoft Graph REST.
    Per-asset Graph calls are too slow at scale (5-10 calls x 800 assets =
    minutes); this module pulls tenant-wide once and buckets by principalId.

    Used by Get-DiscoveryFromEntraServicePrincipals.ps1 +
    Get-DiscoveryFromEntraUsers.ps1 and
    Invoke-IdentityCatalogClassify.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
if (-not (Get-Command -Name Read-SILaParts -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-LaParts.ps1') }

. (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth\Get-SIGraphToken.ps1')
# the run's outcome notes (a role read that was not complete makes the run partial for the role facts -- #899)
if (-not (Get-Command -Name Add-SIEntraRolesPartialNote -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-RunOutcome.ps1') }

# per-process bulk-fetch cache. The Entra User + Entra SP
# discoveries each ran the same 6 bulk fetches (~8 Graph + 1 LA + N Az
# subscription calls), wasting minutes. Cache-once-per-process here so the
# second discovery reuses the first's results.
# guard with Get-Variable so dot-sourcing this file a second time
# doesn't WIPE the cache populated by the first discovery's run.
if (-not (Get-Variable -Name _SICache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SICache = @{}
}

function Reset-SIIdentityFetcherCache {
    # Clear all bulk-fetch caches. Use between Run-AssetProfiling.ps1 invocations
    # in the same PowerShell session if you want fresh data.
    $script:_SICache = @{}
    $global:SI_EntraRoleReadState = $null
    Write-SIInfo '[perms] cache cleared.'
}

# ---------------------------------------------------------------------------------------------------------------------
# THE ENTRA ROLE READ'S COMPLETENESS (shadow-admin guard). Every read that decides "this principal holds NO Entra role"
# records whether it completed: the role definitions, the permanent assignments, the PIM-eligible schedules, the
# role-assigned groups' types, their transitive members and PIM for Groups. Run-level ($global:SI_EntraRoleReadState,
# the same lifetime as the cached maps); the identity discovery also stamps the verdict on every user it builds
# (ENTRA_RoleReadComplete -> the profile row's Properties.collect.entra.RoleReadComplete) so a process that only builds
# record parts (a run collected in parts) can still tell. A read that failed, stopped part-way or never ran = NOT
# complete: "no role" is then unknown, never a fact (si_is_shadow_admin stays null).
# ---------------------------------------------------------------------------------------------------------------------


function Set-SIEntraRoleReadPart {
    <# How one of the role reads went this run. A part read twice is complete only when every read was. #>
    param([Parameter(Mandatory)][string]$Part, [bool]$Complete = $true, [string]$ErrorText = '')
    if ($null -eq $global:SI_EntraRoleReadState) { $global:SI_EntraRoleReadState = @{} }
    $prev = $global:SI_EntraRoleReadState[$Part]
    if ($prev) { $Complete = [bool]$prev.Complete -and $Complete; if (-not $ErrorText) { $ErrorText = [string]$prev.Error } }
    $global:SI_EntraRoleReadState[$Part] = [pscustomobject]@{ Complete = [bool]$Complete; Error = [string]$ErrorText }
}

function Test-SIEntraRoleReadComplete {
    <# PURE. $true only when EVERY role read recorded that it completed; a part not recorded (never ran, state lost) = not complete. #>
    param($State = $global:SI_EntraRoleReadState, [string[]]$Parts)
    # the list is spelled out here (a script variable read from another scope would be empty -- and "no part" = "all done")
    # an unbound [string[]] is $null, and @($null).Count is 1 -- so test for $null itself, or no part would be checked at all
    if ($null -eq $Parts -or $Parts.Count -eq 0) { $Parts = @('Definitions', 'Permanent', 'Eligible', 'GroupTypes', 'GroupMembers', 'PimForGroups') }
    if ($null -eq $State) { return $false }
    foreach ($p in $Parts) {
        $s = $null
        if ($State -is [System.Collections.IDictionary]) { $s = $State[$p] } else { $pp = $State.PSObject.Properties[$p]; if ($pp) { $s = $pp.Value } }
        if ($null -eq $s -or -not [bool]$s.Complete) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------------------------------------------------
# #899 THE ROLE READ IS CHECKED, AND "NOT READ" IS NEVER "NO ROLE". Measured on the internal install (2026-10-23/25):
# GET /roleManagement/directory/roleAssignments answered HTTP 200 and still came back SHORT in 4 of 9 full reads -- pages
# 100,100,100,56 (356 rows, 79 principals) instead of 100,100,100,63 (363 rows, 105 principals), with some rows TWICE and
# others missing. The read was marked complete, six service principals lost their permanent roles in the CI, and a report
# lost 6 of its 15 rows. So:
#   1. every role list (permanent, eligible) is read TWICE, $top=999, keyed by assignment id: accepted only when two reads
#      have no duplicate id and the same ids. Otherwise up to three more reads with a pause; then one filtered read per role
#      definition (roleDefinitionId eq X -- small answers, one page each), unioned by id. Still not shown: NOT complete.
#   2. a read that is not complete never empties a role list: every principal keeps the roles of its STORED record
#      (sidata.CiRecord -- roles, eligible roles, scopes), joined with what this run did see. The tier, the risk factors and
#      the CI follow from the same lists. The run is partial for the role facts (Add-SIEntraRolesPartialNote), and Risk
#      Analysis then gives the reports that read role lists or shadow admin the verdict NotComplete -- nothing of them closes.
#      When the stored roles cannot be read either, the discovery fails as before (the source stays on its last good collection).
# ---------------------------------------------------------------------------------------------------------------------
if (-not (Get-Variable -Name SIRoleReadPauseSeconds -Scope Script -ErrorAction SilentlyContinue)) { $script:SIRoleReadPauseSeconds = @(5, 15, 30) }

function Get-SIGraphRowKey {
    <# PURE. The key one Graph list row is found by: its id; a row without one by principal|role|scope (lower case). #>
    param($Row)
    if ($null -eq $Row) { return '' }
    $p = $Row.PSObject.Properties['id']
    if ($p -and $p.Value) { return ([string]$p.Value).Trim().ToLowerInvariant() }
    $g = { param($n) $x = $Row.PSObject.Properties[$n]; if ($x -and $null -ne $x.Value) { ([string]$x.Value).Trim().ToLowerInvariant() } else { '' } }
    'nokey:{0}|{1}|{2}' -f (& $g 'principalId'), (& $g 'roleDefinitionId'), (& $g 'directoryScopeId')
}

function Read-SIGraphIdSet {
    <#
        ONE full paged read of a Graph list, every row keyed by its id (Get-SIGraphRowKey). Returns @{ Url; Pages; Rows (rows
        answered); Ids (the distinct ids, a set); Duplicates (rows whose id was already in the read); DuplicateIds; ByKey (the
        first row of each id) }. A query that Graph refuses because of $top (HTTP 400) is asked once more without it. Any other
        failure throws, as the pager does.
    #>
    param([Parameter(Mandatory)][string]$RelativeUrl, [Parameter(Mandatory)][string]$Token)
    $st = @{ Pages = 0; Rows = 0; Duplicates = 0 }
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $dupIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $byKey = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $onPage = {
        param($PageRows)
        $st.Pages++
        foreach ($r in @($PageRows)) {
            if ($null -eq $r) { continue }
            $st.Rows++
            $k = Get-SIGraphRowKey $r
            if ($ids.Add($k)) { $byKey[$k] = $r } else { $st.Duplicates++; [void]$dupIds.Add($k) }
        }
    }
    $url = $RelativeUrl
    try { $ret = Invoke-SIGraphPaged -RelativeUrl $url -Token $Token -OnPage $onPage }
    catch {
        $status = 0; try { $status = Get-SIGraphHttpStatus -ErrorRecord $_ } catch { }
        if ($status -ne 400 -or $url -notmatch '[?&]\$top=') { throw }
        $url = ($url -replace '([?&])\$top=\d+&?', '$1') -replace '[?&]$', ''
        $st.Pages = 0; $st.Rows = 0; $st.Duplicates = 0; $ids.Clear(); $dupIds.Clear(); $byKey.Clear()
        Write-SIInfo ('[perms] {0}: Graph refused $top -- read without it' -f $RelativeUrl)
        $ret = Invoke-SIGraphPaged -RelativeUrl $url -Token $Token -OnPage $onPage
    }
    # a pager (or a test seam) that hands the rows back instead of page by page is read the same
    if ($null -ne $ret -and @($ret).Count -gt 0) { & $onPage @($ret) }
    [pscustomobject]@{ Url = $url; Pages = [int]$st.Pages; Rows = [int]$st.Rows; Ids = $ids; Duplicates = [int]$st.Duplicates; DuplicateIds = @($dupIds); ByKey = $byKey }
}

function Test-SIIdSetEqual {
    <# PURE. Do two id sets hold the same ids? #>
    param($A, $B)
    if ($null -eq $A -or $null -eq $B -or $A.Count -ne $B.Count) { return $false }
    foreach ($k in $A) { if (-not $B.Contains($k)) { return $false } }
    $true
}

function Format-SIIdSetRead {
    <# PURE. One read for the step log: "4 page(s), 363 row(s), 363 id(s), 0 duplicate(s)" (+ the duplicate ids). #>
    param($Read)
    $t = '{0} page(s), {1} row(s), {2} id(s), {3} duplicate(s)' -f $Read.Pages, $Read.Rows, $Read.Ids.Count, $Read.Duplicates
    if ($Read.Duplicates -gt 0) { $t += (' [{0}]' -f ((@($Read.DuplicateIds) | Sort-Object) -join ', ')) }
    $t
}

function Read-SIEntraRoleSetChecked {
    <#
        #899: a role list read until two reads AGREE. -RelativeUrl is the list without a query ('/roleManagement/directory/
        roleAssignments' or '/roleManagement/directory/roleEligibilitySchedules'); it is asked with $top=999 and -Select.
          accepted   two full reads, each without a duplicate id, holding the same ids (the second read is the check)
          re-read    up to three more full reads, pausing $script:SIRoleReadPauseSeconds; any two clean equal reads win
          per role   one read per role definition (-RoleDefinitionIds and every role id the full reads saw), filtered
                     roleDefinitionId eq X, unioned by id: accepted when no answer has a duplicate id and the union holds
                     every id a full read saw
          otherwise  NOT complete -- Rows are then every row any read saw (each one is a real assignment; what is missing is
                     unknown)
        Returns @{ Complete; How (full | re-read | per-role | not-complete); Rows; Count; Reads (the full reads); Line (the
        step-log line) }. A read that throws is not caught here: the caller fails as before.
    #>
    param([Parameter(Mandatory)][string]$RelativeUrl, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Label,
          [AllowEmptyCollection()][string[]]$RoleDefinitionIds = @(), [string]$Select = 'id,principalId,roleDefinitionId,directoryScopeId')
    # LIST KEPT: the assignment's id, holder, role and scope -- what the role maps are built from
    $fullUrl = '{0}?$top=999&$select={1}' -f $RelativeUrl, $Select
    $reads = New-Object System.Collections.Generic.List[object]
    $union = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $pauses = @($script:SIRoleReadPauseSeconds)
    $accepted = $null
    $maxReads = 2 + $pauses.Count
    for ($i = 0; $i -lt $maxReads -and $null -eq $accepted; $i++) {
        if ($i -ge 2) { $s = [int]$pauses[$i - 2]; if ($s -gt 0) { Start-Sleep -Seconds $s } }
        $r = Read-SIGraphIdSet -RelativeUrl $fullUrl -Token $Token
        foreach ($k in $r.ByKey.Keys) { if (-not $union.ContainsKey($k)) { $union[$k] = $r.ByKey[$k] } }
        if ($r.Duplicates -eq 0) {
            foreach ($p in $reads) { if ($p.Duplicates -eq 0 -and (Test-SIIdSetEqual $p.Ids $r.Ids)) { $accepted = $r; break } }
        }
        $reads.Add($r)
    }
    $readText = (@(for ($i = 0; $i -lt $reads.Count; $i++) { 'read {0}: {1}' -f ($i + 1), (Format-SIIdSetRead $reads[$i]) }) -join '; ')
    if ($null -ne $accepted) {
        $how = $(if ($reads.Count -le 2) { 'full' } else { 're-read' })
        $rows = @($accepted.ByKey.Values)
        $line = '[perms] {0}: {1} -- accepted ({2} reads agree): {3} assignment(s)' -f $Label, $readText, $(if ($how -eq 'full') { 'two' } else { 'two of ' + $reads.Count }), $rows.Count
        return [pscustomobject]@{ Complete = $true; How = $how; Rows = $rows; Count = $rows.Count; Reads = $reads.ToArray(); Line = $line }
    }
    # the cross-check: one small read per role definition, unioned by id
    $roleIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($RoleDefinitionIds)) { if ($x) { [void]$roleIds.Add([string]$x) } }
    foreach ($v in $union.Values) { $rp = $v.PSObject.Properties['roleDefinitionId']; if ($rp -and $rp.Value) { [void]$roleIds.Add([string]$rp.Value) } }
    $perRole = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $prDup = 0; $prReads = 0
    foreach ($rid in @($roleIds | Sort-Object)) {
        $f = [uri]::EscapeDataString(("roleDefinitionId eq '{0}'" -f $rid))
        # LIST KEPT: the same fields as the full read
        $pr = Read-SIGraphIdSet -RelativeUrl ('{0}?$filter={1}&$top=999&$select={2}' -f $RelativeUrl, $f, $Select) -Token $Token
        $prReads++
        $prDup += $pr.Duplicates
        foreach ($k in $pr.ByKey.Keys) { if (-not $perRole.ContainsKey($k)) { $perRole[$k] = $pr.ByKey[$k] } }
    }
    $missing = 0
    foreach ($k in $union.Keys) { if (-not $perRole.ContainsKey($k)) { $missing++ } }
    $prText = '{0} per-role read(s): {1} id(s), {2} duplicate(s), {3} id(s) a full read saw are not in them' -f $prReads, $perRole.Count, $prDup, $missing
    if ($prReads -gt 0 -and $prDup -eq 0 -and $missing -eq 0) {
        $rows = @($perRole.Values)
        $line = '[perms] {0}: {1} -- the full reads did not agree; {2} -- accepted from the per-role reads: {3} assignment(s)' -f $Label, $readText, $prText, $rows.Count
        return [pscustomobject]@{ Complete = $true; How = 'per-role'; Rows = $rows; Count = $rows.Count; Reads = $reads.ToArray(); Line = $line }
    }
    foreach ($k in $perRole.Keys) { if (-not $union.ContainsKey($k)) { $union[$k] = $perRole[$k] } }
    $rows = @($union.Values)
    $line = '[perms] {0}: {1} -- the full reads did not agree; {2} -- NOT COMPLETE: {3} assignment(s) seen; every identity keeps its stored roles this run' -f $Label, $readText, $prText, $rows.Count
    [pscustomobject]@{ Complete = $false; How = 'not-complete'; Rows = $rows; Count = $rows.Count; Reads = $reads.ToArray(); Line = $line }
}

function Get-SIStoredEntraRolesSql {
    <# One page of the stored role lists of the Entra identities (sidata.CiRecord), by record key. Read-only. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiRecord') IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(450)) AS RecordKey WHERE 1 = 0; RETURN; END
SELECT TOP (CONVERT(INT, @take)) r.RecordKey,
       JSON_QUERY(d.D, '$.si_entra_roles_permanent') AS PermJ, JSON_VALUE(d.D, '$.si_entra_roles_permanent') AS PermV,
       JSON_QUERY(d.D, '$.si_entra_roles_eligible') AS EligJ, JSON_VALUE(d.D, '$.si_entra_roles_eligible') AS EligV,
       JSON_QUERY(d.D, '$.si_entra_role_scopes') AS ScopesJ
FROM sidata.CiRecord r
CROSS APPLY (SELECT CASE WHEN ISJSON(r.DocJson) = 1 THEN r.DocJson END AS D) d
WHERE r.Provider = N'entra' AND r.RecordType IN (N'user', N'service_principal') AND r.RecordKey > @after
  AND (JSON_QUERY(d.D, '$.si_entra_roles_permanent') IS NOT NULL OR JSON_VALUE(d.D, '$.si_entra_roles_permanent') IS NOT NULL
       OR JSON_QUERY(d.D, '$.si_entra_roles_eligible') IS NOT NULL OR JSON_VALUE(d.D, '$.si_entra_roles_eligible') IS NOT NULL
       OR JSON_QUERY(d.D, '$.si_entra_role_scopes') IS NOT NULL)
ORDER BY r.RecordKey;
'@
}

function ConvertFrom-SIStoredRoleRows {
    <#
        PURE. Rows of Get-SIStoredEntraRolesSql -> -Into (@{ <object id> = @{ Permanent; Eligible; Scopes } }). A list stored as
        a one-item text is read as that item. A scope item goes back to the form the run keeps (roleId, role, scopeId as a
        directory scope id, assignment active | eligible -- an activated one is an active assignment). Returns the last key.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][hashtable]$Into)
    $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $v = $r[$n] } else { $p = $r.PSObject.Properties[$n]; $v = $(if ($p) { $p.Value } else { $null }) }; if ($v -is [System.DBNull]) { $null } else { $v } }
    $list = {
        param($j, $v)
        if ($j) { try { return @(@(ConvertFrom-Json -InputObject ([string]$j)) | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { [string]$_ }) } catch { return @() } }
        if ($v -and "$v".Trim()) { return @([string]$v) }
        @()
    }
    $last = ''
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $key = [string](& $val $r 'RecordKey')
        if (-not $key) { continue }
        $last = $key
        $oid = ($key -replace '^entra:', '').ToLowerInvariant()
        $scopes = New-Object System.Collections.Generic.List[object]
        $sj = & $val $r 'ScopesJ'
        if ($sj) {
            try {
                foreach ($s in @(ConvertFrom-Json -InputObject ([string]$sj))) {
                    if ($null -eq $s -or -not $s.roleId) { continue }
                    $type = [string]$s.scopeType; $id = [string]$s.scopeId
                    $dir = switch ($type) { 'tenant' { '/' } 'administrative unit' { '/administrativeUnits/' + $id } 'object' { '/' + $id } default { $(if ($id) { $id } else { '/' }) } }
                    $asg = $(if ([string]$s.assignment -eq 'eligible') { 'eligible' } else { 'active' })
                    $scopes.Add([pscustomobject]@{ roleId = [string]$s.roleId; role = [string]$s.role; scopeId = $dir; assignment = $asg })
                }
            } catch { }
        }
        $Into[$oid] = @{ Permanent = @(& $list (& $val $r 'PermJ') (& $val $r 'PermV')); Eligible = @(& $list (& $val $r 'EligJ') (& $val $r 'EligV')); Scopes = $scopes.ToArray() }
    }
    $last
}

function Get-SIEntraStoredRoles {
    <#
        The role lists every Entra identity's STORED record holds (sidata.CiRecord), read once per run, a page at a time by
        record key -- only the records that hold a role. Returns @{ Known; ByPrincipal; Error }. Known = $false when no
        database is configured or it cannot be read: then nothing can be kept, and the caller fails as before. -Invoke: the SQL
        seam ({ param($Sql, $Params, $Mode) }, Mode 'rows'); default the install's database (New-SIRecordSqlInvoke).
    #>
    param([scriptblock]$Invoke, [int]$PageSize = 5000)
    if ($script:_SICache -and $script:_SICache.ContainsKey('StoredRoles')) { return $script:_SICache['StoredRoles'] }
    $out = @{ Known = $false; ByPrincipal = @{}; Error = '' }
    try {
        if (-not $Invoke) {
            if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../data-model/SI-RecordSql.ps1') }
            $Invoke = New-SIRecordSqlInvoke
        }
        if (-not $Invoke) { $out.Error = 'no database is configured'; return [pscustomobject]$out }
        $after = ''
        while ($true) {
            $rows = @(& $Invoke (Get-SIStoredEntraRolesSql) @{ take = [string]$PageSize; after = $after } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            if ($rows.Count -eq 0) { break }
            $last = ConvertFrom-SIStoredRoleRows -Rows $rows -Into $out.ByPrincipal
            if (-not $last -or $rows.Count -lt $PageSize) { break }
            $after = $last
        }
        $out.Known = $true
    } catch { $out.Known = $false; $out.Error = [string]$_.Exception.Message; $out.ByPrincipal = @{} }
    $o = [pscustomobject]$out
    if ($o.Known -and $script:_SICache) { $script:_SICache['StoredRoles'] = $o }
    $o
}

function Merge-SIEntraStoredRoles {
    <#
        PURE. A role list that was NOT read completely keeps what the stored records hold: every principal's roles of -Kind
        (Permanent | Eligible) = what this run saw + its stored roles, and its stored assignments of that kind join -Scopes
        (once each: role, scope, assignment). A role the run did see stays; nothing is removed. Returns how many principals
        got a stored role back.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Map, [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Scopes,
          [Parameter(Mandatory)]$Stored, [Parameter(Mandatory)][ValidateSet('Permanent', 'Eligible')][string]$Kind,
          # roles this run saw as something else (an activated role is an eligible role) -- never added back: principal -> names
          [hashtable]$Except = @{})
    $n = 0
    $want = $(if ($Kind -eq 'Eligible') { 'eligible' } else { 'active' })
    # the run's own spelling of a principal id (Graph's), found once per id -- never a scan per principal
    $spell = @{}
    foreach ($k in @($Map.Keys) + @($Scopes.Keys)) { $lk = ([string]$k).ToLowerInvariant(); if (-not $spell.ContainsKey($lk)) { $spell[$lk] = [string]$k } }
    foreach ($oid in @($Stored.ByPrincipal.Keys)) {
        $s = $Stored.ByPrincipal[$oid]
        $key = $oid
        if ($spell.ContainsKey($oid.ToLowerInvariant())) { $key = $spell[$oid.ToLowerInvariant()] }
        $added = $false
        $not = @(); if ($Except.ContainsKey($key)) { $not = @($Except[$key]) }
        foreach ($name in @($s[$Kind])) {
            if (-not $name -or $not -contains $name) { continue }
            if (-not $Map.ContainsKey($key)) { $Map[$key] = New-Object System.Collections.ArrayList }
            if (-not ($Map[$key] -contains $name)) { [void]$Map[$key].Add([string]$name); $added = $true }
        }
        foreach ($e in @($s.Scopes)) {
            if ($null -eq $e -or [string]$e.assignment -ne $want) { continue }
            if (-not $Scopes.ContainsKey($key)) { $Scopes[$key] = New-Object System.Collections.ArrayList }
            $dup = $false
            foreach ($c in @($Scopes[$key])) { if ([string]$c.roleId -eq [string]$e.roleId -and [string]$c.scopeId -eq [string]$e.scopeId -and [string]$c.assignment -eq $want) { $dup = $true; break } }
            if (-not $dup) { [void]$Scopes[$key].Add($e) }
        }
        if ($added) { $n++ }
    }
    $n
}

function Resolve-SIEntraRoleReadIncomplete {
    <#
        #899: a role list (-Kind) that was not read completely. The part is recorded NOT complete; the stored roles are kept
        (Merge-SIEntraStoredRoles) and the run is partial for the role facts (Add-SIEntraRolesPartialNote). When the stored
        roles cannot be read, it THROWS -- the discovery then fails as before and the source stays on its last good
        collection: a role list is never written short as if it were whole.
    #>
    param([Parameter(Mandatory)][ValidateSet('Permanent', 'Eligible')][string]$Kind, [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Map,
          [Parameter(Mandatory)][string]$Why, [hashtable]$Except = @{})
    $what = $(if ($Kind -eq 'Eligible') { 'eligible' } else { 'permanent' })
    Set-SIEntraRoleReadPart -Part $Kind -Complete $false -ErrorText $Why
    $stored = Get-SIEntraStoredRoles
    if (-not $stored.Known) {
        throw ('The Entra {0} role assignments could not be read completely ({1}) and the stored roles could not be read ({2}) -- no role list is written short; the identity collection stays on its last good collection.' -f $what, $Why, $stored.Error)
    }
    if (-not $script:_SICache.ContainsKey('RoleScopes')) { $script:_SICache['RoleScopes'] = @{} }
    $n = Merge-SIEntraStoredRoles -Map $Map -Scopes $script:_SICache['RoleScopes'] -Stored $stored -Kind $Kind -Except $Except
    $msg = 'the Entra {0} role assignments could not be read completely this run ({1}); every identity keeps its stored {0} roles and tier ({2} identities got a stored role back) -- the reports on role lists are not complete this run and nothing of them is closed' -f $what, $Why, $n
    if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn ('[perms] ' + $msg) } else { Write-Warning $msg }
    Add-SIEntraRolesPartialNote -Message $msg
    $script:_SICache['RoleReadPartial'] = (@([string]$script:_SICache['RoleReadPartial'], $msg) | Where-Object { $_ }) -join ' | '
}

function Get-SIEntraRoleReadPartialText {
    <# Why the role facts of this run are partial (#899), '' when they are not: stamped on every identity (ENTRA_RoleReadPartial). #>
    if ($script:_SICache -and $script:_SICache.ContainsKey('RoleReadPartial')) { return [string]$script:_SICache['RoleReadPartial'] }
    ''
}

function New-SIIdDuplicateWatch {
    <#
        #899 (users, service principals, role-holding groups): the ids a list read answered, to see whether any came twice.
        Ids are kept as GUIDs where they are one (16 bytes each). A WARNING in the step log only (Write-SIIdDuplicateWarning):
        no state changes, nothing is marked not complete.
    #>
    param([Parameter(Mandatory)][string]$Label)
    [pscustomobject]@{ Label = $Label; Guids = (New-Object 'System.Collections.Generic.HashSet[guid]'); Other = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase))
                       Duplicates = (New-Object System.Collections.Generic.List[string]); Count = 0 }
}

function Add-SIIdDuplicateWatch {
    <# Adds the ids of one page of rows to the watch (-Watch from New-SIIdDuplicateWatch). Never throws. #>
    param($Watch, [AllowEmptyCollection()][object[]]$Rows = @())
    if ($null -eq $Watch) { return }
    try {
        foreach ($r in @($Rows)) {
            if ($null -eq $r) { continue }
            $p = $r.PSObject.Properties['id']; if (-not $p -or -not $p.Value) { continue }
            $s = ([string]$p.Value).Trim(); $Watch.Count++
            $g = [guid]::Empty
            $new = $(if ([guid]::TryParse($s, [ref]$g)) { $Watch.Guids.Add($g) } else { $Watch.Other.Add($s) })
            if (-not $new) { $Watch.Duplicates.Add($s.ToLowerInvariant()) }
        }
    } catch { }
}

function Write-SIIdDuplicateWarning {
    <# The one WARNING line of a watch that saw an id twice (count + ids); nothing when none did. Returns the line or ''. #>
    param($Watch)
    if ($null -eq $Watch -or $Watch.Duplicates.Count -eq 0) { return '' }
    $ids = @($Watch.Duplicates | Sort-Object -Unique)
    $line = '[perms] {0}: Graph answered {1} row(s) whose id it had already answered ({2} id(s): {3}) -- the read may be inconsistent; it is used as read' -f $Watch.Label, $Watch.Duplicates.Count, $ids.Count, ($ids -join ', ')
    if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $line } else { Write-Warning $line }
    $line
}

function Resolve-SIWorkspaceFromResourceId {
    # Get-AzOperationalInsightsWorkspace -ResourceId is NOT a valid parameter
    # set in PS 5.1's Az.OperationalInsights. Parse the resource ID into
    # subscriptionId / RG / name, set context, then call by RG+Name.
    param([Parameter(Mandatory)][string]$ResourceId)
    if ($ResourceId -notmatch '^/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<name>[^/]+)$') {
        throw "Workspace ResourceId not in expected format: $ResourceId"
    }
    $sub = $matches.sub; $rg = $matches.rg; $name = $matches.name
    $prevCtx = Get-SIAzContext
    if (-not $prevCtx -or $prevCtx.Subscription.Id -ne $sub) {
        Set-SIAzContext -SubscriptionId $sub -WarningAction SilentlyContinue | Out-Null
    }
    return Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
}

function Get-SIGraphHttpStatus {
    # Extract numeric HTTP status from a Graph exception. Returns 0 if the
    # error wasn't an HTTP response (DNS, network reset, etc.).
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $resp = $ErrorRecord.Exception.Response
    if ($resp -and $resp.StatusCode) { return [int]$resp.StatusCode }
    # PS5.1 sometimes wraps WebException differently; fall back to message scrape
    if ($ErrorRecord.Exception.Message -match '\((\d{3})\)') { return [int]$Matches[1] }
    return 0
}

function Invoke-SIGraphPaged {
    # Internal: GET a Graph endpoint with @odata.nextLink paging. Returns
    # combined .value array. Caller passes the full URL minus host (we add it).
    #
    # Retries transient errors (429 throttle, 502/503/504 gateway, network reset)
    # up to 3 attempts with exponential backoff (1s, 2s, 4s). Permanent errors
    # (401/403/404, malformed query) propagate immediately so the caller can
    # decide what to do (e.g. emit a domain-specific warning for "no P2 license").
    param(
        [Parameter(Mandatory)][string]$RelativeUrl,
        [Parameter(Mandatory)][string]$Token,
        # page by page (#702 / customer B 2026-10-15): each page's rows are handed to this block ({ param($PageRows) }) and NOT
        # kept -- the result is then empty. Memory follows a page, not the tenant.
        [scriptblock]$OnPage
    )
    $url = if ($RelativeUrl -match '^https?://') { $RelativeUrl } else { 'https://graph.microsoft.com/v1.0' + $RelativeUrl }
    $all = New-Object System.Collections.ArrayList
    $headers = @{ Authorization = ('Bearer ' + $Token); 'ConsistencyLevel' = 'eventual' }
    # The server's Retry-After, read correctly on BOTH editions (pwsh 7's HttpResponseMessage has no
    # header indexer). Loaded on demand from the shared pager.
    if (-not (Get-Command -Name 'Get-SIRetryAfterSeconds' -ErrorAction SilentlyContinue)) {
        $pagerFile = Join-Path $PSScriptRoot 'Invoke-SIPagedRest.ps1'
        if (Test-Path -LiteralPath $pagerFile) { . $pagerFile }
    }
    while ($url) {
        $attempt = 0
        # 5 attempts, honouring Retry-After (#125). This runs once PER service principal across
        # potentially thousands of them, so Graph throttling is the NORMAL case -- and 3 attempts at
        # 1s/2s ignored the server's backoff, gave up, and the caller published the principal with NO
        # permissions: a silent under-tiering.
        $maxAttempts = 5
        $resp = $null
        $renewed = $false
        while ($true) {
            $attempt++
            # #882 (A1): a read of many pages outlives one token -- the cached token before every page (Get-SIGraphToken hands
            # it back until it nears its expiry), and after a 401 ONE forced new token and the SAME page again
            if (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) { try { $tk = [string](Get-SIGraphToken -Resource Graph); if ($tk) { $headers['Authorization'] = 'Bearer ' + $tk } } catch { } }
            try {
                $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
                break
            } catch {
                $status = Get-SIGraphHttpStatus -ErrorRecord $_
                if ($status -eq 401 -and -not $renewed -and (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) {
                    $renewed = $true; $attempt--
                    $tk = $null; try { $tk = [string](Get-SIGraphToken -Resource Graph -ForceRefresh) } catch { $tk = $null }
                    if ($tk) { $headers['Authorization'] = 'Bearer ' + $tk; continue }
                }
                $isTransient = ($status -in 429,502,503,504) -or ($status -eq 0)
                if (-not $isTransient -or $attempt -ge $maxAttempts) { throw }
                $delay = $null
                if (Get-Command -Name 'Get-SIRetryAfterSeconds' -ErrorAction SilentlyContinue) { $delay = Get-SIRetryAfterSeconds -ErrorRecord $_ }
                if ($null -eq $delay) { $delay = [Math]::Pow(2, $attempt) }   # 2, 4, 8, 16s
                if ($delay -gt 60) { $delay = 60 }
                # Per-retry warnings on busy tenants (PIM scans across 80+
                # role-bearing groups can fire 50+ retries that all auto-
                # recover) drown the launcher trace. Bump a counter for an
                # end-of-phase summary line; keep the per-call detail
                # available via -Verbose for debugging.
                if (-not $script:_SIGraphRetryCount) { $script:_SIGraphRetryCount = @{} }
                $key = "HTTP$status"
                if (-not $script:_SIGraphRetryCount.ContainsKey($key)) { $script:_SIGraphRetryCount[$key] = 0 }
                $script:_SIGraphRetryCount[$key]++
                Write-Verbose ('Graph transient error (HTTP {0}) on {1} -- retry {2}/{3} in {4}s' -f $status, $url, $attempt, $maxAttempts, $delay)
                Start-Sleep -Seconds $delay
            }
        }
        if ($resp.value) {
            if ($OnPage) { $null = & $OnPage @($resp.value) }
            else { foreach ($v in $resp.value) { [void]$all.Add($v) } }
        } elseif ($resp -and -not $resp.value -and $resp.PSObject.Properties['id']) {
            [void]$all.Add($resp)
        }
        $url = $resp.'@odata.nextLink'
    }
    return $all.ToArray()
}

function Get-SIEntraRoleDefinitionMap {
    # Returns @{ <roleDefinitionId GUID> = <displayName> } -- needed because
    # roleAssignments come back keyed by roleDefinitionId, but the catalog
    # matches by DisplayName ("Global Administrator", etc.).
    param([Parameter(Mandatory)][string]$Token)
    if ($script:_SICache.ContainsKey('RoleDefMap')) { Write-SIInfo '[perms] role definitions (cache hit)'; return $script:_SICache['RoleDefMap'] }
    # LIST KEPT: a name look-up -- role id + name
    try { $rows = Invoke-SIGraphPaged -RelativeUrl '/roleManagement/directory/roleDefinitions?$select=id,displayName' -Token $Token }
    catch { Set-SIEntraRoleReadPart -Part 'Definitions' -Complete $false -ErrorText $_.Exception.Message; throw }
    $map = @{}
    foreach ($r in $rows) {
        if ($r.id -and $r.displayName) { $map[[string]$r.id] = [string]$r.displayName }
    }
    Set-SIEntraRoleReadPart -Part 'Definitions' -Complete ($map.Count -gt 0) -ErrorText $(if ($map.Count -gt 0) { '' } else { 'no role definition was read' })
    $script:_SICache['RoleDefMap'] = $map
    return $map
}

function Get-SIEntraRoleAssignmentKey {
    <# PURE. The key one role assignment is found by: '<principal id>|<role definition id>|<directory scope id>' (the ids
       lower case; no scope = '/', the tenant). #>
    param([AllowNull()][AllowEmptyString()][string]$PrincipalId, [AllowNull()][AllowEmptyString()][string]$RoleDefinitionId, [AllowNull()][AllowEmptyString()][string]$DirectoryScopeId)
    $s = ([string]$DirectoryScopeId).Trim(); if (-not $s) { $s = '/' }
    '{0}|{1}|{2}' -f ([string]$PrincipalId).Trim().ToLowerInvariant(), ([string]$RoleDefinitionId).Trim().ToLowerInvariant(), $s
}

function Get-SIEntraActivatedRoleAssignments {
    <#
        The role assignments that exist ONLY because an eligible role is activated right now (Privileged Identity
        Management): ONE paged tenant-wide read of the assignment schedule instances (assignmentType 'Activated'), cached
        for the run -- the role maps and the identity context both use it, so it is asked for once, never per identity.
        Returns @{ Complete; Error; ByKey = @{ <Get-SIEntraRoleAssignmentKey> = <end of the activation, ISO text or ''> } }.
        -CacheOnly: what this run already read, or $null (no read is made).
        NEVER THROWS: in a tenant without Privileged Identity Management, or when the read is refused, no activation can
        be told apart -- every active assignment then counts as permanent, exactly as before this read existed.
    #>
    param([string]$Token = '', [switch]$CacheOnly)
    if ($script:_SICache -and $script:_SICache.ContainsKey('ActivatedAssignments')) { return $script:_SICache['ActivatedAssignments'] }
    if ($CacheOnly) { return $null }
    $state = @{ Complete = $false; Error = ''; ByKey = @{} }
    try {
        # LIST KEPT: a join read -- which (principal, role, scope) is an activation and until when; the assignment itself is read once, elsewhere
        $rows = Invoke-SIGraphPaged -RelativeUrl ('/roleManagement/directory/roleAssignmentScheduleInstances?$filter=' + [uri]::EscapeDataString("assignmentType eq 'Activated'")) -Token $Token
        # #899: the same answer shape as the role lists -- an id answered twice is said (a WARNING only)
        $aw = New-SIIdDuplicateWatch -Label 'activated role assignments'; Add-SIIdDuplicateWatch -Watch $aw -Rows @($rows); $null = Write-SIIdDuplicateWarning $aw
        foreach ($r in @($rows)) {
            if ($null -eq $r) { continue }
            $tp = $r.PSObject.Properties['assignmentType']
            if (-not $tp -or [string]$tp.Value -ne 'Activated') { continue }
            $pp = $r.PSObject.Properties['principalId']; $rp = $r.PSObject.Properties['roleDefinitionId']
            if (-not $pp -or -not $rp -or -not $pp.Value -or -not $rp.Value) { continue }
            $sp = $r.PSObject.Properties['directoryScopeId']; $scope = ''; if ($sp) { $scope = [string]$sp.Value }
            $ep = $r.PSObject.Properties['endDateTime']; $end = ''
            if ($ep -and $null -ne $ep.Value) { if ($ep.Value -is [datetime]) { $end = $ep.Value.ToUniversalTime().ToString('o') } else { $end = [string]$ep.Value } }
            $state.ByKey[(Get-SIEntraRoleAssignmentKey -PrincipalId ([string]$pp.Value) -RoleDefinitionId ([string]$rp.Value) -DirectoryScopeId $scope)] = $end
        }
        $state.Complete = $true
    } catch {
        $state.Error = [string]$_.Exception.Message
        $state.ByKey = @{}
        Write-Verbose ('activated role assignments not read ({0}) -- every active assignment counts as permanent this run' -f $state.Error)
    }
    $script:_SICache['ActivatedAssignments'] = $state
    return $state
}

function Add-SIEntraActivatedRolesToEligible {
    <# The roles a principal holds only because they are activated right now (kept by
       Get-SIEntraRoleAssignmentsByPrincipal) are ELIGIBLE roles: added to the eligible map, each role once. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Map)
    if (-not $script:_SICache -or -not $script:_SICache.ContainsKey('ActivatedRolesMap')) { return }
    $act = $script:_SICache['ActivatedRolesMap']
    foreach ($id in @($act.Keys)) {
        if (-not $Map.ContainsKey($id)) { $Map[$id] = New-Object System.Collections.ArrayList }
        foreach ($name in @($act[$id])) { if ($name -and -not ($Map[$id] -contains $name)) { [void]$Map[$id].Add($name) } }
    }
}

function Get-SIEntraRoleAssignmentsByPrincipal {
    # Bulk fetch ALL Entra directory roleAssignments tenant-wide, bucket by
    # principalId. One Graph call (paged), then O(1) lookups per asset.
    # Returns @{ <principalId> = @(<roleDisplayName1>, <roleDisplayName2>, ...) }
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleDefinitionMap
    )
    if ($script:_SICache.ContainsKey('PermRolesMap')) { Write-SIInfo '[perms] role assignments permanent (cache hit)'; return $script:_SICache['PermRolesMap'] }
    # #899: read until two reads agree (Read-SIEntraRoleSetChecked); a read that throws fails the discovery, as before
    try { $read = Read-SIEntraRoleSetChecked -RelativeUrl '/roleManagement/directory/roleAssignments' -Token $Token -Label 'role assignments (permanent)' -RoleDefinitionIds @($RoleDefinitionMap.Keys) }
    catch { Set-SIEntraRoleReadPart -Part 'Permanent' -Complete $false -ErrorText $_.Exception.Message; throw }
    if ($read.Complete) { Write-SIInfo $read.Line } elseif (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $read.Line } else { Write-Warning $read.Line }
    $rows = @($read.Rows)
    $byPrincipal = @{}
    # every assignment WITH ITS SCOPE (Get-SIEntraRoleScopesByPrincipal -> si_entra_role_scopes). OWNER 2026-10-11: a role
    # assigned on an administrative unit or on one object (directoryScopeId other than '/') KEEPS THE ROLE'S TIER -- it is
    # in the map below, which feeds the privilege tier, exactly as the same role tenant-wide, in every tier. For TIER 0
    # only, that it is scoped is said beside the tier as a LEVEL (level 1 = tenant-wide, level 2 = scoped only:
    # si_privilege_tier_level, built from the scopes kept here by discovery/Get-SIEntraContext.ps1); a scoped Tier 1 /
    # Tier 2 role has no level, its scope is listed in si_entra_role_scopes. No scope on the row = tenant-wide.
    # AN ACTIVATED ROLE IS AN ELIGIBLE ROLE: an assignment that exists only because an eligible role is activated right now
    # (Privileged Identity Management) is NOT permanent -- it stays out of the map below and is counted with the eligible
    # roles (Get-SIEntraPIMEligibleByPrincipal adds it), carrying "activated until" in si_entra_role_scopes.
    $activated = Get-SIEntraActivatedRoleAssignments -Token $Token
    $activatedRoles = @{}
    if (-not $script:_SICache.ContainsKey('RoleScopes')) { $script:_SICache['RoleScopes'] = @{} }
    $scopes = $script:_SICache['RoleScopes']
    foreach ($r in $rows) {
        $objId = [string]$r.principalId
        $rid = [string]$r.roleDefinitionId
        if (-not $objId -or -not $rid) { continue }
        $name = $RoleDefinitionMap[$rid]
        if (-not $name) { continue }
        $scopeId = '/'
        $scopeProp = $r.PSObject.Properties['directoryScopeId']
        if ($scopeProp -and -not [string]::IsNullOrWhiteSpace([string]$scopeProp.Value)) { $scopeId = ([string]$scopeProp.Value).Trim() }
        if (-not $scopes.ContainsKey($objId)) { $scopes[$objId] = New-Object System.Collections.ArrayList }
        [void]$scopes[$objId].Add([pscustomobject]@{ roleId = $rid; role = [string]$name; scopeId = $scopeId; assignment = 'active' })
        if ($activated -and $activated.ByKey.ContainsKey((Get-SIEntraRoleAssignmentKey -PrincipalId $objId -RoleDefinitionId $rid -DirectoryScopeId $scopeId))) {
            if (-not $activatedRoles.ContainsKey($objId)) { $activatedRoles[$objId] = New-Object System.Collections.ArrayList }
            if (-not ($activatedRoles[$objId] -contains $name)) { [void]$activatedRoles[$objId].Add($name) }
            continue
        }
        if (-not $byPrincipal.ContainsKey($objId)) { $byPrincipal[$objId] = New-Object System.Collections.ArrayList }
        if (-not ($byPrincipal[$objId] -contains $name)) { [void]$byPrincipal[$objId].Add($name) }
    }
    $script:_SICache['ActivatedRolesMap'] = $activatedRoles
    if ($read.Complete) { Set-SIEntraRoleReadPart -Part 'Permanent' -Complete $true }
    else {
        # NOT complete: what this run saw + every principal's stored permanent roles (or the discovery fails, as before)
        Resolve-SIEntraRoleReadIncomplete -Kind 'Permanent' -Map $byPrincipal -Except $activatedRoles -Why ('the reads did not agree: {0} assignment(s) seen' -f $read.Count)
    }
    $script:_SICache['PermRolesMap'] = $byPrincipal
    return $byPrincipal
}

function Get-SIEntraMfaRegistrationByPrincipal {
    # ONE bulk paged call against /reports/authenticationMethods/userRegistrationDetails
    # returns MFA + SSPR + passwordless registration for every user. Replaces
    # legacy v1's per-user /authentication/methods loop (which was N+1 + 429-prone).
    #
    # Returns @{ <userObjectId> = pscustomobject@{
    #     IsMfaRegistered, IsMfaCapable, IsPasswordlessCapable,
    #     IsSsprRegistered, IsSsprCapable, IsSsprEnabled,
    #     MfaMethods=@(string), MfaMethodCount,
    #     DefaultMfaMethod, SystemPreferredAuthMethods=@(string),
    #     PreferredSecondaryAuthMethod, MfaLastUpdatedDateTime
    # } }
    #
    # Permission: UserAuthenticationMethod.Read.All (already required for
    # the legacy fallback path) OR AuditLog.Read.All for the bulk endpoint.
    #
    # #522 UNKNOWN IS NEVER "NO MFA". Before this, a failed fetch (licence / permission / throttling on a large tenant)
    # returned an EMPTY map and the discovery then defaulted every user to "MFA not registered" -- customer H flagged 8,836
    # of ~8,994. Now the pages already read are kept (Invoke-SIPagedRest never throws), the outcome is recorded
    # (Get-SIEntraMfaRegistrationState), the run says in ONE plain line that MFA data is missing, and a user without a
    # registration row gets MFA UNKNOWN ($null) from the discovery -- the reports read MfaIsRegistered == false, which a
    # null never matches.
    param(
        [Parameter(Mandatory)][string]$Token,
        # test seam: { param($Url, $Token) } returning Invoke-SIPagedRest's shape (Rows / Complete / Error / Count / Pages)
        [scriptblock]$Fetch
    )
    if ($script:_SICache.ContainsKey('MfaRegMap')) {
        Write-SIInfo '[perms] MFA registration details (cache hit)'
        return $script:_SICache['MfaRegMap']
    }
    Write-SIInfo '[perms] fetching MFA registration details (one bulk call to userRegistrationDetails)...'
    # #726: the map lives ON DISK (one entry per user, type-faithful, only the ids in memory) -- every tenant; $map[<id>] reads as before
    if (-not (Get-Command -Name New-SIDiskLookup -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-DiskLookup.ps1')) }
    $byPrincipal = New-SIDiskLookup -Name 'mfa-registration'
    $regUrl = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    # PAGE BY PAGE (#702, customer B 2026-10-15): each page of registration rows becomes its small map entries and is let go -- the
    # tenant's rows are never all held (22,955 at customer B). A pager (or a test seam) that hands back Rows instead is read the same.
    $onRegPage = { param($PageRows) foreach ($r in @($PageRows)) { & $addReg $r } }
    $addReg = { param($r)
        $oid = [string]$r.id
        if (-not $oid) { return }
        # v3 data model: the registration row is the 'registration' part of the user's Entra record
        if (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue) { Add-SIRecordPart -Provider 'entra' -RecordType 'user' -Key $oid -Part 'registration' -Object $r }
        # Drop 'password' from method list -- holding a password isn't MFA on its own.
        $methodsRaw = if ($r.PSObject.Properties['methodsRegistered'] -and $r.methodsRegistered) { @($r.methodsRegistered) } else { @() }
        $mfaMethods = @($methodsRaw | Where-Object { $_ -and $_ -ne 'password' })
        $null = $byPrincipal.Put($oid, (ConvertTo-SIDiskLookupText -InputObject ([pscustomobject]@{
            IsMfaRegistered             = if ($r.PSObject.Properties['isMfaRegistered'])             { [bool]$r.isMfaRegistered }             else { $null }   # #522 absent = unknown, never "no MFA"
            IsMfaCapable                = if ($r.PSObject.Properties['isMfaCapable'])                { [bool]$r.isMfaCapable }                else { $false }
            IsPasswordlessCapable       = if ($r.PSObject.Properties['isPasswordlessCapable'])       { [bool]$r.isPasswordlessCapable }       else { $false }
            IsSsprRegistered            = if ($r.PSObject.Properties['isSsprRegistered'])            { [bool]$r.isSsprRegistered }            else { $false }
            IsSsprCapable               = if ($r.PSObject.Properties['isSsprCapable'])               { [bool]$r.isSsprCapable }               else { $false }
            IsSsprEnabled               = if ($r.PSObject.Properties['isSsprEnabled'])               { [bool]$r.isSsprEnabled }               else { $false }
            IsAdmin                     = if ($r.PSObject.Properties['isAdmin'])                     { [bool]$r.isAdmin }                     else { $false }
            MfaMethods                  = $mfaMethods
            MfaMethodCount              = $mfaMethods.Count
            DefaultMfaMethod            = if ($r.PSObject.Properties['defaultMfaMethod'])            { [string]$r.defaultMfaMethod }          else { '' }
            # @( ) around the whole if (#726): an empty list must stay a list through the on-disk map (an if-statement's empty
            # result is "nothing", which the on-disk entry can only keep as null -- and @($null) is one null, not none)
            SystemPreferredAuthMethods  = @(if ($r.PSObject.Properties['systemPreferredAuthenticationMethods']) { $r.systemPreferredAuthenticationMethods })
            PreferredSecondaryAuthMethod= if ($r.PSObject.Properties['userPreferredMethodForSecondaryAuthentication']) { [string]$r.userPreferredMethodForSecondaryAuthentication } else { '' }
            MfaLastUpdatedDateTime      = if ($r.PSObject.Properties['lastUpdatedDateTime'])         { [string]$r.lastUpdatedDateTime }       else { '' }
        })))
    }
    $page = $null
    try {
        if ($Fetch) { $page = & $Fetch $regUrl $Token }
        else {
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Invoke-SIPagedRest.ps1') }
            # the reports endpoint throttles hard on large tenants -- a longer retry budget than the default
            $page = Invoke-SIPagedRest -Url $regUrl -Token $Token -SourceLabel 'MFA registration' -MaxAttempts 6 -OnPage $onRegPage
        }
    } catch {
        $page = [pscustomobject]@{ Rows = @(); Complete = $false; Error = $_.Exception.Message; Count = 0; Pages = 0 }
    }
    if ($page -and $page.Rows) { & $onRegPage @($page.Rows) }
    $complete = [bool]($page -and $page.Complete)
    $script:_SICache['MfaRegState'] = [pscustomobject]@{ Complete = $complete; Users = $byPrincipal.Count; Error = $(if ($page) { [string]$page.Error } else { 'no answer' }) }
    if ($complete) {
        Write-SIInfo ('[perms] MFA registration details: {0} users with registration data' -f $byPrincipal.Count)
    } else {
        $line = Get-SIMfaMissingLine -State $script:_SICache['MfaRegState']
        if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $line } else { Write-Warning $line }
    }
    $script:_SICache['MfaRegMap'] = $byPrincipal
    return $byPrincipal
}

function ConvertTo-SIUserMfaFields {
    <#
        PURE. One user's MFA registration entry (from Get-SIEntraMfaRegistrationByPrincipal) -> the ENTRA_Mfa* values of
        its discovery record. No entry = MFA UNKNOWN: every value $null (#522 -- never $false, which the reports read as
        "no MFA").
    #>
    param($Entry)
    if ($null -eq $Entry) {
        return @{
            ENTRA_MfaIsRegistered = $null; ENTRA_MfaIsCapable = $null; ENTRA_IsPasswordlessCapable = $null
            ENTRA_IsSsprRegistered = $null; ENTRA_IsSsprCapable = $null; ENTRA_IsSsprEnabled = $null
            ENTRA_MfaMethods = $null; ENTRA_MfaMethodCount = $null; ENTRA_MfaDefaultMethod = $null
            ENTRA_MfaSystemPreferredMethods = $null; ENTRA_MfaPreferredSecondary = $null; ENTRA_MfaLastUpdatedDateTime = $null
        }
    }
    @{
        ENTRA_MfaIsRegistered           = $Entry.IsMfaRegistered
        ENTRA_MfaIsCapable              = $Entry.IsMfaCapable
        ENTRA_IsPasswordlessCapable     = $Entry.IsPasswordlessCapable
        ENTRA_IsSsprRegistered          = $Entry.IsSsprRegistered
        ENTRA_IsSsprCapable             = $Entry.IsSsprCapable
        ENTRA_IsSsprEnabled             = $Entry.IsSsprEnabled
        ENTRA_MfaMethods                = @($Entry.MfaMethods)
        ENTRA_MfaMethodCount            = [int]$Entry.MfaMethodCount
        ENTRA_MfaDefaultMethod          = [string]$Entry.DefaultMfaMethod
        ENTRA_MfaSystemPreferredMethods = @($Entry.SystemPreferredAuthMethods)
        ENTRA_MfaPreferredSecondary     = [string]$Entry.PreferredSecondaryAuthMethod
        ENTRA_MfaLastUpdatedDateTime    = [string]$Entry.MfaLastUpdatedDateTime
    }
}

function Get-SIEntraMfaRegistrationState {
    <# The outcome of this process's MFA registration read: Complete / Users / Error ($null when it has not run). #>
    if ($script:_SICache.ContainsKey('MfaRegState')) { return $script:_SICache['MfaRegState'] }
    $null
}

function Get-SIMfaMissingLine {
    <# PURE. The one plain line a run prints when MFA registration could not be read (fully). #>
    param([Parameter(Mandatory)]$State)
    $why = [string]$State.Error
    $reason = if ($why -match 'HTTP 403|\(403\)|Forbidden') { 'access was refused -- the tenant needs an Entra ID P1 or P2 licence and the SecurityInsight identity needs AuditLog.Read.All' }
              elseif ($why -match 'HTTP 429|\(429\)|TooManyRequests') { 'Microsoft kept asking SecurityInsight to slow down' }
              elseif ($why) { $why } else { 'no reason given' }
    if ([int]$State.Users -gt 0) {
        return ('MFA registration data is incomplete for this run: it was read for {0:N0} users, then stopped ({1}). Users without data show MFA as unknown and are not reported as having no MFA.' -f [int]$State.Users, $reason)
    }
    ('MFA registration data is missing for this run: it could not be read ({0}). No user is reported as having no MFA; MFA shows as unknown.' -f $reason)
}

function Get-SIEntraPIMEligibleByPrincipal {
    # Same shape as Get-SIEntraRoleAssignmentsByPrincipal, but for PIM eligible
    # role assignments (roleEligibilitySchedules). User holds these but must
    # activate before use; still highly relevant for tier classification.
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleDefinitionMap
    )
    if ($script:_SICache.ContainsKey('EligRolesMap')) { Write-SIInfo '[perms] role assignments PIM eligible (cache hit)'; return $script:_SICache['EligRolesMap'] }
    $byPrincipal = @{}
    try {
        # #899: read until two reads agree, as the permanent assignments
        $read = Read-SIEntraRoleSetChecked -RelativeUrl '/roleManagement/directory/roleEligibilitySchedules' -Token $Token -Label 'role assignments (PIM eligible)' -RoleDefinitionIds @($RoleDefinitionMap.Keys)
        if ($read.Complete) { Write-SIInfo $read.Line } elseif (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $read.Line } else { Write-Warning $read.Line }
        $rows = @($read.Rows)
    } catch {
        # Classify the failure so the warning matches reality:
        #   403  -> truly insufficient (no Entra ID P2, or Token lacks RoleManagement.Read.Directory)
        #   5xx  -> Graph backend transient (we already retried 3x in Invoke-SIGraphPaged)
        #   429  -> throttled past retry budget
        #   else -> unknown; surface the raw message
        $status = Get-SIGraphHttpStatus -ErrorRecord $_
        $reason = switch ($status) {
            403     { 'no Entra ID P2 license, or token missing RoleManagement.Read.Directory' }
            429     { 'throttled by Graph after 3 retry attempts' }
            502     { 'Graph gateway error (502) after 3 retry attempts -- transient' }
            503     { 'Graph service unavailable (503) after 3 retry attempts -- transient' }
            504     { 'Graph gateway timeout (504) after 3 retry attempts -- transient' }
            default { ('HTTP {0}' -f $status) }
        }
        Write-Warning ('PIM eligible fetch skipped ({0}): {1}' -f $reason, $_.Exception.Message)
        # NOT complete: "no eligible role" is unknown for every principal (a tenant without Entra ID P2 cannot be told
        # apart from a missing permission here)
        Set-SIEntraRoleReadPart -Part 'Eligible' -Complete $false -ErrorText ($reason + ': ' + $_.Exception.Message)
        # #899: a read that failed on a busy or broken service (not a refusal -- a tenant without Entra ID P2 is refused every
        # run, and has no eligible role to keep) keeps every principal's stored eligible roles when they can be read
        if ($status -in 0, 429, 500, 502, 503, 504) {
            try { Resolve-SIEntraRoleReadIncomplete -Kind 'Eligible' -Map $byPrincipal -Why $reason }
            catch { Write-Warning ('the stored eligible roles could not be kept either -- {0}' -f $_.Exception.Message) }
        }
        Add-SIEntraActivatedRolesToEligible -Map $byPrincipal
        return $byPrincipal
    }
    # every eligible assignment with its scope; one scoped to an administrative unit or an object counts toward the tier
    # like the same role tenant-wide (see Get-SIEntraRoleAssignmentsByPrincipal)
    if (-not $script:_SICache.ContainsKey('RoleScopes')) { $script:_SICache['RoleScopes'] = @{} }
    $scopes = $script:_SICache['RoleScopes']
    foreach ($r in $rows) {
        $objId = [string]$r.principalId
        $rid = [string]$r.roleDefinitionId
        if (-not $objId -or -not $rid) { continue }
        $name = $RoleDefinitionMap[$rid]
        if (-not $name) { continue }
        $scopeId = '/'
        $scopeProp = $r.PSObject.Properties['directoryScopeId']
        if ($scopeProp -and -not [string]::IsNullOrWhiteSpace([string]$scopeProp.Value)) { $scopeId = ([string]$scopeProp.Value).Trim() }
        if (-not $scopes.ContainsKey($objId)) { $scopes[$objId] = New-Object System.Collections.ArrayList }
        [void]$scopes[$objId].Add([pscustomobject]@{ roleId = $rid; role = [string]$name; scopeId = $scopeId; assignment = 'eligible' })
        if (-not $byPrincipal.ContainsKey($objId)) { $byPrincipal[$objId] = New-Object System.Collections.ArrayList }
        if (-not ($byPrincipal[$objId] -contains $name)) { [void]$byPrincipal[$objId].Add($name) }
    }
    # the roles that are active only because they are activated right now: eligible roles
    Add-SIEntraActivatedRolesToEligible -Map $byPrincipal
    if ($read.Complete) { Set-SIEntraRoleReadPart -Part 'Eligible' -Complete $true }
    else {
        # NOT complete: what this run saw + every principal's stored eligible roles (or the discovery fails)
        Resolve-SIEntraRoleReadIncomplete -Kind 'Eligible' -Map $byPrincipal -Why ('the reads did not agree: {0} assignment(s) seen' -f $read.Count)
    }
    $script:_SICache['EligRolesMap'] = $byPrincipal
    return $byPrincipal
}

function Get-SIAppRolePermissionResolver {
    # Builds @{ <resourceSPid>|<appRoleId GUID> = <permission Value> } so we can
    # turn a SP's appRoleAssignments (which carry appRoleId GUIDs) into the
    # human-readable permission strings the catalog uses ("Directory.Read.All").
    # We pull all SPs once (already needed for discovery anyway) and harvest
    # their .appRoles[] -> {id, value}.
    param(
        [Parameter(Mandatory)][string]$Token
    )
    if ($script:_SICache.ContainsKey('AppRoleResolver')) { Write-SIInfo '[perms] appRole resolver (cache hit)'; return $script:_SICache['AppRoleResolver'] }
    $resolver = @{}
    # ONE read of every service principal, also the INDEX the Entra context reads use (Get-SIServicePrincipalIndex): object id
    # <-> application id + name, each API's permission names by id, a managed identity's resource. No second pass.
    $index = @{ ById = @{}; ByAppId = @{}; PermissionNames = @{}; AlternativeNames = @{} }
    # LIST KEPT: an index for look-ups (ids, names, each permission by id) over EVERY service principal, Microsoft ones included -- the whole objects are very large; the service principals SecurityInsight records are read once, elsewhere
    # PAGE BY PAGE (#702, customer B 2026-10-15): each page is indexed and let go -- the service principals (each with its appRoles and
    # scopes) are never all held; only the small index entries stay
    $indexPage = { param($PageRows)
    foreach ($sp in $PageRows) {
        $spId = [string]$sp.id
        if ($spId) {
            $spAppId = ([string]$sp.appId).ToLowerInvariant()
            $index.ById[$spId.ToLowerInvariant()] = [pscustomobject]@{ appId = $spAppId; displayName = [string]$sp.displayName }
            if ($spAppId) {
                $index.ByAppId[$spAppId] = $spId.ToLowerInvariant()
                foreach ($ar in @($sp.appRoles)) { if ($ar -and $ar.id -and $ar.value) { $index.PermissionNames[('{0}|{1}' -f $spAppId, ([string]$ar.id).ToLowerInvariant())] = [string]$ar.value } }
                foreach ($sc in @($sp.oauth2PermissionScopes)) { if ($sc -and $sc.id -and $sc.value) { $index.PermissionNames[('{0}|{1}' -f $spAppId, ([string]$sc.id).ToLowerInvariant())] = [string]$sc.value } }
            }
            if ([string]$sp.servicePrincipalType -eq 'ManagedIdentity' -and @($sp.alternativeNames | Where-Object { $_ }).Count -gt 0) { $index.AlternativeNames[$spId.ToLowerInvariant()] = @($sp.alternativeNames | ForEach-Object { [string]$_ }) }
        }
        if (-not $spId -or -not $sp.appRoles) { continue }
        foreach ($ar in $sp.appRoles) {
            $arId = [string]$ar.id
            $val  = [string]$ar.value
            if ($arId -and $val) { $resolver[("{0}|{1}" -f $spId, $arId)] = $val }
        }
    }
    }
    # LIST KEPT: an index read (#702) -- the ids, names and the app roles / scopes the resolver names; the service principals themselves are read whole elsewhere
    $null = Invoke-SIGraphPaged -RelativeUrl '/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,alternativeNames,appRoles,oauth2PermissionScopes' -Token $Token -OnPage $indexPage
    $script:_SICache['AppRoleResolver'] = $resolver
    $script:_SICache['SpIndex'] = $index
    return $resolver
}

function Get-SIServicePrincipalIndex {
    <# The service-principal index of this run (built by Get-SIAppRolePermissionResolver's one read), or $null when that
       read has not run: ById (object id -> appId, displayName), ByAppId (appId -> object id), PermissionNames
       ('<resource appId>|<permission id>' -> name), AlternativeNames (a managed identity's object id -> its names). #>
    if ($script:_SICache -and $script:_SICache.ContainsKey('SpIndex')) { return $script:_SICache['SpIndex'] }
    $null
}

function Get-SIEntraRoleScopesByPrincipal {
    <# Every Entra role assignment of this run with its scope: @{ <principal id> = [{ roleId, role, scopeId, assignment }] }
       (assignment: active | eligible; scopeId '/' = the tenant). Empty when the role reads have not run. #>
    if ($script:_SICache -and $script:_SICache.ContainsKey('RoleScopes')) { return $script:_SICache['RoleScopes'] }
    @{}
}

function Get-SIRolePrincipalNames {
    <# The display name of every principal that holds an Entra role (users, groups, service principals): @{ <id> = name }. #>
    if ($script:_SICache -and $script:_SICache.ContainsKey('RolePrincipalNames')) { return $script:_SICache['RolePrincipalNames'] }
    @{}
}

function Get-SIRoleGroupLookups {
    <# The run's role-through-group look-ups, as the discoveries built them (empty tables when they have not run):
       GroupRoles (group id -> { Permanent; Eligible }), MemberToGroups (member id -> group ids), PimGroups (principal id ->
       the role-bearing groups it can activate into), ActivatedMembers ('<principal id>|<group id>' -> until when, for a
       membership that exists only because it is activated right now). #>
    $o = @{ GroupRoles = @{}; MemberToGroups = @{}; PimGroups = @{}; RoleDefinitions = @{}; ActivatedMembers = @{} }
    if ($script:_SICache) {
        # a member of a role-holding group ONLY because an eligible membership is activated right now
        # (Get-SIPimGroupActivatedMemberships); empty when that read did not run or was refused
        if ($script:_SICache.ContainsKey('PimGroupActivations') -and $script:_SICache['PimGroupActivations'].ByKey) { $o.ActivatedMembers = $script:_SICache['PimGroupActivations'].ByKey }
        if ($script:_SICache.ContainsKey('RoleDefMap')) { $o.RoleDefinitions = $script:_SICache['RoleDefMap'] }
        if ($script:_SICache.ContainsKey('GroupRoles')) { $o.GroupRoles = $script:_SICache['GroupRoles'] }
        if ($script:_SICache.ContainsKey('MemberToGroups')) { $o.MemberToGroups = $script:_SICache['MemberToGroups'] }
        if ($script:_SICache.ContainsKey('PimForGroupsMap')) { $o.PimGroups = $script:_SICache['PimForGroupsMap'] }
    }
    $o
}

function Add-SIOauth2GrantRows {
    <#
        PURE. Folds a page of /oauth2PermissionGrants rows into -State.ByClient -- summarised while it is read, never one
        entry per consenting user: per client (service principal object id) the permission names in the order met, and per
        (API, admin / user consent) the permission names and HOW MANY users consented.
    #>
    param([Parameter(Mandatory)]$State, [AllowEmptyCollection()][object[]]$Rows = @())
    foreach ($g in $Rows) {
        if ($null -eq $g) { continue }
        $client = ([string]$g.clientId).ToLowerInvariant()
        if (-not $client) { continue }
        $c = $State.ByClient[$client]
        if ($null -eq $c) { $c = @{ Scopes = (New-Object System.Collections.ArrayList); Grants = [ordered]@{}; Users = (New-Object 'System.Collections.Generic.HashSet[string]') }; $State.ByClient[$client] = $c }
        $resource = ([string]$g.resourceId).ToLowerInvariant()
        $type = [string]$g.consentType; if (-not $type) { $type = 'AllPrincipals' }
        $key = $resource + '|' + $type
        if (-not $c.Grants.Contains($key)) { $c.Grants[$key] = @{ ResourceId = $resource; ConsentType = $type; Scopes = (New-Object System.Collections.ArrayList); Users = 0 } }
        $gr = $c.Grants[$key]
        $who = ([string]$g.principalId).ToLowerInvariant()
        if ($type -ne 'AllPrincipals' -and $who) { $gr.Users++; [void]$c.Users.Add($who) }
        foreach ($s in ([string]$g.scope -split '\s+')) {
            if (-not $s) { continue }
            if (-not ($c.Scopes -contains $s)) { [void]$c.Scopes.Add($s) }
            if (-not ($gr.Scopes -contains $s)) { [void]$gr.Scopes.Add($s) }
        }
    }
}

function Get-SIOauth2GrantsByClient {
    <#
        The delegated permission grants of the WHOLE tenant in ONE paged read (GET /oauth2PermissionGrants), summarised per
        client as the pages come -- instead of one request per service principal. Returns
        @{ Complete; Error; ByClient = @{ <service principal id> = { Scopes; Grants; Users } } }; cached for the run.
        NOT complete (refused, throttled past the retries, stopped part-way): the caller reads the principals one by one
        as before, so a failed read never turns into "no delegated permission". -Fetch (tests): { param($Url) } -> rows.
    #>
    param([Parameter(Mandatory)][string]$Token, [scriptblock]$Fetch)
    if ($script:_SICache.ContainsKey('Oauth2Grants')) { return $script:_SICache['Oauth2Grants'] }
    $state = @{ Complete = $false; Error = ''; ByClient = @{} }
    $url = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
    try {
        if ($Fetch) { Add-SIOauth2GrantRows -State $state -Rows @(& $Fetch $url); $state.Complete = $true }
        else {
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Invoke-SIPagedRest.ps1') }
            $page = Invoke-SIPagedRest -Url $url -Token $Token -SourceLabel 'Delegated permission grants' -OnPage { param($PageRows) Add-SIOauth2GrantRows -State $state -Rows @($PageRows) }
            $state.Complete = [bool]$page.Complete; $state.Error = [string]$page.Error
        }
    } catch { $state.Complete = $false; $state.Error = [string]$_.Exception.Message }
    if ($state.Complete) { Write-SIInfo ('[perms] delegated permission grants: {0} service principal(s) hold at least one (one read for the tenant)' -f $state.ByClient.Count) }
    else { Write-SIInfo '[perms] delegated permission grants: the one read for the tenant did not complete -- reading them per service principal instead' }
    $script:_SICache['Oauth2Grants'] = $state
    return $state
}

function Get-SIOauth2ClientScopes {
    <# PURE. The delegated permission names of one service principal from a Get-SIOauth2GrantsByClient state (none = @()). #>
    param($State, [string]$ClientId)
    if ($null -eq $State -or -not $ClientId) { return @() }
    $c = $State.ByClient[$ClientId.ToLowerInvariant()]
    if ($null -eq $c) { return @() }
    return @($c.Scopes.ToArray())
}

function Reset-SIPermissionFetchFailures { $global:SI_PermissionFetchFailures = New-Object System.Collections.ArrayList }

function Add-SIPermissionFetchFailure {
    # One record per principal whose permission lookup failed after every retry. Global because the
    # fetchers and their caller are dot-sourced into different scopes; reset by the caller per run.
    param([string]$Kind, [string]$ObjectId, [string]$Message)
    if ($null -eq $global:SI_PermissionFetchFailures) { Reset-SIPermissionFetchFailures }
    [void]$global:SI_PermissionFetchFailures.Add([pscustomobject]@{ Kind = $Kind; ObjectId = $ObjectId; Message = $Message })
}

function Write-SIPermissionFetchSummary {
    # Once per run, after the per-principal loop. Silence when nothing failed.
    param([string]$Label = 'service principal')
    $f = @($global:SI_PermissionFetchFailures)
    if ($f.Count -eq 0) { return }
    $principals = @($f | ForEach-Object { $_.ObjectId } | Sort-Object -Unique).Count
    $first = $f[0].Message
    $msg = ('[perms] {0} {1}(s): the permission lookup failed after every retry ({2} failed call(s)). Their permissions are UNKNOWN and were published EMPTY -- their tier may be too LOW. Re-run to recover them. First error: {3}' -f $principals, $Label, $f.Count, $first)
    if (Get-Command -Name 'Write-SIWarn' -ErrorAction SilentlyContinue) { Write-SIWarn $msg } else { Write-Warning $msg }
}

function Get-SISPAppRoleAssignments {
    # Per-SP: Application-permission grants (admin-consented). Returns the
    # human-readable permission Values resolved via the AppRole resolver.
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$AppRoleResolver
    )
    $perms = New-Object System.Collections.ArrayList
    try {
        $rows = Invoke-SIGraphPaged -RelativeUrl ('/servicePrincipals/{0}/appRoleAssignments' -f $ObjectId) -Token $Token
    } catch {
        # Still returns empty (the row must ship), but the failure is COUNTED so the run can say how many
        # principals have UNKNOWN permissions -- it used to vanish, and an SP holding e.g.
        # RoleManagement.ReadWrite.Directory was published as having none (#125).
        Add-SIPermissionFetchFailure -Kind 'application' -ObjectId $ObjectId -Message $_.Exception.Message
        return @()
    }
    foreach ($a in $rows) {
        $resourceId = [string]$a.resourceId
        $appRoleId  = [string]$a.appRoleId
        if (-not $resourceId -or -not $appRoleId) { continue }
        $val = $AppRoleResolver[("{0}|{1}" -f $resourceId, $appRoleId)]
        if ($val -and -not ($perms -contains $val)) { [void]$perms.Add($val) }
    }
    return $perms.ToArray()
}

function Get-SIRoleAssignedGroups {
    # identifies which GROUPS hold Entra directory roles (permanent
    # or PIM eligible). Output: @{<groupId> = @{Permanent=@(role); Eligible=@(role)}}.
    # We fetch group object types for all principalIds that appear in role
    # assignments (one /directoryObjects/getByIds batch) so we can filter to
    # actual groups (vs users + SPs in the same buckets).
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$PermanentRolesByPrincipal,    # from Get-SIEntraRoleAssignmentsByPrincipal
        [Parameter(Mandatory)][hashtable]$EligibleRolesByPrincipal      # from Get-SIEntraPIMEligibleByPrincipal
    )
    if ($script:_SICache.ContainsKey('GroupRoles')) { Write-SIInfo '[perms] role-assigned groups (cache hit)'; return $script:_SICache['GroupRoles'] }

    # Union of all principal IDs that appear in either map
    $allIds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($id in $PermanentRolesByPrincipal.Keys) { [void]$allIds.Add($id) }
    foreach ($id in $EligibleRolesByPrincipal.Keys)  { [void]$allIds.Add($id) }
    if ($allIds.Count -eq 0) { Set-SIEntraRoleReadPart -Part 'GroupTypes' -Complete $true; return @{} }

    # /directoryObjects/getByIds is capped at 1000 per call; chunk + batch.
    $idArr = @($allIds)
    $byType = @{}        # principalId -> @odata.type ('#microsoft.graph.group' | '...user' | '...servicePrincipal')
    for ($i = 0; $i -lt $idArr.Count; $i += 1000) {
        $chunk = $idArr[$i..([Math]::Min($i+999, $idArr.Count-1))]
        $body  = @{ ids = $chunk; types = @('group','user','servicePrincipal') } | ConvertTo-Json -Compress
        try {
            $resp = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' `
                -Headers @{ Authorization = ('Bearer ' + $Token); 'Content-Type' = 'application/json' } `
                -Body $body -ErrorAction Stop
            foreach ($obj in $resp.value) {
                if ($obj.id -and $obj.'@odata.type') { $byType[[string]$obj.id] = [string]$obj.'@odata.type' }
                # the display name of every principal that holds a role (role paths name the group: "Group X -> role")
                if ($obj.id -and $obj.PSObject.Properties['displayName'] -and $obj.displayName) {
                    if (-not $script:_SICache.ContainsKey('RolePrincipalNames')) { $script:_SICache['RolePrincipalNames'] = @{} }
                    $script:_SICache['RolePrincipalNames'][[string]$obj.id] = [string]$obj.displayName
                }
            }
        } catch {
            Write-Warning ('directoryObjects/getByIds failed -- {0}' -f $_.Exception.Message)
            Set-SIEntraRoleReadPart -Part 'GroupTypes' -Complete $false -ErrorText $_.Exception.Message
        }
    }

    # Filter to GROUPS only and emit @{groupId = @{Permanent=...; Eligible=...}}
    $result = @{}
    foreach ($id in $allIds) {
        if ($byType[$id] -ne '#microsoft.graph.group') { continue }
        $perm = if ($PermanentRolesByPrincipal.ContainsKey($id)) { @($PermanentRolesByPrincipal[$id]) } else { @() }
        $elig = if ($EligibleRolesByPrincipal.ContainsKey($id))  { @($EligibleRolesByPrincipal[$id])  } else { @() }
        $result[$id] = @{ Permanent = $perm; Eligible = $elig }
    }
    Set-SIEntraRoleReadPart -Part 'GroupTypes' -Complete $true      # AND-ed with a chunk that failed above
    $script:_SICache['GroupRoles'] = $result
    return $result
}

function Get-SIGroupTransitiveMembers {
    # for each role-assigned group, fetch transitiveMembers and
    # invert to @{<userOrSpId> = HashSet[<groupId>]} so per-asset lookup is O(1).
    # Only role-assigned groups are queried (typical tenant: 10-50 groups, not 1000s).
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap   # from Get-SIRoleAssignedGroups
    )
    if ($script:_SICache.ContainsKey('MemberToGroups')) { Write-SIInfo '[perms] group transitive members (cache hit)'; return $script:_SICache['MemberToGroups'] }
    $byMember = @{}     # userOrSpId -> HashSet[groupId]
    foreach ($gid in $RoleAssignedGroupMap.Keys) {
        try {
            # LIST KEPT: membership only -- the member ids of one group
            $rows = Invoke-SIGraphPaged -RelativeUrl ('/groups/{0}/transitiveMembers?$select=id' -f $gid) -Token $Token
        } catch {
            Write-Warning ('transitiveMembers failed for group {0}: {1}' -f $gid, $_.Exception.Message)
            Set-SIEntraRoleReadPart -Part 'GroupMembers' -Complete $false -ErrorText $_.Exception.Message
            continue
        }
        # #899: a member answered twice is said (a WARNING only; the read is used as read)
        $gw = New-SIIdDuplicateWatch -Label ('transitive members of role-holding group {0}' -f $gid); Add-SIIdDuplicateWatch -Watch $gw -Rows @($rows); $null = Write-SIIdDuplicateWarning $gw
        foreach ($m in $rows) {
            $mid = [string]$m.id
            if (-not $mid) { continue }
            if (-not $byMember.ContainsKey($mid)) { $byMember[$mid] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$byMember[$mid].Add($gid)
        }
    }
    Set-SIEntraRoleReadPart -Part 'GroupMembers' -Complete $true      # AND-ed with a group that failed above
    $script:_SICache['MemberToGroups'] = $byMember
    return $byMember
}

function Get-SIPimForGroupsByPrincipal {
    # PIM-for-Groups: principals who are PIM-eligible OR have PIM-active membership
    # in a role-bearing group, but are NOT current static members. Without this,
    # users who can elevate INTO a role-bearing group (without being in it) are
    # missing from EntraRoles_Eligible.
    #
    # Two endpoints, both per-group (with $filter=groupId):
    #   /identityGovernance/privilegedAccess/group/eligibilitySchedules  -- not yet activated
    #   /identityGovernance/privilegedAccess/group/assignmentSchedules   -- already activated
    #
    # Both treated as "Eligible" downstream because the principal still requires
    # activation/membership-grant to actually USE the role.
    #
    # Returns @{<principalId> = HashSet[<groupId>]}
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap   # from Get-SIRoleAssignedGroups
    )
    if ($script:_SICache.ContainsKey('PimForGroupsMap')) { Write-SIInfo '[perms] PIM for Groups (cache hit)'; return $script:_SICache['PimForGroupsMap'] }
    Write-SIInfo ('[perms] PIM for Groups: scanning {0} role-bearing group(s)...' -f $RoleAssignedGroupMap.Count)
    $byPrincipal = @{}
    $totalRows = 0
    $_pimTotal = $RoleAssignedGroupMap.Count; $_pimIdx = 0
    Reset-SIProgress -Label 'PimForGroups' -ErrorAction SilentlyContinue
    foreach ($gid in $RoleAssignedGroupMap.Keys) {
        $_pimIdx++
        try { Write-SIProgress -Label 'PimForGroups' -Index $_pimIdx -Total $_pimTotal } catch { }
        foreach ($endpoint in @('eligibilitySchedules','assignmentSchedules')) {
            try {
                # LIST KEPT: membership only -- who is eligible for or assigned to the group
                $rows = Invoke-SIGraphPaged -RelativeUrl ("/identityGovernance/privilegedAccess/group/{0}?`$filter=groupId eq '{1}'&`$select=principalId,groupId" -f $endpoint, $gid) -Token $Token
            } catch {
                # Tenant may lack Entra ID P2; skip silently per group/endpoint -- but the read is then NOT complete: who
                # can elevate into a role-bearing group is unknown (shadow-admin guard)
                Set-SIEntraRoleReadPart -Part 'PimForGroups' -Complete $false -ErrorText $_.Exception.Message
                continue
            }
            foreach ($r in $rows) {
                $principalId = [string]$r.principalId
                if (-not $principalId) { continue }
                if (-not $byPrincipal.ContainsKey($principalId)) {
                    $byPrincipal[$principalId] = New-Object System.Collections.Generic.HashSet[string]
                }
                if ($byPrincipal[$principalId].Add($gid)) { $totalRows++ }
            }
        }
    }
    Write-SIInfo ('[perms] PIM for Groups loaded: {0} principal->group entries across {1} principals' -f $totalRows, $byPrincipal.Count)
    Set-SIEntraRoleReadPart -Part 'PimForGroups' -Complete $true      # AND-ed with a group / endpoint that failed above
    # who is a member of a role-holding group only while a membership is activated: one more read per group, kept for the
    # run (Get-SIInheritedRolesForPrincipal and the identity context read it from there). It never fails this scan.
    try { $null = Get-SIPimGroupActivatedMemberships -Token $Token -RoleAssignedGroupMap $RoleAssignedGroupMap } catch { Write-Verbose ('activated group memberships not read: {0}' -f $_.Exception.Message) }
    $script:_SICache['PimForGroupsMap'] = $byPrincipal
    return $byPrincipal
}

function Get-SIPimGroupActivationKey {
    <# PURE. The key one membership of a group is found by: '<principal id>|<group id>' (lower case). #>
    param([AllowNull()][AllowEmptyString()][string]$PrincipalId, [AllowNull()][AllowEmptyString()][string]$GroupId)
    '{0}|{1}' -f ([string]$PrincipalId).Trim().ToLowerInvariant(), ([string]$GroupId).Trim().ToLowerInvariant()
}

function Get-SIPimGroupActivatedMemberships {
    <#
        WHO IS A MEMBER OF A ROLE-HOLDING GROUP ONLY BECAUSE AN ELIGIBLE MEMBERSHIP IS ACTIVATED RIGHT NOW (Privileged
        Identity Management for Groups). The roles such a member holds through that group are ELIGIBLE roles, with until
        when the activation lasts -- the same rule as an activated directory role (Get-SIEntraActivatedRoleAssignments).
        ONE paged read per role-holding group (the group's assignment schedule instances; never one per user), cached for
        the run. The permission the PIM for Groups scan already uses reads it (PrivilegedAccess.Read.AzureADGroup).
        A member counts as activated only when the group's instances hold an activated membership for it and NO assigned
        one (a member that is also assigned stays permanent). An activated OWNER is not a member: nothing changes for it
        (it is already counted as able to activate into the group).
        Returns @{ Complete; Error; Groups; ByKey = @{ <Get-SIPimGroupActivationKey> = <end of the activation, ISO text or ''> } }.
        -CacheOnly: what this run already read, or $null (no read is made).
        NEVER THROWS, and never marks the role read incomplete: in a tenant without Privileged Identity Management for
        Groups, or when the read is refused, no activation can be told apart -- every member then counts through the group
        exactly as before this read existed (active = permanent), said once.
    #>
    param([string]$Token = '', [hashtable]$RoleAssignedGroupMap = @{}, [switch]$CacheOnly)
    if ($script:_SICache -and $script:_SICache.ContainsKey('PimGroupActivations')) { return $script:_SICache['PimGroupActivations'] }
    if ($CacheOnly) { return $null }
    $state = @{ Complete = $true; Error = ''; Groups = 0; ByKey = @{} }
    foreach ($gid in @($RoleAssignedGroupMap.Keys)) {
        if (-not $gid) { continue }
        $rows = $null
        try {
            # the group's instances as the service returns them (no property list): which membership is an activation and
            # until when; only the principal, the kind of access, the kind of assignment and the end are used
            $rows = Invoke-SIGraphPaged -RelativeUrl ("/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '{0}'" -f $gid) -Token $Token
        } catch {
            $state.Complete = $false
            if (-not $state.Error) { $state.Error = [string]$_.Exception.Message }
            $status = 0; try { $status = Get-SIGraphHttpStatus -ErrorRecord $_ } catch { $status = 0 }
            # refused for the tenant (no licence, no permission): every group answers the same -- stop asking
            if ($status -in 401, 403) { break }
            continue
        }
        $state.Groups++
        $assigned = New-Object 'System.Collections.Generic.HashSet[string]'
        $activated = @{}
        foreach ($r in @($rows)) {
            if ($null -eq $r) { continue }
            $pp = $r.PSObject.Properties['principalId']
            if (-not $pp -or -not $pp.Value) { continue }
            # an owner is not a member: the group's roles are not held through an ownership
            $ap = $r.PSObject.Properties['accessId']
            if ($ap -and $ap.Value -and ([string]$ap.Value) -ne 'member') { continue }
            $key = Get-SIPimGroupActivationKey -PrincipalId ([string]$pp.Value) -GroupId ([string]$gid)
            $tp = $r.PSObject.Properties['assignmentType']; $type = ''; if ($tp -and $tp.Value) { $type = ([string]$tp.Value).ToLowerInvariant() }
            if ($type -ne 'activated') { [void]$assigned.Add($key); continue }
            $ep = $r.PSObject.Properties['endDateTime']; $end = ''
            if ($ep -and $null -ne $ep.Value) { if ($ep.Value -is [datetime]) { $end = $ep.Value.ToUniversalTime().ToString('o') } else { $end = [string]$ep.Value } }
            $activated[$key] = $end
        }
        foreach ($k in @($activated.Keys)) { if (-not $assigned.Contains($k)) { $state.ByKey[$k] = $activated[$k] } }
    }
    if (-not $state.Complete) {
        Write-SIInfo ('[perms] activated group memberships: not read for every role-holding group ({0}) -- a member of a group that could not be read counts through it as before (active = permanent)' -f $state.Error)
    } elseif ($state.Groups -gt 0) {
        Write-SIInfo ('[perms] activated group memberships: {0} membership(s) of {1} role-holding group(s) exist only while activated -- their roles through the group count as eligible' -f $state.ByKey.Count, $state.Groups)
    }
    $script:_SICache['PimGroupActivations'] = $state
    return $state
}

function Get-SIRolesViaPimGroupChain {
    # Recursive expansion of nested PIM-for-Groups chains. Mirrors the v1
    # Get-AllGroupRoles helper. Loop-safe via $Visited.
    #   User -> PIM Group A (eligible) -> PIM Group B (eligible) -> Role
    # All roles surfaced via this chain are Eligible (the principal still
    # has to activate to become a member).
    # AllowEmptyCollection() on the HashSet params -- PS Mandatory binding
    # otherwise rejects an empty HashSet from the first call (no eligible
    # roles found yet, no groups visited yet).
    param(
        [Parameter(Mandatory)][string[]]$GroupIds,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Eligible,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Visited,
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap,
        [Parameter(Mandatory)][hashtable]$PimGroupsByPrincipal
    )
    foreach ($gid in $GroupIds) {
        if (-not $Visited.Add($gid)) { continue }
        # Roles attached directly to this group -- both Permanent + Eligible go to Eligible
        # (because the principal isn't a current member; activation is required either way).
        if ($RoleAssignedGroupMap.ContainsKey($gid)) {
            $g = $RoleAssignedGroupMap[$gid]
            foreach ($r in $g.Permanent) { [void]$Eligible.Add([string]$r) }
            foreach ($r in $g.Eligible)  { [void]$Eligible.Add([string]$r) }
        }
        # Recurse: this group itself may be PIM-eligible to BECOME a member of another group.
        if ($PimGroupsByPrincipal.ContainsKey($gid)) {
            $nested = @($PimGroupsByPrincipal[$gid] | Where-Object { -not $Visited.Contains($_) })
            if ($nested.Count -gt 0) {
                Get-SIRolesViaPimGroupChain -GroupIds $nested -Eligible $Eligible `
                                             -Visited $Visited `
                                             -RoleAssignedGroupMap $RoleAssignedGroupMap `
                                             -PimGroupsByPrincipal $PimGroupsByPrincipal
            }
        }
    }
}

function Get-SIInheritedRolesForPrincipal {
    # Per-principal: walk the principal's role-via-group inheritance:
    #   1. Active transitive membership in role-bearing groups
    #   2. PIM-for-Groups eligibility/active (recursive nested chains)
    # Returns @{Permanent=string[]; Eligible=string[]}.
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$MemberToGroupsMap,        # from Get-SIGroupTransitiveMembers
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap,     # from Get-SIRoleAssignedGroups
        [hashtable]$PimGroupsByPrincipal = @{},                     # from Get-SIPimForGroupsByPrincipal (optional for back-compat)
        # '<principal id>|<group id>' -> until when (Get-SIPimGroupActivatedMemberships); not given = what this run read
        [hashtable]$ActivatedGroupMemberships = $null
    )
    if ($null -eq $ActivatedGroupMemberships) {
        $ActivatedGroupMemberships = @{}
        $actRead = Get-SIPimGroupActivatedMemberships -CacheOnly
        if ($actRead -and $actRead.ByKey) { $ActivatedGroupMemberships = $actRead.ByKey }
    }
    $perm    = New-Object System.Collections.Generic.HashSet[string]
    $elig    = New-Object System.Collections.Generic.HashSet[string]
    $visited = New-Object System.Collections.Generic.HashSet[string]

    # 1. Active membership -- principal IS a member, so direct roles flow through unchanged.
    if ($MemberToGroupsMap.ContainsKey($ObjectId)) {
        foreach ($gid in $MemberToGroupsMap[$ObjectId]) {
            [void]$visited.Add($gid)
            if (-not $RoleAssignedGroupMap.ContainsKey($gid)) { continue }
            $g = $RoleAssignedGroupMap[$gid]
            # A MEMBERSHIP THAT IS ACTIVATED RIGHT NOW IS AN ELIGIBLE ONE: the principal is a member only until the
            # activation ends, so every role it holds through this group is an eligible role, never a permanent one
            if ($ActivatedGroupMemberships.Count -gt 0 -and $ActivatedGroupMemberships.ContainsKey((Get-SIPimGroupActivationKey -PrincipalId $ObjectId -GroupId ([string]$gid)))) {
                foreach ($r in $g.Permanent) { [void]$elig.Add([string]$r) }
                foreach ($r in $g.Eligible)  { [void]$elig.Add([string]$r) }
                continue
            }
            foreach ($r in $g.Permanent) { [void]$perm.Add([string]$r) }
            foreach ($r in $g.Eligible)  { [void]$elig.Add([string]$r) }
        }
    }

    # 2. PIM-for-Groups -- principal can ELEVATE into the group; everything from this
    #    chain is Eligible. Recursive helper handles nested PIM-into-PIM.
    if ($PimGroupsByPrincipal.ContainsKey($ObjectId)) {
        $eligibleGroupIds = @($PimGroupsByPrincipal[$ObjectId] | Where-Object { -not $visited.Contains($_) })
        if ($eligibleGroupIds.Count -gt 0) {
            Get-SIRolesViaPimGroupChain -GroupIds $eligibleGroupIds -Eligible $elig `
                                         -Visited $visited `
                                         -RoleAssignedGroupMap $RoleAssignedGroupMap `
                                         -PimGroupsByPrincipal $PimGroupsByPrincipal
        }
    }

    return @{ Permanent = @($perm); Eligible = @($elig) }
}

function Get-SIAzureDelegationsByPrincipal {
    # Azure RBAC role assignments by ObjectId, scope-aware
    # tier (Max(RoleTier, ScopeLevel)) precomputed per assignment. Mirrors
    # legacy IAC's $azureDelegationLookup. Uses Az.Resources cmdlets --
    # caller must have run Connect-AzAccount.
    # Returns @{<objectId> = @(@{RoleName, Scope, ScopeLabel, SubscriptionId,
    #                            SubscriptionName, PrincipalType, PrincipalName,
    #                            RoleTier, ScopeLevel, EffectiveTier})}
    [CmdletBinding()]
    param(
        [string[]]$ExcludeSubscriptionPatterns = @()
    )
    if ($script:_SICache.ContainsKey('AzureLookup')) { Write-SIInfo '[perms] Azure RBAC delegations (cache hit)'; return $script:_SICache['AzureLookup'] }
    $lookup = @{}
    $count  = 0

    # Tier helpers need to be loaded (catalog computer dot-sources at module init)
    if (-not (Get-Command Get-SITierFromAzureRoles -ErrorAction SilentlyContinue)) {
        $catModule = Join-Path $PSScriptRoot 'IdentityCatalogTierComputer.ps1'
        if (Test-Path $catModule) {
            . $catModule
            Initialize-SIIdentityCatalog | Out-Null
        } else {
            Write-Warning 'Get-SIAzureDelegationsByPrincipal: catalog tier computer not loaded; skipping.'
            return $lookup
        }
    }

    try {
        $subs = @(Get-SIAzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
    } catch {
        Write-Warning ('Get-AzSubscription failed -- Azure delegations skipped: {0}' -f $_.Exception.Message)
        return $lookup
    }

    if ($ExcludeSubscriptionPatterns.Count -gt 0) {
        $subs = @($subs | Where-Object {
            $sn = $_.Name
            -not ($ExcludeSubscriptionPatterns | Where-Object { $sn -like $_ })
        })
    }
    Write-SIInfo ('[perms] Azure RBAC: scanning {0} subscription(s) for role assignments' -f $subs.Count)

    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    $failedSubs = 0; $firstFail = ''
    try {
        foreach ($sub in $subs) {
            $assignments = $null   # one subscription's answer at a time (#702: memory follows a subscription, not the tenant)
            try {
                Set-SIAzContext -SubscriptionId $sub.Id -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                $assignments = @(Get-SIAzRoleAssignment -ErrorAction Stop -WarningAction SilentlyContinue)
            } catch {
                # #702: OUT OF MEMORY is not one subscription's problem -- the process can no longer read anything correctly
                # (customer B 2026-10-15: 773 "role-assignment read failed" lines over 76 minutes, then every later read failed the
                # same way). It stops the source here, and the source's failure stops the collection (Invoke-Discover).
                if ((Get-Command -Name Test-SIOutOfMemoryText -ErrorAction SilentlyContinue) -and (Test-SIOutOfMemoryText $_)) {
                    throw ('Azure RBAC: the process ran out of memory reading the role assignments of subscription {0} ({1} of {2}) -- {3}' -f $sub.Name, ([array]::IndexOf($subs, $sub) + 1), $subs.Count, $_.Exception.Message)
                }
                $failedSubs++; if (-not $firstFail) { $firstFail = [string]$_.Exception.Message }
                Write-Warning ('  sub {0}: role-assignment read failed -- {1}' -f $sub.Name, $_.Exception.Message)
                continue
            }
            foreach ($a in $assignments) {
                $oid = [string]$a.ObjectId
                if ([string]::IsNullOrWhiteSpace($oid)) { continue }
                $roleName = [string]$a.RoleDefinitionName
                $scope    = [string]$a.Scope
                $roleTier = Get-SITierFromAzureRoles -Roles @($roleName)
                if ($null -eq $roleTier) { $roleTier = 2 }
                $scopeLvl = Get-SIAzureScopeLevel  -Scope $scope
                $effTier  = [Math]::Max($roleTier, $scopeLvl)
                $entry = [ordered]@{
                    RoleName         = $roleName
                    Scope            = $scope
                    ScopeLabel       = Get-SIAzureScopeLabel -Scope $scope
                    SubscriptionId   = [string]$sub.Id
                    SubscriptionName = [string]$sub.Name
                    PrincipalType    = [string]$a.ObjectType
                    PrincipalName    = [string]$a.DisplayName
                    RoleTier         = $roleTier
                    ScopeLevel       = $scopeLvl
                    EffectiveTier    = $effTier
                }
                if (-not $lookup.ContainsKey($oid)) { $lookup[$oid] = New-Object System.Collections.ArrayList }
                [void]$lookup[$oid].Add($entry)
                $count++
            }
        }
    } finally {
        $ProgressPreference = $prevProgress
    }
    if ($failedSubs -gt 0) {
        # never fewer silently: the Azure roles held in those subscriptions are UNKNOWN this run, not absent
        Write-Warning ('  Azure RBAC: the role assignments of {0} of {1} subscription(s) could not be read (first: {2}) -- the Azure roles held there are UNKNOWN this run, not absent.' -f $failedSubs, $subs.Count, $firstFail)
    }
    Write-SIInfo ('[perms] Azure RBAC delegations: {0} assignments across {1} principals' -f $count, $lookup.Count)
    $script:_SICache['AzureLookup'] = $lookup
    return $lookup
}

function Test-SIIdentityInfoTableAbsent {
    <# PURE. Is this Log Analytics error the workspace saying it has NO IdentityInfo table (SEM0100 "Failed to resolve
       table or column expression named 'IdentityInfo'")? Any other failure of the IdentityInfo read is $false. #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    [string]$Message -match "(?i)Failed to resolve table or column expression named 'IdentityInfo'"
}

function Get-SIIdentityInfoByObjectId {
    # bulk pull Defender XDR IdentityInfo (synced from on-prem AD +
    # Entra) and bucket by AccountObjectId for O(1) per-user lookup. Returns
    # @{<userObjectId> = <IdentityInfo row>} where each row carries:
    #   GroupMembership   (string, comma-separated on-prem AD groups)
    #   IsMFARegistered, IsAccountEnabled, IsServiceAccount
    #   RiskLevel, RiskState, EntityRiskScore, BlastRadius
    #   InvestigationPriority, AssignedRoles
    #   AccountUPN, AccountDisplayName, OnPremisesDistinguishedName
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [int]$LookbackDays = 14
    )
    if ($script:_SICache.ContainsKey('IdentityInfo')) { Write-SIInfo '[perms] IdentityInfo (cache hit)'; return $script:_SICache['IdentityInfo'] }
    $byOid = @{}
    if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
        Write-Warning '$global:SI_WorkspaceResourceId not set -- IdentityInfo fetch skipped.'
        return $byOid
    }
    try {
        $ws = Resolve-SIWorkspaceFromResourceId -ResourceId $WorkspaceResourceId
        $wsGuid = $ws.CustomerId.Guid
    } catch {
        Write-Warning ('Workspace resolve failed -- IdentityInfo skipped: {0}' -f $_.Exception.Message)
        return $byOid
    }

    $kql = @"
IdentityInfo
| where TimeGenerated > ago($($LookbackDays)d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| project AccountObjectId, AccountUPN, AccountDisplayName, AccountSID, AccountCloudSID,
          OnPremisesAccountObjectId, OnPremisesDistinguishedName, AccountDomain,
          IsAccountEnabled, IsMFARegistered, IsServiceAccount,
          AssignedRoles, GroupMembership,
          BlastRadius, Tags, Manager = tostring(column_ifexists("Manager", "")),
          InvestigationPriority, InvestigationPriorityPercentile,
          RiskLevel, RiskState, EntityRiskScore,
          AccountCreationTime, DeletedDateTime, LastSeenDate
"@

    try {
        # #639 lane 4: one row per user (millions at a large tenant) -- read in parts when one answer cannot carry it; a cut
        # answer is refused (the read is then not complete, below), never taken as every user
        $resp = Read-SILaParts -WorkspaceId $wsGuid -Query $kql -Key 'AccountObjectId' -What 'IdentityInfo' -Log { param($l, $m) Write-SIInfo ('[perms] ' + $m) }
    } catch {
        $iiMsg = [string]$_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $iiMsg = $iiMsg + ' ' + [string]$_.ErrorDetails.Message }
        if (Test-SIIdentityInfoTableAbsent -Message $iiMsg) {
            # The workspace has no IdentityInfo table: the source that fills it (Microsoft Defender for Identity / the
            # Defender XDR connector) is not connected there. That is a fact about the tenant, not a failed read -- said
            # once per run, plainly, and recorded with its own code; a table that exists and fails stays a failure below.
            Write-SIInfo '[perms] Defender for Identity: this workspace has no IdentityInfo table (the source that fills it is not connected), so on-premises groups and identity risk signals are not read. This is not an error.'
            $script:_SICache['IdentityInfo'] = $byOid
            $script:_SICache['IdentityInfoState'] = [pscustomobject]@{ Complete = $false; Error = ''; Code = 'source-not-present'; Text = 'the IdentityInfo table is not in the workspace (source not present)' }
            return $byOid
        }
        Write-Warning ('IdentityInfo query failed -- AD groups + activity signals will be empty: {0}' -f $_.Exception.Message)
        $script:_SICache['IdentityInfoState'] = [pscustomobject]@{ Complete = $false; Error = [string]$_.Exception.Message }
        return $byOid
    }

    foreach ($row in @($resp.Rows)) {
        $oid = [string]$row.AccountObjectId
        if ([string]::IsNullOrWhiteSpace($oid)) { continue }
        $byOid[$oid] = $row
    }
    Write-SIInfo ('[perms] IdentityInfo: {0} users with on-prem / Defender enrichment' -f $byOid.Count)
    # the investigation priority is UEBA's (BehaviorAnalytics.InvestigationPriority, per activity); IdentityInfo leaves its
    # percentile empty -- internal 2026-10-15: si_mdi_investigation_priority_pct on 0 of 6,943 identities, BehaviorAnalytics
    # scores 21 users (the 3 at or above the 90th percentile were missing from Identity_HighMDIInvestigationPriority)
    $hasPct = $false
    foreach ($row in $byOid.Values) {
        if ($row.PSObject.Properties['InvestigationPriorityPercentile'] -and -not [string]::IsNullOrWhiteSpace([string]$row.InvestigationPriorityPercentile)) { $hasPct = $true; break }
    }
    if (-not $hasPct -and $byOid.Count -gt 0) { Add-SIIdentityInvestigationPriority -ByOid $byOid -WorkspaceId $wsGuid -LookbackDays 30 }
    $script:_SICache['IdentityInfo'] = $byOid
    # the v3 Defender for Identity record pull (Get-DiscoveryFromEntraUsers: Set-SIRecordPull -Provider mdi)
    $script:_SICache['IdentityInfoState'] = [pscustomobject]@{ Complete = $true; Error = '' }
    return $byOid
}

function ConvertTo-SIInvestigationPriorityPercentile {
    <#
        PURE. @{ <objectId> = <the user's highest investigation priority> } -> @{ <objectId> = <percentile 0..100> }: the
        share of the scored users whose priority is at or below this user's (rounded down), 0 for a priority of 0. A
        percentile of 90 or more then holds exactly for a priority at or above the 90th percentile (nearest rank) of the
        users UEBA scored -- what the investigation-priority report asks.
    #>
    param([hashtable]$MaxByOid)
    $out = @{}
    if ($null -eq $MaxByOid -or $MaxByOid.Count -eq 0) { return $out }
    $n = $MaxByOid.Count
    $countByValue = @{}
    foreach ($v in $MaxByOid.Values) { $d = [double]$v; if ($countByValue.ContainsKey($d)) { $countByValue[$d]++ } else { $countByValue[$d] = 1 } }
    $atOrBelow = @{}; $run = 0
    foreach ($d in @($countByValue.Keys | Sort-Object)) { $run += $countByValue[$d]; $atOrBelow[$d] = $run }
    foreach ($k in @($MaxByOid.Keys)) {
        $d = [double]$MaxByOid[$k]
        if ($d -le 0) { $out[$k] = 0; continue }
        $out[$k] = [int][Math]::Floor(100.0 * $atOrBelow[$d] / $n)
    }
    return $out
}

function Add-SIIdentityInvestigationPriority {
    <#
        UEBA's investigation priority onto the IdentityInfo rows (-ByOid, from Get-SIIdentityInfoByObjectId): each user's
        highest BehaviorAnalytics.InvestigationPriority over -LookbackDays and its percentile among the scored users, as the
        row's InvestigationPriority / InvestigationPriorityPercentile when the row has none -- the Defender for Identity
        record part the mdi mapping reads (si_mdi_investigation_priority_pct). The same workspace and the same read as
        IdentityInfo; a workspace without UEBA leaves the rows as they are (said once).
    #>
    param([Parameter(Mandatory)][hashtable]$ByOid, [Parameter(Mandatory)][string]$WorkspaceId, [int]$LookbackDays = 30)
    $kql = @"
BehaviorAnalytics
| where TimeGenerated > ago($($LookbackDays)d)
| extend _oid = tolower(tostring(UsersInsights.AccountObjectID))
| where isnotempty(_oid) and isnotempty(UserPrincipalName)
| summarize MaxPriority = max(InvestigationPriority) by _oid
"@
    # #639 lane 4: one row per scored user -- read in parts when one answer cannot carry it (a cut answer is refused)
    try { $resp = Read-SILaParts -WorkspaceId $WorkspaceId -Query $kql -Key '_oid' -What 'BehaviorAnalytics' -Log { param($l, $m) Write-SIInfo ('[perms] ' + $m) } }
    catch { Write-Warning ('BehaviorAnalytics could not be read -- the investigation priority stays empty: {0}' -f $_.Exception.Message); return }
    $max = @{}
    foreach ($r in @($resp.Rows)) {
        $o = ([string]$r._oid).Trim().ToLowerInvariant()
        $p = ConvertTo-SINumberOrNullLocal ([string]$r.MaxPriority)
        if ($o -and $null -ne $p) { $max[$o] = $p }
    }
    if ($max.Count -eq 0) { Write-SIInfo '[perms] BehaviorAnalytics: no scored users -- the investigation priority stays empty'; return }
    $pct = ConvertTo-SIInvestigationPriorityPercentile -MaxByOid $max
    $set = 0
    foreach ($k in @($ByOid.Keys)) {
        $o = ([string]$k).Trim().ToLowerInvariant()
        if (-not $max.ContainsKey($o)) { continue }
        $row = $ByOid[$k]
        foreach ($pair in @(@('InvestigationPriority', $max[$o]), @('InvestigationPriorityPercentile', $pct[$o]))) {
            $prop = $row.PSObject.Properties[$pair[0]]
            if ($null -eq $prop) { $row | Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1] -Force }
            elseif ([string]::IsNullOrWhiteSpace([string]$prop.Value)) { $prop.Value = $pair[1] }
        }
        $set++
    }
    Write-SIInfo ('[perms] BehaviorAnalytics: investigation priority for {0} of {1} scored users' -f $set, $max.Count)
}

function ConvertTo-SINumberOrNullLocal {
    <# PURE. Text -> double, or $null when it is not a number (invariant culture). #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $d = 0.0
    if ([double]::TryParse($Text, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    return $null
}

function ConvertTo-SIADGroupNames {
    # IdentityInfo.GroupMembership is a JSON array string of {GroupName, GroupSID, GroupType}.
    # Some tenants ship it as a plain string, other as the JSON. Normalise to string[].
    param($Raw)
    if ($null -eq $Raw)                           { return @() }
    if ($Raw -is [System.Array]) {
        return @($Raw | ForEach-Object {
            if ($_ -is [System.Collections.IDictionary] -and $_.Contains('GroupName')) { [string]$_['GroupName'] }
            elseif ($_.PSObject -and $_.PSObject.Properties['GroupName']) { [string]$_.GroupName }
            else { [string]$_ }
        } | Where-Object { $_ })
    }
    $s = [string]$Raw
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    # Try JSON parse
    try {
        $obj = $s | ConvertFrom-Json -ErrorAction Stop
        if ($obj -is [System.Array]) {
            return @($obj | ForEach-Object {
                if ($_.PSObject.Properties['GroupName']) { [string]$_.GroupName } else { [string]$_ }
            } | Where-Object { $_ })
        }
    } catch { }
    # Fallback: comma-separated
    return @($s -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-SISpnSignInLastActivity {
    <#
        Bulk-fetch SP last sign-in. Returns @{<spObjectId> = <DateTime>}.

        cascade three sources -- try Defender XDR's modern GA
        EntraIdSpnSignInEvents first; fall back to AADSpnSignInEventsBeta;
        lastly fall back to LA AADServicePrincipalSignInLogs +
        AADManagedIdentitySignInLogs (the original v2.1 path). Errors only
        surface if all three fail. WorkspaceResourceId param kept for API
        compatibility but unused now -- routing handled by Invoke-SIHuntingQuery.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [int]$LookbackDays = 90
    )
    if ($script:_SICache.ContainsKey('SpnSignIn')) { Write-SIInfo '[perms] SP sign-in (cache hit)'; return $script:_SICache['SpnSignIn'] }
    $byOid = @{}
    $null = $WorkspaceResourceId   # explicit unused-but-required param

    # lazy-load HuntingQuery.ps1 -- IdentityRoleFetcher.ps1 may be
    # imported before HuntingQuery.ps1 in some launcher dot-source orders, so
    # Invoke-SIHuntingQuery isn't in scope yet. Mirrors the lazy-load pattern
    # in Build-EndpointProfileRow.ps1 for Get-SIRiskFactors / Convert-EgBlob.
    if (-not (Get-Command -Name Invoke-SIHuntingQuery -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'HuntingQuery.ps1')
    }

    # The service principal sign-in tables (EntraIdSpnSignInEvents, AADSpnSignInEventsBeta) name the principal
    # ServicePrincipalId -- they have NO AccountObjectId (that is the USER sign-in tables' column). Live 2026-10-23: both
    # Defender sources were refused on every run ("Failed to resolve scalar expression named 'AccountObjectId'") and the
    # sign-in dates came from the last fallback only.
    $xdrTail = @"
| where Timestamp > ago($($LookbackDays)d)
| where isnotempty(ServicePrincipalId)
| project ServicePrincipalId, Timestamp
| summarize LastSignIn = max(Timestamp) by ServicePrincipalId
"@
    $laQuery = @"
union isfuzzy=true
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago($($LookbackDays)d)
        | project ServicePrincipalId, TimeGenerated
        | summarize LastSignIn = max(TimeGenerated) by ServicePrincipalId),
    (AADManagedIdentitySignInLogs
        | where TimeGenerated > ago($($LookbackDays)d)
        | project ServicePrincipalId, TimeGenerated
        | summarize LastSignIn = max(TimeGenerated) by ServicePrincipalId)
| summarize LastSignIn = max(LastSignIn) by ServicePrincipalId
"@

    $attempts = @(
        @{ Label = 'EntraIdSpnSignInEvents (XDR GA)';     Engine = 'DefenderGraph'; Query = "EntraIdSpnSignInEvents`n$xdrTail" },
        @{ Label = 'AADSpnSignInEventsBeta (XDR legacy)'; Engine = 'DefenderGraph'; Query = "AADSpnSignInEventsBeta`n$xdrTail" },
        @{ Label = 'AADServicePrincipalSignInLogs + AADManagedIdentitySignInLogs (LA)'; Engine = 'LogAnalytics'; Query = $laQuery }
    )

    # For LA route, target the Defender workspace (where AAD*SignInLogs live)
    # if customer has set SI_DefenderWorkspaceResourceId; else fall back to
    # SI_WorkspaceResourceId. Defender XDR routes (DefenderGraph) ignore this --
    # they use the SPN's Graph token directly.
    $laTargetWs = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DefenderWorkspaceResourceId)) {
        [string]$global:SI_DefenderWorkspaceResourceId
    } else {
        [string]$global:SI_WorkspaceResourceId
    }

    $rows   = $null
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($a in $attempts) {
        $where = if ($a.Engine -eq 'LogAnalytics') { " (workspace=$laTargetWs)" } else { '' }
        Write-SIInfo ("[perms] SP sign-in source: trying {0}{1}..." -f $a.Label, $where)
        $w = $null
        $r = $null
        try {
            if ($a.Engine -eq 'LogAnalytics') {
                $r = @(Invoke-SIHuntingQuery -Query $a.Query -QueryEngine $a.Engine -WorkspaceResourceId $laTargetWs -WarningVariable w -WarningAction SilentlyContinue)
            } else {
                $r = @(Invoke-SIHuntingQuery -Query $a.Query -QueryEngine $a.Engine -WarningVariable w -WarningAction SilentlyContinue)
            }
        } catch {
            $errors.Add(("{0}: {1}" -f $a.Label, $_.Exception.Message))
            continue
        }
        if ($w -and $w.Count -gt 0) {
            $errors.Add(("{0}: {1}" -f $a.Label, ($w -join ' | ')))
            continue
        }
        # 0 ROWS FOR THE WHOLE TENANT IS NOT A COMPLETE READ (live 2026-10-23: the Log Analytics fallback answered 0 rows --
        # its tables empty / not ingested -- and every service principal was read as "no sign-in in 90 days"). A tenant's
        # service principals sign in all the time (managed identities, Microsoft's own); a source that holds none of it
        # does not know, so the next source is asked, and none answering is UNKNOWN.
        if ($r.Count -eq 0) {
            $errors.Add(("{0}: answered 0 rows for the whole tenant -- not a complete read" -f $a.Label))
            continue
        }
        $rows = $r
        Write-SIInfo ("[perms] SP sign-in source: OK -- {0} rows from {1}" -f $rows.Count, $a.Label)
        break
    }

    if ($null -eq $rows) {
        Write-SIWarn ('[perms] SP sign-in UNKNOWN this run: no source answered a sign-in for the tenant -- no service principal gets a sign-in verdict (never "no sign-in in {0} days")' -f $LookbackDays)
        foreach ($e in $errors) { Write-SIWarn ("  - {0}" -f $e) }
        $script:_SICache['SpnSignInKnown'] = $false
        $script:_SICache['SpnSignIn'] = $byOid
        return $byOid
    }
    $script:_SICache['SpnSignInKnown'] = $true

    foreach ($row in $rows) {
        $oid = [string]$row.ServicePrincipalId
        if (-not $oid) { continue }
        try { $byOid[$oid] = [datetime]$row.LastSignIn } catch { }
    }
    Write-SIInfo ('[perms] SP sign-in: {0} principals with sign-in activity in last {1}d' -f $byOid.Count, $LookbackDays)
    $script:_SICache['SpnSignIn'] = $byOid
    return $byOid
}

function Test-SISpnSignInKnown {
    <# Did this run's service principal sign-in lookup (Get-SISpnSignInLastActivity) read a source that answered? $false =
       UNKNOWN: a principal missing from the map has no sign-in verdict -- never "no sign-in". Before the lookup ran: $true. #>
    return ($script:_SICache['SpnSignInKnown'] -ne $false)
}

function ConvertTo-SICustomSecurityAttributes {
    # Normalises the customSecurityAttributes block (PSCustomObject of attribute
    # sets, each containing key/value pairs) into a clean dictionary, stripping
    # OData annotation keys. Returns @{} when none present.
    param($Raw)
    if ($null -eq $Raw) { return @{} }
    $result = [ordered]@{}
    $keys = if ($Raw -is [System.Collections.IDictionary]) { @($Raw.Keys) }
            else { @($Raw.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($setName in $keys) {
        if ($setName -like '*@odata*') { continue }
        $setBlock = if ($Raw -is [System.Collections.IDictionary]) { $Raw[$setName] } else { $Raw.$setName }
        if (-not $setBlock) { continue }
        $setResult = [ordered]@{}
        $setKeys = if ($setBlock -is [System.Collections.IDictionary]) { @($setBlock.Keys) }
                   else { @($setBlock.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $setKeys) {
            if ($k -like '*@odata*') { continue }
            $v = if ($setBlock -is [System.Collections.IDictionary]) { $setBlock[$k] } else { $setBlock.$k }
            if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
                $setResult[$k] = @($v | ForEach-Object { [string]$_ } | Where-Object { $_ })
            } else {
                $setResult[$k] = [string]$v
            }
        }
        if ($setResult.Count -gt 0) { $result[$setName] = $setResult }
    }
    return $result
}

function Get-SIDaysSince {
    param($DateValue)
    if (-not $DateValue) { return -1 }
    try {
        $d = if ($DateValue -is [datetime]) { $DateValue } else { [datetime]$DateValue }
        return [int]([datetime]::UtcNow - $d).TotalDays
    } catch { return -1 }
}

function Get-SIPrincipalAzureTier {
    # Per-principal: Min EffectiveTier across ObjectId + inherited group IDs.
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$AzureLookup,
        [string[]]$InheritedGroupIds = @()
    )
    $allIds = @($ObjectId) + @($InheritedGroupIds)
    $minTier = $null
    foreach ($id in $allIds) {
        if (-not $AzureLookup.ContainsKey($id)) { continue }
        foreach ($e in $AzureLookup[$id]) {
            $t = [int]$e.EffectiveTier
            if ($null -eq $minTier -or $t -lt $minTier) { $minTier = $t }
        }
    }
    return $minTier   # null when no Az delegations
}

function Get-SISPOauth2Grants {
    # Per-SP: Delegated-permission grants (oauth2). Permission strings are
    # already human-readable in the .scope field (space-separated).
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$ObjectId
    )
    $perms = New-Object System.Collections.ArrayList
    try {
        $rows = Invoke-SIGraphPaged -RelativeUrl ('/servicePrincipals/{0}/oauth2PermissionGrants' -f $ObjectId) -Token $Token
    } catch {
        Add-SIPermissionFetchFailure -Kind 'delegated' -ObjectId $ObjectId -Message $_.Exception.Message   # counted, see above (#125)
        return @()
    }
    foreach ($g in $rows) {
        if ($g.scope) {
            foreach ($s in ([string]$g.scope -split '\s+')) {
                if ($s -and -not ($perms -contains $s)) { [void]$perms.Add($s) }
            }
        }
    }
    return $perms.ToArray()
}

# Exposure Graph identity enrichment.
# Bulk-fetches EG nodes for identity NodeLabels (user, group, serviceprincipal,
# managedidentity) once per snapshot, indexes by AAD ObjectId so per-asset
# lookup is O(1). Mirrors the bulk-fetch + cache pattern of the other
# Get-SI* fetchers in this module.
#
# Returns @{ <aadObjectId> = pscustomobject{NodeId, NodeLabel, NodeName,
# Categories, EntityIds, RawData} }. The RawData field is the entire
# NodeProperties.rawData blob -- the schema-driven row builder
# (Build-IdentityProfileRow) walks arbitrary paths declared in
# identity.schema.json (source=exposureGraph, sourcePath=eg.node.NodeProperties.rawData.<path>).
# Adding a new EG-sourced flat column becomes a JSON edit, no engine code.
function Invoke-SIEgIdentityQuery {
    <#
        One Exposure Graph hunting query with retry, returning @{ Ok; Rows; Error }.
        The DefenderGraph route of Invoke-SIHuntingQuery signals failure with a WARNING and an empty
        result rather than an exception, so a failure has to be read from -WarningVariable (the same
        convention the SP sign-in lookup in this file uses). Retries throttles and transient failures
        with 5/15/45s backoff; never throws.
    #>
    param([Parameter(Mandatory)][string]$Query, [int]$MaxAttempts = 3, [int]$BackoffBaseSeconds = 5)
    $lastErr = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $w = $null; $r = $null
        try {
            $r = @(Invoke-SIHuntingQuery -Query $Query -QueryEngine DefenderGraph -WarningVariable w -WarningAction SilentlyContinue)
            if (-not $w -or @($w).Count -eq 0) { return @{ Ok = $true; Rows = $r; Error = $null } }
            $lastErr = (@($w) | ForEach-Object { [string]$_ }) -join ' | '
        } catch {
            $lastErr = [string]$_.Exception.Message
        }
        if ($attempt -lt $MaxAttempts) {
            $delay = [int]($BackoffBaseSeconds * [Math]::Pow(3, $attempt - 1))
            if ($delay -gt 0) { Start-Sleep -Seconds $delay }
        }
    }
    return @{ Ok = $false; Rows = @(); Error = $lastErr }
}

function Invoke-SIEgHuntingRequests {
    <#
        #882: the hunting queries sent to Microsoft Graph AT ONCE (one runHuntingQuery request each, all in flight together)
        -- one outcome per query, in order: @{ Ok; Rows; Status (0 = no answer); RetryAfter (seconds or $null); Error; Bytes
        (the answer's size) }. No client time limit of SI's own (the service ends a query at its own limit). Never throws.
        REST / .NET only.
    #>
    param([Parameter(Mandatory)][string]$Token, [string[]]$Queries = @())
    $out = New-Object System.Collections.Generic.List[object]
    if (@($Queries).Count -eq 0) { return , $out.ToArray() }
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch { }
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
    try {
        $tasks = New-Object System.Collections.Generic.List[object]
        foreach ($q in @($Queries)) {
            try {
                $req = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::Post), 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
                $req.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue 'Bearer', $Token
                # UTF-8 bytes with the charset declared (#114)
                $req.Content = New-Object System.Net.Http.StringContent ((ConvertTo-Json -InputObject @{ Query = [string]$q } -Compress)), ([System.Text.Encoding]::UTF8), 'application/json'
                $tasks.Add($client.SendAsync($req))
            } catch { $tasks.Add($_.Exception) }
        }
        foreach ($t in $tasks) {
            if ($t -is [System.Exception]) { $out.Add([pscustomobject]@{ Ok = $false; Rows = @(); Status = 0; RetryAfter = $null; Error = $t.Message; Bytes = 0L }); continue }
            try {
                $resp = $t.GetAwaiter().GetResult()
                $status = [int]$resp.StatusCode
                $ra = $null
                try { $rah = $resp.Headers.RetryAfter; if ($rah) { if ($null -ne $rah.Delta) { $ra = [int][Math]::Ceiling(([TimeSpan]$rah.Delta).TotalSeconds) } elseif ($null -ne $rah.Date) { $ra = [int][Math]::Max(0, [Math]::Ceiling((([DateTimeOffset]$rah.Date).UtcDateTime - [datetime]::UtcNow).TotalSeconds)) } } } catch { }
                $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $rows = @(); $ok = $false; $err = ''
                if ($status -eq 200) {
                    try { $p = $text | ConvertFrom-Json; $rows = if ($p.results) { @($p.results) } elseif ($p.Results) { @($p.Results) } else { @() }; $ok = $true } catch { $err = 'the answer could not be read: ' + $_.Exception.Message }
                } else { $err = ('{0} {1} {2}' -f $status, [string]$resp.ReasonPhrase, $(if ($text -and $text.Length -gt 400) { $text.Substring(0, 400) } else { $text })).Trim() }
                $out.Add([pscustomobject]@{ Ok = $ok; Rows = $rows; Status = $status; RetryAfter = $ra; Error = $err; Bytes = [long]([string]$text).Length })
                $resp.Dispose()
            } catch {
                $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
                $out.Add([pscustomobject]@{ Ok = $false; Rows = @(); Status = 0; RetryAfter = $null; Error = $m; Bytes = 0L })
            }
        }
    } finally { $client.Dispose() }
    , $out.ToArray()
}

function Update-SIEgIdentityConcurrency {
    <#
        PURE (changes -State). #882: how many hunting queries the next wave sends -- one more after a wave Microsoft answered
        without a 429, half (never below one) after a throttled one; never more than the measured memory allows (-State.Cap,
        0 = not measured). Returns the new number.
    #>
    param([Parameter(Mandatory)]$State, [bool]$Throttled)
    $c = [Math]::Max(1, [int]$State.Concurrency)
    if ($Throttled) { $c = [Math]::Max(1, [int][Math]::Floor($c / 2)); $State.ThrottledWaves = [int]$State.ThrottledWaves + 1 } else { $c = $c + 1 }
    if ([int]$State.Cap -gt 0 -and $c -gt [int]$State.Cap) { $c = [int]$State.Cap }
    $State.Concurrency = [Math]::Max(1, $c)
    [int]$State.Concurrency
}

function Get-SIEgIdentityMemoryCap {
    <# PURE. #882: how many answers fit at once in HALF of the free memory (-FreeBytes, -1 = not known -> 0 = no cap), each
       answer as large as the largest one measured in memory (-PerAnswerBytes). At least 1. #>
    param([long]$FreeBytes = -1, [long]$PerAnswerBytes = 0)
    if ($FreeBytes -lt 0 -or $PerAnswerBytes -le 0) { return 0 }
    [int][Math]::Max(1, [Math]::Floor(($FreeBytes / 2.0) / $PerAnswerBytes))
}

function Invoke-SIEgIdentityQueriesParallel {
    <#
        #882 -- THE EXPOSURE GRAPH IDENTITY READ IN PARALLEL (largest install, 2026-10-21: 1.92 million identity nodes, 385
        hunting queries one after another, 2 h 25 min - 4 h 55 min). The queries (one hash bucket each) go out in WAVES:
        a wave Microsoft answered without a 429 lets the next send one more, a throttled one halves it (never below one) and
        its Retry-After is waited ONCE for the wave; the answers held at once never exceed what half the free memory holds
        (measured from the answers themselves).
        THE SAME ORDER AS ONE AFTER ANOTHER: each answer goes down the pipeline as @{ Kind = 'answer'; Index; Rows } strictly
        in QUERY ORDER -- an answer that arrives before an earlier query's (one asked again) waits until that one is in -- so
        the caller indexes exactly what, and in exactly the order, the serial read did (a name several nodes share keeps the
        node it had). A query that fails for another reason is asked again first in the next wave (5 s / 15 s / 45 s backoff,
        as before) up to -MaxAttempts times; a throttled one does not use an attempt while the waves can still shrink.
        #882 (A3): an answer with Microsoft's maximum of rows was CUT -- -Split { param($Index) } -> the queries that read that
        part in smaller parts (they add up to it; they are answered after the queries given); the cut answer itself is never
        handed on. Without -Split a cut answer is a failed query.
        Last: @{ Kind = 'result'; Failed (@{ Index; Error }); Requests; MaxConcurrency; ThrottledWaves; Cuts }.
        Seams: -SendMany { param([string[]]$Queries) } -> outcomes (Invoke-SIEgHuntingRequests), -Sleep, -FreeBytes { }.
    #>
    param([string[]]$Queries = @(), [scriptblock]$SendMany, [scriptblock]$Sleep, [scriptblock]$FreeBytes,
          [int]$MaxAttempts = 3, [int]$BackoffBaseSeconds = 5, [scriptblock]$Split, [int]$CutRows = 100000)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $FreeBytes) { $FreeBytes = { try { [System.GC]::Collect(); $l = [long][System.GC]::GetGCMemoryInfo().TotalAvailableMemoryBytes; if ($l -le 0) { -1 } else { [long][Math]::Max(0, $l - [System.Diagnostics.Process]::GetCurrentProcess().WorkingSet64) } } catch { -1L } } }
    if (-not $SendMany) {
        $SendMany = {
            param([string[]]$Qs)
            if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Get-SIGraphToken.ps1') }
            $tk = Get-SIGraphToken -Resource Graph   # asked per wave: a read of hours outlives one token
            # the function hands its outcomes back as ONE array already: never wrapped again (the sign-in-method read broke the
            # same way -- a wave of 2+ queries came back as one item and every query but the first was asked again)
            Invoke-SIEgHuntingRequests -Token $tk -Queries $Qs
        }
    }
    $qs = New-Object System.Collections.Generic.List[string]; foreach ($q in @($Queries)) { $qs.Add([string]$q) }
    $cuts = 0
    $st = [pscustomobject]@{ Concurrency = 1; MaxConcurrency = 1; ThrottledWaves = 0; Requests = 0; Cap = 0; PerAnswer = 0L }
    $attempts = @{}
    $pending = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt $qs.Count; $i++) { $pending.Add($i) }
    $failed = New-Object System.Collections.Generic.List[object]
    $held = @{}            # index -> rows: answered, waiting for an earlier query
    $skip = @{}            # index -> $true: failed, or cut and read again in parts
    $next = 0              # the next index to hand on
    while ($pending.Count -gt 0) {
        $width = [Math]::Max(1, [Math]::Min([int]$st.Concurrency, $pending.Count))
        $wave = $pending.GetRange(0, $width).ToArray(); $pending.RemoveRange(0, $width)
        if ($width -gt [int]$st.MaxConcurrency) { $st.MaxConcurrency = $width }
        $m0 = [System.GC]::GetTotalMemory($false)
        # the seam hands its outcomes back as ONE array (`, @(...)`): taken as it is -- @(& ...) would make it ONE item, the array
        $outs = & $SendMany @($wave | ForEach-Object { $qs[$_] }); $outs = @($outs)
        $m1 = [System.GC]::GetTotalMemory($false)
        $st.Requests = [int]$st.Requests + $wave.Count
        $throttled = $false; $wait = 0; $backoff = 0
        $retry = New-Object System.Collections.Generic.List[int]
        for ($w = 0; $w -lt $wave.Count; $w++) {
            $idx = $wave[$w]; $o = $null; if ($w -lt $outs.Count) { $o = $outs[$w] }
            if ($o -and [bool]$o.Ok -and @($o.Rows).Count -ge $CutRows) {
                $outs[$w] = $null; $cuts++
                if ($Split) { foreach ($sq in @(& $Split $idx)) { $qs.Add([string]$sq); $pending.Add($qs.Count - 1) }; $skip[$idx] = $true; continue }
                $failed.Add([pscustomobject]@{ Index = $idx; Error = ('the answer was cut at {0:N0} rows' -f $CutRows) }); $skip[$idx] = $true; continue
            }
            if ($o -and [bool]$o.Ok) { $held[$idx] = @($o.Rows); $outs[$w] = $null; continue }
            $status = if ($o) { [int]$o.Status } else { 0 }
            $isThrottle = $status -eq 429
            if ($isThrottle) { $throttled = $true; if ($o.RetryAfter -and [int]$o.RetryAfter -gt $wait) { $wait = [int]$o.RetryAfter } }
            if (-not ($isThrottle -and [int]$st.Concurrency -gt 1)) { $attempts[$idx] = 1 + [int]$attempts[$idx] }
            if ([int]$attempts[$idx] -ge $MaxAttempts) { $failed.Add([pscustomobject]@{ Index = $idx; Error = $(if ($o) { [string]$o.Error } else { 'no answer' }) }); $skip[$idx] = $true; continue }
            if (-not $isThrottle -and [int]$attempts[$idx] -gt 0) { $d = [int]($BackoffBaseSeconds * [Math]::Pow(3, [int]$attempts[$idx] - 1)); if ($d -gt $backoff) { $backoff = $d } }
            $retry.Add($idx)
        }
        $outs = $null
        # hand on, in query order, everything whose turn has come
        while ($next -lt $qs.Count) {
            if ($held.ContainsKey($next)) { [pscustomobject]@{ Kind = 'answer'; Index = $next; Rows = $held[$next] }; $held.Remove($next); $next++ }
            elseif ($skip.ContainsKey($next)) { $next++ }
            else { break }
        }
        # measure -> adapt: the memory one answer takes (the largest wave measured), the free memory now
        if ($wave.Count -gt 0 -and $m1 -gt $m0) { $per = [long](($m1 - $m0) / $wave.Count); if ($per -gt [long]$st.PerAnswer) { $st.PerAnswer = $per } }
        $fb = -1L; try { $fb = [long](& $FreeBytes) } catch { $fb = -1L }
        $st.Cap = Get-SIEgIdentityMemoryCap -FreeBytes $fb -PerAnswerBytes ([long]$st.PerAnswer)
        $null = Update-SIEgIdentityConcurrency -State $st -Throttled $throttled
        if ($retry.Count) {
            $pending.InsertRange(0, $retry)
            $d = [Math]::Max($backoff, $(if ($throttled) { [Math]::Max(1, $wait) } else { 0 }))
            if ($d -gt 0) { & $Sleep $d }
        }
    }
    [pscustomobject]@{ Kind = 'result'; Failed = $failed.ToArray(); Requests = [int]$st.Requests; MaxConcurrency = [int]$st.MaxConcurrency; ThrottledWaves = [int]$st.ThrottledWaves; Cuts = $cuts }
}

function Get-SIEgAdIdentity {
    <#
        PURE. Is an Exposure Graph identity node (with no Entra object id) an on-prem AD identity? Yes when it carries
        any of: a domain SID (S-1-5-21-...), an AD account name AND domain (rawData.accountName + accountDomain), AD
        critical groups (rawData.nestedCriticalAdGroups) or an admin count above 0 (rawData.adminCount). Operator
        2026-10-09: such nodes are kept as AD identity records; a node that is neither Entra nor AD is dropped.
    #>
    param([AllowNull()]$RawData, [AllowNull()][AllowEmptyString()][string]$Sid)
    $why = New-Object System.Collections.Generic.List[string]
    if ($Sid -and $Sid -match '^s-1-5-21-') { $why.Add('domain SID') }
    if ($null -ne $RawData) {
        $g = { param($n) $p = $RawData.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
        if ([string](& $g 'accountName') -and [string](& $g 'accountDomain')) { $why.Add('AD account name + domain') }
        $crit = @(& $g 'nestedCriticalAdGroups' | Where-Object { $_ })
        if ($crit.Count -gt 0) { $why.Add('AD critical groups') }
        $ac = 0; if ([int]::TryParse([string](& $g 'adminCount'), [ref]$ac) -and $ac -gt 0) { $why.Add('admin count') }
    }
    [pscustomobject]@{ IsAd = ($why.Count -gt 0); Why = $why.ToArray() }
}

function ConvertTo-SIEgResolvedIds {
    <#
        PURE. The ids of one Exposure Graph identity node as plain {type,id} objects -- what eg.locked.json reads first
        (node.SIEntityIds) for entra_object_id, ad_sid and ad_object_guid. EG's own EntityIds are an array of JSON
        STRINGS, the Entra id often as 'tenantid=..;objectid=..'; the mapping's select cannot read those. The Entra
        object id and the SID are the ones Get-SIExposureGraphIdentities resolved (EntityIds, then rawData).
    #>
    param([AllowNull()]$EntityIds, [AllowNull()][AllowEmptyString()][string]$AadObjectId, [AllowNull()][AllowEmptyString()][string]$Sid)
    $out = New-Object System.Collections.Generic.List[object]
    if ($AadObjectId) { $out.Add([pscustomobject]@{ type = 'AadObjectId'; id = $AadObjectId.ToLowerInvariant() }) }
    if ($Sid) { $out.Add([pscustomobject]@{ type = 'SecurityIdentifier'; id = $Sid.ToUpperInvariant() }) }
    foreach ($eid in @($EntityIds)) {
        if ($null -eq $eid) { continue }
        if ($eid -is [string]) { try { $eid = $eid | ConvertFrom-Json } catch { continue } }
        $t = [string]$eid.type; $i = [string]$eid.id
        if (-not $t -or -not $i) { continue }
        if ($t -in 'AadObjectId', 'SecurityIdentifier') { continue }     # the resolved ones above
        $out.Add([pscustomobject]@{ type = $t; id = $i })
    }
    $out.ToArray()
}

function Get-SIExposureGraphIdentities {
    [CmdletBinding()]
    param()

    if ($script:_SICache.ContainsKey('EgIdentitiesMap')) {
        Write-SIInfo '[perms] EG identity nodes (cache hit)'
        return $script:_SICache['EgIdentitiesMap']
    }
    # #726: the index lives ON DISK (one entry each, type-faithful, only the keys in memory) -- every tenant, whatever its size;
    # $egMap[<key>] / ContainsKey / Count read as the hashtable did
    if (-not (Get-Command -Name New-SIDiskLookup -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-DiskLookup.ps1')) }
    $egMap = New-SIDiskLookup -Name 'eg-identity'

    # file moved from identity-catalog/ to engine/shared/.
    # $PSScriptRoot now = v2.2/engine/asset-profiling/shared/; three parents -> v2.2/
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $hqPath  = Join-Path $siRoot 'engine\asset-profiling\shared\HuntingQuery.ps1'
    if (-not (Test-Path $hqPath)) {
        Write-Warning ('Get-SIExposureGraphIdentities: HuntingQuery.ps1 not found at {0} -- skipping' -f $hqPath)
        return $egMap
    }
    . $hqPath

    Write-SIInfo '[perms] fetching identity nodes from Exposure Graph (per-label, bucket if > threshold)...'

    # Two-pass per label:
    #   1. count probe -- cheap, tells us how many rows we'll need
    #   2. fetch -- single query when count <= threshold; hash-bucketed
    #      otherwise. Bucketing splits a huge result set across multiple
    #      runHuntingQuery calls so each response stays under the API
    #      payload cap (NodeProperties rawData can be multi-KB per row).
    # Default threshold 30000 -- the Defender Advanced Hunting UI's default
    # row cap. Customer-tunable via $global:SI_EgIdentityBucketThreshold.
    $bucketThreshold = if ($global:SI_EgIdentityBucketThreshold) { [int]$global:SI_EgIdentityBucketThreshold } else { 30000 }
    # PAGE BY PAGE (#702, customer B 2026-10-15): every answer is indexed AS IT ARRIVES and let go -- the raw rows (each with its whole
    # NodeProperties text) were all held until every label was read, and customer B's 26,748 users + 19,862 groups did not fit. The
    # rows held at once are one answer: at most SI_EgIdentityPageRows (5,000) per query, so a large label is read in more,
    # smaller hash buckets. Only the trimmed index entries stay.
    $pageRows = if ($global:SI_EgIdentityPageRows -and [int]$global:SI_EgIdentityPageRows -gt 0) { [int]$global:SI_EgIdentityPageRows } else { 5000 }
    $chunkRows = [Math]::Min($bucketThreshold, $pageRows)
    $labels = @('user','serviceprincipal','managedidentity','group')

    # v3 data model -- THE v2.2 RULE (operator 2026-10-09: "use the same ruleset"): an Exposure Graph identity node is
    # never an asset of its own; it only enriches the Entra object it maps to. So a node becomes a record ONLY when the
    # index below keeps it (an Entra object id was found), and the record carries that id (+ the SID) so correlation
    # links it to the Entra record. Captured in the loop below, AFTER the skip-no-aadOid check. (Was: every row a
    # record, before the filter -- customer H 96,551 records instead of ~51,400, and no Entra id on any of them.)
    $egCaptureRecords = [bool](Get-Command -Name Add-SIRecordPartFromSource -ErrorAction SilentlyContinue)
    if ($egCaptureRecords) { Set-SIRecordPull -Provider 'eg' -Complete $true }

    # #412 full asset metadata (identity profiler only): the kept nodes, whole. A no-op at the security level, and when
    # another engine reads the same map.
    $egCaptureFull = [bool]((Get-Command -Name Test-SIFullAssetPropertiesOn -ErrorAction SilentlyContinue) -and (Test-SIFullAssetPropertiesOn -Engine 'identity'))
    if ($egCaptureFull) { Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete $true }

    # #475: the index keeps only the rawData fields the profile, the rules and the mapping read (SI-EgRawTrim.ps1) --
    # the whole rawData of every node ran customer H's identity job out of memory. Full asset metadata keeps it whole.
    # The trim file is loaded for EVERY run: the index below calls Select-SIEgRawFields for each node it keeps, also when
    # the rawData is kept whole. It was loaded only when the fields are trimmed, so an identity run with full asset
    # metadata stopped at the first node ("Select-SIEgRawFields is not recognized") and collected no identity at all.
    if (-not (Get-Command -Name Select-SIEgRawFields -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-EgRawTrim.ps1') }
    $egKeep = $null
    if (-not $egCaptureFull) {
        $egKeep = Get-SIEgIdentityKeepKeys -SIRoot $siRoot
        if ($null -ne $egKeep) { Write-SIInfo ('[perms] EG identity nodes: keeping {0} rawData field(s) the profile, rules and mapping read' -f $egKeep.Count) }
    }
    $skipNoProps = 0; $skipNoOid = 0; $kept = 0; $adKept = 0; $dropped = 0; $rowsTotal = 0; $sampleRowKeys = ''
    $perLabelTotal = @{}; $perLabelKept = @{}; $perLabelSkipNoOid = @{}; $perLabelAdKept = @{}
    $diagSamplesPerLabel = @{}   # per-label: capture first 1 raw EntityIds payload that fails to extract -- helps diagnose schema drift
    # one answer's rows -> the index (and the records); the caller lets the answer go right after
    $indexChunk = { param($chunk)
    foreach ($row in @($chunk)) {
        $rowsTotal++
        if (-not $sampleRowKeys -and $row) { $sampleRowKeys = (@($row.PSObject.Properties.Name) -join ',') }
        $nodeLabel = [string]$row.NodeLabel
        if (-not $perLabelTotal.ContainsKey($nodeLabel)) { $perLabelTotal[$nodeLabel] = 0; $perLabelKept[$nodeLabel] = 0; $perLabelSkipNoOid[$nodeLabel] = 0 }
        $perLabelTotal[$nodeLabel]++

        $entityIdsRaw = $row.EntityIds
        $entityIds = if ($entityIdsRaw -is [string]) { try { $entityIdsRaw | ConvertFrom-Json } catch { @() } } else { $entityIdsRaw }
        $nodeProps = if ($row.NodeProperties -is [string]) { try { $row.NodeProperties | ConvertFrom-Json } catch { $null } } else { $row.NodeProperties }
        if (-not $nodeProps) { $skipNoProps++; continue }
        # rawData may be nested under .rawData OR may BE the top-level NodeProperties blob (varies by EG version).
        $rawData = if ($nodeProps.PSObject.Properties['rawData'] -and $nodeProps.rawData) { $nodeProps.rawData } else { $nodeProps }

        # AadObjectId discovery -- iterate ALL EntityIds entries (groups have
        # SecurityIdentifier at [0] and AadObjectId at [1]), case-insensitive type
        # match. The id format is either a bare GUID or the legacy
        # 'tenantid=<guid>;objectid=<guid>' form -- the regex pulls any GUID
        # following 'objectid=' (length-agnostic). Fallback: any 36-char GUID
        # anywhere in the id string. rawData.<various oid keys> as last resort.
        $aadOid = $null
        $sid    = $null
        foreach ($eid in @($entityIds)) {
            # EG returns EntityIds as an array of JSON-encoded
            # STRINGS (not objects). ConvertFrom-Json on the outer array gives
            # an array of strings -- each entry still needs a second parse to
            # become an object with .type / .id properties. Without this
            # second-pass parse, $eid.type was always $null and EVERY service-
            # principal + many users got skip-no-aadOid'd silently.
            if ($eid -is [string]) {
                try { $eid = $eid | ConvertFrom-Json } catch { continue }
            }
            $etype = ([string]$eid.type).ToLowerInvariant()
            $raw   = [string]$eid.id
            if (-not $etype -or -not $raw) { continue }
            if ($etype -eq 'aadobjectid' -and -not $aadOid) {
                if ($raw -match 'objectid=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $aadOid = $matches[1].ToLower() }
                elseif ($raw -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')      { $aadOid = $matches[1].ToLower() }
            } elseif ($etype -eq 'securityidentifier' -and -not $sid) {
                $sid = $raw.ToLower()
            }
        }
        # rawData fallbacks -- different EG node types expose the AAD id under
        # different property names.
        if (-not $aadOid -and $rawData) {
            # added 'aadId' (used by EG group nodes per actual
            # rawData schema -- previously missing from the fallback list, so
            # groups whose only AAD identifier was rawData.aadId got skipped).
            foreach ($key in @('aadId','accountObjectId','objectId','aadObjectId','groupId','principalId','userId','id')) {
                if ($rawData.PSObject.Properties[$key] -and $rawData.$key) {
                    $cand = [string]$rawData.$key
                    if ($cand -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $aadOid = $matches[1].ToLower(); break }
                }
            }
        }
        # the SID may also sit only in rawData (an on-prem AD account EG learnt from Defender for Identity)
        if (-not $sid -and $rawData) {
            foreach ($key in @('adSid', 'accountSid', 'onPremSid', 'onPremisesSecurityIdentifier', 'securityIdentifier', 'sid')) {
                if ($rawData.PSObject.Properties[$key] -and $rawData.$key -and ([string]$rawData.$key) -match '^S-1-\d') { $sid = ([string]$rawData.$key).ToLower(); break }
            }
        }
        if (-not $aadOid) {
            $skipNoOid++; $perLabelSkipNoOid[$nodeLabel]++
            # operator 2026-10-09 ("that would make good sense to include"): a node with NO Entra id but an on-prem AD
            # identity is KEPT as an AD identity record (v2.2 lost these -- customer H: tier-0 Domain Admins accounts). It
            # is not put in the index (the index enriches Entra objects); correlation links it by SID to the Entra user
            # whose onPremisesSecurityIdentifier it is. Anything that is neither Entra nor AD is dropped.
            if ($egCaptureRecords -or $egCaptureFull) {
                $adId = Get-SIEgAdIdentity -RawData $rawData -Sid $sid
                if ($adId.IsAd) {
                    $adKept++; if (-not $perLabelAdKept.ContainsKey($nodeLabel)) { $perLabelAdKept[$nodeLabel] = 0 }; $perLabelAdKept[$nodeLabel]++
                    $egNode = ConvertTo-SIFullExposureGraphNode -Row $row
                    if ($egCaptureFull) { Add-SIFullSourceObject -SourceSystem 'exposure-graph' -Object $egNode -AnchorColumn 'ExposureGraphNodeId' -AnchorValue ([string]$row.NodeId) }
                    if ($egCaptureRecords) {
                        $egNode | Add-Member -NotePropertyName 'SIEntityIds' -NotePropertyValue (ConvertTo-SIEgResolvedIds -EntityIds $entityIds -AadObjectId $null -Sid $sid) -Force
                        $egNode | Add-Member -NotePropertyName 'SIIdentitySource' -NotePropertyValue 'ad' -Force
                        Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object $egNode
                    }
                    continue
                }
            }
            $dropped++
            # Capture one diagnostic sample per label so the next run prints
            # the actual EntityIds + rawData key list -- no guessing about what
            # shape the API returned.
            if (-not $diagSamplesPerLabel.ContainsKey($nodeLabel)) {
                $entitySample = if ($entityIdsRaw -is [string]) { $entityIdsRaw } else { ($entityIdsRaw | ConvertTo-Json -Compress -Depth 5) }
                $rawKeys      = if ($rawData) { (@($rawData.PSObject.Properties.Name) -join ',') } else { '<no rawData>' }
                $diagSamplesPerLabel[$nodeLabel] = @{
                    EntitySample = if ($entitySample.Length -gt 200) { $entitySample.Substring(0,200) + '...' } else { $entitySample }
                    RawKeys      = if ($rawKeys.Length -gt 200) { $rawKeys.Substring(0,200) + '...' } else { $rawKeys }
                }
            }
            continue
        }

        $entry = [pscustomobject]@{
            NodeId     = [string]$row.NodeId
            NodeLabel  = $nodeLabel
            NodeName   = [string]$row.NodeName
            Categories = $row.Categories
            EntityIds  = $entityIds
            RawData    = (Select-SIEgRawFields -Raw $rawData -Keep $egKeep)
        }
        # Multi-key indexing: AAD object id (primary), SID (groups via on-prem SID),
        # NodeName lowercased (display-name lookup), NodeId (EG-native lookup).
        # #726: the entry is written once to the on-disk index and let go; every key points at it
        $entryAt = $egMap.Append((ConvertTo-SIDiskLookupText $entry))
        $entry = $null
        $egMap.SetKey($aadOid, $entryAt)
        if ($sid) { $egMap.SetKey($sid, $entryAt) }
        if ($row.NodeName) {
            $nameKey = ([string]$row.NodeName).ToLowerInvariant()
            $null = $egMap.TryAddKey($nameKey, $entryAt)
        }
        if ($row.NodeId) {
            $idKey = ([string]$row.NodeId).ToLowerInvariant()
            $null = $egMap.TryAddKey($idKey, $entryAt)
        }
        $kept++; $perLabelKept[$nodeLabel]++

        # the v2.2 rule (above): only a kept node is a record, and it carries the Entra object id it was kept for
        if ($egCaptureRecords -or $egCaptureFull) {
            $egNode = ConvertTo-SIFullExposureGraphNode -Row $row
            # full asset metadata keeps (a copy of) the source's node as it is -- its hook also captures the record part,
            # which the call below replaces with the one that carries the Entra object id
            if ($egCaptureFull) { Add-SIFullSourceObject -SourceSystem 'exposure-graph' -Object $egNode -AnchorColumn 'ExposureGraphNodeId' -AnchorValue ([string]$row.NodeId) }
            if ($egCaptureRecords) {
                # SIEntityIds: the ids THIS fetch resolved, as plain {type,id} objects (EG's own EntityIds are JSON strings,
                # often 'tenantid=..;objectid=..'); eg.locked.json reads it first for entra_object_id and ad_sid
                $egNode | Add-Member -NotePropertyName 'SIEntityIds' -NotePropertyValue (ConvertTo-SIEgResolvedIds -EntityIds $entityIds -AadObjectId $aadOid -Sid $sid) -Force
                $egNode | Add-Member -NotePropertyName 'SIIdentitySource' -NotePropertyValue 'entra' -Force
                Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object $egNode
            }
        }
    }
    }

    foreach ($label in $labels) {
        $rowCount = 0
        # The DefenderGraph route WARNS and returns @() on failure -- it does not throw -- so the old
        # catch that forced the bucketed path was unreachable: a failed probe read as count 0 and the
        # label was fetched in ONE query, however large (#125). Invoke-SIEgIdentityQuery retries and
        # reports the failure explicitly.
        $countQ = "ExposureGraphNodes | where NodeLabel == '$label' | count"
        $probe  = Invoke-SIEgIdentityQuery -Query $countQ
        if ($probe.Ok) {
            $countRes = @($probe.Rows)
            if ($countRes.Count -gt 0) {
                $first = $countRes[0]
                if ($first.PSObject.Properties['Count']) { $rowCount = [int]$first.Count }
                elseif ($first.PSObject.Properties['count_']) { $rowCount = [int]$first.count_ }
            }
        } else {
            Write-Warning ('  EG count probe failed for label={0} -- {1}; using the bucketed fetch (safe for any size)' -f $label, $probe.Error)
            $rowCount = $bucketThreshold + 1   # force bucketed path on probe failure (ceil(threshold / page) buckets)
        }

        $proj = "project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodeProperties"
        $fetched = 0
        $useBuckets = ($rowCount -gt $chunkRows)
        $bucketCount = [int][Math]::Ceiling($rowCount / [double]$chunkRows)
        if (-not $useBuckets) {
            # Single query
            $kql    = "ExposureGraphNodes | where NodeLabel == '$label' | $proj"
            $single = Invoke-SIEgIdentityQuery -Query $kql
            if ($single.Ok) {
                $chunk = @($single.Rows)
                . $indexChunk $chunk
                $fetched = $chunk.Count
                $chunk = $null; $single = $null
                Write-SIInfo ('     [{0,-18}] count={1,5}  fetched={2,5}  (single)' -f $label, $rowCount, $fetched)
            } else {
                # A failed single fetch is retried SMALLER, not given up: the usual cause is a response
                # too large for the API, which is exactly what buckets fix.
                Write-Warning ('  EG fetch failed for label={0} -- {1}; retrying as a bucketed fetch' -f $label, $single.Error)
                $useBuckets = $true
                $bucketCount = [Math]::Max(4, [int][Math]::Ceiling($rowCount / [double]$chunkRows))
            }
        }
        if ($useBuckets) {
            # Bucketed: ceil(rowCount / page rows) buckets, hash-distributed -- each answer indexed and let go.
            if ($bucketCount -lt 2) { $bucketCount = 2 }
            $failedBuckets = 0
            # KQL hash(NodeId, N) returns a stable value in [0, N-1] (it does the modulo itself) -- partitions every node into
            # exactly one bucket so the N bucket queries union to the full set. (Was hash_djb2(...) % N, which is NOT a KQL
            # function -> "Unknown function: 'hash_djb2'" BadRequest on every bucket, 2026-06-18.)
            # #882 (C6): the buckets go out IN PARALLEL WAVES (Invoke-SIEgIdentityQueriesParallel: as many at once as Microsoft
            # takes and the free memory holds, measured); each answer is indexed here, in bucket order within its wave, and
            # let go. A bucket answered with Microsoft's maximum of rows was CUT (A3): it is read again as two buckets of the
            # doubled count (its nodes are in bucket b or b + N of 2N), until none is cut -- never a cut bucket read as whole.
            $egSpec = New-Object System.Collections.Generic.List[object]
            $egQuery = { param($n, $bk) "ExposureGraphNodes | where NodeLabel == '{0}' | extend _bucket = hash(NodeId, {1}) | where _bucket == {2} | {3}" -f $label, $n, $bk, $proj }
            for ($b = 0; $b -lt $bucketCount; $b++) { $egSpec.Add(@($bucketCount, $b)) }
            $egRun = @{ Queries = @(foreach ($x in $egSpec) { & $egQuery $x[0] $x[1] })
                        Split = { param($i) $x = $egSpec[$i]; $n2 = 2 * [int]$x[0]; foreach ($nb in @([int]$x[1], ([int]$x[1] + [int]$x[0]))) { $egSpec.Add(@($n2, $nb)); & $egQuery $n2 $nb } } }
            if ($script:SIEgIdentitySendMany) { $egRun.SendMany = $script:SIEgIdentitySendMany }
            if ($script:SIEgIdentitySleep) { $egRun.Sleep = $script:SIEgIdentitySleep }
            if ($script:SIEgIdentityFreeBytes) { $egRun.FreeBytes = $script:SIEgIdentityFreeBytes }
            $egRes = $null
            Invoke-SIEgIdentityQueriesParallel @egRun | ForEach-Object {
                if ($_.Kind -eq 'answer') { $chunk = @($_.Rows); . $indexChunk $chunk; $fetched += $chunk.Count; $chunk = $null }
                else { $egRes = $_ }
            }
            foreach ($f in @($egRes.Failed)) {
                $failedBuckets++
                $fx = $egSpec[[int]$f.Index]
                Write-Warning ('  EG fetch failed for label={0} bucket={1}/{2} -- {3}' -f $label, $fx[1], $fx[0], $f.Error)
            }
            Write-SIInfo ('     [{0,-18}] count={1,5}  fetched={2,5}  ({3} buckets; {4} request(s), up to {5} at once, Microsoft asked to slow down {6} time(s){7})' -f $label, $rowCount, $fetched, $bucketCount, $egRes.Requests, $egRes.MaxConcurrency, $egRes.ThrottledWaves, $(if ($egRes.Cuts) { ('; {0} cut bucket(s) read again in halves' -f $egRes.Cuts) } else { '' }))
            if ($failedBuckets -gt 0) {
                Write-Warning ('  EG identity nodes for label={0} are INCOMPLETE: {1} of {2} bucket(s) failed after retries. Identities in those buckets carry no EG enrichment this run (UNKNOWN, not absent).' -f $label, $failedBuckets, $bucketCount)
            }
        }
    }

    if ($rowsTotal -eq 0) {
        Write-Warning '  EG returned 0 identity nodes (license or permission issue?)'
        $script:_SICache['EgIdentitiesMap'] = $egMap
        return $egMap
    }

    Write-SIInfo ('[perms] EG identity nodes: {0} entries indexed (rows={1}, skip-no-props={2}, skip-no-aadOid={3})' -f $egMap.Count, $rowsTotal, $skipNoProps, $skipNoOid)
    Write-SIInfo ('[perms] EG identity nodes: {0} of {1} have an Entra object id (recorded, enriching their Entra object); {2} have no Entra id but an on-prem AD identity (recorded as AD identities, linked by SID); {3} are neither Entra nor AD and {4} have no properties -- those {5} are dropped (the v2.2 rule, extended for on-prem AD).' -f $kept, $rowsTotal, $adKept, $dropped, $skipNoProps, ($dropped + $skipNoProps))
    foreach ($k in ($perLabelTotal.Keys | Sort-Object)) {
        Write-SIInfo ('     [{0,-18}] total={1,5}  kept={2,5}  skip-no-aadOid={3}  (of those kept as AD identities={4})' -f $k, $perLabelTotal[$k], $perLabelKept[$k], $perLabelSkipNoOid[$k], [int]$perLabelAdKept[$k])
    }
    if ($global:SI_Verbose) {
        foreach ($k in ($diagSamplesPerLabel.Keys | Sort-Object)) {
            Write-SIInfo ('     [{0,-18}] sample EntityIds: {1}' -f $k, $diagSamplesPerLabel[$k].EntitySample)
            Write-SIInfo ('     [{0,-18}] sample rawData keys: {1}' -f $k, $diagSamplesPerLabel[$k].RawKeys)
        }
    }
    if ($egMap.Count -eq 0 -and ($skipNoProps + $skipNoOid) -gt 0) {
        Write-Warning ('  EG: parsed 0 of {0} nodes. Sample row keys: {1}' -f `
            $rowsTotal, $sampleRowKeys)
    }
    $script:_SICache['EgIdentitiesMap'] = $egMap
    return $egMap
}
