#Requires -Version 5.1
<#
    SecurityInsight -- ONLY LIVE USER-ASSIGNED IDENTITIES ON SI'S JOBS AND APPS (#1413, found read-only at a customer install 2026-11-26).

    A user-assigned identity DELETED from the resource group stays listed on the jobs and apps that carried it: ARM keeps the
    key on an existing resource, but any PUT that names it is refused --
      "FailedIdentityOperation ... userAssignedIdentities/uami-si-updater was not found"   (caj-si-image-check, made from the updater)
      "FailedIdentityOperation ... userAssignedIdentities/id-si-prod-pro-ca was not found" (caj-si-job-requests, made from an engine job)
    Four installs carry five dead keys each: id-si-prod-pro-ca on every engine job,
    uami-si-updater on caj-si-updater, uami-securityinsight-tagging on caj-si-asset-tagging, uami-si-management on
    ca-si-management, uami-si-mcp on ca-si-mcp -- each beside its live replacement; no registry or secret uses a dead one.

    TWO PARTS:
      1. THE COPY FILTER (Read-SILiveIdentities + Select-SILiveIdentityKeys): every job / app body BUILT BY COPYING another
         resource's identities (the image check job from the updater, a missing job from its donor, the web app's copy)
         carries only identities that exist. The resource group's identities are read ONCE (all pages); an identity of THIS
         resource group that is not on the list is not carried, one line each. An identity of another resource group is
         always kept (the list does not cover it). The list not read (or not completely) = the body as before -- never blocks.
      2. THE CLEAN-UP (Invoke-SIDeadIdentityCleanup): a dead reference on an EXISTING SI job or app is taken off, fail closed:
         (a) only when the resource group's list was read completely AND a GET of that identity answers 404 (403 / 500 / no
             answer = kept, said);
         (b) a live identity is never removed; a resource where the dead identity is still USED (a registry pull, a Key
             Vault secret, a scale rule, any setting -- anywhere outside identity.userAssignedIdentities) or that signs in
             with it (its client id is a setting of the resource) is NOT touched -- a WARNING and a problem instead; a
             resource that would be left with no user-assigned identity is not touched either;
         (c) one identity-only PATCH (JSON merge patch: the live keys, the dead key = null); never a PUT of a read body; the FIRST
             one is a CANARY (read back before any other is sent -- refused / not read back = one WARNING, nothing else sent); one wait
             budget for the whole step (10 min); an app with a fixed revision suffix is not touched (WARNING);
         (d) one line per removed reference;
         (e) read back: every SI job / app again, every identity on it must exist -- else a loud problem.
         A job's change applies to its next execution (a running one keeps the spec it started with, and a deleted identity
         gives it no token anyway). An app's identity PATCH makes a new revision: the clean-up waits until the app's latest
         revision is its latest READY one (the web stays up on the old revision until then); not ready = a loud problem.
    PURE except Read-SILiveIdentities / Test-SIIdentityExists / Invoke-SIDeadIdentityCleanup (their ARM calls go through
    -Rest { param($Method, $Uri, $Body, $Resource, $Headers) -> @{ Status; Body } }, the SI REST seam). Never throws.
    PS 5.1 and 7. No module.
#>

function Get-SILiveIdentityApi {
    <# PURE. The Microsoft.ManagedIdentity api-version (a function, not a script variable: a script that finds these functions
       already defined by its caller does not dot-source this file again, so a script variable would not exist there). #>
    '2023-01-31'
}

function Get-SILiveIdentityProp {
    <# PURE. A nested property (PSCustomObject or dictionary); $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function Get-SILiveIdentityKeys {
    <# PURE. The keys of identity.userAssignedIdentities of a resource (as written), @() for none. #>
    param($Resource)
    $ua = Get-SILiveIdentityProp $Resource @('identity', 'userAssignedIdentities')
    if ($null -eq $ua) { return @() }
    if ($ua -is [System.Collections.IDictionary]) { return @($ua.Keys | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() }) }
    @($ua.PSObject.Properties | ForEach-Object { [string]$_.Name } | Where-Object { $_.Trim() })
}

function ConvertTo-SILiveIdentityKey {
    <# PURE. One identity resource id as compared: trimmed, no trailing '/', lower case. #>
    param([AllowEmptyString()][AllowNull()][string]$Id)
    ("$Id".Trim().TrimEnd('/')).ToLowerInvariant()
}

function Get-SILiveIdentityScope {
    <# PURE. The id prefix of the resource group's user-assigned identities (lower case, ending in '/'). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    ('/subscriptions/{0}/resourcegroups/{1}/providers/microsoft.managedidentity/userassignedidentities/' -f $SubscriptionId.Trim(), $ResourceGroup.Trim()).ToLowerInvariant()
}

function Get-SILiveIdentityName {
    <# PURE. The last segment of an identity id (its name). #>
    param([string]$Id)
    $t = "$Id".Trim().TrimEnd('/'); if (-not $t) { return '' }
    ($t -split '/')[-1]
}

function Read-SILiveIdentities {
    <#
        The resource group's user-assigned identities, ONE list read (every page, nextLink). Returns @{ Ok; Ids (a
        case-insensitive set of lower-case ids); Scope; Count; Problem }. Ok only when EVERY page answered 2xx and the
        last page has no nextLink; anything else = Ok $false (the caller then carries the body as before / removes nothing).
        Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [int]$MaxPages = 50)
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $scope = Get-SILiveIdentityScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    $no = { param($p) [pscustomobject]@{ Ok = $false; Ids = $ids; Scope = $scope; Count = $ids.Count; Problem = $p } }
    try {
        $url = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version={2}' -f $SubscriptionId, $ResourceGroup, (Get-SILiveIdentityApi)
        for ($p = 0; $p -lt [Math]::Max(1, $MaxPages); $p++) {
            $r = $null
            try { $r = & $Rest 'GET' $url $null 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' } } catch { return (& $no ('the identities of {0} could not be read ({1})' -f $ResourceGroup, $_.Exception.Message)) }
            $code = 0; try { $code = [int]$r.Status } catch { }
            if ($code -lt 200 -or $code -ge 300) { return (& $no ('the identities of {0} could not be read (HTTP {1})' -f $ResourceGroup, $code)) }
            $page = $null; try { $page = ("$($r.Body)" | ConvertFrom-Json) } catch { $page = $null }
            if (-not $page -or -not $page.PSObject.Properties['value']) { return (& $no ('the identities of {0} could not be read (no list in the answer)' -f $ResourceGroup)) }
            foreach ($x in @($page.value)) { $id = [string](Get-SILiveIdentityProp $x @('id')); if ($id.Trim()) { $null = $ids.Add((ConvertTo-SILiveIdentityKey $id)) } }
            $next = if ($page.PSObject.Properties['nextLink']) { [string]$page.nextLink } else { '' }
            if (-not $next.Trim()) { return [pscustomobject]@{ Ok = $true; Ids = $ids; Scope = $scope; Count = $ids.Count; Problem = '' } }
            $url = $next
        }
        & $no ('the identities of {0} could not be read completely (more than {1} pages)' -f $ResourceGroup, $MaxPages)
    } catch { & $no ('the identities of {0} could not be read ({1})' -f $ResourceGroup, $_.Exception.Message) }
}

function Test-SILiveIdentityDead {
    <# PURE. Is -Id an identity of the listed resource group that is NOT on the list? Never true without a complete list. #>
    param([string]$Id, $Live)
    if (-not $Live -or -not $Live.Ok) { return $false }
    $k = ConvertTo-SILiveIdentityKey $Id
    if (-not $k -or -not $k.StartsWith([string]$Live.Scope)) { return $false }   # another resource group: the list does not cover it
    -not $Live.Ids.Contains($k)
}

function Select-SILiveIdentityKeys {
    <#
        PURE. THE COPY FILTER: of -Keys (identity ids copied from another resource), the ones to carry into the new body built
        for -Name. A key of this resource group missing from -Live (Read-SILiveIdentities) is dropped, one line each; every
        other key is kept as written. -Live not read (Ok $false / $null) = every key kept, no line. Returns @{ Keep; Dropped; Lines }.
    #>
    param([AllowEmptyCollection()][AllowNull()][string[]]$Keys = @(), $Live, [string]$Name = '', [string]$Kind = 'job')
    $keep = New-Object System.Collections.Generic.List[string]; $drop = New-Object System.Collections.Generic.List[string]; $lines = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Keys)) {
        if (-not "$k".Trim()) { continue }
        if (Test-SILiveIdentityDead -Id $k -Live $Live) {
            $drop.Add([string]$k)
            $lines.Add(('{3} {0}: identity {1} no longer exists -- not carried ({2})' -f $Name, (Get-SILiveIdentityName $k), $k, $Kind))
        } else { $keep.Add([string]$k) }
    }
    if ($drop.Count -and -not $keep.Count) {
        # nothing would be left: a body without an identity is no better -- carried as before, said
        return [pscustomobject]@{ Keep = [string[]]@($drop.ToArray()); Dropped = [string[]]@(); Lines = [string[]]@(('WARNING: {2} {0}: none of the identities it is made from exists ({1}) -- carried as they are' -f $Name, (($drop | ForEach-Object { Get-SILiveIdentityName $_ }) -join ', '), $Kind)) }
    }
    [pscustomobject]@{ Keep = [string[]]$keep.ToArray(); Dropped = [string[]]$drop.ToArray(); Lines = [string[]]$lines.ToArray() }
}

# =====================================================================================================================
#  THE CLEAN-UP of existing jobs and apps
# =====================================================================================================================
function Test-SIIdentityExists {
    <# ONE GET of the identity. 'live' (2xx) | 'dead' (404 ONLY) | 'unknown' (anything else: 403, 500, no answer). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$Id)
    try {
        $r = & $Rest 'GET' ('https://management.azure.com{0}?api-version={1}' -f "$Id".Trim().TrimEnd('/'), (Get-SILiveIdentityApi)) $null 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' }
        $code = 0; try { $code = [int]$r.Status } catch { }
        if ($code -ge 200 -and $code -lt 300) { return 'live' }
        if ($code -eq 404) { return 'dead' }
        'unknown'
    } catch { 'unknown' }
}

function Test-SIDeadIdentityUsed {
    <#
        PURE. Is -Id still USED by -Resource anywhere outside identity.userAssignedIdentities -- a registry pull, a Key Vault
        secret, a scale rule, a setting (its properties, searched as text, case-insensitive) -- or does the resource sign in
        with it (-ClientId, the identity's client id as the resource lists it, is the value of one of its settings)?
        Returns '' (not used) or where.
    #>
    param([Parameter(Mandatory)]$Resource, [Parameter(Mandatory)][string]$Id, [string]$ClientId = '')
    $props = Get-SILiveIdentityProp $Resource @('properties')
    $txt = ''; try { $txt = (ConvertTo-Json -InputObject $props -Depth 60 -Compress).ToLowerInvariant() } catch { return 'its settings could not be read' }
    $k = ConvertTo-SILiveIdentityKey $Id
    if ($k -and $txt.Contains($k)) { return 'its settings (a registry, a secret, a scale rule or a setting) still name it' }
    if ("$ClientId".Trim() -and $txt.Contains(("$ClientId".Trim()).ToLowerInvariant())) { return ('it signs in with it (client id {0} is one of its settings)' -f "$ClientId".Trim()) }
    ''
}

function Get-SIDeadIdentityPatch {
    <#
        PURE. The identity-only PATCH (JSON merge patch) that takes -Dead off -Resource: @{ identity = @{ type; userAssignedIdentities
        = every other key as {} and each dead key as null } } -- nothing else. $null when no user-assigned identity would remain
        (the resource is then not touched) or nothing is dead.
    #>
    param([Parameter(Mandatory)]$Resource, [AllowEmptyCollection()][string[]]$Dead = @())
    $deadSet = @($Dead | ForEach-Object { ConvertTo-SILiveIdentityKey $_ } | Where-Object { $_ })
    if (-not $deadSet.Count) { return $null }
    $ua = [ordered]@{}; $kept = 0; $gone = 0
    foreach ($k in @(Get-SILiveIdentityKeys $Resource)) {
        if ($deadSet -contains (ConvertTo-SILiveIdentityKey $k)) { $ua[$k] = $null; $gone++ } else { $ua[$k] = [ordered]@{}; $kept++ }
    }
    if (-not $gone -or -not $kept) { return $null }
    $type = [string](Get-SILiveIdentityProp $Resource @('identity', 'type'))
    $type = if ($type -match '(?i)SystemAssigned') { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' }
    [ordered]@{ identity = [ordered]@{ type = $type; userAssignedIdentities = $ua } }
}

function Test-SISiResource {
    <# PURE. Is -Resource one of SI's jobs / apps (its name caj-si-* / ca-si-*, or the tag product = securityinsight)? #>
    param($Resource)
    $n = [string](Get-SILiveIdentityProp $Resource @('name'))
    if ($n -match '^(caj|ca)-si-') { return $true }
    [string](Get-SILiveIdentityProp $Resource @('tags', 'product')) -ieq 'securityinsight'
}

function Test-SIDeadIdentityCleanupOn {
    <# PURE. The clean-up's off-switch: SI_UPDATER_IDENTITY_CLEANUP on the updater job (-Value). off / false / 0 / no / disabled =
       off; anything else (not set too) = ON. The copy filter has no switch -- it is always on. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    "$Value".Trim() -notmatch '^(?i)(off|false|0|no|disabled?)$'
}
function Invoke-SIDeadIdentityCleanup {
    <#
        THE CLEAN-UP (the file header, part 2). -Rest: the SI REST seam. -WhatIf: the plan only (no PATCH). -Sleep / -Polls:
        test seams; -MaxWaitSeconds: the whole step's read-back wait. Returns @{ Ok; Removed (@{ Resource; Kind; Identity }); Held
        (@{ Resource; Identity; Why }); Lines; Problems (loud); Soft (a soft problem: the list or an identity not readable) }.
        Ok $false = a problem the caller reports loudly (Problems). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [switch]$WhatIf, [string]$AppApi = '2025-07-01', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Polls = 30,
          # the whole step's read-back wait (every resource together), seconds
          [int]$MaxWaitSeconds = 600)
    $lines = New-Object System.Collections.Generic.List[string]; $problems = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[object]; $held = New-Object System.Collections.Generic.List[object]; $soft = New-Object System.Collections.Generic.List[string]
    $out = { [pscustomobject]@{ Ok = (-not $problems.Count); Removed = $removed.ToArray(); Held = $held.ToArray(); Lines = $lines.ToArray(); Problems = $problems.ToArray(); Soft = $soft.ToArray() } }
    try {
        $hdr = @{ 'Content-Type' = 'application/json' }
        $call = { param([string]$m, [string]$u, $b) $r = $null; try { $r = & $Rest $m $u $b 'https://management.azure.com/' $hdr } catch { $r = [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }; if (-not $r) { $r = [pscustomobject]@{ Status = 0; Body = 'no answer' } }; $r }
        $ok = { param($r) [int]$r.Status -ge 200 -and [int]$r.Status -lt 300 }
        $parse = { param($r) $o = $null; try { $o = ("$($r.Body)" | ConvertFrom-Json) } catch { $o = $null }; $o }
        $base = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App' -f $SubscriptionId, $ResourceGroup
        $readAll = {
            # every SI job and app of the resource group (every page); $null when a list could not be read completely
            $all = New-Object System.Collections.Generic.List[object]
            foreach ($kind in @('jobs', 'containerApps')) {
                $url = '{0}/{1}?api-version={2}' -f $base, $kind, $AppApi
                for ($p = 0; $url; $p++) {
                    if ($p -ge 50) { return $null }
                    $r = & $call 'GET' $url $null
                    if (-not (& $ok $r)) { return $null }
                    $pg = & $parse $r; if (-not $pg -or -not $pg.PSObject.Properties['value']) { return $null }
                    foreach ($x in @($pg.value)) { if ($x -and (Test-SISiResource $x)) { $all.Add([pscustomobject]@{ Kind = $(if ($kind -eq 'jobs') { 'job' } else { 'app' }); Name = [string]$x.name; Path = ('{0}/{1}/{2}' -f $base, $kind, [string]$x.name); Res = $x }) } }
                    $url = if ($pg.PSObject.Properties['nextLink']) { [string]$pg.nextLink } else { '' }
                }
            }
            , $all.ToArray()
        }
        # (a) the resource group's identity list, read completely -- else NOTHING is removed
        $live = Read-SILiveIdentities -Rest $Rest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        if (-not $live.Ok) { $t = 'identities: nothing removed -- {0}; the next update checks again' -f $live.Problem; $lines.Add($t); $soft.Add($t); return (& $out) }
        $res = & $readAll
        if ($null -eq $res) { $t = 'identities: nothing removed -- the jobs and apps could not be read completely; the next update checks again'; $lines.Add($t); $soft.Add($t); return (& $out) }
        $verdict = @{}   # identity key -> live | dead | unknown (one GET per identity)
        $state = { param([string]$id) $k = ConvertTo-SILiveIdentityKey $id; if (-not $verdict.ContainsKey($k)) { $verdict[$k] = Test-SIIdentityExists -Rest $Rest -Id $id }; $verdict[$k] }
        $todo = New-Object System.Collections.Generic.List[object]
        foreach ($x in @($res)) {
            $dead = New-Object System.Collections.Generic.List[string]
            foreach ($k in @(Get-SILiveIdentityKeys $x.Res)) {
                if (-not (Test-SILiveIdentityDead -Id $k -Live $live)) { continue }   # on the list, or another resource group: kept
                $v = & $state $k
                if ($v -eq 'dead') { $dead.Add($k) }
                elseif ($v -eq 'live') { $lines.Add(('identities: {0}: {1} is not on the resource group''s list but exists (its own read answered) -- kept' -f $x.Name, (Get-SILiveIdentityName $k))) }
                else {
                    $held.Add([pscustomobject]@{ Resource = $x.Name; Identity = $k; Why = 'its own read did not answer 404' })
                    $t = 'identities: {0} keeps {1} -- it is not on the resource group''s list, but its own read did not say it is gone (not 404); the next update checks again' -f $x.Name, (Get-SILiveIdentityName $k)
                    $lines.Add($t); $soft.Add($t)
                }
            }
            if (-not $dead.Count) { continue }
            $names = ($dead | ForEach-Object { Get-SILiveIdentityName $_ }) -join ', '
            # (b) a dead identity still USED (or signed in with) -> this resource is not touched
            $why = ''
            foreach ($d in $dead) {
                $cid = [string](Get-SILiveIdentityProp (Get-SILiveIdentityProp $x.Res @('identity', 'userAssignedIdentities')) @($d, 'clientId'))
                $u = Test-SIDeadIdentityUsed -Resource $x.Res -Id $d -ClientId $cid
                if ($u) { $why = ('{0}: {1}' -f (Get-SILiveIdentityName $d), $u); break }
            }
            # an app with a fixed revision suffix: a PATCH would need a new suffix (its template) -- not touched by this step
            if (-not $why -and $x.Kind -eq 'app' -and "$(Get-SILiveIdentityProp $x.Res @('properties', 'template', 'revisionSuffix'))".Trim()) { $why = 'the app has a fixed revision suffix (its template is not changed by this step)' }
            $patch = if ($why) { $null } else { Get-SIDeadIdentityPatch -Resource $x.Res -Dead $dead.ToArray() }
            if (-not $why -and -not $patch) { $why = 'no user-assigned identity would be left on it' }
            if ($why) {
                foreach ($d in $dead) { $held.Add([pscustomobject]@{ Resource = $x.Name; Identity = $d; Why = $why }) }
                $t = 'WARNING: identities: {0} carries the deleted identity {1}, NOT removed -- {2}; its next full write would be refused (set its identity right, then the next update removes it)' -f $x.Name, $names, $why
                $lines.Add($t); $problems.Add($t); continue
            }
            if ($WhatIf) { foreach ($d in $dead) { $lines.Add(('identities: {0} would lose the deleted identity {1} (re-run with -Apply)' -f $x.Name, (Get-SILiveIdentityName $d))) }; continue }
            $todo.Add([pscustomobject]@{ X = $x; Dead = $dead.ToArray(); Names = $names; Patch = $patch })
        }
        if ($WhatIf -or -not $todo.Count) {
            if (-not $lines.Count) { $lines.Add('identities: every identity on SI''s jobs and apps exists') }
            return (& $out)
        }
        # (e) the read back of ONE changed resource, inside ONE wait budget for the whole step (-MaxWaitSeconds): until Succeeded
        # without the dead key; an app also until its latest revision SERVES (Test-SIUpdaterRevisionServing where the updater
        # has it: Running, Healthy, all traffic; else its latest revision is its latest ready one)
        $budget = @{ Waited = 0 }
        $settle = {
            param($x, [string[]]$Dead)
            $deadKeys = @($Dead | ForEach-Object { ConvertTo-SILiveIdentityKey $_ })
            $last = ''; $still = @()
            for ($i = 0; $i -lt [Math]::Max(1, $Polls); $i++) {
                $g = & $call 'GET' ('{0}?api-version={1}' -f $x.Path, $AppApi) $null
                $j = if (& $ok $g) { & $parse $g } else { $null }
                $ps = [string](Get-SILiveIdentityProp $j @('properties', 'provisioningState'))
                $still = @(Get-SILiveIdentityKeys $j | Where-Object { $deadKeys -contains (ConvertTo-SILiveIdentityKey $_) })
                $ready = $true; $stop = $false; $rwhy = ''
                if ($j -and $x.Kind -eq 'app') {
                    $lr = [string](Get-SILiveIdentityProp $j @('properties', 'latestRevisionName'))
                    if (Get-Command -Name Test-SIUpdaterRevisionServing -ErrorAction SilentlyContinue) {
                        $rv = $null
                        if ($lr) { $rg = & $call 'GET' ('{0}/revisions/{1}?api-version={2}' -f $x.Path, $lr, $AppApi) $null; if (& $ok $rg) { $rv = & $parse $rg } }
                        $sv = Test-SIUpdaterRevisionServing -App $j -Rev $rv -Revision $lr
                        $ready = [bool]$sv.Ok; $stop = [bool]$sv.Failed; $rwhy = [string]$sv.Why
                    } else {
                        $ready = [bool]($lr -and $lr -eq [string](Get-SILiveIdentityProp $j @('properties', 'latestReadyRevisionName'))); $rwhy = 'its new revision is not ready'
                    }
                }
                $last = if (-not $j) { 'it could not be read' } elseif ($ps -in @('Failed', 'Canceled')) { "Azure shows $ps" } elseif ($still.Count) { 'it still lists the deleted identity' } elseif (-not $ready) { $rwhy } else { '' }
                if ($j -and $ps -eq 'Succeeded' -and -not $still.Count -and $ready) { return [pscustomobject]@{ Good = $true; Still = $false; Last = '' } }
                if ($ps -in @('Failed', 'Canceled') -or $stop) { break }
                if ($budget.Waited -ge $MaxWaitSeconds) { $last = ('{0}; the step''s wait of {1} s is used up' -f $last, $MaxWaitSeconds); break }
                & $Sleep 10; $budget.Waited += 10
            }
            [pscustomobject]@{ Good = $false; Still = [bool]@($still).Count; Last = $last }
        }
        # (c) the identity-only PATCH. The FIRST one is the CANARY (a job where there is one; the updater's own job only when no
        # other): it is read back before anything else is sent; the dead key still there / no read back = one WARNING, nothing else sent
        $order = @(@($todo | Where-Object { $_.X.Kind -eq 'job' -and $_.X.Name -ne 'caj-si-updater' }) + @($todo | Where-Object { $_.X.Kind -eq 'job' -and $_.X.Name -eq 'caj-si-updater' }) + @($todo | Where-Object { $_.X.Kind -ne 'job' }))
        $changed = New-Object System.Collections.Generic.List[object]
        $n = 0; $halt = ''
        foreach ($t0 in $order) {
            $n++
            $x = $t0.X
            if ($halt) { foreach ($d in $t0.Dead) { $held.Add([pscustomobject]@{ Resource = $x.Name; Identity = $d; Why = $halt }) }; continue }
            $r = & $call 'PATCH' ('{0}?api-version={1}' -f $x.Path, $AppApi) (ConvertTo-Json -InputObject $t0.Patch -Depth 10 -Compress)
            if (-not (& $ok $r)) {
                foreach ($d in $t0.Dead) { $held.Add([pscustomobject]@{ Resource = $x.Name; Identity = $d; Why = 'the PATCH was refused' }) }
                $t = 'WARNING: identities: the deleted identity {0} could NOT be taken off {1} (HTTP {2}) -- {3}the next update tries again' -f $t0.Names, $x.Name, [int]$r.Status, $(if ($n -eq 1) { 'it was the first change (the canary), so no other job or app was changed; ' } else { '' })
                $lines.Add($t); $problems.Add($t)
                if ($n -eq 1) { $halt = 'the canary was refused -- not sent' }
                continue
            }
            if ($n -eq 1) {
                $c = & $settle $x $t0.Dead
                if (-not $c.Good) {
                    $t = 'WARNING: identities: the first change ({0}, the canary) did not read back ({1}) -- no other job or app was changed; the next update tries again' -f $x.Name, $c.Last
                    $lines.Add($t); $problems.Add($t)
                    $halt = 'the canary did not read back -- not sent'
                    if ($c.Still) { foreach ($d in $t0.Dead) { $held.Add([pscustomobject]@{ Resource = $x.Name; Identity = $d; Why = $halt }) }; continue }
                }
            }
            # (d) one line per removed reference
            foreach ($d in $t0.Dead) {
                $removed.Add([pscustomobject]@{ Resource = $x.Name; Kind = $x.Kind; Identity = $d })
                $lines.Add(('identities: {0}: the deleted identity {1} taken off ({2}) -- {3}' -f $x.Name, (Get-SILiveIdentityName $d), $d, $(if ($x.Kind -eq 'job') { 'its next execution runs without it; a running one is not changed' } else { 'a new revision, waited for until it serves' })))
            }
            if ($n -gt 1) { $changed.Add($t0) }
        }
        foreach ($t0 in $changed) {
            $c = & $settle $t0.X $t0.Dead
            if (-not $c.Good) { $t = 'WARNING: identities: {0} did not read back after the deleted identity was taken off ({1}) -- the next update checks again' -f $t0.X.Name, $c.Last; $lines.Add($t); $problems.Add($t) }
        }
        $again = & $readAll
        if ($null -eq $again) { $t = 'WARNING: identities: the jobs and apps could not be read back -- not proven that only live identities remain'; $lines.Add($t); $problems.Add($t); return (& $out) }
        $live2 = Read-SILiveIdentities -Rest $Rest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $src = if ($live2.Ok) { $live2 } else { $live }
        $bad = @(foreach ($x in @($again)) { foreach ($k in @(Get-SILiveIdentityKeys $x.Res)) { if ((Test-SILiveIdentityDead -Id $k -Live $src) -and $verdict[(ConvertTo-SILiveIdentityKey $k)] -ne 'live' -and -not @($held | Where-Object { $_.Resource -eq $x.Name -and (ConvertTo-SILiveIdentityKey $_.Identity) -eq (ConvertTo-SILiveIdentityKey $k) }).Count) { '{0}: {1}' -f $x.Name, (Get-SILiveIdentityName $k) } } })
        if ($bad.Count) { $t = 'WARNING: identities: read back -- still a deleted identity on {0}' -f ($bad -join '; '); $lines.Add($t); $problems.Add($t) }
        else { $lines.Add(('identities: read back -- {0} deleted identity reference(s) taken off; every other identity on SI''s jobs and apps is on the resource group''s list' -f $removed.Count)) }
        & $out
    } catch {
        $t = 'WARNING: identities: the clean-up stopped ({0}) -- the next update checks again' -f $_.Exception.Message
        $lines.Add($t); $problems.Add($t); & $out
    }
}
