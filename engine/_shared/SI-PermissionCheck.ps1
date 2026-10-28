#Requires -Version 5.1
<#
    SI -- AN ENGINE CHECKS ITS OWN PERMISSIONS AT RUN START, and the run-health END record says what is missing.

    Why: asset tagging runs under its own identity, and on every Pro install that identity had no user in the Pro database --
    the daily run failed for days before anyone saw why (operator 2026-10-08: "make sure to add permissions into the get
    started so we can verify we have the needed permissions"). The web app cannot read other identities' grants, but every
    engine can read its OWN, cheaply and exactly:
      api       -- the 'roles' claim of the engine's own access token for each API (Microsoft Graph, Microsoft Threat
                   Protection, Defender for Endpoint) against the catalog. One token per API, nothing else is called.
      azure     -- ONE read of the caller's own permissions (Microsoft.Authorization/permissions) at the collection scope;
                   Reader = '*/read'. A scope that cannot be read is "not checked", never "missing".
      database  -- Pro only: the settings layer already signs in to the Pro database; it records whether the sign-in
                   worked and IS_ROLEMEMBER for the roles ($global:SI_ProDatabaseAccess, Read-SIProDatabaseAccess in
                   engine/pro-settings/SI-ProSettings.ps1). Community has no Pro database: the area is simply absent.
    The catalog is config/permissions.locked.json -- the ONE list (engine, docs and tests read it).

    NEVER STOPS A RUN (warn, don't block): every function here swallows its own failures and says "not checked". A missing
    permission the run actually needs still fails the run exactly as before.

    Result (Invoke-SIPermissionSelfCheck, kept in $global:SI_PermissionCheck):
      { Engine; Identity (client id); IdentityKey; Label; Checked = @( { Area; Item; State = ok|missing|not-checked; Fix; When } ) }
    The run-health END record carries ConvertTo-SIPermissionGapsJson of it (only the gaps and the not-checked items).

    PS 5.1 safe, no PowerShell modules (REST / .NET only). Shipped in both editions; it never loads a Pro path.
#>

function Get-SIPermissionCatalog {
    <# The catalog (config/permissions.locked.json), parsed. -Path is a seam for tests; cached per process for the default path. #>
    param([string]$Path)
    $default = -not $Path
    if ($default -and $script:SIPermissionCatalog) { return $script:SIPermissionCatalog }
    if ($default) { $Path = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'config', 'permissions.locked.json') }
    $cat = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ($default) { $script:SIPermissionCatalog = $cat }
    $cat
}

function Get-SIPermissionEngineSpec {
    <# PURE. Which identity an engine (SI_ENGINE) runs as, and which areas it checks: the catalog's entry, else 'default'. #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][string]$Engine)
    $e = $Engine.Trim().ToLowerInvariant()
    $spec = $null
    if ($Catalog.engines) {
        foreach ($p in $Catalog.engines.PSObject.Properties) { if ($p.Name -eq $e) { $spec = $p.Value } }
        if (-not $spec) { $spec = $Catalog.engines.default }
    }
    if (-not $spec) { throw ("the permission catalog has no entry for the engine '{0}' and no default" -f $e) }
    $key = [string]$spec.identity
    $identity = $null
    if ($Catalog.identities) { foreach ($p in $Catalog.identities.PSObject.Properties) { if ($p.Name -eq $key) { $identity = $p.Value } } }
    if (-not $identity) { throw ("the permission catalog names no identity '{0}' for the engine '{1}'" -f $key, $e) }
    [pscustomobject]@{ Engine = $e; IdentityKey = $key; Identity = $identity; Checks = @($spec.checks | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
}

function ConvertFrom-SIPermissionJwt {
    <# PURE. The claims of a JWT (no signature check -- only our own token's roles / appid are read). $null when not a JWT. #>
    param([AllowEmptyString()][AllowNull()][string]$Token)
    $parts = ([string]$Token) -split '\.'
    if ($parts.Count -lt 2 -or -not $parts[1]) { return $null }
    $p = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    try { return ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json) } catch { return $null }
}

function Get-SIPermissionTokenRoles {
    <# PURE. The application permissions ('roles' claim) of a token; @() when it has none. $null when it is not a token. #>
    param([AllowEmptyString()][AllowNull()][string]$Token)
    $c = ConvertFrom-SIPermissionJwt -Token $Token
    if ($null -eq $c) { return $null }
    # the leading comma keeps an EMPTY list a list ($null would read as "no token" = not checked)
    if ($c.PSObject.Properties['roles']) { return , [string[]]@($c.roles | ForEach-Object { [string]$_ }) }
    return , [string[]]@()
}

function Test-SIPermissionTruthy {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    ("$Value".Trim().Trim('$').ToLowerInvariant()) -in @('true', '1', 'yes', 'on')
}

function New-SIPermissionItem {
    param([string]$Area, [string]$Item, [string]$State, [string]$Fix, [string]$When)
    [pscustomobject]@{ Area = $Area; Item = $Item; State = $State; Fix = $Fix; When = $When }
}

function Test-SIPermissionApiRoles {
    <#
        PURE. One API's required roles (the catalog entry: roles + conditionalRoles) against the roles of the engine's own
        token. -TokenRoles $null = the token could not be had: every role is "not-checked". A conditional role carries its
        'when' setting; whether it counts is decided when the result is recorded (the setting may come from the Pro database).
    #>
    param([Parameter(Mandatory)]$Api, [AllowNull()][string[]]$TokenRoles, [string]$Fix, [string]$Reason)
    $have = @{}
    $known = ($null -ne $TokenRoles)
    if ($known) { foreach ($r in $TokenRoles) { $have[([string]$r).ToLowerInvariant()] = $true } }
    $out = New-Object System.Collections.Generic.List[object]
    $want = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Api.roles)) { if ($r) { $want.Add(@{ Role = [string]$r; When = '' }) } }
    foreach ($c in @($Api.conditionalRoles)) { if ($c -and $c.role) { $want.Add(@{ Role = [string]$c.role; When = [string]$c.when }) } }
    foreach ($w in $want) {
        $state = if (-not $known) { 'not-checked' } elseif ($have.ContainsKey($w.Role.ToLowerInvariant())) { 'ok' } else { 'missing' }
        $fixText = if ($state -eq 'not-checked' -and $Reason) { $Reason } else { $Fix }
        $out.Add((New-SIPermissionItem -Area ([string]$Api.resource) -Item $w.Role -State $state -Fix $fixText -When $w.When))
    }
    $out.ToArray()
}

function Test-SIPermissionAzureActions {
    <#
        PURE. The catalog's Azure items against the caller's own permissions at a scope (the 'value' of
        Microsoft.Authorization/permissions: entries of actions + notActions). An item is ok when one entry has an action
        pattern that covers it (wildcards, case-insensitive) and no notAction of that entry removes it.
        -Permissions $null = they could not be read: every item is "not-checked" (never "missing").
    #>
    param([object[]]$Items, [AllowNull()][object[]]$Permissions, [string]$Scope, [string]$Fix, [string]$Reason)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($Items)) {
        if (-not $it) { continue }
        $name = [string]$it.item; $action = [string]$it.action; $when = [string]$it.when
        if ($null -eq $Permissions) {
            $out.Add((New-SIPermissionItem -Area 'Azure' -Item $name -State 'not-checked' -Fix $(if ($Reason) { $Reason } else { $Fix }) -When $when))
            continue
        }
        $granted = $false
        foreach ($p in @($Permissions)) {
            if (-not $p) { continue }
            $hit = $false
            foreach ($a in @($p.actions)) { if ($a -and ($action -like [string]$a)) { $hit = $true; break } }
            if (-not $hit) { continue }
            $removed = $false
            foreach ($n in @($p.notActions)) { if ($n -and ($action -like [string]$n)) { $removed = $true; break } }
            if (-not $removed) { $granted = $true; break }
        }
        $label = if ($Scope) { '{0} ({1})' -f $name, $Scope } else { $name }
        $out.Add((New-SIPermissionItem -Area 'Azure' -Item $label -State $(if ($granted) { 'ok' } else { 'missing' }) -Fix $Fix -When $when))
    }
    $out.ToArray()
}

function Get-SIPermissionDatabaseFailure {
    <#
        PURE. Why a sign-in to the Pro database failed, from the error's text -- because "cannot connect" is not "no user":
          firewall     -- the server's firewall or network rules refused the connection before any sign-in: SQL error 40615
                          ("Cannot open server ... Client with IP address ... is not allowed to access the server"), 40914
                          (a virtual network rule), 47073 (public network access is off)
          unreachable  -- the server did not answer or was not found: a connection timeout, a network error, a name that
                          does not resolve, a database that is not available right now (40613)
          no-user      -- a database that ANSWERED refused the sign-in: "Login failed for user" (18456), the
                          token-identified principal, "Cannot open database ... requested by the login" (4060)
          unknown      -- anything else (an empty text too)
        The firewall is asked first: its text also says "Cannot open server ... requested by the login", which read alone
        looks like a refused sign-in (first customer install 2026-10-12: the database user existed, the firewall rule for
        the install's own jobs did not, and Get Started said "a database user for this identity is missing").
    #>
    param([AllowEmptyString()][AllowNull()][string]$Message)
    $m = "$Message"
    if (-not $m.Trim()) { return 'unknown' }
    if ($m -match '(?i)is not allowed to access the server|\b(40615|40914|47073)\b|Deny Public Network Access|virtual network rule|Connection was denied') { return 'firewall' }
    if ($m -match '(?i)Connection Timeout Expired|timeout period elapsed|network-related or instance-specific|No such host is known|Name or service not known|nodename nor servname|could not be resolved|server was not found or was not accessible|is not currently available|\b40613\b|actively refused|forcibly closed') { return 'unreachable' }
    if ($m -match '(?i)Login failed for user|\b18456\b|token-identified principal|Cannot open database .* requested by the login') { return 'no-user' }
    'unknown'
}

function Test-SIPermissionDatabaseRoles {
    <#
        PURE. The Pro database roles the identity needs against what the settings layer recorded ($global:SI_ProDatabaseAccess):
          $null                              -> not checked (the settings layer did not get to the database)
          @{ SignIn = 'failed'; Error }      -> one "missing" item, and WHICH one the error says (Get-SIPermissionDatabaseFailure):
                                                the database could not be reached (its firewall refused this job / it did
                                                not answer) -- or the identity cannot sign in (no database user). Only a
                                                refused sign-in on a database that answers is "no database user".
          @{ SignIn = 'ok'; Roles = @{..} }  -> per role: IS_ROLEMEMBER = 1 (or db_owner) ok, 0 missing, unknown not-checked
    #>
    param([string[]]$Roles, $Access, [string]$Fix)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Access) {
        foreach ($r in @($Roles)) { if ($r) { $out.Add((New-SIPermissionItem -Area 'Pro database' -Item $r -State 'not-checked' -Fix 'The run did not reach the Pro database, so its access was not checked.')) } }
        return $out.ToArray()
    }
    $signIn = [string]$Access.SignIn
    if ($signIn -eq 'failed') {
        $err = ''
        if ($Access -is [System.Collections.IDictionary]) { if ($Access.Contains('Error')) { $err = [string]$Access['Error'] } }
        elseif ($Access.PSObject.Properties['Error']) { $err = [string]$Access.Error }
        $why = Get-SIPermissionDatabaseFailure -Message $err
        if ($why -eq 'firewall') {
            $out.Add((New-SIPermissionItem -Area 'Pro database' -Item 'connection (the database could not be reached: its firewall refused this job)' -State 'missing' `
                -Fix 'The database user is not the problem: the database server''s firewall refused this job before it could sign in. As an Azure administrator of the install: open the SQL server in the Azure portal, Networking, and allow Azure services and resources to access this server -- or run the guided install again (setup\Install-SecurityInsight.ps1): its database step sets the rule the install''s own jobs need.'))
            return $out.ToArray()
        }
        if ($why -eq 'unreachable') {
            $out.Add((New-SIPermissionItem -Area 'Pro database' -Item 'connection (the database could not be reached: it did not answer)' -State 'missing' `
                -Fix 'The database user is not the problem: the database server did not answer this job. Check in the Azure portal that the SQL server and the Pro database are running and that the server''s Networking lets the install''s jobs in; the next run checks again.'))
            return $out.ToArray()
        }
        $out.Add((New-SIPermissionItem -Area 'Pro database' -Item 'sign-in (a database user for this identity)' -State 'missing' -Fix $Fix))
        return $out.ToArray()
    }
    $have = $Access.Roles
    $owner = $false
    if ($have -is [System.Collections.IDictionary] -and $have.Contains('db_owner')) { $owner = ([string]$have['db_owner'] -eq '1') }
    foreach ($r in @($Roles)) {
        if (-not $r) { continue }
        $v = $null
        if ($have -is [System.Collections.IDictionary] -and $have.Contains($r)) { $v = $have[$r] }
        $state = if ($owner -or [string]$v -eq '1') { 'ok' } elseif ($null -eq $v -or [string]$v -eq '') { 'not-checked' } else { 'missing' }
        $fixText = if ($state -eq 'not-checked') { 'The role membership could not be read from the Pro database.' } else { $Fix }
        $out.Add((New-SIPermissionItem -Area 'Pro database' -Item $r -State $state -Fix $fixText))
    }
    $out.ToArray()
}

function Resolve-SIPermissionAzureScope {
    <#
        PURE over -Globals. The scope the Azure read is made at -- where SecurityInsight collects from:
          SI_PermissionCheck_AzureScope (an explicit scope), else the first of SI_Bootstrap_IdentityReaderScopes (what setup
          granted Reader at: the subscription, a management group or the tenant root group), else the install's
          subscription (SI_AzSubscriptionId, or the one in SI_WorkspaceResourceId). Reader granted higher up is inherited, so
          the subscription is never a false "missing". '' when none is known.
    #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $x = [string](& $g 'SI_PermissionCheck_AzureScope')
    if ($x.Trim()) { return $x.Trim().TrimEnd('/') }
    foreach ($s in @(& $g 'SI_Bootstrap_IdentityReaderScopes')) { if ($s -and "$s".Trim().StartsWith('/')) { return "$s".Trim().TrimEnd('/') } }
    $sub = [string](& $g 'SI_AzSubscriptionId')
    if (-not $sub.Trim()) { $ws = [string](& $g 'SI_WorkspaceResourceId'); if ($ws -match '/subscriptions/([^/]+)') { $sub = $Matches[1] } }
    if ($sub.Trim()) { return ('/subscriptions/{0}' -f $sub.Trim()) }
    ''
}

function Get-SIPermissionGlobals {
    <# The current $global: values as a hashtable (what the pure functions read). #>
    $h = @{}
    foreach ($v in (Get-Variable -Scope Global -ErrorAction SilentlyContinue)) { $h[$v.Name] = $v.Value }
    $h
}

function Invoke-SIPermissionSelfCheck {
    <#
        Run start: the engine's own API and Azure permissions (the database part is added when the result is recorded --
        the settings layer reads it later in the run start). NEVER THROWS and never stops the run; prints one line per gap.
        -GetToken { param($Resource) <token> } and -GetArmPermissions { param($Scope) , @(<value entries>) } are seams
        (tests; $null from -GetArmPermissions = could not be read, , @() = read and empty);
        by default they are SecurityInsight's own REST sign-in (Get-SIAzureToken, Invoke-SIArm) -- the same identity the
        run uses for everything else. Sets and returns $global:SI_PermissionCheck.
    #>
    param([Parameter(Mandatory)][string]$Engine, $Catalog, [scriptblock]$GetToken, [scriptblock]$GetArmPermissions,
          [hashtable]$Globals, [switch]$Quiet)
    $result = $null
    try {
        if (-not $Catalog) { $Catalog = Get-SIPermissionCatalog }
        if (-not $Globals) { $Globals = Get-SIPermissionGlobals }
        $spec = Get-SIPermissionEngineSpec -Catalog $Catalog -Engine $Engine
        $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
        $identity = [string](& $g 'SI_UAMI_ClientId')
        if (-not ([bool](& $g 'SI_UseManagedIdentity')) -or -not $identity) { $id2 = [string](& $g 'SI_SPN_AppId'); if ($id2) { $identity = $id2 } }
        if (-not $GetToken) {
            $GetToken = { param($Resource) if (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue) { Get-SIAzureToken -Resource $Resource } }
        }
        if (-not $GetArmPermissions) {
            $GetArmPermissions = { param($Scope)
                if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { return $null }
                $r = Invoke-SIArm -Path ($Scope + '/providers/Microsoft.Authorization/permissions') -ApiVersion '2022-04-01'
                if ($null -eq $r) { return $null }
                , @($r.value)
            }
        }
        $items = New-Object System.Collections.Generic.List[object]
        $fix = $spec.Identity.fix
        if ($spec.Checks -contains 'api') {
            foreach ($api in @($spec.Identity.api)) {
                $roles = $null; $why = ''
                try {
                    $tok = [string](& $GetToken ([string]$api.audience))
                    if ($tok) {
                        $roles = Get-SIPermissionTokenRoles -Token $tok
                        $claims = ConvertFrom-SIPermissionJwt -Token $tok
                        if (-not $identity -and $claims) { foreach ($n in 'appid', 'azp') { if ($claims.PSObject.Properties[$n] -and $claims.$n) { $identity = [string]$claims.$n; break } } }
                    }
                    if ($null -eq $roles) { $why = ('No access token for {0} could be had, so its permissions were not checked.' -f $api.resource) }
                } catch { $roles = $null; $why = ('No access token for {0} could be had, so its permissions were not checked ({1}).' -f $api.resource, $_.Exception.Message) }
                foreach ($i in (Test-SIPermissionApiRoles -Api $api -TokenRoles $roles -Fix ([string]$fix.api) -Reason $why)) { $items.Add($i) }
            }
        }
        if ($spec.Checks -contains 'azure' -and @($spec.Identity.azure).Count) {
            $scope = Resolve-SIPermissionAzureScope -Globals $Globals
            $perms = $null; $why = ''
            if (-not $scope) { $why = 'The scope SecurityInsight collects from is not known here, so the Azure roles were not checked.' }
            else {
                try { $perms = & $GetArmPermissions $scope } catch { $perms = $null; $why = ('The Azure permissions at {0} could not be read ({1}), so the Azure roles were not checked.' -f $scope, $_.Exception.Message) }
                if ($null -eq $perms -and -not $why) { $why = ('The Azure permissions at {0} could not be read, so the Azure roles were not checked.' -f $scope) }
            }
            foreach ($i in (Test-SIPermissionAzureActions -Items @($spec.Identity.azure) -Permissions $perms -Scope $scope -Fix ([string]$fix.azure) -Reason $why)) { $items.Add($i) }
        }
        $result = [pscustomobject]@{
            Engine = $spec.Engine; Identity = $identity; IdentityKey = $spec.IdentityKey; Label = [string]$spec.Identity.label
            Checks = $spec.Checks; DatabaseRoles = @($spec.Identity.database | ForEach-Object { [string]$_ }); DatabaseFix = [string]$fix.database
            Checked = $items.ToArray(); Error = ''; CheckedAt = [datetime]::UtcNow
        }
    } catch {
        # the check itself failed: recorded as such (Get Started counts it as open), and the run goes on
        $result = [pscustomobject]@{ Engine = $Engine; Identity = ''; IdentityKey = ''; Label = ''; Checks = @(); DatabaseRoles = @(); DatabaseFix = ''
            Checked = @(); Error = ('The permission check could not run: {0}' -f $_.Exception.Message); CheckedAt = [datetime]::UtcNow }
    }
    $global:SI_PermissionCheck = $result
    if (-not $Quiet) { try { Write-SIPermissionCheckSummary -Check $result } catch { } }
    $result
}

function Complete-SIPermissionCheck {
    <#
        PURE. The check as it stands at the end of the run: the conditional items whose setting is off are dropped (asset
        tagging writes only with SI_Pro_AssetTagging_Apply), and -- on a Pro install (SI_ProSqlServer + SI_ProSqlDatabase)
        when the engine checks the database -- the Pro database items from -DatabaseAccess. Community: no database area.
    #>
    param([Parameter(Mandatory)]$Check, [hashtable]$Globals = @{}, $DatabaseAccess)
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Check.Checked)) {
        if (-not $i) { continue }
        if ($i.When -and -not (Test-SIPermissionTruthy (& $g ([string]$i.When)))) { continue }
        $items.Add($i)
    }
    $isPro = -not [string]::IsNullOrWhiteSpace([string](& $g 'SI_ProSqlServer')) -and -not [string]::IsNullOrWhiteSpace([string](& $g 'SI_ProSqlDatabase'))
    if ($isPro -and @($Check.Checks) -contains 'database' -and @($Check.DatabaseRoles).Count) {
        foreach ($i in (Test-SIPermissionDatabaseRoles -Roles @($Check.DatabaseRoles) -Access $DatabaseAccess -Fix ([string]$Check.DatabaseFix))) { $items.Add($i) }
    }
    [pscustomobject]@{ Engine = $Check.Engine; Identity = $Check.Identity; IdentityKey = $Check.IdentityKey; Label = $Check.Label
        Checked = $items.ToArray(); Error = [string]$Check.Error; CheckedAt = $Check.CheckedAt }
}

function Get-SIPermissionListFingerprint {
    <#
        PURE. A short fingerprint of a set of permission names ('<api>|<permission>'; case, order and repeats do not
        matter): 16 hex characters of their SHA-256, '' for an empty set. The run record carries the fingerprint of the
        application permissions an engine actually CHECKED; a reader that holds the list (the update's note about
        permissions an existing install has not granted yet, setup/_shared/SI-PermissionNote.ps1) can tell "nothing is
        missing from THIS list" from "nothing was missing from an older, shorter list".
    #>
    param([string[]]$Names = @())
    $set = @{}
    foreach ($n in @($Names)) { $k = "$n".Trim().ToLowerInvariant(); if ($k) { $set[$k] = $true } }
    if (-not $set.Count) { return '' }
    [string[]]$keys = @($set.Keys)
    [Array]::Sort($keys, [System.StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($keys -join "`n"))) } finally { $sha.Dispose() }
    $hex = New-Object System.Text.StringBuilder
    foreach ($b in $hash) { $null = $hex.Append($b.ToString('x2')) }
    $hex.ToString().Substring(0, 16)
}

function ConvertTo-SIPermissionGapsJson {
    <#
        PURE. What the run-health record carries: the engine, its identity and ONLY the gaps and the not-checked items (an
        empty list = every permission is in place). Kept short: at most -MaxItems items, then 'more' says how many were left
        out (the missing ones first). 'apiChecked' = the fingerprint of the application permissions that WERE checked
        (ok or missing; Get-SIPermissionListFingerprint) -- absent when none was.
    #>
    param([Parameter(Mandatory)]$Check, [int]$MaxItems = 40)
    $gaps = @(@($Check.Checked) | Where-Object { $_ -and $_.State -eq 'missing' }) + @(@($Check.Checked) | Where-Object { $_ -and $_.State -eq 'not-checked' })
    $keep = @($gaps | Select-Object -First $MaxItems)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($i in $keep) { $list.Add([ordered]@{ area = [string]$i.Area; item = [string]$i.Item; state = [string]$i.State; fix = [string]$i.Fix }) }
    $o = [ordered]@{ v = 1; engine = [string]$Check.Engine; identity = [string]$Check.Identity; label = [string]$Check.Label
        missing = @($gaps | Where-Object { $_.State -eq 'missing' }).Count; notChecked = @($gaps | Where-Object { $_.State -eq 'not-checked' }).Count
        items = $list.ToArray(); more = ($gaps.Count - $keep.Count) }
    if ([string]$Check.Error) { $o['error'] = [string]$Check.Error }
    # the application permissions this run checked on its own token (every area but the Azure roles and the database)
    $apiNames = @(@($Check.Checked) | Where-Object { $_ -and [string]$_.State -ne 'not-checked' -and @('Azure', 'Pro database') -notcontains [string]$_.Area } | ForEach-Object { '{0}|{1}' -f $_.Area, $_.Item })
    if ($apiNames.Count) { $o['apiChecked'] = Get-SIPermissionListFingerprint -Names $apiNames }
    # -InputObject: a 1-item list stays a list in PS 5.1
    ConvertTo-Json -InputObject $o -Depth 5 -Compress
}

function Get-SIRunHealthPermissionGaps {
    <#
        The PermissionGaps value of a run-health record: '' unless this process ran the self-check, the record is an END
        record and it is the engine's own (the job flow's step records 'flow:<engine>' speak for another job's identity).
        NEVER THROWS.
    #>
    param($RunContext, [string]$Phase = 'End')
    try {
        if ($Phase -ne 'End') { return '' }
        $chk = Get-Variable -Scope Global -Name SI_PermissionCheck -ValueOnly -ErrorAction SilentlyContinue
        if (-not $chk) { return '' }
        $eng = if ($RunContext) { [string]$RunContext.Engine } else { '' }
        if ($eng -like 'flow:*') { return '' }
        $db = Get-Variable -Scope Global -Name SI_ProDatabaseAccess -ValueOnly -ErrorAction SilentlyContinue
        $done = Complete-SIPermissionCheck -Check $chk -Globals (Get-SIPermissionGlobals) -DatabaseAccess $db
        return (ConvertTo-SIPermissionGapsJson -Check $done)
    } catch { return '' }
}

function Write-SIPermissionCheckSummary {
    <# One line per missing permission (customer-facing), one line for what could not be checked; never throws. #>
    param($Check)
    if (-not $Check) { return }
    if ([string]$Check.Error) { Write-Warning ('[permissions] {0}' -f $Check.Error); return }
    $who = if ($Check.Identity) { '{0} ({1})' -f $Check.Label, $Check.Identity } else { $Check.Label }
    $missing = @(@($Check.Checked) | Where-Object { $_.State -eq 'missing' -and -not $_.When })
    $notChecked = @(@($Check.Checked) | Where-Object { $_.State -eq 'not-checked' -and -not $_.When })
    if (-not $missing.Count) { Write-Host ('[permissions] {0}: every permission checked is in place{1}.' -f $who, $(if ($notChecked.Count) { ' ({0} could not be checked)' -f $notChecked.Count } else { '' })) }
    foreach ($m in $missing) { Write-Warning ('[permissions] {0} is missing {1} {2} -- {3}' -f $who, $m.Area, $m.Item, $m.Fix) }
    foreach ($a in @($notChecked | Group-Object Area)) { Write-Host ('[permissions] {0}: {1} not checked -- {2}' -f $who, $a.Name, $a.Group[0].Fix) }
}
