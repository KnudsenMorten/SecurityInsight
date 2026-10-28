#Requires -Version 5.1
<#
    ENTRA CONTEXT -- what Entra ID knows about an identity that the user / service-principal lists do not carry, read ONCE
    per run for the whole tenant and added as PARTS to the Entra records the discovery already captured. Nothing here
    creates a record: a part is only added to a record that exists (as Invoke-SISpOwnerCapture does).

    READ ONLY. Every call is a GET (the Defender for Identity summary is one hunting query). Each read is ONE paged
    tenant-wide call whose pages are summarised as they arrive (Invoke-SIPagedRest -OnPage) -- never one request per user
    or per service principal. The few reads that go per OBJECT go per policy object, not per identity: the members of the
    groups Conditional Access names, the owners of the groups that hold an Entra role, the instances of each access
    review -- tens of calls in a large tenant.

      service principal records (entra | service_principal | <object id>)
        app            the application registration of the principal (GET /applications, owners expanded): credentials,
                       requested permissions (id AND name), owners (id + sign-in name + display name), publisher domain,
                       notes, and its federated credentials (a second read: Graph expands one relation per request)
        oauth2Grants   the delegated permissions granted to it, per API, with the consent type and HOW MANY users
                       consented (GET /oauth2PermissionGrants, read once by the discovery -- Get-SIOauth2GrantsByClient)
        signIn         last sign-in of the application, as a client and as a resource (beta servicePrincipalSignInActivities)
        credUsage      when each secret / certificate was last used (beta appCredentialSignInActivities)
        spExtra        a managed identity's resource (alternativeNames)
        contextReads   which of the tenant-wide reads completed -- so "no owner" / "never used" is a fact, not a guess
      user and service principal records
        roleScopes     every Entra role assignment WITH its scope (tenant / administrative unit / object, id + name), the
                       paths a role is held through (direct, group, a group it can activate into), what activating an
                       eligible role requires, until when an activated role lasts (an activated role is an ELIGIBLE role),
                       and, for a Tier 0 identity only, the LEVEL inside Tier 0 (tierLevel: level 1 = a Tier 0 role is
                       tenant-wide, level 2 = held on an administrative unit / one object only -- still Tier 0)
        risk           Identity Protection: risk level / state / detail, and the risk detections of the last 30 days
        controls       the privileged objects it OWNS (a group that holds a role, a service principal with a role)
        accessReview   the last access review of the roles, groups and applications it holds
        notLicensed    the context the tenant's licences do not include -- { fields, licence, text: "not licensed (...)" }
      user records
        manager        id + sign-in name + display name
        sponsors       a guest's sponsors
        ca             Conditional Access: how many enabled policies apply, whether one enforces MFA for all cloud apps,
                       the policies that apply to the user but EXCLUDE it (id + name), and whether it is excluded from
                       ALL of them (excludedFromAll -- one of the two break-glass rules)
      Entra device records (entra | device | <device id>)
        registeredOwners   the registered owners (id + sign-in name + display name)
      Defender for Identity user records (mdi | user | <object id>)
        logon          30 days of IdentityLogonEvents, summarised in the query: last on-premises logon, cleartext LDAP
                       binds, NTLM logons

    A READ THAT FAILS never fails the run and never turns into a finding: its parts are simply not written (unknown). A
    read the tenant is NOT LICENSED for is recorded as such, and the records say so in the 'notLicensed' part
    (-> si_not_licensed) -- never in a security field: "not licensed" in si_ca_excluded_policies would read as a
    break-glass account.

    No PowerShell modules. PowerShell 5.1 syntax: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name ConvertTo-SIOwnerItem -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDerivedSources.ps1') }

# =====================================================================================================================
#  STATE, AND ONE READ
# =====================================================================================================================

function Get-SIEntraContextState {
    <# The run's context state: Reads (name -> how the read went), Apps (the application registrations), NotLicensed. #>
    if ($null -eq $global:SIEntraContextState) { $global:SIEntraContextState = @{ Reads = [ordered]@{}; Apps = $null; NotLicensed = (New-Object System.Collections.ArrayList) } }
    $global:SIEntraContextState
}

function Reset-SIEntraContextState {
    <# Starts the context of a new run (the service-principal discovery calls it before its first context read). #>
    $global:SIEntraContextState = $null
    $null = Get-SIEntraContextState
}

function Write-SIEntraContextLine {
    <# One plain line for the run log (never throws; works before the engine's own writers are loaded). #>
    param([string]$Message, [switch]$Warn)
    try {
        if ($Warn) { if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $Message } else { Write-Warning $Message } }
        elseif (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $Message } else { Write-Host ('[INFO] ' + $Message) }
    } catch { }
}

function Get-SIEntraContextFailure {
    <#
        PURE. Why a read did not complete, from its error text: @{ Kind = licence | permission | throttled | other; Text }.
        licence     the tenant does not have the licence the data needs (Graph says so in the error)
        permission  the read was refused (403) for another reason: the permission is not granted yet
    #>
    param([AllowNull()][AllowEmptyString()][string]$ErrorText, [string]$Licence = '')
    $e = [string]$ErrorText
    if ($e -match '(?i)premium|licen[sc]e|NonPremiumTenant|B2C tenant|not onboarded|AadPremiumLicenseRequired|requires an? .*subscription|workload identit') {
        $what = $Licence; if (-not $what) { $what = 'a licence the tenant does not have' }
        return @{ Kind = 'licence'; Text = ('not licensed ({0})' -f $what) }
    }
    if ($e -match '(?i)HTTP 403|\(403\)|Forbidden|Authorization_RequestDenied|Insufficient privileges|AccessDenied|PermissionScopeNotGranted|Unauthorized|HTTP 401') {
        return @{ Kind = 'permission'; Text = 'access was refused -- the permission is not granted to the SecurityInsight identity yet' }
    }
    if ($e -match '(?i)HTTP 429|\(429\)|TooManyRequests') { return @{ Kind = 'throttled'; Text = 'Microsoft kept asking SecurityInsight to slow down' } }
    if (-not $e) { return @{ Kind = 'other'; Text = 'no reason given' } }
    return @{ Kind = 'other'; Text = $e }
}

function Add-SIEntraNotLicensed {
    <# Records that the tenant is not licensed for a piece of context: the fields it would fill, for which records. #>
    param([Parameter(Mandatory)][string]$Licence, [Parameter(Mandatory)][string[]]$Fields, [ValidateSet('user', 'service_principal', 'both')][string]$AppliesTo = 'both')
    $st = Get-SIEntraContextState
    foreach ($x in @($st.NotLicensed)) { if ($x.licence -eq $Licence -and $x.appliesTo -eq $AppliesTo -and (@($x.fields) -join ',') -eq ($Fields -join ',')) { return } }
    [void]$st.NotLicensed.Add([pscustomobject][ordered]@{ fields = @($Fields); licence = $Licence; text = ('not licensed ({0})' -f $Licence); appliesTo = $AppliesTo })
}

function Invoke-SIEntraContextRead {
    <#
    .SYNOPSIS  ONE paged tenant-wide read. Each page's rows go to -OnRows ({ param($PageRows) }) and are not kept. Records
               how it went in the context state (Reads[<name>]: Complete, Rows, Error, Kind) and says ONE plain line when
               it did not complete. Never throws.
    .PARAMETER Fetch    tests: { param($Url) } -> the rows of the whole read (a throw = a failed read)
    .PARAMETER Licence  the licence this data needs -- named when Graph refuses the read for a missing licence
    .PARAMETER Fields   the SI fields the read fills (recorded with a missing licence)
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][string]$Url, [string]$Token = '',
          [Parameter(Mandatory)][scriptblock]$OnRows, [scriptblock]$Fetch, [string]$Licence = '', [string[]]$Fields = @(),
          [ValidateSet('user', 'service_principal', 'both')][string]$AppliesTo = 'both', [switch]$Quiet)
    $siRead = [ordered]@{ Name = $Name; What = $What; Complete = $false; Rows = 0; Error = ''; Kind = '' }
    try {
        if ($Fetch) {
            $siGot = @(& $Fetch $Url)
            $siRead.Rows = $siGot.Count
            if ($siGot.Count -gt 0) { $null = & $OnRows $siGot }
            $siRead.Complete = $true
        } else {
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1') }
            $siPage = Invoke-SIPagedRest -Url $Url -Token $Token -SourceLabel $What -OnPage $OnRows
            $siRead.Rows = [int]$siPage.Count; $siRead.Complete = [bool]$siPage.Complete; $siRead.Error = [string]$siPage.Error
        }
    } catch { $siRead.Complete = $false; $siRead.Error = [string]$_.Exception.Message }
    if (-not $siRead.Complete) {
        $why = Get-SIEntraContextFailure -ErrorText $siRead.Error -Licence $Licence
        $siRead.Kind = $why.Kind
        if ($why.Kind -eq 'licence' -and $Licence -and @($Fields).Count -gt 0) { Add-SIEntraNotLicensed -Licence $Licence -Fields $Fields -AppliesTo $AppliesTo }
        if (-not $Quiet) {
            if ($why.Kind -eq 'licence') { Write-SIEntraContextLine ('{0}: {1} -- shown as "{1}" on each identity, never as "no risk".' -f $What, $why.Text) }
            else { Write-SIEntraContextLine -Warn ('{0}: not read in full ({1}). What it adds stays unknown this run; nothing is reported from its absence.' -f $What, $why.Text) }
        }
    }
    $out = [pscustomobject]$siRead
    (Get-SIEntraContextState).Reads[$Name] = $out
    $out
}

function Add-SIEntraContextPart {
    <# A part on an ALREADY CAPTURED record -- never a new record. Returns $true when the part was added. #>
    param([string]$Provider = 'entra', [Parameter(Mandatory)][string]$RecordType, [AllowNull()][AllowEmptyString()][string]$Id, [Parameter(Mandatory)][string]$Part, $Object)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Id)) { return $false }
    $cap = $global:SIRecordCaptureState
    if ($null -eq $cap -or -not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return $false }
    $key = $Id.Trim().ToLowerInvariant()
    # #721: held or streamed (the discover phase streams its records; their ids are remembered)
    $capId = ('{0}|{1}|{2}' -f $Provider, $RecordType, $key)
    if (Get-Command -Name Test-SIRecordCaptured -ErrorAction SilentlyContinue) { if (-not (Test-SIRecordCaptured -Id $capId -State $cap)) { return $false } }
    elseif (-not $cap.Records.ContainsKey($capId)) { return $false }
    try { Add-SIRecordPart -Provider $Provider -RecordType $RecordType -Key $key -Part $Part -Object $Object; return $true } catch { return $false }
}

function Get-SIEntraCapturedIds {
    <# The keys (object ids) of the captured Entra records of one record type. #>
    param([Parameter(Mandatory)][string]$RecordType, [string]$Provider = 'entra')
    $cap = $global:SIRecordCaptureState
    if ($null -eq $cap) { return }
    # #721: held or streamed
    if (Get-Command -Name Get-SIRecordCapturedKeys -ErrorAction SilentlyContinue) { Get-SIRecordCapturedKeys -Provider $Provider -RecordType $RecordType -State $cap; return }
    foreach ($r in @($cap.Records.Values)) { if ($r.Provider -eq $Provider -and $r.RecordType -eq $RecordType) { [string]$r.Key } }
}

function Get-SIContextValue {
    <# PURE. A named value of a hashtable / PSObject, or $null. #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] }; return $null }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

# =====================================================================================================================
#  APPLICATION REGISTRATIONS  (part 'app')
# =====================================================================================================================

function ConvertTo-SIEntraAppPart {
    <#
        PURE. One /applications object -> the 'app' part: what the record needs, nothing secret (Graph never returns a
        secret's value). Requested permissions carry id AND name (-SpIndex: Get-SIServicePrincipalIndex).
    #>
    param($App, $SpIndex)
    if ($null -eq $App) { return $null }
    $appId = ([string](Get-SIContextValue $App 'appId')).ToLowerInvariant()
    if (-not $appId) { return $null }
    $pw = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-SIContextValue $App 'passwordCredentials')) {
        if ($null -eq $c) { continue }
        $pw.Add([pscustomobject][ordered]@{ keyId = [string]$c.keyId; displayName = [string]$c.displayName; hint = [string]$c.hint; startDateTime = $c.startDateTime; endDateTime = $c.endDateTime })
    }
    $keys = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-SIContextValue $App 'keyCredentials')) {
        if ($null -eq $c) { continue }
        $keys.Add([pscustomobject][ordered]@{ keyId = [string]$c.keyId; displayName = [string]$c.displayName; type = [string]$c.type; usage = [string]$c.usage; startDateTime = $c.startDateTime; endDateTime = $c.endDateTime })
    }
    $req = New-Object System.Collections.Generic.List[object]
    foreach ($rra in @(Get-SIContextValue $App 'requiredResourceAccess')) {
        if ($null -eq $rra) { continue }
        $apiAppId = ([string]$rra.resourceAppId).ToLowerInvariant()
        $apiName = ''
        if ($SpIndex -and $apiAppId -and $SpIndex.ByAppId.ContainsKey($apiAppId)) { $apiSp = $SpIndex.ById[[string]$SpIndex.ByAppId[$apiAppId]]; if ($apiSp) { $apiName = [string]$apiSp.displayName } }
        foreach ($ra in @($rra.resourceAccess)) {
            if ($null -eq $ra -or -not $ra.id) { continue }
            $permId = ([string]$ra.id).ToLowerInvariant()
            $permName = ''
            if ($SpIndex -and $SpIndex.PermissionNames.ContainsKey(('{0}|{1}' -f $apiAppId, $permId))) { $permName = [string]$SpIndex.PermissionNames[('{0}|{1}' -f $apiAppId, $permId)] }
            $kind = 'delegated'; if ([string]$ra.type -eq 'Role') { $kind = 'application' }
            $req.Add([pscustomobject][ordered]@{ api = $apiName; apiAppId = $apiAppId; permission = $permName; permissionId = $permId; kind = $kind })
        }
    }
    $owners = @(@(Get-SIContextValue $App 'owners') | ForEach-Object { ConvertTo-SIOwnerItem $_ } | Where-Object { $_ })
    $more = Get-SIContextValue $App 'owners@odata.nextLink'
    $o = [ordered]@{
        id = [string](Get-SIContextValue $App 'id'); appId = $appId; displayName = [string](Get-SIContextValue $App 'displayName')
        signInAudience = [string](Get-SIContextValue $App 'signInAudience'); publisherDomain = [string](Get-SIContextValue $App 'publisherDomain')
        notes = [string](Get-SIContextValue $App 'notes'); createdDateTime = (Get-SIContextValue $App 'createdDateTime')
        passwordCredentials = $pw.ToArray(); keyCredentials = $keys.ToArray(); requestedPermissions = $req.ToArray()
        owners = $owners; ownersTruncated = [bool]($more -or $owners.Count -ge 20)
    }
    # WHOLE OBJECT (continuous discovery): the application is read without a property list, so everything else Graph
    # returns for it (redirect URIs, exposed API, app roles, tags, identifier URIs ... and whatever Microsoft adds) is kept
    # beside the values above -- which are never replaced. The raw credential and permission lists are left out: the part
    # holds them in the reduced form built above.
    Add-SIContextOtherProperties -Into $o -From $App -Skip @('passwordCredentials', 'keyCredentials', 'requiredResourceAccess', 'owners', 'federatedIdentityCredentials')
    return $o
}

function Add-SIContextOtherProperties {
    <#
        PURE. Every property of a source object that -Into does not hold yet and that has a value, added after the ones
        already there (never replacing one). Names in -Skip and annotation names (@odata...) are left out.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Into, [AllowNull()]$From, [string[]]$Skip = @())
    if ($null -eq $From) { return }
    $props = @()
    if ($From -is [System.Collections.IDictionary]) { $props = @($From.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $From[$_] } }) }
    else { $props = @($From.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $props) {
        if (-not $p.Name -or $p.Name.Contains('@') -or $Skip -contains $p.Name -or $Into.Contains($p.Name)) { continue }
        $v = $p.Value
        if ($null -eq $v) { continue }
        if ($v -is [string] -and -not $v.Trim()) { continue }
        if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string]) -and -not ($v -is [System.Collections.IDictionary]) -and @($v).Count -eq 0) { continue }
        $Into[$p.Name] = $v
    }
}

function Get-SIEntraApplications {
    <#
    .SYNOPSIS  The tenant's application registrations, read ONCE per run: @{ Read; Complete; Federated; ByAppId = @{ <application
               id> = the 'app' part } }. GET /applications with owners expanded ($top=100: Graph caps the page with $expand),
               then a second read for the federated credentials (Graph expands one relation per request).
               Permission: Application.Read.All (held). -Fetch (tests): { param($Url) } -> rows.
    #>
    param([string]$Token = '', [scriptblock]$Fetch, [switch]$Refresh)
    if ($Refresh) { Reset-SIEntraContextState }
    $st = Get-SIEntraContextState
    if ($st.Apps -and $st.Apps.Read) { return $st.Apps }
    $cxApps = @{ Read = $false; Complete = $false; Federated = $false; ByAppId = @{} }
    $cxIndex = $null
    if (Get-Command -Name Get-SIServicePrincipalIndex -ErrorAction SilentlyContinue) { $cxIndex = Get-SIServicePrincipalIndex }
    # WHOLE OBJECT: no property list -- an application registration is a small object and a tenant has far fewer of them
    # than users, so everything Graph returns is kept (ConvertTo-SIEntraAppPart). The expanded owners keep their three
    # properties: an owner is a reference (id + name + sign-in name), not an object SecurityInsight records here.
    $url = 'https://graph.microsoft.com/v1.0/applications?$expand=owners($select=id,displayName,userPrincipalName)&$top=100'
    $r = Invoke-SIEntraContextRead -Name 'applications' -What 'Application registrations' -Url $url -Token $Token -Fetch $Fetch -OnRows {
        param($PageRows)
        foreach ($cxA in $PageRows) { $cxP = ConvertTo-SIEntraAppPart -App $cxA -SpIndex $cxIndex; if ($cxP) { $cxApps.ByAppId[[string]$cxP.appId] = $cxP } }
    }
    $cxApps.Read = ([bool]$r.Complete -or $cxApps.ByAppId.Count -gt 0)
    $cxApps.Complete = [bool]$r.Complete
    if ($cxApps.Read) {
        $cxSeen = New-Object 'System.Collections.Generic.HashSet[string]'
        # LIST KEPT: a join read -- only the application id and its federated credentials (five values each) are needed; the application itself is read whole above
        $furl = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId&$expand=federatedIdentityCredentials($select=id,name,issuer,subject,audiences)&$top=100'
        $f = Invoke-SIEntraContextRead -Name 'federatedCredentials' -What 'Federated credentials of application registrations' -Url $furl -Token $Token -Fetch $Fetch -OnRows {
            param($PageRows)
            foreach ($cxA in $PageRows) {
                $cxId = ([string](Get-SIContextValue $cxA 'appId')).ToLowerInvariant()
                if (-not $cxId -or -not $cxApps.ByAppId.ContainsKey($cxId)) { continue }
                $cxList = New-Object System.Collections.Generic.List[object]
                foreach ($cxF in @(Get-SIContextValue $cxA 'federatedIdentityCredentials')) {
                    if ($null -eq $cxF) { continue }
                    $cxList.Add([pscustomobject][ordered]@{ id = [string]$cxF.id; name = [string]$cxF.name; issuer = [string]$cxF.issuer; subject = [string]$cxF.subject; audiences = @($cxF.audiences) })
                }
                $cxApps.ByAppId[$cxId]['federatedIdentityCredentials'] = $cxList.ToArray()
                [void]$cxSeen.Add($cxId)
            }
        }
        if ($f.Complete) {
            # the read covered every application: one it did not name has no federated credential (a fact, said as false)
            foreach ($cxId in @($cxApps.ByAppId.Keys)) {
                $cxT = $cxApps.ByAppId[$cxId]
                if (-not $cxT.Contains('federatedIdentityCredentials')) { $cxT['federatedIdentityCredentials'] = @() }
                $cxT['hasFederatedCredential'] = (@($cxT['federatedIdentityCredentials']).Count -gt 0)
            }
            $cxApps.Federated = $true
        }
    }
    $st.Apps = $cxApps
    return $cxApps
}

function Get-SIEntraAppOwners {
    <# PURE. The owners of an application registration by its application id from a Get-SIEntraApplications state (none = @()). #>
    param($Apps, [AllowNull()][AllowEmptyString()][string]$AppId)
    if ($null -eq $Apps -or -not $Apps.Read -or [string]::IsNullOrWhiteSpace($AppId)) { return @() }
    $a = $Apps.ByAppId[$AppId.ToLowerInvariant()]
    if ($null -eq $a) { return @() }
    return @($a['owners'] | Where-Object { $_ })
}

function Test-SIEntraAppOwnersKnown {
    <#
        PURE. Are the owners of this service principal's APPLICATION known? Not read at all ($null) = as before this read
        existed (the principal's own owners decide). Read in full, or its application found, or a managed identity (it has
        no application registration), or an application of ANOTHER tenant = known. A partial read and an application of
        this tenant that was not among the rows read = NOT known: "no owner" is then unknown, never a finding.
    #>
    param($Apps, $ServicePrincipal, [string]$TenantId = '')
    if ($null -eq $Apps) { return $true }
    if ($Apps.Complete) { return $true }
    $appId = ([string](Get-SIContextValue $ServicePrincipal 'appId')).ToLowerInvariant()
    if ($appId -and $Apps.ByAppId -and $Apps.ByAppId.ContainsKey($appId)) { return $true }
    if ([string](Get-SIContextValue $ServicePrincipal 'servicePrincipalType') -eq 'ManagedIdentity') { return $true }
    $org = ([string](Get-SIContextValue $ServicePrincipal 'appOwnerOrganizationId')).Trim()
    if ($org -and $TenantId -and -not [string]::Equals($org, $TenantId.Trim(), [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

# =====================================================================================================================
#  DELEGATED PERMISSION GRANTS  (part 'oauth2Grants')
# =====================================================================================================================

function ConvertTo-SIOauth2GrantPart {
    <#
        PURE. One client's entry of the tenant-wide grants read (Add-SIOauth2GrantRows) -> the 'oauth2Grants' part:
        permissions (names), consentType (admin | user | admin and user), consentedUserCount, and per API the id AND name,
        the consent type, the permissions and how many users consented.
    #>
    param($Entry, $SpIndex)
    if ($null -eq $Entry) { return $null }
    $grants = New-Object System.Collections.Generic.List[object]
    $admin = $false; $user = $false
    foreach ($k in @($Entry.Grants.Keys)) {
        $g = $Entry.Grants[$k]
        $rid = [string]$g.ResourceId
        $rname = ''
        if ($SpIndex -and $rid -and $SpIndex.ById.ContainsKey($rid)) { $rname = [string]$SpIndex.ById[$rid].displayName }
        $isAdmin = ([string]$g.ConsentType -eq 'AllPrincipals')
        if ($isAdmin) { $admin = $true } else { $user = $true }
        $grants.Add([pscustomobject][ordered]@{ resourceId = $rid; resourceName = $rname; consentType = $(if ($isAdmin) { 'admin' } else { 'user' })
                permissions = @($g.Scopes.ToArray()); userCount = [int]$g.Users })
    }
    $type = ''
    if ($admin -and $user) { $type = 'admin and user' } elseif ($admin) { $type = 'admin' } elseif ($user) { $type = 'user' }
    [pscustomobject][ordered]@{ permissions = @($Entry.Scopes.ToArray()); consentType = $type; consentedUserCount = [int]$Entry.Users.Count; grants = $grants.ToArray() }
}

# =====================================================================================================================
#  ROLE ASSIGNMENTS WITH THEIR SCOPE, ROLE PATHS, PIM  (part 'roleScopes')
# =====================================================================================================================

function Get-SIEntraRoleScopeInfo {
    <#
        PURE. A role assignment's directoryScopeId -> @{ Type; Id; TenantWide }.
          '/' (or none)                    tenant              the whole directory
          '/administrativeUnits/<id>'      administrative unit only the members of that unit -- NOT a tenant-wide role
          '/<object id>'                   object              one application, service principal or group -- NOT tenant-wide
    #>
    param([AllowNull()][AllowEmptyString()][string]$DirectoryScopeId)
    $s = ([string]$DirectoryScopeId).Trim()
    if (-not $s -or $s -eq '/') { return @{ Type = 'tenant'; Id = '/'; TenantWide = $true } }
    if ($s -match '^/administrativeUnits/(?<id>[^/]+)$') { return @{ Type = 'administrative unit'; Id = $Matches['id'].ToLowerInvariant(); TenantWide = $false } }
    if ($s -match '^/(?<id>[0-9a-fA-F-]{36})$') { return @{ Type = 'object'; Id = $Matches['id'].ToLowerInvariant(); TenantWide = $false } }
    return @{ Type = 'other'; Id = $s; TenantWide = $false }
}

function ConvertTo-SIRoleScopeItems {
    <#
        PURE. One principal's assignments (Get-SIEntraRoleScopesByPrincipal) -> the items of si_entra_role_scopes:
        { role, roleId, assignment (active | eligible | activated), scopeType, scopeId, scopeName, tenantWide[, activatedUntil] }.
        -ScopeNames: scope id -> name (administrative units; an object scope's name from the service-principal index).
        -Activated: '<principal>|<role id>|<scope id>' -> the end of a PIM activation (an active assignment that is one).
    #>
    param([AllowEmptyCollection()][object[]]$Entries = @(), [string]$PrincipalId = '', [hashtable]$ScopeNames = @{}, [hashtable]$Activated = @{})
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in @($Entries)) {
        if ($null -eq $e) { continue }
        $info = Get-SIEntraRoleScopeInfo -DirectoryScopeId ([string]$e.scopeId)
        $key = '{0}|{1}|{2}' -f ([string]$e.roleId).ToLowerInvariant(), $info.Id, [string]$e.assignment
        if (-not $seen.Add($key)) { continue }
        $name = ''
        if ($info.TenantWide) { $name = 'Tenant' } elseif ($ScopeNames.ContainsKey([string]$info.Id)) { $name = [string]$ScopeNames[[string]$info.Id] }
        $item = [ordered]@{ role = [string]$e.role; roleId = ([string]$e.roleId).ToLowerInvariant(); assignment = [string]$e.assignment
            scopeType = [string]$info.Type; scopeId = [string]$info.Id; scopeName = $name; tenantWide = [bool]$info.TenantWide }
        if ([string]$e.assignment -eq 'active') {
            $ak = '{0}|{1}|{2}' -f $PrincipalId.ToLowerInvariant(), ([string]$e.roleId).ToLowerInvariant(), ([string]$e.scopeId)
            if ($Activated.ContainsKey($ak)) { $item['assignment'] = 'activated'; if ($Activated[$ak]) { $item['activatedUntil'] = $Activated[$ak] } }
        }
        $out.Add([pscustomobject]$item)
    }
    return $out.ToArray()
}

function Get-SIGroupActivationOf {
    <#
        PURE. Is this principal a member of this role-holding group ONLY because an eligible membership is activated right
        now? -> @{ Activated; Until } from the run's look-ups (Get-SIRoleGroupLookups .ActivatedMembers, keyed
        '<principal id>|<group id>' lower case). No look-up, or the read did not run / was refused = not activated.
    #>
    param($Lookups, [string]$PrincipalId = '', [string]$GroupId = '')
    $no = @{ Activated = $false; Until = '' }
    if ($null -eq $Lookups -or -not $PrincipalId -or -not $GroupId) { return $no }
    $map = $null
    if ($Lookups -is [System.Collections.IDictionary]) { if ($Lookups.Contains('ActivatedMembers')) { $map = $Lookups['ActivatedMembers'] } }
    else { $mp = $Lookups.PSObject.Properties['ActivatedMembers']; if ($mp) { $map = $mp.Value } }
    if ($null -eq $map -or $map -isnot [System.Collections.IDictionary] -or $map.Count -eq 0) { return $no }
    $key = '{0}|{1}' -f $PrincipalId.Trim().ToLowerInvariant(), $GroupId.Trim().ToLowerInvariant()
    if (-not $map.Contains($key)) { return $no }
    return @{ Activated = $true; Until = [string]$map[$key] }
}

function ConvertTo-SIGroupActivatedRoleItems {
    <#
        PURE. The roles a principal holds through ONE group whose membership is activated right now, as items of
        si_entra_role_scopes: the group's own assignments (-GroupItems: ConvertTo-SIRoleScopeItems of the group) with the
        group named (via, viaGroupId) and until when the membership lasts (membershipActivatedUntil). A role the group
        holds actively reads assignment 'activated' with activatedUntil -- for this principal it lasts only as long as the
        membership; a role the group is only eligible for stays 'eligible'.
    #>
    param([AllowEmptyCollection()][object[]]$GroupItems = @(), [string]$GroupId = '', [string]$GroupName = '', [string]$Until = '')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($gi in @($GroupItems)) {
        if ($null -eq $gi) { continue }
        $item = [ordered]@{}
        foreach ($p in $gi.PSObject.Properties) { if ($p.Name -ne 'activatedUntil') { $item[$p.Name] = $p.Value } }
        if ([string]$gi.assignment -ne 'eligible') { $item['assignment'] = 'activated'; if ($Until) { $item['activatedUntil'] = $Until } }
        $item['via'] = $(if ($GroupName) { $GroupName } else { $GroupId })
        $item['viaGroupId'] = $GroupId
        if ($Until) { $item['membershipActivatedUntil'] = $Until }
        $out.Add([pscustomobject]$item)
    }
    return $out.ToArray()
}

function Get-SIRolePaths {
    <#
        PURE. HOW a principal holds (or can get) each Entra role, one line per path -- "Global Administrator (direct)",
        "Group IT Admins -> User Administrator", "Group Tier0 (can activate) -> Global Administrator",
        "Helpdesk Administrator (eligible)", "User Administrator (administrative unit Sales)",
        "Global Administrator via Tier0 Admins (eligible, activated until 2026-10-11T18:00:00Z)" (a member of the group
        only while an eligible membership is activated).
        -Items: ConvertTo-SIRoleScopeItems of the principal; -Lookups: Get-SIRoleGroupLookups; -Names: id -> display name.
    #>
    param([string]$PrincipalId = '', [AllowEmptyCollection()][object[]]$Items = @(), $Lookups, [hashtable]$Names = @{})
    $out = New-Object System.Collections.Generic.List[string]
    $add = { param($t) if ($t -and -not $out.Contains($t)) { $out.Add($t) } }
    foreach ($i in @($Items)) {
        if ($null -eq $i) { continue }
        $how = 'direct'
        if ([string]$i.assignment -eq 'eligible') { $how = 'eligible' }
        elseif ([string]$i.assignment -eq 'activated') {
            # an activated role is an ELIGIBLE role that is switched on right now -- said with until when it lasts
            $how = 'eligible, activated'
            $until = ''; $up = $i.PSObject.Properties['activatedUntil']; if ($up -and $up.Value) { $until = [string]$up.Value }
            if ($until) { $how = 'eligible, activated until {0}' -f $until }
        }
        if (-not $i.tenantWide) { $sn = [string]$i.scopeName; if (-not $sn) { $sn = [string]$i.scopeId }; $how = ('{0}, {1} {2}' -f $how, [string]$i.scopeType, $sn) }
        & $add ('{0} ({1})' -f [string]$i.role, $how)
    }
    if ($Lookups -and $PrincipalId) {
        $gname = { param($g) $n = ''; if ($Names.ContainsKey([string]$g)) { $n = [string]$Names[[string]$g] }; if (-not $n) { $n = [string]$g }; $n }
        $pid2 = $PrincipalId
        $member = $null
        if ($Lookups.MemberToGroups.ContainsKey($pid2)) { $member = $Lookups.MemberToGroups[$pid2] }
        foreach ($g in @($member)) {
            if (-not $g -or -not $Lookups.GroupRoles.ContainsKey([string]$g)) { continue }
            $gr = $Lookups.GroupRoles[[string]$g]
            # a member only because an eligible membership is activated right now: every role through this group is an
            # ELIGIBLE role, said with until when the activation lasts
            $act = Get-SIGroupActivationOf -Lookups $Lookups -PrincipalId $pid2 -GroupId ([string]$g)
            if ($act.Activated) {
                $how = 'eligible, activated'; if ($act.Until) { $how = 'eligible, activated until {0}' -f $act.Until }
                foreach ($r in (@($gr.Permanent) + @($gr.Eligible))) { if ($r) { & $add ('{0} via {1} ({2})' -f [string]$r, (& $gname $g), $how) } }
                continue
            }
            foreach ($r in @($gr.Permanent)) { if ($r) { & $add ('Group {0} -> {1}' -f (& $gname $g), [string]$r) } }
            foreach ($r in @($gr.Eligible)) { if ($r) { & $add ('Group {0} -> {1} (eligible)' -f (& $gname $g), [string]$r) } }
        }
        $pim = $null
        if ($Lookups.PimGroups.ContainsKey($pid2)) { $pim = $Lookups.PimGroups[$pid2] }
        foreach ($g in @($pim)) {
            if (-not $g -or -not $Lookups.GroupRoles.ContainsKey([string]$g)) { continue }
            $gr = $Lookups.GroupRoles[[string]$g]
            foreach ($r in (@($gr.Permanent) + @($gr.Eligible))) { if ($r) { & $add ('Group {0} (can activate) -> {1}' -f (& $gname $g), [string]$r) } }
        }
    }
    return $out.ToArray()
}

function Get-SIRoleTierLevel {
    <#
        PURE. THE LEVEL INSIDE TIER 0 (owner 2026-10-11: "tier 0, level 2 i call it, so still tier 0"). A role assigned
        only on an administrative unit or on one object keeps the role's tier in EVERY tier; the LEVEL exists for TIER 0
        ONLY and says how far the Tier 0 role reaches:
          level 1   a Tier 0 role is held TENANT-WIDE
          level 2   every Tier 0 role is held on a SCOPE only (an administrative unit, one object)
        An identity with both a tenant-wide and a scoped Tier 0 role is level 1. A scoped Tier 1 / Tier 2 role is plain
        Tier 1 / Tier 2: it counts exactly as the role tenant-wide, its scope is listed (si_entra_role_scopes, id + name),
        and it gets NO level -- the result is then $null.
        -Holdings: every way the identity holds a role -- its own assignments (ConvertTo-SIRoleScopeItems) and those of the
                   groups it is a member of or can activate into ({ role, roleId, scopeType, scopeId, scopeName, tenantWide
                   [, via] }); permanent, eligible and activated alike.
        -RoleTier: { param($roleName) } -> the role's tier (0-3), or $null for a role the tier catalog does not know.
        Returns $null when the identity holds no Tier 0 role, else { tier = 0; level; text; scoped } -- text e.g.
          "Tier 0, level 2 -- Privileged Authentication Administrator on administrative unit Sales (id 1f2e...)"
          "Tier 0, level 1 -- Global Administrator, tenant-wide"
        scoped: the deciding roles held on a scope, each with the scope's type, id AND name.
    #>
    param([AllowEmptyCollection()][object[]]$Holdings = @(), [scriptblock]$RoleTier)
    if (-not $RoleTier) { return $null }
    $best = $null
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($Holdings)) {
        if ($null -eq $h -or -not [string]$h.role) { continue }
        $t = $null
        try { $t = & $RoleTier ([string]$h.role) } catch { $t = $null }
        if ($null -eq $t -or "$t" -eq '') { continue }
        $t = [int]$t
        $rows.Add(@{ H = $h; T = $t })
        if ($null -eq $best -or $t -lt $best) { $best = $t }
    }
    # the level is a Tier 0 notion only: any other tier has none
    if ($null -eq $best -or $best -ne 0) { return $null }
    $deciding = @($rows | Where-Object { $_.T -eq $best })
    $via = { param($h) $p = $h.PSObject.Properties['via']; if ($p -and $p.Value) { ' (through group {0})' -f [string]$p.Value } else { '' } }
    $wide = @($deciding | Where-Object { [bool]$_.H.tenantWide } | Sort-Object { [string]$_.H.role })
    if ($wide.Count -gt 0) {
        $text = 'Tier {0}, level 1 -- {1}, tenant-wide{2}' -f $best, [string]$wide[0].H.role, (& $via $wide[0].H)
        return [ordered]@{ tier = $best; level = 1; text = $text; scoped = @() }
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $scoped = New-Object System.Collections.Generic.List[object]
    $said = New-Object System.Collections.Generic.List[string]
    foreach ($d in @($deciding | Sort-Object { [string]$_.H.role }, { [string]$_.H.scopeName }, { [string]$_.H.scopeId })) {
        $h = $d.H
        if (-not $seen.Add(('{0}|{1}' -f ([string]$h.roleId).ToLowerInvariant(), [string]$h.scopeId))) { continue }
        $item = [ordered]@{ role = [string]$h.role; roleId = ([string]$h.roleId).ToLowerInvariant(); scopeType = [string]$h.scopeType; scopeId = [string]$h.scopeId; scopeName = [string]$h.scopeName }
        $vp = $h.PSObject.Properties['via']; if ($vp -and $vp.Value) { $item['via'] = [string]$vp.Value }
        $scoped.Add([pscustomobject]$item)
        $type = [string]$h.scopeType; if (-not $type -or $type -eq 'other') { $type = 'scope' }
        $where = if ([string]$h.scopeName) { '{0} {1} (id {2})' -f $type, [string]$h.scopeName, [string]$h.scopeId } else { '{0} {1}' -f $type, [string]$h.scopeId }
        $said.Add(('{0} on {1}{2}' -f [string]$h.role, $where, (& $via $h)))
    }
    $shown = @($said | Select-Object -First 3)
    $tail = ''; if ($said.Count -gt $shown.Count) { $tail = '; and {0} more' -f ($said.Count - $shown.Count) }
    $text = 'Tier {0}, level 2 -- {1}{2}' -f $best, ($shown -join '; '), $tail
    return [ordered]@{ tier = $best; level = 2; text = $text; scoped = $scoped.ToArray() }
}

function ConvertTo-SIPimActivationRule {
    <#
        PURE. One role's PIM policy assignment (policies/roleManagementPolicyAssignments with policy.rules expanded) ->
        @{ roleId; requires = MFA / justification / ticket / approval / authentication context <claim>; maxDuration }.
        Only the rules for ACTIVATING an eligible assignment (the '..._EndUser_Assignment' rules).
    #>
    param($Assignment)
    if ($null -eq $Assignment) { return $null }
    $roleId = ([string](Get-SIContextValue $Assignment 'roleDefinitionId')).ToLowerInvariant()
    if (-not $roleId) { return $null }
    $req = New-Object System.Collections.Generic.List[string]
    $max = ''
    $policy = Get-SIContextValue $Assignment 'policy'
    foreach ($rule in @(Get-SIContextValue $policy 'rules')) {
        if ($null -eq $rule) { continue }
        $id = [string](Get-SIContextValue $rule 'id')
        switch ($id) {
            'Enablement_EndUser_Assignment' {
                foreach ($x in @(Get-SIContextValue $rule 'enabledRules')) {
                    switch ([string]$x) { 'MultiFactorAuthentication' { $req.Add('MFA') } 'Justification' { $req.Add('justification') } 'Ticketing' { $req.Add('ticket') } }
                }
            }
            'Approval_EndUser_Assignment' {
                $set = Get-SIContextValue $rule 'setting'
                if ((Get-SIContextValue $set 'isApprovalRequired') -eq $true) { $req.Add('approval') }
            }
            'AuthenticationContext_EndUser_Assignment' {
                if ((Get-SIContextValue $rule 'isEnabled') -eq $true) { $cv = [string](Get-SIContextValue $rule 'claimValue'); $req.Add(('authentication context {0}' -f $cv).Trim()) }
            }
            'Expiration_EndUser_Assignment' { $max = [string](Get-SIContextValue $rule 'maximumDuration') }
        }
    }
    @{ roleId = $roleId; requires = $req.ToArray(); maxDuration = $max }
}

# =====================================================================================================================
#  CONDITIONAL ACCESS  (part 'ca')
# =====================================================================================================================

function ConvertTo-SICaPolicy {
    <#
        PURE. One Conditional Access policy -> what the per-user verdict needs. Only an ENABLED policy counts (report-only
        and disabled policies enforce nothing). RequiresMfa: the grant asks for MFA or an authentication strength and
        nothing else can satisfy it instead ("MFA OR compliant device" does not enforce MFA). AllApps: all cloud apps.
    #>
    param($Policy)
    if ($null -eq $Policy) { return $null }
    $set = { param($list) $h = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase); foreach ($x in @($list)) { if ($x) { [void]$h.Add([string]$x) } }; , $h }
    $cond = Get-SIContextValue $Policy 'conditions'
    $users = Get-SIContextValue $cond 'users'
    $apps = Get-SIContextValue $cond 'applications'
    $grant = Get-SIContextValue $Policy 'grantControls'
    $incU = & $set (Get-SIContextValue $users 'includeUsers')
    $excU = & $set (Get-SIContextValue $users 'excludeUsers')
    $built = @(@(Get-SIContextValue $grant 'builtInControls') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $strength = Get-SIContextValue $grant 'authenticationStrength'
    $hasMfa = ($built -contains 'mfa') -or ($null -ne $strength)
    $others = @($built | Where-Object { $_ -ne 'mfa' })
    $op = [string](Get-SIContextValue $grant 'operator')
    $mfa = $false
    if ($hasMfa -and -not ($built -contains 'block')) { $mfa = ($others.Count -eq 0) -or ($op -eq 'AND') }
    $incApps = @(@(Get-SIContextValue $apps 'includeApplications') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    @{
        Id = [string](Get-SIContextValue $Policy 'id'); Name = [string](Get-SIContextValue $Policy 'displayName')
        Enabled = ([string](Get-SIContextValue $Policy 'state') -eq 'enabled')
        IncludeAll = $incU.Contains('All'); IncludeUsers = $incU; ExcludeUsers = $excU
        IncludeGuests = ($incU.Contains('GuestsOrExternalUsers') -or ($null -ne (Get-SIContextValue $users 'includeGuestsOrExternalUsers')))
        ExcludeGuests = ($excU.Contains('GuestsOrExternalUsers') -or ($null -ne (Get-SIContextValue $users 'excludeGuestsOrExternalUsers')))
        IncludeGroups = (& $set (Get-SIContextValue $users 'includeGroups')); ExcludeGroups = (& $set (Get-SIContextValue $users 'excludeGroups'))
        IncludeRoles = (& $set (Get-SIContextValue $users 'includeRoles')); ExcludeRoles = (& $set (Get-SIContextValue $users 'excludeRoles'))
        RequiresMfa = [bool]$mfa; AllApps = ($incApps -contains 'All'); Blocks = ($built -contains 'block')
    }
}

function Get-SICaUserVerdict {
    <#
        PURE. Conditional Access for ONE user: @{ policyCount; mfaEnforced; mfaPolicies; excluded }.
          policyCount   enabled policies that apply to the user (included, not excluded)
          mfaEnforced   $true when one of them requires MFA for all cloud apps; $false when none does; left out ($null)
                        when a group a policy names could not be read (unknown is never "not enforced")
          excluded      the enabled policies that WOULD apply to the user but exclude it (id + name) -- a policy that
                        never included the user is not listed
          excludedFromAll  $true when at least one enabled policy would apply and EVERY one of them excludes the user;
                        $false when one applies (or none would apply at all); left out when that cannot be told
        Conditions other than who and which apps (locations, device platforms, risk) are not evaluated.
        -GroupMembers: group id -> HashSet of member ids; -UnknownGroups: groups whose members could not be read;
        -RoleIds: the role definition ids the user holds tenant-wide.
    #>
    param([Parameter(Mandatory)][string]$UserId, [bool]$IsGuest = $false, [AllowEmptyCollection()][object[]]$Policies = @(), [hashtable]$GroupMembers = @{},
          $UnknownGroups, $RoleIds)
    $applies = 0; $unknown = $false
    $mfa = New-Object System.Collections.Generic.List[object]
    $excluded = New-Object System.Collections.Generic.List[object]
    $inGroup = { param($groups) foreach ($g in $groups) { $m = $GroupMembers[[string]$g]; if ($m -and $m.Contains($UserId)) { return $true } }; $false }
    $hasRole = { param($roles) if ($null -eq $RoleIds) { return $false }; foreach ($r in $roles) { if ($RoleIds.Contains([string]$r)) { return $true } }; $false }
    foreach ($p in @($Policies)) {
        if ($null -eq $p -or -not $p.Enabled) { continue }
        if ($UnknownGroups) {
            $dep = $false
            foreach ($g in $p.IncludeGroups) { if ($UnknownGroups.Contains([string]$g)) { $dep = $true } }
            foreach ($g in $p.ExcludeGroups) { if ($UnknownGroups.Contains([string]$g)) { $dep = $true } }
            if ($dep) { $unknown = $true; continue }
        }
        $inc = $p.IncludeAll -or $p.IncludeUsers.Contains($UserId) -or ($IsGuest -and $p.IncludeGuests) -or (& $inGroup $p.IncludeGroups) -or (& $hasRole $p.IncludeRoles)
        if (-not $inc) { continue }
        $exc = $p.ExcludeUsers.Contains($UserId) -or ($IsGuest -and $p.ExcludeGuests) -or (& $inGroup $p.ExcludeGroups) -or (& $hasRole $p.ExcludeRoles)
        $ref = [pscustomobject][ordered]@{ id = [string]$p.Id; name = [string]$p.Name }
        if ($exc) { $excluded.Add($ref); continue }
        $applies++
        if ($p.RequiresMfa -and $p.AllApps) { $mfa.Add($ref) }
    }
    $o = [ordered]@{ policyCount = $applies }
    if ($mfa.Count -gt 0) { $o['mfaEnforced'] = $true } elseif (-not $unknown) { $o['mfaEnforced'] = $false }
    $o['mfaPolicies'] = $mfa.ToArray()
    $o['excluded'] = $excluded.ToArray()
    # excluded from ALL: at least one enabled policy would apply to the user, and every one of them excludes it. One policy
    # that applies = not excluded from all (a fact even when another policy's group could not be read); none applies and a
    # group could not be read = left out (unknown is never "excluded from all", and never "not")
    if ($applies -gt 0) { $o['excludedFromAll'] = $false }
    elseif (-not $unknown) { $o['excludedFromAll'] = ($excluded.Count -gt 0) }
    return $o
}

function Get-SIEntraGroupMemberIds {
    <# The transitive USER members of one group: @{ Complete; Ids = HashSet }. One paged read per group. -Fetch (tests). #>
    param([Parameter(Mandatory)][string]$GroupId, [string]$Token = '', [scriptblock]$Fetch)
    $cxIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    # LIST KEPT: membership only -- the member ids of one group; the users themselves are read once, elsewhere
    $url = 'https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers/microsoft.graph.user?$select=id&$top=999' -f $GroupId
    $r = Invoke-SIEntraContextRead -Name ('groupMembers:' + $GroupId) -What 'Members of a group Conditional Access names' -Url $url -Token $Token -Fetch $Fetch -Quiet -OnRows {
        param($PageRows)
        foreach ($cxM in $PageRows) { if ($cxM -and $cxM.id) { [void]$cxIds.Add([string]$cxM.id) } }
    }
    (Get-SIEntraContextState).Reads.Remove(('groupMembers:' + $GroupId))
    # A group that NO LONGER EXISTS (HTTP 404 Request_ResourceNotFound: deleted, still named by a policy) is not a failed
    # read: it has no members, so it includes or excludes nobody -- known, never unknown. Live 2026-10-23: 12 such groups on
    # every run left "MFA enforced" unknown for the users those policies decide. Any other failure stays unknown.
    if (-not $r.Complete -and (Test-SIEntraGroupGone -ErrorText ([string]$r.Error))) { return @{ Complete = $true; Ids = $cxIds; Gone = $true } }
    @{ Complete = [bool]$r.Complete; Ids = $cxIds; Gone = $false }
}

function Test-SIEntraGroupGone {
    <# PURE. Is this failed group read Microsoft Graph saying the group does not exist (404 Request_ResourceNotFound)? #>
    param([AllowNull()][AllowEmptyString()][string]$ErrorText)
    $e = [string]$ErrorText
    ($e -match '(?i)Request_ResourceNotFound') -and ($e -match '(?i)HTTP 404|\(404\)|\b404\b|does not exist')
}

# =====================================================================================================================
#  ACCESS REVIEWS  (part 'accessReview')
# =====================================================================================================================

function Get-SIAccessReviewTargets {
    <#
        PURE. What an access review definition reviews, from its scope queries: a list of @{ Kind = group | role |
        application; Id }. A review of "all groups" (no single object in its scope) answers nothing.
    #>
    param($Definition)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Definition) { return $out.ToArray() }
    $queries = New-Object System.Collections.Generic.List[string]
    $scope = Get-SIContextValue $Definition 'scope'
    $q = [string](Get-SIContextValue $scope 'query'); if ($q) { $queries.Add($q) }
    foreach ($rs in @(Get-SIContextValue $scope 'resourceScopes')) { $q = [string](Get-SIContextValue $rs 'query'); if ($q) { $queries.Add($q) } }
    foreach ($ps in @(Get-SIContextValue $scope 'principalScopes')) { $q = [string](Get-SIContextValue $ps 'query'); if ($q -and $q -match '/groups/') { $queries.Add($q) } }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $g = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    foreach ($q in $queries) {
        $kind = ''; $id = ''
        if ($q -match ("roleDefinitionId eq '(?<id>$g)'") -or $q -match ("/roleDefinitions/(?<id>$g)")) { $kind = 'role'; $id = $Matches['id'] }
        elseif ($q -match ("/servicePrincipals/(?<id>$g)")) { $kind = 'application'; $id = $Matches['id'] }
        elseif ($q -match ("/groups/(?<id>$g)")) { $kind = 'group'; $id = $Matches['id'] }
        if ($kind -and $seen.Add($kind + '|' + $id.ToLowerInvariant())) { $out.Add(@{ Kind = $kind; Id = $id.ToLowerInvariant() }) }
    }
    return $out.ToArray()
}

function Get-SIAccessReviewLatest {
    <# PURE. The newest instance of a review that has ENDED (or was completed / applied): @{ Date; Status }, or $null. #>
    param([AllowEmptyCollection()][object[]]$Instances = @(), [datetime]$Now = [datetime]::UtcNow)
    $best = $null
    foreach ($i in @($Instances)) {
        if ($null -eq $i) { continue }
        $status = [string](Get-SIContextValue $i 'status')
        $end = Get-SIContextValue $i 'endDateTime'
        $t = $null
        if ($end -is [datetime]) { $t = $end.ToUniversalTime() }
        elseif ($end) { $d = [datetimeoffset]::MinValue; if ([datetimeoffset]::TryParse([string]$end, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $t = $d.UtcDateTime } }
        if ($null -eq $t) { continue }
        if ($t -gt $Now.ToUniversalTime() -and $status -notin 'Completed', 'Applied') { continue }
        if ($null -eq $best -or $t -gt $best.Date) { $best = @{ Date = $t; Status = $status } }
    }
    return $best
}

# =====================================================================================================================
#  THE CAPTURE -- every read, every part
# =====================================================================================================================

function Invoke-SIEntraContextCapture {
    <#
    .SYNOPSIS  Reads the Entra context for the tenant and adds its parts to the captured Entra (and Defender for Identity)
               records. Called by the identity discovery after its sources, in every path (one process, or a run collected
               in parts: the parts are handed over with the records). Returns the number of parts added. Never throws and
               never fails the run.
    .PARAMETER Fetch  tests: { param($Url) } -> the rows of that read; no network, no token
    .PARAMETER Hunt   tests: { param($Kql) } -> the rows of the Defender for Identity summary
    .PARAMETER RoleTier  tests: { param($RoleName) } -> the tier of an Entra role (default: the privilege tier catalog)
    #>
    param([string]$Token = '', [scriptblock]$Fetch, [scriptblock]$Hunt, [datetime]$Now = [datetime]::UtcNow, [scriptblock]$RoleTier)
    $added = 0
    try {
        if ($null -eq $global:SIRecordCaptureState) { return 0 }
        $shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'shared'
        if (-not $Fetch) {
            if (-not $Token) {
                if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Get-SIGraphToken.ps1') }
                $Token = Get-SIGraphToken -Resource Graph
            }
            # the run's role and service-principal look-ups (their cache outlives the discoveries that filled it)
            if (-not (Get-Command -Name Get-SIEntraRoleScopesByPrincipal -ErrorAction SilentlyContinue)) { . (Join-Path $shared 'IdentityRoleFetcher.ps1') }
        }
        $cxUsers = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($cxId in @(Get-SIEntraCapturedIds -RecordType 'user')) { [void]$cxUsers.Add($cxId) }
        $cxSps = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($cxId in @(Get-SIEntraCapturedIds -RecordType 'service_principal')) { [void]$cxSps.Add($cxId) }
        if ($cxUsers.Count -eq 0 -and $cxSps.Count -eq 0) { return 0 }

        $cxIndex = $null; $cxScopes = @{}; $cxLookups = $null; $cxNames = @{}
        if (Get-Command -Name Get-SIServicePrincipalIndex -ErrorAction SilentlyContinue) { $cxIndex = Get-SIServicePrincipalIndex }
        if (Get-Command -Name Get-SIEntraRoleScopesByPrincipal -ErrorAction SilentlyContinue) { $cxScopes = Get-SIEntraRoleScopesByPrincipal }
        if (Get-Command -Name Get-SIRoleGroupLookups -ErrorAction SilentlyContinue) { $cxLookups = Get-SIRoleGroupLookups }
        if (Get-Command -Name Get-SIRolePrincipalNames -ErrorAction SilentlyContinue) { $cxNames = Get-SIRolePrincipalNames }
        if ($null -eq $cxLookups) { $cxLookups = @{ GroupRoles = @{}; MemberToGroups = @{}; PimGroups = @{}; RoleDefinitions = @{} } }
        $cxCount = @{ Parts = 0 }
        $cxAdd = { param($RecordType, $Id, $Part, $Object, $Provider = 'entra') if (Add-SIEntraContextPart -Provider $Provider -RecordType $RecordType -Id $Id -Part $Part -Object $Object) { $cxCount.Parts++ } }

        # ---- 1. service principals: the application registration, grants, sign-in, credential use --------------------
        if ($cxSps.Count -gt 0) {
            $apps = Get-SIEntraApplications -Token $Token -Fetch $Fetch
            if ($apps -and $apps.Read -and $cxIndex) {
                foreach ($cxAppId in @($apps.ByAppId.Keys)) {
                    if (-not $cxIndex.ByAppId.ContainsKey($cxAppId)) { continue }
                    & $cxAdd 'service_principal' ([string]$cxIndex.ByAppId[$cxAppId]) 'app' ([pscustomobject]$apps.ByAppId[$cxAppId])
                }
            }
            # delegated permission grants: the discovery's one read for the tenant, summarised per client
            $grants = $null
            if ($Fetch) { $grants = @{ Complete = $false; ByClient = @{} }; try { Add-SIOauth2GrantRows -State $grants -Rows @(& $Fetch 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'); $grants.Complete = $true } catch { } }
            elseif (Get-Command -Name Get-SIOauth2GrantsByClient -ErrorAction SilentlyContinue) { try { $grants = Get-SIOauth2GrantsByClient -Token $Token } catch { $grants = $null } }
            if ($grants -and $grants.Complete) {
                foreach ($cxClient in @($grants.ByClient.Keys)) {
                    if (-not $cxSps.Contains([string]$cxClient)) { continue }
                    & $cxAdd 'service_principal' ([string]$cxClient) 'oauth2Grants' (ConvertTo-SIOauth2GrantPart -Entry $grants.ByClient[$cxClient] -SpIndex $cxIndex)
                }
            }
            # last sign-in per application (Entra ID P1 / P2; AuditLog.Read.All)
            if ($cxIndex) {
                $null = Invoke-SIEntraContextRead -Name 'servicePrincipalSignIn' -What 'Service principal sign-in activity' -Token $Token -Fetch $Fetch -Licence 'Entra ID P1' `
                    -Fields @('si_last_sign_in', 'si_last_app_sign_in', 'si_last_delegated_sign_in') -AppliesTo 'service_principal' `
                    -Url 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999' -OnRows {
                    param($PageRows)
                    foreach ($cxR in $PageRows) {
                        $cxA = ([string](Get-SIContextValue $cxR 'appId')).ToLowerInvariant()
                        if (-not $cxA -or -not $cxIndex.ByAppId.ContainsKey($cxA)) { continue }
                        $cxO = [ordered]@{}
                        foreach ($cxN in 'lastSignInActivity', 'delegatedClientSignInActivity', 'delegatedResourceSignInActivity', 'applicationAuthenticationClientSignInActivity', 'applicationAuthenticationResourceSignInActivity') {
                            $cxT = Get-SIContextValue (Get-SIContextValue $cxR $cxN) 'lastSignInDateTime'
                            if ($cxT) { $cxO[$cxN] = [pscustomobject]@{ lastSignInDateTime = $cxT } }
                        }
                        if ($cxO.Count -gt 0) { & $cxAdd 'service_principal' ([string]$cxIndex.ByAppId[$cxA]) 'signIn' ([pscustomobject]$cxO) }
                    }
                }
                # when each secret / certificate was last used
                $cxUse = @{}
                $use = Invoke-SIEntraContextRead -Name 'credentialUse' -What 'Last use of application secrets and certificates' -Token $Token -Fetch $Fetch -Licence 'Entra ID P1' `
                    -Fields @('si_credentials') -AppliesTo 'service_principal' `
                    -Url 'https://graph.microsoft.com/beta/reports/appCredentialSignInActivities?$top=999' -OnRows {
                    param($PageRows)
                    foreach ($cxR in $PageRows) {
                        $cxA = ([string](Get-SIContextValue $cxR 'appId')).ToLowerInvariant()
                        $cxK = ([string](Get-SIContextValue $cxR 'keyId')).ToLowerInvariant()
                        $cxT = Get-SIContextValue (Get-SIContextValue $cxR 'signInActivity') 'lastSignInDateTime'
                        if (-not $cxA -or -not $cxK -or -not $cxT) { continue }
                        if ($cxT -isnot [datetime]) { try { $cxT = [datetime]::Parse([string]$cxT, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) } catch { $cxT = $null } }
                        if ($null -eq $cxT) { continue }
                        if (-not $cxUse.ContainsKey($cxA)) { $cxUse[$cxA] = @{} }
                        if (-not $cxUse[$cxA].ContainsKey($cxK) -or $cxT -gt $cxUse[$cxA][$cxK]) { $cxUse[$cxA][$cxK] = $cxT }
                    }
                }
                foreach ($cxA in @($cxUse.Keys)) {
                    if (-not $cxIndex.ByAppId.ContainsKey($cxA)) { continue }
                    $cxItems = @($cxUse[$cxA].Keys | Sort-Object | ForEach-Object { [pscustomobject][ordered]@{ keyId = $_; lastUsed = $cxUse[$cxA][$_].ToUniversalTime().ToString('o') } })
                    & $cxAdd 'service_principal' ([string]$cxIndex.ByAppId[$cxA]) 'credUsage' ([pscustomobject]@{ items = $cxItems })
                }
                # a managed identity's resource
                foreach ($cxId in @($cxIndex.AlternativeNames.Keys)) { & $cxAdd 'service_principal' ([string]$cxId) 'spExtra' ([pscustomobject]@{ alternativeNames = @($cxIndex.AlternativeNames[$cxId]) }) }
            }
            # which tenant-wide reads completed, on every service principal ("no owner" / "never used" is then a fact)
            $reads = [pscustomobject][ordered]@{
                applications = [bool]($apps -and $apps.Complete); federatedCredentials = [bool]($apps -and $apps.Federated)
                delegatedGrants = [bool]($grants -and $grants.Complete); credentialUse = [bool]($cxIndex -and $use -and $use.Complete)
            }
            foreach ($cxId in $cxSps) { & $cxAdd 'service_principal' $cxId 'contextReads' $reads }
        }

        # ---- 2. role assignments with their scope, role paths, PIM -------------------------------------------------
        $cxScopeNames = @{}
        $hasScoped = $false
        foreach ($cxP in @($cxScopes.Keys)) { foreach ($cxE in @($cxScopes[$cxP])) { if ([string]$cxE.scopeId -ne '/') { $hasScoped = $true } } }
        if ($hasScoped) {
            # LIST KEPT: a name look-up -- id + name of the administrative units that scope a role; a unit is not an object SecurityInsight records
            $null = Invoke-SIEntraContextRead -Name 'administrativeUnits' -What 'Administrative units' -Token $Token -Fetch $Fetch `
                -Url 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName&$top=999' -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) { if ($cxR -and $cxR.id) { $cxScopeNames[([string]$cxR.id).ToLowerInvariant()] = [string]$cxR.displayName } }
            }
            if ($cxIndex) { foreach ($cxP in @($cxScopes.Keys)) { foreach ($cxE in @($cxScopes[$cxP])) { $cxI = Get-SIEntraRoleScopeInfo ([string]$cxE.scopeId); if ($cxI.Type -eq 'object' -and $cxIndex.ById.ContainsKey([string]$cxI.Id)) { $cxScopeNames[[string]$cxI.Id] = [string]$cxIndex.ById[[string]$cxI.Id].displayName } } } }
        }
        $cxActivated = @{}; $cxRules = @{}
        # the activations the role maps already read this run (shared\IdentityRoleFetcher.ps1: an activated role counts as
        # an eligible role there) -- used as they are, so the tenant is asked once; read here only when that read did not
        # run or did not complete (the reason is then said, and a missing licence is recorded)
        $cxActRead = $null
        if (-not $Fetch -and (Get-Command -Name Get-SIEntraActivatedRoleAssignments -ErrorAction SilentlyContinue)) { try { $cxActRead = Get-SIEntraActivatedRoleAssignments -CacheOnly } catch { $cxActRead = $null } }
        if ($cxActRead -and $cxActRead.Complete) {
            foreach ($cxK in @($cxActRead.ByKey.Keys)) { $cxActivated[[string]$cxK] = [string]$cxActRead.ByKey[$cxK] }
            (Get-SIEntraContextState).Reads['pimActivations'] = [pscustomobject][ordered]@{ Name = 'pimActivations'; What = 'Activated role assignments (Privileged Identity Management)'; Complete = $true; Rows = $cxActivated.Count; Error = ''; Kind = '' }
        }
        if ($cxScopes.Count -gt 0) {
            if (-not ($cxActRead -and $cxActRead.Complete)) {
            $null = Invoke-SIEntraContextRead -Name 'pimActivations' -What 'Activated role assignments (Privileged Identity Management)' -Token $Token -Fetch $Fetch -Licence 'Entra ID P2' `
                -Fields @('si_entra_role_scopes') -Url ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=' + [uri]::EscapeDataString("assignmentType eq 'Activated'")) -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) {
                    if ([string](Get-SIContextValue $cxR 'assignmentType') -ne 'Activated') { continue }
                    $cxS = [string](Get-SIContextValue $cxR 'directoryScopeId'); if (-not $cxS) { $cxS = '/' }
                    $cxEnd = Get-SIContextValue $cxR 'endDateTime'
                    if ($cxEnd -is [datetime]) { $cxEnd = $cxEnd.ToUniversalTime().ToString('o') }
                    $cxActivated[('{0}|{1}|{2}' -f ([string]$cxR.principalId).ToLowerInvariant(), ([string]$cxR.roleDefinitionId).ToLowerInvariant(), $cxS)] = [string]$cxEnd
                }
            }
            }
            $null = Invoke-SIEntraContextRead -Name 'pimPolicies' -What 'Role activation rules (Privileged Identity Management)' -Token $Token -Fetch $Fetch -Licence 'Entra ID P2' `
                -Fields @('si_pim_activation_requires') -Url ('https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?$filter=' + [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole'") + '&$expand=policy($expand=rules)') -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) { $cxRule = ConvertTo-SIPimActivationRule -Assignment $cxR; if ($cxRule) { $cxRules[[string]$cxRule.roleId] = $cxRule } }
            }
        }
        # the tier of a role by its name, from the privilege tier catalog the identity profiler classifies with (the same
        # catalog, so the level speaks about the same tier). No catalog = no level (unknown), never a guess.
        $cxRoleTier = $RoleTier
        if (-not $cxRoleTier -and -not $Fetch) {
            try {
                if (-not (Get-Command -Name Get-SIEntraRoleMatches -ErrorAction SilentlyContinue)) { . (Join-Path $shared 'IdentityCatalogTierComputer.ps1') }
                $null = Initialize-SIIdentityCatalog
                $cxRoleTier = { param($cxRoleName) $cxM = @(Get-SIEntraRoleMatches -Roles @([string]$cxRoleName)); if ($cxM.Count -gt 0) { [int]$cxM[0].CatalogTier } else { $null } }
            } catch { $cxRoleTier = $null; Write-SIEntraContextLine -Warn ('The level inside the privilege tier is not set this run: the privilege tier catalog could not be read ({0}).' -f $_.Exception.Message) }
        }
        $cxRoleIdByName = @{}
        foreach ($cxRid in @($cxLookups.RoleDefinitions.Keys)) { $cxRoleIdByName[[string]$cxLookups.RoleDefinitions[$cxRid]] = ([string]$cxRid).ToLowerInvariant() }
        $cxPrincipals = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($cxP in @($cxScopes.Keys)) { [void]$cxPrincipals.Add([string]$cxP) }
        foreach ($cxP in @($cxLookups.MemberToGroups.Keys)) { [void]$cxPrincipals.Add([string]$cxP) }
        foreach ($cxP in @($cxLookups.PimGroups.Keys)) { [void]$cxPrincipals.Add([string]$cxP) }
        # the tenant-wide role ids each principal holds (direct, and through the groups it is a member of) -- Conditional
        # Access names roles by id, and so do access reviews
        $cxRoleIds = @{}
        foreach ($cxP in $cxPrincipals) {
            $cxType = ''
            if ($cxUsers.Contains($cxP)) { $cxType = 'user' } elseif ($cxSps.Contains($cxP)) { $cxType = 'service_principal' } else { continue }
            $cxEntries = @(); if ($cxScopes.ContainsKey($cxP)) { $cxEntries = @($cxScopes[$cxP]) }
            $cxItems = @(ConvertTo-SIRoleScopeItems -Entries $cxEntries -PrincipalId $cxP -ScopeNames $cxScopeNames -Activated $cxActivated)
            $cxPaths = @(Get-SIRolePaths -PrincipalId $cxP -Items $cxItems -Lookups $cxLookups -Names $cxNames)
            $cxHeld = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $cxElig = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($cxI in $cxItems) { if ($cxI.tenantWide) { if ([string]$cxI.assignment -eq 'eligible') { [void]$cxElig.Add([string]$cxI.roleId) } else { [void]$cxHeld.Add([string]$cxI.roleId) } } }
            foreach ($cxG in @($cxLookups.MemberToGroups[$cxP])) {
                if (-not $cxG -or -not $cxLookups.GroupRoles.ContainsKey([string]$cxG)) { continue }
                foreach ($cxRn in @($cxLookups.GroupRoles[[string]$cxG].Permanent)) { if ($cxRn -and $cxRoleIdByName.ContainsKey([string]$cxRn)) { [void]$cxHeld.Add($cxRoleIdByName[[string]$cxRn]) } }
                foreach ($cxRn in @($cxLookups.GroupRoles[[string]$cxG].Eligible)) { if ($cxRn -and $cxRoleIdByName.ContainsKey([string]$cxRn)) { [void]$cxElig.Add($cxRoleIdByName[[string]$cxRn]) } }
            }
            foreach ($cxG in @($cxLookups.PimGroups[$cxP])) {
                if (-not $cxG -or -not $cxLookups.GroupRoles.ContainsKey([string]$cxG)) { continue }
                foreach ($cxRn in (@($cxLookups.GroupRoles[[string]$cxG].Permanent) + @($cxLookups.GroupRoles[[string]$cxG].Eligible))) { if ($cxRn -and $cxRoleIdByName.ContainsKey([string]$cxRn)) { [void]$cxElig.Add($cxRoleIdByName[[string]$cxRn]) } }
            }
            $cxRoleIds[$cxP] = $cxHeld
            $cxActivation = New-Object System.Collections.Generic.List[object]
            foreach ($cxRid in @($cxElig | Sort-Object)) {
                if (-not $cxRules.ContainsKey($cxRid)) { continue }
                $cxActivation.Add([pscustomobject][ordered]@{ role = [string]$cxLookups.RoleDefinitions[$cxRid]; roleId = $cxRid; requires = @($cxRules[$cxRid].requires); maxDuration = [string]$cxRules[$cxRid].maxDuration })
            }
            if ($cxItems.Count -eq 0 -and $cxPaths.Count -eq 0) { continue }
            $cxPart = [ordered]@{ items = $cxItems; paths = $cxPaths }
            # a role held through a group the identity is a member of ONLY while an eligible membership is activated: listed
            # with the group and until when (an eligible role, as an activated directory role is) -- after its own
            # assignments, which the paths, the held roles and the level above are computed from
            $cxViaItems = New-Object System.Collections.Generic.List[object]
            foreach ($cxG in @($cxLookups.MemberToGroups[$cxP])) {
                if (-not $cxG -or -not $cxScopes.ContainsKey([string]$cxG)) { continue }
                $cxAct = Get-SIGroupActivationOf -Lookups $cxLookups -PrincipalId $cxP -GroupId ([string]$cxG)
                if (-not $cxAct.Activated) { continue }
                $cxGn = ''; if ($cxNames.ContainsKey([string]$cxG)) { $cxGn = [string]$cxNames[[string]$cxG] }
                $cxGroupItems = @(ConvertTo-SIRoleScopeItems -Entries @($cxScopes[[string]$cxG]) -PrincipalId ([string]$cxG) -ScopeNames $cxScopeNames -Activated $cxActivated)
                foreach ($cxVi in @(ConvertTo-SIGroupActivatedRoleItems -GroupItems $cxGroupItems -GroupId ([string]$cxG) -GroupName $cxGn -Until ([string]$cxAct.Until))) { $cxViaItems.Add($cxVi) }
            }
            if ($cxViaItems.Count -gt 0) { $cxPart['items'] = @(@($cxItems) + @($cxViaItems.ToArray())) }
            if ($cxActivation.Count -gt 0) { $cxPart['activation'] = $cxActivation.ToArray() }
            # the level inside the privilege tier: every way the identity holds a role -- its own assignments and those of
            # the groups it is a member of or can activate into, each with its scope -- decides it (Get-SIRoleTierLevel)
            if ($cxRoleTier) {
                $cxHoldings = New-Object System.Collections.Generic.List[object]
                foreach ($cxI in $cxItems) { $cxHoldings.Add($cxI) }
                foreach ($cxG in (@($cxLookups.MemberToGroups[$cxP]) + @($cxLookups.PimGroups[$cxP]))) {
                    if (-not $cxG -or -not $cxScopes.ContainsKey([string]$cxG)) { continue }
                    $cxGn = ''; if ($cxNames.ContainsKey([string]$cxG)) { $cxGn = [string]$cxNames[[string]$cxG] }; if (-not $cxGn) { $cxGn = [string]$cxG }
                    foreach ($cxGi in @(ConvertTo-SIRoleScopeItems -Entries @($cxScopes[[string]$cxG]) -PrincipalId ([string]$cxG) -ScopeNames $cxScopeNames -Activated $cxActivated)) {
                        $cxGi | Add-Member -NotePropertyName via -NotePropertyValue $cxGn -Force
                        $cxHoldings.Add($cxGi)
                    }
                }
                $cxLevel = $null
                try { $cxLevel = Get-SIRoleTierLevel -Holdings $cxHoldings.ToArray() -RoleTier $cxRoleTier } catch { $cxLevel = $null }
                if ($cxLevel) { $cxPart['tierLevel'] = [pscustomobject]$cxLevel }
            }
            & $cxAdd $cxType $cxP 'roleScopes' ([pscustomobject]$cxPart)
        }

        # ---- 3. users: manager, sponsors, Conditional Access ------------------------------------------------------
        $cxGuests = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        if ($cxUsers.Count -gt 0) {
            # LIST KEPT: a join read -- the user id and its manager as a reference (id + name + sign-in name); the user itself is read once, elsewhere
            $null = Invoke-SIEntraContextRead -Name 'managers' -What 'Managers of users' -Token $Token -Fetch $Fetch -AppliesTo 'user' `
                -Url 'https://graph.microsoft.com/v1.0/users?$select=id,userType&$expand=manager($select=id,displayName,userPrincipalName)&$top=999' -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) {
                    if ($null -eq $cxR -or -not $cxR.id) { continue }
                    if ([string](Get-SIContextValue $cxR 'userType') -eq 'Guest') { [void]$cxGuests.Add([string]$cxR.id) }
                    $cxM = Get-SIContextValue $cxR 'manager'
                    if ($null -eq $cxM -or -not (Get-SIContextValue $cxM 'id')) { continue }
                    & $cxAdd 'user' ([string]$cxR.id) 'manager' ([pscustomobject][ordered]@{ id = ([string]$cxM.id).ToLowerInvariant(); userPrincipalName = ([string](Get-SIContextValue $cxM 'userPrincipalName')).ToLowerInvariant(); displayName = [string](Get-SIContextValue $cxM 'displayName') })
                }
            }
            # LIST KEPT: a join read -- the guest id and its sponsors as references (id + name + sign-in name)
            $null = Invoke-SIEntraContextRead -Name 'sponsors' -What 'Sponsors of guest users' -Token $Token -Fetch $Fetch -AppliesTo 'user' `
                -Url ('https://graph.microsoft.com/v1.0/users?$filter=' + [uri]::EscapeDataString("userType eq 'Guest'") + '&$select=id&$expand=sponsors($select=id,displayName,userPrincipalName)&$top=100') -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) {
                    if ($null -eq $cxR -or -not $cxR.id) { continue }
                    $cxList = @(@(Get-SIContextValue $cxR 'sponsors') | ForEach-Object { ConvertTo-SIOwnerItem $_ } | Where-Object { $_ })
                    if ($cxList.Count -gt 0) { & $cxAdd 'user' ([string]$cxR.id) 'sponsors' ([pscustomobject]@{ items = $cxList }) }
                }
            }
            $cxPolicies = New-Object System.Collections.Generic.List[object]
            $ca = Invoke-SIEntraContextRead -Name 'conditionalAccess' -What 'Conditional Access policies' -Token $Token -Fetch $Fetch -Licence 'Entra ID P1' `
                -Fields @('si_ca_mfa_enforced', 'si_ca_policy_count', 'si_ca_excluded_policies') -AppliesTo 'user' `
                -Url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) { $cxPol = ConvertTo-SICaPolicy -Policy $cxR; if ($cxPol -and $cxPol.Enabled) { $cxPolicies.Add($cxPol) } }
            }
            if ($ca.Complete) {
                $cxMembers = @{}
                $cxUnknown = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                $cxGone = 0
                foreach ($cxPol in $cxPolicies) {
                    foreach ($cxG in (@($cxPol.IncludeGroups) + @($cxPol.ExcludeGroups))) {
                        if (-not $cxG -or $cxMembers.ContainsKey([string]$cxG) -or $cxUnknown.Contains([string]$cxG)) { continue }
                        $cxGm = Get-SIEntraGroupMemberIds -GroupId ([string]$cxG) -Token $Token -Fetch $Fetch
                        if ($cxGm.Complete) { $cxMembers[[string]$cxG] = $cxGm.Ids; if ($cxGm.Gone) { $cxGone++ } } else { [void]$cxUnknown.Add([string]$cxG) }
                    }
                }
                if ($cxGone -gt 0) { Write-SIEntraContextLine ('Conditional Access: {0} group(s) the policies name no longer exist -- they include or exclude no user (the policies still name them; remove them from the policies to tidy up).' -f $cxGone) }
                if ($cxUnknown.Count -gt 0) { Write-SIEntraContextLine -Warn ('Conditional Access: the members of {0} group(s) the policies name could not be read -- whether MFA is enforced stays unknown for the users those policies would decide.' -f $cxUnknown.Count) }
                $policyArr = $cxPolicies.ToArray()
                foreach ($cxU in $cxUsers) {
                    $cxV = Get-SICaUserVerdict -UserId $cxU -IsGuest ($cxGuests.Contains($cxU)) -Policies $policyArr -GroupMembers $cxMembers -UnknownGroups $cxUnknown -RoleIds $cxRoleIds[$cxU]
                    & $cxAdd 'user' $cxU 'ca' ([pscustomobject]$cxV)
                }
            }
        }

        # ---- 4. Identity Protection -----------------------------------------------------------------------------------
        # #639: the 'risk' part of a user goes into the hand-over AS ITS PAGE ARRIVES -- never every user's context held.
        # The 30 days of detections are read FIRST and kept only as a compact summary per user who HAS detections (a count
        # and the detection types, as one text); then each page of risky users adds its users' parts at once, the detection
        # summary merged in and let go; the users with detections but no risky-user entry are added last.
        if ($cxUsers.Count -gt 0) {
            $cxDet = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
            $since = $Now.ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
            # LIST KEPT (the $select below): 30 days of detections are SUMMARISED per user to a count and the detection types --
            # a detection is a large object (location, address, activity) and there can be very many; the whole object is not kept
            $rd = Invoke-SIEntraContextRead -Name 'riskDetections' -What 'Identity Protection risk detections (30 days)' -Token $Token -Fetch $Fetch -Licence 'Entra ID P2' `
                -Fields @('si_risk_detections_30d', 'si_risk_detection_types_30d') -AppliesTo 'user' `
                -Url ('https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=' + [uri]::EscapeDataString("detectedDateTime ge $since") + '&$select=userId,riskEventType,riskLevel,detectedDateTime&$top=500') -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) {
                    $cxU = ([string](Get-SIContextValue $cxR 'userId')).ToLowerInvariant()
                    if (-not $cxU -or -not $cxUsers.Contains($cxU)) { continue }
                    $cxT = [string](Get-SIContextValue $cxR 'riskEventType')
                    $cxS = $null
                    if (-not $cxDet.TryGetValue($cxU, [ref]$cxS)) { $cxS = [pscustomobject]@{ N = 0; Types = '' }; $cxDet[$cxU] = $cxS }
                    $cxS.N++
                    if ($cxT -and -not (("`n" + $cxS.Types + "`n").Contains("`n" + $cxT + "`n"))) { if ($cxS.Types) { $cxS.Types += "`n" + $cxT } else { $cxS.Types = $cxT } }
                }
            }
            $cxDetOf = {
                param($cxU, $cxO)
                $cxS = $null
                if ($rd.Complete -and $cxDet.TryGetValue($cxU, [ref]$cxS)) {
                    $cxO['detections30d'] = [int]$cxS.N
                    $cxO['detectionTypes30d'] = @(([string]$cxS.Types -split "`n") | Where-Object { $_ } | Sort-Object -CaseSensitive -Unique)
                    [void]$cxDet.Remove($cxU)
                }
            }
            $ru = Invoke-SIEntraContextRead -Name 'riskyUsers' -What 'Identity Protection risky users' -Token $Token -Fetch $Fetch -Licence 'Entra ID P2' `
                -Fields @('si_entra_risk_level', 'si_entra_risk_state', 'si_entra_risk_detail', 'si_entra_risk_updated') -AppliesTo 'user' `
                -Url 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$top=500' -OnRows {
                # WHOLE OBJECT: no property list -- a risky-user object is a handful of values and only users at risk have one
                param($PageRows)
                foreach ($cxR in $PageRows) {
                    if ($null -eq $cxR -or -not $cxR.id -or -not $cxUsers.Contains([string]$cxR.id)) { continue }
                    $cxU = ([string]$cxR.id).ToLowerInvariant()
                    $cxO = [ordered]@{ riskLevel = [string]$cxR.riskLevel; riskState = [string]$cxR.riskState; riskDetail = [string]$cxR.riskDetail; riskLastUpdatedDateTime = $cxR.riskLastUpdatedDateTime }
                    Add-SIContextOtherProperties -Into $cxO -From $cxR -Skip @('id')
                    & $cxDetOf $cxU $cxO
                    & $cxAdd 'user' $cxU 'risk' ([pscustomobject]$cxO)
                }
            }
            # the users with detections and no risky-user entry: their detection summary alone
            if ($rd.Complete) {
                foreach ($cxU in @($cxDet.Keys | Sort-Object)) {
                    $cxO = [ordered]@{}
                    & $cxDetOf $cxU $cxO
                    if ($cxO.Count -gt 0) { & $cxAdd 'user' $cxU 'risk' ([pscustomobject]$cxO) }
                }
            }
            $cxDet.Clear(); $cxDet = $null
        }        if ($cxSps.Count -gt 0) {
            $null = Invoke-SIEntraContextRead -Name 'riskyServicePrincipals' -What 'Identity Protection risky service principals' -Token $Token -Fetch $Fetch -Licence 'Workload Identities Premium' `
                -Fields @('si_entra_risk_level', 'si_entra_risk_state', 'si_entra_risk_detail', 'si_entra_risk_updated') -AppliesTo 'service_principal' `
                -Url 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals?$top=500' -OnRows {
                # WHOLE OBJECT: no property list -- a handful of values, and only service principals at risk have one
                param($PageRows)
                foreach ($cxR in $PageRows) {
                    if ($null -eq $cxR -or -not $cxR.id) { continue }
                    $cxRs = [ordered]@{ riskLevel = [string]$cxR.riskLevel; riskState = [string]$cxR.riskState; riskDetail = [string]$cxR.riskDetail; riskLastUpdatedDateTime = $cxR.riskLastUpdatedDateTime }
                    Add-SIContextOtherProperties -Into $cxRs -From $cxR -Skip @('id')
                    & $cxAdd 'service_principal' ([string]$cxR.id) 'risk' ([pscustomobject]$cxRs)
                }
            }
        }

        # ---- 5. the privileged objects an identity OWNS -----------------------------------------------------------
        $cxOwned = @{}
        $cxOwn = {
            param($OwnerId, $Kind, $Id, $Name, $Roles)
            $ok = ([string]$OwnerId).ToLowerInvariant()
            if (-not $ok -or @($Roles).Count -eq 0) { return }
            if (-not $cxOwned.ContainsKey($ok)) { $cxOwned[$ok] = New-Object System.Collections.Generic.List[object] }
            $cxOwned[$ok].Add([pscustomobject][ordered]@{ kind = $Kind; id = [string]$Id; name = [string]$Name; roles = @($Roles | Sort-Object -Unique) })
        }
        $cxTenantRoles = { param($Id) @(@($cxScopes[[string]$Id]) | Where-Object { $_ -and [string]$_.scopeId -eq '/' } | ForEach-Object { [string]$_.role }) }
        # service principals that hold an Entra role: their owners, and the owners of their application registration
        $spOwners = $global:SISpOwnerState
        foreach ($cxP in @($cxScopes.Keys)) {
            $cxSpId = ([string]$cxP).ToLowerInvariant()
            if (-not $cxSps.Contains($cxSpId)) { continue }
            $cxRolesHeld = & $cxTenantRoles $cxP
            if (@($cxRolesHeld).Count -eq 0) { continue }
            $cxSpName = ''; $cxSpApp = ''
            if ($cxIndex -and $cxIndex.ById.ContainsKey($cxSpId)) { $cxSpName = [string]$cxIndex.ById[$cxSpId].displayName; $cxSpApp = [string]$cxIndex.ById[$cxSpId].appId }
            if ($spOwners -and $spOwners.Read -and $spOwners.Owners -and $spOwners.Owners.ContainsKey($cxSpId)) { foreach ($cxO in @($spOwners.Owners[$cxSpId])) { & $cxOwn $cxO.id 'service principal' $cxSpId $cxSpName $cxRolesHeld } }
            foreach ($cxO in @(Get-SIEntraAppOwners -Apps (Get-SIEntraContextState).Apps -AppId $cxSpApp)) { & $cxOwn $cxO.id 'application' $cxSpApp $cxSpName $cxRolesHeld }
        }
        # groups that hold an Entra role: their owners (one read per such group)
        foreach ($cxG in @($cxLookups.GroupRoles.Keys)) {
            $cxGr = $cxLookups.GroupRoles[$cxG]
            $cxGroupRoles = @(@($cxGr.Permanent) + @($cxGr.Eligible) | Where-Object { $_ })
            if ($cxGroupRoles.Count -eq 0) { continue }
            $cxGName = ''; if ($cxNames.ContainsKey([string]$cxG)) { $cxGName = [string]$cxNames[[string]$cxG] }
            $cxGOwners = New-Object System.Collections.Generic.List[object]
            # LIST KEPT: references only -- the owners of a role-holding group as id + name + sign-in name
            $go = Invoke-SIEntraContextRead -Name ('groupOwners:' + $cxG) -What 'Owners of a group that holds an Entra role' -Token $Token -Fetch $Fetch -Quiet `
                -Url ('https://graph.microsoft.com/v1.0/groups/{0}/owners?$select=id,displayName,userPrincipalName&$top=999' -f $cxG) -OnRows {
                param($PageRows)
                foreach ($cxR in $PageRows) { $cxIt = ConvertTo-SIOwnerItem $cxR; if ($cxIt) { $cxGOwners.Add($cxIt) } }
            }
            (Get-SIEntraContextState).Reads.Remove(('groupOwners:' + $cxG))
            if ($go.Complete) { foreach ($cxO in $cxGOwners) { & $cxOwn $cxO.id 'group' $cxG $cxGName $cxGroupRoles } }
        }
        foreach ($cxO in @($cxOwned.Keys)) {
            $cxType = ''
            if ($cxUsers.Contains($cxO)) { $cxType = 'user' } elseif ($cxSps.Contains($cxO)) { $cxType = 'service_principal' } else { continue }
            & $cxAdd $cxType $cxO 'controls' ([pscustomobject]@{ items = @($cxOwned[$cxO].ToArray() | Sort-Object kind, name, id) })
        }

        # ---- 6. access reviews (AccessReview.Read.All) ------------------------------------------------------------
        $cxDefs = New-Object System.Collections.Generic.List[object]
        $ar = Invoke-SIEntraContextRead -Name 'accessReviews' -What 'Access reviews' -Token $Token -Fetch $Fetch -Licence 'Entra ID Governance or Entra ID P2' `
            -Fields @('si_last_access_review', 'si_last_access_review_date') `
            -Url 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=100' -OnRows {
            param($PageRows)
            foreach ($cxR in $PageRows) {
                $cxTargets = @(Get-SIAccessReviewTargets -Definition $cxR)
                if ($cxTargets.Count -gt 0) { $cxDefs.Add(@{ Id = [string]$cxR.id; Name = [string](Get-SIContextValue $cxR 'displayName'); Status = [string](Get-SIContextValue $cxR 'status'); Targets = $cxTargets }) }
            }
        }
        if ($ar.Complete -and $cxDefs.Count -gt 0) {
            $cxReviewed = @{}     # '<kind>|<id>' -> the newest review of that object
            foreach ($cxD in $cxDefs) {
                $cxInst = New-Object System.Collections.Generic.List[object]
                # LIST KEPT: a summary by design -- when each review ran and how it ended; the decisions inside a review are not read
                $ir = Invoke-SIEntraContextRead -Name ('accessReviewInstances:' + $cxD.Id) -What 'Access review instances' -Token $Token -Fetch $Fetch -Quiet `
                    -Url ('https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances?$select=id,status,startDateTime,endDateTime&$top=100' -f $cxD.Id) -OnRows {
                    param($PageRows)
                    foreach ($cxR in $PageRows) { if ($cxR) { $cxInst.Add($cxR) } }
                }
                (Get-SIEntraContextState).Reads.Remove(('accessReviewInstances:' + $cxD.Id))
                if (-not $ir.Complete) { continue }
                $cxLast = Get-SIAccessReviewLatest -Instances $cxInst.ToArray() -Now $Now
                foreach ($cxT in $cxD.Targets) {
                    $cxKey = '{0}|{1}' -f $cxT.Kind, $cxT.Id
                    $cxNew = @{ reviewId = $cxD.Id; reviewName = $cxD.Name; lastReviewed = $null; status = 'never completed' }
                    if ($cxLast) { $cxNew.lastReviewed = $cxLast.Date; $cxNew.status = [string]$cxLast.Status }
                    $cxOld = $cxReviewed[$cxKey]
                    if ($null -eq $cxOld -or ($cxNew.lastReviewed -and (-not $cxOld.lastReviewed -or $cxNew.lastReviewed -gt $cxOld.lastReviewed))) { $cxReviewed[$cxKey] = $cxNew }
                }
            }
            $cxReviewItem = {
                param($Kind, $Id, $Name)
                $rv = $cxReviewed[('{0}|{1}' -f $Kind, ([string]$Id).ToLowerInvariant())]
                if ($null -eq $rv) { return $null }
                $o = [ordered]@{ kind = $Kind; id = ([string]$Id).ToLowerInvariant(); name = [string]$Name; reviewId = [string]$rv.reviewId; reviewName = [string]$rv.reviewName; status = [string]$rv.status }
                if ($rv.lastReviewed) { $o['lastReviewed'] = ([datetime]$rv.lastReviewed).ToUniversalTime().ToString('o') }
                [pscustomobject]$o
            }
            $cxTargetsOf = @{}
            $cxPush = { param($Principal, $Item) if ($null -eq $Item) { return }; $pk = ([string]$Principal).ToLowerInvariant(); if (-not $cxTargetsOf.ContainsKey($pk)) { $cxTargetsOf[$pk] = New-Object System.Collections.Generic.List[object] }; $cxTargetsOf[$pk].Add($Item) }
            foreach ($cxP in $cxPrincipals) {
                $cxPk = ([string]$cxP).ToLowerInvariant()
                foreach ($cxE in @($cxScopes[$cxP])) { if ($cxE) { & $cxPush $cxPk (& $cxReviewItem 'role' $cxE.roleId $cxE.role) } }
                foreach ($cxG in (@($cxLookups.MemberToGroups[$cxP]) + @($cxLookups.PimGroups[$cxP]))) { if ($cxG) { & $cxPush $cxPk (& $cxReviewItem 'group' $cxG $cxNames[[string]$cxG]) } }
            }
            foreach ($cxSpId in $cxSps) { $cxSpName = ''; if ($cxIndex -and $cxIndex.ById.ContainsKey($cxSpId)) { $cxSpName = [string]$cxIndex.ById[$cxSpId].displayName }; & $cxPush $cxSpId (& $cxReviewItem 'application' $cxSpId $cxSpName) }
            foreach ($cxPk in @($cxTargetsOf.Keys)) {
                $cxType = ''
                if ($cxUsers.Contains($cxPk)) { $cxType = 'user' } elseif ($cxSps.Contains($cxPk)) { $cxType = 'service_principal' } else { continue }
                $cxSeenItems = New-Object 'System.Collections.Generic.HashSet[string]'
                $cxList = @($cxTargetsOf[$cxPk] | Where-Object { $cxSeenItems.Add(('{0}|{1}' -f $_.kind, $_.id)) })
                $cxDates = @($cxList | Where-Object { $_.PSObject.Properties['lastReviewed'] } | ForEach-Object { [string]$_.lastReviewed } | Sort-Object)
                $cxPart = [ordered]@{ items = $cxList }
                if ($cxDates.Count -gt 0) { $cxPart['lastReviewed'] = $cxDates[-1] }
                & $cxAdd $cxType $cxPk 'accessReview' ([pscustomobject]$cxPart)
            }
        }

        # ---- 7. Defender for Identity: 30 days of logons, summarised in the query ---------------------------------
        $cxMdi = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($cxId in @(Get-SIEntraCapturedIds -RecordType 'user' -Provider 'mdi')) { [void]$cxMdi.Add($cxId) }
        if ($cxMdi.Count -gt 0) {
            $kql = Get-SIMdiLogonSummaryKql
            $rowsMdi = $null; $mdiErr = ''
            try {
                if ($Hunt) { $rowsMdi = @(& $Hunt $kql) }
                else {
                    if (-not (Get-Command -Name Invoke-SIHuntingQuery -ErrorAction SilentlyContinue)) { . (Join-Path $shared 'HuntingQuery.ps1') }
                    $hw = $null
                    $rowsMdi = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine 'DefenderGraph' -WarningVariable hw -WarningAction SilentlyContinue)
                    if ($hw -and @($hw).Count -gt 0) { $mdiErr = (@($hw) -join ' | '); $rowsMdi = $null }
                }
            } catch { $mdiErr = [string]$_.Exception.Message; $rowsMdi = $null }
            $mdiFields = @('si_onprem_last_logon', 'si_cleartext_ldap', 'si_ntlm_logons')
            if ($null -eq $rowsMdi) {
                if ($mdiErr -match '(?i)IdentityLogonEvents' -and $mdiErr -match '(?i)resolve|not found|does not exist|unknown table|Failed to resolve') {
                    Add-SIEntraNotLicensed -Licence 'Defender for Identity' -Fields $mdiFields -AppliesTo 'user'
                    Write-SIEntraContextLine 'Defender for Identity logons: not licensed (Defender for Identity) -- shown as such on each user, never as "no logon".'
                } else { Write-SIEntraContextLine -Warn ('Defender for Identity logons: not read ({0}). On-premises logon, cleartext LDAP and NTLM stay unknown this run.' -f $mdiErr) }
                (Get-SIEntraContextState).Reads['mdiLogons'] = [pscustomobject]@{ Name = 'mdiLogons'; What = 'Defender for Identity logons'; Complete = $false; Rows = 0; Error = $mdiErr; Kind = '' }
            } else {
                # #639: each summary row goes into its user's part and is let go as it is added -- the rows are not kept
                # beside the parts
                $mdiCount = @($rowsMdi).Count
                for ($cxI = 0; $cxI -lt $mdiCount; $cxI++) {
                    $cxR = $rowsMdi[$cxI]; $rowsMdi[$cxI] = $null
                    $cxU = ([string](Get-SIContextValue $cxR 'AccountObjectId')).ToLowerInvariant()
                    if (-not $cxU) { continue }
                    $cxO = [ordered]@{ CleartextLdap = [int](Get-SIContextValue $cxR 'CleartextLdap'); NtlmLogons = [int](Get-SIContextValue $cxR 'NtlmLogons') }
                    $cxT = Get-SIContextValue $cxR 'OnPremLastLogon'; if ($cxT) { $cxO['OnPremLastLogon'] = $cxT }
                    & $cxAdd 'user' $cxU 'logon' ([pscustomobject]$cxO) 'mdi'
                }
                $rowsMdi = $null
                (Get-SIEntraContextState).Reads['mdiLogons'] = [pscustomobject]@{ Name = 'mdiLogons'; What = 'Defender for Identity logons'; Complete = $true; Rows = $mdiCount; Error = ''; Kind = '' }
                if ($mdiCount -ge 100000) { Write-SIEntraContextLine -Warn 'Defender for Identity logons: Microsoft returns at most 100,000 summary rows per query -- users beyond that keep these three values unknown.' }
            }
        }

        # ---- 8. what the tenant is not licensed for, on each record it concerns -----------------------------------
        $nl = @((Get-SIEntraContextState).NotLicensed)
        if ($nl.Count -gt 0) {
            foreach ($cxKind in 'user', 'service_principal') {
                $cxMine = @($nl | Where-Object { $_.appliesTo -in $cxKind, 'both' } | ForEach-Object { [pscustomobject][ordered]@{ fields = @($_.fields); licence = [string]$_.licence; text = [string]$_.text } })
                if ($cxMine.Count -eq 0) { continue }
                $cxPart = [pscustomobject]@{ items = $cxMine }
                $cxSet = $cxUsers; if ($cxKind -eq 'service_principal') { $cxSet = $cxSps }
                foreach ($cxId in $cxSet) { & $cxAdd $cxKind $cxId 'notLicensed' $cxPart }
            }
        }

        $added = [int]$cxCount.Parts
        $st = Get-SIEntraContextState
        $done = @($st.Reads.Values | Where-Object { $_.Complete }).Count
        $all = @($st.Reads.Values).Count
        Write-SIEntraContextLine ('identity context: {0} of {1} read(s) completed; {2:N0} detail(s) added to {3:N0} user(s) and {4:N0} service principal(s)' -f $done, $all, $added, $cxUsers.Count, $cxSps.Count)
    } catch {
        Write-SIEntraContextLine -Warn ('identity context: stopped early ({0}). The identities are unaffected; the context read so far is kept.' -f $_.Exception.Message)
    }
    return $added
}

function Get-SIMdiLogonSummaryKql {
    <# PURE. 30 days of Defender for Identity logons, summarised per Entra object id INSIDE the query (never the raw events). #>
    @"
IdentityLogonEvents
| where Timestamp > ago(30d)
| where isnotempty(AccountObjectId)
| summarize OnPremLastLogon = maxif(Timestamp, Application =~ "Active Directory" and ActionType =~ "LogonSuccess"),
            CleartextLdap = countif(LogonType =~ "LDAP cleartext"),
            NtlmLogons = countif(Protocol =~ "Ntlm" and ActionType =~ "LogonSuccess")
            by AccountObjectId
| where isnotnull(OnPremLastLogon) or CleartextLdap > 0 or NtlmLogons > 0
"@
}

# =====================================================================================================================
#  ENTRA DEVICES: the registered owners  (part 'registeredOwners', endpoint discovery)
# =====================================================================================================================

function Invoke-SIEntraDeviceOwnerCapture {
    <#
    .SYNOPSIS  The registered owners of every Entra device -> part 'registeredOwners' ({ items: id, upn, name, type }) on its
               captured Entra device record (keyed by the device id). ONE paged read (GET /devices with registeredOwners
               expanded, $top=100; Device.Read.All, held). Returns the number of records decorated. Never throws.
    #>
    param([string]$Token = '', [scriptblock]$Fetch)
    $cxDone = @{ N = 0 }
    try {
        if ($null -eq $global:SIRecordCaptureState) { return 0 }
        if (@(Get-SIEntraCapturedIds -RecordType 'device').Count -eq 0) { return 0 }
        if (-not $Fetch -and -not $Token) {
            if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Get-SIGraphToken.ps1') }
            $Token = Get-SIGraphToken -Resource Graph
        }
        # LIST KEPT: a join read -- the device id and its registered owners as references; the device itself is read once, elsewhere
        $null = Invoke-SIEntraContextRead -Name 'deviceOwners' -What 'Registered owners of devices' -Token $Token -Fetch $Fetch `
            -Url 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId&$expand=registeredOwners($select=id,displayName,userPrincipalName)&$top=100' -OnRows {
            param($PageRows)
            foreach ($cxR in $PageRows) {
                if ($null -eq $cxR -or -not $cxR.deviceId) { continue }
                $cxList = @(@(Get-SIContextValue $cxR 'registeredOwners') | ForEach-Object { ConvertTo-SIOwnerItem $_ } | Where-Object { $_ })
                if ($cxList.Count -eq 0) { continue }
                if (Add-SIEntraContextPart -RecordType 'device' -Id ([string]$cxR.deviceId) -Part 'registeredOwners' -Object ([pscustomobject]@{ items = $cxList })) { $cxDone.N++ }
            }
        }
    } catch { Write-SIEntraContextLine -Warn ('Registered owners of devices: ' + $_.Exception.Message) }
    return [int]$cxDone.N
}
