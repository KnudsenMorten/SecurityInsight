#Requires -Version 5.1
<#
    SecurityInsight -- ONE PULL PER SOURCE (REQUIREMENTS #301 / #412, operator 2026-10-06).

    Operator: "we dont pull in the same data twice (limited and full) ... if we do asset full, then it is 100% the same
    fields as limited - but with the extra metadata." Approved: one pull per source + history.

    TWO LEVELS, ONE SETTING (SI_AssetProperties):
      security (the default, in the Community edition and Pro alike)
                  every profiler reads its sources EXACTLY as before -- the same URLs, the same $select, the same
                  ARG projection -- and collects nothing extra. This file then does nothing at all.
      full        (opt-in; the Community edition has it too, owner 2026-10-27) each profiler reads each source ONCE, with the narrowing removed, and in the same
                  pass (a) builds its security record from that object -- the same fields, the same values, so the
                  SI_*_Profile_CL row is identical to the security level's -- and (b) keeps the whole object here, so
                  the Output stage publishes it to SI_AssetProperties_CL with the SAME CollectionTime as the profile row.
                  There is no second pass any more: the separate asset-properties job no longer reads any source.

    WHY THE LEVEL IS DECIDED ONCE, BEFORE DISCOVERY: the source queries depend on it. 'full' needs (1) the setting and
    (2) the publisher (engine\asset-properties -- in every copy since 2026-10-27; Initialize-SIFullAssetProperties still
    loads it only after Test-Path finds it). No licence is asked: the full asset properties are in the Community edition
    (owner 2026-10-27, SI #750 (1)). Anything short of both runs the security level and says why, ONCE.

    WHAT THIS FILE HOLDS (no licence dependency):
      * the run state ($global:SIFullAssetPropertiesState): the level, the engine, the collected objects, per-source pull
        status -- reset by every engine run (a container session runs several engines);
      * Add-SIFullSourceObject: what a discovery function calls for each whole source object (a no-op at security);
      * the Microsoft Graph wide $select (Get-SIFullGraphUrl): Graph has no "everything" -- a property is returned only
        when it is in the default set or named in $select -- so 'full' = the security $select UNION a declared list of
        collection-selectable properties. The security fields stay first and are never removed, which is what keeps the
        security record identical. A full $select Graph refuses (HTTP 400) is retried ONCE with the security URL and said:
        that source then carries the security fields only, and the profile row is unaffected.

    PS 5.1 + 7. No PowerShell modules. NO Set-StrictMode (it leaks into the caller's scope).
#>

# The properties a full pull asks Microsoft Graph for IN ADDITION to the security $select -- each a v1.0 property that
# may be selected on the COLLECTION with the permission the security pull already holds (Device.Read.All /
# User.Read.All / Application.Read.All). Deliberately NOT here: properties only readable on a single object
# (mailboxSettings, aboutMe, birthday, hireDate, interests, mySite, pastProjects, preferredName, responsibilities,
# schools, skills -- HTTP 501 on the collection) and properties behind another permission (employeeLeaveDateTime,
# employeeHireDate: User-LifeCycleInfo.Read.All). One wrong name makes Graph refuse the WHOLE request, which is why a
# refusal falls back to the security URL rather than failing the source.
$script:SIFullGraphExtraSelect = @{
    'entra-device' = @(
        'accountEnabled', 'alternativeSecurityIds', 'complianceExpirationDateTime', 'deviceMetadata', 'deviceOwnership', 'deviceVersion',
        'enrollmentProfileName', 'enrollmentType', 'extensionAttributes', 'isCompliant', 'isManaged', 'managementType', 'manufacturer',
        'mdmAppId', 'model', 'onPremisesLastSyncDateTime', 'onPremisesSecurityIdentifier', 'onPremisesSyncEnabled', 'operatingSystemVersion',
        'physicalIds', 'systemLabels'
    )
    'entra-user' = @(
        'businessPhones', 'givenName', 'surname', 'mobilePhone', 'officeLocation', 'preferredLanguage', 'city', 'companyName', 'country',
        'state', 'streetAddress', 'postalCode', 'usageLocation', 'employeeId', 'employeeType', 'employeeOrgData', 'mailNickname',
        'otherMails', 'proxyAddresses', 'imAddresses', 'onPremisesDistinguishedName', 'onPremisesDomainName', 'onPremisesSamAccountName',
        'onPremisesUserPrincipalName', 'onPremisesSecurityIdentifier', 'onPremisesImmutableId', 'onPremisesLastSyncDateTime',
        'onPremisesExtensionAttributes', 'onPremisesProvisioningErrors', 'assignedPlans', 'provisionedPlans', 'licenseAssignmentStates',
        'passwordPolicies', 'lastPasswordChangeDateTime', 'signInSessionsValidFromDateTime', 'creationType', 'externalUserState',
        'externalUserStateChangeDateTime', 'identities', 'ageGroup', 'consentProvidedForMinor', 'legalAgeGroupClassification',
        'preferredDataLocation', 'faxNumber', 'securityIdentifier'
    )
    'entra-serviceprincipal' = @(
        'addIns', 'alternativeNames', 'appDescription', 'appDisplayName', 'appRoleAssignmentRequired', 'appRoles', 'applicationTemplateId',
        'description', 'disabledByMicrosoftStatus', 'info', 'loginUrl', 'logoutUrl', 'notes', 'notificationEmailAddresses',
        'oauth2PermissionScopes', 'preferredSingleSignOnMode', 'preferredTokenSigningKeyThumbprint', 'replyUrls',
        'resourceSpecificApplicationPermissions', 'samlSingleSignOnSettings', 'servicePrincipalNames', 'tokenEncryptionKeyId'
    )
}

# WHOLE OBJECT (continuous discovery): the sources whose full pull names NO properties at all. Microsoft Graph returns
# every property of a device without a $select, the object is small and it is one object per device -- so the full pull
# drops the list, and a property Microsoft adds arrives on the next run with no code change. NOT here, each for its reason:
#   entra-user              Graph returns only a default set of a user's properties without a $select (there is no
#                           "everything") -- the list above stays; what Graph offers beyond it is shown as "offered, not
#                           read" by the weekly discovery of Graph's published model.
#   entra-serviceprincipal  customSecurityAttributes is returned only when named, and Microsoft's own service principals
#                           carry very large role and permission lists -- the list above stays.
$script:SIFullGraphWholeObject = @('entra-device')

# Which source systems each profiler collects at the full level (the anchor each resolves through is in the Pro file).
$script:SIFullEngineSources = @{
    endpoint = @('mde', 'entra-device', 'exposure-graph', 'intune-device')
    identity = @('entra-user', 'entra-serviceprincipal', 'exposure-graph', 'ad-computer')
    azure    = @('arm', 'arm-vm-extension', 'exposure-graph')
}

function Get-SIFullAssetPropertiesEngineSources {
    <# PURE. The source systems a profiler collects whole at the full level ('' for an engine that collects none, e.g. publicip). #>
    param([AllowEmptyString()][string]$Engine)
    $k = ([string]$Engine).Trim().ToLowerInvariant()
    if ($script:SIFullEngineSources.ContainsKey($k)) { return @($script:SIFullEngineSources[$k]) }
    @()
}

function Get-SIFullAssetPropertiesProPath {
    <# The SecurityInsight Pro file that publishes the full objects -- '' when this copy does not carry it (Community). #>
    param([string]$SIRoot)
    if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) }
    $p = [System.IO.Path]::Combine($SIRoot, 'engine', 'asset-properties', '_shared', 'SI-AssetPropertiesProfiler.ps1')
    if (Test-Path -LiteralPath $p) { return $p }
    ''
}

function Get-SIFullAssetPropertiesSetting {
    <# PURE. SI_AssetProperties as the level it asks for: 'full' (any case) or 'security' (anything else, unset included). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'security' }
    if (([string]$Value).Trim().ToLowerInvariant() -eq 'full') { return 'full' }
    'security'
}

function Reset-SIFullAssetProperties {
    <# The run state, at the security level. Every engine run starts here (a container session runs several engines). #>
    param([string]$Engine = '')
    $global:SIFullAssetPropertiesState = [pscustomobject]@{
        Level   = 'security'
        Engine  = ([string]$Engine).Trim().ToLowerInvariant()
        Reason  = ''
        Entries = New-Object System.Collections.Generic.List[object]
        Pulls   = @{}
    }
    $global:SIFullAssetPropertiesState
}

function Set-SIFullAssetPropertiesLevel {
    <# Marks this run 'full' (only the Pro file calls this, after it established the licence) or 'security' with the reason. #>
    param([Parameter(Mandatory)][ValidateSet('security', 'full')][string]$Level, [string]$Reason = '')
    if ($null -eq $global:SIFullAssetPropertiesState) { $null = Reset-SIFullAssetProperties }
    $global:SIFullAssetPropertiesState.Level = $Level
    $global:SIFullAssetPropertiesState.Reason = $Reason
}

function Test-SIFullAssetPropertiesOn {
    <#
        Is THIS run collecting whole source objects? $false whenever the state was never initialised -- the security level.
        -Engine: and is the run THAT profiler (a shared helper -- the Exposure Graph identity fetch -- keeps its nodes only
        for the identity profiler).
    #>
    param([string]$Engine = '')
    $s = $global:SIFullAssetPropertiesState
    if ($null -eq $s -or [string]$s.Level -ne 'full') { return $false }
    if ($Engine -and [string]$s.Engine -ne $Engine.Trim().ToLowerInvariant()) { return $false }
    $true
}

function Initialize-SIFullAssetProperties {
    <#
        Decides the level for one engine run, ONCE, before discovery. Returns the Pro file to dot-source ('' when the run
        stays at the security level) -- the CALLER dot-sources it, at its own scope, so the Pro functions outlive this call.
        The Pro file's Enable-SIFullAssetProperties then checks the licence and sets the level.
    #>
    param([Parameter(Mandatory)][string]$Engine, [string]$SIRoot, [AllowNull()]$Setting = $global:SI_AssetProperties, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) if ($l -eq 'WARN') { Write-Warning $m } else { Write-Host ('[INFO] ' + $m) } } }
    $null = Reset-SIFullAssetProperties -Engine $Engine
    if ((Get-SIFullAssetPropertiesSetting $Setting) -ne 'full') { return '' }
    if (@(Get-SIFullAssetPropertiesEngineSources $Engine).Count -eq 0) {
        Set-SIFullAssetPropertiesLevel -Level security -Reason ('the {0} profiler has no asset metadata to collect' -f $Engine)
        return ''
    }
    $pro = Get-SIFullAssetPropertiesProPath -SIRoot $SIRoot
    if (-not $pro) {
        Set-SIFullAssetPropertiesLevel -Level security -Reason 'this copy does not include the full asset metadata publisher (engine\asset-properties)'
        & $Log 'WARN' "SI_AssetProperties = 'full', but this copy does not include the full asset metadata publisher (engine\asset-properties) -- the security level runs (the source queries are unchanged)."
        return ''
    }
    $pro
}

function Copy-SIFullSourceObject {
    <#
        PURE. A shallow copy of a source object as an ordered PSCustomObject (a hashtable's keys, or an object's
        properties). A copy, because discovery stamps its own fields on some objects afterwards (ENTRA_IsDeleted) and the
        stored object must be the source's -- not SecurityInsight's working copy.
    #>
    param([AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return $null }
    $o = [ordered]@{}
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in @($InputObject.Keys)) { $o[[string]$k] = $InputObject[$k] }
    } else {
        foreach ($p in $InputObject.PSObject.Properties) { $o[$p.Name] = $p.Value }
    }
    [pscustomobject]$o
}

function Add-SIFullSourceObject {
    <#
        Keeps one WHOLE source object for the full asset metadata -- a no-op at the security level.
          -SourceSystem  mde | entra-device | entra-user | entra-serviceprincipal | arm | exposure-graph | intune-device | ad-computer
          -AnchorColumn  the profile column that names the same object (MdeDeviceId, AadDeviceId, EntraAccountObjectId,
                         AzureResourceId, EgNodeId, OnPremObjectGuid) and -AnchorValue its value in this object. The
                         Output stage resolves the object to its profile row through it. Omitted = the source's default.
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [AllowNull()]$Object, [string]$AnchorColumn = '', [AllowNull()][AllowEmptyString()][string]$AnchorValue = '')
    # v3 data model (V3-DATA-MODEL part 2, P1): EVERY source object is also a part of an SI record, at every level --
    # the record capture maps it through data-model/mappings. Never throws.
    if ($null -ne $Object -and (Get-Command -Name Add-SIRecordPartFromSource -ErrorAction SilentlyContinue)) { Add-SIRecordPartFromSource -SourceSystem $SourceSystem -Object $Object -AnchorValue $AnchorValue }
    if (-not (Test-SIFullAssetPropertiesOn)) { return }
    if ($null -eq $Object) { return }
    $global:SIFullAssetPropertiesState.Entries.Add([pscustomobject]@{
        SourceSystem = $SourceSystem.Trim().ToLowerInvariant()
        Object       = (Copy-SIFullSourceObject $Object)
        AnchorColumn = [string]$AnchorColumn
        AnchorValue  = [string]$AnchorValue
    })
}

function Set-SIFullSourcePull {
    <#
        Records how one source's pull went at the full level (a no-op at security): Complete, the error, and -Narrowed when
        Graph refused the wide $select and the security URL was used instead (the object then carries the security fields).
        A source with a pull record is a source this run ATTEMPTED -- what the collection-change guard compares.
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [bool]$Complete = $true, [string]$ErrorText = '', [string]$Skipped = '', [switch]$Narrowed)
    # v3 data model: the record capture needs every provider's completeness, at every level
    if (Get-Command -Name Set-SIRecordPullFromSource -ErrorAction SilentlyContinue) { Set-SIRecordPullFromSource -SourceSystem $SourceSystem -Complete $Complete -ErrorText $ErrorText }
    if (-not (Test-SIFullAssetPropertiesOn)) { return }
    $k = $SourceSystem.Trim().ToLowerInvariant()
    $prev = $global:SIFullAssetPropertiesState.Pulls[$k]
    if ($prev) {
        # a source pulled in two calls (active + deleted users) is complete only when both were, and narrowed when either was
        $Complete = [bool]$prev.Complete -and $Complete
        if (-not $ErrorText) { $ErrorText = [string]$prev.Error }
        if ([bool]$prev.Narrowed) { $Narrowed = $true }
    }
    $global:SIFullAssetPropertiesState.Pulls[$k] = [pscustomobject]@{ SourceSystem = $k; Complete = [bool]$Complete; Error = [string]$ErrorText; Skipped = [string]$Skipped; Narrowed = [bool]$Narrowed }
}

function Get-SIFullAssetPropertiesState {
    <# The run state (level, engine, reason, kept objects, pull records); $null before any run initialised it. #>
    $global:SIFullAssetPropertiesState
}

function Get-SIFullSourceObjects {
    <# The objects this run kept (empty at the security level). #>
    $s = $global:SIFullAssetPropertiesState
    if ($null -eq $s) { return @() }
    @($s.Entries.ToArray())
}

function Get-SIFullGraphUrl {
    <#
        PURE. The full pull's URL from the security pull's URL: the same path and the same query, with $select = the
        security $select (unchanged, first) UNION the declared extra properties of -SourceSystem. A URL without a $select
        is returned unchanged (nothing was narrowed).
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [Parameter(Mandatory)][string]$SecurityUrl)
    $k = $SourceSystem.Trim().ToLowerInvariant()
    $extra = if ($script:SIFullGraphExtraSelect.ContainsKey($k)) { @($script:SIFullGraphExtraSelect[$k]) } else { @() }
    $m = [regex]::Match($SecurityUrl, '([?&])\$select=([^&]*)')
    # a whole-object source: the same URL without its $select (Graph then returns every property of the object)
    if ($m.Success -and $script:SIFullGraphWholeObject -contains $k) {
        $rest = $SecurityUrl.Substring($m.Index + $m.Length)
        if ($m.Groups[1].Value -eq '?') { if ($rest.StartsWith('&')) { return ($SecurityUrl.Substring(0, $m.Index) + '?' + $rest.Substring(1)) }; return $SecurityUrl.Substring(0, $m.Index) }
        return ($SecurityUrl.Substring(0, $m.Index) + $rest)
    }
    if (-not $m.Success -or $extra.Count -eq 0) { return $SecurityUrl }
    $have = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($m.Groups[2].Value -split ',')) { $f = $f.Trim(); if ($f -and $have.Add($f)) { $list.Add($f) } }
    foreach ($f in $extra) { if ($f -and $have.Add($f)) { $list.Add($f) } }
    $SecurityUrl.Substring(0, $m.Index) + $m.Groups[1].Value + '$select=' + ($list -join ',') + $SecurityUrl.Substring($m.Index + $m.Length)
}

function Get-SIFullGraphSelectFields {
    <# PURE. The $select fields of a Graph URL, in order ('' entries dropped). #>
    param([Parameter(Mandatory)][string]$Url)
    $m = [regex]::Match($Url, '[?&]\$select=([^&]*)')
    if (-not $m.Success) { return @() }
    @($m.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-SIFullGraphSelectRefused {
    <#
        PURE. Did Graph refuse the full $select itself (HTTP 400 / an unknown or unsupported property) with NOTHING
        collected? Only then is the security URL tried -- a partial page means the $select was accepted.
    #>
    param([AllowNull()]$Page)
    if ($null -eq $Page) { return $false }
    if ([bool]$Page.Complete) { return $false }
    if (@($Page.Rows).Count -gt 0) { return $false }
    ([string]$Page.Error) -match '(?i)\b400\b|\b501\b|bad ?request|could not find a property|not supported|is not selectable|invalid \$select|unsupported'
}

function Invoke-SIFullAwareGraphPull {
    <#
        One Graph collection pull that is the security pull at the security level and the ONE wide pull at the full level.
          -SecurityUrl  the URL the security level uses -- unchanged; at security it is the only URL ever requested
          -Fetch        { param($Url, $Label) -> @{ Rows; Complete; Error; Pages } } (Invoke-SIPagedRest by the caller)
        Returns the page. At full: the wide URL first; a refused wide $select is retried with -SecurityUrl and the source is
        recorded -Narrowed (said once). The pull status is recorded for -SourceSystem.
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [Parameter(Mandatory)][string]$SecurityUrl, [Parameter(Mandatory)][scriptblock]$Fetch,
          [string]$Label = '', [switch]$NoPullRecord)
    if (-not (Test-SIFullAssetPropertiesOn)) { return (& $Fetch $SecurityUrl $Label) }
    $wide = Get-SIFullGraphUrl -SourceSystem $SourceSystem -SecurityUrl $SecurityUrl
    $page = & $Fetch $wide ($Label + ' (full)')
    $narrowed = $false
    if ($wide -ne $SecurityUrl -and (Test-SIFullGraphSelectRefused $page)) {
        Write-Warning ("full asset metadata: Microsoft Graph refused the full property list for {0} ({1}) -- this run reads it with the security property list; its full metadata carries the security fields only, and the profile is unaffected." -f $SourceSystem, ([string]$page.Error))
        $page = & $Fetch $SecurityUrl $Label
        $narrowed = $true
    }
    if (-not $NoPullRecord) {
        $ok = $false; $err = ''
        if ($page) { $ok = [bool]$page.Complete; $err = [string]$page.Error }
        Set-SIFullSourcePull -SourceSystem $SourceSystem -Complete $ok -ErrorText $err -Narrowed:$narrowed
    }
    $page
}

function ConvertFrom-SIFullJsonText {
    <# PURE. A JSON text column (ARG tostring(...), an EG NodeProperties string) back to its value; text that is not JSON stays text; '' -> $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if (-not ($Value -is [string])) { return $Value }
    $t = $Value.Trim()
    if (-not $t) { return $null }
    if ($t -match '^[\[{]' -or $t -eq 'null' -or $t -eq 'true' -or $t -eq 'false') {
        try { return (ConvertFrom-Json -InputObject $t) } catch { return $Value }
    }
    $Value
}

# The ARM envelope columns the azure profiler's Resource Graph query does not project at the security level. The full
# level appends them to the SAME projection (prefixed Full*, so no security column is touched or shadowed).
$script:SIFullArgEnvelope = 'FullId = id, FullType = type, FullTenantId = tenantId, FullManagedBy = managedBy, FullPlan = plan, FullZones = zones, FullExtendedLocation = extendedLocation'

function Get-SIFullArgKql {
    <#
        PURE. The azure profiler's Resource Graph query at the full level: the security query, unchanged, with the rest of
        the ARM envelope appended to its LAST `| project` (before its `| order by`). A query with no `| order by` gets the
        columns at its end.
    #>
    param([Parameter(Mandatory)][string]$SecurityKql)
    $nl = if ($SecurityKql.Contains("`r`n")) { "`r`n" } else { "`n" }
    $i = $SecurityKql.LastIndexOf($nl + '| order by')
    if ($i -lt 0) { return ($SecurityKql.TrimEnd() + ',' + $nl + '    ' + $script:SIFullArgEnvelope) }
    $SecurityKql.Substring(0, $i) + ',' + $nl + '    ' + $script:SIFullArgEnvelope + $SecurityKql.Substring($i)
}

function ConvertTo-SIFullArmObject {
    <#
        PURE. One row of the azure profiler's Resource Graph query (full level) -> the ARM resource as ARM describes it:
        id, name, type, kind, location, resourceGroup, subscriptionId, tenantId, managedBy, sku, plan, zones,
        extendedLocation, identity, tags and properties -- the JSON text columns parsed back into objects, arrays kept.
    #>
    param([Parameter(Mandatory)][AllowNull()]$Row)
    if ($null -eq $Row) { return $null }
    $g = { param($n) $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $id = & $g 'FullId'; if (-not $id) { $id = & $g 'ResourceId' }
    $type = & $g 'FullType'; if (-not $type) { $type = & $g 'Type' }
    $kind = & $g 'Kind'; if ($kind -is [string] -and -not $kind) { $kind = $null }
    [pscustomobject][ordered]@{
        id               = $id
        name             = & $g 'Name'
        type             = $type
        kind             = $kind
        location         = & $g 'Location'
        resourceGroup    = & $g 'RG'
        subscriptionId   = & $g 'Subscription'
        tenantId         = & $g 'FullTenantId'
        managedBy        = & $g 'FullManagedBy'
        sku              = ConvertFrom-SIFullJsonText (& $g 'SkuJson')
        plan             = ConvertFrom-SIFullJsonText (& $g 'FullPlan')
        zones            = ConvertFrom-SIFullJsonText (& $g 'FullZones')
        extendedLocation = ConvertFrom-SIFullJsonText (& $g 'FullExtendedLocation')
        identity         = ConvertFrom-SIFullJsonText (& $g 'IdentityJson')
        tags             = ConvertFrom-SIFullJsonText (& $g 'TagsJson')
        properties       = ConvertFrom-SIFullJsonText (& $g 'PropertiesJson')
    }
}

function ConvertTo-SIFullExposureGraphNode {
    <#
        PURE. One Exposure Graph node row -> the object kept for it: NodeId, NodeName, NodeLabel, Categories, EntityIds and
        NodeProperties, the JSON text columns parsed back into objects (a node read as NodePropertiesJson is the same node).
    #>
    param([Parameter(Mandatory)][AllowNull()]$Row)
    if ($null -eq $Row) { return $null }
    $o = [ordered]@{}
    foreach ($p in $Row.PSObject.Properties) {
        $n = $p.Name
        if ($n -eq 'NodePropertiesJson') { $n = 'NodeProperties' }
        if ($n -in 'NodeProperties', 'EntityIds', 'Categories') { $o[$n] = ConvertFrom-SIFullJsonText $p.Value } else { $o[$n] = $p.Value }
    }
    [pscustomobject]$o
}

function Get-SIFullAssetPropertiesHandoverStore {
    <# The run's state store (the same blob container the parts and the records use). Test seam: $global:SI_AssetPropsHandoverStore. #>
    if ($global:SI_AssetPropsHandoverStore) { return $global:SI_AssetPropsHandoverStore }
    if (-not (Get-Command -Name New-SICollectBlobStore -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-CollectParts.ps1')) }
    New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)
}

function Save-SIFullAssetPropertiesPartHandover {
    <# A part's hand-over: the identity of the rows it built + the objects it kept itself (Save-SIAssetPropsHandover, Pro). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    if (-not (Get-Command -Name Save-SIAssetPropsHandover -ErrorAction SilentlyContinue)) { throw 'the hand-over (SI-AssetPropertiesHandover.ps1) is not loaded' }
    $run = [string][Environment]::GetEnvironmentVariable('SI_COLLECT_ENGINE_RUN')
    if (-not $run) { throw 'the run id of the parts (SI_COLLECT_ENGINE_RUN) is not set' }
    $part = [int][Environment]::GetEnvironmentVariable('SI_COLLECT_PART')
    $s = $global:SIFullAssetPropertiesState
    $res = Save-SIAssetPropsHandover -Store (Get-SIFullAssetPropertiesHandoverStore) -Engine ([string]$s.Engine) -RunId $run -Who ('part-{0:D5}' -f $part) `
        -Entries @(Get-SIFullSourceObjects) -Pulls $s.Pulls -ProfileRows @($Rows)
    Write-Host ('[INFO] full asset metadata: {0} profile row(s) and {1} kept object(s) handed over -- the run''s full metadata is published once, when every part is done' -f $res.Rows, $res.Entries)
    $res
}

function Save-SIFullAssetPropertiesDiscoverHandover {
    <#
        The producer's hand-over after discovery (the container calls it beside the records hand-over): the objects
        discovery kept + its pull records. Nothing at the security level. Returns the number of objects saved, or $null.
    #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, $Store)
    $s = $global:SIFullAssetPropertiesState
    if ($null -eq $s -or [string]$s.Level -ne 'full') { return $null }
    if (-not (Get-Command -Name Save-SIAssetPropsHandover -ErrorAction SilentlyContinue)) {
        $pro = Get-SIFullAssetPropertiesProPath
        if (-not $pro) { return $null }
        . ([System.IO.Path]::Combine((Split-Path -Parent $pro), 'SI-AssetPropertiesHandover.ps1'))
    }
    if (-not $Store) { $Store = Get-SIFullAssetPropertiesHandoverStore }
    $res = Save-SIAssetPropsHandover -Store $Store -Engine $Engine -RunId $RunId -Who 'discover' -Entries @(Get-SIFullSourceObjects) -Pulls $s.Pulls
    $s.Entries.Clear()
    $res.Entries
}

function Publish-SIFullAssetProperties {
    <#
        The Output stage's call, after the profile rows are built: hands the kept objects and the built rows to the Pro
        publisher. Nothing at the security level, nothing without the Pro publisher loaded. NEVER throws -- the full
        metadata must not cost the customer the profile run -- but a failure is said, loudly.
    #>
    param([Parameter(Mandatory)]$RunContext, [AllowEmptyCollection()][object[]]$Rows = @())
    if (-not (Test-SIFullAssetPropertiesOn)) { return $null }
    if (-not (Get-Command -Name Publish-SIProfilerAssetProperties -ErrorAction SilentlyContinue)) {
        Write-Warning 'full asset metadata: the publisher is not loaded in this run -- nothing is published to SI_AssetProperties_CL.'
        return $null
    }
    # A PART of a run collected in parts (KEDA worker, or one job in parts) publishes nothing: the objects were kept by
    # discovery, in another process, and the rows of the other parts are elsewhere. It hands over the identity of the rows
    # it built (+ any object it kept itself); the run's last step publishes the run's full metadata ONCE
    # (SI-AssetPropertiesHandover.ps1). Ring 1, 2026-10-11: before this, identity in queue mode never published any.
    if ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE') -eq 'parts') {
        try { return (Save-SIFullAssetPropertiesPartHandover -Rows @($Rows)) }
        catch {
            Write-Warning ('full asset metadata: this part could not hand its rows over -- {0}. The profile rows are unaffected; this part''s assets get no full metadata this run.' -f $_.Exception.Message)
            return $null
        }
    }
    try { return (Publish-SIProfilerAssetProperties -RunContext $RunContext -ProfileRows @($Rows) -Entries @(Get-SIFullSourceObjects) -Pulls $global:SIFullAssetPropertiesState.Pulls) }
    catch {
        Write-Warning ('full asset metadata could not be published this run -- {0}. The profile rows are unaffected; the asset page keeps the previous full metadata until the next run.' -f $_.Exception.Message)
        return $null
    }
}
